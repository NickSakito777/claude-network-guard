import Darwin
import Foundation

// Candidate source only. The installed helper source is not present in this checkout.
enum PortObserverCandidate {
    static let outputDirectory = ["private", "var", "db", "local.fox.claude-port-observer"]
    static let outputName = "ports.json"
    static let maxOutputBytes = 16_384
    static let maxSampleDurationNS: Int64 = 2_500_000_000

    enum CaptureStatus: Equatable { case success, spawnFailed, readFailed, tooLarge }

    struct Capture: Equatable {
        let status: CaptureStatus
        let bytes: Data
    }

    struct ProcessIdentity: Equatable {
        let pid: Int32
        let startSeconds: UInt64
        let startMicroseconds: UInt64
        let executablePath: String
    }

    struct ClockReading {
        let wallMS: Int64?
        let monotonicNS: Int64?
    }

    private struct SocketRow: Equatable {
        let port: Int
        let localAddress: String
        let pid: Int32
    }

    private struct ParsedSockets {
        let rows: [SocketRow]
        let malformed: Bool
    }

    private enum IdentityRead {
        case unavailable
        case value(ProcessIdentity)
    }

    // Fixed two-sample protocol. Each final lsof row is bracketed by equal PID identities.
    // The injected closures keep the complete ordering testable without live sampling.
    static func sample(capture: () -> Capture, clock: () -> ClockReading,
                       bootSessionUUID: () -> String?,
                       processIdentity: (Int32) -> ProcessIdentity?) -> Data {
        // Stamp before any work so age is conservative for every fact in the transaction.
        let started = clock()
        let firstCapture = capture()
        let firstParsed = parseLsof(firstCapture.bytes)
        // These identities are read after sample one and immediately before sample two.
        let identitiesBefore = readIdentities(firstParsed.rows, processIdentity: processIdentity)

        let secondCapture = capture()
        let secondParsed = parseLsof(secondCapture.bytes)
        // Serialize only sample-two rows, and only when sample-one facts and bracketed identity agree.
        let identitiesAfter = readIdentities(secondParsed.rows, processIdentity: processIdentity)
        let finished = clock()
        let boot = bootSessionUUID()

        return build(firstCapture: firstCapture, first: firstParsed,
            identitiesBefore: identitiesBefore, secondCapture: secondCapture,
            second: secondParsed, identitiesAfter: identitiesAfter,
            started: started, finished: finished, bootSessionUUID: boot)
    }

    private static func build(firstCapture: Capture, first: ParsedSockets,
                              identitiesBefore: [Int32: IdentityRead],
                              secondCapture: Capture, second: ParsedSockets,
                              identitiesAfter: [Int32: IdentityRead],
                              started: ClockReading, finished: ClockReading,
                              bootSessionUUID: String?) -> Data {
        var listeners: [[String: Any]] = []
        var portObservations: [[String: Any]] = []
        let rowFactsChanged = [7896, 17897].contains { port in
            canonical(first.rows.filter { $0.port == port }) != canonical(second.rows.filter { $0.port == port })
        }
        let identityChanged = identityMismatch(first.rows + second.rows,
            before: identitiesBefore, after: identitiesAfter)
        let identityUnavailable = identityReadFailed(first.rows + second.rows,
            before: identitiesBefore, after: identitiesAfter)
        let elapsedNS = sampleElapsed(started: started, finished: finished)
        let clockValid = elapsedNS != nil
        let sampleTooLong = elapsedNS.map { $0 > maxSampleDurationNS } ?? false
        let bootValid = bootSessionUUID.flatMap(UUID.init(uuidString:)) != nil
        let status: String
        if !clockValid { status = "clock_failed" }
        else if firstCapture.status != .success { status = firstCapture.status.producerStatus }
        else if secondCapture.status != .success { status = secondCapture.status.producerStatus }
        else if first.malformed || second.malformed { status = "malformed_output" }
        else if rowFactsChanged { status = "sample_changed" }
        else if identityChanged { status = "identity_changed" }
        else if identityUnavailable { status = "identity_read_failed" }
        else if sampleTooLong { status = "sampling_too_long" }
        else if !bootValid { status = "boot_uuid_failed" }
        else { status = "ok" }

        for port in [7896, 17897] {
            let firstRows = first.rows.filter { $0.port == port }
            let secondRows = second.rows.filter { $0.port == port }
            let rowsStable = canonical(firstRows) == canonical(secondRows)
            var portRows: [[String: Any]] = []
            var everyIdentityBound = rowsStable
            if rowsStable {
                for row in secondRows {
                    guard let identity = stableIdentity(row.pid,
                        before: identitiesBefore, after: identitiesAfter) else {
                        everyIdentityBound = false
                        continue
                    }
                    portRows.append(listenerRow(row, identity: identity))
                }
            }
            listeners.append(contentsOf: portRows)

            let querySucceeded = status == "ok" && rowsStable && everyIdentityBound
            let factBound = rowsStable && everyIdentityBound && !sampleTooLong
            let state: String
            if querySucceeded {
                state = secondRows.isEmpty ? "absent" : "present"
            } else if !factBound {
                // Do not turn a changed row set, changing PID identity, or long sample into a port claim.
                state = "unknown"
                listeners.removeLast(portRows.count)
            } else {
                state = secondRows.isEmpty ? "unknown" : "present"
            }
            let queryStatus = querySucceeded ? "success" : "failure"
            portObservations.append(["port": port, "query_status": queryStatus, "state": state])
        }

        let fullListenerSet = portObservations.allSatisfy {
            ($0["state"] as? String) == "present" && ($0["query_status"] as? String) == "success"
        } && listeners.count == 2

        let document: [String: Any] = [
            "schema_version": 2,
            "ok": status == "ok" && fullListenerSet,
            "status": status,
            "observed_at_unix_ms": started.wallMS.map { $0 as Any } ?? NSNull(),
            "observed_monotonic_ns": started.monotonicNS.map { $0 as Any } ?? NSNull(),
            "boot_session_uuid": bootSessionUUID.map { $0 as Any } ?? NSNull(),
            "listeners": listeners,
            "port_observations": portObservations,
        ]
        guard let encoded = try? JSONSerialization.data(withJSONObject: document, options: [.sortedKeys]) else {
            return Data()
        }
        if encoded.count <= maxOutputBytes { return encoded }
        let bounded: [String: Any] = [
            "schema_version": 2,
            "ok": false,
            "status": "too_large",
            "observed_at_unix_ms": started.wallMS.map { $0 as Any } ?? NSNull(),
            "observed_monotonic_ns": started.monotonicNS.map { $0 as Any } ?? NSNull(),
            "boot_session_uuid": bootSessionUUID.map { $0 as Any } ?? NSNull(),
            "listeners": [],
            "port_observations": [7896, 17897].map {
                ["port": $0, "query_status": "failure", "state": "unknown"] as [String: Any]
            },
        ]
        return (try? JSONSerialization.data(withJSONObject: bounded, options: [.sortedKeys])) ?? Data()
    }

    private static func readIdentities(_ rows: [SocketRow],
                                      processIdentity: (Int32) -> ProcessIdentity?) -> [Int32: IdentityRead] {
        var result: [Int32: IdentityRead] = [:]
        for pid in Set(rows.map(\.pid)).sorted() {
            result[pid] = processIdentity(pid).map(IdentityRead.value) ?? .unavailable
        }
        return result
    }

    private static func identityMismatch(_ rows: [SocketRow],
                                         before: [Int32: IdentityRead],
                                         after: [Int32: IdentityRead]) -> Bool {
        for pid in Set(rows.map(\.pid)) {
            guard case let .value(left)? = before[pid],
                  case let .value(right)? = after[pid] else { continue }
            if left != right || left.pid != pid || right.pid != pid { return true }
        }
        return false
    }

    private static func identityReadFailed(_ rows: [SocketRow],
                                           before: [Int32: IdentityRead],
                                           after: [Int32: IdentityRead]) -> Bool {
        for pid in Set(rows.map(\.pid)) {
            guard case let .value(left)? = before[pid],
                  case let .value(right)? = after[pid] else { return true }
            if !valid(left) || !valid(right) { return true }
        }
        return false
    }

    private static func stableIdentity(_ pid: Int32,
                                       before: [Int32: IdentityRead],
                                       after: [Int32: IdentityRead]) -> ProcessIdentity? {
        guard case let .value(left)? = before[pid],
              case let .value(right)? = after[pid],
              left == right, left.pid == pid, valid(left) else { return nil }
        return right
    }

    private static func valid(_ identity: ProcessIdentity) -> Bool {
        identity.pid > 0 && identity.startSeconds > 0 &&
            identity.startMicroseconds < 1_000_000 && identity.executablePath.hasPrefix("/")
    }

    private static func listenerRow(_ row: SocketRow, identity: ProcessIdentity) -> [String: Any] {
        ["port": row.port, "local_address": row.localAddress, "pid": row.pid,
         "process_start_sec": identity.startSeconds,
         "process_start_usec": identity.startMicroseconds,
         "executable_path": identity.executablePath]
    }

    private static func canonical(_ rows: [SocketRow]) -> [SocketRow] {
        rows.sorted {
            if $0.port != $1.port { return $0.port < $1.port }
            if $0.localAddress != $1.localAddress { return $0.localAddress < $1.localAddress }
            return $0.pid < $1.pid
        }
    }

    private static func sampleElapsed(started: ClockReading, finished: ClockReading) -> Int64? {
        guard let wallStart = started.wallMS, let wallEnd = finished.wallMS,
              let monoStart = started.monotonicNS, let monoEnd = finished.monotonicNS,
              wallStart > 0, wallEnd >= wallStart, monoStart > 0, monoEnd >= monoStart else { return nil }
        let (elapsed, overflow) = monoEnd.subtractingReportingOverflow(monoStart)
        return overflow ? nil : elapsed
    }

    static func captureLsof() -> Capture {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = ["-nP", "-iTCP", "-sTCP:LISTEN", "-Fpn"]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return Capture(status: .spawnFailed, bytes: Data()) }

        let lock = NSLock()
        var finished = false
        var timedOut = false
        let timeout = DispatchWorkItem {
            lock.lock(); defer { lock.unlock() }
            if !finished && process.isRunning {
                timedOut = true
                _ = Darwin.kill(process.processIdentifier, SIGKILL)
            }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 1, execute: timeout)
        var output = Data()
        var tooLarge = false
        var readFailed = false
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(pipe.fileHandleForReading.fileDescriptor, &buffer, buffer.count)
            if count < 0 { readFailed = true; break }
            if count == 0 { break }
            output.append(contentsOf: buffer[0..<count])
            if output.count > maxOutputBytes {
                tooLarge = true
                _ = Darwin.kill(process.processIdentifier, SIGKILL)
                break
            }
        }
        process.waitUntilExit()
        lock.lock(); finished = true; let didTimeout = timedOut; lock.unlock()
        timeout.cancel()
        if tooLarge { return Capture(status: .tooLarge, bytes: output) }
        if readFailed || didTimeout || process.terminationStatus != 0 {
            return Capture(status: .readFailed, bytes: output)
        }
        return Capture(status: .success, bytes: output)
    }

    // Diagnostic CLI seam: call the canonical sampler without invoking its privileged writer.
    static func sampleLive() -> Data {
        sample(capture: captureLsof, clock: clockReading,
            bootSessionUUID: readBootUUID, processIdentity: processIdentity)
    }

    static func writeCurrentSnapshot() -> Bool {
        let bytes = sample(capture: captureLsof, clock: clockReading,
            bootSessionUUID: readBootUUID, processIdentity: processIdentity)
        return writeAtomically(bytes)
    }

    private static func clockReading() -> ClockReading {
        let wall = Int64(Date().timeIntervalSince1970 * 1_000)
        var time = timespec()
        let monotonic: Int64? = clock_gettime(CLOCK_MONOTONIC, &time) == 0
            ? Int64(time.tv_sec) * 1_000_000_000 + Int64(time.tv_nsec) : nil
        return ClockReading(wallMS: wall > 0 ? wall : nil,
                            monotonicNS: monotonic.flatMap { $0 > 0 ? $0 : nil })
    }

    private static func parseLsof(_ data: Data) -> ParsedSockets {
        guard let output = String(data: data, encoding: .utf8) else {
            return ParsedSockets(rows: [], malformed: true)
        }
        var currentPID: Int32?
        var rows: [SocketRow] = []
        var malformed = false
        for line in output.split(whereSeparator: \.isNewline) {
            guard let tag = line.first else { continue }
            let value = line.dropFirst()
            if tag == "p" {
                currentPID = Int32(value)
                if currentPID == nil || currentPID! <= 0 { malformed = true }
            } else if tag == "n" {
                guard let endpoint = endpoint(String(value)) else {
                    malformed = true
                    continue
                }
                guard [7896, 17897].contains(endpoint.port) else { continue }
                guard let pid = currentPID else { malformed = true; continue }
                rows.append(SocketRow(port: endpoint.port,
                    localAddress: endpoint.address + ".\(endpoint.port)", pid: pid))
            }
        }
        return ParsedSockets(rows: rows, malformed: malformed)
    }

    private static func endpoint(_ value: String) -> (address: String, port: Int)? {
        guard let colon = value.lastIndex(of: ":"), let port = Int(value[value.index(after: colon)...]) else {
            return nil
        }
        return (String(value[..<colon]), port)
    }

    private static func processIdentity(_ pid: Int32) -> ProcessIdentity? {
        var sec: UInt64 = 0
        var usec: UInt64 = 0
        var path = [CChar](repeating: 0, count: 4096)
        let result = path.withUnsafeMutableBufferPointer {
            candidateObserverProcessIdentity(pid, &sec, &usec, $0.baseAddress!, UInt32($0.count))
        }
        guard result == 1 else { return nil }
        return ProcessIdentity(pid: pid, startSeconds: sec, startMicroseconds: usec,
                               executablePath: String(cString: path))
    }

    private static func readBootUUID() -> String? {
        var count = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &count, nil, 0) == 0,
              (2...128).contains(count) else { return nil }
        var bytes = [CChar](repeating: 0, count: count)
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &count, nil, 0) == 0 else { return nil }
        return String(cString: bytes)
    }

    private static func writeAtomically(_ data: Data) -> Bool {
        guard geteuid() == 0, !data.isEmpty, data.count <= maxOutputBytes else { return false }
        var directoryFD = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryFD >= 0 else { return false }
        defer { close(directoryFD) }
        for component in outputDirectory {
            let next = component.withCString {
                openat(directoryFD, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            }
            guard next >= 0 else { return false }
            var info = stat()
            guard fstat(next, &info) == 0, info.st_uid == 0,
                  (info.st_mode & 0o022) == 0, (info.st_mode & S_IFMT) == S_IFDIR else {
                close(next); return false
            }
            close(directoryFD)
            directoryFD = next
        }

        let temporary = ".ports.json.\(UUID().uuidString).tmp"
        let fd = temporary.withCString {
            openat(directoryFD, $0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        }
        guard fd >= 0 else { return false }
        var okay = true
        var offset = 0
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { okay = false; return }
            while offset < raw.count {
                let count = Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
                if count <= 0 { okay = false; break }
                offset += count
            }
        }
        if okay { okay = fchmod(fd, 0o644) == 0 && fsync(fd) == 0 }
        close(fd)
        let renamed = okay && temporary.withCString { from in
            outputName.withCString { to in renameat(directoryFD, from, directoryFD, to) == 0 }
        }
        if !renamed { _ = temporary.withCString { unlinkat(directoryFD, $0, 0) } }
        return renamed && fsync(directoryFD) == 0
    }
}

private extension PortObserverCandidate.CaptureStatus {
    var producerStatus: String {
        switch self {
        case .success: return "ok"
        case .spawnFailed: return "spawn_failed"
        case .readFailed: return "lsof_read_failed"
        case .tooLarge: return "too_large"
        }
    }
}

@_silgen_name("cng_observer_process_identity")
private func candidateObserverProcessIdentity(_ pid: Int32, _ sec: UnsafeMutablePointer<UInt64>,
    _ usec: UnsafeMutablePointer<UInt64>, _ path: UnsafeMutablePointer<CChar>, _ size: UInt32) -> Int32

#if PORT_OBSERVER_HELPER_MAIN
@main
struct PortObserverCandidateMain {
    static func main() { _ = PortObserverCandidate.writeCurrentSnapshot() }
}
#endif
