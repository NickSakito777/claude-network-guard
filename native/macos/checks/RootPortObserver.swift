import Foundation
import Darwin

// Reads and diagnoses the existing root-owned observer contract without changing that service.
enum RootPortObserver {
    private static let path = ["private", "var", "db", "local.fox.claude-port-observer", "ports.json"]
    private static let maxBytes = 16_384
    private static let maxAgeMS: Int64 = 2_500

    enum PortState: String, Equatable { case unavailable, missing, invalid, present }
    enum QueryState: String, Equatable { case unknown, failure, success }
    enum FileState: String, Equatable { case unreadable, invalid, readable }
    enum ValidationState: String, Equatable { case unavailable, invalid, valid }
    enum FreshnessState: String, Equatable { case unavailable, invalid, fresh, stale, future }
    enum BootState: String, Equatable { case unavailable, invalid, matches, mismatch }
    enum OwnerState: String, Equatable { case unknown, notApplicable, unavailable, matches, mismatch }

    struct ListenerFact: Equatable {
        let port: Int?
        let localAddress: String?
        let pid: Int32?
        let processStartSec: UInt64?
        let processStartUsec: UInt64?
        let executablePath: String?
        let identity: ListenerIdentity?
        let valid: Bool
    }

    struct PortFact: Equatable {
        let state: PortState
        let queryState: QueryState
        // Raw rows stay private to native validation; the outward DTO strips identity fields.
        let listeners: [ListenerFact]
        let invalid: Bool
        var reportedIdentities: [ListenerIdentity] { listeners.compactMap(\.identity) }
        var admittedIdentity: ListenerIdentity? {
            state == .present && queryState == .success && reportedIdentities.count == 1
                ? reportedIdentities.first : nil
        }

        init(state: PortState, queryState: QueryState, listeners: [ListenerFact], invalid: Bool = false) {
            self.state = state
            self.queryState = queryState
            self.listeners = listeners
            self.invalid = invalid
        }
    }

    struct Diagnostic: Equatable {
        let fileState: FileState
        let schemaState: ValidationState
        let observedAtUnixMS: Int64?
        let observedMonotonicNS: Int64?
        let bootSessionUUID: String?
        let producerStatus: String
        let wallFreshness: FreshnessState
        let monotonicFreshness: FreshnessState
        let bootState: BootState
        let upstream: PortFact
        let ingress: PortFact
        var ingressOwnerState: OwnerState
        var errorCode: String?
        var ownerErrorCode: String?
        var reportedUpstreamIdentities: [ListenerIdentity] { upstream.reportedIdentities }
        var reportedIngressIdentities: [ListenerIdentity] { ingress.reportedIdentities }

        // Observer stamps advance independently of network identity; callers compare freshness separately.
        func sameFacts(as other: Diagnostic) -> Bool {
            fileState == other.fileState && schemaState == other.schemaState &&
            producerStatus == other.producerStatus &&
            bootSessionUUID == other.bootSessionUUID && wallFreshness == other.wallFreshness &&
            monotonicFreshness == other.monotonicFreshness && bootState == other.bootState &&
            upstream == other.upstream && ingress == other.ingress &&
            ingressOwnerState == other.ingressOwnerState && errorCode == other.errorCode &&
            ownerErrorCode == other.ownerErrorCode
        }

    }

    static func read() throws -> (upstream: [ListenerIdentity], ingress: [ListenerIdentity]) {
        let facts = readDiagnostic()
        if let failure = admissionFailure(facts) {
            throw EnvironmentCheckFailure.observation(failure)
        }
        guard let upstream = facts.upstream.admittedIdentity,
              let ingress = facts.ingress.admittedIdentity,
              let wall = facts.observedAtUnixMS, let mono = facts.observedMonotonicNS else {
            throw EnvironmentCheckFailure.observation("root_observer_missing_listener")
        }
        // Recheck age after process identity validation; diagnostics never extend this window.
        try fresh(wall: wall, mono: mono)
        return ([upstream], [ingress])
    }

    static func readDiagnostic() -> Diagnostic {
        let data: Data?
        var readFailure: String?
        do { data = try secureRead() }
        catch {
            data = nil
            readFailure = failureKey(error)
        }
        let wallNow = Int64(Date().timeIntervalSince1970 * 1_000)
        let monoNow = monotonicNowNS()
        let currentBoot = try? bootUUID()
        var result = diagnose(data: data, readFailure: readFailure,
            wallNowMS: wallNow > 0 ? wallNow : nil, monotonicNowNS: monoNow,
            currentBootUUID: currentBoot)
        if result.ingress.state == .missing {
            result.ingressOwnerState = .notApplicable
        } else if let ingress = result.ingress.admittedIdentity {
            do {
                let live = try processIdentity(ingress.pid)
                let liveIdentity = ListenerIdentity(pid: ingress.pid, executable: live.path,
                    birth: "\(live.sec).\(live.usec)", bindAddress: ingress.bindAddress)
                result.ingressOwnerState = liveIdentity == ingress ? .matches : .mismatch
            } catch {
                result.ingressOwnerState = .unavailable
                result.ownerErrorCode = failureKey(error)
            }
        } else { result.ingressOwnerState = .unknown }
        return result
    }

    static func admissionFailure(_ facts: Diagnostic) -> String? {
        if facts.fileState == .unreadable { return facts.errorCode ?? "root_observer_path" }
        if facts.fileState == .invalid || facts.schemaState != .valid {
            return facts.errorCode ?? "root_observer_schema"
        }
        if facts.producerStatus != "ok" {
            return facts.producerStatus == "missing_listener"
                ? "root_observer_missing_listener" : "root_observer_\(facts.producerStatus)"
        }
        if facts.bootState == .mismatch { return "root_observer_boot" }
        if facts.bootState != .matches { return "boot_uuid" }
        if facts.wallFreshness == .unavailable || facts.monotonicFreshness == .unavailable ||
            facts.wallFreshness == .invalid || facts.monotonicFreshness == .invalid {
            return "monotonic_clock"
        }
        if facts.wallFreshness != .fresh || facts.monotonicFreshness != .fresh {
            return "root_observer_stale"
        }
        if facts.upstream.invalid || facts.ingress.invalid ||
            facts.upstream.state == .invalid || facts.ingress.state == .invalid {
            return "root_observer_listener"
        }
        if facts.upstream.state == .present && facts.upstream.admittedIdentity == nil ||
            facts.ingress.state == .present && facts.ingress.admittedIdentity == nil {
            return "root_observer_listener"
        }
        if facts.upstream.state != .present || facts.ingress.state != .present {
            return "root_observer_missing_listener"
        }
        if facts.ingressOwnerState == .mismatch { return "ingress_process_changed" }
        if facts.ingressOwnerState != .matches {
            return facts.ownerErrorCode ?? "ingress_process_identity"
        }
        return nil
    }

    // Pure fixture seam: reads legacy v1 and explicit per-port v2 data without OS sampling.
    static func diagnose(data: Data?, readFailure: String? = nil,
                         wallNowMS: Int64?, monotonicNowNS: Int64?,
                         currentBootUUID: String?,
                         liveIngressIdentity: ListenerIdentity? = nil) -> Diagnostic {
        let unknown = PortFact(state: .unavailable, queryState: .unknown, listeners: [])
        guard let data else {
            return Diagnostic(fileState: .unreadable, schemaState: .unavailable,
                observedAtUnixMS: nil, observedMonotonicNS: nil, bootSessionUUID: nil,
                producerStatus: "unknown", wallFreshness: .unavailable,
                monotonicFreshness: .unavailable, bootState: .unavailable,
                upstream: unknown, ingress: unknown, ingressOwnerState: .unknown,
                errorCode: readFailure ?? "root_observer_path")
        }
        guard let raw = try? JSONSerialization.jsonObject(with: data),
              let value = raw as? [String: Any] else {
            return Diagnostic(fileState: .invalid, schemaState: .invalid,
                observedAtUnixMS: nil, observedMonotonicNS: nil, bootSessionUUID: nil,
                producerStatus: "unknown", wallFreshness: .invalid,
                monotonicFreshness: .invalid, bootState: .invalid,
                upstream: unknown, ingress: unknown, ingressOwnerState: .unknown,
                errorCode: readFailure ?? "root_observer_schema")
        }

        let wall = value["observed_at_unix_ms"] as? Int64
        let mono = value["observed_monotonic_ns"] as? Int64
        let wallState = stampState(observed: wall, now: wallNowMS,
            limit: maxAgeMS, invalidWhenMissing: true)
        let monoState = stampState(observed: mono, now: monotonicNowNS,
            limit: maxAgeMS * 1_000_000, invalidWhenMissing: true)
        let boot = value["boot_session_uuid"] as? String
        let bootState = parseBootState(value["boot_session_uuid"], currentBootUUID: currentBootUUID)
        let rawStatus = value["status"] as? String
        let acceptedStatuses: Set<String> = ["ok", "missing_listener", "netstat_read_failed",
            "spawn_failed", "too_large", "lsof_read_failed", "identity_read_failed",
            "clock_failed", "boot_uuid_failed", "malformed_output", "sample_changed",
            "identity_changed", "sampling_too_long"]
        let status = rawStatus.flatMap { acceptedStatuses.contains($0) ? $0 : nil } ?? "unknown"
        let v1Keys: Set<String> = ["ok", "status", "observed_at_unix_ms",
            "observed_monotonic_ns", "boot_session_uuid", "listeners"]
        let v2Keys = v1Keys.union(["schema_version", "port_observations"])
        let version2 = value["schema_version"] as? Int == 2
        let keysValid = Set(value.keys) == (version2 ? v2Keys : v1Keys)
        let statusOK = value["ok"] as? Bool
        let statusConsistent = version2
            ? (statusOK != nil && (status == "ok" || statusOK == false))
            : statusOK == (status == "ok")
        let envelopeValid = keysValid && status != "unknown" && statusConsistent
        var schemaValid = envelopeValid
        var schemaFailure = envelopeValid ? nil : "root_observer_schema"
        guard let rows = value["listeners"] as? [Any] else {
            return Diagnostic(fileState: .readable, schemaState: .invalid,
                observedAtUnixMS: wall, observedMonotonicNS: mono, bootSessionUUID: boot,
                producerStatus: status, wallFreshness: wallState, monotonicFreshness: monoState,
                bootState: bootState, upstream: unknown, ingress: unknown,
                ingressOwnerState: .unknown, errorCode: readFailure ?? "root_observer_schema")
        }

        var listeners: [Int: [ListenerFact]] = [7896: [], 17897: []]
        var rowError = false
        for item in rows {
            guard let row = item as? [String: Any], let port = row["port"] as? Int,
                  listeners[port] != nil else {
                schemaValid = false
                rowError = true
                continue
            }
            let (fact, valid) = parse(row: row, port: port)
            listeners[port, default: []].append(fact)
            if !valid {
                schemaValid = false
                rowError = true
                schemaFailure = "root_observer_listener"
            }
        }

        let upstream: PortFact
        let ingress: PortFact
        if version2 {
            let perPort = parsePortObservations(value["port_observations"], listeners: listeners)
            if !perPort.valid {
                schemaValid = false
                schemaFailure = "root_observer_schema"
            }
            upstream = perPort.values[7896] ?? unknown
            ingress = perPort.values[17897] ?? unknown
        } else {
            let successfulScan = status == "ok" && statusOK == true
            func legacyFact(_ port: Int) -> PortFact {
                let rows = listeners[port] ?? []
                if !rows.isEmpty {
                    let invalid = !rows.allSatisfy(\.valid)
                    return PortFact(state: invalid ? .invalid : .present,
                                    queryState: successfulScan ? .success : .failure,
                                    listeners: rows, invalid: invalid)
                }
                return successfulScan
                    ? PortFact(state: .missing, queryState: .success, listeners: [])
                    : PortFact(state: .unavailable, queryState: .failure, listeners: [])
            }
            upstream = legacyFact(7896)
            ingress = legacyFact(17897)
        }

        var ownerState: OwnerState
        if ingress.state == .missing { ownerState = .notApplicable }
        else if let liveIngressIdentity, let reported = ingress.admittedIdentity {
            ownerState = liveIngressIdentity == reported ? .matches : .mismatch
        } else { ownerState = .unknown }
        if rowError { schemaFailure = "root_observer_listener" }
        return Diagnostic(fileState: .readable,
            schemaState: schemaValid ? .valid : .invalid,
            observedAtUnixMS: wall, observedMonotonicNS: mono, bootSessionUUID: boot,
            producerStatus: status, wallFreshness: wallState,
            monotonicFreshness: monoState, bootState: bootState,
            upstream: upstream, ingress: ingress, ingressOwnerState: ownerState,
            errorCode: readFailure ?? (schemaValid ? nil : schemaFailure ?? "root_observer_schema"))
    }

    private static func parse(row: [String: Any], port: Int) -> (ListenerFact, Bool) {
        let expectedKeys: Set<String> = ["port", "local_address", "pid", "process_start_sec",
            "process_start_usec", "executable_path"]
        let address = row["local_address"] as? String
        let pid = row["pid"] as? Int32
        let sec = row["process_start_sec"] as? UInt64
        let usec = row["process_start_usec"] as? UInt64
        let executable = row["executable_path"] as? String
        let identity: ListenerIdentity?
        if let address, let pid, let sec, let usec, let executable,
           pid > 0, sec > 0, usec < 1_000_000, executable.hasPrefix("/") {
            identity = ListenerIdentity(pid: pid, executable: executable,
                birth: "\(sec).\(usec)",
                bindAddress: address == "127.0.0.1.\(port)" ? "127.0.0.1:\(port)" : address)
        } else { identity = nil }
        let valid = Set(row.keys) == expectedKeys && row["port"] as? Int == port &&
            address == "127.0.0.1.\(port)" && pid.map { $0 > 0 } == true &&
            sec.map { $0 > 0 } == true && usec.map { $0 < 1_000_000 } == true &&
            executable?.hasPrefix("/") == true
        return (ListenerFact(port: row["port"] as? Int, localAddress: address,
            pid: pid, processStartSec: sec, processStartUsec: usec,
            executablePath: executable, identity: identity, valid: valid), valid)
    }

    private static func parsePortObservations(_ raw: Any?,
        listeners: [Int: [ListenerFact]]) -> (values: [Int: PortFact], valid: Bool) {
        guard let entries = raw as? [Any] else { return ([:], false) }
        let expectedKeys: Set<String> = ["port", "query_status", "state"]
        var values: [Int: PortFact] = [:]
        var valid = entries.count == 2
        for entry in entries {
            guard let value = entry as? [String: Any],
                  let port = value["port"] as? Int, [7896, 17897].contains(port),
                  values[port] == nil,
                  Set(value.keys) == expectedKeys,
                  let query = value["query_status"] as? String,
                  let state = value["state"] as? String else {
                valid = false
                continue
            }
            let rows = listeners[port] ?? []
            let rowInvalid = !rows.allSatisfy(\.valid)
            let fact: PortFact
            if query == "success", state == "present", !rows.isEmpty {
                fact = PortFact(state: rowInvalid ? .invalid : .present,
                                queryState: .success, listeners: rows, invalid: rowInvalid)
            } else if query == "success", (state == "absent" || state == "missing"), rows.isEmpty {
                fact = PortFact(state: .missing, queryState: .success, listeners: [])
            } else if query == "failure", state == "present" {
                fact = PortFact(state: rowInvalid ? .invalid : .present,
                                queryState: .failure, listeners: rows, invalid: rowInvalid)
            } else if query == "failure", (state == "unknown" || state == "unavailable") {
                guard rows.isEmpty else {
                    valid = false
                    values[port] = PortFact(state: .invalid, queryState: .failure,
                                            listeners: rows, invalid: true)
                    continue
                }
                fact = PortFact(state: .unavailable, queryState: .failure, listeners: rows)
            } else {
                valid = false
                fact = PortFact(state: .invalid, queryState: .failure, listeners: rows, invalid: true)
            }
            values[port] = fact
        }
        if values.count != 2 { valid = false }
        return (values, valid)
    }

    private static func parseBootState(_ raw: Any?, currentBootUUID: String?) -> BootState {
        guard let raw, !(raw is NSNull) else { return .unavailable }
        guard let value = raw as? String, let observed = UUID(uuidString: value) else { return .invalid }
        guard let currentBootUUID, let current = UUID(uuidString: currentBootUUID) else { return .unavailable }
        return observed == current ? .matches : .mismatch
    }

    private static func stampState(observed: Int64?, now: Int64?, limit: Int64,
                                   invalidWhenMissing: Bool) -> FreshnessState {
        guard let observed else { return invalidWhenMissing ? .invalid : .unavailable }
        guard let now else { return .unavailable }
        guard observed > 0, now > 0 else { return .invalid }
        let (age, overflow) = now.subtractingReportingOverflow(observed)
        guard !overflow else { return .invalid }
        if age < 0 { return .future }
        return age <= limit ? .fresh : .stale
    }

    private static func failureKey(_ error: Error) -> String {
        if let failure = error as? EnvironmentCheckFailure,
           case let .observation(key) = failure { return key }
        return "root_observer_unavailable"
    }

    private static func processIdentity(_ pid: Int32) throws -> (sec: UInt64, usec: UInt64, path: String) {
        var sec: UInt64 = 0, usec: UInt64 = 0
        var bytes = [CChar](repeating: 0, count: 4096)
        let good = bytes.withUnsafeMutableBufferPointer { buffer in
            cngObserverProcessIdentity(pid, &sec, &usec, buffer.baseAddress!, UInt32(buffer.count))
        }
        guard good == 1 else { throw EnvironmentCheckFailure.observation("ingress_process_identity") }
        return (sec, usec, String(cString: bytes))
    }

    private static func fresh(wall: Int64, mono: Int64) throws {
        var now = timespec()
        guard clock_gettime(CLOCK_MONOTONIC, &now) == 0 else {
            throw EnvironmentCheckFailure.observation("monotonic_clock")
        }
        let monoNow = Int64(now.tv_sec) * 1_000_000_000 + Int64(now.tv_nsec)
        let wallNow = Int64(Date().timeIntervalSince1970 * 1000)
        guard wall > 0, mono > 0,
              (0...maxAgeMS).contains(wallNow - wall),
              (0...(maxAgeMS * 1_000_000)).contains(monoNow - mono) else {
            throw EnvironmentCheckFailure.observation("root_observer_stale")
        }
    }

    private static func monotonicNowNS() -> Int64? {
        var now = timespec()
        guard clock_gettime(CLOCK_MONOTONIC, &now) == 0 else { return nil }
        return Int64(now.tv_sec) * 1_000_000_000 + Int64(now.tv_nsec)
    }

    private static func bootUUID() throws -> String {
        var count = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &count, nil, 0) == 0,
              (2...128).contains(count) else {
            throw EnvironmentCheckFailure.observation("boot_uuid")
        }
        var bytes = [CChar](repeating: 0, count: count)
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &count, nil, 0) == 0 else {
            throw EnvironmentCheckFailure.observation("boot_uuid")
        }
        return String(cString: bytes)
    }

    private static func secureRead() throws -> Data {
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw EnvironmentCheckFailure.observation("root_observer_path") }
        defer { close(fd) }
        try verify(fd: fd, directory: true)
        for (index, name) in path.enumerated() {
            let last = index == path.count - 1
            let next = name.withCString { openat(fd, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
                (last ? O_NONBLOCK : O_DIRECTORY)) }
            guard next >= 0 else { throw EnvironmentCheckFailure.observation("root_observer_path") }
            do { try verify(fd: next, directory: !last) }
            catch { close(next); throw error }
            close(fd)
            fd = next
        }
        var before = stat()
        guard fstat(fd, &before) == 0 else {
            throw EnvironmentCheckFailure.observation("root_observer_metadata")
        }
        var data = Data()
        var bytes = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(fd, &bytes, bytes.count)
            guard count >= 0 else { throw EnvironmentCheckFailure.observation("root_observer_read") }
            if count == 0 { break }
            data.append(contentsOf: bytes[0..<count])
            guard data.count <= maxBytes else { throw EnvironmentCheckFailure.observation("root_observer_size") }
        }
        try verify(fd: fd, directory: false)
        var after = stat()
        guard fstat(fd, &after) == 0, data.count == before.st_size,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw EnvironmentCheckFailure.observation("root_observer_changed")
        }
        return data
    }

    private static func verify(fd: Int32, directory: Bool) throws {
        var info = stat()
        guard fstat(fd, &info) == 0,
              info.st_uid == 0, (info.st_mode & 0o022) == 0,
              (info.st_mode & S_IFMT) == (directory ? S_IFDIR : S_IFREG),
              directory || (info.st_nlink == 1 && info.st_size > 0 && info.st_size <= maxBytes) else {
            throw EnvironmentCheckFailure.observation("root_observer_metadata")
        }
    }
}

@_silgen_name("cng_observer_process_identity")
private func cngObserverProcessIdentity(_ pid: Int32, _ sec: UnsafeMutablePointer<UInt64>,
    _ usec: UnsafeMutablePointer<UInt64>, _ path: UnsafeMutablePointer<CChar>,
    _ size: UInt32) -> Int32
