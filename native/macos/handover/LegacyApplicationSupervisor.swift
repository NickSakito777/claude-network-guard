import AppKit
import Foundation
import LegacyProcessShim

struct LegacyScope: Codable, Equatable {
    let pathPrefix: String
    let codeRequirement: String
}

struct LegacyTarget: Codable, Equatable {
    let targetID: String
    let bundlePath: String
    let executablePath: String
    let arguments: [String]
    let scopes: [LegacyScope]
}

struct LegacyStopReceipt {
    let confirmedExited: [ProcessBirth]
    let checkedAt: Date
}

enum LegacySupervisorError: Error, Equatable {
    case invalidSealedTarget, unknownTarget, inspectionIncomplete
    case inspectionFailure(InventoryFailure)
    case signatureMismatch(Int32), processChanged(Int32), stillRunning
    case cleanupLaunchInFlight, cleanupProcessStillRunning
    case gateNotLocked, gateNotReady, launchFailed, launchIdentityMismatch, signalFailed(Int32, Int32)
}

enum PostSignatureIdentity: Equatable {
    case exited
    case sameLiveProcess
    case changedProcess
    case unavailable
}

// Targets are loaded from root-owned sealed activation data by the caller;
// UI fields never reach this initializer. No global process-name matching.
final class LegacyApplicationSupervisor {
    private let targets: [String: LegacyTarget]
    private let protectedScopes: [LegacyScope]
    var protectedScopePaths: [String] { protectedScopes.map(\.pathPrefix) }
    private let flightLock = NSLock()
    private var inFlight: Set<UUID> = []

    struct Operations {
        let dispatchMain: (@escaping () -> Void) -> Void
        let openApplication: (LegacyTarget, @escaping (Result<Int32, Error>) -> Void) -> Void
        let snapshot: (Int32) throws -> ProcessBirth
        let signatureMatches: (Int32, String) -> Bool
        let physicalPath: (String) -> Bool
        let currentUID: UInt32
        let inventory: ([LegacyScope]) throws -> [(ProcessBirth, LegacyScope)]
        let signalIfSame: (ProcessBirth, LegacyScope, Int32) -> Int32
    }

    private func productionOperations() -> Operations {
        Operations(dispatchMain: { work in DispatchQueue.main.async(execute: work) },
            openApplication: { target, completion in
                let configuration = NSWorkspace.OpenConfiguration()
                configuration.arguments = target.arguments
                NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: target.bundlePath),
                    configuration: configuration) { running, error in
                    if let error { completion(.failure(error)) }
                    else if let running { completion(.success(running.processIdentifier)) }
                    else { completion(.failure(LegacySupervisorError.launchFailed)) }
                }
            }, snapshot: { [self] pid in
                var record = lg_process()
                guard lg_process_snapshot(pid, &record) == 0 else {
                    throw LegacySupervisorError.launchIdentityMismatch
                }
                return birth(record)
            }, signatureMatches: { lg_signature_matches($0, $1) == 0 },
            physicalPath: Self.physical, currentUID: getuid(),
            inventory: { [self] in try matchingProcesses(in: $0) },
            signalIfSame: Self.signalIfSame)
    }

    private static func signalIfSame(_ process: ProcessBirth, _ scope: LegacyScope, _ signal: Int32) -> Int32 {
        var pin = lg_process()
        pin.pid = process.pid; pin.uid = process.uid
        pin.birth_sec = process.startSeconds; pin.birth_usec = process.startMicroseconds
        _ = process.executable.withCString { path in
            strncpy(&pin.path.0, path, MemoryLayout.size(ofValue: pin.path) - 1)
        }
        return scope.codeRequirement.withCString { lg_signal_if_same(&pin, $0, signal) }
    }

    private func beginFlight() -> UUID {
        let id = UUID()
        flightLock.lock(); inFlight.insert(id); flightLock.unlock()
        return id
    }
    private func endFlight(_ id: UUID) {
        flightLock.lock(); inFlight.remove(id); flightLock.unlock()
    }
    private var hasInFlight: Bool {
        flightLock.lock(); defer { flightLock.unlock() }
        return !inFlight.isEmpty
    }

    private static func lexical(_ path: String, trailingSlash: Bool) -> Bool {
        guard path.hasPrefix("/"), !path.contains("//"), !path.contains("\0"),
              !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) else {
            return false
        }
        return trailingSlash ? path.hasSuffix("/") : !path.hasSuffix("/")
    }

    private static func physical(_ path: String) -> Bool {
        guard let resolved = realpath(path, nil) else { return false }
        defer { free(resolved) }
        return String(cString: resolved) == String(path.dropLast(path.hasSuffix("/") ? 1 : 0))
    }

    init(targets values: [LegacyTarget], managerLaunchOnly: Bool = false) throws {
        guard !values.isEmpty, let account = getpwuid(getuid()),
              let directory = account.pointee.pw_dir else {
            throw LegacySupervisorError.invalidSealedTarget
        }
        let home = String(cString: directory)
        guard Self.lexical(home, trailingSlash: false) else {
            throw LegacySupervisorError.invalidSealedTarget
        }
        let claudeRoot = "/Applications/Claude.app/Contents/"
        let managerRoot = "/Applications/AdsPower Global.app/Contents/"
        let sunBrowserRoot = home + "/Library/Application Support/adspower_global/cwd_global/"
        var result: [String: LegacyTarget] = [:]
        for target in values {
            guard ["claude", "adspower"].contains(target.targetID),
                  result[target.targetID] == nil,
                  Self.lexical(target.bundlePath, trailingSlash: false),
                  Self.lexical(target.executablePath, trailingSlash: false),
                  target.bundlePath.hasSuffix(".app"),
                  target.executablePath.hasPrefix(target.bundlePath + "/Contents/MacOS/"),
                  !target.scopes.isEmpty,
                  target.scopes.allSatisfy({ Self.lexical($0.pathPrefix, trailingSlash: true) &&
                     !$0.codeRequirement.isEmpty && !$0.codeRequirement.contains("\0") &&
                     $0.codeRequirement.utf8.count <= 2048 }) else {
                throw LegacySupervisorError.invalidSealedTarget
            }
            if target.targetID == "claude" {
                guard target.bundlePath == "/Applications/Claude.app",
                      target.scopes.count == 1,
                      Set(target.scopes.map(\.pathPrefix)) == Set([claudeRoot]),
                      target.arguments == ["--proxy-server=http://127.0.0.1:17897",
                                            "--disable-quic"] else {
                    throw LegacySupervisorError.invalidSealedTarget
                }
            } else {
                guard target.bundlePath == "/Applications/AdsPower Global.app",
                      target.scopes.count == 2,
                      Set(target.scopes.map(\.pathPrefix)) == Set([managerRoot, sunBrowserRoot]),
                      target.arguments.isEmpty else {
                    throw LegacySupervisorError.invalidSealedTarget
                }
            }
            guard target.scopes.contains(where: { target.executablePath.hasPrefix($0.pathPrefix) }) else {
                throw LegacySupervisorError.invalidSealedTarget
            }
            result[target.targetID] = target
        }
        targets = result
        let scopes = values.flatMap(\.scopes)
        protectedScopes = managerLaunchOnly
            ? scopes.filter { $0.pathPrefix != managerRoot }
            : scopes
    }

    private func birth(_ value: lg_process) -> ProcessBirth {
        var raw = value.path
        let path = withUnsafeBytes(of: &raw) { bytes -> String in
            let sequence = bytes.prefix { $0 != 0 }
            return String(decoding: sequence, as: UTF8.self)
        }
        return ProcessBirth(pid: value.pid, uid: value.uid,
                            startSeconds: value.birth_sec,
                            startMicroseconds: value.birth_usec, executable: path)
    }

    // ps comm is discovery only. It never supplies a process identity, launch
    // permission, or a PID eligible for a signal.
    private var inventoryTarget: InventoryFailure.Target { targets["claude"] != nil ? .claude : .sunbrowser }

    private func inspection(_ step: InventoryFailure.Step, pid: Int32? = nil, rc: Int32? = nil,
                            detail: lg_inspection = lg_inspection(), identity: Int32? = nil,
                            discoveryBytes: Int32? = nil) -> LegacySupervisorError {
        var value = InventoryFailure(target: inventoryTarget, step: step, pid: pid, rc: rc,
            call: detail.call, raw: detail.result, os: detail.error, value: detail.value, identity: identity)
        if let bytes = discoveryBytes { value.ps = 5; value.psBytes = bytes; value.psFlags = 15 }
        return .inspectionFailure(value)
    }

    private func candidatePathFromPS(_ pid: pid_t) throws -> (path: String, bytes: Int32) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-p", String(pid), "-o", "comm="]
        process.environment = ["PATH": "/usr/bin:/bin", "LC_ALL": "C"]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }
        func failure(_ step: InventoryFailure.Step, state: Int32, code: Int64 = 0,
                     bytes: Int32 = 0, flags: Int32 = 0) -> LegacySupervisorError {
            var value = InventoryFailure(target: inventoryTarget, step: step, pid: pid)
            value.ps = state; value.psCode = code; value.psBytes = bytes; value.psFlags = flags
            return .inspectionFailure(value)
        }
        do { try process.run() }
        catch {
            let error = error as NSError
            let state: Int32 = error.domain == NSPOSIXErrorDomain ? 1 : error.domain == NSCocoaErrorDomain ? 2 : 3
            throw failure(.psRun, state: state, code: Int64(error.code))
        }
        output.fileHandleForWriting.closeFile()
        if finished.wait(timeout: .now() + 1) == .timedOut {
            if process.isRunning { process.terminate() }
            throw failure(.psTimeout, state: 4)
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let bytes = Int32(clamping: data.count)
        let status = process.terminationStatus
        var flags: Int32 = status == 0 ? 1 : 0
        if flags == 1 && data.count <= 8192 { flags |= 2 }
        let decoded = flags == 3 ? String(data: data, encoding: .utf8) : nil
        if decoded != nil { flags |= 4 }
        guard let text = decoded else {
            throw failure(.psResult, state: 5, code: Int64(status), bytes: bytes, flags: flags)
        }
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, !value.contains("\n"), !value.contains("\0") else {
            throw failure(.psShape, state: 6, code: Int64(status), bytes: bytes, flags: flags)
        }
        return (value, bytes)
    }

    static func discoveredCandidate(_ path: String, scopes: [LegacyScope]) -> Bool {
        scopes.contains { path.hasPrefix($0.pathPrefix) }
    }

    static func postSignatureIdentity(_ statusResult: Int32) -> PostSignatureIdentity {
        switch statusResult {
        case ESRCH: return .exited
        case 0: return .sameLiveProcess
        case ESTALE: return .changedProcess
        default: return .unavailable
        }
    }

    // Internal for isolated fixtures; production callers still use only sealed scopes.
    func matchingProcesses(in inspectedScopes: [LegacyScope]) throws -> [(ProcessBirth, LegacyScope)] {
        guard inspectedScopes.allSatisfy({ Self.physical($0.pathPrefix) }) else {
            throw inspection(.scope)
        }
        var pids = [pid_t](repeating: 0, count: 8192)
        var listDetail = lg_inspection()
        let count = pids.withUnsafeMutableBufferPointer {
            lg_list_pids_observed($0.baseAddress, Int32($0.count), &listDetail)
        }
        guard count >= 0 && count < pids.count else {
            throw inspection(.list, rc: count, detail: listDetail)
        }
        var selected: [(ProcessBirth, LegacyScope)] = []
        for pid in pids.prefix(Int(count)) where pid > 0 {
            var inventory = lg_status(), statusDetail = lg_inspection()
            let inventoryResult = lg_process_status_observed(pid, &inventory, &statusDetail)
            if inventoryResult == ESRCH { continue }
            guard inventoryResult == 0 else { throw inspection(.status, pid: pid, rc: inventoryResult, detail: statusDetail) }
            if inventory.uid != getuid() { continue }
            if inventory.zombie != 0 { continue }
            var record = lg_process(), detail = lg_inspection()
            let result = lg_process_snapshot_observed(pid, &record, &detail)
            if result == ESRCH {
                var expected = lg_process()
                expected.pid = pid; expected.uid = inventory.uid
                expected.birth_sec = inventory.birth_sec
                expected.birth_usec = inventory.birth_usec
                var after = lg_status()
                let statusResult = lg_process_status(pid, &after)
                let identityResult = lg_process_status_identity(&expected, statusResult, &after)
                switch Self.postSignatureIdentity(identityResult) {
                case .exited: continue
                case .changedProcess: throw LegacySupervisorError.processChanged(pid)
                case .sameLiveProcess, .unavailable:
                    throw inspection(.snapshotGone, pid: pid, rc: result, detail: detail, identity: identityResult)
                }
            }
            if result == EACCES {
                let discovery: (path: String, bytes: Int32)
                do { discovery = try candidatePathFromPS(pid) }
                catch LegacySupervisorError.inspectionFailure(var evidence) {
                    // `ps` is discovery only. If it fails, recheck the PID
                    // against the identity captured before the snapshot so a
                    // process that exited during discovery is not reported as
                    // an inspection failure. A live, reused, or unreadable PID
                    // still fails closed, retaining the original `ps` detail.
                    var expected = lg_process()
                    expected.pid = pid; expected.uid = inventory.uid
                    expected.birth_sec = inventory.birth_sec
                    expected.birth_usec = inventory.birth_usec
                    var after = lg_status()
                    let afterStatus = lg_process_status(pid, &after)
                    let identityResult = lg_process_status_identity(&expected, afterStatus, &after)
                    evidence.identity = identityResult
                    if Self.postSignatureIdentity(identityResult) == .exited { continue }
                    evidence.rc = result; evidence.call = detail.call; evidence.raw = detail.result
                    evidence.os = detail.error; evidence.value = detail.value
                    throw LegacySupervisorError.inspectionFailure(evidence)
                }
                var after = lg_status()
                let afterStatus = lg_process_status(pid, &after)
                if afterStatus == ESRCH { continue }
                guard afterStatus == 0,
                      after.uid == inventory.uid,
                      after.birth_sec == inventory.birth_sec,
                      after.birth_usec == inventory.birth_usec else {
                    throw inspection(.pathStatus, pid: pid, rc: afterStatus, detail: detail,
                        identity: afterStatus == 0 ? ESTALE : afterStatus, discoveryBytes: discovery.bytes)
                }
                if Self.discoveredCandidate(discovery.path, scopes: inspectedScopes) {
                    // Discovery cannot supply identity or signal authority.
                    throw inspection(.pathCandidate, pid: pid, rc: result, detail: detail,
                        identity: 0, discoveryBytes: discovery.bytes)
                }
                continue
            }
            guard result == 0 else { throw inspection(.snapshot, pid: pid, rc: result, detail: detail) }
            guard record.uid == getuid() else { continue }
            let process = birth(record)
            guard let scope = inspectedScopes.first(where: {
                process.executable.hasPrefix($0.pathPrefix)
            }) else { continue }
            guard pid != getpid() else { throw inspection(.selfPID, pid: pid) }
            guard Self.physical(process.executable) else { throw inspection(.physical, pid: pid) }
            var signatureDetail = lg_inspection()
            let signatureResult = lg_signature_matches_observed(pid, scope.codeRequirement, &signatureDetail)
            if signatureResult != 0 {
                var after = lg_status()
                let statusResult = lg_process_status(pid, &after)
                let identityResult = lg_process_status_identity(&record, statusResult, &after)
                switch Self.postSignatureIdentity(identityResult) {
                case .exited: continue
                case .sameLiveProcess: throw LegacySupervisorError.signatureMismatch(pid)
                case .changedProcess: throw LegacySupervisorError.processChanged(pid)
                case .unavailable:
                    throw inspection(.signatureStatus, pid: pid, rc: signatureResult, detail: signatureDetail, identity: identityResult)
                }
            }
            var again = lg_process(), finalDetail = lg_inspection()
            let finalSnapshotResult = lg_process_snapshot_observed(pid, &again, &finalDetail)
            if finalSnapshotResult == ESRCH {
                var after = lg_status()
                let statusResult = lg_process_status(pid, &after)
                let identityResult = lg_process_status_identity(&record, statusResult, &after)
                switch Self.postSignatureIdentity(identityResult) {
                case .exited: continue
                case .changedProcess: throw LegacySupervisorError.processChanged(pid)
                case .sameLiveProcess, .unavailable:
                    throw inspection(.finalGone, pid: pid, rc: finalSnapshotResult, detail: finalDetail, identity: identityResult)
                }
            }
            guard finalSnapshotResult == 0 else {
                throw inspection(.finalSnapshot, pid: pid, rc: finalSnapshotResult, detail: finalDetail)
            }
            guard birth(again) == process else { throw LegacySupervisorError.processChanged(pid) }
            selected.append((process, scope))
        }
        return selected
    }

    func isQuiescent(operations: Operations? = nil) throws -> Bool {
        guard !hasInFlight else { return false }
        let operations = operations ?? productionOperations()
        let empty = try operations.inventory(protectedScopes).isEmpty
        return empty && !hasInFlight
    }

    func isTargetRunning(targetID: String, operations: Operations? = nil) throws -> Bool {
        let operations = operations ?? productionOperations()
        guard let target = targets[targetID],
              let scope = target.scopes.first(where: {
                  target.executablePath.hasPrefix($0.pathPrefix)
              }) else { throw LegacySupervisorError.unknownTarget }
        return try operations.inventory([scope]).contains {
            $0.0.executable == target.executablePath
        }
    }

    // The caller must obtain lock confirmation from its trusted native gate
    // observer. The lock readback is invoked again immediately before signals.
    func stopAfterGateLocked(lockReadback: () throws -> Bool,
                             operations: Operations? = nil) throws -> LegacyStopReceipt {
        let operations = operations ?? productionOperations()
        guard try lockReadback() else { throw LegacySupervisorError.gateNotLocked }
        guard !hasInFlight else { throw LegacySupervisorError.cleanupLaunchInFlight }
        var pass: UInt32 = 0
        func inventory(_ phase: InventoryFailure.Phase) throws -> [(ProcessBirth, LegacyScope)] {
            pass = pass == UInt32.max ? pass : pass + 1
            do { return try operations.inventory(protectedScopes) }
            catch LegacySupervisorError.inspectionFailure(var detail) {
                detail.target = inventoryTarget; detail.phase = phase; detail.pass = pass
                throw LegacySupervisorError.inspectionFailure(detail)
            }
        }
        let selected = try inventory(.beforeTerm)
        for (process, scope) in selected {
            guard try lockReadback() else { throw LegacySupervisorError.gateNotLocked }
            let result = operations.signalIfSame(process, scope, SIGTERM)
            guard result == 0 || result == ESRCH else {
                throw LegacySupervisorError.signalFailed(process.pid, result)
            }
        }
        let end = Date().addingTimeInterval(1)
        while Date() < end {
            if try inventory(.termWait).isEmpty { break }
            Thread.sleep(forTimeInterval: 0.05)
        }
        for (process, scope) in try inventory(.beforeKill) {
            guard selected.contains(where: { $0.0 == process && $0.1 == scope }),
                  try lockReadback() else { throw LegacySupervisorError.processChanged(process.pid) }
            let result = operations.signalIfSame(process, scope, SIGKILL)
            guard result == 0 || result == ESRCH else {
                throw LegacySupervisorError.signalFailed(process.pid, result)
            }
        }
        let final = try inventory(.final)
        guard final.isEmpty else { throw LegacySupervisorError.cleanupProcessStillRunning }
        guard !hasInFlight else { throw LegacySupervisorError.cleanupLaunchInFlight }
        return LegacyStopReceipt(confirmedExited: selected.map(\.0), checkedAt: Date())
    }

    // NSWorkspace may return an externally started process. A stable identity
    // is a target fact, not evidence that this call created or owns that PID.
    func launch(targetID: String, gateReadback: @escaping () throws -> Bool,
                operations: Operations? = nil,
                completion: @escaping (Result<ProcessBirth, Error>) -> Void) {
        guard let target = targets[targetID] else {
            completion(.failure(LegacySupervisorError.unknownTarget)); return
        }
        let operations = operations ?? productionOperations()
        let flight = beginFlight()
        func finish(_ result: Result<ProcessBirth, Error>) {
            endFlight(flight)
            completion(result)
        }
        operations.dispatchMain { [self] in
            do {
                guard try gateReadback() else { throw LegacySupervisorError.gateNotReady }
                if protectedScopes.contains(where: { target.executablePath.hasPrefix($0.pathPrefix) }) {
                    guard try !isTargetRunning(targetID: targetID, operations: operations) else {
                        throw LegacySupervisorError.stillRunning
                    }
                }
                guard operations.physicalPath(target.bundlePath),
                      operations.physicalPath(target.executablePath) else {
                    throw LegacySupervisorError.invalidSealedTarget
                }
                guard try gateReadback() else { throw LegacySupervisorError.gateNotReady }
            } catch { finish(.failure(error)); return }
            operations.openApplication(target) { reply in
                do {
                    let pid = try reply.get()
                    let process = try operations.snapshot(pid)
                    guard process.valid, process.pid == pid, process.uid == operations.currentUID,
                          process.executable == target.executablePath,
                          let scope = target.scopes.first(where: { process.executable.hasPrefix($0.pathPrefix) }),
                          operations.signatureMatches(pid, scope.codeRequirement),
                          try operations.snapshot(pid) == process else {
                        throw LegacySupervisorError.launchIdentityMismatch
                    }
                    guard try gateReadback() else { throw LegacySupervisorError.gateNotReady }
                    finish(.success(process))
                } catch {
                    // All stop authority stays in stopAfterGateLocked's selected
                    // target scope and fresh locked-Gate/identity readbacks.
                    finish(.failure(error))
                }
            }
        }
    }
}
