import Darwin
import Dispatch
import Foundation
import LegacyProcessShim
import Security

enum GateHelperHostError: Error, Equatable {
    case invalidBundle, spawn(Int32), processIdentity, signature, socket(Int32)
    case protocolFailure, timeout, rejected(GateHelperRejectReason), closed
}

struct GateHelperVerifiedProcess: Equatable {
    let pid: Int32
    let uid: UInt32
    let birthSeconds: Int64
    let birthMicroseconds: Int32
    let executablePath: String
    let codeRequirement: String
}

// The host owns only the authenticated control channel. NativeGate descriptors
// are created and retained exclusively inside the standalone helper process.
final class GateHelperHost {
    static let protocolVersion: UInt16 = 1
    static let controlFD: Int32 = 3
    static let helperRelativePath = "Contents/Helpers/GuardGateHelper"
    static let helperRequirement = "identifier \"local.fox.guard.gatehelper\""
    static let hostRequirement = "identifier \"local.fox.guard\""

    private let lock = NSRecursiveLock()
    private let channel: GateHelperChannel
    private let helperPID: Int32
    private let helperIdentity: GateHelperVerifiedProcess
    private let nonce: [UInt8]
    private let epoch: UInt64
    private let onFault: (String) -> Void
    private var heartbeatTimer: DispatchSourceTimer?
    private var controlChannelClosed = false
    private var nextSequence: UInt64 = 3
    private var generation: UInt64 = 0
    private var prepared = false
    private var terminal = false
    private var exitWasObserved = false
    private var cached: [GateHelperTarget: GateHelperSnapshot] = [:]

    let helperExecutablePath: String
    var processIdentity: GateHelperVerifiedProcess { helperIdentity }
    var helperExitConfirmed: Bool { withLock { exitWasObserved } }

    init(bundleURL: URL = Bundle.main.bundleURL,
         onFault: @escaping (String) -> Void = { _ in }) throws {
        self.onFault = onFault
        let helperURL = bundleURL.appendingPathComponent("Contents")
            .appendingPathComponent("Helpers").appendingPathComponent("GuardGateHelper")
        let helperPath = helperURL.path
        guard Self.isRegularExecutable(helperPath),
              Self.physicalPath(helperPath),
              Self.processIdentity(pid: getpid(), expectedPath: Bundle.main.executableURL?.path,
                                   requirement: Self.hostRequirement) != nil else {
            throw GateHelperHostError.invalidBundle
        }
        helperExecutablePath = helperPath

        var descriptors: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else {
            throw GateHelperHostError.socket(errno)
        }
        let hostFD = descriptors[0]
        let childFD = descriptors[1]
        // This SDK has no atomic SOCK_CLOEXEC option for socketpair. Mark the
        // ends immediately; the independent helper heartbeat watchdog does not
        // rely on EOF for host-loss closure while the inheritance audit remains open.
        guard Self.setCloseOnExec(hostFD) else {
            let code = errno
            close(hostFD); close(childFD)
            throw GateHelperHostError.socket(code)
        }
        guard Self.setCloseOnExec(childFD) else {
            let code = errno
            close(hostFD); close(childFD)
            throw GateHelperHostError.socket(code)
        }
        var spawned: pid_t = -1
        let spawnCode = helperPath.withCString {
            lg_spawn_controlled_helper($0, childFD, Self.controlFD, &spawned)
        }
        close(childFD)
        guard spawnCode == 0, spawned > 1 else {
            close(hostFD)
            throw GateHelperHostError.spawn(spawnCode == 0 ? ECHILD : spawnCode)
        }
        helperPID = Int32(spawned)

        do {
            let identity = try Self.waitForIdentity(pid: Int32(spawned), path: helperPath,
                                                    requirement: Self.helperRequirement)
            helperIdentity = identity
            channel = try GateHelperChannel(descriptor: hostFD)
            nonce = try Self.randomBytes(count: 32)
            epoch = try Self.randomEpoch()

            try channel.send(GateHelperMessage(version: Self.protocolVersion,
                nonce: nonce, epoch: epoch, generation: 0, sequence: 1, kind: .hello))
            let ready = try channel.receive()
            guard ready.version == Self.protocolVersion,
                  ready.kind == .ready, ready.nonce == nonce, ready.epoch == epoch,
                  ready.generation == 0, ready.sequence == 1,
                  ready.helperProcess == GateHelperProcessIdentity(pid: Int32(spawned), uid: getuid()) else {
                throw GateHelperHostError.protocolFailure
            }
            try Self.revalidate(identity)

            let host = GateHelperProcessIdentity(pid: getpid(), uid: getuid())
            try channel.send(GateHelperMessage(version: Self.protocolVersion,
                nonce: nonce, epoch: epoch, generation: 0, sequence: 2,
                kind: .initialize, hostProcess: host,
            policyVersion: Self.protocolVersion))
            let initialized = try channel.receive()
            guard initialized.version == Self.protocolVersion,
                  initialized.kind == .initialized, initialized.sequence == 2,
                  initialized.generation == 0,
                  initialized.nonce == nonce, initialized.epoch == epoch,
                  initialized.targetSnapshots?.count == GateHelperTarget.allCases.count,
                  initialized.targetSnapshots?.allSatisfy({
                      !$0.snapshot.bound && !$0.snapshot.open && $0.snapshot.activePairs == 0 &&
                      $0.snapshot.pending == 0 && $0.snapshot.generation == 0
                  }) == true else {
                throw GateHelperHostError.protocolFailure
            }
            cache(initialized.targetSnapshots)
            startHeartbeat()
        } catch {
            close(hostFD)
            _ = Self.waitForExit(pid: Int32(spawned), timeoutNanoseconds: 4_000_000_000)
            throw error
        }
    }

    func endpoint(_ target: GateHelperTarget) -> GateHelperTargetEndpoint {
        GateHelperTargetEndpoint(host: self, target: target)
    }

    fileprivate func prepareClosed() throws {
        try withLock {
            if prepared {
                guard try snapshots().allSatisfy({ $0.snapshot.bound && !$0.snapshot.open &&
                                                   $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0 }) else {
                    throw GateHelperHostError.protocolFailure
                }
                return
            }
            let response = try request(.prepare, generation: generation, expected: .prepared)
            let states = try requireSnapshots(response)
            guard states.count == GateHelperTarget.allCases.count,
                  states.allSatisfy({ $0.snapshot.bound && !$0.snapshot.open &&
                                      $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0 }) else {
                throw GateHelperHostError.protocolFailure
            }
            prepared = true
            cache(states)
        }
    }

    fileprivate func open(_ generation: UInt64, target: GateHelperTarget) throws {
        try withLock {
            guard prepared, !terminal, generation > self.generation else {
                throw GateHelperHostError.protocolFailure
            }
            let response = try request(.open, target: target, generation: generation,
                                       expected: .opened)
            let states = try requireSnapshots(response)
            guard states.first(where: { $0.target == target })?.snapshot.open == true,
                  states.filter({ $0.snapshot.open }).allSatisfy({
                      $0.snapshot.generation == generation && $0.snapshot.bound
                  }) else {
                throw GateHelperHostError.protocolFailure
            }
            self.generation = generation
            cache(states)
        }
    }

    fileprivate func renew(_ generation: UInt64) throws {
        try withLock {
            guard prepared, !terminal, generation == self.generation else {
                throw GateHelperHostError.protocolFailure
            }
            let response = try request(.renew, generation: generation, expected: .renewed)
            let states = try requireSnapshots(response)
            guard states.contains(where: { $0.snapshot.open }) &&
                  states.filter({ $0.snapshot.open }).allSatisfy({
                      $0.snapshot.generation == generation && $0.snapshot.bound
                  }) else { throw GateHelperHostError.protocolFailure }
            cache(states)
        }
    }

    fileprivate func status(_ target: GateHelperTarget) throws -> GateHelperSnapshot {
        try withLock {
            guard !terminal else { throw GateHelperHostError.closed }
            let response = try request(.status, generation: generation, expected: .status)
            let states = try requireSnapshots(response)
            cache(states)
            guard let snapshot = states.first(where: { $0.target == target })?.snapshot else {
                throw GateHelperHostError.protocolFailure
            }
            return snapshot
        }
    }

    fileprivate func operationFailed() {
        onFault("gate_helper_session")
        failClosed()
    }

    fileprivate func lockAll() throws {
        try withLock {
            guard !terminal else { return }
            let response = try request(.lock, generation: generation, expected: .locked,
                                       timeoutMilliseconds: 4_500)
            let states = try requireSnapshots(response)
            guard states.count == GateHelperTarget.allCases.count,
                  states.allSatisfy({ $0.snapshot.bound && !$0.snapshot.open &&
                                      $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0 }) else {
                throw GateHelperHostError.protocolFailure
            }
            cache(states)
        }
    }

    fileprivate func revokeAndWait() throws {
        try withLock {
            guard !terminal else { return }
            stopHeartbeat()
            let response = try request(.revoke, generation: generation, expected: .revoked,
                                       timeoutMilliseconds: 4_500)
            let states = try requireSnapshots(response)
            guard states.allSatisfy({ !$0.snapshot.bound && !$0.snapshot.open &&
                                      $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0 }) else {
                throw GateHelperHostError.protocolFailure
            }
            cache(states)
            let status = Self.waitForExit(pid: helperPID, timeoutNanoseconds: 4_500_000_000)
            guard status == 0 else { throw GateHelperHostError.timeout }
            exitWasObserved = true
            terminal = true
        }
    }

    private func snapshots() throws -> [GateHelperTargetSnapshot] {
        let response = try request(.status, generation: generation, expected: .status)
        return try requireSnapshots(response)
    }

    private func request(_ kind: GateHelperKind, target: GateHelperTarget? = nil,
                         generation: UInt64, expected: GateHelperKind,
                         timeoutMilliseconds: Int32 = 1_200) throws -> GateHelperMessage {
        guard !terminal, nextSequence < UInt64.max else { throw GateHelperHostError.closed }
        let sequence = nextSequence
        let message = GateHelperMessage(version: Self.protocolVersion,
            nonce: nonce, epoch: epoch, generation: generation, sequence: sequence,
            kind: kind, target: target)
        do {
            try channel.send(message)
            let response = try channel.receive(timeoutMilliseconds: timeoutMilliseconds)
            guard response.version == Self.protocolVersion,
                  response.nonce == nonce, response.epoch == epoch,
                  response.sequence == sequence,
                  response.generation == generation else { throw GateHelperHostError.protocolFailure }
            nextSequence += 1
            guard response.kind == expected else {
                if response.kind == .rejected, let reason = response.reason {
                    throw GateHelperHostError.rejected(reason)
                }
                throw GateHelperHostError.protocolFailure
            }
            return response
        } catch let error as GateHelperHostError { throw error }
        catch let error as GateHelperIOError {
            if case .closed = error { terminal = true; throw GateHelperHostError.closed }
            if case .timedOut = error { throw GateHelperHostError.timeout }
            throw GateHelperHostError.protocolFailure
        } catch { throw GateHelperHostError.protocolFailure }
    }

    private func requireSnapshots(_ message: GateHelperMessage) throws -> [GateHelperTargetSnapshot] {
        guard let states = message.targetSnapshots,
              states.count == GateHelperTarget.allCases.count,
              Set(states.map(\.target)) == Set(GateHelperTarget.allCases) else {
            throw GateHelperHostError.protocolFailure
        }
        try Self.revalidate(helperIdentity)
        return states
    }

    private func heartbeat() throws {
        try withLock {
            guard !terminal else { throw GateHelperHostError.closed }
            let response = try request(.heartbeat, generation: generation, expected: .alive)
            let states = try requireSnapshots(response)
            cache(states)
        }
    }

    private func startHeartbeat() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "local.fox.guard.gate-helper-heartbeat"))
        timer.schedule(deadline: .now() + .milliseconds(500), repeating: .milliseconds(500),
                       leeway: .milliseconds(50))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            do { try self.heartbeat() }
            catch {
                self.onFault("gate_helper_heartbeat")
                self.failClosed()
            }
        }
        heartbeatTimer = timer
        timer.resume()
    }

    private func stopHeartbeat() {
        heartbeatTimer?.setEventHandler {}
        heartbeatTimer?.cancel()
        heartbeatTimer = nil
    }

    fileprivate func failClosed() {
        withLock {
            stopHeartbeat()
            guard !terminal else { return }
            do { try lockAll() } catch { }
            do { try revokeAndWait() } catch {
                terminal = true
                closeControlChannel()
            }
        }
    }

    private func closeControlChannel() {
        guard !controlChannelClosed else { return }
        controlChannelClosed = true
        close(channel.descriptor)
    }

    private func cache(_ states: [GateHelperTargetSnapshot]?) {
        guard let states else { return }
        cached = Dictionary(uniqueKeysWithValues: states.map { ($0.target, $0.snapshot) })
    }

    private func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock.lock(); defer { lock.unlock() }
        return try operation()
    }

    private static func setCloseOnExec(_ descriptor: Int32) -> Bool {
        let flags = fcntl(descriptor, F_GETFD)
        return flags >= 0 && fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0
    }

    private static func isRegularExecutable(_ path: String) -> Bool {
        var value = stat()
        return path.withCString { lstat($0, &value) == 0 } &&
            (value.st_mode & S_IFMT) == S_IFREG && (value.st_mode & 0o111) != 0 &&
            value.st_nlink == 1
    }

    private static func physicalPath(_ path: String) -> Bool {
        guard let value = path.withCString({ realpath($0, nil) }) else { return false }
        defer { free(value) }
        return String(cString: value) == path
    }

    private static func processIdentity(pid: Int32, expectedPath: String?,
                                        requirement: String) -> GateHelperVerifiedProcess? {
        guard let expectedPath, !expectedPath.isEmpty else { return nil }
        var record = lg_process()
        guard lg_process_snapshot(pid, &record) == 0, record.pid == pid,
              record.uid == getuid(), lg_signature_matches(pid, requirement) == 0 else { return nil }
        var raw = record.path
        let path = withUnsafeBytes(of: &raw) { bytes -> String in
            String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
        }
        guard path == expectedPath else { return nil }
        return GateHelperVerifiedProcess(pid: pid, uid: record.uid,
            birthSeconds: record.birth_sec, birthMicroseconds: record.birth_usec,
            executablePath: path, codeRequirement: requirement)
    }

    private static func waitForIdentity(pid: Int32, path: String,
                                        requirement: String) throws -> GateHelperVerifiedProcess {
        let deadline = DispatchTime.now().uptimeNanoseconds &+ 1_200_000_000
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if let identity = processIdentity(pid: pid, expectedPath: path, requirement: requirement) {
                return identity
            }
            usleep(10_000)
        }
        throw GateHelperHostError.processIdentity
    }

    private static func revalidate(_ expected: GateHelperVerifiedProcess) throws {
        guard processIdentity(pid: expected.pid, expectedPath: expected.executablePath,
                              requirement: expected.codeRequirement) == expected else {
            throw GateHelperHostError.processIdentity
        }
    }

    private static func randomBytes(count: Int) throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        let result = bytes.withUnsafeMutableBufferPointer { buffer -> OSStatus in
            guard let base = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, buffer.count, base)
        }
        guard result == errSecSuccess, bytes.contains(where: { $0 != 0 }) else {
            throw GateHelperHostError.protocolFailure
        }
        return bytes
    }

    private static func randomEpoch() throws -> UInt64 {
        let bytes = try randomBytes(count: MemoryLayout<UInt64>.size)
        let value = bytes.enumerated().reduce(UInt64(0)) { partial, element in
            partial | (UInt64(element.element) << (element.offset * 8))
        }
        guard value != 0 else { throw GateHelperHostError.protocolFailure }
        return value
    }

    private static func waitForExit(pid: Int32, timeoutNanoseconds: UInt64) -> Int32? {
        let deadline = DispatchTime.now().uptimeNanoseconds &+ timeoutNanoseconds
        var status: Int32 = 0
        while DispatchTime.now().uptimeNanoseconds < deadline {
            let result = waitpid(pid, &status, WNOHANG)
            if result == pid {
                return status & 0x7f == 0 ? (status >> 8) & 0xff : -1
            }
            if result < 0 && errno != EINTR { return nil }
            usleep(10_000)
        }
        return nil
    }

    deinit {
        stopHeartbeat()
        if !terminal {
            try? revokeAndWait()
        }
        closeControlChannel()
    }
}

final class GateHelperTargetEndpoint: GateController {
    private let host: GateHelperHost
    let target: GateHelperTarget
    var entryPort: UInt16 { target == .claude ? 17_897 : 17_898 }

    init(host: GateHelperHost, target: GateHelperTarget) {
        self.host = host
        self.target = target
    }

    func prepareClosed() throws { try host.prepareClosed() }
    func open(generation: UInt64) throws { try host.open(generation, target: target) }
    func renew(generation: UInt64, leaseMillis: UInt64) throws {
        guard leaseMillis == 3_000 else { throw GateHelperHostError.protocolFailure }
        try host.renew(generation)
    }
    func status() -> GateControllerStatus {
        do {
            let state = try host.status(target)
            return GateControllerStatus(available: true, bound: state.bound, open: state.open,
                                        activePairs: Int(state.activePairs), pending: Int(state.pending))
        } catch {
            host.operationFailed()
            return GateControllerStatus(available: false, bound: false, open: false,
                                        activePairs: 0, pending: 0)
        }
    }
    func lock() {
        do { try host.lockAll() } catch { host.operationFailed() }
    }
    func revoke() {
        do { try host.revokeAndWait() } catch { host.operationFailed() }
    }
}
