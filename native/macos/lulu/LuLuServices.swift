import Foundation
import Darwin
import Dispatch

// LuLu owns the installed filtering boundary for the two legacy GUI targets.
// This fence owns only our loopback gate and never treats a file or UI boolean
// as an OS filtering acknowledgment.
final class LuLuGateFence {
    private let lock = NSLock()
    private let gates: [String: GateController]
    private let onFault: (String) -> Void
    private var epoch: UInt64 = 0
    private var bound = false
    private var released = false
    private var pendingPreparation = 0
    private var openCalls = 0
    private var launchCalls = 0
    private var permitted: Set<String> = []
    private var launched: Set<String> = []

    init(claude: GateController, sunbrowser: GateController, onFault: @escaping (String) -> Void) {
        gates = ["claude": claude, "sunbrowser": sunbrowser]
        self.onFault = onFault
    }

    func generation() -> UInt64 { lock.lock(); defer { lock.unlock() }; return epoch }
    func current(_ expected: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !released && epoch == expected
    }
    func ownsGate() -> Bool { lock.lock(); defer { lock.unlock() }; return bound && !released }

    func bindClosed(expected: UInt64) throws {
        lock.lock(); defer { lock.unlock() }
        guard !released, epoch == expected else { throw NativeControlError.rejected("prepare_invalidated") }
        if bound { return }
        pendingPreparation += 1
        defer { pendingPreparation -= 1 }
        do {
            for target in gates.keys.sorted() { try gates[target]!.prepareClosed() }
            bound = true
        } catch {
            gates.values.forEach { $0.revoke() }
            throw error
        }
    }

    func beginOpen() throws -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        guard bound, !released else { throw NativeControlError.rejected("gate_unprepared") }
        openCalls += 1
        return epoch
    }
    func endOpen() { lock.lock(); openCalls -= 1; lock.unlock() }

    func open(target: String, generation: UInt64, expected: UInt64) throws {
        lock.lock(); defer { lock.unlock() }
        guard !released, bound, epoch == expected, gates[target] != nil else {
            throw NativeControlError.rejected("open_invalidated")
        }
        // Renew only explicitly selected targets; the other endpoint stays closed.
        try gates[target]!.open(generation: generation)
        for name in permitted.sorted() where name != target {
            try gates[name]!.renew(generation: generation, leaseMillis: 3_000)
        }
        permitted.insert(target)
    }

    func renew(_ generation: UInt64, expected: UInt64) throws {
        lock.lock(); defer { lock.unlock() }
        guard !released, bound, epoch == expected, !permitted.isEmpty else {
            throw NativeControlError.rejected("open_invalidated")
        }
        for name in permitted.sorted() { try gates[name]!.renew(generation: generation, leaseMillis: 3_000) }
    }

    func beginLaunch(target: String) throws -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        guard !released, bound, permitted.contains(target), let state = gates[target]?.status(),
              state.available, state.open else {
            throw NativeControlError.rejected("gate_locked")
        }
        launchCalls += 1
        launched.insert(target)
        return epoch
    }
    func endLaunch() { lock.lock(); launchCalls -= 1; lock.unlock() }

    func gateOpen(at expected: UInt64, target: String? = nil) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !released, bound, epoch == expected else { return false }
        if let target {
            guard let state = gates[target]?.status() else { return false }
            return permitted.contains(target) && state.available && state.open
        }
        return !permitted.isEmpty && permitted.allSatisfy {
            guard let state = gates[$0]?.status() else { return false }
            return state.available && state.open
        }
    }
    func activeTargets() -> [String] { lock.lock(); defer { lock.unlock() }; return permitted.sorted() }

    private func allLocked() -> Bool {
        gates.values.allSatisfy {
            let state = $0.status()
            return state.available && state.bound && !state.open && state.activePairs == 0 && state.pending == 0
        }
    }
    func gateLocked(at expected: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !released && bound && epoch == expected && allLocked()
    }
    func status() -> GateControllerStatus {
        lock.lock(); defer { lock.unlock() }
        let states = gates.values.map { $0.status() }
        return .init(available: states.allSatisfy(\.available),
                     bound: states.allSatisfy(\.bound), open: states.contains(where: \.open),
                     activePairs: states.reduce(0) { $0 + $1.activePairs },
                     pending: states.reduce(0) { $0 + $1.pending })
    }
    func cleanupState() -> (epoch: UInt64, owned: Bool, pending: Bool,
                           preparation: Int, open: Int, launch: Int, targets: Set<String>) {
        lock.lock(); defer { lock.unlock() }
        return (epoch, bound && !released, pendingPreparation != 0 || openCalls != 0 || launchCalls != 0,
                pendingPreparation, openCalls, launchCalls, launched)
    }
    func confirmCleanup(at expected: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard epoch == expected, allLocked() else { return false }
        launched.removeAll()
        return true
    }
    func emergencyLock() {
        lock.lock(); defer { lock.unlock() }
        epoch &+= 1
        gates.values.forEach { $0.lock() }
        permitted.removeAll()
    }
    func fault(reason: String) {
        lock.lock(); defer { lock.unlock() }
        guard !released else { return }
        epoch &+= 1
        gates.values.forEach { $0.lock() }
        permitted.removeAll()
        onFault(reason)
    }
    func release() {
        lock.lock(); defer { lock.unlock() }
        epoch &+= 1
        released = true
        bound = false
        permitted.removeAll()
        gates.values.forEach { $0.revoke() }
    }
}

private final class LuLuBaselineMonitor {
    struct WatchEntry {
        let path: String
        let maximumBytes: Int
        // Manifest baselines carry root-pinned digests. LuLu's two policy
        // files are instead sealed to their content at enrollment, then
        // semantically checked by LuLuPolicy before the gate can open.
        let sealedDigests: [String]?
    }

    private struct WatchedFile {
        let path: String
        let maximumBytes: Int
        let metadata: ProtectedFiles.Metadata
        let sha256: String
    }

    private let lock = NSLock()
    private var sources: [DispatchSourceFileSystemObject] = []
    private var stopped = false
    private var tripped = false
    private let eventQueue = DispatchQueue(label: "local.fox.guard.baseline-watch", qos: .userInitiated)

    init(entries: [WatchEntry], onChange: @escaping (String) -> Void) throws {
        guard (6...34).contains(entries.count),
              Set(entries.map(\.path)).count == entries.count else {
            throw NativeControlError.rejected("baseline_watch_scope")
        }
        var opened: [DispatchSourceFileSystemObject] = []
        do {
            for entry in entries {
                let snapshot = try ProtectedFiles.readSnapshot(entry.path,
                    maximum: entry.maximumBytes, owner: nil)
                if let sealed = entry.sealedDigests {
                    guard sealed.contains(snapshot.sha256) else {
                        throw NativeControlError.rejected("baseline_watch_seal")
                    }
                }
                let watched = WatchedFile(path: entry.path, maximumBytes: entry.maximumBytes,
                                          metadata: snapshot.metadata, sha256: snapshot.sha256)
                let descriptor = open(entry.path, O_EVTONLY | O_NOFOLLOW | O_CLOEXEC)
                guard descriptor >= 0 else { throw NativeControlError.unavailable("baseline_watch") }
                var info = stat()
                guard fstat(descriptor, &info) == 0,
                      (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
                      info.st_size > 0, info.st_size <= entry.maximumBytes,
                      watched.metadata.matchesExceptAccessTime(ProtectedFiles.Metadata(info)) else {
                    close(descriptor)
                    throw NativeControlError.rejected("baseline_watch_file")
                }
                let source = DispatchSource.makeFileSystemObjectSource(
                    fileDescriptor: descriptor,
                    eventMask: [.write, .delete, .rename, .revoke, .attrib, .extend],
                    queue: eventQueue)
                source.setEventHandler { [weak self, weak source] in
                    self?.changed(onChange, file: watched, eventMask: source?.data ?? 0)
                }
                source.setCancelHandler { close(descriptor) }
                source.resume()
                opened.append(source)
            }
            sources = opened
        } catch {
            opened.forEach { $0.cancel() }
            throw error
        }
    }

#if GUARD_OFFLINE_E2E
    init(offlineFixture: Void) { stopped = true }
#endif

    private func changed(_ onChange: (String) -> Void, file: WatchedFile, eventMask: UInt) {
        let attribOnly = eventMask == DispatchSource.FileSystemEvent.attrib.rawValue
        if attribOnly, confirmsAtimeOnlyChange(file, eventMask: eventMask) { return }

        lock.lock()
        guard !stopped, !tripped else { lock.unlock(); return }
        tripped = true
        let closing = sources
        lock.unlock()
        let rawName = URL(fileURLWithPath: file.path).lastPathComponent.lowercased()
        let name = String(rawName.replacingOccurrences(of: "[^a-z0-9]+", with: "_",
            options: .regularExpression).prefix(32))
        onChange("baseline_file_changed_\(name.isEmpty ? "unknown" : name)_mask_\(String(eventMask, radix: 16))")
        closing.forEach { $0.cancel() }
    }

    private func confirmsAtimeOnlyChange(_ file: WatchedFile, eventMask: UInt) -> Bool {
        let attribMask = DispatchSource.FileSystemEvent.attrib.rawValue
        guard let current = try? ProtectedFiles.readSnapshot(file.path,
                maximum: file.maximumBytes, owner: nil) else { return false }
        return ProtectedFiles.confirmsAtimeOnlyVnodeChange(
            eventMask: eventMask, attribMask: attribMask,
            metadata: file.metadata, sha256: file.sha256, current: current)
    }

    var isLive: Bool {
        lock.lock(); defer { lock.unlock() }
        return !stopped && !tripped && sources.count >= 6 && sources.allSatisfy { !$0.isCancelled }
    }

    func stop() {
        lock.lock()
        guard !stopped else { lock.unlock(); return }
        stopped = true
        let closing = sources
        sources.removeAll()
        lock.unlock()
        closing.forEach { $0.cancel() }
    }

    deinit { stop() }
}

private final class LuLuBaselineMonitorRef {
    private let lock = NSLock()
    private weak var value: LuLuBaselineMonitor?

    func set(_ value: LuLuBaselineMonitor) {
        lock.lock(); self.value = value; lock.unlock()
    }

    func stop() {
        lock.lock(); let current = value; lock.unlock()
        current?.stop()
    }
}

private final class LuLuExtensionMonitor {
    private let lock = NSLock()
    private let checker: NativeEnvironmentChecker
    private let onFault: (String) -> Void
    private let timer: DispatchSourceTimer
    private var stopped = false
    private var tripped = false
    private var lastSuccessNS: UInt64?

    init(checker: NativeEnvironmentChecker, onFault: @escaping (String) -> Void) {
        self.checker = checker
        self.onFault = onFault
        let queue = DispatchQueue(label: "local.fox.guard.lulu-extension-health", qos: .utility)
        timer = DispatchSource.makeTimerSource(queue: queue)
        timer.setEventHandler { [weak self] in self?.check() }
        timer.schedule(deadline: .now(), repeating: .seconds(1), leeway: .milliseconds(100))
        timer.resume()
    }

#if GUARD_OFFLINE_E2E
    init(offlineChecker: NativeEnvironmentChecker) {
        checker = offlineChecker; onFault = { _ in }
        timer = DispatchSource.makeTimerSource(queue: .global())
        stopped = true
        timer.resume()
    }
#endif

    private func check() {
        do {
            try checker.checkExtensionHealth()
            recordSuccess()
        } catch let failure as EnvironmentCheckFailure {
            switch failure {
            case .configuration("lulu_extension"):
                trip("extension_health_disabled")
            default:
                trip("extension_health_unreadable")
            }
        } catch {
            trip("extension_health_unreadable")
        }
    }

    private func trip(_ reason: String) {
        lock.lock()
        guard !stopped, !tripped else { lock.unlock(); return }
        tripped = true
        lock.unlock()
        onFault(reason)
        stop()
    }

    private func recordSuccess() {
        let now = NativeEnvironmentChecker.continuousNowNS()
        guard now > 0 else {
            lock.lock()
            let shouldFault = !stopped && !tripped
            tripped = tripped || shouldFault
            lock.unlock()
            if shouldFault { onFault("extension_health_clock"); stop() }
            return
        }
        lock.lock()
        if !stopped && !tripped { lastSuccessNS = now }
        lock.unlock()
    }

    var isLive: Bool {
        lock.lock(); let success = lastSuccessNS, live = !stopped && !tripped; lock.unlock()
        let now = NativeEnvironmentChecker.continuousNowNS()
        guard live, let success, now >= success else {
            return false
        }
        return now - success <= 2_500_000_000
    }

    var isMonitoring: Bool {
        lock.lock(); defer { lock.unlock() }
        return !stopped && !tripped && !timer.isCancelled
    }

    func stop() {
        lock.lock()
        guard !stopped else { lock.unlock(); return }
        stopped = true
        lock.unlock()
        timer.cancel()
    }

    deinit { stop() }
}

private final class LuLuExtensionMonitorRef {
    private let lock = NSLock()
    private weak var value: LuLuExtensionMonitor?

    func set(_ value: LuLuExtensionMonitor) {
        lock.lock(); self.value = value; lock.unlock()
    }

    func stop() {
        lock.lock(); let current = value; lock.unlock()
        current?.stop()
    }
}

final class LuLuServices {
    // A cold-session diagnostic does not construct this service, bind the Gate,
    // inspect policy, probe an upstream, or alter lastVerifiedStamp.
    static func portObservationPayload(_ facts: RootPortObserver.Diagnostic) throws -> Data {
        func key(_ value: String?) -> Any {
            guard let value, !value.isEmpty, value.utf8.count <= 80,
                  value.range(of: "^[a-z0-9_]+$", options: .regularExpression) != nil else {
                return NSNull()
            }
            return value
        }
        // Native query states can distinguish unknown/absent; retain the fixed
        // outward DTO vocabulary without inventing an absent-port observation.
        func portState(_ raw: String) -> String {
            switch raw {
            case "present": return "present"
            case "absent", "missing": return "missing"
            case "invalid": return "invalid"
            default: return "unavailable"
            }
        }
        let owner = facts.ingressOwnerState.rawValue
        let outwardOwner = ["matches", "mismatch", "unavailable"].contains(owner) ? owner : "unchecked"
        let producer = facts.producerStatus
        let milliseconds: Any = facts.observedAtUnixMS.flatMap { value -> Any? in
            (1...9_007_199_254_740_991).contains(value) ? NSNumber(value: value) : nil
        } ?? NSNull()
        let payload: [String: Any] = [
            "diagnosticOnly": true,
            "fileState": facts.fileState.rawValue,
            "schemaState": facts.schemaState.rawValue,
            "producerStatus": key(["unknown", "unavailable"].contains(producer) ? nil : producer),
            "upstreamState": portState(facts.upstream.state.rawValue),
            "ingressState": portState(facts.ingress.state.rawValue),
            "ingressOwnerState": outwardOwner,
            "bootState": facts.bootState.rawValue,
            "wallFreshness": facts.wallFreshness.rawValue,
            "monotonicFreshness": facts.monotonicFreshness.rawValue,
            "observedAtUnixMs": milliseconds,
            "failure": key(RootPortObserver.admissionFailure(facts))
        ]
        return try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    }

    // Fixed target endpoints: Claude 17897, SunBrowser 17898; leases open separately.
    let targets: Set<String> = ["claude", "sunbrowser"]
    private let manifest: LuLuManifest
    private let supervisors: [String: LegacyApplicationSupervisor]
    private let safety: LuLuGateFence
    private let baselineMonitorLock = NSLock()
    private var baselineMonitor: LuLuBaselineMonitor
    private let baselineMonitorRef: LuLuBaselineMonitorRef
    private let extensionMonitorLock = NSLock()
    private var extensionMonitor: LuLuExtensionMonitor
    private let extensionMonitorRef: LuLuExtensionMonitorRef
    private let checkerLock = NSLock()
    private var checker: NativeEnvironmentChecker
    private let cleanupDiagnosticLock = NSLock()
    private var lastCleanupDiagnostic: NativeCleanupDiagnostic = .unavailable
    private var lastVerifiedStamp: NativeCheckStamp?

    var cleanupDiagnostic: NativeCleanupDiagnostic {
        cleanupDiagnosticLock.lock(); defer { cleanupDiagnosticLock.unlock() }
        return lastCleanupDiagnostic
    }

    private func recordCleanup(_ diagnostic: NativeCleanupDiagnostic) {
        cleanupDiagnosticLock.lock()
        lastCleanupDiagnostic = diagnostic
        cleanupDiagnosticLock.unlock()
    }

    static func cleanupReason(_ error: Error) -> NativeCleanupDiagnostic {
        guard let error = error as? LegacySupervisorError else { return .unknownError }
        switch error {
        case .invalidSealedTarget: return .invalidSealedTarget
        case .unknownTarget: return .unknownTarget
        case .inspectionIncomplete: return .inspectionIncomplete
        case .inspectionFailure(let detail): return .inspectionFailure(detail)
        case .signatureMismatch(let pid): return .signatureMismatch(pid)
        case .processChanged(let pid): return .processChanged(pid)
        case .stillRunning: return .stillRunning
        case .cleanupLaunchInFlight: return .supervisorLaunchInFlight
        case .cleanupProcessStillRunning: return .processStillRunning
        case .gateNotLocked: return .gateNotLocked
        case .gateNotReady: return .gateNotReady
        case .launchFailed: return .launchFailed
        case .launchIdentityMismatch: return .launchIdentityMismatch
        case let .signalFailed(pid, code): return .signalFailed(pid, code)
        }
    }

    private init(manifest: LuLuManifest, supervisors: [String: LegacyApplicationSupervisor],
                 safety: LuLuGateFence,
                 baselineMonitor: LuLuBaselineMonitor, baselineMonitorRef: LuLuBaselineMonitorRef,
                 extensionMonitor: LuLuExtensionMonitor, extensionMonitorRef: LuLuExtensionMonitorRef,
                 checker: NativeEnvironmentChecker) {
        self.manifest = manifest
        self.supervisors = supervisors
        self.safety = safety
        self.baselineMonitor = baselineMonitor
        self.baselineMonitorRef = baselineMonitorRef
        self.extensionMonitor = extensionMonitor
        self.extensionMonitorRef = extensionMonitorRef
        self.checker = checker
    }

#if GUARD_OFFLINE_E2E
    var offlineFixture: LuLuOfflineE2EFixture?
    static func makeOfflineFixture(_ scenario: Int32, onFault: @escaping (String) -> Void) throws -> LuLuServices {
        let fixture = try LuLuOfflineE2EFixture(scenario: scenario)
        let safety = LuLuGateFence(claude: try SwiftNativeGate.fixture(entryPort: 17_897),
            sunbrowser: try SwiftNativeGate.fixture(entryPort: 17_898), onFault: onFault)
        let service = LuLuServices(manifest: fixture.manifest,
            supervisors: ["claude": fixture.supervisor], safety: safety,
            baselineMonitor: LuLuBaselineMonitor(offlineFixture: ()),
            baselineMonitorRef: LuLuBaselineMonitorRef(),
            extensionMonitor: LuLuExtensionMonitor(offlineChecker: fixture.checker),
            extensionMonitorRef: LuLuExtensionMonitorRef(), checker: fixture.checker)
        service.offlineFixture = fixture
        try safety.bindClosed(expected: 0)
        _ = try safety.beginOpen()
        defer { safety.endOpen() }
        try safety.open(target: "claude", generation: 1, expected: 0)
        return service
    }
#endif

    private var supervisorOperations: LegacyApplicationSupervisor.Operations? {
#if GUARD_OFFLINE_E2E
        return offlineFixture?.operations
#else
        return nil
#endif
    }

    static func make(onFault: @escaping (String) -> Void) throws -> LuLuServices {
        let manifest = try LuLuManifest.production()
        guard Set(manifest.legacyTargets.map(\.targetID)) == Set(["claude", "adspower"]),
              manifest.legacyTargets.count == 2 else {
            throw NativeControlError.rejected("legacy_targets")
        }
        guard let claudeTarget = manifest.legacyTargets.first(where: { $0.targetID == "claude" }) else {
            throw NativeControlError.rejected("legacy_targets")
        }
        guard let browserTarget = manifest.legacyTargets.first(where: { $0.targetID == "adspower" }) else {
            throw NativeControlError.rejected("legacy_targets")
        }
        let supervisors = [
            "claude": try LegacyApplicationSupervisor(targets: [claudeTarget]),
            "sunbrowser": try LegacyApplicationSupervisor(targets: [browserTarget], managerLaunchOnly: true)
        ]
        let baselineMonitorRef = LuLuBaselineMonitorRef()
        let extensionMonitorRef = LuLuExtensionMonitorRef()
        let gateFault: (String) -> Void = { reason in
            onFault(reason)
            baselineMonitorRef.stop()
            extensionMonitorRef.stop()
        }
        let gateHost = try GateHelperHost(onFault: gateFault)
        let safety = LuLuGateFence(claude: gateHost.endpoint(.claude),
                                   sunbrowser: gateHost.endpoint(.sunbrowser),
                                   onFault: gateFault)
        let baselineMonitor = try LuLuBaselineMonitor(
            entries: Self.watchPaths(manifest),
            onChange: { [weak safety] reason in safety?.fault(reason: reason) })
        baselineMonitorRef.set(baselineMonitor)
        try manifest.verify() // Re-read after watchers are live to close the verify/watch race.
        guard let executable = Bundle.main.executableURL?.path else {
            throw NativeControlError.unavailable("controller_executable")
        }
        let checker = try NativeEnvironmentChecker.production(
            expectedIngressExecutable: executable, expectedIngressPID: getpid(),
            onNetworkChange: { [weak safety] reason in safety?.fault(reason: reason) })
        let extensionMonitor = LuLuExtensionMonitor(checker: checker,
            onFault: { [weak safety] reason in safety?.fault(reason: reason) })
        extensionMonitorRef.set(extensionMonitor)
        return LuLuServices(manifest: manifest, supervisors: supervisors,
                            safety: safety, baselineMonitor: baselineMonitor,
                            baselineMonitorRef: baselineMonitorRef,
                            extensionMonitor: extensionMonitor, extensionMonitorRef: extensionMonitorRef,
                            checker: checker)
    }

    private func background<T>(_ work: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do { continuation.resume(returning: try work()) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    private func requireCurrent(_ epoch: UInt64) throws {
        guard safety.current(epoch) else { throw NativeControlError.rejected("operation_invalidated") }
    }

    private func currentChecker() -> NativeEnvironmentChecker {
        checkerLock.lock(); defer { checkerLock.unlock() }
        return checker
    }

    private func replaceChecker(_ replacement: NativeEnvironmentChecker) {
        checkerLock.lock(); checker = replacement; checkerLock.unlock()
    }

    private func diagnostic(_ failure: EnvironmentCheckFailure?) -> String {
        switch failure {
        case .observation(let key): return "observation_\(key)"
        case .probe(let key, _): return "observation_\(key)"
        case .configuration(let key): return "configuration_\(key)"
        case .networkChanged: return "network_changed"
        case .exitMismatch: return "fixed_ip_mismatch"
        case nil: return "environment_check"
        }
    }

    // The policy reader returns facts from the installed LuLu surfaces. It
    // must be implemented by the LuLuPolicy module; a caller cannot inject it.
    private func verifyPolicy() throws {
#if GUARD_OFFLINE_E2E
        if offlineFixture != nil { return } // Fixture prerequisite, never compiled into the candidate.
#endif
        try manifest.verify()
        let facts = try LuLuPolicy.loadFacts(
            pythonExecutable: URL(fileURLWithPath: manifest.pythonExecutable),
            scriptURL: manifest.factsScriptURL)
        _ = try LuLuPolicy.validate(facts: facts, expectedHome: manifest.home,
                                    expectedLegacyDigest: manifest.firewallPolicySHA)
    }

    private static func watchPaths(_ manifest: LuLuManifest) -> [LuLuBaselineMonitor.WatchEntry] {
        manifest.baselineFiles.map {
            LuLuBaselineMonitor.WatchEntry(path: $0.path, maximumBytes: $0.maximumBytes,
                                           sealedDigests: $0.digests)
        } + [
            LuLuBaselineMonitor.WatchEntry(
                path: "/Library/Objective-See/LuLu/preferences.plist",
                maximumBytes: 67_108_864, sealedDigests: nil),
            LuLuBaselineMonitor.WatchEntry(
                path: "/Library/Objective-See/LuLu/rules.plist",
                maximumBytes: 67_108_864, sealedDigests: nil),
        ]
    }

    private func rearmBaselineMonitor() throws {
        try manifest.verify()
        let replacement = try LuLuBaselineMonitor(
            entries: Self.watchPaths(manifest),
            onChange: { [weak safety] reason in safety?.fault(reason: reason) })
        baselineMonitorRef.set(replacement)
        do { try manifest.verify() }
        catch { replacement.stop(); throw error }
        baselineMonitorLock.lock()
        let old = baselineMonitor
        baselineMonitor = replacement
        baselineMonitorLock.unlock()
        old.stop()
    }

    private func baselineMonitorIsLive() -> Bool {
        baselineMonitorLock.lock()
        let monitor = baselineMonitor
        baselineMonitorLock.unlock()
        return monitor.isLive
    }

    private func rearmExtensionMonitor(using checker: NativeEnvironmentChecker) throws {
        try manifest.verify()
        let replacement = LuLuExtensionMonitor(checker: checker,
            onFault: { [weak safety] reason in safety?.fault(reason: reason) })
        extensionMonitorRef.set(replacement)
        do { try manifest.verify() }
        catch { replacement.stop(); throw error }
        extensionMonitorLock.lock()
        let old = extensionMonitor
        extensionMonitor = replacement
        extensionMonitorLock.unlock()
        old.stop()
    }

    private func extensionMonitorIsLive() -> Bool {
        extensionMonitorLock.lock()
        let monitor = extensionMonitor
        extensionMonitorLock.unlock()
        return monitor.isLive
    }

    private func extensionMonitorIsMonitoring() -> Bool {
        extensionMonitorLock.lock()
        let monitor = extensionMonitor
        extensionMonitorLock.unlock()
        return monitor.isMonitoring
    }

    func prepare(isCurrent: @escaping () -> Bool = { true }) async throws {
        let epoch = safety.generation()
        try await background { [self] in
            guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
            try ensureMonitors()
            try verifyPolicy()
            guard try supervisors.values.allSatisfy({ try $0.isQuiescent() }) else {
                throw NativeControlError.rejected("legacy_process_still_running")
            }
        }
        guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
        try requireCurrent(epoch)
        try await background { [self] in try safety.bindClosed(expected: epoch) }
        guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
        try requireCurrent(epoch)
        try await background { [self] in
            let end = Date().addingTimeInterval(1.5)
            while Date() < end {
                guard safety.current(epoch) else {
                    throw NativeControlError.rejected("operation_invalidated")
                }
                guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
                if let report = try? RootPortObserver.read(),
                   report.upstream.count == 1,
                   report.upstream[0].executable == NativeEnvironmentChecker.coreExecutable,
                   report.ingress.count == 1,
                   report.ingress[0].pid == getpid(),
                   report.ingress[0].executable == Bundle.main.executableURL?.path {
                    return
                }
                Thread.sleep(forTimeInterval: 0.05)
            }
            throw NativeControlError.timeout
        }
        guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
        try requireCurrent(epoch)
    }

    private func ensureMonitors() throws {
        try manifest.verify()
        if !baselineMonitorIsLive() { try rearmBaselineMonitor() }
        if !extensionMonitorIsMonitoring() {
            try rearmExtensionMonitor(using: currentChecker())
        }
        try manifest.verify()
    }

    private func stamp(_ report: EnvironmentCheckReport) throws -> NativeCheckStamp {
        guard report.productionObserved, report.observationsMatch,
              report.observedIP == NativeEnvironmentChecker.expectedIP,
              report.failure == nil, report.startedAtContinuousNS > 0,
              report.checkedAtContinuousNS >= report.startedAtContinuousNS,
              report.checkedAtContinuousNS - report.startedAtContinuousNS <= 25_000_000_000,
              let fingerprint = report.networkFingerprint, fingerprint.count == 64,
              let upstreamFingerprint = report.upstreamFingerprint, upstreamFingerprint.count == 64,
              let ingressFingerprint = report.ingressFingerprint, ingressFingerprint.count == 64,
              let generation = report.beforeGeneration,
              report.afterGeneration == generation else {
            let head = diagnostic(report.failure)
            let history = report.probeDiagnostics.filter { "observation_" + $0 != head }
            throw NativeControlError.rejected(([head] + history).joined(separator: "\n"))
        }
        let observedAt = Int64(Date().timeIntervalSince1970 * 1_000)
        guard observedAt > 0 else { throw NativeControlError.rejected("observation_clock") }
        return NativeCheckStamp(fingerprint: fingerprint, generation: generation,
                                checkedAtNS: report.checkedAtContinuousNS,
                                observedIP: report.observedIP,
                                observedAtUnixMS: observedAt,
                                upstreamFingerprint: upstreamFingerprint,
                                ingressFingerprint: ingressFingerprint)
    }

    func fullCheck(throughEntry: Bool, isCurrent: @escaping () -> Bool = { true }) async throws -> NativeCheckStamp {
        let budget = EnvironmentInspectionBudget(isCurrent: isCurrent)
        if !safety.ownsGate() {
            guard !throughEntry else { throw NativeControlError.rejected("entry_unprepared") }
            try await prepare(isCurrent: isCurrent) // binds only a closed gate; inspect grants nothing
        }
        let paths: [NativeEnvironmentChecker.ProbePath] = throughEntry
            ? safety.activeTargets().map { $0 == "sunbrowser" ? .sunbrowserEntry : .entry }
            : [.upstream]
        var completed: NativeCheckStamp?
        for path in paths {
            let checked = try await checkedEnvironment(using: currentChecker(), path: path, budget: budget, isCurrent: isCurrent)
            if let previous = completed {
                guard checked.fingerprint == previous.fingerprint, checked.generation == previous.generation,
                      checked.upstreamFingerprint == previous.upstreamFingerprint,
                      checked.ingressFingerprint == previous.ingressFingerprint else {
                    throw NativeControlError.rejected("target_environment_changed")
                }
            }
            completed = checked
        }
        guard let completed else { throw NativeControlError.rejected("entry_unprepared") }
        if throughEntry { try requireFreshPublicObservation() }
        try checkBudget(budget)
        setVerifiedStamp(completed)
        return completed
    }

    private func checkBudget(_ budget: EnvironmentInspectionBudget) throws {
        do { _ = try budget.remainingSeconds() }
        catch let failure as EnvironmentCheckFailure {
            throw NativeControlError.rejected(budget.diagnostic(failure))
        }
    }

    private func checkedEnvironment(using checker: NativeEnvironmentChecker, path: NativeEnvironmentChecker.ProbePath,
                                    budget: EnvironmentInspectionBudget, isCurrent: @escaping () -> Bool) async throws -> NativeCheckStamp {
        guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
        try checkBudget(budget)
        let epoch = safety.generation()
        let report = try await background { [self] in
            guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
            try checkBudget(budget)
            try verifyPolicy()
            try checkBudget(budget)
            let result = path != .upstream ? checker.probeThroughIngress(path: path, validateRetry: { [self] in
                guard isCurrent(), safety.current(epoch), safety.gateOpen(at: epoch) else {
                    throw EnvironmentCheckFailure.observation("retry_invalidated")
                }
                do { try requireFreshPublicObservation() }
                catch { throw EnvironmentCheckFailure.observation("public_observation_expired") }
            }, budget: budget) : checker.inspect(path: .upstream, budget: budget)
            // Preserve a terminal probe failure even if subsequent policy reads fail.
            guard result.failure == nil else { return result }
            try checkBudget(budget)
            try verifyPolicy()
            try checkBudget(budget)
            return result
        }
        guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
        try requireCurrent(epoch)
        let first = try stamp(report)
        try checkBudget(budget)
        let local = try await background { [self] in
            guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
            try verifyPolicy()
            try checkBudget(budget)
            let snapshot = try checker.localSnapshot()
            try checkBudget(budget)
            try verifyPolicy()
            try checkBudget(budget)
            return snapshot
        }
        guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
        try requireCurrent(epoch)
        guard local.generation == first.generation,
              local.fingerprint == first.fingerprint,
              let now = NativeContinuousClock.nowNS(), now >= first.checkedAtNS else {
            throw NativeControlError.rejected("final_environment_changed")
        }
        try checkBudget(budget)
        return NativeCheckStamp(fingerprint: local.fingerprint,
                                generation: local.generation, checkedAtNS: now,
                                observedIP: first.observedIP,
                                observedAtUnixMS: first.observedAtUnixMS,
                                upstreamFingerprint: first.upstreamFingerprint,
                                ingressFingerprint: first.ingressFingerprint)
    }

    // Three-second gate renewal uses only local facts and the root observer;
    // LuLu policy and baseline bytes are watched for vnode drift, not rehashed
    // on every lease tick. This never refreshes the last public-IP observation.
    func renew(generation: UInt64, expectedGeneration: UInt64,
               expectedFingerprint: String, expectedUpstreamFingerprint: String,
               expectedIngressFingerprint: String,
               isCurrent: @escaping () -> Bool) async throws {
        let epoch = try safety.beginOpen()
        defer { safety.endOpen() }
        do {
            guard isCurrent(), safety.current(epoch), baselineMonitorIsLive() else {
                throw NativeControlError.rejected("renewal_invalidated")
            }
            let checker = currentChecker()
            let local = try await background { try checker.renewalSnapshot() }
            let verified = verifiedStamp()
            guard isCurrent(), safety.current(epoch),
                  let verified,
                  verified.fingerprint == expectedFingerprint,
                  verified.generation == expectedGeneration,
                  verified.upstreamFingerprint == expectedUpstreamFingerprint,
                  verified.ingressFingerprint == expectedIngressFingerprint,
                  baselineMonitorIsLive(),
                  extensionMonitorIsLive(),
                  let now = NativeContinuousClock.nowNS(),
                  verified.matches(local, checkedAtNS: now) else {
                throw NativeControlError.rejected("renewal_environment_changed")
            }
            try requireFreshPublicObservation()
            try safety.renew(generation, expected: epoch)
            guard isCurrent(), safety.gateOpen(at: epoch) else {
                throw NativeControlError.rejected("renewal_gate_not_open")
            }
        } catch {
            safety.emergencyLock()
            throw error
        }
    }

    private func setVerifiedStamp(_ stamp: NativeCheckStamp) {
        cleanupDiagnosticLock.lock()
        lastVerifiedStamp = stamp
        cleanupDiagnosticLock.unlock()
    }

    private func verifiedStamp() -> NativeCheckStamp? {
        cleanupDiagnosticLock.lock(); defer { cleanupDiagnosticLock.unlock() }
        return lastVerifiedStamp
    }

    private func requireFreshPublicObservation() throws {
        guard let verified = verifiedStamp(),
              let now = NativeContinuousClock.nowNS(),
              verified.hasFreshPublicObservation(at: now) else {
            throw NativeControlError.rejected("public_observation_expired")
        }
    }

    private func requireOpenReadiness() throws {
        guard baselineMonitorIsLive() else {
            throw NativeControlError.rejected("baseline_monitor_not_live")
        }
        guard extensionMonitorIsLive() else {
            throw NativeControlError.rejected("extension_health_not_fresh")
        }
        try requireFreshPublicObservation()
    }

    func readback() -> (bound: Bool, open: Bool, activePairs: Int, epoch: UInt64,
                        owned: Bool, pending: Bool) {
        let state = safety.cleanupState()
        let gateState = safety.status()
        return (gateState.bound, gateState.open, gateState.activePairs, state.epoch,
                state.owned, state.pending)
    }

    // Explicit locked-only observation recovery. It rebuilds the local SC
    // watcher, then performs a full upstream diagnostic before swapping it in.
    // It neither restarts a service nor grants a gate lease.
    func recoverObservation() async throws -> NativeCheckStamp {
        let state = safety.cleanupState()
        guard state.owned, !state.pending,
              safety.gateLocked(at: state.epoch) else {
            throw NativeControlError.rejected("recovery_requires_owned_locked_gate")
        }
        let budget = EnvironmentInspectionBudget(isCurrent: { [self] in
            safety.current(state.epoch) && safety.gateLocked(at: state.epoch)
        })
        try rearmBaselineMonitor()
        let executable = Bundle.main.executableURL?.path
        guard let executable else { throw NativeControlError.unavailable("controller_executable") }
        let replacement = try NativeEnvironmentChecker.production(
            expectedIngressExecutable: executable, expectedIngressPID: getpid(),
            onNetworkChange: { [weak safety] reason in safety?.fault(reason: reason) })
        try rearmExtensionMonitor(using: replacement)
        let completed = try await checkedEnvironment(using: replacement, path: .upstream, budget: budget) { [self] in
            safety.current(state.epoch) && safety.gateLocked(at: state.epoch)
        }
        try checkBudget(budget)
        replaceChecker(replacement)
        guard safety.current(state.epoch), safety.gateLocked(at: state.epoch) else {
            throw NativeControlError.rejected("recovery_invalidated")
        }
        setVerifiedStamp(completed)
        return completed
    }

    func open(target: String, generation: UInt64, isCurrent: @escaping () -> Bool = { true }) async throws {
        guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
        guard let supervisor = supervisors[target] else { throw NativeControlError.rejected("target_disabled") }
        if !safety.activeTargets().contains(target) {
            guard try supervisor.isQuiescent() else { throw NativeControlError.rejected("legacy_process_still_running") }
        }
        try requireOpenReadiness()
        let epoch = try safety.beginOpen()
        do {
            try await background { [self] in
                guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
                try verifyPolicy()
            }
            guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
            try requireCurrent(epoch)
            try requireOpenReadiness()
            try safety.open(target: target, generation: generation, expected: epoch)
            try requireCurrent(epoch)
            safety.endOpen()
        } catch {
            safety.endOpen()
            safety.emergencyLock()
            throw error
        }
    }

    func launch(target: String, generation: UInt64,
                isCurrent: @escaping () -> Bool = { true }) async throws {
        guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
        guard let supervisor = supervisors[target] else { throw NativeControlError.rejected("target_disabled") }
        let epoch = try safety.beginLaunch(target: target)
        defer { safety.endLaunch() }
        try await background { [self] in
            guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
            try verifyPolicy()
        }
        guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
        try requireCurrent(epoch)
        try await withCheckedThrowingContinuation { continuation in
            supervisor.launch(targetID: target == "sunbrowser" ? "adspower" : target,
                gateReadback: { [safety] in isCurrent() && safety.gateOpen(at: epoch, target: target) },
                operations: supervisorOperations,
                completion: { result in
                    switch result {
                    case .success: continuation.resume(returning: ())
                    case .failure(let error): continuation.resume(throwing: error)
                    }
                })
        }
        guard isCurrent() else { throw NativeControlError.rejected("operation_invalidated") }
        try requireCurrent(epoch)
    }

    func emergencyLock() { safety.emergencyLock() }

    // An invalidated open/launch may still be unwinding an awaited operation.
    // Give only that pending bookkeeping a bounded chance to settle. This
    // helper cannot open a gate, launch, signal, or retry a supervisor error.
    static func waitForPendingCleanup(
        pending: () -> Bool,
        now: () -> UInt64? = NativeContinuousClock.nowNS,
        pause: (UInt64) async throws -> Void = { try await Task.sleep(nanoseconds: $0) }
    ) async {
        guard pending(), let start = now() else { return }
        let budget: UInt64 = 2_000_000_000
        while pending() {
            guard !Task.isCancelled, let current = now(), current >= start,
                  current - start < budget else { return }
            let remaining = budget - (current - start)
            do { try await pause(min(50_000_000, remaining)) }
            catch { return }
        }
    }

    func finishLock() async -> Bool {
        recordCleanup(.unavailable)
        await Self.waitForPendingCleanup(pending: { [safety] in safety.cleanupState().pending })
        // Unwinding an invalidated open can advance the epoch itself. Always
        // take a fresh state after waiting, then retain every original gate and
        // supervisor check; a stale pre-wait epoch is not cleanup authority.
        let state = safety.cleanupState()
        guard !state.pending else {
            recordCleanup(.pending(preparation: state.preparation, open: state.open, launch: state.launch))
            return false
        }
        if !state.owned { return true } // never touch the old tool's scope
        guard safety.gateLocked(at: state.epoch) else {
            recordCleanup(.gateBeforeStop)
            return false
        }
        do {
            _ = try await background { [self] in
                for target in state.targets.sorted() {
                    guard let supervisor = supervisors[target] else { throw LegacySupervisorError.unknownTarget }
                    _ = try supervisor.stopAfterGateLocked(
                        lockReadback: { [safety] in safety.gateLocked(at: state.epoch) },
                        operations: supervisorOperations)
                }
            }
            guard safety.current(state.epoch) else {
                recordCleanup(.generationChanged)
                return false
            }
            guard safety.gateLocked(at: state.epoch) else {
                recordCleanup(.gateAfterStop)
                return false
            }
            let confirmed = safety.confirmCleanup(at: state.epoch)
            if !confirmed { recordCleanup(.confirmationRejected) }
            return confirmed
        } catch {
            recordCleanup(Self.cleanupReason(error))
            return false
        }
    }

    func release() {
        recordCleanup(.unavailable)
        safety.release()
        baselineMonitorLock.lock()
        let monitor = baselineMonitor
        baselineMonitorLock.unlock()
        monitor.stop()
        extensionMonitorLock.lock()
        let extensionMonitor = self.extensionMonitor
        extensionMonitorLock.unlock()
        extensionMonitor.stop()
    }
}
