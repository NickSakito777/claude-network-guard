import Darwin
import Foundation

// Inject only native effects; exercise the production supervisor launch/stop methods.
enum LegacyLaunchCoordinationTests {
    private final class Fixture {
        let supervisor: LegacyApplicationSupervisor
        let target: LegacyTarget
        let process: ProcessBirth
        var processes: [ProcessBirth] = []
        var queued: [() -> Void] = []
        var callback: ((Result<Int32, Error>) -> Void)?
        var result: Result<ProcessBirth, Error>?
        var completions = 0
        var opens = 0
        var snapshots = 0
        var gateOpen = true
        var cancelled = false
        var signaturesValid = true
        var physicalPathsReadable = true
        var signalAttempts: [(ProcessBirth, Int32)] = []
        var deliveredSignals: [(ProcessBirth, Int32)] = []
        var snapshotTransform: ((ProcessBirth, Int) -> ProcessBirth)?
        var beforeInventory: (() -> Void)?
        var beforeSignal: (() -> Void)?
        var afterSignal: ((Int32) -> Void)?
        var inventoryOverrides: [[ProcessBirth]] = []

        init(manager: Bool = false) throws {
            let root = manager ? "/Applications/AdsPower Global.app/Contents/" : "/Applications/Claude.app/Contents/"
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            let scopes = manager
                ? [LegacyScope(pathPrefix: root, codeRequirement: "fixture-manager"),
                   LegacyScope(pathPrefix: home + "/Library/Application Support/adspower_global/cwd_global/", codeRequirement: "fixture-engine")]
                : [LegacyScope(pathPrefix: root, codeRequirement: "fixture-claude")]
            let fixtureTarget = LegacyTarget(targetID: manager ? "adspower" : "claude",
                bundlePath: String(root.dropLast("/Contents/".count)),
                executablePath: root + "MacOS/" + (manager ? "AdsPower Global" : "Claude"),
                arguments: manager ? [] : ["--proxy-server=http://127.0.0.1:17897", "--disable-quic"],
                scopes: scopes)
            let fixtureSupervisor = try LegacyApplicationSupervisor(targets: [fixtureTarget], managerLaunchOnly: manager)
            let fixtureProcess = ProcessBirth(pid: 40_001, uid: getuid(), startSeconds: 1_700_000_000,
                startMicroseconds: 1, executable: fixtureTarget.executablePath)
            target = fixtureTarget; supervisor = fixtureSupervisor; process = fixtureProcess
        }

        var operations: LegacyApplicationSupervisor.Operations {
            .init(dispatchMain: { self.queued.append($0) },
                openApplication: { target, completion in
                    precondition(target == self.target)
                    self.opens += 1; self.callback = completion
                }, snapshot: { pid in
                    self.snapshots += 1
                    guard let process = self.processes.first(where: { $0.pid == pid }) else {
                        throw LegacySupervisorError.launchIdentityMismatch
                    }
                    return self.snapshotTransform?(process, self.snapshots) ?? process
                }, signatureMatches: { _, _ in self.signaturesValid },
                physicalPath: { _ in self.physicalPathsReadable }, currentUID: getuid(),
                inventory: { scopes in
                    self.beforeInventory?()
                    let rows = self.inventoryOverrides.isEmpty ? self.processes : self.inventoryOverrides.removeFirst()
                    let selected = rows.compactMap { process -> (ProcessBirth, LegacyScope)? in
                        guard let scope = scopes.first(where: { process.executable.hasPrefix($0.pathPrefix) }) else { return nil }
                        guard self.signaturesValid else { return nil }
                        return (process, scope)
                    }
                    if !self.signaturesValid, let process = rows.first(where: { process in
                        scopes.contains(where: { process.executable.hasPrefix($0.pathPrefix) })
                    }) { throw LegacySupervisorError.signatureMismatch(process.pid) }
                    return selected
                }, signalIfSame: { pin, scope, signal in
                    self.signalAttempts.append((pin, signal)); self.beforeSignal?()
                    // The real C primitive rechecks this pinned identity and signature.
                    guard self.processes.contains(pin), self.signaturesValid,
                          pin.executable.hasPrefix(scope.pathPrefix) else { return ESTALE }
                    self.deliveredSignals.append((pin, signal))
                    self.processes.removeAll { $0 == pin }
                    self.afterSignal?(signal)
                    return 0
                })
        }

        func begin() {
            supervisor.launch(targetID: target.targetID,
                gateReadback: { self.gateOpen && !self.cancelled }, operations: operations,
                completion: { self.result = $0; self.completions += 1 })
        }
        func runMain() { precondition(queued.count == 1); queued.removeFirst()() }
        func complete() { precondition(callback != nil); callback?(.success(process.pid)) }
        func stop() throws -> LegacyStopReceipt {
            try supervisor.stopAfterGateLocked(lockReadback: { !self.gateOpen }, operations: operations)
        }
        func expectFailure(_ expected: LegacySupervisorError) {
            guard case .failure(let error)? = result else { preconditionFailure("Expected launch failure") }
            precondition(error as? LegacySupervisorError == expected)
        }
        func changed(_ process: ProcessBirth) -> ProcessBirth {
            ProcessBirth(pid: process.pid, uid: process.uid, startSeconds: process.startSeconds + 1,
                startMicroseconds: process.startMicroseconds, executable: process.executable)
        }
    }

    static func run() {
        do {
            let existing = try Fixture()
            existing.processes = [existing.process]; existing.begin(); existing.runMain()
            existing.expectFailure(.stillRunning)
            precondition(existing.opens == 0 && existing.signalAttempts.isEmpty)

            // The precheck sees no process; an external launch wins before NSWorkspace's reply.
            let reused = try Fixture()
            reused.begin(); reused.runMain()
            reused.processes = [reused.process]
            reused.complete()
            guard case .success(let returned)? = reused.result else { preconditionFailure("Stable target identity rejected") }
            precondition(returned == reused.process && reused.signalAttempts.isEmpty)
            precondition(reused.completions == 1)
            let ordinary = ProcessBirth(pid: 40_002, uid: getuid(), startSeconds: 1_700_000_001,
                startMicroseconds: 1, executable: "/Applications/Other.app/Contents/MacOS/Other")
            let unselectedEngine = ProcessBirth(pid: 40_004, uid: getuid(), startSeconds: 1_700_000_004,
                startMicroseconds: 1, executable: FileManager.default.homeDirectoryForCurrentUser.path +
                    "/Library/Application Support/adspower_global/cwd_global/fixture/SunBrowser")
            reused.processes.append(contentsOf: [ordinary, unselectedEngine])
            reused.gateOpen = false
            let stopped = try reused.stop()
            precondition(stopped.confirmedExited == [reused.process])
            precondition(reused.processes == [ordinary, unselectedEngine] && reused.deliveredSignals.count == 1)

            let late = try Fixture()
            late.begin(); late.runMain(); late.processes = [late.process]; late.gateOpen = false
            let pendingQuiescent = try late.supervisor.isQuiescent(operations: late.operations)
            precondition(!pendingQuiescent)
            do { _ = try late.stop(); preconditionFailure("Pending callback falsely confirmed cleanup") }
            catch LegacySupervisorError.cleanupLaunchInFlight {}
            late.complete(); late.expectFailure(.gateNotReady)
            precondition(late.signalAttempts.isEmpty && late.completions == 1)
            _ = try late.stop()
            precondition(late.deliveredSignals.count == 1)

            let beforeDispatch = try Fixture()
            beforeDispatch.begin(); beforeDispatch.cancelled = true; beforeDispatch.runMain()
            beforeDispatch.expectFailure(.gateNotReady)
            precondition(beforeDispatch.opens == 0 && beforeDispatch.signalAttempts.isEmpty)
            let duringPrecheck = try Fixture()
            duringPrecheck.beforeInventory = { duringPrecheck.cancelled = true }
            duringPrecheck.begin(); duringPrecheck.runMain(); duringPrecheck.expectFailure(.gateNotReady)
            precondition(duringPrecheck.opens == 0)

            let cancelled = try Fixture()
            cancelled.begin(); cancelled.runMain(); cancelled.processes = [cancelled.process]
            cancelled.cancelled = true; cancelled.complete(); cancelled.expectFailure(.gateNotReady)
            precondition(cancelled.signalAttempts.isEmpty)
            do { _ = try cancelled.stop(); preconditionFailure("Cancellation was mistaken for a closed Gate") }
            catch LegacySupervisorError.gateNotLocked {}
            precondition(cancelled.signalAttempts.isEmpty)
            cancelled.gateOpen = false; _ = try cancelled.stop()
            precondition(cancelled.deliveredSignals.count == 1)

            let changedCallback = try Fixture()
            changedCallback.snapshotTransform = { process, count in count == 2 ? changedCallback.changed(process) : process }
            changedCallback.begin(); changedCallback.runMain(); changedCallback.processes = [changedCallback.process]
            changedCallback.complete(); changedCallback.expectFailure(.launchIdentityMismatch)
            precondition(changedCallback.signalAttempts.isEmpty)

            let changedBeforeSignal = try Fixture()
            changedBeforeSignal.processes = [changedBeforeSignal.process]; changedBeforeSignal.gateOpen = false
            changedBeforeSignal.beforeSignal = { changedBeforeSignal.processes = [changedBeforeSignal.changed(changedBeforeSignal.process)] }
            do { _ = try changedBeforeSignal.stop(); preconditionFailure("Changed identity was signalled") }
            catch LegacySupervisorError.signalFailed(_, ESTALE) {}
            precondition(changedBeforeSignal.deliveredSignals.isEmpty)

            let changedBeforeKill = try Fixture()
            changedBeforeKill.processes = [changedBeforeKill.process]; changedBeforeKill.gateOpen = false
            changedBeforeKill.afterSignal = { _ in
                changedBeforeKill.processes = [changedBeforeKill.changed(changedBeforeKill.process)]
                changedBeforeKill.inventoryOverrides = [[]]
            }
            do { _ = try changedBeforeKill.stop(); preconditionFailure("Reused PID reached KILL") }
            catch LegacySupervisorError.processChanged(_) {}
            precondition(changedBeforeKill.signalAttempts.count == 1 && changedBeforeKill.signalAttempts[0].1 == SIGTERM)

            let signature = try Fixture()
            signature.begin(); signature.runMain(); signature.processes = [signature.process]; signature.signaturesValid = false
            signature.complete(); signature.expectFailure(.launchIdentityMismatch); signature.gateOpen = false
            do { _ = try signature.stop(); preconditionFailure("Unknown signature reached cleanup") }
            catch LegacySupervisorError.signatureMismatch(_) {}
            precondition(signature.signalAttempts.isEmpty)

            let manager = try Fixture(manager: true)
            manager.processes = [manager.process]; manager.begin(); manager.runMain()
            precondition(manager.opens == 1)
            let engine = ProcessBirth(pid: 40_003, uid: getuid(), startSeconds: 1_700_000_002,
                startMicroseconds: 1, executable: manager.target.scopes[1].pathPrefix + "fixture/SunBrowser")
            let unselectedClaude = ProcessBirth(pid: 40_005, uid: getuid(), startSeconds: 1_700_000_005,
                startMicroseconds: 1, executable: reused.target.executablePath)
            manager.processes.append(contentsOf: [engine, unselectedClaude])
            manager.gateOpen = false; manager.complete()
            manager.expectFailure(.gateNotReady); precondition(manager.signalAttempts.isEmpty)
            let engineStop = try manager.stop()
            precondition(engineStop.confirmedExited == [engine] && manager.processes == [manager.process, unselectedClaude])
            precondition(manager.supervisor.protectedScopePaths == [manager.target.scopes[1].pathPrefix])
            print("Production launch/stop coordination fixtures passed: external reuse, pending/late/cancelled callbacks, selected scopes, Manager exclusion, signature and PID changes; all application/process effects injected.")
        } catch { preconditionFailure("Legacy launch coordination fixture: \(error)") }
    }
}
