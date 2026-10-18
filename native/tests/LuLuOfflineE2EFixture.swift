#if GUARD_OFFLINE_E2E
import Foundation
import Darwin

private struct OfflineE2ESource: EnvironmentSource {
    func snapshot() throws -> EnvironmentSnapshot { throw EnvironmentCheckFailure.observation("unexpected_fixture_probe") }
}
private struct OfflineE2EProbe: HTTPSExitProbe {
    func observedAddresses(proxyPort: UInt16, budget: EnvironmentInspectionBudget) throws -> [String] {
        throw EnvironmentCheckFailure.observation("unexpected_fixture_probe")
    }
}

// Every process effect is synthetic. Gates use NG_OFFLINE_TEST Unix socketpairs.
final class LuLuOfflineE2EFixture {
    let supervisor: LegacyApplicationSupervisor
    let manifest: LuLuManifest
    let checker: NativeEnvironmentChecker
    private let process: ProcessBirth
    private let lock = NSLock()
    private let holdCallback: Bool
    private let scenario: Int32
    private var refuseSignal: Bool
    private var present = false
    private var signals: Int32 = 0
    private var inventoryPass = 0
    private var legacyInventoryFailure = false
    private var callback: ((Result<Int32, Error>) -> Void)?

    init(scenario: Int32) throws {
        self.scenario = scenario
        let target = LegacyTarget(targetID: "claude", bundlePath: "/Applications/Claude.app",
            executablePath: "/Applications/Claude.app/Contents/MacOS/Claude",
            arguments: ["--proxy-server=http://127.0.0.1:17897", "--disable-quic"],
            scopes: [LegacyScope(pathPrefix: "/Applications/Claude.app/Contents/", codeRequirement: "fixture")])
        supervisor = try LegacyApplicationSupervisor(targets: [target])
        manifest = LuLuManifest(schemaVersion: 1, route: "offline-fixture", controllerBundleID: "fixture",
            controllerUID: getuid(), home: FileManager.default.homeDirectoryForCurrentUser.path,
            pythonExecutable: "/fixture", factsScriptSHA256: String(repeating: "a", count: 64),
            firewallPolicySHA: String(repeating: "b", count: 64), baselineFiles: [],
            legacyTargets: [target], disabledTargets: ["sunbrowser", "ccbaga_browser", "claude_code", "mcp"])
        checker = NativeEnvironmentChecker(source: OfflineE2ESource(), probe: OfflineE2EProbe(), expectedIngressExecutable: "/fixture")
        process = ProcessBirth(pid: 40_101, uid: getuid(), startSeconds: 1_700_000_000,
            startMicroseconds: 1, executable: target.executablePath)
        holdCallback = scenario == 1
        refuseSignal = scenario == 2
    }

    var operations: LegacyApplicationSupervisor.Operations {
        .init(dispatchMain: { work in DispatchQueue.global().async(execute: work) },
            openApplication: { _, completion in
                self.lock.lock(); self.present = true
                if self.holdCallback { self.callback = completion }
                self.lock.unlock()
                if !self.holdCallback { completion(.success(self.process.pid)) }
            }, snapshot: { _ in
                self.lock.lock(); defer { self.lock.unlock() }
                guard self.present else { throw LegacySupervisorError.launchIdentityMismatch }
                return self.process
            }, signatureMatches: { _, _ in true }, physicalPath: { _ in true }, currentUID: getuid(),
            inventory: { scopes in
                self.lock.lock(); defer { self.lock.unlock() }
                if (30...33).contains(self.scenario), self.present || self.signals > 0 {
                    self.inventoryPass += 1
                    if self.inventoryPass == Int(self.scenario - 29) {
                        throw LegacySupervisorError.inspectionFailure(self.inventoryEvidence(.status))
                    }
                }
                guard self.present, let scope = scopes.first(where: { self.process.executable.hasPrefix($0.pathPrefix) }) else { return [] }
                if (10...25).contains(self.scenario) {
                    if self.legacyInventoryFailure { throw LegacySupervisorError.inspectionIncomplete }
                    throw LegacySupervisorError.inspectionFailure(self.inventoryEvidence(
                        InventoryFailure.Step.allCases[Int(self.scenario - 10)]))
                }
                if self.scenario == 3 { throw LegacySupervisorError.signatureMismatch(self.process.pid) }
                if self.scenario == 4 { throw LegacySupervisorError.inspectionIncomplete }
                if self.scenario == 6 { throw LegacySupervisorError.processChanged(self.process.pid) }
                return [(self.process, scope)]
            }, signalIfSame: { pin, _, signal in
                self.lock.lock(); defer { self.lock.unlock() }
                guard pin == self.process, !self.refuseSignal else { return ESTALE }
                guard self.present else { return ESRCH }
                precondition(signal == SIGTERM || signal == SIGKILL)
                self.signals += 1
                if self.scenario != 5 { self.present = false }
                return 0
            })
    }

    private func inventoryEvidence(_ step: InventoryFailure.Step) -> InventoryFailure {
        InventoryFailure(target: .sunbrowser, step: step, pid: process.pid, rc: EACCES,
            call: 2, raw: -17, os: 1, value: 8192, identity: EPERM,
            ps: 5, psCode: 1, psBytes: 8193, psFlags: 1)
    }

    func control(_ action: Int32) -> Int32 {
        lock.lock()
        if action == 1 {
            let completion = callback; callback = nil; lock.unlock()
            completion?(.success(process.pid))
            return completion == nil ? -2 : 0
        }
        if action == 2 { refuseSignal = false }
        if action == 4 { legacyInventoryFailure = true }
        if action == 3 { present = false } // synthetic late exit, no OS process is involved
        let state: Int32 = (callback == nil ? 0 : 1) | (present ? 2 : 0) | (signals << 8)
        lock.unlock()
        return state
    }
}
#endif
