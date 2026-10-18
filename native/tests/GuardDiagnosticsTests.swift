import Foundation
import Dispatch

private final class ProbeFixture: HTTPSExitProbe {
    var replies: [Result<[String], EnvironmentCheckFailure>]
    var calls = 0
    init(_ replies: [Result<[String], EnvironmentCheckFailure>]) { self.replies = replies }
    func observedAddresses(proxyPort: UInt16, budget: EnvironmentInspectionBudget) throws -> [String] {
        precondition(proxyPort == 17897)
        calls += 1
        return try replies.removeFirst().get()
    }
}

private struct SourceFixture: EnvironmentSource {
    func snapshot() throws -> EnvironmentSnapshot {
        EnvironmentSnapshot(networkGeneration: 7, physicalNetwork: "fixture",
            proxyDescription: "<dictionary> {\n HTTPEnable : 0\n HTTPSEnable : 0\n SOCKSEnable : 0\n ProxyAutoConfigEnable : 0\n ProxyAutoDiscoveryEnable : 0\n}",
            tunRoute: "gateway: 198.18.0.1\ninterface: utun7",
            tunInterface: "inet 198.18.0.1", extensionList: "com.objective-see.lulu.extension [activated enabled]",
            luluPreferences: try PropertyListSerialization.data(fromPropertyList: ["disabled": false], format: .xml, options: 0),
            upstream: [ListenerIdentity(pid: 321, executable: NativeEnvironmentChecker.coreExecutable,
                birth: "1700000000.123456", bindAddress: "127.0.0.1:7896")],
            legacyIngress: [ListenerIdentity(pid: 654, executable: "/fixture/guard",
                birth: "1700000001.123456", bindAddress: "127.0.0.1:17897")], rootPortObservation: nil)
    }
}

// Offline diagnostics: fake captures, Unix sockets and one owned sleep child only.
enum GuardDiagnosticsTests {
    static func run() {
        let parsed = ProductionHTTPSExitProbe.parseOutput("\n__CG_PROBE_METADATA_V1__:0.05;200;0;0;0\n")
        let phase = ProductionHTTPSExitProbe.failurePhase(terminationStatus: 28, timedOut: false,
                                                         metrics: parsed.metrics)
        precondition(phase == .tls)
        for (status, outerTimeout, cause) in [(Int32(28), false, "curl_timeout"),
                                             (7, false, "connection_error"),
                                             (35, false, "tls_error"),
                                             (60, false, "certificate_error"),
                                             (9, true, "process_timeout")] {
            let key = ProductionHTTPSExitProbe.diagnosticKey(endpoint: .ipinfo,
                terminationStatus: status, timedOut: outerTimeout, phase: phase, elapsedMS: 5002)
            precondition(key == "https_probe_ipinfo_status_\(status)_cause_\(cause)_phase_tls_elapsed_ms_5002")
        }
        probeCancellationFixture()
        productionProbeFixtures()
        LegacyLaunchCoordinationTests.run()
        retryFixtures()
        networkEventFixtures()
        targetGateFixtures()
        cleanupDiagnosticFixtures()

        let bridge = GuardLuLuBridge(callback: nil, context: nil)
        let recorded = DispatchSemaphore(value: 0)
        let read = DispatchSemaphore(value: 0)
        let completed = DispatchGroup()
        for reason in ["probe_failed", "renewal_failed"] {
            completed.enter()
            DispatchQueue.global().async {
                defer { completed.leave() }
                var buffer = [CChar](repeating: 0, count: 512)
                let status = buffer.withUnsafeMutableBufferPointer {
                    bridge.record(NativeControlError.rejected(reason), into: $0.baseAddress, capacity: $0.count)
                }
                recorded.signal()
                precondition(read.wait(timeout: .now() + 5) == .success)
                precondition(status == 2 && String(cString: buffer) == reason)
            }
        }
        // Both calls have finished writing before either caller consumes its error.
        for _ in 0..<2 { precondition(recorded.wait(timeout: .now() + 5) == .success) }
        for _ in 0..<2 { read.signal() }
        precondition(completed.wait(timeout: .now() + 5) == .success)

        var buffer = [CChar](repeating: 0, count: 512)
        func record(_ reason: String) -> String {
            let status = buffer.withUnsafeMutableBufferPointer {
                bridge.record(NativeControlError.rejected(reason), into: $0.baseAddress, capacity: $0.count)
            }
            precondition(status == 2)
            return String(cString: buffer)
        }
        let historyBudget = EnvironmentInspectionBudget()
        for _ in 0..<4 {
            historyBudget.record("https_probe_cloudflare_status_unavailable_cause_process_timeout_phase_proxy_connect_elapsed_ms_999999")
        }
        let history = historyBudget.diagnostic(.observation("inspection_budget_exceeded_elapsed_ms_25000"))
        var historyBuffer = [CChar](repeating: 0, count: 1_024)
        let historyStatus = historyBuffer.withUnsafeMutableBufferPointer {
            bridge.record(NativeControlError.rejected(history), into: $0.baseAddress, capacity: $0.count)
        }
        precondition(historyStatus == 2 && String(cString: historyBuffer) == history)
        bridge.reportFault("network_changed")
        precondition(record("operation_invalidated") == "network_changed")
        precondition(record("other_call_failed") == "other_call_failed")
        precondition(record("operation_invalidated") == "network_changed")
        bridge.beginExplicitRecovery()
        precondition(record("operation_invalidated") == "operation_invalidated")
        precondition(bridge.currentService() == nil)
        bridge.dispose()
        let refused: Result<Void, Error> = bridge.withService { _ in
            preconditionFailure("Disposed bridge must not create or run a service")
        }
        guard case .failure(NativeControlError.rejected("bridge_destroyed")) = refused else {
            preconditionFailure("Service creation errors must reach the caller")
        }
        cancelledCallsStayInert()
        print("Probe classifications, concurrent call-local errors and fault-latch fixtures passed.")
    }

    private static func cleanupDiagnosticFixtures() {
        let failures: [(LegacySupervisorError, String)] = [
            (.inspectionIncomplete, "cleanup_process_inspection_incomplete"),
            (.signatureMismatch(41), "cleanup_signature_mismatch_pid_41"),
            (.processChanged(41), "cleanup_process_changed_pid_41"),
            (.cleanupLaunchInFlight, "cleanup_supervisor_launch_in_flight"),
            (.cleanupProcessStillRunning, "cleanup_process_still_running"),
            (.signalFailed(41, 1), "cleanup_signal_failed_pid_41_code_1")
        ]
        for (error, key) in failures { precondition(LuLuServices.cleanupReason(error).key == key) }
        precondition(NativeCleanupDiagnostic.pending(preparation: 0, open: 0, launch: 1).key ==
            "cleanup_pending_prepare_0_open_0_launch_1")
        precondition(NativeCleanupDiagnostic.pending(preparation: Int.max, open: Int.max, launch: Int.max).key.utf8.count < 256)
        precondition(NativeCleanupDiagnostic.confirmationRejected.key == "cleanup_confirmation_rejected")
        var handle: UnsafeMutableRawPointer?
        precondition(guard_lulu_create({ _ in }, nil, &handle) == 0)
        defer { guard_lulu_destroy(handle) }
        var c: Int32 = 0, b: Int32 = 0, o: Int32 = 0, p: Int32 = 0, w: Int32 = 0, n: Int32 = 0
        var text = [CChar](repeating: 120, count: 512)
        text.withUnsafeMutableBufferPointer { buffer in
            precondition(guard_lulu_finish_lock(handle, &c, &b, &o, &p, &w, &n, buffer.baseAddress, 0) == 4)
            precondition(guard_lulu_finish_lock(handle, &c, &b, &o, &p, &w, &n, buffer.baseAddress, 513) == 4)
            precondition(guard_lulu_finish_lock(handle, &c, &b, &o, &p, &w, &n, buffer.baseAddress, buffer.count) == 0)
        }
        precondition(c == 1 && b == 0 && o == 0 && p == 0 && w == 0 && n == 0 && text[0] == 0)
    }

    private static func cancelledCallsStayInert() {
        var handle: UnsafeMutableRawPointer?
        precondition(guard_lulu_create({ _ in }, nil, &handle) == 0)
        defer { guard_lulu_destroy(handle) }
        var error = [CChar](repeating: 0, count: 512)
        error.withUnsafeMutableBufferPointer { buffer in
            precondition(guard_lulu_prepare(handle, { _ in 0 }, nil, buffer.baseAddress, buffer.count) == 2)
            "claude".withCString { target in
                precondition(guard_lulu_open(handle, 1, target, { _ in 0 }, nil, buffer.baseAddress, buffer.count) == 2)
                precondition(guard_lulu_launch(handle, target, 1, { _ in 0 }, nil, buffer.baseAddress, buffer.count) == 2)
            }
        }
        let value = Unmanaged<GuardLuLuBridge>.fromOpaque(handle!).takeUnretainedValue()
        precondition(value.currentService() == nil)
    }

    private static func networkEventFixtures() {
        let scope = NetworkEventScope(services: ["fixture-service"], interfaces: ["en0"])
        let known: [String: NetworkEventCategory] = [
            "State:/Network/Global/IPv4": .globalAddress,
            "State:/Network/Global/DNS": .globalDNS,
            "Setup:/Network/Global/Proxies": .globalProxy,
            "State:/Network/Service/fixture-service/IPv6": .serviceAddress,
            "Setup:/Network/Service/fixture-service/DNS": .serviceDNS,
            "State:/Network/Service/fixture-service/Proxies": .serviceProxy,
            "State:/Network/Interface/en0/Link": .interfaceLink,
        ]
        for (key, category) in known {
            precondition(NetworkEventPolicy.classify([key], scope: scope) == [category])
        }
        let subscribed = NetworkEventPolicy.subscriptionKeys(scope: scope)
        precondition(!NetworkEventPolicy.classify(subscribed, scope: scope).contains(.unclassifiedNotification))
        for keys: [String]? in [nil, [], ["unknown"], ["State:/Network/Interface/en9/Link"]] {
            precondition(NetworkEventPolicy.classify(keys, scope: scope) == [.unclassifiedNotification])
        }
        precondition(NetworkEventPolicy.classify(["State:/Network/Global/DNS", "unknown"], scope: scope)
            == [.globalDNS, .unclassifiedNotification])
        precondition(Set(WiFiAssociationEvent.allCases.map(\.category)).count == WiFiAssociationEvent.allCases.count)
    }

    private static func targetGateFixtures() {
        do {
            let claude = try SwiftNativeGate.fixture(entryPort: 17_897)
            let browser = try SwiftNativeGate.fixture(entryPort: 17_898)
            let fence = LuLuGateFence(claude: claude, sunbrowser: browser, onFault: { _ in })
            try fence.bindClosed(expected: 0)
            precondition(fence.gateLocked(at: 0))
            try fence.open(target: "claude", generation: 1, expected: 0)
            precondition(claude.status().open && !browser.status().open)
            precondition(!fence.gateOpen(at: 0, target: "sunbrowser"))
            do { _ = try fence.beginLaunch(target: "sunbrowser"); preconditionFailure("unselected target launched") }
            catch NativeControlError.rejected("gate_locked") {}
            _ = try fence.beginLaunch(target: "claude"); fence.endLaunch()
            try fence.renew(1, expected: 0)
            precondition(!browser.status().open && fence.cleanupState().targets == ["claude"])
            fence.emergencyLock()
            precondition(fence.gateLocked(at: 1) && fence.confirmCleanup(at: 1))
            try fence.open(target: "sunbrowser", generation: 2, expected: 1)
            precondition(browser.status().open && !claude.status().open)
            _ = try fence.beginLaunch(target: "sunbrowser"); fence.endLaunch()
            precondition(fence.cleanupState().targets == ["sunbrowser"])
            try fence.open(target: "claude", generation: 3, expected: 1)
            precondition(claude.status().open && browser.status().open)
            fence.fault(reason: "fixture_fault")
            precondition(fence.gateLocked(at: 2) && !fence.gateOpen(at: 2))
            do { try fence.open(target: "mcp", generation: 4, expected: 2); preconditionFailure("unknown target granted") }
            catch NativeControlError.rejected("open_invalidated") {}
            fence.release()
            precondition(!claude.status().bound && !browser.status().bound)
            print("Independent target gate/lease/cleanup fixtures passed with Unix sockets only.")
        } catch { preconditionFailure("Target gate fixture: \(error)") }
    }

    private static func probeCancellationFixture() {
        // Only this fixture owns a harmless sleeping child; never a user's process.
        let started = DispatchTime.now().uptimeNanoseconds
        let result = ProductionEnvironmentSource.capture("/bin/sleep", ["2"], timeoutSeconds: 1,
            isCurrent: { DispatchTime.now().uptimeNanoseconds - started < 50_000_000 })
        precondition(result.cancelled && !result.timedOut && result.elapsedMS < 1_000)
        print("Owned offline sleep-child cancellation fixture passed; no host inspection/network.")
    }

    private static func productionProbeFixtures() {
        func reply(_ body: String, status: Int32 = 0, elapsedMS: UInt64 = 1) -> ProductionEnvironmentSource.ProcessCapture {
            let metadata = status == 0 ? "0.01;200;0.02;0.03;200" : "0.01;200;0;0;0"
            return .init(output: Data((body + "\n__CG_PROBE_METADATA_V1__:" + metadata + "\n").utf8),
                terminationStatus: status, timedOut: false, outputLimitExceeded: false,
                readFailed: false, elapsedMS: elapsedMS)
        }
        func inspect(_ probe: ProductionHTTPSExitProbe, budget: EnvironmentInspectionBudget,
                     validateRetry: @escaping () throws -> Void = {}) -> EnvironmentCheckReport {
            NativeEnvironmentChecker(source: SourceFixture(), probe: probe,
                expectedIngressExecutable: "/fixture/guard")
                .probeThroughIngress(validateRetry: validateRetry, budget: budget)
        }
        let expected = NativeEnvironmentChecker.expectedIP
        for wrongSite in [0, 1] {
            var calls = 0
            let probe = ProductionHTTPSExitProbe { arguments, _, _ in
                precondition(!arguments.contains("--insecure") && !arguments.contains("-k"))
                precondition(arguments.contains("--disable") && arguments.contains("--proxy"))
                let site = calls; calls += 1
                // The old implementation reached a later timeout and could retry away a wrong first IP.
                if wrongSite == 0 && site == 1 { return reply("", status: 28) }
                return reply(site == 0 ? (wrongSite == 0 ? "203.0.113.1" : expected)
                    : "ip=203.0.113.1")
            }
            let report = inspect(probe, budget: EnvironmentInspectionBudget(), validateRetry: {
                preconditionFailure("A wrong IP must never reach retry admission")
            })
            precondition(!report.observationsMatch && calls == wrongSite + 1)
            guard case .probe(let key, retryable: false)? = report.failure else {
                preconditionFailure("Missing terminal wrong-IP cause")
            }
            precondition(key.contains(wrongSite == 0 ? "ipinfo" : "cloudflare"))
            precondition(key.contains("exit_mismatch") && !key.contains("203.0.113"))
        }
        for status: Int32 in [35, 60] {
            var calls = 0
            let probe = ProductionHTTPSExitProbe { _, _, _ in calls += 1; return reply("", status: status) }
            let report = inspect(probe, budget: EnvironmentInspectionBudget(), validateRetry: {
                preconditionFailure("TLS/certificate failures must never retry")
            })
            precondition(!report.observationsMatch && calls == 1)
        }
        var now: UInt64 = 1_000_000_000
        var calls = 0
        var admissions = 0
        var limits: [Double] = []
        let budget = EnvironmentInspectionBudget(clock: { now })
        let probe = ProductionHTTPSExitProbe { arguments, timeout, _ in
            let remaining = Double(26_000_000_000 - now) / 1_000_000_000
            let connect = Double(arguments[arguments.firstIndex(of: "--connect-timeout")! + 1])!
            let transfer = Double(arguments[arguments.firstIndex(of: "--max-time")! + 1])!
            precondition(connect <= remaining && transfer <= remaining && timeout <= remaining)
            precondition(connect <= 5 && transfer <= 8 && timeout <= 10)
            limits.append(timeout)
            calls += 1
            let duration: UInt64 = calls <= 2 ? 9_000_000_000 : calls == 3 ? 4_000_000_000 : 3_000_000_000
            now += duration
            return reply(calls % 2 == 1 ? expected : "", status: calls % 2 == 1 ? 0 : 28,
                         elapsedMS: duration / 1_000_000)
        }
        let exhausted = inspect(probe, budget: budget, validateRetry: { admissions += 1 })
        precondition(!exhausted.observationsMatch && calls == 4 && admissions == 1)
        precondition(limits == [10, 10, 7, 3])
        precondition(exhausted.failure == .observation("inspection_budget_exceeded_elapsed_ms_25000"))
        precondition(exhausted.probeDiagnostics.count == 4)
        precondition(exhausted.probeDiagnostics.allSatisfy { $0.count <= 128 && !$0.contains(expected) })
        precondition(budget.diagnostic(exhausted.failure).contains("cloudflare_status_28"))

        now = 1_000_000_000; calls = 0
        let admissionBudget = EnvironmentInspectionBudget(clock: { now })
        let admissionProbe = ProductionHTTPSExitProbe { _, _, _ in
            calls += 1; now += 4_000_000_000; return reply("", status: 28)
        }
        let noRetryBudget = inspect(admissionProbe, budget: admissionBudget, validateRetry: { now += 21_000_000_000 })
        precondition(calls == 1 && noRetryBudget.failure == .observation("inspection_budget_exceeded_elapsed_ms_25000"))

        now = 1_000_000_000; calls = 0
        let interruptedBudget = EnvironmentInspectionBudget(clock: { now })
        let interrupted = inspect(ProductionHTTPSExitProbe { _, _, check in
            precondition(check()); calls += 1; now += 25_000_000_000
            precondition(!check(), "In-flight deadline predicate must use the shared continuous clock")
            var result = reply(""); result.cancelled = true
            return result
        }, budget: interruptedBudget)
        precondition(calls == 1 && interrupted.failure == .observation("inspection_budget_exceeded_elapsed_ms_25000"))
        precondition(interrupted.probeDiagnostics.count == 1 && interrupted.probeDiagnostics[0].contains("interrupted"))

        var current = true; calls = 0
        let cancellationBudget = EnvironmentInspectionBudget(isCurrent: { current })
        let cancelled = inspect(ProductionHTTPSExitProbe { _, _, check in
            precondition(check()); calls += 1; current = false; return reply(expected)
        }, budget: cancellationBudget)
        precondition(calls == 1 && cancelled.failure == .observation("inspection_cancelled"))
        let cancelledBeforeRequest = inspect(ProductionHTTPSExitProbe { _, _, _ in
            preconditionFailure("Cancelled inspection started a request")
        }, budget: EnvironmentInspectionBudget(isCurrent: { false }))
        precondition(cancelledBeforeRequest.failure == .observation("inspection_cancelled"))
        print("Production probe fixtures passed: both wrong-IP sites, no masked retry, TLS, shared deadline, retry admission and cancellation; no subprocess/network.")
    }

    private static func retryFixtures() {
        for code in [Int32(7), 28] {
            precondition(ProductionHTTPSExitProbe.permitsRetry(terminationStatus: code, timedOut: false, phase: .tls))
        }
        for code in [Int32(0), 22, 35, 60] {
            precondition(!ProductionHTTPSExitProbe.permitsRetry(terminationStatus: code, timedOut: false, phase: .tls))
        }
        precondition(!ProductionHTTPSExitProbe.permitsRetry(terminationStatus: 28, timedOut: true, phase: .process))
        let success: Result<[String], EnvironmentCheckFailure> = .success(Array(repeating: NativeEnvironmentChecker.expectedIP, count: 2))
        let timeout: Result<[String], EnvironmentCheckFailure> = .failure(.probe("timeout", retryable: true))
        func inspect(_ replies: [Result<[String], EnvironmentCheckFailure>], validate: (() throws -> Void)? = nil)
            -> (EnvironmentCheckReport, Int) {
            let probe = ProbeFixture(replies)
            let checker = NativeEnvironmentChecker(source: SourceFixture(), probe: probe,
                expectedIngressExecutable: "/fixture/guard")
            return (checker.probeThroughIngress(validateRetry: validate), probe.calls)
        }
        let strict = inspect([timeout, success])
        precondition(!strict.0.observationsMatch && strict.1 == 1)
        let recovered = inspect([timeout, success], validate: {})
        precondition(recovered.0.observationsMatch && !recovered.0.productionObserved && recovered.1 == 2)
        let exhausted = inspect([timeout, timeout, success], validate: {})
        precondition(!exhausted.0.observationsMatch && exhausted.1 == 2)
        let certificate = inspect([.failure(.probe("certificate_error", retryable: false)), success], validate: {
            preconditionFailure("Certificate failure must never reach retry admission")
        })
        precondition(certificate.1 == 1)
        let mismatch = inspect([.success(["203.0.113.1", "203.0.113.1"]), success], validate: {})
        precondition(mismatch.0.failure == .exitMismatch && mismatch.1 == 1)
        for failure in [EnvironmentCheckFailure.networkChanged, .observation("public_observation_expired")] {
            let refused = inspect([timeout, success], validate: { throw failure })
            precondition(refused.0.failure == failure && refused.1 == 1)
        }
        var validations = 0
        let expiredDuringRetry = inspect([timeout, success], validate: {
            validations += 1
            if validations == 2 { throw EnvironmentCheckFailure.observation("public_observation_expired") }
        })
        precondition(!expiredDuringRetry.0.observationsMatch && expiredDuringRetry.1 == 2 && validations == 2)
        let stamp = NativeCheckStamp(fingerprint: "fixture", generation: 7, checkedAtNS: 1,
            observedIP: NativeEnvironmentChecker.expectedIP, observedAtUnixMS: 1,
            upstreamFingerprint: "fixture", ingressFingerprint: "fixture")
        precondition(stamp.hasFreshPublicObservation(at: 60_000_000_001))
        precondition(!stamp.hasFreshPublicObservation(at: 60_000_000_002))
        print("Single retry, strict start, certificate/IP refusal and unchanged 60-second expiry fixtures passed.")
    }
}
