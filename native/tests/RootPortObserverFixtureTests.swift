import Foundation

enum EnvironmentCheckFailure: Error, Equatable {
    case observation(String)
}

struct ListenerIdentity: Equatable {
    let pid: Int32
    let executable: String
    let birth: String
    let bindAddress: String
}

@_cdecl("cng_observer_process_identity")
func fixtureProcessIdentity(_ pid: Int32, _ sec: UnsafeMutablePointer<UInt64>,
                            _ usec: UnsafeMutablePointer<UInt64>, _ path: UnsafeMutablePointer<CChar>,
                            _ size: UInt32) -> Int32 {
    return 0
}

@main
struct RootPortObserverFixtureTests {
    struct Socket: Equatable {
        let port: Int
        let address: String
        let pid: Int32
    }

    static let boot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    static let otherBoot = "11111111-2222-4333-8444-555555555555"
    static let wall: Int64 = 1_800_000_000_000
    static let mono: Int64 = 9_000_000_000_000

    static func row(_ port: Int) -> [String: Any] {
        ["port": port,
         "local_address": "127.0.0.1.\(port)",
         "pid": port == 7896 ? 91 : 42,
         "process_start_sec": port == 7896 ? 1_700_000_000 : 1_700_000_001,
         "process_start_usec": port == 7896 ? 123_456 : 654_321,
         "executable_path": port == 7896 ? "/Applications/FlClash.app/Contents/MacOS/FlClashCore" : "/Applications/Guard.app/Contents/MacOS/Guard"]
    }

    static func payload(_ ports: [Int], wall observedWall: Int64 = wall,
                        mono observedMono: Int64 = mono, boot observedBoot: String = boot,
                        ok: Bool = true, status: String = "ok") -> Data {
        let value: [String: Any] = [
            "ok": ok,
            "status": status,
            "observed_at_unix_ms": observedWall,
            "observed_monotonic_ns": observedMono,
            "boot_session_uuid": observedBoot,
            "listeners": ports.map(row)
        ]
        return try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    }

    static func expectedIngress() -> ListenerIdentity {
        ListenerIdentity(pid: 42, executable: "/Applications/Guard.app/Contents/MacOS/Guard",
                         birth: "1700000001.654321", bindAddress: "127.0.0.1:17897")
    }

    static func sockets(_ ports: [Int]) -> [Socket] {
        ports.map { Socket(port: $0, address: "127.0.0.1", pid: $0 == 7896 ? 91 : 42) }
    }

    static func capture(_ sockets: [Socket], status: PortObserverCandidate.CaptureStatus = .success)
        -> PortObserverCandidate.Capture {
        var lines: [String] = []
        for socket in sockets {
            lines.append("p\(socket.pid)")
            lines.append("n\(socket.address):\(socket.port)")
        }
        return PortObserverCandidate.Capture(status: status,
            bytes: Data(lines.joined(separator: "\n").utf8))
    }

    static func processIdentity(_ pid: Int32, seconds: UInt64? = nil, path: String? = nil)
        -> PortObserverCandidate.ProcessIdentity {
        let upstream = pid == 91
        return PortObserverCandidate.ProcessIdentity(pid: pid,
            startSeconds: seconds ?? (upstream ? 1_700_000_000 : 1_700_000_001),
            startMicroseconds: upstream ? 123_456 : 654_321,
            executablePath: path ?? (upstream
                ? "/Applications/FlClash.app/Contents/MacOS/FlClashCore"
                : "/Applications/Guard.app/Contents/MacOS/Guard"))
    }

    static func candidateTrace(first: [Socket], second: [Socket]? = nil,
                               status: PortObserverCandidate.CaptureStatus = .success,
                               startMono: Int64 = mono - 1,
                               finishMono: Int64 = mono,
                               identityResponses: [Int32: [PortObserverCandidate.ProcessIdentity?]]? = nil)
        -> (Data, RootPortObserver.Diagnostic) {
        let captures = [capture(first, status: status), capture(second ?? first, status: status)]
        var captureIndex = 0
        var clockIndex = 0
        var identityCalls: [Int32: Int] = [:]
        let encoded = PortObserverCandidate.sample(capture: {
            defer { captureIndex += 1 }
            return captures[min(captureIndex, captures.count - 1)]
        }, clock: {
            defer { clockIndex += 1 }
            return clockIndex == 0
                ? PortObserverCandidate.ClockReading(wallMS: wall - 1, monotonicNS: startMono)
                : PortObserverCandidate.ClockReading(wallMS: wall, monotonicNS: finishMono)
        }, bootSessionUUID: { boot }) { pid in
            let call = identityCalls[pid, default: 0]
            identityCalls[pid] = call + 1
            if let responses = identityResponses, let perPID = responses[pid] {
                return call < perPID.count ? perPID[call] : nil
            }
            return processIdentity(pid)
        }
        let facts = RootPortObserver.diagnose(data: encoded, wallNowMS: wall,
            monotonicNowNS: mono, currentBootUUID: boot,
            liveIngressIdentity: (second ?? first).contains(where: { $0.port == 17897 })
                ? expectedIngress() : nil)
        return (encoded, facts)
    }

    static func candidate(_ ports: [Int], status: PortObserverCandidate.CaptureStatus = .success,
                          identityAvailable: Bool = true) -> (Data, RootPortObserver.Diagnostic) {
        let responses: [Int32: [PortObserverCandidate.ProcessIdentity?]]? = identityAvailable ? nil : [
            91: [nil, nil], 42: [nil, nil]
        ]
        return candidateTrace(first: sockets(ports), status: status, identityResponses: responses)
    }

    static func observe(_ ports: [Int], wall observedWall: Int64 = wall,
                        mono observedMono: Int64 = mono, boot observedBoot: String = boot,
                        ok: Bool = true, status: String = "ok",
                        liveIngress: ListenerIdentity? = expectedIngress()) -> RootPortObserver.Diagnostic {
        RootPortObserver.diagnose(data: payload(ports, wall: observedWall, mono: observedMono,
            boot: observedBoot, ok: ok, status: status),
            wallNowMS: wall, monotonicNowNS: mono, currentBootUUID: boot,
            liveIngressIdentity: ports.contains(17897) ? liveIngress : nil)
    }

    static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else { fatalError("FAIL: \(message)") }
        print("PASS: \(message)")
    }

    static func main() {
        let both = observe([7896, 17897], wall: wall - 1, mono: mono - 1)
        expect(both.upstream.state == .present && both.ingress.state == .present,
               "both listener facts remain available")
        expect(RootPortObserver.admissionFailure(both) == nil,
               "complete same-boot fresh observation is admissible")
        let nextTick = observe([7896, 17897])
        expect(both.observedAtUnixMS != nextTick.observedAtUnixMS && both.sameFacts(as: nextTick),
               "new sample timestamps do not masquerade as network-generation changes")

        let gateMissing = observe([7896])
        expect(gateMissing.upstream.state == .present && gateMissing.ingress.state == .missing,
               "missing 17897 Gate preserves the 7896 upstream fact")
        expect(RootPortObserver.admissionFailure(gateMissing) == "root_observer_missing_listener",
               "missing Gate cannot be admitted")

        let upstreamMissing = observe([17897])
        expect(upstreamMissing.upstream.state == .missing && upstreamMissing.ingress.state == .present,
               "missing 7896 upstream preserves the 17897 Gate fact")
        expect(RootPortObserver.admissionFailure(upstreamMissing) == "root_observer_missing_listener",
               "missing upstream cannot be admitted")

        let neither = observe([])
        expect(neither.upstream.state == .missing && neither.ingress.state == .missing,
               "both missing listeners are reported independently")
        expect(RootPortObserver.admissionFailure(neither) == "root_observer_missing_listener",
               "neither listener cannot be admitted")

        let legacyUnknown = observe([], ok: false, status: "missing_listener")
        expect(legacyUnknown.producerStatus == "missing_listener" &&
               legacyUnknown.upstream.state == .unavailable && legacyUnknown.ingress.state == .unavailable &&
               RootPortObserver.admissionFailure(legacyUnknown) == "root_observer_missing_listener",
               "legacy missing_listener with an empty row list means unknown, not absent")
        for status in ["netstat_read_failed", "spawn_failed", "too_large"] {
            let failed = observe([], ok: false, status: status)
            expect(failed.upstream.state == .unavailable && failed.ingress.state == .unavailable &&
                   failed.producerStatus == status,
                   "legacy query failure \(status) keeps both ports unknown")
        }
        let partialLegacy = observe([7896], ok: false, status: "netstat_read_failed")
        expect(partialLegacy.upstream.state == .present &&
               partialLegacy.upstream.queryState == .failure &&
               partialLegacy.ingress.state == .unavailable &&
               RootPortObserver.admissionFailure(partialLegacy) == "root_observer_netstat_read_failed",
               "legacy partial rows stay visible but a failed whole scan is not a successful port query")

        let unreadable = RootPortObserver.diagnose(data: nil, readFailure: "root_observer_path",
            wallNowMS: wall, monotonicNowNS: mono, currentBootUUID: boot)
        expect(unreadable.fileState == .unreadable &&
               RootPortObserver.admissionFailure(unreadable) == "root_observer_path",
               "unreadable observer file remains diagnostic and fails closed")

        let oldBoot = observe([7896, 17897], boot: otherBoot)
        expect(oldBoot.bootState == .mismatch &&
               RootPortObserver.admissionFailure(oldBoot) == "root_observer_boot",
               "old boot observation cannot be admitted")

        let stale = observe([7896, 17897], wall: wall - 2_501,
                            mono: mono - 2_501_000_000)
        expect(stale.wallFreshness == .stale && stale.monotonicFreshness == .stale &&
               RootPortObserver.admissionFailure(stale) == "root_observer_stale",
               "stale wall and monotonic observations cannot be admitted")

        let mixed = observe([7896, 17897], wall: wall - 1,
                            mono: mono - 2_501_000_000)
        expect(mixed.wallFreshness == .fresh && mixed.monotonicFreshness == .stale &&
               RootPortObserver.admissionFailure(mixed) == "root_observer_stale",
               "mixed fresh wall and stale monotonic stamps cannot be admitted")

        let wrongOwner = ListenerIdentity(pid: 43, executable: expectedIngress().executable,
            birth: expectedIngress().birth, bindAddress: expectedIngress().bindAddress)
        let ownerMismatch = observe([7896, 17897], liveIngress: wrongOwner)
        expect(ownerMismatch.ingressOwnerState == .mismatch &&
               RootPortObserver.admissionFailure(ownerMismatch) == "ingress_process_changed",
               "mismatched ingress owner cannot be admitted")

        var malformed = try! JSONSerialization.jsonObject(with: payload([7896, 17897])) as! [String: Any]
        var rows = malformed["listeners"] as! [[String: Any]]
        rows[1]["local_address"] = "127.0.0.2.17897"
        malformed["listeners"] = rows
        let malformedData = try! JSONSerialization.data(withJSONObject: malformed)
        let invalidRow = RootPortObserver.diagnose(data: malformedData,
            wallNowMS: wall, monotonicNowNS: mono, currentBootUUID: boot)
        expect(invalidRow.ingress.state == .invalid && invalidRow.ingress.listeners.first?.pid == 42 &&
               invalidRow.ingress.listeners.first?.localAddress == "127.0.0.2.17897" &&
               invalidRow.upstream.state == .present &&
               RootPortObserver.admissionFailure(invalidRow) == "root_observer_listener",
               "invalid row retains reported port fields without authorizing it")

        expect(both.producerStatus == "ok" && both.schemaState == .valid &&
               both.upstream.reportedIdentities.first?.pid == 91,
               "native facts retain producer status and identity for integration mapping")

        let candidateBoth = candidate([7896, 17897])
        expect(candidateBoth.1.producerStatus == "ok" && candidateBoth.1.schemaState == .valid &&
               candidateBoth.1.upstream.state == .present && candidateBoth.1.ingress.state == .present &&
               RootPortObserver.admissionFailure(candidateBoth.1) == nil,
               "candidate producer reports both identities from one successful injected capture")

        let candidateGateMissing = candidate([7896])
        let candidateUpstreamMissing = candidate([17897])
        let candidateNeither = candidate([])
        expect(candidateGateMissing.1.upstream.state == .present &&
               candidateGateMissing.1.ingress.state == .missing &&
               RootPortObserver.admissionFailure(candidateGateMissing.1) == "root_observer_missing_listener",
               "candidate preserves upstream when Gate is absent")
        expect(candidateUpstreamMissing.1.upstream.state == .missing &&
               candidateUpstreamMissing.1.ingress.state == .present &&
               RootPortObserver.admissionFailure(candidateUpstreamMissing.1) == "root_observer_missing_listener",
               "candidate preserves Gate when upstream is absent")
        expect(candidateNeither.1.upstream.state == .missing && candidateNeither.1.ingress.state == .missing &&
               RootPortObserver.admissionFailure(candidateNeither.1) == "root_observer_missing_listener",
               "successful empty capture reports both expected ports absent")

        let candidateReadFailed = candidate([7896, 17897], status: .readFailed)
        expect(candidateReadFailed.1.producerStatus == "lsof_read_failed" &&
               candidateReadFailed.1.upstream.state == .present &&
               candidateReadFailed.1.ingress.state == .present &&
               RootPortObserver.admissionFailure(candidateReadFailed.1) == "root_observer_lsof_read_failed",
               "partial rows from failed capture remain diagnostic and are not admitted")
        let candidatePartiallyRead = candidate([7896], status: .readFailed)
        expect(candidatePartiallyRead.1.upstream.state == .present &&
               candidatePartiallyRead.1.ingress.state == .unavailable &&
               RootPortObserver.admissionFailure(candidatePartiallyRead.1) == "root_observer_lsof_read_failed",
               "failed capture preserves its available port fact and leaves the other unknown")

        let candidateIdentityFailed = candidate([7896, 17897], identityAvailable: false)
        expect(candidateIdentityFailed.1.producerStatus == "identity_read_failed" &&
               candidateIdentityFailed.1.upstream.state == .unavailable &&
               candidateIdentityFailed.1.ingress.state == .unavailable &&
               candidateIdentityFailed.1.upstream.listeners.isEmpty &&
               candidateIdentityFailed.1.ingress.listeners.isEmpty &&
               RootPortObserver.admissionFailure(candidateIdentityFailed.1) == "root_observer_identity_read_failed",
               "unavailable process identity is not fabricated or admitted")

        let oldPIDIdentity = processIdentity(91, seconds: 1_600_000_000)
        let reusedPIDIdentity = processIdentity(91, seconds: 1_700_000_010)
        let reusedAfterLsof = candidateTrace(first: sockets([7896]), identityResponses: [
            91: [oldPIDIdentity, reusedPIDIdentity]
        ])
        expect(reusedAfterLsof.1.producerStatus == "identity_changed" &&
               reusedAfterLsof.1.upstream.state == .unavailable &&
               reusedAfterLsof.1.upstream.queryState == .failure &&
               reusedAfterLsof.1.upstream.reportedIdentities.isEmpty &&
               RootPortObserver.admissionFailure(reusedAfterLsof.1) == "root_observer_identity_changed",
               "PID reuse after the second lsof cannot attach a new birth identity to the old row")

        let reusedBetweenSamples = candidateTrace(first: sockets([7896]), identityResponses: [
            91: [reusedPIDIdentity, reusedPIDIdentity]
        ])
        expect(reusedBetweenSamples.1.producerStatus == "ok" &&
               reusedBetweenSamples.1.upstream.reportedIdentities.first?.birth == "1700000010.123456",
               "second lsof plus matching identity reads binds the reused PID to the current row")

        let changedEndpoint = candidateTrace(first: sockets([7896]), second: [
            Socket(port: 7896, address: "127.0.0.2", pid: 91)
        ])
        expect(changedEndpoint.1.producerStatus == "sample_changed" &&
               changedEndpoint.1.upstream.state == .unavailable &&
               changedEndpoint.1.upstream.queryState == .failure &&
               changedEndpoint.1.upstream.reportedIdentities.isEmpty &&
               RootPortObserver.admissionFailure(changedEndpoint.1) == "root_observer_sample_changed",
               "endpoint changes across bounded samples remain visible but cannot be admitted")

        let longSample = candidateTrace(first: sockets([7896, 17897]),
            startMono: mono - PortObserverCandidate.maxSampleDurationNS - 1,
            finishMono: mono)
        expect(longSample.1.producerStatus == "sampling_too_long" &&
               longSample.1.upstream.queryState == .failure && longSample.1.ingress.queryState == .failure &&
               longSample.1.upstream.state == .unavailable && longSample.1.ingress.state == .unavailable &&
               RootPortObserver.admissionFailure(longSample.1) == "root_observer_sampling_too_long",
               "overlong sample does not claim port states and fails the freshness contract")

        let wrongPID = PortObserverCandidate.ProcessIdentity(pid: 999,
            startSeconds: reusedPIDIdentity.startSeconds,
            startMicroseconds: reusedPIDIdentity.startMicroseconds,
            executablePath: reusedPIDIdentity.executablePath)
        let identityMismatch = candidateTrace(first: sockets([7896]), identityResponses: [
            91: [wrongPID, wrongPID]
        ])
        expect(identityMismatch.1.producerStatus == "identity_changed" &&
               identityMismatch.1.upstream.state == .unavailable &&
               identityMismatch.1.upstream.reportedIdentities.isEmpty &&
               RootPortObserver.admissionFailure(identityMismatch.1) == "root_observer_identity_changed",
               "identity PID mismatch is reported as unproven rather than serialized")

        var mixedGeneration = try! JSONSerialization.jsonObject(with: candidateBoth.0) as! [String: Any]
        var perPort = mixedGeneration["port_observations"] as! [[String: Any]]
        perPort[0]["observed_at_unix_ms"] = wall
        perPort[1]["observed_at_unix_ms"] = wall - 5_000
        mixedGeneration["port_observations"] = perPort
        let mixedGenerationData = try! JSONSerialization.data(withJSONObject: mixedGeneration)
        let mixedGenerationFacts = RootPortObserver.diagnose(data: mixedGenerationData,
            wallNowMS: wall, monotonicNowNS: mono, currentBootUUID: boot)
        expect(mixedGenerationFacts.schemaState == .invalid &&
               RootPortObserver.admissionFailure(mixedGenerationFacts) == "root_observer_schema",
               "per-port mixed-generation stamps are rejected; candidate uses one snapshot generation")

        print("All RootPortObserver fixture checks passed.")
    }
}
