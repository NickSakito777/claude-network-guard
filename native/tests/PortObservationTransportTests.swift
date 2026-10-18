import Foundation

// Construct data only. Never call readDiagnostic, LuLuServices.make or any Gate.
@main
struct PortObservationTransportTests {
    static func main() throws {
        GuardDiagnosticsTests.run()
        let wall: Int64 = 1_800_000_000_000
        let mono: Int64 = 9_000_000_000_000
        let boot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        let rows: [[String: Any]] = [7896, 17897].map { port in
            ["port": port, "local_address": "127.0.0.1.\(port)", "pid": port,
             "process_start_sec": 1_700_000_000, "process_start_usec": 123_456,
             "executable_path": port == 7896 ? "/fixture/core" : "/fixture/guard"]
        }
        let raw = try JSONSerialization.data(withJSONObject: [
            "ok": true, "status": "ok", "observed_at_unix_ms": wall,
            "observed_monotonic_ns": mono, "boot_session_uuid": boot, "listeners": rows
        ])
        let live = ListenerIdentity(pid: 17897, executable: "/fixture/guard",
            birth: "1700000000.123456", bindAddress: "127.0.0.1:17897")
        let diagnostic = RootPortObserver.diagnose(data: raw, wallNowMS: wall,
            monotonicNowNS: mono, currentBootUUID: boot, liveIngressIdentity: live)
        let payload = try LuLuServices.portObservationPayload(diagnostic)
        let value = try JSONSerialization.jsonObject(with: payload) as! [String: Any]
        precondition(payload.count < 2_048)
        precondition(value["diagnosticOnly"] as? Bool == true)
        precondition(value["upstreamState"] as? String == "present")
        precondition(value["ingressState"] as? String == "present")
        precondition(value["ingressOwnerState"] as? String == "matches")
        precondition(value["producerStatus"] as? String == "ok")
        precondition(value["observedAtUnixMs"] as? Int64 == wall)
        precondition(value["failure"] is NSNull)
        precondition(Set(value.keys) == Set(["diagnosticOnly", "fileState", "schemaState",
            "producerStatus", "upstreamState", "ingressState", "ingressOwnerState",
            "bootState", "wallFreshness", "monotonicFreshness", "observedAtUnixMs", "failure"]))
        let absent = RootPortObserver.diagnose(data: nil, readFailure: "root_observer_path",
            wallNowMS: wall, monotonicNowNS: mono, currentBootUUID: boot)
        let unavailable = try JSONSerialization.jsonObject(
            with: LuLuServices.portObservationPayload(absent)) as! [String: Any]
        precondition(unavailable["upstreamState"] as? String == "unavailable")
        precondition(unavailable["ingressState"] as? String == "unavailable")
        precondition(unavailable["producerStatus"] is NSNull)
        precondition(unavailable["failure"] as? String == "root_observer_path")
        precondition(CommandLine.arguments.count == 2)
        try payload.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
        print("Native diagnostic fixture serialization passed; no service/Gate/host read was used.")
    }
}
