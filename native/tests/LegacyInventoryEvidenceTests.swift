import AppKit
import Darwin
import Foundation

@_silgen_name("fixture_set") private func fixtureSet(_ value: Int32)
@_silgen_name("fixture_count") private func fixtureCount(_ kind: Int32) -> Int32

// Only this standalone fixture shadows Foundation.Process. No subprocess runs.
final class Process {
    static var mode = 0
    static var calls = 0
    var executableURL: URL?
    var arguments: [String] = []
    var environment: [String:String] = [:]
    var standardOutput: Any?
    var standardError: Any?
    var terminationHandler: ((Process) -> Void)?
    var terminationStatus: Int32 = 0
    var isRunning = false
    func run() throws {
        Self.calls += 1
        precondition(executableURL?.path == "/bin/ps")
        precondition(arguments == ["-p", "40001", "-o", "comm="])
        if Self.mode == 1 { throw NSError(domain:NSPOSIXErrorDomain,code:Int(EPERM)) }
        if Self.mode == 4 { return } // Timeout, never a real process.
        if Self.mode == 3 { terminationStatus = 1 }
        let value = Self.mode == 2 ? "/Applications/Claude.app/Contents/MacOS/Claude\n"
            : Self.mode == 7 ? "" : Self.mode == 8 ? "one\ntwo" : Self.mode == 9 ? "one\0two"
            : Self.mode == 6 ? String(repeating:"x",count:8193) : "/fixture/unrelated\n"
        let bytes = Self.mode == 5 ? Data([0xff]) : Data(value.utf8)
        (standardOutput as! Pipe).fileHandleForWriting.write(bytes)
        terminationHandler?(self)
    }
    func terminate() { preconditionFailure("No real or synthetic running process should be terminated") }
}

@main enum LegacyInventoryEvidenceTests {
    static func target() -> LegacyTarget {
        LegacyTarget(targetID:"claude",bundlePath:"/Applications/Claude.app",
            executablePath:"/Applications/Claude.app/Contents/MacOS/Claude",
            arguments:["--proxy-server=http://127.0.0.1:17897","--disable-quic"],
            scopes:[LegacyScope(pathPrefix:"/Applications/Claude.app/Contents/",codeRequirement:"fixture")])
    }
    static func main() throws {
        let supervisor = try LegacyApplicationSupervisor(targets:[target()])
        let rows: [(Int32,Int,InventoryFailure.Step)] = [
            (1,0,.list),(17,0,.list),(2,0,.status),(4,0,.snapshotGone),
            (5,1,.psRun),(5,4,.psTimeout),(5,3,.psResult),(5,5,.psResult),
            (5,6,.psResult),(5,7,.psShape),(5,8,.psShape),(5,9,.psShape),
            (7,2,.pathCandidate),(19,0,.pathStatus),(20,0,.pathStatus),
            (9,0,.snapshot),(21,0,.selfPID),(22,0,.physical),
            (12,0,.signatureStatus),(13,0,.finalSnapshot),(15,0,.finalGone)
        ]
        var seen = Set<String>()
        for (scenario,mode,expected) in rows {
            fixtureSet(scenario); Process.mode=mode; Process.calls=0
            do { _ = try supervisor.isQuiescent(); preconditionFailure("Expected \(expected)") }
            catch LegacySupervisorError.inspectionFailure(let detail) {
                precondition(detail.step == expected && detail.target == .claude)
                precondition(detail.phase == .observation && detail.pass == 0)
                precondition(detail.wire.utf8.count < 472)
                seen.insert(detail.step.rawValue)
                if scenario==5 {
                    // Preserve the original EACCES and subcall detail, even when
                    // ps fails before the existing confirmed-gone status check.
                    precondition(detail.rc==EACCES && detail.call==2 && detail.raw == -17)
                    precondition(fixtureCount(0)==1 && Process.calls==1)
                }
                if expected == .psRun { precondition(detail.ps==1 && detail.psCode==Int64(EPERM)) }
                if expected == .psTimeout { precondition(detail.ps==4) }
                if mode==3 { precondition(detail.psCode==1 && detail.psFlags==0) }
                if mode==5 { precondition(detail.psFlags==3 && detail.psBytes==1) }
                if mode==6 { precondition(detail.psFlags==1 && detail.psBytes==8193) }
                if expected == .psShape { precondition(detail.psFlags==7) }
                if expected == .pathCandidate || expected == .pathStatus { precondition(detail.ps==5 && detail.psFlags==15) }
                if expected == .list { precondition(detail.call==6 && detail.value==8192) }
                precondition(!detail.wire.contains("/fixture/") && !detail.wire.contains("comm="))
            }
            precondition(fixtureCount(2)==0)
        }
        fixtureSet(0)
        do {
            _ = try supervisor.matchingProcesses(in:[LegacyScope(pathPrefix:"/\0",codeRequirement:"fixture")])
            preconditionFailure("Expected scope refusal")
        } catch LegacySupervisorError.inspectionFailure(let detail) {
            precondition(detail.step == .scope && detail.pid == nil && detail.rc == nil)
            seen.insert(detail.step.rawValue)
        }
        precondition(seen.count == 16)

        // Confirmed exits/unrelated paths still skip; definite identity/signature
        // failures retain their existing distinct errors and never gain authority.
        for scenario: Int32 in [3,6,8,11,14,18] {
            fixtureSet(scenario); Process.mode=0
            let empty = try supervisor.isQuiescent(); precondition(empty)
            precondition(fixtureCount(2)==0)
        }
        fixtureSet(10)
        do { _ = try supervisor.isQuiescent(); preconditionFailure("Expected signature refusal") }
        catch LegacySupervisorError.signatureMismatch(40001) {}
        fixtureSet(16)
        do { _ = try supervisor.isQuiescent(); preconditionFailure("Expected birth refusal") }
        catch LegacySupervisorError.processChanged(40001) {}

        let phases: [InventoryFailure.Phase] = [.beforeTerm,.termWait,.beforeKill,.final]
        for failAt in 1...4 {
            var calls=0, signals=0
            let process=ProcessBirth(pid:40001,uid:getuid(),startSeconds:1700000000,
                                     startMicroseconds:1,executable:target().executablePath)
            let scope=target().scopes[0]
            let operations=LegacyApplicationSupervisor.Operations(
                dispatchMain:{ _ in preconditionFailure("No launch") },
                openApplication:{ _,_ in preconditionFailure("No launch") },
                snapshot:{ _ in preconditionFailure("No launch") },
                signatureMatches:{ _,_ in preconditionFailure("No launch") },
                physicalPath:{ _ in true },currentUID:getuid(),
                inventory:{ _ in
                    calls += 1
                    if calls==failAt { throw LegacySupervisorError.inspectionFailure(
                        InventoryFailure(target:.sunbrowser,step:.status,pid:40001,rc:EPERM)) }
                    return calls==1 ? [(process,scope)] : []
                }, signalIfSame:{ _,_,_ in signals += 1; return 0 })
            do {
                _ = try supervisor.stopAfterGateLocked(lockReadback:{true},operations:operations)
                preconditionFailure("Expected phase evidence")
            } catch LegacySupervisorError.inspectionFailure(let detail) {
                precondition(detail.phase==phases[failAt-1] && detail.pass==UInt32(failAt))
                precondition(detail.target == .claude && detail.rc==EPERM)
                precondition(signals==(failAt==1 ? 0 : 1))
            }
        }
        let extreme=InventoryFailure(target:.sunbrowser,phase:.beforeTerm,pass:.max,step:.signatureStatus,
            pid:.min,rc:.min,call:.min,raw:.min,os:.min,value:.min,identity:.min,
            ps:.min,psCode:.min,psBytes:.min,psFlags:.min)
        let wire=NativeCleanupDiagnostic.inspectionFailure(extreme).wire
        precondition(wire.utf8.count < 512 && wire.split(separator:"\n").count==2)
        precondition(!wire.contains("/Applications/") && !wire.contains("PATH"))
        print("Inventory evidence: all 16 sources, four stop phases, PS validity/exit-race, unchanged refusal/skip behavior and worst-case \(wire.utf8.count)-byte transport passed; zero real process effects.")
    }
}
