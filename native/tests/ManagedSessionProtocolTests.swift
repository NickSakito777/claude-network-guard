import Foundation

private let targetPath = "/Applications/Claude.app/Contents/MacOS/claude"
private let targetRequirement = "identifier \"ai.local.claude\" and anchor apple generic"
private let cleanupScope = "/Applications/Claude.app/Contents/"
private let requestID = UUID(uuidString: "56d932a5-c791-431a-b437-2799c1c45d17")!

private func identity(_ pid: Int32, _ path: String, _ requirement: String) -> ManagedSessionProcessIdentity {
    ManagedSessionProcessIdentity(pid: pid, uid: 501, birthSeconds: Int64(pid) + 100,
        birthMicroseconds: 123, executablePath: path, codeRequirement: requirement)
}

private func makeBinding(nonceByte: UInt8 = 0x41, generation: UInt64 = 9) -> ManagedSessionBinding {
    ManagedSessionBinding(nonce: Data(repeating: nonceByte, count: 32),
        host: identity(400, "/Applications/Guard.app/Contents/MacOS/Guard",
                       "identifier \"local.fox.guard\" and anchor apple generic"),
        epoch: 7, generation: generation)
}

private func supervisorIdentity() -> ManagedSessionProcessIdentity {
    identity(401, "/Applications/Guard.app/Contents/Helpers/SessionSupervisor",
             "identifier \"local.fox.guard.supervisor\" and anchor apple generic")
}

private func makeState(binding: ManagedSessionBinding = makeBinding()) throws -> ManagedSessionProtocolState {
    try ManagedSessionProtocolState(binding: binding, supervisor: supervisorIdentity(),
        targetID: "claude", targetExecutable: targetPath, targetCodeRequirement: targetRequirement,
        cleanupScopePaths: [cleanupScope])
}

private func header(_ binding: ManagedSessionBinding, _ sequence: UInt64) -> ManagedSessionHeader {
    ManagedSessionHeader(binding: binding, sequence: sequence)
}

private func gateReadback(_ binding: ManagedSessionBinding, open: Bool,
                          activePairs: Int = 0, pending: Int = 0,
                          owner: ManagedSessionProcessIdentity? = nil) -> ManagedSessionGateReadback {
    ManagedSessionGateReadback(binding: binding, owner: owner ?? binding.host,
        bound: true, open: open, activePairs: activePairs, pending: pending)
}

private func processExit(_ process: ManagedSessionProcessIdentity) -> ManagedSessionProcessExitObservation {
    ManagedSessionProcessExitObservation(expected: process, observed: process)
}

private func completeGateFDAudit(_ binding: ManagedSessionBinding,
                                 missingKinds: Set<ManagedSessionGateDescriptorKind> = [],
                                 missingExclusions: Set<ManagedSessionGateFDEscapePath> = []) -> ManagedSessionGateFDInheritanceAudit {
    ManagedSessionGateFDInheritanceAudit(binding: binding, owner: binding.host,
        auditedDescriptorKinds: Set(ManagedSessionGateDescriptorKind.allCases).subtracting(missingKinds),
        excludedEscapePaths: Set(ManagedSessionGateFDEscapePath.allCases).subtracting(missingExclusions))
}

private func inventory(_ binding: ManagedSessionBinding,
                       requested: Set<String> = [cleanupScope],
                       inspected: Set<String> = [cleanupScope], complete: Bool = true,
                       remaining: Int = 0) -> ManagedSessionFinalInventoryReadback {
    ManagedSessionFinalInventoryReadback(binding: binding,
        requestedScopePaths: requested, inspectedScopePaths: inspected,
        inspectionComplete: complete, remainingOwnedProcesses: remaining)
}

private func readyState() throws -> ManagedSessionProtocolState {
    let binding = makeBinding()
    var state = try makeState(binding: binding)
    try state.accept(.supervisorReady(header(binding, 1), supervisorIdentity()), observedAtNanos: 100)
    return state
}

private func openedState() throws -> ManagedSessionProtocolState {
    let binding = makeBinding()
    var state = try readyState()
    try state.guardDidOpenGate(gateReadback(binding, open: true), observedAtNanos: 101)
    return state
}

private func launchPendingState() throws -> ManagedSessionProtocolState {
    let binding = makeBinding()
    var state = try openedState()
    try state.accept(.hostLaunchRequest(header(binding, 1), "claude", requestID), observedAtNanos: 200)
    return state
}

private func spawnReturn(_ request: UUID = requestID, pid: Int32 = 402) -> ManagedSessionSpawnReturn {
    let child = identity(pid, targetPath, targetRequirement)
    return ManagedSessionSpawnReturn(requestID: request, returnedPID: pid, process: child)
}

private func runningState() throws -> ManagedSessionProtocolState {
    let binding = makeBinding()
    var state = try launchPendingState()
    try state.accept(.supervisorSpawnReceipt(header(binding, 2), "claude", spawnReturn()),
        observedAtNanos: 300)
    return state
}

private func lockedForCleanup(_ state: inout ManagedSessionProtocolState,
                              binding: ManagedSessionBinding,
                              hostSequence: UInt64 = 2) throws {
    try state.accept(.hostLockReadback(header(binding, hostSequence), gateReadback(binding, open: false)),
                     observedAtNanos: 500)
}

private final class Checks {
    private(set) var count = 0

    func require(_ value: Bool, _ message: String) {
        guard value else { fatalError(message) }
        count += 1
    }

    func fails(_ expected: ManagedSessionProtocolFailure,
               _ operation: () throws -> Void) {
        do {
            try operation()
            fatalError("expected failure: \(expected)")
        } catch let actual as ManagedSessionProtocolFailure {
            require(actual == expected, "failure mismatch: \(actual) != \(expected)")
        } catch {
            fatalError("unexpected error: \(error)")
        }
    }
}

@main
private struct ManagedSessionProtocolTests {
    static func main() throws {
        let checks = Checks()
        try nonceAndGateOrdering(checks)
        try staleAndReplayMessages(checks)
        try heartbeatBoundariesAndLateDelivery(checks)
        try crashClosureNeedsExitAndFDInvariant(checks)
        try supervisorExitRequiresOneTimeHostTakeover(checks)
        try delayedSpawnReceiptIsBoundToRequest(checks)
        try lockedGateAndCompleteScopedInventory(checks)
        print("managed session protocol fixture passed (\(checks.count) assertions)")
    }

    private static func nonceAndGateOrdering(_ c: Checks) throws {
        let nonce = try ManagedSessionBinding.randomNonce()
        c.require(nonce.count == 32 && nonce.contains(where: { $0 != 0 }),
                  "session nonce must be 256-bit nonzero random data")
        c.require(ManagedSessionMessageKind(rawValue: "openGate") == nil &&
                  ManagedSessionMessageKind(rawValue: "renewGate") == nil,
                  "supervisor protocol must not expose Gate commands")
        c.require(ManagedSessionProtocolState.heartbeatFreshnessNanos <
                  ManagedSessionProtocolState.gateLeaseDurationNanos,
                  "heartbeat freshness must end before the Gate lease")

        let binding = makeBinding()
        var state = try makeState(binding: binding)
        c.fails(.invalidGateReadback) {
            try state.guardDidOpenGate(gateReadback(binding, open: true), observedAtNanos: 100)
        }
        c.require(state.phase == .recovery, "Gate must not open before supervisor READY")

        c.fails(.invalidBinding) {
            _ = try ManagedSessionProtocolState(binding: binding, supervisor: supervisorIdentity(),
                targetID: "claude", targetExecutable: targetPath,
                targetCodeRequirement: targetRequirement,
                cleanupScopePaths: ["/Applications/Other.app/Contents/"])
        }

        var wrongOwner = try readyState()
        c.fails(.invalidGateReadback) {
            try wrongOwner.guardDidOpenGate(gateReadback(binding, open: true,
                owner: supervisorIdentity()), observedAtNanos: 101)
        }
        c.require(wrongOwner.phase == .recovery, "Gate observer identity must be the bound host")

        var ready = try readyState()
        try ready.guardDidOpenGate(gateReadback(binding, open: true), observedAtNanos: 101)
        c.require(ready.phase == .gateOpen, "Guard may open only after a fresh READY and host readback")
    }

    private static func staleAndReplayMessages(_ c: Checks) throws {
        let binding = makeBinding()
        var staleNonce = try makeState(binding: binding)
        let otherNonce = makeBinding(nonceByte: 0x42)
        c.fails(.staleBinding) {
            try staleNonce.accept(.supervisorReady(header(otherNonce, 1), supervisorIdentity()),
                observedAtNanos: 100)
        }

        var staleGeneration = try makeState(binding: binding)
        let otherGeneration = makeBinding(generation: 10)
        c.fails(.staleBinding) {
            try staleGeneration.accept(.supervisorReady(header(otherGeneration, 1), supervisorIdentity()),
                observedAtNanos: 100)
        }

        var replay = try readyState()
        c.fails(.sequence) {
            try replay.accept(.supervisorHeartbeat(header(binding, 1)), observedAtNanos: 150)
        }
        c.require(replay.phase == .recovery, "replayed sequence must fail the session closed")
    }

    private static func heartbeatBoundariesAndLateDelivery(_ c: Checks) throws {
        let binding = makeBinding()
        var state = try readyState()
        try state.guardDidOpenGate(gateReadback(binding, open: true), observedAtNanos: 101)
        c.require(state.mayRenewGate(at: 1_000_000_100), "fresh heartbeat permits renewal well before lease expiry")
        c.require(!state.mayRenewGate(at: 1_500_000_100), "heartbeat age equal to freshness bound is stale")

        try state.accept(.supervisorHeartbeat(header(binding, 2)), observedAtNanos: 1_500_000_100)
        c.require(!state.mayRenewGate(at: 1_500_000_099), "a heartbeat timestamp in the future cannot renew")
        c.require(state.mayRenewGate(at: 2_500_000_099), "strictly fresh heartbeat permits renewal")
        c.require(!state.mayRenewGate(at: 3_000_000_100), "missed heartbeat blocks renewal before the three-second Gate lease")
        c.fails(.heartbeatClockWentBackwards) {
            try state.accept(.supervisorHeartbeat(header(binding, 3)), observedAtNanos: 1_499_999_999)
        }
        c.require(state.phase == .recovery, "monotonic timestamp regression fails the session closed")

        var locked = try runningState()
        try lockedForCleanup(&locked, binding: binding)
        c.require(locked.phase == .cleanupReady, "real locked-and-empty readback starts cleanup")
        try locked.accept(.supervisorHeartbeat(header(binding, 3)), observedAtNanos: 50)
        c.require(locked.phase == .cleanupReady && !locked.mayRenewGate(at: 600),
                  "late same-session heartbeat after lock is ignored and never renews")
    }

    private static func crashClosureNeedsExitAndFDInvariant(_ c: Checks) throws {
        let binding = makeBinding()
        var eofOnly = try runningState()
        eofOnly.observeHostControlEOF()
        try eofOnly.observeGateClosureSentinelEOF(.init(binding: binding, owner: binding.host,
                                                        source: .gateOwnedSentinelEOF))
        c.fails(.cleanupNotReady) { try eofOnly.claimCleanup(by: .supervisor(supervisorIdentity())) }
        c.require(eofOnly.phase == .running && eofOnly.gateSentinelEOFObserved,
                  "sentinel EOF corroborates shutdown but proves neither host exit nor all FD closure")

        var exitAndSentinel = try runningState()
        try exitAndSentinel.observeHostExit(processExit(binding.host))
        try exitAndSentinel.observeGateClosureSentinelEOF(.init(binding: binding, owner: binding.host,
                                                               source: .gateOwnedSentinelEOF))
        c.fails(.cleanupNotReady) {
            try exitAndSentinel.claimCleanup(by: .supervisor(supervisorIdentity()))
        }
        c.require(exitAndSentinel.phase == .running,
                  "host exit plus sentinel EOF is insufficient without the audited FD invariant")

        var eofAndAudit = try runningState()
        try eofAndAudit.observeGateFDInheritanceAudit(completeGateFDAudit(binding))
        c.fails(.cleanupNotReady) { try eofAndAudit.claimCleanup(by: .supervisor(supervisorIdentity())) }
        try eofAndAudit.observeHostExit(processExit(binding.host))
        c.require(eofAndAudit.phase == .cleanupReady,
                  "exact host exit plus complete no-escape audit is sufficient without sentinel EOF")
        try eofAndAudit.claimCleanup(by: .supervisor(supervisorIdentity()))
        c.fails(.cleanupAlreadyClaimed) {
            try eofAndAudit.claimCleanup(by: .supervisor(supervisorIdentity()))
        }

        var wrongHost = try runningState()
        let reusedPID = ManagedSessionProcessIdentity(pid: binding.host.pid, uid: binding.host.uid,
            birthSeconds: binding.host.birthSeconds + 1, birthMicroseconds: binding.host.birthMicroseconds,
            executablePath: binding.host.executablePath, codeRequirement: binding.host.codeRequirement)
        c.fails(.wrongHost) {
            try wrongHost.observeHostExit(.init(expected: binding.host, observed: reusedPID))
        }

        var incompleteAudit = try runningState()
        try incompleteAudit.observeHostExit(processExit(binding.host))
        c.fails(.incompleteGateFDInheritanceAudit) {
            try incompleteAudit.observeGateFDInheritanceAudit(completeGateFDAudit(binding,
                missingKinds: [.listenerPollDuplicate], missingExclusions: [.forkWithoutExec]))
        }
        c.fails(.cleanupNotReady) {
            try incompleteAudit.claimCleanup(by: .supervisor(supervisorIdentity()))
        }
    }

    private static func supervisorExitRequiresOneTimeHostTakeover(_ c: Checks) throws {
        let binding = makeBinding()
        let helper = supervisorIdentity()
        var state = try runningState()
        c.require(state.cleanupOwner == .supervisor(helper), "supervisor is the initial single cleanup owner")
        try state.observeSupervisorExit(processExit(helper))
        c.require(state.phase == .recovery && state.cleanupOwner == nil,
                  "supervisor death releases ownership into recovery")
        c.fails(.cleanupOwnerMismatch) { try state.claimCleanup(by: .guardHost(binding.host)) }

        var lockedNotProven = try runningState()
        try lockedNotProven.observeSupervisorExit(processExit(helper))
        c.fails(.invalidGateReadback) {
            try lockedNotProven.accept(.hostLockReadback(header(binding, 2),
                gateReadback(binding, open: false, pending: 1)), observedAtNanos: 500)
        }
        c.require(lockedNotProven.cleanupOwner == nil,
                  "host cannot take over on a locked readback that still has a pending Gate client")
        try lockedForCleanup(&lockedNotProven, binding: binding)
        c.require(lockedNotProven.cleanupOwner == .guardHost(binding.host),
                  "a fresh zero-active/zero-pending readback enables the one-time takeover")

        var wrongHelper = try runningState()
        let reusedHelperPID = ManagedSessionProcessIdentity(pid: helper.pid, uid: helper.uid,
            birthSeconds: helper.birthSeconds + 1, birthMicroseconds: helper.birthMicroseconds,
            executablePath: helper.executablePath, codeRequirement: helper.codeRequirement)
        c.fails(.wrongSupervisor) {
            try wrongHelper.observeSupervisorExit(.init(expected: helper, observed: reusedHelperPID))
        }
        c.require(wrongHelper.cleanupOwner == .supervisor(helper),
                  "PID reuse cannot transfer ownership away from a still-pinned supervisor")

        try lockedForCleanup(&state, binding: binding)
        c.require(state.phase == .cleanupReady && state.cleanupOwner == .guardHost(binding.host),
                  "host takes over only after exact supervisor death and locked empty Gate readback")
        c.fails(.cleanupOwnerMismatch) { try state.claimCleanup(by: .supervisor(helper)) }
        try state.claimCleanup(by: .guardHost(binding.host))
        c.fails(.cleanupAlreadyClaimed) { try state.claimCleanup(by: .guardHost(binding.host)) }

        var duringCleanup = try runningState()
        try lockedForCleanup(&duringCleanup, binding: binding)
        try duringCleanup.claimCleanup(by: .supervisor(helper))
        let child = spawnReturn().process
        try duringCleanup.markTermIssued(for: child, by: .supervisor(helper), at: 1_000)
        try duringCleanup.observeSupervisorExit(processExit(helper))
        try lockedForCleanup(&duringCleanup, binding: binding, hostSequence: 3)
        c.require(duringCleanup.phase == .cleaning &&
                  duringCleanup.cleanupOwner == .guardHost(binding.host),
                  "host resumes an already-claimed cleanup only after supervisor death")
        try duringCleanup.markKillIssued(for: child, by: .guardHost(binding.host), at: 1_500_001_000)
    }

    private static func delayedSpawnReceiptIsBoundToRequest(_ c: Checks) throws {
        let binding = makeBinding()
        var mismatch = try launchPendingState()
        let otherRequest = UUID(uuidString: "c68a2b5f-6296-4203-9b6d-a94bd4103a78")!
        c.fails(.launchRequestMismatch) {
            try mismatch.accept(.supervisorSpawnReceipt(header(binding, 2), "claude",
                spawnReturn(otherRequest)), observedAtNanos: 250)
        }
        c.require(mismatch.child == nil, "receipt for another launch request cannot pin an external PID")

        var wrongPID = try launchPendingState()
        c.fails(.wrongChild) {
            try wrongPID.accept(.supervisorSpawnReceipt(header(binding, 2), "claude",
                .init(requestID: requestID, returnedPID: 999, process: spawnReturn().process)),
                observedAtNanos: 250)
        }
        c.require(wrongPID.child == nil, "spawn return PID must equal the identity snapshot PID")

        var state = try launchPendingState()
        state.observeHostControlEOF()
        try state.observeHostExit(processExit(binding.host))
        try state.observeGateFDInheritanceAudit(completeGateFDAudit(binding))
        c.fails(.cleanupNotReady) { try state.claimCleanup(by: .supervisor(supervisorIdentity())) }
        c.require(state.phase == .launchInFlight,
                  "host crash before a spawn receipt leaves the target PID unknown")

        try state.accept(.supervisorSpawnReceipt(header(binding, 2), "claude", spawnReturn()),
                         observedAtNanos: 400)
        c.require(state.phase == .cleanupReady && state.child?.pid == 402,
                  "delayed receipt for the unique request pins the exact posix_spawn return PID")
        try state.claimCleanup(by: .supervisor(supervisorIdentity()))
        let child = spawnReturn().process
        try state.markTermIssued(for: child, by: .supervisor(supervisorIdentity()), at: 1_000)
        c.fails(.gracePeriod) {
            try state.markKillIssued(for: child, by: .supervisor(supervisorIdentity()), at: 1_000_001_000)
        }
        try state.markKillIssued(for: child, by: .supervisor(supervisorIdentity()), at: 1_500_001_000)
        try state.confirmChildExited(processExit(child), by: .supervisor(supervisorIdentity()))
        c.fails(.incompleteInventory) {
            try state.finishFinalInventory(inventory(binding, complete: false),
                                           by: .supervisor(supervisorIdentity()))
        }
        c.require(state.phase == .recovery, "incomplete inventory cannot confirm cleanup")
    }

    private static func lockedGateAndCompleteScopedInventory(_ c: Checks) throws {
        let binding = makeBinding()
        var activeGate = try runningState()
        c.fails(.invalidGateReadback) {
            try activeGate.accept(.hostLockReadback(header(binding, 2),
                gateReadback(binding, open: false, activePairs: 1)), observedAtNanos: 600)
        }
        c.require(activeGate.phase == .recovery, "active relay/pending readback cannot authorize cleanup")

        var missingScope = try runningState()
        try lockedForCleanup(&missingScope, binding: binding)
        try missingScope.claimCleanup(by: .supervisor(supervisorIdentity()))
        let child = spawnReturn().process
        try missingScope.confirmChildExited(processExit(child), by: .supervisor(supervisorIdentity()))
        c.fails(.incompleteInventory) {
            try missingScope.finishFinalInventory(inventory(binding, inspected: []),
                                                  by: .supervisor(supervisorIdentity()))
        }
        c.require(missingScope.phase == .recovery,
                  "an uninspected required process scope cannot be treated as empty")

        var wrongRequestedScope = try runningState()
        try lockedForCleanup(&wrongRequestedScope, binding: binding)
        try wrongRequestedScope.claimCleanup(by: .supervisor(supervisorIdentity()))
        try wrongRequestedScope.confirmChildExited(processExit(child), by: .supervisor(supervisorIdentity()))
        c.fails(.incompleteInventory) {
            try wrongRequestedScope.finishFinalInventory(inventory(binding,
                requested: ["/Applications/Other.app/Contents/"]), by: .supervisor(supervisorIdentity()))
        }

        var complete = try runningState()
        try lockedForCleanup(&complete, binding: binding)
        try complete.claimCleanup(by: .supervisor(supervisorIdentity()))
        try complete.confirmChildExited(processExit(child), by: .supervisor(supervisorIdentity()))
        try complete.finishFinalInventory(inventory(binding), by: .supervisor(supervisorIdentity()))
        c.require(complete.phase == .complete && complete.cleanupOwner == nil,
                  "only complete empty inventory of every configured scope confirms cleanup")
        try complete.observeSupervisorExit(processExit(supervisorIdentity()))
        try complete.accept(.supervisorHeartbeat(header(binding, 3)), observedAtNanos: 999)
        c.require(complete.phase == .complete, "terminal completion survives later process notifications")
    }
}
