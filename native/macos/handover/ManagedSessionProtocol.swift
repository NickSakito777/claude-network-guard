import Foundation
import Security

// Offline contract model only; production Gate closure and helper IPC are not wired here.
enum ManagedSessionProtocolFailure: Error, Equatable {
    case invalidBinding, staleBinding, sequence, invalidTransition
    case invalidGateReadback, wrongHost, wrongSupervisor
    case cleanupNotReady, cleanupAlreadyClaimed, wrongChild, gracePeriod
    case cleanupOwnerMismatch, launchRequestMismatch, heartbeatClockWentBackwards
    case invalidObservationTime, incompleteGateFDInheritanceAudit, incompleteInventory, nonceUnavailable
}

struct ManagedSessionProcessIdentity: Codable, Equatable {
    let pid: Int32
    let uid: UInt32
    let birthSeconds: Int64
    let birthMicroseconds: Int32
    let executablePath: String
    let codeRequirement: String

    var isValid: Bool {
        pid > 0 && birthSeconds > 0 && (0..<1_000_000).contains(birthMicroseconds) &&
        executablePath.hasPrefix("/") && !executablePath.hasSuffix("/") &&
        !executablePath.contains("//") &&
        !executablePath.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) &&
        !executablePath.unicodeScalars.contains(where: { $0.value == 0 }) &&
        !codeRequirement.isEmpty && codeRequirement.utf8.count <= 2_048 &&
        !codeRequirement.unicodeScalars.contains(where: { $0.value == 0 })
    }
}

struct ManagedSessionBinding: Codable, Equatable {
    let nonce: Data
    let host: ManagedSessionProcessIdentity
    let epoch: UInt64
    let generation: UInt64

    var isValid: Bool {
        nonce.count == 32 && nonce.contains(where: { $0 != 0 }) &&
        host.isValid && epoch > 0 && generation > 0
    }

    static func randomNonce() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let result = bytes.withUnsafeMutableBufferPointer { buffer -> OSStatus in
            guard let address = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, buffer.count, address)
        }
        guard result == errSecSuccess else { throw ManagedSessionProtocolFailure.nonceUnavailable }
        return Data(bytes)
    }
}

enum ManagedSessionPeer: Hashable { case guardHost, supervisor }
enum ManagedSessionMessageKind: String, Codable, CaseIterable {
    case ready, heartbeat, launchRequest, launchReceipt, lockReadback
}

// Gate commands deliberately have no representation in the supervisor protocol.
// Events are trusted model inputs here; a future IPC adapter must authenticate
// the peer process and decode/bind every field before calling accept(_:).
struct ManagedSessionHeader: Equatable {
    let binding: ManagedSessionBinding
    let sequence: UInt64
}

struct ManagedSessionGateReadback: Equatable {
    let binding: ManagedSessionBinding
    // A model input from the native observer; production must source this from
    // the process that owns the Gate and a real ng_lock/readback call. ng_lock
    // leaves the listener bound for locked inspection; isLockedAndEmpty means
    // relay/pending sockets are gone, not that ng_revoke closed the listener.
    let owner: ManagedSessionProcessIdentity
    let bound: Bool
    let open: Bool
    let activePairs: Int
    let pending: Int

    var isLockedAndEmpty: Bool {
        bound && !open && activePairs == 0 && pending == 0
    }

    var isOpenAndEmpty: Bool {
        bound && open && activePairs == 0 && pending == 0
    }
}

// The spawn adapter must revalidate the bound host and current Gate lease at
// the final admission boundary, serialize that check against cancellation/EOF,
// and capture both timestamps from the same monotonic clock around posix_spawn.
// The return PID must come directly from posix_spawn; a process lookup is not a receipt.
struct ManagedSessionSpawnReturn: Equatable {
    let requestID: UUID
    let spawnStartedAtNanos: UInt64
    let returnedAtNanos: UInt64
    let returnedPID: Int32
    let process: ManagedSessionProcessIdentity
}

enum ManagedSessionEvent {
    case supervisorReady(ManagedSessionHeader, ManagedSessionProcessIdentity)
    case supervisorHeartbeat(ManagedSessionHeader)
    case hostLaunchRequest(ManagedSessionHeader, String, UUID)
    case supervisorSpawnReceipt(ManagedSessionHeader, String, ManagedSessionSpawnReturn)
    case hostLockReadback(ManagedSessionHeader, ManagedSessionGateReadback)

    var peer: ManagedSessionPeer {
        switch self {
        case .supervisorReady, .supervisorHeartbeat, .supervisorSpawnReceipt: return .supervisor
        case .hostLaunchRequest, .hostLockReadback: return .guardHost
        }
    }

    var header: ManagedSessionHeader {
        switch self {
        case .supervisorReady(let header, _), .supervisorHeartbeat(let header),
             .hostLaunchRequest(let header, _, _), .supervisorSpawnReceipt(let header, _, _),
             .hostLockReadback(let header, _): return header
        }
    }

    var kind: ManagedSessionMessageKind {
        switch self {
        case .supervisorReady: return .ready
        case .supervisorHeartbeat: return .heartbeat
        case .hostLaunchRequest: return .launchRequest
        case .supervisorSpawnReceipt: return .launchReceipt
        case .hostLockReadback: return .lockReadback
        }
    }
}

enum ManagedSessionGateWitnessSource: Equatable { case gateOwnedSentinelEOF }

struct ManagedSessionGateClosureWitness {
    let binding: ManagedSessionBinding
    let owner: ManagedSessionProcessIdentity
    let source: ManagedSessionGateWitnessSource
}

// These source-audit inputs describe every descriptor class and escape route.
// They are not runtime observations and this file has no production producer.
// The source digest is only a freshness check; a complete review must separately
// resolve every escape path. Current known-unresolved paths block this barrier.
enum ManagedSessionGateDescriptorKind: Hashable, CaseIterable {
    case listener, listenerPollDuplicate, acceptedClient, pendingUpstream
    case activeClient, activeUpstream, closureSentinel
}

enum ManagedSessionGateFDEscapePath: Hashable, CaseIterable {
    case execInheritance, creationToCloexecRace, forkWithoutExec
    case dupOrFcntlDup, descriptorPassing, unreviewedSpawnPath
}

struct ManagedSessionGateFDInheritanceAudit: Equatable {
    let binding: ManagedSessionBinding
    let owner: ManagedSessionProcessIdentity
    let auditedDescriptorKinds: Set<ManagedSessionGateDescriptorKind>
    let excludedEscapePaths: Set<ManagedSessionGateFDEscapePath>
    let unresolvedEscapePaths: Set<ManagedSessionGateFDEscapePath>
    let sourceSnapshotSHA256: String

    var isComplete: Bool {
        // A matching digest only says the selected source snapshot is fresh.
        // It cannot turn known-unresolved production paths into proof.
        ManagedSessionSourceSnapshot.currentKnownUnresolvedEscapePaths.isEmpty &&
        auditedDescriptorKinds == Set(ManagedSessionGateDescriptorKind.allCases) &&
        excludedEscapePaths == Set(ManagedSessionGateFDEscapePath.allCases) &&
        unresolvedEscapePaths.isEmpty &&
        sourceSnapshotSHA256 == ManagedSessionSourceSnapshot.sha256
    }
}

#if MANAGED_SESSION_FIXTURE_TESTS
// This is a hypothetical state-machine premise, not an audit of the current
// source tree. It has no source digest and is absent from non-fixture builds.
struct ManagedSessionGateFDInheritanceFixtureAssumption: Equatable {
    let binding: ManagedSessionBinding
    let owner: ManagedSessionProcessIdentity
    let assumedDescriptorKindsContained: Set<ManagedSessionGateDescriptorKind>
    let assumedEscapePathsAbsent: Set<ManagedSessionGateFDEscapePath>

    var isCompleteHypothesis: Bool {
        assumedDescriptorKindsContained == Set(ManagedSessionGateDescriptorKind.allCases) &&
        assumedEscapePathsAbsent == Set(ManagedSessionGateFDEscapePath.allCases)
    }
}
#endif

// OS process observers must revalidate exact PID/UID/birth/path/signature and
// return this typed observation. The state machine itself cannot prove exit.
struct ManagedSessionProcessExitObservation: Equatable {
    let expected: ManagedSessionProcessIdentity
    let observed: ManagedSessionProcessIdentity
}

// The OS-backed inventory adapter must request every configured scope and only
// report inspected scopes after a complete, error-free enumeration.
struct ManagedSessionFinalInventoryReadback: Equatable {
    let binding: ManagedSessionBinding
    let requestedScopePaths: Set<String>
    let inspectedScopePaths: Set<String>
    let inspectionComplete: Bool
    let remainingOwnedProcesses: Int
}

enum ManagedSessionCleanupOwner: Equatable {
    case supervisor(ManagedSessionProcessIdentity)
    case guardHost(ManagedSessionProcessIdentity)
}

// Pure state model only. The adapter boundary is explicit in the typed
// Gate/process/spawn/inventory observations above, but no OS adapter is wired.
// Never use construction of one of these values as proof that the OS fact was
// actually observed.
struct ManagedSessionProtocolState {
    static let gateLeaseDurationNanos: UInt64 = 3_000_000_000
    // Leave a full safety margin before the Gate lease can expire. The age
    // comparison below is strict, so a heartbeat exactly this old is stale.
    static let heartbeatFreshnessNanos: UInt64 = 1_500_000_000

    enum Phase: Equatable {
        case awaitingReady, ready, gateOpen, launchInFlight, running
        case cleanupReady, cleaning, awaitingFinalInventory, complete, recovery
    }

    private let binding: ManagedSessionBinding
    private let supervisor: ManagedSessionProcessIdentity
    private let targetID: String
    private let targetExecutable: String
    private let targetCodeRequirement: String
    private let cleanupScopePaths: Set<String>
    private(set) var phase: Phase = .awaitingReady
    private(set) var child: ManagedSessionProcessIdentity?
    private(set) var cleanupOwner: ManagedSessionCleanupOwner?
    private(set) var gateSentinelEOFObserved = false
    private var nextHostSequence: UInt64 = 1
    private var nextSupervisorSequence: UInt64 = 1
    private var lastHeartbeatNanos: UInt64?
    private var supervisorAlive = true
    private var hostControlEOFAtNanos: UInt64?
    private var hostExitObserved = false
    private var gateFDInheritanceAudited = false
    private var gracefulGateLockedAndEmpty = false
    private var pendingLaunchRequestID: UUID?
    private var pendingLaunchRequestedAtNanos: UInt64?
    private var phaseBeforeSupervisorExit: Phase?
    private var cleanupClaimed = false
    private var termAtNanos: UInt64?
    private var killIssued = false

    private var hostControlEOF: Bool { hostControlEOFAtNanos != nil }

    private static func appContentsScope(for executablePath: String) -> String? {
        let components = executablePath.split(separator: "/")
        guard let appIndex = components.lastIndex(where: { $0.hasSuffix(".app") }),
              appIndex + 2 < components.endIndex,
              components[appIndex + 1] == "Contents" else { return nil }
        return "/" + components[..<(appIndex + 2)].joined(separator: "/") + "/"
    }

    init(binding: ManagedSessionBinding, supervisor: ManagedSessionProcessIdentity,
         targetID: String, targetExecutable: String, targetCodeRequirement: String,
         cleanupScopePaths: Set<String>) throws {
        guard let targetContentsScope = Self.appContentsScope(for: targetExecutable),
              binding.isValid, supervisor.isValid, supervisor.uid == binding.host.uid,
              !targetID.isEmpty, targetID.utf8.count <= 64,
              !targetID.unicodeScalars.contains(where: { $0.value == 0 }),
              targetExecutable.hasPrefix("/"), !targetExecutable.hasSuffix("/"),
              !targetExecutable.contains("//"),
              !targetExecutable.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }),
              !targetExecutable.unicodeScalars.contains(where: { $0.value == 0 }),
              !targetCodeRequirement.isEmpty, targetCodeRequirement.utf8.count <= 2_048,
              !targetCodeRequirement.unicodeScalars.contains(where: { $0.value == 0 }),
              !cleanupScopePaths.isEmpty,
              cleanupScopePaths.contains(where: { scope in
                  scope.hasPrefix(targetContentsScope) && targetExecutable.hasPrefix(scope)
              }),
              cleanupScopePaths.allSatisfy({ path in
                  path.hasPrefix(targetContentsScope) &&
                  path.hasPrefix("/") && !path.contains("//") &&
                  path.hasSuffix("/") &&
                  !path.unicodeScalars.contains(where: { $0.value == 0 }) &&
                  !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." })
              }) else {
            throw ManagedSessionProtocolFailure.invalidBinding
        }
        self.binding = binding
        self.supervisor = supervisor
        self.targetID = targetID
        self.targetExecutable = targetExecutable
        self.targetCodeRequirement = targetCodeRequirement
        self.cleanupScopePaths = cleanupScopePaths
        cleanupOwner = .supervisor(supervisor)
    }

    mutating func accept(_ event: ManagedSessionEvent, observedAtNanos: UInt64) throws {
        let header = event.header
        guard header.binding == binding else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.staleBinding
        }
        let expected = event.peer == .guardHost ? nextHostSequence : nextSupervisorSequence
        guard expected < UInt64.max, header.sequence == expected else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.sequence
        }
        do {
            try transition(event, observedAtNanos: observedAtNanos)
            if event.peer == .guardHost { nextHostSequence += 1 }
            else { nextSupervisorSequence += 1 }
        } catch {
            enterRecovery()
            throw error
        }
    }

    private mutating func transition(_ event: ManagedSessionEvent,
                                    observedAtNanos: UInt64) throws {
        switch event {
        case .supervisorReady(_, let identity):
            guard supervisorAlive, phase == .awaitingReady, identity == supervisor else {
                throw ManagedSessionProtocolFailure.wrongSupervisor
            }
            phase = .ready
            lastHeartbeatNanos = observedAtNanos

        case .supervisorHeartbeat:
            // Buffered same-session heartbeats may arrive after a lock, host
            // disconnect, or cleanup transition. Consume their sequence but
            // ignore them; they neither renew nor invalidate cleanup.
            if phase == .complete || gracefulGateLockedAndEmpty || hostControlEOF || !supervisorAlive ||
                [.cleanupReady, .cleaning, .awaitingFinalInventory, .recovery].contains(phase) {
                return
            }
            guard [.ready, .gateOpen, .launchInFlight, .running].contains(phase) else {
                throw ManagedSessionProtocolFailure.invalidTransition
            }
            guard let lastHeartbeat = lastHeartbeatNanos, observedAtNanos >= lastHeartbeat else {
                throw ManagedSessionProtocolFailure.heartbeatClockWentBackwards
            }
            lastHeartbeatNanos = observedAtNanos

        case .hostLaunchRequest(_, let target, let requestID):
            guard !hostControlEOF, phase == .gateOpen, target == targetID else {
                throw ManagedSessionProtocolFailure.invalidTransition
            }
            guard requestID.uuidString != "00000000-0000-0000-0000-000000000000" else {
                throw ManagedSessionProtocolFailure.launchRequestMismatch
            }
            pendingLaunchRequestID = requestID
            pendingLaunchRequestedAtNanos = observedAtNanos
            phase = .launchInFlight

        case .supervisorSpawnReceipt(_, let target, let spawnReturn):
            guard supervisorAlive, phase == .launchInFlight, target == targetID else {
                throw ManagedSessionProtocolFailure.invalidTransition
            }
            guard let pendingRequest = pendingLaunchRequestID,
                  let requestedAt = pendingLaunchRequestedAtNanos,
                  spawnReturn.requestID == pendingRequest else {
                throw ManagedSessionProtocolFailure.launchRequestMismatch
            }
            guard spawnReturn.spawnStartedAtNanos >= requestedAt,
                  spawnReturn.returnedAtNanos >= spawnReturn.spawnStartedAtNanos,
                  spawnReturn.returnedAtNanos <= observedAtNanos,
                  hostControlEOFAtNanos.map({ spawnReturn.spawnStartedAtNanos < $0 }) ?? true else {
                throw ManagedSessionProtocolFailure.invalidObservationTime
            }
            let process = spawnReturn.process
            guard process.isValid, process.uid == binding.host.uid,
                  process.pid != binding.host.pid, process.pid != supervisor.pid,
                  spawnReturn.returnedPID == process.pid,
                  process.executablePath == targetExecutable,
                  process.codeRequirement == targetCodeRequirement else {
                throw ManagedSessionProtocolFailure.wrongChild
            }
            child = process
            pendingLaunchRequestID = nil
            pendingLaunchRequestedAtNanos = nil
            phase = .running
            updateCleanupReadiness()

        case .hostLockReadback(_, let readback):
            guard !hostControlEOF, readback.binding == binding,
                  readback.owner == binding.host, readback.isLockedAndEmpty else {
                throw ManagedSessionProtocolFailure.invalidGateReadback
            }
            if [.gateOpen, .launchInFlight, .running].contains(phase),
               supervisorAlive, cleanupOwner == .supervisor(supervisor) {
                gracefulGateLockedAndEmpty = true
                updateCleanupReadiness()
                return
            }
            if cleanupOwner == .guardHost(binding.host),
               [.cleanupReady, .cleaning, .awaitingFinalInventory].contains(phase) {
                // Repeated native locked readbacks are idempotent for the
                // current owner and cannot reopen or reset cleanup state.
                gracefulGateLockedAndEmpty = true
                return
            }
            // Host takeover is a one-time ownership transfer after the OS
            // adapter has confirmed this exact supervisor is dead. A locked,
            // empty Gate readback is also required. No Boolean “owner” claim
            // can substitute for those two independent observations.
            guard phase == .recovery, !supervisorAlive,
                  cleanupOwner == nil, phaseBeforeSupervisorExit != nil else {
                throw ManagedSessionProtocolFailure.invalidTransition
            }
            gracefulGateLockedAndEmpty = true
            guard child != nil else { return } // unknown launch PID stays in recovery
            cleanupOwner = .guardHost(binding.host)
            let resume = phaseBeforeSupervisorExit!
            phaseBeforeSupervisorExit = nil
            if cleanupClaimed && [.cleaning, .awaitingFinalInventory].contains(resume) {
                phase = resume
            } else {
                phase = .cleanupReady
            }
        }
    }

    // Model input only. Production must call the native Gate adapter after READY
    // and pass the actual Gate owner and native readback; the supervisor has no
    // open/renew operation in this protocol.
    mutating func guardDidOpenGate(_ readback: ManagedSessionGateReadback,
                                   observedAtNanos: UInt64) throws {
        guard phase == .ready, !hostControlEOF,
              readback.binding == binding, readback.owner == binding.host,
              readback.isOpenAndEmpty, heartbeatIsFresh(at: observedAtNanos) else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.invalidGateReadback
        }
        phase = .gateOpen
    }

    // EOF time is when the adapter observed the transport close, not the exact
    // host exit time. A delayed receipt is admissible only if spawn began first.
    mutating func observeHostControlEOF(atNanos: UInt64) throws {
        guard atNanos > 0,
              hostControlEOFAtNanos.map({ atNanos >= $0 }) ?? true else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.invalidObservationTime
        }
        hostControlEOFAtNanos = atNanos
    }

    // Input from an OS-backed process observer, not a fact validated by this
    // state machine. The adapter must recheck PID, UID, birth, executable and signature.
    mutating func observeHostExit(_ observation: ManagedSessionProcessExitObservation) throws {
        guard observation.expected == binding.host,
              observation.observed == binding.host else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.wrongHost
        }
        hostExitObserved = true
        updateCleanupReadiness()
    }

    // A private sentinel EOF corroborates owner shutdown, but never proves that
    // every Gate descriptor is closed or authorizes cleanup by itself.
    mutating func observeGateClosureSentinelEOF(_ witness: ManagedSessionGateClosureWitness) throws {
        guard witness.binding == binding, witness.owner == binding.host,
              witness.source == .gateOwnedSentinelEOF else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.invalidGateReadback
        }
        gateSentinelEOFObserved = true
    }

    mutating func observeGateFDInheritanceAudit(_ audit: ManagedSessionGateFDInheritanceAudit) throws {
        guard audit.binding == binding, audit.owner == binding.host else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.invalidGateReadback
        }
        guard audit.isComplete else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.incompleteGateFDInheritanceAudit
        }
        gateFDInheritanceAudited = true
        updateCleanupReadiness()
    }

#if MANAGED_SESSION_FIXTURE_TESTS
    // Exercises the crash-barrier transition under an explicitly imaginary
    // all-paths-contained premise. Never use this to represent source evidence.
    mutating func assumeGateFDInheritanceForFixture(
        _ assumption: ManagedSessionGateFDInheritanceFixtureAssumption
    ) throws {
        guard assumption.binding == binding, assumption.owner == binding.host else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.invalidGateReadback
        }
        guard assumption.isCompleteHypothesis else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.incompleteGateFDInheritanceAudit
        }
        gateFDInheritanceAudited = true
        updateCleanupReadiness()
    }
#endif

    // The process adapter must confirm this exact birth identity is no longer
    // live. A matching PID by itself is not sufficient.
    mutating func observeSupervisorExit(_ observation: ManagedSessionProcessExitObservation) throws {
        guard observation.expected == supervisor,
              observation.observed == supervisor else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.wrongSupervisor
        }
        supervisorAlive = false
        cleanupOwner = nil
        if phase != .complete {
            phaseBeforeSupervisorExit = phase
            phase = .recovery
        }
    }

    func mayRenewGate(at nowNanos: UInt64) -> Bool {
        guard supervisorAlive, cleanupOwner == .supervisor(supervisor),
              !hostControlEOF, !gracefulGateLockedAndEmpty,
              [.gateOpen, .launchInFlight, .running].contains(phase) else { return false }
        return heartbeatIsFresh(at: nowNanos)
    }

    mutating func claimCleanup(by owner: ManagedSessionCleanupOwner) throws {
        guard !cleanupClaimed else { throw ManagedSessionProtocolFailure.cleanupAlreadyClaimed }
        guard cleanupOwner == owner else { throw ManagedSessionProtocolFailure.cleanupOwnerMismatch }
        guard phase == .cleanupReady, cleanupBarrierEstablished else {
            throw ManagedSessionProtocolFailure.cleanupNotReady
        }
        cleanupClaimed = true
        phase = .cleaning
    }

    mutating func markTermIssued(for process: ManagedSessionProcessIdentity,
                                 by owner: ManagedSessionCleanupOwner,
                                 at nowNanos: UInt64) throws {
        guard cleanupOwner == owner else { throw ManagedSessionProtocolFailure.cleanupOwnerMismatch }
        guard phase == .cleaning, cleanupClaimed, cleanupBarrierEstablished,
              process == child else { throw ManagedSessionProtocolFailure.wrongChild }
        guard termAtNanos == nil else { throw ManagedSessionProtocolFailure.invalidTransition }
        termAtNanos = nowNanos
    }

    mutating func markKillIssued(for process: ManagedSessionProcessIdentity,
                                 by owner: ManagedSessionCleanupOwner,
                                 at nowNanos: UInt64) throws {
        guard cleanupOwner == owner else { throw ManagedSessionProtocolFailure.cleanupOwnerMismatch }
        guard phase == .cleaning, cleanupClaimed, cleanupBarrierEstablished,
              process == child else { throw ManagedSessionProtocolFailure.wrongChild }
        guard let termAtNanos else { throw ManagedSessionProtocolFailure.invalidTransition }
        guard nowNanos >= termAtNanos, nowNanos - termAtNanos >= 1_500_000_000 else {
            throw ManagedSessionProtocolFailure.gracePeriod
        }
        guard !killIssued else { throw ManagedSessionProtocolFailure.invalidTransition }
        killIssued = true
    }

    mutating func confirmChildExited(_ observation: ManagedSessionProcessExitObservation,
                                     by owner: ManagedSessionCleanupOwner) throws {
        guard cleanupOwner == owner else { throw ManagedSessionProtocolFailure.cleanupOwnerMismatch }
        guard phase == .cleaning, cleanupClaimed,
              observation.expected == child, observation.observed == child else {
            throw ManagedSessionProtocolFailure.wrongChild
        }
        phase = .awaitingFinalInventory
    }

    // This is an adapter result. Production must re-enumerate every configured
    // scope and never pass a Boolean assembled from partial process lookups.
    mutating func finishFinalInventory(_ readback: ManagedSessionFinalInventoryReadback,
                                       by owner: ManagedSessionCleanupOwner) throws {
        guard cleanupOwner == owner else {
            throw ManagedSessionProtocolFailure.cleanupOwnerMismatch
        }
        guard readback.binding == binding else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.staleBinding
        }
        guard phase == .awaitingFinalInventory, readback.inspectionComplete,
              readback.requestedScopePaths == cleanupScopePaths,
              readback.inspectedScopePaths.isSuperset(of: cleanupScopePaths),
              readback.remainingOwnedProcesses == 0 else {
            enterRecovery()
            throw ManagedSessionProtocolFailure.incompleteInventory
        }
        phase = .complete
        cleanupOwner = nil
    }

    // Graceful ng_lock keeps its listener bound but drains every pending/active
    // relay. Crash proof instead needs exact owner exit plus the complete
    // source audit excluding every way those descriptors could escape.
    private var cleanupBarrierEstablished: Bool {
        gracefulGateLockedAndEmpty || (hostExitObserved && gateFDInheritanceAudited)
    }

    private mutating func updateCleanupReadiness() {
        guard cleanupOwner != nil, child != nil, cleanupBarrierEstablished,
              phase != .recovery, phase != .cleaning,
              phase != .awaitingFinalInventory, phase != .complete else { return }
        phase = .cleanupReady
    }

    private func heartbeatIsFresh(at nowNanos: UInt64) -> Bool {
        guard let lastHeartbeatNanos, nowNanos >= lastHeartbeatNanos else { return false }
        return nowNanos - lastHeartbeatNanos < Self.heartbeatFreshnessNanos
    }

    private mutating func enterRecovery() {
        if phase != .complete { phase = .recovery }
    }
}
