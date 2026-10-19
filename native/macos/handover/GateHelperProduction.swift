import Darwin
import Foundation

// This executable is compiled independently from the Tauri host. It is not
// launched or packaged into the app by the current M2 milestone.
enum GateHelperProductionPolicy {
    static let version: UInt16 = 1
    static let leaseNanoseconds: UInt64 = 3_000_000_000
    static let terminationTimeoutNanoseconds: UInt64 = 4_000_000_000
    static let timeoutExitCode: Int32 = 76
    static let controlDescriptor: Int32 = 3
}

// NativeGate.c pins both fixed targets to 127.0.0.1:7896; the protocol has no
// field capable of changing that upstream or either entry port.
private enum FixedGateTarget: CaseIterable {
    case claude
    case sunbrowser

    var wire: GateHelperTarget {
        switch self {
        case .claude: return .claude
        case .sunbrowser: return .sunbrowser
        }
    }

    var port: UInt16 {
        switch self {
        case .claude: return 17_897
        case .sunbrowser: return 17_898
        }
    }
}

private enum GateHelperProductionPhase {
    case awaitingInitialize
    case initialized
    case prepared
    case revoked
}

private struct ProductionNativeGateReadback {
    var bound: UInt32 = 0
    var open: UInt32 = 0
    var generation: UInt64 = 0
    var activePairs: UInt32 = 0
    var pending: UInt32 = 0
}

@_silgen_name("ng_create") private func productionNGCreate() -> OpaquePointer?
@_silgen_name("ng_destroy") private func productionNGDestroy(_ gate: OpaquePointer)
@_silgen_name("ng_bind_loopback_port") private func productionNGBind(_ gate: OpaquePointer, _ port: UInt16) -> Int32
@_silgen_name("ng_renew") private func productionNGRenew(
    _ gate: OpaquePointer, _ generation: UInt64, _ leaseNanoseconds: UInt64
) -> Int32
@_silgen_name("ng_continuous_ns") private func productionNGContinuousNS() -> UInt64
@_silgen_name("ng_begin_lock") private func productionNGBeginLock(
    _ gate: OpaquePointer, _ ticket: UnsafeMutablePointer<UInt64>
) -> Int32
@_silgen_name("ng_lock_until") private func productionNGLockUntil(
    _ gate: OpaquePointer, _ ticket: UInt64, _ deadline: UInt64
) -> Int32
@_silgen_name("ng_begin_revoke") private func productionNGBeginRevoke(
    _ gate: OpaquePointer, _ ticket: UnsafeMutablePointer<UInt64>
) -> Int32
@_silgen_name("ng_revoke_until") private func productionNGRevokeUntil(
    _ gate: OpaquePointer, _ ticket: UInt64, _ deadline: UInt64
) -> Int32
@_silgen_name("ng_destroy_quiescent") private func productionNGDestroyQuiescent(
    _ gate: OpaquePointer
) -> Int32
@_silgen_name("ng_get_readback") private func productionNGReadback(
    _ gate: OpaquePointer, _ output: UnsafeMutablePointer<ProductionNativeGateReadback>
) -> Int32

#if GUARD_GATE_FIXTURE_TESTS
@_silgen_name("ng_test_enable") private func productionNGTestEnable(_ gate: OpaquePointer)
@_silgen_name("ng_test_take_listener_fd") private func productionNGTestTakeListener(
    _ gate: OpaquePointer, _ descriptor: Int32
) -> Int32
@_silgen_name("ng_test_adopt_pair") private func productionNGTestAdoptPair(
    _ gate: OpaquePointer, _ client: Int32, _ upstream: Int32
) -> Int32
@_silgen_name("ng_test_begin_pending") private func productionNGTestBeginPending(
    _ gate: OpaquePointer, _ client: Int32, _ generation: UnsafeMutablePointer<UInt64>
) -> Int32
@_silgen_name("ng_test_register_pending_upstream") private func productionNGTestRegisterPendingUpstream(
    _ gate: OpaquePointer, _ generation: UInt64, _ upstream: Int32
) -> Int32
@_silgen_name("ng_test_hold_drain") private func productionNGTestHoldDrain(_ gate: OpaquePointer) -> Int32
@_silgen_name("ng_test_finish_pending") private func productionNGTestFinishPending(
    _ gate: OpaquePointer, _ generation: UInt64
) -> Int32
@_silgen_name("ng_test_release_drain") private func productionNGTestReleaseDrain(_ gate: OpaquePointer) -> Int32
#endif

private func productionReadback(_ gate: OpaquePointer) -> GateHelperSnapshot? {
    var value = ProductionNativeGateReadback()
    guard productionNGReadback(gate, &value) == 0 else { return nil }
    return GateHelperSnapshot(bound: value.bound != 0, open: value.open != 0,
                              generation: value.generation, activePairs: value.activePairs,
                              pending: value.pending)
}

private final class ProductionGateLockWorker {
    let gates: [OpaquePointer]
    let wakePipe: GateWakePipe
    let deadline: UInt64
    private let stateLock = NSLock()
    private var completed = false
    private var resultCode: Int32 = 0

    init(gates: [OpaquePointer], wakePipe: GateWakePipe, deadline: UInt64) {
        self.gates = gates
        self.wakePipe = wakePipe
        self.deadline = deadline
    }

    func start() -> Int32 {
        let context = Unmanaged.passRetained(self).toOpaque()
        var created: pthread_t?
        let result = pthread_create(&created, nil, runProductionGateLockWorker, context)
        guard result == 0 else {
            Unmanaged<ProductionGateLockWorker>.fromOpaque(context).release()
            return result
        }
        guard let created else { _exit(GateHelperProductionPolicy.timeoutExitCode) }
        guard pthread_detach(created) == 0 else {
            _exit(GateHelperProductionPolicy.timeoutExitCode)
        }
        return 0
    }

    func execute() {
        var result: Int32 = 0
        var tickets: [UInt64] = []
        for gate in gates {
            var ticket: UInt64 = 0
            let current = productionNGBeginLock(gate, &ticket)
            if current == 0, ticket != 0 { tickets.append(ticket) }
            else if result == 0 { result = current == 0 ? EINVAL : current }
        }
        if result == 0 {
            if tickets.count != gates.count {
                result = EINVAL
            } else {
                for (gate, ticket) in zip(gates, tickets) {
                    result = productionNGLockUntil(gate, ticket, deadline)
                    if result != 0 { break }
                }
            }
        }
        finish(result)
    }

    private func finish(_ result: Int32) {
        wakePipe.signal()
        stateLock.lock()
        resultCode = result
        completed = true
        stateLock.unlock()
    }

    var isCompleted: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return completed
    }

    var result: Int32? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return completed ? resultCode : nil
    }
}

private func runProductionGateLockWorker(_ context: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? {
    Unmanaged<ProductionGateLockWorker>.fromOpaque(context).takeRetainedValue().execute()
    return nil
}

#if GUARD_GATE_FIXTURE_TESTS
private struct GateHelperFixtureActivityDescriptors {
    var activeClient: Int32
    var activeUpstream: Int32
    var pendingClient: Int32
    var pendingUpstream: Int32

    mutating func closeRemaining() {
        for descriptor in [activeClient, activeUpstream, pendingClient, pendingUpstream]
        where descriptor >= 0 {
            close(descriptor)
        }
        activeClient = -1
        activeUpstream = -1
        pendingClient = -1
        pendingUpstream = -1
    }
}
#endif

final class GateHelperProductionServer {
    private let channel: GateHelperChannel
    private let serverWakePipe: GateWakePipe
#if GUARD_GATE_FIXTURE_TESTS
    private var fixtureListenerDescriptors: [GateHelperTarget: Int32]
    private var fixtureActivityDescriptors: GateHelperFixtureActivityDescriptors
#endif
    private var gates: [GateHelperTarget: OpaquePointer] = [:]
    private var phase = GateHelperProductionPhase.awaitingInitialize
    private var nonce: [UInt8] = []
    private var epoch: UInt64 = 0
    private var expectedSequence: UInt64 = 2
    private var generation: UInt64 = 0
    private var lastHostActivityNS = productionNGContinuousNS()
    private var lockWorker: ProductionGateLockWorker?
    private var lockRequest: GateHelperMessage?
    private var deferredRevoke: GateHelperMessage?

#if GUARD_GATE_FIXTURE_TESTS
    private init(channel: GateHelperChannel,
                 fixtureListenerDescriptors: [GateHelperTarget: Int32],
                 fixtureActivityDescriptors: GateHelperFixtureActivityDescriptors) throws {
        self.channel = channel
        self.fixtureListenerDescriptors = fixtureListenerDescriptors
        self.fixtureActivityDescriptors = fixtureActivityDescriptors
        serverWakePipe = try GateWakePipe()
    }
#else
    init(channel: GateHelperChannel) throws {
        self.channel = channel
        serverWakePipe = try GateWakePipe()
    }
#endif

    static func runInheritedControlFD(_ descriptor: Int32) -> Int32 {
        guard descriptor == GateHelperProductionPolicy.controlDescriptor,
              getuid() == geteuid(),
              GateHelperChannel.isAnonymousUnixStream(descriptor) else { return 64 }
        do {
#if GUARD_GATE_FIXTURE_TESTS && GUARD_GATE_HOST_FIXTURE_TESTS
            var claude: [Int32] = [-1, -1]
            var sunbrowser: [Int32] = [-1, -1]
            guard socketpair(AF_UNIX, SOCK_STREAM, 0, &claude) == 0,
                  socketpair(AF_UNIX, SOCK_STREAM, 0, &sunbrowser) == 0 else { return 70 }
            close(claude[1]); close(sunbrowser[1])
            do {
                let channel = try GateHelperChannel(descriptor: descriptor)
                let server = try GateHelperProductionServer(
                    channel: channel,
                    fixtureListenerDescriptors: [.claude: claude[0], .sunbrowser: sunbrowser[0]],
                    fixtureActivityDescriptors: GateHelperFixtureActivityDescriptors(
                        activeClient: -1, activeUpstream: -1,
                        pendingClient: -1, pendingUpstream: -1)
                )
                return server.run()
            } catch {
                close(claude[0]); close(sunbrowser[0])
                return 70
            }
#else
            let channel = try GateHelperChannel(descriptor: descriptor)
#if GUARD_GATE_FIXTURE_TESTS
            return try GateHelperProductionServer(
                channel: channel, fixtureListenerDescriptors: [:],
                fixtureActivityDescriptors: GateHelperFixtureActivityDescriptors(
                    activeClient: -1, activeUpstream: -1,
                    pendingClient: -1, pendingUpstream: -1)
            ).run()
#else
            return try GateHelperProductionServer(channel: channel).run()
#endif
#endif
        } catch {
            fputs("Gate helper rejected inherited control endpoint.\n", stderr)
            return 64
        }
    }

#if GUARD_GATE_FIXTURE_TESTS
    static func runFixtureChild(arguments: [String]) -> Int32 {
        guard arguments.count == 8,
              let control = Int32(arguments[0]),
              let claudeListener = Int32(arguments[1]),
              let sunbrowserListener = Int32(arguments[2]),
              let sentinel = Int32(arguments[3]),
              let activeClient = Int32(arguments[4]),
              let activeUpstream = Int32(arguments[5]),
              let pendingClient = Int32(arguments[6]),
              let pendingUpstream = Int32(arguments[7]) else { return 64 }
        errno = 0
        guard fcntl(sentinel, F_GETFD) == -1 && errno == EBADF,
              GateHelperChannel.isAnonymousUnixStream(control) else { return 65 }
        do {
            let channel = try GateHelperChannel(descriptor: control)
            let server = try GateHelperProductionServer(
                channel: channel,
                fixtureListenerDescriptors: [
                    .claude: claudeListener,
                    .sunbrowser: sunbrowserListener,
                ],
                fixtureActivityDescriptors: GateHelperFixtureActivityDescriptors(
                    activeClient: activeClient, activeUpstream: activeUpstream,
                    pendingClient: pendingClient, pendingUpstream: pendingUpstream)
            )
            return server.run()
        } catch {
            fputs("Gate helper production fixture setup failed.\n", stderr)
            close(claudeListener)
            close(sunbrowserListener)
            for descriptor in [activeClient, activeUpstream, pendingClient, pendingUpstream] {
                close(descriptor)
            }
            return 70
        }
    }
#endif

    private func run() -> Int32 {
        var result: Int32 = 0
        do { try serve() }
        catch let transport as GateHelperIOError {
            // EOF is the host-loss signal; cleanup below revokes all owned
            // descriptors before the process reports a graceful exit.
            if case .closed = transport {
                result = 0
            } else {
                fputs("Gate helper transport failed; revoking owned Gate state.\n", stderr)
                result = 1
            }
        }
        catch {
            // The transport contains no user payloads; keep diagnostics fixed.
            fputs("Gate helper session ended; revoking owned Gate state.\n", stderr)
            result = 1
        }
        finishAndDestroy()
        return result
    }

    private func serve() throws {
        let hello = try channel.receive()
        guard hello.version == 1, hello.kind == .hello,
              hello.nonce.count == 32, hello.nonce.contains(where: { $0 != 0 }),
              hello.epoch > 0, hello.generation == 0, hello.sequence == 1 else {
            throw GateHelperIOError.invalidFrame
        }
        nonce = hello.nonce
        epoch = hello.epoch
        lastHostActivityNS = productionNGContinuousNS()
        let helper = GateHelperProcessIdentity(pid: getpid(), uid: UInt32(getuid()))
        try channel.send(GateHelperMessage(
            version: 1, nonce: nonce, epoch: epoch, generation: 0, sequence: 1,
            kind: .ready, helperProcess: helper
        ))

        while true {
            if lockWorker?.isCompleted == true, try finishLockWorker() { return }
            let now = productionNGContinuousNS()
            guard now >= lastHostActivityNS else { _exit(GateHelperProductionPolicy.timeoutExitCode) }
            if lockWorker == nil &&
               now - lastHostActivityNS >= GateHelperProductionPolicy.leaseNanoseconds {
                expireHostSession()
                return
            }
            let timeout: Int32
            if let worker = lockWorker {
                timeout = boundedPollTimeout(until: worker.deadline)
            } else {
                timeout = 100
            }
            let activity = try channel.waitForActivity(
                wakeDescriptor: serverWakePipe.reader, timeoutMilliseconds: timeout
            )
            if activity.wake, try finishLockWorker() { return }
            if activity.control {
                let request: GateHelperMessage
                if let worker = lockWorker {
                    request = try channel.receive(
                        timeoutMilliseconds: remainingMilliseconds(until: worker.deadline))
                } else {
                    request = try channel.receive()
                }
                if try process(request) { return }
            }
        }
    }

    private func process(_ request: GateHelperMessage) throws -> Bool {
        if request.version != 1 { try reject(request, reason: .version); return false }
        if request.nonce != nonce { try reject(request, reason: .nonce); return false }
        if request.epoch != epoch { try reject(request, reason: .epoch); return false }
        if request.sequence != expectedSequence { try reject(request, reason: .sequence); return false }
        guard expectedSequence < UInt64.max else { throw GateHelperIOError.invalidFrame }
        expectedSequence += 1
        lastHostActivityNS = productionNGContinuousNS()

        if lockWorker != nil {
            switch request.kind {
            case .revoke:
                guard deferredRevoke == nil else {
                    try reject(request, reason: .command)
                    return false
                }
                guard request.generation == generation else {
                    try reject(request, reason: .generation)
                    return false
                }
                deferredRevoke = request
                return false
#if GUARD_GATE_FIXTURE_TESTS
            case .fixtureStatus:
                guard request.generation == generation, request.target == nil else {
                    try reject(request, reason: request.generation == generation ? .target : .generation)
                    return false
                }
                try channel.send(response(request, kind: .fixtureSnapshot, targets: try snapshots()))
                return false
            case .fixtureReleaseDrain:
                guard request.generation == generation, request.target == nil,
                      let claude = gates[GateHelperTarget.claude],
                      let sunbrowser = gates[GateHelperTarget.sunbrowser],
                      productionNGTestFinishPending(sunbrowser, generation) == 0,
                      productionNGTestReleaseDrain(claude) == 0 else {
                    try reject(request, reason: .state)
                    return false
                }
                try channel.send(response(request, kind: .fixtureDrainReleased, targets: try snapshots()))
                return false
#endif
            default:
                try reject(request, reason: .state)
                return false
            }
        }

        switch request.kind {
        case .initialize:
            try initialize(request)
        case .prepare:
            try prepare(request)
        case .open:
            try open(request)
        case .renew:
            try renew(request)
        case .status:
            guard request.target == nil else {
                try reject(request, reason: .target)
                return false
            }
            guard phase != .awaitingInitialize, phase != .revoked else {
                try reject(request, reason: .state)
                return false
            }
            guard request.generation == generation else {
                try reject(request, reason: .generation)
                return false
            }
            try channel.send(response(request, kind: .status, targets: try snapshots()))
        case .heartbeat:
            guard phase == .initialized || phase == .prepared,
                  request.generation == generation, request.target == nil else {
                try reject(request, reason: phase == .initialized || phase == .prepared ? .generation : .state)
                return false
            }
            try channel.send(response(request, kind: .alive, targets: try snapshots()))
#if GUARD_GATE_FIXTURE_TESTS
        case .fixtureSeedActivity:
            try seedFixtureActivity(request)
        case .fixtureHoldDrain:
            try holdFixtureDrain(request)
        case .fixtureStatus:
            guard request.generation == generation, request.target == nil else {
                try reject(request, reason: request.generation == generation ? .target : .generation)
                return false
            }
            try channel.send(response(request, kind: .fixtureSnapshot, targets: try snapshots()))
        case .fixtureFillOutputBuffer:
            guard phase == .prepared, request.generation == generation,
                  request.target == nil else {
                try reject(request, reason: phase == .prepared ? .generation : .state)
                return false
            }
            try channel.fillOutputBufferForFixture()
        case .fixtureReleaseDrain:
            try reject(request, reason: .state)
#endif
        case .lock:
            try startLock(request)
        case .revoke:
            if try revoke(request) { return true }
        case .hello, .ready, .initialized, .prepared, .opened, .renewed, .locked, .revoked,
             .alive, .rejected:
            try reject(request, reason: .command)
#if GUARD_GATE_FIXTURE_TESTS
        case .fixtureReleasePending, .fixtureFailNextLockThread,
             .fixtureSeeded, .fixtureHeld, .fixtureDrainReleased, .fixtureSnapshot,
             .fixtureArmed, .fixturePendingReleased:
            try reject(request, reason: .command)
#endif
        }
        return phase == .revoked
    }

    private func initialize(_ request: GateHelperMessage) throws {
        guard phase == .awaitingInitialize else { try reject(request, reason: .state); return }
        guard request.generation == 0 else { try reject(request, reason: .generation); return }
        guard request.policyVersion == GateHelperProductionPolicy.version,
              request.target == nil else { try reject(request, reason: .policy); return }
        guard let host = request.hostProcess, host.isValid,
              host.pid == getppid(), host.uid == UInt32(getuid()) else {
            try reject(request, reason: .peer)
            return
        }
        guard gateHelperReadbackABIIsCompatible() else {
            try reject(request, reason: .native)
            return
        }
        var allocated: [GateHelperTarget: OpaquePointer] = [:]
        for target in FixedGateTarget.allCases {
            guard let gate = productionNGCreate() else {
                allocated.values.forEach(productionNGDestroy)
                try reject(request, reason: .native)
                return
            }
#if GUARD_GATE_FIXTURE_TESTS
            productionNGTestEnable(gate)
#endif
            allocated[target.wire] = gate
        }
        gates = allocated
        phase = .initialized
        try channel.send(response(request, kind: .initialized, targets: try snapshots()))
    }

    private func prepare(_ request: GateHelperMessage) throws {
        guard phase == .initialized || phase == .prepared else {
            try reject(request, reason: .state)
            return
        }
        guard request.generation == generation, request.target == nil else {
            try reject(request, reason: request.generation == generation ? .target : .generation)
            return
        }
        for target in FixedGateTarget.allCases {
            guard let gate = gates[target.wire] else {
                revokeAndMarkTerminal()
                try reject(request, reason: .native, targets: try snapshots())
                return
            }
            guard productionReadback(gate)?.bound != true else { continue }
            let result: Int32
#if GUARD_GATE_FIXTURE_TESTS
            guard let descriptor = fixtureListenerDescriptors[target.wire] else {
                revokeAndMarkTerminal()
                try reject(request, reason: .native, targets: try snapshots())
                return
            }
            result = productionNGTestTakeListener(gate, descriptor)
            fixtureListenerDescriptors.removeValue(forKey: target.wire)
#else
            result = productionNGBind(gate, target.port)
#endif
            guard result == 0 else {
                revokeAndMarkTerminal()
                try reject(request, reason: .native, targets: try snapshots())
                return
            }
        }
        phase = .prepared
        let current = try snapshots()
        guard current.allSatisfy({ $0.snapshot.bound && !$0.snapshot.open &&
                                   $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0 }) else {
            revokeAndMarkTerminal()
            try reject(request, reason: .native, targets: try snapshots())
            return
        }
        try channel.send(response(request, kind: .prepared, targets: current))
    }

#if GUARD_GATE_FIXTURE_TESTS
    private func seedFixtureActivity(_ request: GateHelperMessage) throws {
        guard phase == .prepared, request.generation == generation,
              request.target == nil else {
            try reject(request, reason: phase == .prepared ? .generation : .state)
            return
        }
        guard let claude = gates[.claude], let sunbrowser = gates[.sunbrowser],
              fixtureActivityDescriptors.activeClient >= 0,
              fixtureActivityDescriptors.activeUpstream >= 0,
              fixtureActivityDescriptors.pendingClient >= 0,
              fixtureActivityDescriptors.pendingUpstream >= 0,
              try snapshots().allSatisfy({ $0.snapshot.open && $0.snapshot.generation == generation }) else {
            try reject(request, reason: .state)
            return
        }

        let activeClient = fixtureActivityDescriptors.activeClient
        let activeUpstream = fixtureActivityDescriptors.activeUpstream
        fixtureActivityDescriptors.activeClient = -1
        fixtureActivityDescriptors.activeUpstream = -1
        guard productionNGTestAdoptPair(claude, activeClient, activeUpstream) == 0 else {
            revokeAndMarkTerminal()
            try reject(request, reason: .native, targets: try snapshots())
            return
        }

        let pendingClient = fixtureActivityDescriptors.pendingClient
        fixtureActivityDescriptors.pendingClient = -1
        var pendingGeneration: UInt64 = 0
        guard productionNGTestBeginPending(sunbrowser, pendingClient, &pendingGeneration) == 0,
              pendingGeneration == generation else {
            revokeAndMarkTerminal()
            try reject(request, reason: .native, targets: try snapshots())
            return
        }

        let pendingUpstream = fixtureActivityDescriptors.pendingUpstream
        guard productionNGTestRegisterPendingUpstream(
            sunbrowser, pendingGeneration, pendingUpstream
        ) == 0 else {
            close(pendingUpstream)
            fixtureActivityDescriptors.pendingUpstream = -1
            revokeAndMarkTerminal()
            try reject(request, reason: .native, targets: try snapshots())
            return
        }
        fixtureActivityDescriptors.pendingUpstream = -1
        try channel.send(response(request, kind: .fixtureSeeded, targets: try snapshots()))
    }

    private func holdFixtureDrain(_ request: GateHelperMessage) throws {
        guard phase == .prepared, request.generation == generation,
              request.target == nil, let gate = gates[.claude],
              productionNGTestHoldDrain(gate) == 0 else {
            try reject(request, reason: .state)
            return
        }
        try channel.send(response(request, kind: .fixtureHeld, targets: try snapshots()))
    }
#endif

    private func open(_ request: GateHelperMessage) throws {
        guard phase == .prepared else { try reject(request, reason: .state); return }
        guard let target = request.target,
              let selected = gates[target] else { try reject(request, reason: .target); return }
        guard request.generation > generation else { try reject(request, reason: .generation); return }
        guard productionReadback(selected)?.bound == true else { try reject(request, reason: .state); return }

        let active = try snapshots().filter { $0.snapshot.open }.map(\.target)
        let renewalTargets = Set(active).union([target])
        for name in GateHelperTarget.allCases where renewalTargets.contains(name) {
            guard let gate = gates[name], productionNGRenew(
                gate, request.generation, GateHelperProductionPolicy.leaseNanoseconds
            ) == 0 else {
                lockAllBounded()
                generation = maxGeneration()
                try reject(request, reason: .native, targets: try snapshots())
                return
            }
        }
        generation = request.generation
        let current = try snapshots()
        guard current.first(where: { $0.target == target })?.snapshot.open == true,
              current.filter({ renewalTargets.contains($0.target) }).allSatisfy({
                  $0.snapshot.generation == generation && $0.snapshot.open
              }) else {
            lockAllBounded()
            generation = maxGeneration()
            try reject(request, reason: .native, targets: try snapshots())
            return
        }
        try channel.send(response(request, kind: .opened, targets: current))
    }

    private func renew(_ request: GateHelperMessage) throws {
        guard phase == .prepared else { try reject(request, reason: .state); return }
        guard request.target == nil else { try reject(request, reason: .target); return }
        guard request.generation == generation else { try reject(request, reason: .generation); return }
        let active = try snapshots().filter { $0.snapshot.open }.map(\.target)
        guard !active.isEmpty else { try reject(request, reason: .lease); return }
        for target in active {
            guard let gate = gates[target], productionNGRenew(
                gate, generation, GateHelperProductionPolicy.leaseNanoseconds
            ) == 0 else {
                lockAllBounded()
                generation = maxGeneration()
                try reject(request, reason: .native, targets: try snapshots())
                return
            }
        }
        try channel.send(response(request, kind: .renewed, targets: try snapshots()))
    }

    private func startLock(_ request: GateHelperMessage) throws {
        guard phase == .initialized || phase == .prepared else { try reject(request, reason: .state); return }
        guard request.generation == generation, request.target == nil else {
            try reject(request, reason: request.generation == generation ? .target : .generation)
            return
        }
        guard let values = orderedGates() else { _exit(GateHelperProductionPolicy.timeoutExitCode) }
        let deadline = timeoutDeadline()
        let worker = ProductionGateLockWorker(gates: values, wakePipe: serverWakePipe,
                                              deadline: deadline)
        guard worker.start() == 0 else { _exit(GateHelperProductionPolicy.timeoutExitCode) }
        lockRequest = request
        lockWorker = worker
    }

    private func finishLockWorker() throws -> Bool {
        guard let worker = lockWorker, let result = worker.result else { return false }
        serverWakePipe.drain()
        guard result == 0, productionNGContinuousNS() < worker.deadline,
              let request = lockRequest else {
            _exit(GateHelperProductionPolicy.timeoutExitCode)
        }
        let current = try snapshots()
        let empty = current.count == FixedGateTarget.allCases.count &&
            current.allSatisfy { !$0.snapshot.open && $0.snapshot.activePairs == 0 &&
                $0.snapshot.pending == 0 && (phase != .prepared || $0.snapshot.bound) }
        guard empty else { _exit(GateHelperProductionPolicy.timeoutExitCode) }
        try channel.send(response(request, kind: .locked, targets: current),
                         deadline: worker.deadline)
        lockRequest = nil
        lockWorker = nil
        if let revokeRequest = deferredRevoke {
            deferredRevoke = nil
            _ = try revoke(revokeRequest)
            return true
        }
        return false
    }

    @discardableResult
    private func revoke(_ request: GateHelperMessage) throws -> Bool {
        guard phase != .awaitingInitialize, phase != .revoked,
              request.generation == generation, request.target == nil else {
            try reject(request, reason: phase == .revoked ? .state : .generation)
            return false
        }
        let before = try snapshots()
        guard before.allSatisfy({ !$0.snapshot.open && $0.snapshot.activePairs == 0 &&
                                  $0.snapshot.pending == 0 }) else {
            try reject(request, reason: .state, targets: before)
            return false
        }
        guard let values = orderedGates() else { _exit(GateHelperProductionPolicy.timeoutExitCode) }
        let deadline = timeoutDeadline()
        guard revokeAllUntil(values, deadline: deadline),
              productionNGContinuousNS() < deadline,
              let final = try? snapshots(),
              final.allSatisfy({ !$0.snapshot.bound && !$0.snapshot.open &&
                                  $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0 }) else {
            _exit(GateHelperProductionPolicy.timeoutExitCode)
        }
        guard productionNGContinuousNS() < deadline else {
            _exit(GateHelperProductionPolicy.timeoutExitCode)
        }
        do {
            try channel.send(response(request, kind: .revoked, targets: final),
                             deadline: deadline)
        } catch {
            _exit(GateHelperProductionPolicy.timeoutExitCode)
        }
        phase = .revoked
        return true
    }

    private func snapshots() throws -> [GateHelperTargetSnapshot] {
        try GateHelperTarget.allCases.map { target in
            guard let gate = gates[target], let value = productionReadback(gate) else {
                throw GateHelperIOError.system(EIO)
            }
            return GateHelperTargetSnapshot(target: target, snapshot: value)
        }
    }

    private func maxGeneration() -> UInt64 {
        gates.values.compactMap { productionReadback($0)?.generation }.max() ?? generation
    }

    private func orderedGates() -> [OpaquePointer]? {
        let values = FixedGateTarget.allCases.compactMap { gates[$0.wire] }
        return values.count == FixedGateTarget.allCases.count ? values : nil
    }

    private func timeoutDeadline() -> UInt64 {
        let (deadline, overflow) = productionNGContinuousNS().addingReportingOverflow(
            GateHelperProductionPolicy.terminationTimeoutNanoseconds
        )
        guard !overflow else { _exit(GateHelperProductionPolicy.timeoutExitCode) }
        return deadline
    }

    private func remainingMilliseconds(until deadline: UInt64) -> Int32 {
        let now = productionNGContinuousNS()
        guard now < deadline else { _exit(GateHelperProductionPolicy.timeoutExitCode) }
        let remaining = deadline - now
        let milliseconds = remaining / 1_000_000 + (remaining % 1_000_000 == 0 ? 0 : 1)
        return Int32(min(milliseconds, UInt64(Int32.max)))
    }

    private func boundedPollTimeout(until deadline: UInt64) -> Int32 {
        min(remainingMilliseconds(until: deadline), 100)
    }

    private func beginLockAll(_ values: [OpaquePointer]) -> [UInt64]? {
        var success = true
        var tickets: [UInt64] = []
        for gate in values {
            var ticket: UInt64 = 0
            let result = productionNGBeginLock(gate, &ticket)
            if result == 0, ticket != 0 { tickets.append(ticket) }
            else { success = false }
        }
        return success && tickets.count == values.count ? tickets : nil
    }

    private func lockAllUntil(_ values: [OpaquePointer], deadline: UInt64) -> Bool {
        guard let tickets = beginLockAll(values) else { return false }
        for (gate, ticket) in zip(values, tickets)
        where productionNGLockUntil(gate, ticket, deadline) != 0 { return false }
        return true
    }

    private func lockAllBounded() {
        let deadline = timeoutDeadline()
        guard let values = orderedGates(), lockAllUntil(values, deadline: deadline),
              productionNGContinuousNS() < deadline else {
            _exit(GateHelperProductionPolicy.timeoutExitCode)
        }
    }

    private func revokeAllUntil(_ values: [OpaquePointer], deadline: UInt64) -> Bool {
        var success = true
        var tickets: [UInt64] = []
        for gate in values {
            var ticket: UInt64 = 0
            let result = productionNGBeginRevoke(gate, &ticket)
            if result == 0, ticket != 0 { tickets.append(ticket) }
            else { success = false }
        }
        guard success, tickets.count == values.count else { return false }
        for (gate, ticket) in zip(values, tickets)
        where productionNGRevokeUntil(gate, ticket, deadline) != 0 { return false }
        return true
    }

    private func revokeAndMarkTerminal() {
        let deadline = timeoutDeadline()
        guard let values = orderedGates(),
              revokeAllUntil(values, deadline: deadline),
              productionNGContinuousNS() < deadline,
              let final = try? snapshots(),
              final.allSatisfy({ !$0.snapshot.bound && !$0.snapshot.open &&
                                  $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0 }) else {
            _exit(GateHelperProductionPolicy.timeoutExitCode)
        }
        phase = .revoked
    }

    private func expireHostSession() {
        guard !gates.isEmpty else { phase = .revoked; return }
        let deadline = timeoutDeadline()
        guard let values = orderedGates(), lockAllUntil(values, deadline: deadline),
              productionNGContinuousNS() < deadline,
              let locked = try? snapshots(),
              locked.count == FixedGateTarget.allCases.count,
              locked.allSatisfy({ $0.snapshot.bound && !$0.snapshot.open &&
                                  $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0 }),
              revokeAllUntil(values, deadline: deadline),
              productionNGContinuousNS() < deadline,
              let final = try? snapshots(),
              final.count == FixedGateTarget.allCases.count,
              final.allSatisfy({ !$0.snapshot.bound && !$0.snapshot.open &&
                                $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0 }) else {
            _exit(GateHelperProductionPolicy.timeoutExitCode)
        }
        phase = .revoked
    }

    private func response(_ request: GateHelperMessage, kind: GateHelperKind,
                          targets: [GateHelperTargetSnapshot]) -> GateHelperMessage {
        GateHelperMessage(version: 1, nonce: nonce, epoch: epoch,
                          generation: generation, sequence: request.sequence,
                          kind: kind, targetSnapshots: targets)
    }

    private func response(_ request: GateHelperMessage, kind: GateHelperKind,
                          reason: GateHelperRejectReason,
                          targets: [GateHelperTargetSnapshot]) -> GateHelperMessage {
        GateHelperMessage(version: 1, nonce: nonce, epoch: epoch,
                          generation: generation, sequence: request.sequence,
                          kind: kind, reason: reason, targetSnapshots: targets)
    }

    private func reject(_ request: GateHelperMessage, reason: GateHelperRejectReason,
                        targets: [GateHelperTargetSnapshot]? = nil) throws {
        try channel.send(GateHelperMessage(
            version: 1, nonce: nonce.isEmpty ? request.nonce : nonce,
            epoch: epoch == 0 ? request.epoch : epoch, generation: generation,
            sequence: request.sequence, kind: .rejected, reason: reason,
            targetSnapshots: targets
        ))
    }

    private func finishAndDestroy() {
        var cleanupDeadline: UInt64?
        if let worker = lockWorker {
            cleanupDeadline = worker.deadline
            while !worker.isCompleted {
                _ = pollWake(serverWakePipe.reader, until: worker.deadline)
                serverWakePipe.drain()
            }
            guard let result = worker.result, result == 0,
                  productionNGContinuousNS() < worker.deadline,
                  let current = try? snapshots(),
                  current.allSatisfy({ !$0.snapshot.open && $0.snapshot.activePairs == 0 &&
                                       $0.snapshot.pending == 0 &&
                                       (phase != .prepared || $0.snapshot.bound) }) else {
                _exit(GateHelperProductionPolicy.timeoutExitCode)
            }
            lockWorker = nil
            lockRequest = nil
        }
        if phase != .revoked, !gates.isEmpty {
            guard let values = orderedGates() else { _exit(GateHelperProductionPolicy.timeoutExitCode) }
            let deadline = cleanupDeadline ?? timeoutDeadline()
            guard revokeAllUntil(values, deadline: deadline),
                  productionNGContinuousNS() < deadline,
                  let final = try? snapshots(),
                  final.allSatisfy({ !$0.snapshot.bound && !$0.snapshot.open &&
                                      $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0 }) else {
                _exit(GateHelperProductionPolicy.timeoutExitCode)
            }
            phase = .revoked
        }
        for gate in gates.values where productionNGDestroyQuiescent(gate) != 0 {
            _exit(GateHelperProductionPolicy.timeoutExitCode)
        }
        gates.removeAll()
#if GUARD_GATE_FIXTURE_TESTS
        for descriptor in fixtureListenerDescriptors.values where fcntl(descriptor, F_GETFD) >= 0 {
            close(descriptor)
        }
        fixtureListenerDescriptors.removeAll()
        fixtureActivityDescriptors.closeRemaining()
#endif
    }

    private func pollWake(_ descriptor: Int32, until deadline: UInt64) -> Bool {
        var event = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
        return poll(&event, 1, boundedPollTimeout(until: deadline)) > 0
    }
}
