import Darwin
import Foundation

struct GateHelperSnapshot: Codable, Equatable {
    let bound: Bool
    let open: Bool
    let generation: UInt64
    let activePairs: UInt32
    let pending: UInt32
}

enum GateHelperKind: String, Codable {
    case hello
    case ready
    case status
    case lock
    case locked
    case revoke
    case revoked
    case rejected
#if GUARD_GATE_FIXTURE_TESTS
    case fixtureReleasePending
    case fixtureFailNextLockThread
    case fixtureArmed
    case fixturePendingReleased
#endif
}

enum GateHelperRejectReason: String, Codable {
    case version
    case nonce
    case epoch
    case sequence
    case generation
    case command
    case native
}

struct GateHelperMessage: Codable {
    let version: UInt16
    let nonce: [UInt8]
    let epoch: UInt64
    let generation: UInt64
    let sequence: UInt64
    let kind: GateHelperKind
    var snapshot: GateHelperSnapshot? = nil
    var reason: GateHelperRejectReason? = nil
}

private struct NativeGateReadback {
    var bound: UInt32 = 0
    var open: UInt32 = 0
    var generation: UInt64 = 0
    var activePairs: UInt32 = 0
    var pending: UInt32 = 0
}

@_silgen_name("ng_create") private func ngCreate() -> OpaquePointer?
@_silgen_name("ng_destroy") private func ngDestroy(_ gate: OpaquePointer)
@_silgen_name("ng_revoke") private func ngRevoke(_ gate: OpaquePointer)
@_silgen_name("ng_lock") private func ngLock(_ gate: OpaquePointer)
@_silgen_name("ng_get_readback") private func ngGetReadback(
    _ gate: OpaquePointer,
    _ output: UnsafeMutablePointer<NativeGateReadback>
) -> Int32

#if GUARD_GATE_FIXTURE_TESTS
@_silgen_name("ng_test_enable") private func ngTestEnable(_ gate: OpaquePointer)
@_silgen_name("ng_test_take_listener_fd") private func ngTestTakeListener(
    _ gate: OpaquePointer,
    _ descriptor: Int32
) -> Int32
@_silgen_name("ng_renew") private func ngRenew(
    _ gate: OpaquePointer,
    _ generation: UInt64,
    _ leaseNanoseconds: UInt64
) -> Int32
@_silgen_name("ng_test_adopt_pair") private func ngTestAdoptPair(
    _ gate: OpaquePointer,
    _ client: Int32,
    _ upstream: Int32
) -> Int32
@_silgen_name("ng_test_begin_pending") private func ngTestBeginPending(
    _ gate: OpaquePointer,
    _ client: Int32,
    _ generation: UnsafeMutablePointer<UInt64>
) -> Int32
@_silgen_name("ng_test_register_pending_upstream") private func ngTestRegisterPendingUpstream(
    _ gate: OpaquePointer,
    _ generation: UInt64,
    _ upstream: Int32
) -> Int32
@_silgen_name("ng_test_adopt_pending") private func ngTestAdoptPending(
    _ gate: OpaquePointer,
    _ generation: UInt64
) -> Int32
#endif

private let gateHelperMaximumFrame = 4_096
private let gateHelperVersion: UInt16 = 1
private let gateHelperIODeadlineMilliseconds: Int32 = 1_200

enum GateHelperIOError: Error, CustomStringConvertible {
    case closed
    case timedOut
    case invalidFrame
    case system(Int32)

    var description: String {
        switch self {
        case .closed: return "control channel closed"
        case .timedOut: return "control I/O deadline expired"
        case .invalidFrame: return "invalid or oversized control frame"
        case let .system(code): return "control I/O failed with errno \(code)"
        }
    }
}

final class GateHelperChannel {
    let descriptor: Int32
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init(descriptor: Int32) throws {
        self.descriptor = descriptor
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0,
              fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw GateHelperIOError.system(errno)
        }
        var noSignal: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE,
                         &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw GateHelperIOError.system(errno)
        }
    }

    func send(_ message: GateHelperMessage) throws {
        guard let body = try? encoder.encode(message),
              !body.isEmpty, body.count <= gateHelperMaximumFrame else {
            throw GateHelperIOError.invalidFrame
        }
        let deadline = try gateHelperDeadline()
        var length = UInt32(body.count).bigEndian
        try withUnsafeBytes(of: &length) { try writeAll(descriptor, $0, deadline: deadline) }
        try body.withUnsafeBytes { try writeAll(descriptor, $0, deadline: deadline) }
    }

    func receive() throws -> GateHelperMessage {
        let deadline = try gateHelperDeadline()
        let prefix = try readExactly(descriptor, count: MemoryLayout<UInt32>.size,
                                     deadline: deadline)
        let bytes = [UInt8](prefix)
        guard bytes.count == 4 else { throw GateHelperIOError.invalidFrame }
        let size = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16) |
                   (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
        guard size > 0, size <= gateHelperMaximumFrame else {
            throw GateHelperIOError.invalidFrame
        }
        let body = try readExactly(descriptor, count: Int(size), deadline: deadline)
        guard let message = try? decoder.decode(GateHelperMessage.self, from: body) else {
            throw GateHelperIOError.invalidFrame
        }
        return message
    }

    func waitForActivity(wakeDescriptor: Int32, timeoutMilliseconds: Int32) throws
        -> (control: Bool, wake: Bool) {
        var events = [
            pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0),
            pollfd(fd: wakeDescriptor, events: Int16(POLLIN | POLLHUP), revents: 0),
        ]
        let result = poll(&events, nfds_t(events.count), timeoutMilliseconds)
        if result < 0 {
            if errno == EINTR { return (false, false) }
            throw GateHelperIOError.system(errno)
        }
        guard result > 0 else { return (false, false) }
        if events.contains(where: { $0.revents & Int16(POLLNVAL | POLLERR) != 0 }) {
            throw GateHelperIOError.system(EBADF)
        }
        return (events[0].revents & Int16(POLLIN | POLLHUP) != 0,
                events[1].revents & Int16(POLLIN | POLLHUP) != 0)
    }
}

private func gateHelperDeadline() throws -> Int64 {
    var now = timespec()
    guard clock_gettime(CLOCK_MONOTONIC, &now) == 0 else {
        throw GateHelperIOError.system(errno)
    }
    let current = Int64(now.tv_sec) * 1_000 + Int64(now.tv_nsec) / 1_000_000
    return current + Int64(gateHelperIODeadlineMilliseconds)
}

private func gateHelperWait(_ descriptor: Int32, events: Int16, deadline: Int64) throws {
    while true {
        var now = timespec()
        guard clock_gettime(CLOCK_MONOTONIC, &now) == 0 else {
            throw GateHelperIOError.system(errno)
        }
        let current = Int64(now.tv_sec) * 1_000 + Int64(now.tv_nsec) / 1_000_000
        let remaining = deadline - current
        guard remaining > 0 else { throw GateHelperIOError.timedOut }
        var event = pollfd(fd: descriptor, events: events, revents: 0)
        let result = poll(&event, 1, Int32(min(remaining, Int64(Int32.max))))
        if result < 0 {
            if errno == EINTR { continue }
            throw GateHelperIOError.system(errno)
        }
        if result == 0 { continue }
        if event.revents & events != 0 { return }
        if event.revents & Int16(POLLERR | POLLNVAL | POLLHUP) != 0 {
            throw GateHelperIOError.closed
        }
    }
}

private func writeAll(_ descriptor: Int32,
                      _ bytes: UnsafeRawBufferPointer,
                      deadline: Int64) throws {
    guard let base = bytes.baseAddress else { throw GateHelperIOError.invalidFrame }
    var offset = 0
    while offset < bytes.count {
        let count = send(descriptor, base.advanced(by: offset), bytes.count - offset, 0)
        if count > 0 { offset += count; continue }
        if count < 0 && errno == EINTR { continue }
        if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
            try gateHelperWait(descriptor, events: Int16(POLLOUT), deadline: deadline)
            continue
        }
        if count == 0 { throw GateHelperIOError.closed }
        throw GateHelperIOError.system(errno)
    }
}

private func readExactly(_ descriptor: Int32, count: Int, deadline: Int64) throws -> Data {
    guard count > 0 else { throw GateHelperIOError.invalidFrame }
    var data = Data(count: count)
    try data.withUnsafeMutableBytes { bytes in
        guard let base = bytes.baseAddress else { throw GateHelperIOError.invalidFrame }
        var offset = 0
        while offset < bytes.count {
            try gateHelperWait(descriptor, events: Int16(POLLIN), deadline: deadline)
            let result = recv(descriptor, base.advanced(by: offset), bytes.count - offset, 0)
            if result > 0 { offset += result; continue }
            if result == 0 { throw GateHelperIOError.closed }
            if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
            throw GateHelperIOError.system(errno)
        }
    }
    return data
}

private final class GateWakePipe {
    let reader: Int32
    let writer: Int32

    init() throws {
        var descriptors: [Int32] = [-1, -1]
        let result = descriptors.withUnsafeMutableBufferPointer { pipe($0.baseAddress!) }
        guard result == 0 else { throw GateHelperIOError.system(errno) }
        reader = descriptors[0]
        writer = descriptors[1]
        do {
            try Self.prepare(reader)
            try Self.prepare(writer)
        } catch {
            close(reader)
            close(writer)
            throw error
        }
    }

    deinit {
        close(reader)
        close(writer)
    }

    func signal() {
        var byte: UInt8 = 1
        while true {
            let result = write(writer, &byte, 1)
            if result == 1 { return }
            if result < 0 && errno == EINTR { continue }
            return
        }
    }

    func drain() {
        var bytes = [UInt8](repeating: 0, count: 32)
        while true {
            let result = bytes.withUnsafeMutableBytes { read(reader, $0.baseAddress, $0.count) }
            if result > 0 { continue }
            if result < 0 && errno == EINTR { continue }
            return
        }
    }

    private static func prepare(_ descriptor: Int32) throws {
        let descriptorFlags = fcntl(descriptor, F_GETFD)
        let statusFlags = fcntl(descriptor, F_GETFL)
        guard descriptorFlags >= 0, statusFlags >= 0,
              fcntl(descriptor, F_SETFD, descriptorFlags | FD_CLOEXEC) == 0,
              fcntl(descriptor, F_SETFL, statusFlags | O_NONBLOCK) == 0 else {
            throw GateHelperIOError.system(errno)
        }
    }
}

private final class GateLockWorker {
    let gate: OpaquePointer
    let wakePipe: GateWakePipe
    private let stateLock = NSLock()
    private var completed = false
    private var thread: pthread_t?

    init(gate: OpaquePointer, wakePipe: GateWakePipe) {
        self.gate = gate
        self.wakePipe = wakePipe
    }

    func start(injectFailure: Bool) -> Int32 {
        if injectFailure { return EAGAIN }
        let context = Unmanaged.passRetained(self).toOpaque()
        var created: pthread_t?
        let result = pthread_create(&created, nil, runGateLockWorker, context)
        guard result == 0 else {
            Unmanaged<GateLockWorker>.fromOpaque(context).release()
            return result
        }
        guard let created else {
            // Success without a join handle would make safe Gate destruction impossible.
            _exit(74)
        }
        thread = created
        return 0
    }

    func execute() {
        ngLock(gate)
        stateLock.lock()
        completed = true
        stateLock.unlock()
        wakePipe.signal()
    }

    var isCompleted: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return completed
    }

    func join() -> Int32 {
        guard let thread else { return EINVAL }
        let result = pthread_join(thread, nil)
        if result == 0 { self.thread = nil }
        return result
    }
}

private func runGateLockWorker(_ context: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? {
    let worker = Unmanaged<GateLockWorker>.fromOpaque(context).takeRetainedValue()
    worker.execute()
    return nil
}

private func readback(_ gate: OpaquePointer) -> GateHelperSnapshot? {
    var value = NativeGateReadback()
    guard ngGetReadback(gate, &value) == 0 else { return nil }
    return GateHelperSnapshot(bound: value.bound != 0,
                              open: value.open != 0,
                              generation: value.generation,
                              activePairs: value.activePairs,
                              pending: value.pending)
}

private func readbackABIIsCompatible() -> Bool {
    MemoryLayout<NativeGateReadback>.size == 24 &&
    MemoryLayout<NativeGateReadback>.stride == 24 &&
    MemoryLayout<NativeGateReadback>.alignment == 8 &&
    MemoryLayout.offset(of: \NativeGateReadback.bound) == 0 &&
    MemoryLayout.offset(of: \NativeGateReadback.open) == 4 &&
    MemoryLayout.offset(of: \NativeGateReadback.generation) == 8 &&
    MemoryLayout.offset(of: \NativeGateReadback.activePairs) == 16 &&
    MemoryLayout.offset(of: \NativeGateReadback.pending) == 20
}

enum GateHelperChild {
    static let fixtureGeneration: UInt64 = 41

    static func runFixtureChild(arguments: [String]) -> Int32 {
        guard arguments.count == 8,
              let control = Int32(arguments[1]),
              let listener = Int32(arguments[2]),
              let activeClient = Int32(arguments[3]),
              let activeUpstream = Int32(arguments[4]),
              let pendingClient = Int32(arguments[5]),
              let pendingUpstream = Int32(arguments[6]),
              let sentinel = Int32(arguments[7]) else { return 64 }
        errno = 0
        guard fcntl(sentinel, F_GETFD) == -1 && errno == EBADF else { return 65 }
        guard readbackABIIsCompatible() else { return 66 }
        guard let gate = ngCreate() else { return 70 }
        ngTestEnable(gate)
        guard ngTestTakeListener(gate, listener) == 0,
              ngRenew(gate, fixtureGeneration, 3_000_000_000) == 0,
              ngTestAdoptPair(gate, activeClient, activeUpstream) == 0 else {
            ngRevoke(gate)
            ngDestroy(gate)
            return 71
        }
        var pendingGeneration: UInt64 = 0
        guard ngTestBeginPending(gate, pendingClient, &pendingGeneration) == 0,
              pendingGeneration == fixtureGeneration,
              ngTestRegisterPendingUpstream(gate, pendingGeneration, pendingUpstream) == 0 else {
            drainFixturePending(gate)
            ngRevoke(gate)
            ngDestroy(gate)
            return 72
        }
        do {
            let channel = try GateHelperChannel(descriptor: control)
            let session = try GateHelperSession(gate: gate, channel: channel)
            session.run()
        } catch {
            drainFixturePending(gate)
            ngRevoke(gate)
        }
        ngDestroy(gate)
        return 0
    }
}

private func drainFixturePending(_ gate: OpaquePointer) {
#if GUARD_GATE_FIXTURE_TESTS
    if let current = readback(gate), current.pending != 0 {
        _ = ngTestAdoptPending(gate, current.generation)
    }
#endif
}

private final class GateHelperSession {
    private let gate: OpaquePointer
    private let channel: GateHelperChannel
    private let wakePipe: GateWakePipe
    private var sessionNonce: [UInt8] = []
    private var sessionEpoch: UInt64 = 0
    private var expectedSequence: UInt64 = 2
    private var sessionGeneration: UInt64 = 0
    private var lockWorker: GateLockWorker?
    private var workerRequestForReply: GateHelperMessage?
    private var deferredRevoke: GateHelperMessage?
    private var failNextLockThread = false

    init(gate: OpaquePointer, channel: GateHelperChannel) throws {
        self.gate = gate
        self.channel = channel
        wakePipe = try GateWakePipe()
    }

    func run() {
        do {
            try serve()
        } catch {
            fputs("Gate helper session ended safely: \(error)\n", stderr)
        }
        finishAndRevoke()
    }

    private func serve() throws {
        let hello = try channel.receive()
        guard hello.version == gateHelperVersion, hello.kind == .hello,
              hello.nonce.count == 32, hello.epoch != 0,
              hello.generation == 0, hello.sequence == 1,
              let initial = readback(gate) else { throw GateHelperIOError.invalidFrame }
        sessionNonce = hello.nonce
        sessionEpoch = hello.epoch
        sessionGeneration = initial.generation
        try channel.send(GateHelperMessage(
            version: gateHelperVersion, nonce: sessionNonce, epoch: sessionEpoch,
            generation: initial.generation, sequence: hello.sequence,
            kind: .ready, snapshot: initial
        ))

        while true {
            if lockWorker?.isCompleted == true, try finishLockWorker() { return }
            let activity = try channel.waitForActivity(wakeDescriptor: wakePipe.reader,
                                                       timeoutMilliseconds: 100)
            if activity.wake, try finishLockWorker() { return }
            if activity.control {
                let request = try channel.receive()
                if try process(request) { return }
            }
        }
    }

    private func process(_ request: GateHelperMessage) throws -> Bool {
        let currentGeneration = sessionGeneration
        if request.version != gateHelperVersion {
            try reject(request, reason: .version, generation: currentGeneration)
            return false
        }
        if request.nonce != sessionNonce {
            try reject(request, reason: .nonce, generation: currentGeneration)
            return false
        }
        if request.epoch != sessionEpoch {
            try reject(request, reason: .epoch, generation: currentGeneration)
            return false
        }
        if request.sequence != expectedSequence {
            try reject(request, reason: .sequence, generation: currentGeneration)
            return false
        }
        guard expectedSequence < UInt64.max else { throw GateHelperIOError.invalidFrame }
        expectedSequence += 1
        if request.generation != currentGeneration {
            try reject(request, reason: .generation, generation: currentGeneration)
            return false
        }

        if lockWorker != nil && request.kind != .revoke {
#if GUARD_GATE_FIXTURE_TESTS
            if request.kind == .fixtureReleasePending {
                let result = ngTestAdoptPending(gate, request.generation)
                guard result == EPERM || result == 0 else {
                    try reject(request, reason: .native, generation: currentGeneration)
                    return false
                }
                try channel.send(GateHelperMessage(
                    version: gateHelperVersion, nonce: sessionNonce, epoch: sessionEpoch,
                    generation: currentGeneration, sequence: request.sequence,
                    kind: .fixturePendingReleased
                ))
                return false
            }
#endif
            try reject(request, reason: .command, generation: currentGeneration)
            return false
        }

        switch request.kind {
        case .status:
            guard let snapshot = readback(gate) else { throw GateHelperIOError.system(EIO) }
            try channel.send(response(for: request, kind: .status, snapshot: snapshot))
        case .lock:
            let worker = GateLockWorker(gate: gate, wakePipe: wakePipe)
            let result = worker.start(injectFailure: failNextLockThread)
            failNextLockThread = false
            guard result == 0 else {
                // A failed worker must never leave an open Gate behind.
                drainFixturePending(gate)
                ngRevoke(gate)
                guard let final = readback(gate) else { throw GateHelperIOError.system(EIO) }
                try channel.send(rejection(for: request, reason: .native, snapshot: final))
                return true
            }
            workerRequestForReply = request
            lockWorker = worker
#if GUARD_GATE_FIXTURE_TESTS
        case .fixtureFailNextLockThread:
            failNextLockThread = true
            try channel.send(GateHelperMessage(
                version: gateHelperVersion, nonce: sessionNonce, epoch: sessionEpoch,
                generation: currentGeneration, sequence: request.sequence,
                kind: .fixtureArmed
            ))
#endif
        case .revoke:
            if lockWorker != nil {
                guard deferredRevoke == nil else {
                    try reject(request, reason: .command, generation: currentGeneration)
                    return false
                }
                deferredRevoke = request
                return false
            }
            drainFixturePending(gate)
            ngRevoke(gate)
            guard let final = readback(gate) else { throw GateHelperIOError.system(EIO) }
            try channel.send(response(for: request, kind: .revoked, snapshot: final))
            return true
        case .hello, .ready, .locked, .revoked, .rejected:
            try reject(request, reason: .command, generation: currentGeneration)
#if GUARD_GATE_FIXTURE_TESTS
        case .fixtureReleasePending, .fixturePendingReleased, .fixtureArmed:
            try reject(request, reason: .command, generation: currentGeneration)
#endif
        }
        return false
    }

    private func finishLockWorker() throws -> Bool {
        guard let worker = lockWorker, worker.isCompleted else { return false }
        wakePipe.drain()
        let result = worker.join()
        guard result == 0 else {
            // Destroying the Gate without a successful join could race ng_lock.
            _exit(74)
        }
        lockWorker = nil
        guard let snapshot = readback(gate) else { throw GateHelperIOError.system(EIO) }
        let request = workerRequestForReply
        guard let request else { throw GateHelperIOError.system(EINVAL) }
        try channel.send(response(for: request, kind: .locked, snapshot: snapshot))
        workerRequestForReply = nil
        if let revoke = deferredRevoke {
            deferredRevoke = nil
            ngRevoke(gate)
            guard let final = readback(gate) else { throw GateHelperIOError.system(EIO) }
            try channel.send(response(for: revoke, kind: .revoked, snapshot: final))
            return true
        }
        return false
    }

    private func reject(_ request: GateHelperMessage,
                        reason: GateHelperRejectReason,
                        generation: UInt64) throws {
        try channel.send(rejection(for: request, reason: reason, generation: generation))
    }

    private func rejection(for request: GateHelperMessage,
                           reason: GateHelperRejectReason,
                           generation: UInt64) -> GateHelperMessage {
        GateHelperMessage(version: gateHelperVersion, nonce: request.nonce,
                          epoch: request.epoch, generation: generation,
                          sequence: request.sequence, kind: .rejected, reason: reason)
    }

    private func rejection(for request: GateHelperMessage,
                           reason: GateHelperRejectReason,
                           snapshot: GateHelperSnapshot) -> GateHelperMessage {
        GateHelperMessage(version: gateHelperVersion, nonce: request.nonce,
                          epoch: request.epoch, generation: snapshot.generation,
                          sequence: request.sequence, kind: .rejected,
                          snapshot: snapshot, reason: reason)
    }

    private func response(for request: GateHelperMessage,
                          kind: GateHelperKind,
                          snapshot: GateHelperSnapshot) -> GateHelperMessage {
        GateHelperMessage(version: gateHelperVersion, nonce: request.nonce,
                          epoch: request.epoch, generation: snapshot.generation,
                          sequence: request.sequence, kind: kind, snapshot: snapshot)
    }

    private func finishAndRevoke() {
        drainFixturePending(gate)
        if let worker = lockWorker {
            while !worker.isCompleted {
                _ = pollWake(wakePipe.reader, timeoutMilliseconds: 100)
                wakePipe.drain()
            }
            if worker.join() != 0 { _exit(74) }
            lockWorker = nil
        }
        ngRevoke(gate)
    }

    private func pollWake(_ descriptor: Int32, timeoutMilliseconds: Int32) -> Bool {
        var event = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
        return poll(&event, 1, timeoutMilliseconds) > 0
    }
}
