import Foundation
#if GUARD_GATE_FIXTURE_TESTS
import Darwin
@_silgen_name("ng_test_enable") private func cTestEnable(_ gate: OpaquePointer)
@_silgen_name("ng_test_take_listener_fd") private func cTestListener(_ gate: OpaquePointer, _ fd: Int32) -> Int32
#endif

@_silgen_name("ng_create") private func cCreate() -> OpaquePointer?
@_silgen_name("ng_destroy") private func cDestroy(_ gate: OpaquePointer)
@_silgen_name("ng_bind_loopback_port") private func cBind(_ gate: OpaquePointer, _ port: UInt16) -> Int32
@_silgen_name("ng_renew") private func cRenew(_ gate: OpaquePointer, _ generation: UInt64,
                                                 _ leaseNS: UInt64) -> Int32
@_silgen_name("ng_revoke") private func cRevoke(_ gate: OpaquePointer)
@_silgen_name("ng_lock") private func cLock(_ gate: OpaquePointer)
@_silgen_name("ng_tick") private func cTick(_ gate: OpaquePointer)
@_silgen_name("ng_is_open") private func cOpen(_ gate: OpaquePointer) -> Int32
@_silgen_name("ng_is_bound") private func cBound(_ gate: OpaquePointer) -> Int32
@_silgen_name("ng_active_pairs") private func cPairs(_ gate: OpaquePointer) -> Int

enum NativeGateError: Error, Equatable { case allocation, bind(Int32), renewal(Int32) }

// Install this object only behind the authenticated native controller. The C
// service owns one fixed target endpoint, closes on lease expiry independently of the UI event loop,
// and never accepts an upstream other than 127.0.0.1:7896.
final class SwiftNativeGate {
    struct Status { let bound: Bool; let open: Bool; let activePairs: Int }
    private let handle: OpaquePointer
    let entryPort: UInt16
    private let stateLock = NSLock()
    private var prepared = false
#if GUARD_GATE_FIXTURE_TESTS
    private var fixtureDescriptor: Int32?
    static func fixture(entryPort: UInt16) throws -> SwiftNativeGate {
        let gate = try SwiftNativeGate(entryPort: entryPort)
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw NativeGateError.allocation }
        close(pair[1])
        gate.fixtureDescriptor = pair[0]
        cTestEnable(gate.handle)
        return gate
    }
#endif

    init(entryPort: UInt16 = 17_897) throws {
        guard entryPort == 17_897 || entryPort == 17_898 else { throw NativeGateError.bind(22) }
        guard let value = cCreate() else { throw NativeGateError.allocation }
        handle = value
        self.entryPort = entryPort
    }

    // Call only after OS readback shows 17897 vacant and old apps quiescent.
    func prepareClosed() throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard !prepared else { throw NativeGateError.bind(16) }
        let code: Int32
#if GUARD_GATE_FIXTURE_TESTS
        if let descriptor = fixtureDescriptor {
            code = cTestListener(handle, descriptor)
            if code == 0 { fixtureDescriptor = nil }
        } else { code = cBind(handle, entryPort) }
#else
        code = cBind(handle, entryPort)
#endif
        guard code == 0 else { throw NativeGateError.bind(code) }
        prepared = true
    }

    func renew(generation: UInt64, leaseMillis: UInt64) throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard prepared, leaseMillis > 0, leaseMillis <= 3_000 else {
            throw NativeGateError.renewal(22)
        }
        let code = cRenew(handle, generation, leaseMillis * 1_000_000)
        guard code == 0 else { throw NativeGateError.renewal(code) }
    }

    func revoke() {
        stateLock.lock()
        defer { stateLock.unlock() }
        cRevoke(handle)
        prepared = false
    }
    func lock() {
        stateLock.lock()
        defer { stateLock.unlock() }
        cLock(handle)
    }
    func status() -> Status {
        cTick(handle)
        return Status(bound: cBound(handle) != 0,
                      open: cOpen(handle) != 0, activePairs: cPairs(handle))
    }

    deinit {
#if GUARD_GATE_FIXTURE_TESTS
        if let descriptor = fixtureDescriptor { close(descriptor) }
#endif
        cDestroy(handle)
    }
}
