import Foundation
import Dispatch

public typealias GuardLuLuFaultCallback = @convention(c) (UnsafeMutableRawPointer?) -> Void
public typealias GuardLuLuCurrentCallback = @convention(c) (UnsafeMutableRawPointer?) -> Int32

private final class WaitBox<T> {
    private let lock = NSLock()
    private var result: Result<T, Error>?
    func set(_ value: Result<T, Error>) { lock.lock(); result = value; lock.unlock() }
    func get() -> Result<T, Error>? { lock.lock(); defer { lock.unlock() }; return result }
}

final class GuardLuLuBridge {
    private let callback: GuardLuLuFaultCallback?
    private let context: UnsafeMutableRawPointer?
    private let callbackLock = NSLock()
    private var callbacksEnabled = true
    private let creationLock = NSLock()
    private let serviceLock = NSLock()
    private var service: LuLuServices?
    private var destroyed = false
    private let faultLock = NSLock()
    private var pendingFault: String?

    init(callback: GuardLuLuFaultCallback?, context: UnsafeMutableRawPointer?) {
        self.callback = callback
        self.context = context
    }

    func serviceForAction() throws -> LuLuServices {
        creationLock.lock()
        defer { creationLock.unlock() }
        if let existing = currentService() { return existing }
        serviceLock.lock()
        let unavailable = destroyed
        serviceLock.unlock()
        guard !unavailable else { throw NativeControlError.rejected("bridge_destroyed") }
        let created = try LuLuServices.make(onFault: { [weak self] reason in self?.reportFault(reason) })
        serviceLock.lock()
        guard !destroyed else {
            serviceLock.unlock()
            created.release()
            throw NativeControlError.rejected("bridge_destroyed")
        }
        service = created
        serviceLock.unlock()
        return created
    }

#if GUARD_OFFLINE_E2E
    func installOfflineFixture(_ scenario: Int32) throws {
        creationLock.lock(); defer { creationLock.unlock() }
        guard currentService() == nil else { throw NativeControlError.rejected("fixture_service_exists") }
        let created = try LuLuServices.makeOfflineFixture(scenario, onFault: { [weak self] in self?.reportFault($0) })
        serviceLock.lock(); defer { serviceLock.unlock() }
        guard !destroyed else { created.release(); throw NativeControlError.rejected("bridge_destroyed") }
        service = created
    }
#endif

    func currentService() -> LuLuServices? {
        serviceLock.lock()
        defer { serviceLock.unlock() }
        return destroyed ? nil : service
    }

    func withService<T>(_ operation: @escaping (LuLuServices) async throws -> T) -> Result<T, Error> {
        do {
            let service = try serviceForAction()
            return wait { try await operation(service) }
        } catch { return .failure(error) }
    }

    private func boundedFaultKey(_ value: String) -> String {
        let candidate = String(value.prefix(80))
        return candidate.range(of: "^[a-z0-9_]+$", options: .regularExpression) == nil
            ? "native_guard_fault" : candidate
    }

    func reportFault(_ reason: String) {
        callbackLock.lock(); defer { callbackLock.unlock() }
        guard callbacksEnabled else { return }
        faultLock.lock()
        if pendingFault == nil { pendingFault = boundedFaultKey(reason) }
        faultLock.unlock()
        callback?(context)
    }

    func beginExplicitRecovery() {
        faultLock.lock(); pendingFault = nil; faultLock.unlock()
    }

    // Each synchronous ABI call owns its error buffer, including across async work.
    func record(_ error: Error, into output: UnsafeMutablePointer<CChar>?, capacity: Int) -> Int32 {
        var key: String
        var status: Int32 = 2
        if let value = error as? NativeControlError {
            switch value {
            case .unavailable(let reason): key = reason; status = 1
            case .rejected(let reason): key = reason
            case .timeout: key = "native_timeout"; status = 3
            }
        } else if let value = error as? LegacySupervisorError {
            key = LuLuServices.cleanupReason(value).key
        } else {
            key = "native_operation_failed"
        }
        if key == "operation_invalidated" {
            faultLock.lock()
            key = pendingFault ?? key
            faultLock.unlock()
        }
        guard copyText(key, into: output, capacity: capacity) else { return 4 }
        return status
    }

    func dispose() {
        callbackLock.lock()
        callbacksEnabled = false
        callbackLock.unlock()
        creationLock.lock()
        defer { creationLock.unlock() }
        serviceLock.lock()
        guard !destroyed else { serviceLock.unlock(); return }
        destroyed = true
        let value = service
        service = nil
        serviceLock.unlock()
        guard let value else { return }
        value.emergencyLock()
        _ = wait { await value.finishLock() }
        value.release()
    }
}

private func wait<T>(_ operation: @escaping () async throws -> T) -> Result<T, Error> {
    let semaphore = DispatchSemaphore(value: 0)
    let box = WaitBox<T>()
    Task.detached {
        do { box.set(.success(try await operation())) }
        catch { box.set(.failure(error)) }
        semaphore.signal()
    }
    semaphore.wait()
    return box.get() ?? .failure(NativeControlError.unavailable("bridge_completion"))
}

private func bridge(_ raw: UnsafeMutableRawPointer?) -> GuardLuLuBridge? {
    guard let raw else { return nil }
    return Unmanaged<GuardLuLuBridge>.fromOpaque(raw).takeUnretainedValue()
}

private func isCurrent(_ callback: GuardLuLuCurrentCallback?, _ context: UnsafeMutableRawPointer?) -> Bool {
    callback?(context) == 1
}

private func copyText(_ value: String?, into output: UnsafeMutablePointer<CChar>?, capacity: Int) -> Bool {
    guard let output, capacity > 0 else { return false }
    let bytes = Array((value ?? "").utf8)
    guard bytes.count < capacity else { return false }
    for (index, byte) in bytes.enumerated() { output[index] = CChar(bitPattern: byte) }
    output[bytes.count] = 0
    return true
}

private func write(_ stamp: NativeCheckStamp,
                   fingerprint: UnsafeMutablePointer<CChar>?,
                   upstream: UnsafeMutablePointer<CChar>?, ingress: UnsafeMutablePointer<CChar>?,
                   ip: UnsafeMutablePointer<CChar>?, generation: UnsafeMutablePointer<UInt64>?,
                   checkedAt: UnsafeMutablePointer<UInt64>?, observedAt: UnsafeMutablePointer<Int64>?) -> Int32 {
    guard copyText(stamp.fingerprint, into: fingerprint, capacity: 65),
          copyText(stamp.upstreamFingerprint, into: upstream, capacity: 65),
          copyText(stamp.ingressFingerprint, into: ingress, capacity: 65),
          copyText(stamp.observedIP, into: ip, capacity: 64),
          let generation, let checkedAt, let observedAt else { return 4 }
    generation.pointee = stamp.generation
    checkedAt.pointee = stamp.checkedAtNS
    observedAt.pointee = stamp.observedAtUnixMS ?? 0
    return 0
}

// Display-only read; deliberately no bridge handle, service construction,
// callback, error latch or permit token is reachable from this entry point.
@_cdecl("guard_lulu_port_observation")
public func guard_lulu_port_observation(_ output: UnsafeMutablePointer<CChar>?, _ capacity: Int) -> Int32 {
    guard let output, (1...2_048).contains(capacity) else { return 4 }
    output.pointee = 0
    do {
        let payload = try LuLuServices.portObservationPayload(RootPortObserver.readDiagnostic())
        guard let text = String(data: payload, encoding: .utf8),
              copyText(text, into: output, capacity: capacity) else { return 4 }
        return 0
    } catch { return 4 }
}

@_cdecl("guard_lulu_create")
public func guard_lulu_create(_ callback: GuardLuLuFaultCallback?, _ context: UnsafeMutableRawPointer?,
                             _ output: UnsafeMutablePointer<UnsafeMutableRawPointer?>?) -> Int32 {
    guard let output, let callback else { return 4 }
    output.pointee = Unmanaged.passRetained(GuardLuLuBridge(callback: callback, context: context)).toOpaque()
    return 0
}

@_cdecl("guard_lulu_destroy")
public func guard_lulu_destroy(_ raw: UnsafeMutableRawPointer?) {
    guard let raw else { return }
    let value = Unmanaged<GuardLuLuBridge>.fromOpaque(raw).takeRetainedValue()
    value.dispose()
}

@_cdecl("guard_lulu_prepare")
public func guard_lulu_prepare(_ raw: UnsafeMutableRawPointer?, _ current: GuardLuLuCurrentCallback?,
                               _ context: UnsafeMutableRawPointer?,
                               _ errorOutput: UnsafeMutablePointer<CChar>?, _ errorCapacity: Int) -> Int32 {
    guard let value = bridge(raw) else { return 4 }
    value.beginExplicitRecovery()
    guard isCurrent(current, context) else { return 2 }
    switch value.withService({ service in try await service.prepare(isCurrent: { isCurrent(current, context) }) }) {
    case .success: return 0
    case .failure(let error): return value.record(error, into: errorOutput, capacity: errorCapacity)
    }
}

@_cdecl("guard_lulu_full_check")
public func guard_lulu_full_check(_ raw: UnsafeMutableRawPointer?, _ throughEntry: Int32,
                                  _ current: GuardLuLuCurrentCallback?, _ context: UnsafeMutableRawPointer?,
                                  _ fingerprint: UnsafeMutablePointer<CChar>?,
                                  _ upstream: UnsafeMutablePointer<CChar>?,
                                  _ ingress: UnsafeMutablePointer<CChar>?,
                                  _ ip: UnsafeMutablePointer<CChar>?,
                                  _ generation: UnsafeMutablePointer<UInt64>?,
                                  _ checkedAt: UnsafeMutablePointer<UInt64>?,
                                  _ observedAt: UnsafeMutablePointer<Int64>?,
                               _ errorOutput: UnsafeMutablePointer<CChar>?, _ errorCapacity: Int) -> Int32 {
    guard let value = bridge(raw), isCurrent(current, context) else { return 2 }
    switch value.withService({ service in try await service.fullCheck(throughEntry: throughEntry != 0,
                                                  isCurrent: { isCurrent(current, context) }) }) {
    case .success(let stamp): return write(stamp, fingerprint: fingerprint, upstream: upstream,
                                               ingress: ingress, ip: ip, generation: generation,
                                               checkedAt: checkedAt, observedAt: observedAt)
    case .failure(let error): return value.record(error, into: errorOutput, capacity: errorCapacity)
    }
}

@_cdecl("guard_lulu_renew")
public func guard_lulu_renew(_ raw: UnsafeMutableRawPointer?, _ generation: UInt64,
                             _ expectedGeneration: UInt64, _ expectedFingerprint: UnsafePointer<CChar>?,
                             _ expectedUpstream: UnsafePointer<CChar>?, _ expectedIngress: UnsafePointer<CChar>?,
                             _ current: GuardLuLuCurrentCallback?, _ context: UnsafeMutableRawPointer?,
                               _ errorOutput: UnsafeMutablePointer<CChar>?, _ errorCapacity: Int) -> Int32 {
    guard let value = bridge(raw), isCurrent(current, context),
          let expectedFingerprint, let expectedUpstream, let expectedIngress,
          let service = value.currentService() else { return 2 }
    let fingerprint = String(cString: expectedFingerprint)
    let upstream = String(cString: expectedUpstream)
    let ingress = String(cString: expectedIngress)
    switch wait({
        try await service.renew(generation: generation, expectedGeneration: expectedGeneration,
                                expectedFingerprint: fingerprint,
                                expectedUpstreamFingerprint: upstream,
                                expectedIngressFingerprint: ingress,
                                isCurrent: { isCurrent(current, context) })
    }) {
    case .success: return 0
    case .failure(let error): return value.record(error, into: errorOutput, capacity: errorCapacity)
    }
}

@_cdecl("guard_lulu_open")
public func guard_lulu_open(_ raw: UnsafeMutableRawPointer?, _ generation: UInt64,
                            _ target: UnsafePointer<CChar>?,
                            _ current: GuardLuLuCurrentCallback?, _ context: UnsafeMutableRawPointer?,
                               _ errorOutput: UnsafeMutablePointer<CChar>?, _ errorCapacity: Int) -> Int32 {
    guard let value = bridge(raw), isCurrent(current, context), let target else { return 2 }
    let targetID = String(cString: target)
    switch value.withService({ service in try await service.open(target: targetID, generation: generation, isCurrent: { isCurrent(current, context) }) }) {
    case .success: return 0
    case .failure(let error): return value.record(error, into: errorOutput, capacity: errorCapacity)
    }
}

@_cdecl("guard_lulu_launch")
public func guard_lulu_launch(_ raw: UnsafeMutableRawPointer?, _ target: UnsafePointer<CChar>?,
                              _ generation: UInt64, _ current: GuardLuLuCurrentCallback?,
                              _ context: UnsafeMutableRawPointer?,
                               _ errorOutput: UnsafeMutablePointer<CChar>?, _ errorCapacity: Int) -> Int32 {
    guard let value = bridge(raw), isCurrent(current, context), let target else { return 2 }
    switch value.withService({ service in try await service.launch(target: String(cString: target), generation: generation,
                                               isCurrent: { isCurrent(current, context) }) }) {
    case .success: return 0
    case .failure(let error): return value.record(error, into: errorOutput, capacity: errorCapacity)
    }
}

@_cdecl("guard_lulu_emergency_lock")
public func guard_lulu_emergency_lock(_ raw: UnsafeMutableRawPointer?) {
    bridge(raw)?.currentService()?.emergencyLock()
}

@_cdecl("guard_lulu_finish_lock")
public func guard_lulu_finish_lock(_ raw: UnsafeMutableRawPointer?, _ confirmed: UnsafeMutablePointer<Int32>?,
                                   _ bound: UnsafeMutablePointer<Int32>?, _ open: UnsafeMutablePointer<Int32>?,
                                   _ pairs: UnsafeMutablePointer<Int32>?, _ owned: UnsafeMutablePointer<Int32>?,
                                   _ pending: UnsafeMutablePointer<Int32>?,
                                   _ diagnostic: UnsafeMutablePointer<CChar>?, _ diagnosticCapacity: Int) -> Int32 {
    guard let value = bridge(raw), let confirmed, let bound, let open, let pairs, let owned, let pending,
          let diagnostic, (1...512).contains(diagnosticCapacity) else { return 4 }
    diagnostic.pointee = 0
    confirmed.pointee = 0; bound.pointee = 0; open.pointee = 0
    pairs.pointee = 0; owned.pointee = 0; pending.pointee = 0
    guard let service = value.currentService() else {
        confirmed.pointee = 1
        return 0
    }
    let cleanup = wait { await service.finishLock() }
    guard case .success(let result) = cleanup else {
        _ = copyText("cleanup_bridge_completion_failed", into: diagnostic, capacity: diagnosticCapacity)
        return 3
    }
    let state = service.readback()
    confirmed.pointee = result ? 1 : 0
    bound.pointee = state.bound ? 1 : 0
    open.pointee = state.open ? 1 : 0
    pairs.pointee = Int32(clamping: state.activePairs)
    owned.pointee = state.owned ? 1 : 0
    pending.pointee = state.pending ? 1 : 0
    if !result && !copyText(service.cleanupDiagnostic.wire, into: diagnostic, capacity: diagnosticCapacity) { return 4 }
    return 0
}

@_cdecl("guard_lulu_recover_observation")
public func guard_lulu_recover_observation(_ raw: UnsafeMutableRawPointer?,
                                          _ fingerprint: UnsafeMutablePointer<CChar>?,
                                          _ upstream: UnsafeMutablePointer<CChar>?,
                                          _ ingress: UnsafeMutablePointer<CChar>?,
                                          _ ip: UnsafeMutablePointer<CChar>?,
                                          _ generation: UnsafeMutablePointer<UInt64>?,
                                          _ checkedAt: UnsafeMutablePointer<UInt64>?,
                                          _ observedAt: UnsafeMutablePointer<Int64>?,
                               _ errorOutput: UnsafeMutablePointer<CChar>?, _ errorCapacity: Int) -> Int32 {
    guard let value = bridge(raw) else { return 4 }
    value.beginExplicitRecovery()
    switch value.withService({ service in try await service.recoverObservation() }) {
    case .success(let stamp): return write(stamp, fingerprint: fingerprint, upstream: upstream,
                                               ingress: ingress, ip: ip, generation: generation,
                                               checkedAt: checkedAt, observedAt: observedAt)
    case .failure(let error): return value.record(error, into: errorOutput, capacity: errorCapacity)
    }
}

@_cdecl("guard_lulu_readback")
public func guard_lulu_readback(_ raw: UnsafeMutableRawPointer?, _ bound: UnsafeMutablePointer<Int32>?,
                               _ open: UnsafeMutablePointer<Int32>?, _ pairs: UnsafeMutablePointer<Int32>?,
                               _ owned: UnsafeMutablePointer<Int32>?, _ pending: UnsafeMutablePointer<Int32>?) -> Int32 {
    guard let value = bridge(raw), let bound, let open, let pairs, let owned, let pending else { return 4 }
    guard let service = value.currentService() else {
        bound.pointee = 0; open.pointee = 0; pairs.pointee = 0; owned.pointee = 0; pending.pointee = 0
        return 0
    }
    let state = service.readback()
    bound.pointee = state.bound ? 1 : 0
    open.pointee = state.open ? 1 : 0
    pairs.pointee = Int32(clamping: state.activePairs)
    owned.pointee = state.owned ? 1 : 0
    pending.pointee = state.pending ? 1 : 0
    return 0
}

#if GUARD_OFFLINE_E2E
@_cdecl("guard_lulu_offline_install")
public func guard_lulu_offline_install(_ raw: UnsafeMutableRawPointer?, _ scenario: Int32) -> Int32 {
    guard let value = bridge(raw), ((0...6).contains(scenario) || (10...25).contains(scenario) || (30...33).contains(scenario)) else { return -1 }
    do { try value.installOfflineFixture(scenario); return 0 } catch { return -2 }
}
@_cdecl("guard_lulu_offline_control")
public func guard_lulu_offline_control(_ raw: UnsafeMutableRawPointer?, _ action: Int32) -> Int32 {
    guard let fixture = bridge(raw)?.currentService()?.offlineFixture else { return -1 }
    return fixture.control(action)
}
#endif
