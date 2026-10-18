// [INPUT]: Rust-owned Guard commands and existing LuLu headless service results.
// [OUTPUT]: Full-check stamps, direct renewal matching and cleanup diagnostics for the C ABI.
// [POS]: Transport/error values only; Rust remains the Guard business-state authority.
// [PROTOCOL]: Adapted from integration/controller/ControllerContracts.swift.
import Foundation

enum NativeControlError: Error {
    case unavailable(String)
    case rejected(String)
    case timeout
}

struct ProcessBirth: Equatable {
    let pid: Int32
    let uid: UInt32
    let startSeconds: Int64
    let startMicroseconds: Int32
    let executable: String

    var valid: Bool {
        pid > 0 && startSeconds > 0 && startMicroseconds >= 0 &&
        startMicroseconds < 1_000_000 && executable.hasPrefix("/") && !executable.isEmpty
    }
}

struct NativeCheckStamp: Equatable {
    static let publicObservationMaxAgeNS: UInt64 = 60_000_000_000

    let fingerprint: String
    let generation: UInt64
    let checkedAtNS: UInt64
    let observedIP: String?
    let observedAtUnixMS: Int64?
    let upstreamFingerprint: String
    let ingressFingerprint: String

    func matches(_ snapshot: EnvironmentRenewalSnapshot, checkedAtNS: UInt64) -> Bool {
        checkedAtNS >= self.checkedAtNS && generation == snapshot.networkGeneration &&
        upstreamFingerprint == snapshot.upstreamFingerprint &&
        ingressFingerprint == snapshot.ingressFingerprint
    }

    func hasFreshPublicObservation(at continuousNowNS: UInt64) -> Bool {
        guard observedIP != nil, observedAtUnixMS != nil,
              checkedAtNS > 0, continuousNowNS >= checkedAtNS else { return false }
        return continuousNowNS - checkedAtNS <= Self.publicObservationMaxAgeNS
    }

}

struct EnvironmentRenewalSnapshot: Equatable {
    let networkGeneration: UInt64
    let upstreamFingerprint: String
    let ingressFingerprint: String
}

enum LuLuExtensionStatus {
    static func isEnabled(in listing: String) -> Bool {
        listing.split(separator: "\n").contains {
            $0.contains("com.objective-see.lulu.extension") && $0.contains("[activated enabled]")
        }
    }
}

// One failed inventory only. Fixed enums and bounded integers; no paths, argv,
// environment, ps output or arbitrary NSError text can enter this transport.
struct InventoryFailure: Equatable {
    enum Target: String { case claude = "Claude", sunbrowser = "SunBrowser" }
    enum Phase: String {
        case observation = "inv_observation", beforeTerm = "inv_before_term"
        case termWait = "inv_term_wait", beforeKill = "inv_before_kill", final = "inv_final"
    }
    enum Step: String, CaseIterable {
        case scope = "inv_scope", list = "inv_list", status = "inv_status"
        case snapshotGone = "inv_snapshot_gone", pathStatus = "inv_path_status"
        case pathCandidate = "inv_path_candidate", snapshot = "inv_snapshot"
        case selfPID = "inv_self_pid", physical = "inv_physical"
        case signatureStatus = "inv_signature_status", finalGone = "inv_final_gone"
        case finalSnapshot = "inv_final_snapshot", psRun = "inv_ps_run"
        case psTimeout = "inv_ps_timeout", psResult = "inv_ps_result", psShape = "inv_ps_shape"
    }
    var target: Target
    var phase: Phase = .observation
    var pass: UInt32 = 0
    let step: Step
    var pid: Int32? = nil
    var rc: Int32? = nil
    var call: Int32 = 0
    var raw: Int32 = 0
    var os: Int32 = 0
    var value: Int32 = 0
    var identity: Int32? = nil
    // ps state: 0=not used, 1=POSIX run error, 2=Cocoa run error,
    // 3=other run error, 4=timeout, 5=result, 6=output shape.
    var ps: Int32 = 0
    var psCode: Int64 = 0
    var psBytes: Int32 = 0
    // Bits: exit zero, <=8192 bytes, valid UTF8, valid trimmed single line.
    var psFlags: Int32 = 0

    var wire: String {
        func number(_ value: Int32?) -> String { value.map(String.init) ?? "-" }
        return "Inventory evidence: target=\(target.rawValue), phase=\(phase.rawValue), pass=\(pass), step=\(step.rawValue), pid=\(number(pid)), rc=\(number(rc)), call=\(call), raw=\(raw), os=\(os), value=\(value), identity=\(number(identity)), ps=\(ps), psCode=\(psCode), psBytes=\(psBytes), psFlags=\(psFlags)."
    }
}

enum NativeCleanupDiagnostic: Equatable {
    case unavailable, pending(preparation: Int, open: Int, launch: Int)
    case gateBeforeStop, gateAfterStop, generationChanged, confirmationRejected
    case invalidSealedTarget, unknownTarget, inspectionIncomplete
    case signatureMismatch(Int32), processChanged(Int32), stillRunning
    case supervisorLaunchInFlight, processStillRunning
    case gateNotLocked, gateNotReady, launchFailed, launchIdentityMismatch
    case signalFailed(Int32, Int32), unknownError
    case inspectionFailure(InventoryFailure)

    var wire: String {
        if case .inspectionFailure(let detail) = self { return key + "\n" + detail.wire }
        return key
    }

    var key: String {
        switch self {
        case .unavailable: return "cleanup_reason_unavailable"
        case let .pending(preparation, open, launch):
            return "cleanup_pending_prepare_\(preparation)_open_\(open)_launch_\(launch)"
        case .gateBeforeStop: return "cleanup_gate_not_locked_before_stop"
        case .gateAfterStop: return "cleanup_gate_not_locked_after_stop"
        case .generationChanged: return "cleanup_generation_changed"
        case .confirmationRejected: return "cleanup_confirmation_rejected"
        case .invalidSealedTarget: return "cleanup_invalid_sealed_target"
        case .unknownTarget: return "cleanup_unknown_target"
        case .inspectionIncomplete: return "cleanup_process_inspection_incomplete"
        case .inspectionFailure: return "cleanup_process_inspection_incomplete"
        case .signatureMismatch(let pid): return "cleanup_signature_mismatch_pid_\(pid)"
        case .processChanged(let pid): return "cleanup_process_changed_pid_\(pid)"
        case .stillRunning: return "cleanup_process_or_launch_still_running"
        case .supervisorLaunchInFlight: return "cleanup_supervisor_launch_in_flight"
        case .processStillRunning: return "cleanup_process_still_running"
        case .gateNotLocked: return "cleanup_supervisor_gate_not_locked"
        case .gateNotReady: return "cleanup_supervisor_gate_not_ready"
        case .launchFailed: return "cleanup_launch_failed"
        case .launchIdentityMismatch: return "cleanup_launch_identity_mismatch"
        case let .signalFailed(pid, code): return "cleanup_signal_failed_pid_\(pid)_code_\(code)"
        case .unknownError: return "cleanup_unknown_error"
        }
    }
}
