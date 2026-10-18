// [INPUT]: Guard commands, an administrator-provisioned Windows principal, and fixed WFP object IDs.
// [OUTPUT]: Fail-closed Windows readiness, read-only WFP/SCM identity inspection, and a SID-scoped persistent deny transaction foundation.
// [POS]: Adapter construction is inert; explicit inspection reads fixed WFP objects and provider-service identity, while targets remain unavailable without verified provisioning and a trusted launcher.
// [PROTOCOL]: Update this header when the contract changes, then check CLAUDE.md.
use crate::guard::{ActionToken, Backend, BackendAction, BackendResult};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const PROVIDER_KEY: Guid = Guid::from_u128(0x4c73e2f1_7a18_4d16_9a43_60549d2d7651);
const SUBLAYER_KEY: Guid = Guid::from_u128(0xd46d8b09_4ca6_4851_afa1_2da57d2a2630);
const DENY_V4_KEY: Guid = Guid::from_u128(0xa7f069f5_1de7_4c9d_a8d8_75fcad833930);
const DENY_V6_KEY: Guid = Guid::from_u128(0xf9f5a95d_1df4_4ac5_9c1d_798f49b7c393);

const PROVIDER_NAME: &str = "Claude Network Guard candidate";
const SUBLAYER_NAME: &str = "Claude Network Guard candidate deny";
const DENY_V4_NAME: &str = "Claude Guard deny outbound v4";
const DENY_V6_NAME: &str = "Claude Guard deny outbound v6";
const SUBLAYER_WEIGHT: u16 = 0x4000;
const PERSISTENT: u32 = 0x0000_0001;
const FWP_ACTRL_MATCH_FILTER: u32 = 0x0000_0001;

// No Windows installer currently provisions this service, a dedicated account,
// the gate, or a target launcher. Keep this unset until those are delivered and
// their ACL, image path, startup mode, principal, and readiness are verified.
const PROVIDER_SERVICE_NAME: Option<&str> = None;
const GATE_SERVICE_NAME: Option<&str> = None;
const NATIVE_WRITE_READINESS_CONFIGURED: bool = false;
const SERVICE_SID_TYPE_RESTRICTED: u32 = 3;
const SERVICE_SID_TYPE_UNRESTRICTED_VALUE: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl Guid {
    const fn from_u128(value: u128) -> Self {
        Self {
            data1: (value >> 96) as u32,
            data2: (value >> 80 & 0xffff) as u16,
            data3: (value >> 64 & 0xffff) as u16,
            data4: (value as u64).to_be_bytes(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Principal {
    managed_sid: String,
    interactive_sid: String,
    standard_account_verified: bool,
}

impl Principal {
    fn valid(&self) -> bool {
        is_account_sid(&self.managed_sid)
            && is_account_sid(&self.interactive_sid)
            && self.managed_sid != self.interactive_sid
            && self.standard_account_verified
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ServiceReadiness {
    installed: bool,
    auto_start: bool,
    running: bool,
    identity_verified: bool,
    image_configured: bool,
    expected_image: bool,
}

impl ServiceReadiness {
    fn ready(&self) -> bool {
        self.installed
            && self.auto_start
            && self.running
            && self.identity_verified
            && self.image_configured
            && self.expected_image
    }
}

fn service_identity_is_verified(
    account_configured: bool,
    service_sid_type: u32,
    running: bool,
    process_id: u32,
    token_has_service_sid: bool,
    same_process_after_readback: bool,
) -> bool {
    account_configured
        && matches!(service_sid_type, SERVICE_SID_TYPE_UNRESTRICTED_VALUE | SERVICE_SID_TYPE_RESTRICTED)
        && running
        && process_id != 0
        && token_has_service_sid
        && same_process_after_readback
}

fn inspection_result(readiness: &Readiness) -> BackendResult {
    let blockers = readiness.blockers();
    if matches!(
        readiness.fixed_wfp_readback,
        FixedWfpReadback::ObjectsPresent | FixedWfpReadback::Failed
    ) {
        return recovery(&blockers.join(","));
    }
    if blockers.is_empty() {
        unavailable("windows-data-plane-and-target-readiness-not-accepted")
    } else {
        unavailable(&blockers.join(","))
    }
}

fn start_readiness_result(readiness: &Readiness) -> Option<BackendResult> {
    if matches!(
        readiness.fixed_wfp_readback,
        FixedWfpReadback::ObjectsPresent | FixedWfpReadback::Failed
    ) {
        Some(recovery(&readiness.blockers().join(",")))
    } else if !readiness.can_prepare_target() {
        Some(unavailable(&readiness.blockers().join(",")))
    } else {
        None
    }
}

fn lock_readiness_result(readiness: &Readiness) -> BackendResult {
    match readiness.fixed_wfp_readback {
        FixedWfpReadback::ObjectsPresent => {
            recovery("fixed-wfp-objects-present-but-cleanup-not-provisioned")
        }
        FixedWfpReadback::Failed => recovery("fixed-wfp-objects-not-readable"),
        FixedWfpReadback::NotRead => recovery("fixed-wfp-state-not-checked"),
        FixedWfpReadback::AllMissing => {
            unavailable("windows-gate-and-workload-cleanup-not-provisioned")
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixedWfpReadback {
    NotRead,
    AllMissing,
    ObjectsPresent,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Readiness {
    supported_architecture: bool,
    native_api_available: bool,
    fixed_wfp_readback: FixedWfpReadback,
    principal: Option<Principal>,
    provider_service: Option<ServiceReadiness>,
    gate_service: Option<ServiceReadiness>,
    gate_handoff_verified: bool,
    target_launcher_verified: bool,
}

impl Readiness {
    fn blockers(&self) -> Vec<&'static str> {
        let mut blockers = Vec::new();
        if !self.supported_architecture {
            blockers.push("windows-x64-required");
        }
        if !self.native_api_available {
            blockers.push("windows-filtering-platform-unavailable");
        }
        if self.fixed_wfp_readback == FixedWfpReadback::Failed {
            blockers.push("fixed-wfp-objects-not-readable");
        }
        if self.fixed_wfp_readback == FixedWfpReadback::ObjectsPresent {
            blockers.push("fixed-wfp-objects-present-unverified");
        }
        if !self.principal.as_ref().is_some_and(Principal::valid) {
            blockers.push("dedicated-standard-principal-not-provisioned");
        }
        if let Some(service) = &self.provider_service {
            if !service.installed {
                blockers.push("wfp-provider-service-not-installed");
            }
            if !service.auto_start {
                blockers.push("wfp-provider-service-not-auto-start");
            }
            if !service.running {
                blockers.push("wfp-provider-service-not-running");
            }
            if !service.identity_verified {
                blockers.push("wfp-provider-service-identity-not-verified");
            }
            if !service.image_configured {
                blockers.push("wfp-provider-service-image-not-configured");
            }
            if !service.expected_image {
                blockers.push("wfp-provider-service-image-not-verified");
            }
        } else {
            blockers.push("wfp-provider-service-not-ready");
        }
        if !self.gate_service.as_ref().is_some_and(ServiceReadiness::ready) {
            blockers.push("guard-gate-service-not-ready");
        }
        if !self.gate_handoff_verified {
            blockers.push("authenticated-gate-handoff-not-verified");
        }
        if !self.target_launcher_verified {
            blockers.push("target-launcher-not-integrated");
        }
        blockers
    }

    fn can_prepare_target(&self) -> bool {
        self.blockers().is_empty()
    }
}

/// Construction has no OS side effects. Readiness is gathered only for an explicit native action.
pub(crate) fn backend() -> Arc<dyn Backend> {
    Arc::new(WindowsBackend::default())
}

#[derive(Default)]
struct WindowsBackend {
    emergency_generation: AtomicU64,
}

impl Backend for WindowsBackend {
    fn emergency_lock(&self) {
        // There are no gate or permit handles in this build. The epoch still
        // invalidates any future asynchronous WFP setup before its commit edge.
        self.emergency_generation.fetch_add(1, Ordering::SeqCst);
    }

    fn execute(&self, action: BackendAction, token: ActionToken) -> BackendResult {
        let emergency_generation = self.emergency_generation.load(Ordering::SeqCst);
        if !token.is_current() {
            return unavailable("stale-windows-guard-action");
        }

        match action {
            BackendAction::Inspect | BackendAction::Recover => {
                let readiness = native_readiness();
                inspection_result(&readiness)
            }
            BackendAction::Start(_) => {
                let readiness = native_readiness();
                if let Some(result) = start_readiness_result(&readiness) {
                    return result;
                }
                if !token.is_current()
                    || self.emergency_generation.load(Ordering::SeqCst) != emergency_generation
                {
                    return recovery("windows-start-cancelled-before-wfp-commit");
                }

                // This stage deliberately has no authenticated gate permit or
                // process launcher, so even a provisioned deny baseline cannot
                // authorize a target. The transaction below is kept private to
                // the future prepare path and cannot be reached from WebView input.
                unavailable("windows-target-permit-and-launch-path-not-integrated")
            }
            BackendAction::Lock => {
                // There are no accepted targets, workloads, or dynamic permit
                // sessions in this build. Do not claim a platform lock.
                let readiness = native_readiness();
                lock_readiness_result(&readiness)
            }
        }
    }
}

fn unavailable(reason: &str) -> BackendResult {
    BackendResult::Unavailable {
        reason: reason.into(),
        available_targets: HashSet::new(),
        owned_workloads: HashSet::new(),
        cleanup_confirmed: true,
    }
}

fn recovery(reason: &str) -> BackendResult {
    BackendResult::Recovery {
        reason: reason.into(),
        available_targets: HashSet::new(),
        owned_workloads: HashSet::new(),
        cleanup_confirmed: false,
    }
}

fn native_readiness() -> Readiness {
    #[cfg(windows)]
    {
        native::readiness()
    }
    #[cfg(not(windows))]
    {
        Readiness {
            supported_architecture: false,
            native_api_available: false,
            fixed_wfp_readback: FixedWfpReadback::NotRead,
            principal: None,
            provider_service: None,
            gate_service: None,
            gate_handoff_verified: false,
            target_launcher_verified: false,
        }
    }
}

fn is_account_sid(value: &str) -> bool {
    let mut parts = value.split('-');
    if parts.next() != Some("S") || parts.next() != Some("1") || parts.next() != Some("5") {
        return false;
    }
    let components = parts.collect::<Vec<_>>();
    components.len() == 5
        && components.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u32>().is_ok()
        })
        && components.last().is_some_and(|rid| rid.parse::<u32>().is_ok_and(|rid| rid != 0))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionMode {
    ReadOnly,
    Write,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProviderReadback {
    key: Guid,
    flags: u32,
    display_name: String,
    service_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SublayerReadback {
    key: Guid,
    flags: u32,
    provider_key: Option<Guid>,
    weight: u16,
    display_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FilterReadback {
    key: Guid,
    flags: u32,
    provider_key: Option<Guid>,
    sublayer_key: Guid,
    layer_key: Guid,
    action_type: u32,
    weight_type: i32,
    condition_count: u32,
    condition_field: Option<Guid>,
    match_type: Option<i32>,
    condition_type: Option<i32>,
    condition_sid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
struct ObjectSet {
    provider: Option<ProviderReadback>,
    sublayer: Option<SublayerReadback>,
    deny_v4: Option<FilterReadback>,
    deny_v6: Option<FilterReadback>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectSetState {
    AllMissing,
    AllExact,
    AllOwnedNotReady,
    PartialOrConflicting,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DenyPlan {
    principal: Principal,
    provider_service_name: String,
}

impl DenyPlan {
    fn validate(&self) -> bool {
        self.principal.valid()
            && !self.provider_service_name.is_empty()
            && self.provider_service_name == self.provider_service_name.trim()
    }
}

fn classify_objects(objects: &ObjectSet, plan: &DenyPlan) -> ObjectSetState {
    let present = [
        objects.provider.is_some(),
        objects.sublayer.is_some(),
        objects.deny_v4.is_some(),
        objects.deny_v6.is_some(),
    ];
    if present.iter().all(|found| !found) {
        return ObjectSetState::AllMissing;
    }
    if !present.iter().all(|found| *found) {
        return ObjectSetState::PartialOrConflicting;
    }

    let provider = objects.provider.as_ref().unwrap();
    let sublayer = objects.sublayer.as_ref().unwrap();
    let filters = [objects.deny_v4.as_ref().unwrap(), objects.deny_v6.as_ref().unwrap()];
    let provider_flags_exact = provider.flags == PERSISTENT;
    let provider_flags_known = provider.flags == PERSISTENT
        || provider.flags == (PERSISTENT | windows_provider_disabled_flag());
    let sublayer_exact = sublayer.flags == PERSISTENT
        && sublayer.key == SUBLAYER_KEY
        && sublayer.provider_key == Some(PROVIDER_KEY)
        && sublayer.weight == SUBLAYER_WEIGHT
        && sublayer.display_name == SUBLAYER_NAME;
    let provider_exact = provider.key == PROVIDER_KEY
        && provider.display_name == PROVIDER_NAME
        && provider.service_name.as_deref() == Some(plan.provider_service_name.as_str())
        && provider_flags_known;
    if !provider_exact || !sublayer_exact {
        return ObjectSetState::PartialOrConflicting;
    }

    let exact_filter = |filter: &FilterReadback, key: Guid, layer: Guid| {
        filter.key == key
            && filter.provider_key == Some(PROVIDER_KEY)
            && filter.sublayer_key == SUBLAYER_KEY
            && filter.layer_key == layer
            && (filter.flags == PERSISTENT
                || filter.flags == (PERSISTENT | windows_filter_disabled_flag()))
            && filter.action_type == 0x0000_1001
            && filter.weight_type == 0
            && filter.condition_count == 1
            && filter.condition_field == Some(wfp_ale_user_id())
            && filter.match_type == Some(0)
            && filter.condition_type == Some(14)
            && filter.condition_sid.as_deref() == Some(plan.principal.managed_sid.as_str())
    };
    if !exact_filter(&filters[0], DENY_V4_KEY, wfp_ale_connect_v4())
        || !exact_filter(&filters[1], DENY_V6_KEY, wfp_ale_connect_v6())
    {
        return ObjectSetState::PartialOrConflicting;
    }
    if provider_flags_exact
        && sublayer.flags == PERSISTENT
        && filters.iter().all(|filter| filter.flags == PERSISTENT)
    {
        ObjectSetState::AllExact
    } else {
        ObjectSetState::AllOwnedNotReady
    }
}

#[cfg(windows)]
fn windows_provider_disabled_flag() -> u32 {
    windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_PROVIDER_FLAG_DISABLED
}
#[cfg(not(windows))]
fn windows_provider_disabled_flag() -> u32 {
    16
}
#[cfg(windows)]
fn windows_filter_disabled_flag() -> u32 {
    windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_FLAG_DISABLED
}
#[cfg(not(windows))]
fn windows_filter_disabled_flag() -> u32 {
    32
}
#[cfg(windows)]
fn wfp_ale_user_id() -> Guid {
    let value = windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_ALE_USER_ID;
    Guid { data1: value.data1, data2: value.data2, data3: value.data3, data4: value.data4 }
}
#[cfg(not(windows))]
fn wfp_ale_user_id() -> Guid {
    Guid::from_u128(0xaf043a0a_b34d_4f86_979c_c90371af6e66)
}
#[cfg(windows)]
fn wfp_ale_connect_v4() -> Guid {
    let value = windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    Guid { data1: value.data1, data2: value.data2, data3: value.data3, data4: value.data4 }
}
#[cfg(not(windows))]
fn wfp_ale_connect_v4() -> Guid {
    Guid::from_u128(0xc38d57d1_05a7_4c33_904f_7fbceee60e82)
}
#[cfg(windows)]
fn wfp_ale_connect_v6() -> Guid {
    let value = windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    Guid { data1: value.data1, data2: value.data2, data3: value.data3, data4: value.data4 }
}
#[cfg(not(windows))]
fn wfp_ale_connect_v6() -> Guid {
    Guid::from_u128(0x4a72393b_319f_44bc_84c3_ba54dcb3b6b4)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CloseReport {
    abort_status: Option<u32>,
    close_status: Option<u32>,
}

trait WfpSession {
    fn begin(&mut self, mode: TransactionMode) -> u32;
    fn read_objects(&mut self) -> Result<ObjectSet, u32>;
    fn add_provider(&mut self, plan: &DenyPlan) -> u32;
    fn add_sublayer(&mut self, plan: &DenyPlan) -> u32;
    fn add_filter(&mut self, plan: &DenyPlan, v6: bool) -> u32;
    fn commit(&mut self) -> u32;
    fn abort(&mut self) -> u32;
    fn close(&mut self) -> CloseReport;
}

trait WfpSessionFactory: Send + Sync {
    fn open(&self) -> Result<Box<dyn WfpSession>, u32>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DenyInstallStatus {
    NotReady,
    ExistingExact,
    ExistingDisabled,
    Conflict,
    ReadbackError,
    TransactionAborted,
    AbortUnconfirmed,
    CommitOutcomeUnknown,
    CommittedExactReadback,
    CommittedReadbackUnverified,
    EngineCloseUnconfirmed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DenyInstallResult {
    status: DenyInstallStatus,
    error: Option<u32>,
    abort_status: Option<u32>,
    close_status: Option<u32>,
    deny_may_be_installed: bool,
}

impl DenyInstallResult {
    fn no_calls(status: DenyInstallStatus) -> Self {
        Self {
            status,
            error: None,
            abort_status: None,
            close_status: None,
            deny_may_be_installed: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WriteReadiness {
    principal_verified: bool,
    provider_service_ready: bool,
    gate_service_ready: bool,
    gate_handoff_verified: bool,
    target_launcher_verified: bool,
}

impl WriteReadiness {
    fn native_ready(self) -> bool {
        NATIVE_WRITE_READINESS_CONFIGURED
            && PROVIDER_SERVICE_NAME.is_some()
            && GATE_SERVICE_NAME.is_some()
            && self.principal_verified
            && self.provider_service_ready
            && self.gate_service_ready
            && self.gate_handoff_verified
            && self.target_launcher_verified
    }

    #[cfg(test)]
    fn offline_fixture() -> Self {
        Self {
            principal_verified: true,
            provider_service_ready: true,
            gate_service_ready: true,
            gate_handoff_verified: true,
            target_launcher_verified: true,
        }
    }
}

fn install_persistent_deny(
    factory: &dyn WfpSessionFactory,
    plan: &DenyPlan,
    readiness: WriteReadiness,
    is_current: impl Fn() -> bool,
) -> DenyInstallResult {
    if !plan.validate()
        || !readiness.native_ready()
        || !is_current()
    {
        return DenyInstallResult::no_calls(DenyInstallStatus::NotReady);
    }
    install_transaction(factory, plan, is_current)
}

fn install_transaction(
    factory: &dyn WfpSessionFactory,
    plan: &DenyPlan,
    is_current: impl Fn() -> bool,
) -> DenyInstallResult {
    if !plan.validate() || !is_current() {
        return DenyInstallResult::no_calls(DenyInstallStatus::NotReady);
    }
    let mut session = match factory.open() {
        Ok(session) => session,
        Err(error) => {
            let mut result = DenyInstallResult::no_calls(DenyInstallStatus::ReadbackError);
            result.error = Some(error);
            return result;
        }
    };
    if !is_current() {
        let close = session.close();
        return result_with_close(DenyInstallStatus::Cancelled, None, None, false, close);
    }
    let begin = session.begin(TransactionMode::Write);
    if begin != 0 {
        let close = session.close();
        return result_with_close(DenyInstallStatus::ReadbackError, Some(begin), None, false, close);
    }

    let before = match session.read_objects() {
        Ok(readback) => readback,
        Err(error) => {
            let abort = session.abort();
            let close = session.close();
            return result_with_close(
                if abort == 0 { DenyInstallStatus::ReadbackError } else { DenyInstallStatus::AbortUnconfirmed },
                Some(error), nonzero(abort), true, close,
            );
        }
    };
    match classify_objects(&before, plan) {
        ObjectSetState::AllExact => {
            let abort = session.abort();
            let close = session.close();
            return result_with_close(
                if abort == 0 { DenyInstallStatus::ExistingExact } else { DenyInstallStatus::AbortUnconfirmed },
                nonzero(abort), nonzero(abort), true, close,
            );
        }
        ObjectSetState::AllOwnedNotReady => {
            let abort = session.abort();
            let close = session.close();
            return result_with_close(
                if abort == 0 { DenyInstallStatus::ExistingDisabled } else { DenyInstallStatus::AbortUnconfirmed },
                nonzero(abort), nonzero(abort), true, close,
            );
        }
        ObjectSetState::PartialOrConflicting => {
            let abort = session.abort();
            let close = session.close();
            return result_with_close(
                if abort == 0 { DenyInstallStatus::Conflict } else { DenyInstallStatus::AbortUnconfirmed },
                nonzero(abort), nonzero(abort), contains_deny(&before), close,
            );
        }
        ObjectSetState::AllMissing => {}
    }

    let mut writes = false;
    for step in 0..4 {
        if !is_current() {
            let abort = session.abort();
            let close = session.close();
            return result_with_close(
                if abort == 0 { DenyInstallStatus::Cancelled } else { DenyInstallStatus::AbortUnconfirmed },
                nonzero(abort), nonzero(abort), writes, close,
            );
        }
        let status = match step {
            0 => session.add_provider(plan),
            1 => session.add_sublayer(plan),
            2 => session.add_filter(plan, false),
            _ => session.add_filter(plan, true),
        };
        if status != 0 {
            let abort = session.abort();
            let close = session.close();
            return result_with_close(
                if abort == 0 { DenyInstallStatus::TransactionAborted } else { DenyInstallStatus::AbortUnconfirmed },
                Some(status), nonzero(abort), true, close,
            );
        }
        writes = true;
    }

    if !is_current() {
        let abort = session.abort();
        let close = session.close();
        return result_with_close(
            if abort == 0 { DenyInstallStatus::Cancelled } else { DenyInstallStatus::AbortUnconfirmed },
            nonzero(abort), nonzero(abort), true, close,
        );
    }
    let commit = session.commit();
    if commit != 0 {
        let abort = session.abort();
        let close = session.close();
        return result_with_close(
            DenyInstallStatus::CommitOutcomeUnknown,
            Some(commit), nonzero(abort), true, close,
        );
    }

    let read_status = session.begin(TransactionMode::ReadOnly);
    let after = if read_status == 0 { session.read_objects() } else { Err(read_status) };
    let readback = match after {
        Ok(value) => {
            let commit = session.commit();
            if commit == 0 { Some(value) } else { None }
        }
        Err(_) => None,
    };
    let close = session.close();
    let result_status = match (readback.as_ref().map(|objects| classify_objects(objects, plan)), close.close_status) {
        (_, Some(code)) if code != 0 => DenyInstallStatus::EngineCloseUnconfirmed,
        (Some(ObjectSetState::AllExact), _) => DenyInstallStatus::CommittedExactReadback,
        _ => DenyInstallStatus::CommittedReadbackUnverified,
    };
    result_with_close(result_status, nonzero(read_status), close.abort_status, true, close)
}

fn nonzero(status: u32) -> Option<u32> {
    (status != 0).then_some(status)
}

fn contains_deny(objects: &ObjectSet) -> bool {
    objects.deny_v4.is_some() || objects.deny_v6.is_some()
}

fn result_with_close(
    status: DenyInstallStatus,
    error: Option<u32>,
    abort_status: Option<u32>,
    deny_may_be_installed: bool,
    close: CloseReport,
) -> DenyInstallResult {
    let status = if close.close_status.is_some_and(|code| code != 0) {
        DenyInstallStatus::EngineCloseUnconfirmed
    } else {
        status
    };
    DenyInstallResult {
        status,
        error: error.or(close.close_status),
        abort_status: abort_status.or(close.abort_status),
        close_status: close.close_status,
        deny_may_be_installed: deny_may_be_installed || close.abort_status.is_some_and(|code| code != 0),
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HLOCAL, LocalFree};
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    use windows_sys::Win32::Security::{
        CheckTokenMembership, DuplicateToken, GetAce, GetAclInformation, GetLengthSid,
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, IsValidSecurityDescriptor,
        IsValidSid, LookupAccountNameW, SID_NAME_USE, SE_SELF_RELATIVE, SecurityImpersonation,
        TOKEN_DUPLICATE, TOKEN_QUERY, ACL_SIZE_INFORMATION,
    };
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
    use windows_sys::Win32::System::Services as services;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const MAX_SERVICE_CONFIG_BYTES: u32 = 1024 * 1024;

    struct ServiceHandle(services::SC_HANDLE);

    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { services::CloseServiceHandle(self.0); }
            }
        }
    }

    struct KernelHandle(windows_sys::Win32::Foundation::HANDLE);

    impl Drop for KernelHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0); }
            }
        }
    }

    fn service_token_has_sid(name: &str, process_id: u32) -> Result<bool, u32> {
        if process_id == 0 {
            return Ok(false);
        }
        let account = wide_null(&format!("NT SERVICE\\{name}"));
        let mut sid_bytes = 0u32;
        let mut domain_chars = 0u32;
        let mut account_use: SID_NAME_USE = 0;
        let first_lookup = unsafe {
            LookupAccountNameW(
                null(),
                account.as_ptr(),
                null_mut(),
                &mut sid_bytes,
                null_mut(),
                &mut domain_chars,
                &mut account_use,
            )
        };
        if first_lookup != 0 {
            return Err(13);
        }
        if sid_bytes == 0 || sid_bytes > 64 * 1024 || domain_chars > 32 * 1024 {
            return Err(87);
        }
        let mut sid_storage = vec![0usize; (sid_bytes as usize).div_ceil(size_of::<usize>())];
        let mut domain = vec![0u16; domain_chars as usize];
        if unsafe {
            LookupAccountNameW(
                null(),
                account.as_ptr(),
                sid_storage.as_mut_ptr().cast(),
                &mut sid_bytes,
                domain.as_mut_ptr(),
                &mut domain_chars,
                &mut account_use,
            )
        } == 0
        {
            return Err(unsafe { GetLastError() });
        }
        let sid = sid_storage.as_mut_ptr().cast();
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(87);
        }

        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if process.is_null() {
            return Err(unsafe { GetLastError() });
        }
        let _process = KernelHandle(process);
        let mut token = null_mut();
        if unsafe {
            OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token)
        } == 0 || token.is_null()
        {
            return Err(unsafe { GetLastError() });
        }
        let _token = KernelHandle(token);
        let mut impersonation_token = null_mut();
        if unsafe { DuplicateToken(token, SecurityImpersonation, &mut impersonation_token) } == 0
            || impersonation_token.is_null()
        {
            return Err(unsafe { GetLastError() });
        }
        let _impersonation_token = KernelHandle(impersonation_token);
        let mut member = 0;
        if unsafe { CheckTokenMembership(impersonation_token, sid, &mut member) } == 0 {
            return Err(unsafe { GetLastError() });
        }
        Ok(member != 0)
    }

    /// Reads SCM configuration for the service named by the fixed WFP provider.
    /// The expected image is deliberately unverified until provisioning pins it.
    fn service_readiness(name: &str) -> Result<ServiceReadiness, u32> {
        if name.is_empty()
            || name.len() > 256
            || name.contains('\0')
            || name.contains('/')
            || name.contains('\\')
        {
            return Err(87);
        }
        let mut name_wide = wide_null(name);
        let manager = unsafe {
            services::OpenSCManagerW(null(), null(), services::SC_MANAGER_CONNECT)
        };
        if manager.is_null() {
            return Err(unsafe { GetLastError() });
        }
        let _manager = ServiceHandle(manager);
        let service = unsafe {
            services::OpenServiceW(
                manager,
                name_wide.as_mut_ptr(),
                services::SERVICE_QUERY_CONFIG | services::SERVICE_QUERY_STATUS,
            )
        };
        if service.is_null() {
            return Err(unsafe { GetLastError() });
        }
        let _service = ServiceHandle(service);

        let mut required = 0u32;
        let first_query = unsafe {
            services::QueryServiceConfigW(service, null_mut(), 0, &mut required)
        };
        if first_query != 0 {
            return Err(13);
        }
        if required < size_of::<services::QUERY_SERVICE_CONFIGW>() as u32
            || required > MAX_SERVICE_CONFIG_BYTES
        {
            return Err(unsafe { GetLastError() });
        }
        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut config_buffer = vec![0usize; words];
        if unsafe {
            services::QueryServiceConfigW(
                service,
                config_buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(unsafe { GetLastError() });
        }
        let config = unsafe { &*config_buffer.as_ptr().cast::<services::QUERY_SERVICE_CONFIGW>() };
        let image_configured = wide_string(config.lpBinaryPathName)
            .is_some_and(|path| !path.trim().is_empty());
        let account_configured = wide_string(config.lpServiceStartName)
            .is_some_and(|account| !account.trim().is_empty());

        let mut sid_info: services::SERVICE_SID_INFO = unsafe { zeroed() };
        let mut sid_info_bytes = 0u32;
        if unsafe {
            services::QueryServiceConfig2W(
                service,
                services::SERVICE_CONFIG_SERVICE_SID_INFO,
                (&mut sid_info as *mut services::SERVICE_SID_INFO).cast(),
                size_of::<services::SERVICE_SID_INFO>() as u32,
                &mut sid_info_bytes,
            )
        } == 0
        {
            return Err(unsafe { GetLastError() });
        }
        let mut status: services::SERVICE_STATUS_PROCESS = unsafe { zeroed() };
        let mut status_bytes = 0u32;
        if unsafe {
            services::QueryServiceStatusEx(
                service,
                services::SC_STATUS_PROCESS_INFO,
                (&mut status as *mut services::SERVICE_STATUS_PROCESS).cast(),
                size_of::<services::SERVICE_STATUS_PROCESS>() as u32,
                &mut status_bytes,
            )
        } == 0
        {
            return Err(unsafe { GetLastError() });
        }
        let sid_enabled = matches!(
            sid_info.dwServiceSidType,
            services::SERVICE_SID_TYPE_UNRESTRICTED | SERVICE_SID_TYPE_RESTRICTED
        );
        let process_identity = if account_configured && sid_enabled && status.dwCurrentState == services::SERVICE_RUNNING {
            service_token_has_sid(name, status.dwProcessId).unwrap_or(false)
        } else {
            false
        };
        let mut after_status: services::SERVICE_STATUS_PROCESS = unsafe { zeroed() };
        let mut after_status_bytes = 0u32;
        if unsafe {
            services::QueryServiceStatusEx(
                service,
                services::SC_STATUS_PROCESS_INFO,
                (&mut after_status as *mut services::SERVICE_STATUS_PROCESS).cast(),
                size_of::<services::SERVICE_STATUS_PROCESS>() as u32,
                &mut after_status_bytes,
            )
        } == 0
        {
            return Err(unsafe { GetLastError() });
        }
        let identity_verified = service_identity_is_verified(
            account_configured,
            sid_info.dwServiceSidType,
            status.dwCurrentState == services::SERVICE_RUNNING,
            status.dwProcessId,
            process_identity,
            after_status.dwCurrentState == services::SERVICE_RUNNING
                && after_status.dwProcessId == status.dwProcessId,
        );

        Ok(ServiceReadiness {
            installed: true,
            auto_start: config.dwStartType == services::SERVICE_AUTO_START,
            running: status.dwCurrentState == services::SERVICE_RUNNING,
            identity_verified,
            image_configured,
            // No Windows deployment manifest pins the expected service image yet.
            expected_image: false,
        })
    }

    const TRANSACTION_READ_ONLY: u32 = 1;
    const SDDL_REVISION_1: u32 = 1;
    const ACL_SIZE_INFORMATION_CLASS: i32 = 2;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const FWP_ACTRL_MATCH_FILTER: u32 = super::FWP_ACTRL_MATCH_FILTER;
    const WFP_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
    const WFP_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;
    const WFP_FILTER_NOT_FOUND: u32 = 0x8032_0003;

    struct Session {
        engine: windows_sys::Win32::Foundation::HANDLE,
        transaction: Option<TransactionMode>,
        abort_status: Option<u32>,
        close_status: Option<u32>,
    }

    impl Session {
        fn open() -> Result<Self, u32> {
            let mut engine = null_mut();
            let status = unsafe {
                wfp::FwpmEngineOpen0(
                    null(),
                    RPC_C_AUTHN_DEFAULT as u32,
                    null(),
                    null(),
                    &mut engine,
                )
            };
            if status != 0 { return Err(status); }
            if engine.is_null() { return Err(87); }
            Ok(Self { engine, transaction: None, abort_status: None, close_status: None })
        }

        fn begin(&mut self, mode: TransactionMode) -> u32 {
            if self.engine.is_null() || self.transaction.is_some() { return 1; }
            let flags = if mode == TransactionMode::ReadOnly { TRANSACTION_READ_ONLY } else { 0 };
            let status = unsafe { wfp::FwpmTransactionBegin0(self.engine, flags) };
            if status == 0 { self.transaction = Some(mode); }
            status
        }

        fn commit(&mut self) -> u32 {
            if self.engine.is_null() || self.transaction.is_none() { return 1; }
            let status = unsafe { wfp::FwpmTransactionCommit0(self.engine) };
            if status == 0 { self.transaction = None; }
            status
        }

        fn abort(&mut self) -> u32 {
            if self.engine.is_null() || self.transaction.is_none() { return 1; }
            let status = unsafe { wfp::FwpmTransactionAbort0(self.engine) };
            if status == 0 { self.transaction = None; }
            else { self.abort_status = Some(status); }
            status
        }

        fn close(&mut self) -> CloseReport {
            if !self.engine.is_null() {
                if self.transaction.is_some() { let _ = self.abort(); }
                let engine = self.engine;
                self.engine = null_mut();
                let status = unsafe { wfp::FwpmEngineClose0(engine) };
                if status != 0 { self.close_status = Some(status); }
            }
            CloseReport { abort_status: self.abort_status, close_status: self.close_status }
        }

        fn read_provider(&self) -> Result<Option<ProviderReadback>, u32> {
            let mut pointer = null_mut();
            let key = to_wfp_guid(PROVIDER_KEY);
            let status = unsafe { wfp::FwpmProviderGetByKey0(self.engine, &key, &mut pointer) };
            if status == WFP_PROVIDER_NOT_FOUND { return Ok(None); }
            if status != 0 || pointer.is_null() { return Err(if status == 0 { 13 } else { status }); }
            let result = unsafe {
                let value = &*pointer;
                Ok(Some(ProviderReadback {
                    key: from_wfp_guid(value.providerKey),
                    flags: value.flags,
                    display_name: wide_string(value.displayData.name).unwrap_or_default(),
                    service_name: wide_string(value.serviceName),
                }))
            };
            free_wfp(pointer.cast());
            result
        }

        fn read_sublayer(&self) -> Result<Option<SublayerReadback>, u32> {
            let mut pointer = null_mut();
            let key = to_wfp_guid(SUBLAYER_KEY);
            let status = unsafe { wfp::FwpmSubLayerGetByKey0(self.engine, &key, &mut pointer) };
            if status == WFP_SUBLAYER_NOT_FOUND { return Ok(None); }
            if status != 0 || pointer.is_null() { return Err(if status == 0 { 13 } else { status }); }
            let result = unsafe {
                let value = &*pointer;
                Ok(Some(SublayerReadback {
                    key: from_wfp_guid(value.subLayerKey),
                    flags: value.flags,
                    provider_key: read_guid(value.providerKey),
                    weight: value.weight,
                    display_name: wide_string(value.displayData.name).unwrap_or_default(),
                }))
            };
            free_wfp(pointer.cast());
            result
        }

        fn read_filter(&self, key: Guid) -> Result<Option<FilterReadback>, u32> {
            let mut pointer = null_mut();
            let key = to_wfp_guid(key);
            let status = unsafe { wfp::FwpmFilterGetByKey0(self.engine, &key, &mut pointer) };
            if status == WFP_FILTER_NOT_FOUND { return Ok(None); }
            if status != 0 || pointer.is_null() { return Err(if status == 0 { 13 } else { status }); }
            let result = unsafe {
                let value = &*pointer;
                let condition = if value.numFilterConditions == 1 && !value.filterCondition.is_null() {
                    let condition = &*value.filterCondition;
                    let sid = if condition.conditionValue.r#type == wfp::FWP_SECURITY_DESCRIPTOR_TYPE {
                        let blob = condition.conditionValue.Anonymous.sd;
                        if blob.is_null() { None } else { read_condition_sid(&*blob) }
                    } else { None };
                    (Some(from_wfp_guid(condition.fieldKey)), Some(condition.matchType), Some(condition.conditionValue.r#type), sid)
                } else { (None, None, None, None) };
                Ok(Some(FilterReadback {
                    key: from_wfp_guid(value.filterKey),
                    flags: value.flags,
                    provider_key: read_guid(value.providerKey),
                    sublayer_key: from_wfp_guid(value.subLayerKey),
                    layer_key: from_wfp_guid(value.layerKey),
                    action_type: value.action.r#type,
                    weight_type: value.weight.r#type,
                    condition_count: value.numFilterConditions,
                    condition_field: condition.0,
                    match_type: condition.1,
                    condition_type: condition.2,
                    condition_sid: condition.3,
                }))
            };
            free_wfp(pointer.cast());
            result
        }

        fn add_provider(&self, plan: &DenyPlan) -> u32 {
            let mut name = wide_null(PROVIDER_NAME);
            let mut service = wide_null(&plan.provider_service_name);
            let mut value: wfp::FWPM_PROVIDER0 = unsafe { zeroed() };
            value.providerKey = to_wfp_guid(PROVIDER_KEY);
            value.displayData.name = name.as_mut_ptr();
            value.flags = PERSISTENT;
            value.serviceName = service.as_mut_ptr();
            unsafe { wfp::FwpmProviderAdd0(self.engine, &value, null_mut()) }
        }

        fn add_sublayer(&self) -> u32 {
            let mut name = wide_null(SUBLAYER_NAME);
            let mut provider_key = to_wfp_guid(PROVIDER_KEY);
            let mut value: wfp::FWPM_SUBLAYER0 = unsafe { zeroed() };
            value.subLayerKey = to_wfp_guid(SUBLAYER_KEY);
            value.displayData.name = name.as_mut_ptr();
            value.flags = PERSISTENT;
            value.providerKey = &mut provider_key;
            value.weight = SUBLAYER_WEIGHT;
            unsafe { wfp::FwpmSubLayerAdd0(self.engine, &value, null_mut()) }
        }

        fn add_filter(&self, plan: &DenyPlan, v6: bool) -> u32 {
            let filter_key = if v6 { DENY_V6_KEY } else { DENY_V4_KEY };
            let layer_key = if v6 { wfp_ale_connect_v6() } else { wfp_ale_connect_v4() };
            let display = if v6 { DENY_V6_NAME } else { DENY_V4_NAME };
            let mut name = wide_null(display);
            let mut provider_key = to_wfp_guid(PROVIDER_KEY);
            let sd = match security_descriptor(&plan.principal.managed_sid) {
                Ok(sd) => sd,
                Err(error) => return error,
            };
            let mut blob = wfp::FWP_BYTE_BLOB { size: sd.length, data: sd.pointer.cast() };
            let condition = wfp::FWPM_FILTER_CONDITION0 {
                fieldKey: to_wfp_guid(wfp_ale_user_id()),
                matchType: wfp::FWP_MATCH_EQUAL,
                conditionValue: wfp::FWP_CONDITION_VALUE0 {
                    r#type: wfp::FWP_SECURITY_DESCRIPTOR_TYPE,
                    Anonymous: wfp::FWP_CONDITION_VALUE0_0 { sd: &mut blob },
                },
            };
            let mut value: wfp::FWPM_FILTER0 = unsafe { zeroed() };
            value.filterKey = to_wfp_guid(filter_key);
            value.displayData.name = name.as_mut_ptr();
            value.flags = PERSISTENT;
            value.providerKey = &mut provider_key;
            value.layerKey = to_wfp_guid(layer_key);
            value.subLayerKey = to_wfp_guid(SUBLAYER_KEY);
            value.weight = wfp::FWP_VALUE0 { r#type: wfp::FWP_EMPTY, Anonymous: unsafe { zeroed() } };
            value.numFilterConditions = 1;
            value.filterCondition = &condition as *const _ as *mut _;
            value.action = wfp::FWPM_ACTION0 {
                r#type: wfp::FWP_ACTION_BLOCK,
                Anonymous: wfp::FWPM_ACTION0_0 { filterType: to_wfp_guid(Guid::from_u128(0)) },
            };
            value.Anonymous = wfp::FWPM_FILTER0_0 { rawContext: 0 };
            let mut filter_id = 0;
            let status = unsafe { wfp::FwpmFilterAdd0(self.engine, &value, null_mut(), &mut filter_id) };
            status
        }
    }

    impl Drop for Session {
        fn drop(&mut self) { let _ = self.close(); }
    }

    impl WfpSession for Session {
        fn begin(&mut self, mode: TransactionMode) -> u32 {
            let flags = if mode == TransactionMode::ReadOnly { TRANSACTION_READ_ONLY } else { 0 };
            if self.engine.is_null() || self.transaction.is_some() { return 1; }
            let status = unsafe { wfp::FwpmTransactionBegin0(self.engine, flags) };
            if status == 0 { self.transaction = Some(mode); }
            status
        }
        fn read_objects(&mut self) -> Result<ObjectSet, u32> {
            if self.transaction.is_none() { return Err(1); }
            Ok(ObjectSet {
                provider: self.read_provider()?,
                sublayer: self.read_sublayer()?,
                deny_v4: self.read_filter(DENY_V4_KEY)?,
                deny_v6: self.read_filter(DENY_V6_KEY)?,
            })
        }
        fn add_provider(&mut self, plan: &DenyPlan) -> u32 { Session::add_provider(self, plan) }
        fn add_sublayer(&mut self, _plan: &DenyPlan) -> u32 { Session::add_sublayer(self) }
        fn add_filter(&mut self, plan: &DenyPlan, v6: bool) -> u32 { Session::add_filter(self, plan, v6) }
        fn commit(&mut self) -> u32 { Session::commit(self) }
        fn abort(&mut self) -> u32 { Session::abort(self) }
        fn close(&mut self) -> CloseReport { Session::close(self) }
    }

    struct NativeFactory;
    impl WfpSessionFactory for NativeFactory {
        fn open(&self) -> Result<Box<dyn WfpSession>, u32> { Ok(Box::new(Session::open()?)) }
    }

    struct LocalSecurityDescriptor { pointer: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR, length: u32 }
    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) { if !self.pointer.is_null() { unsafe { let _ = LocalFree(self.pointer.cast::<c_void>() as HLOCAL); } } }
    }

    fn security_descriptor(sid: &str) -> Result<LocalSecurityDescriptor, u32> {
        if !super::is_account_sid(sid) { return Err(87); }
        let sddl = format!("D:(A;;0x{FWP_ACTRL_MATCH_FILTER:08X};;;{sid})");
        let mut wide = wide_null(&sddl);
        let mut pointer = null_mut();
        let mut length = 0;
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_mut_ptr(), SDDL_REVISION_1, &mut pointer, &mut length,
            )
        };
        if ok == 0 || pointer.is_null() || length == 0 {
            return Err(unsafe { GetLastError() });
        }
        Ok(LocalSecurityDescriptor { pointer, length })
    }

    fn read_condition_sid(blob: &wfp::FWP_BYTE_BLOB) -> Option<String> {
        if blob.size == 0 || blob.size > 64 * 1024 || blob.data.is_null() { return None; }
        let sd = blob.data.cast();
        unsafe {
            if IsValidSecurityDescriptor(sd) == 0 { return None; }
            let mut control = 0u16;
            let mut revision = 0u32;
            if GetSecurityDescriptorControl(sd, &mut control, &mut revision) == 0
                || control & SE_SELF_RELATIVE == 0
            { return None; }
            let mut dacl_present = 0;
            let mut dacl_defaulted = 0;
            let mut dacl = null_mut();
            if GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted) == 0
                || dacl_present == 0 || dacl.is_null()
            { return None; }
            let mut acl_info: ACL_SIZE_INFORMATION = zeroed();
            if GetAclInformation(
                dacl,
                (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                ACL_SIZE_INFORMATION_CLASS,
            ) == 0 || acl_info.AceCount != 1
            { return None; }
            let mut ace = null_mut();
            if GetAce(dacl, 0, &mut ace) == 0 || ace.is_null() { return None; }
            let ace_type = *(ace.cast::<u8>());
            let ace_flags = *ace.cast::<u8>().add(1);
            let ace_size = std::ptr::read_unaligned(ace.cast::<u8>().add(2).cast::<u16>());
            let access_mask = std::ptr::read_unaligned(ace.cast::<u8>().add(4).cast::<u32>());
            if ace_type != ACCESS_ALLOWED_ACE_TYPE || ace_flags != 0
                || access_mask != FWP_ACTRL_MATCH_FILTER || ace_size < 16
            { return None; }
            let sid = ace.cast::<u8>().add(8).cast();
            let sid_length = GetLengthSid(sid);
            if sid_length == 0 || 8u32.saturating_add(sid_length) > ace_size as u32
                || IsValidSid(sid) == 0
            { return None; }
            let mut sid_string = null_mut();
            if ConvertSidToStringSidW(sid, &mut sid_string) == 0 || sid_string.is_null() { return None; }
            let result = wide_string(sid_string);
            let _ = LocalFree(sid_string.cast::<c_void>() as HLOCAL);
            result.filter(|value| super::is_account_sid(value))
        }
    }

    fn wide_string(value: windows_sys::core::PWSTR) -> Option<String> {
        if value.is_null() { return None; }
        unsafe {
            let mut len = 0usize;
            while len < 32768 && *value.add(len) != 0 { len += 1; }
            if len == 32768 { return None; }
            Some(String::from_utf16_lossy(std::slice::from_raw_parts(value, len)))
        }
    }

    fn wide_null(value: &str) -> Vec<u16> { value.encode_utf16().chain(Some(0)).collect() }
    fn read_guid(value: *mut windows_sys::core::GUID) -> Option<Guid> { if value.is_null() { None } else { Some(from_wfp_guid(unsafe { *value })) } }
    fn to_wfp_guid(value: Guid) -> windows_sys::core::GUID {
        windows_sys::core::GUID { data1: value.data1, data2: value.data2, data3: value.data3, data4: value.data4 }
    }
    fn from_wfp_guid(value: windows_sys::core::GUID) -> Guid {
        Guid { data1: value.data1, data2: value.data2, data3: value.data3, data4: value.data4 }
    }
    fn free_wfp(value: *mut c_void) {
        if value.is_null() { return; }
        let mut pointer = value;
        unsafe { wfp::FwpmFreeMemory0(&mut pointer); }
    }

    pub(super) fn readiness() -> Readiness {
        let architecture = std::env::consts::ARCH == "x86_64";
        let (native_api_available, fixed_wfp_readback, objects) = if !architecture {
            (false, FixedWfpReadback::NotRead, None)
        } else {
            match read_fixed_objects() {
                Ok(objects) => {
                    let any = objects.provider.is_some()
                        || objects.sublayer.is_some()
                        || objects.deny_v4.is_some()
                        || objects.deny_v6.is_some();
                    (
                        true,
                        if any { FixedWfpReadback::ObjectsPresent } else { FixedWfpReadback::AllMissing },
                        Some(objects),
                    )
                }
                Err(_) => (false, FixedWfpReadback::Failed, None),
            }
        };
        let provider_service = objects
            .as_ref()
            .and_then(|objects| objects.provider.as_ref())
            .and_then(|provider| provider.service_name.as_deref())
            .and_then(|name| service_readiness(name).ok());
        Readiness {
            supported_architecture: architecture,
            native_api_available,
            fixed_wfp_readback,
            principal: None,
            provider_service,
            gate_service: None,
            gate_handoff_verified: false,
            target_launcher_verified: false,
        }
    }

    /// Queries only the product's four fixed GUIDs in a read-only WFP transaction.
    /// This is called only by an explicit Guard inspection/start command, never by backend().
    fn read_fixed_objects() -> Result<ObjectSet, u32> {
        let mut session = NativeFactory.open()?;
        let begin = session.begin(TransactionMode::ReadOnly);
        if begin != 0 {
            let close = session.close();
            return Err(close.close_status.unwrap_or(begin));
        }
        let objects = match session.read_objects() {
            Ok(objects) => objects,
            Err(error) => {
                let abort = session.abort();
                let close = session.close();
                return Err(close.close_status.or_else(|| nonzero(abort)).unwrap_or(error));
            }
        };
        let commit = session.commit();
        if commit != 0 {
            let abort = session.abort();
            let close = session.close();
            return Err(close.close_status.or_else(|| nonzero(abort)).unwrap_or(commit));
        }
        let close = session.close();
        if let Some(error) = close.close_status { return Err(error); }
        if let Some(error) = close.abort_status { return Err(error); }
        Ok(objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn sample_principal() -> Principal {
        Principal {
            managed_sid: "S-1-5-21-111-222-333-1001".into(),
            interactive_sid: "S-1-5-21-111-222-333-1002".into(),
            standard_account_verified: true,
        }
    }

    fn ready_plan() -> DenyPlan {
        DenyPlan { principal: sample_principal(), provider_service_name: "GuardWfpProvider".into() }
    }

    fn exact_objects(plan: &DenyPlan) -> ObjectSet {
        let filter = |key, layer| FilterReadback {
            key, flags: PERSISTENT, provider_key: Some(PROVIDER_KEY), sublayer_key: SUBLAYER_KEY,
            layer_key: layer, action_type: 0x1001, weight_type: 0, condition_count: 1,
            condition_field: Some(wfp_ale_user_id()), match_type: Some(0), condition_type: Some(14),
            condition_sid: Some(plan.principal.managed_sid.clone()),
        };
        ObjectSet {
            provider: Some(ProviderReadback { key: PROVIDER_KEY, flags: PERSISTENT,
                display_name: PROVIDER_NAME.into(), service_name: Some(plan.provider_service_name.clone()) }),
            sublayer: Some(SublayerReadback { key: SUBLAYER_KEY, flags: PERSISTENT,
                provider_key: Some(PROVIDER_KEY), weight: SUBLAYER_WEIGHT, display_name: SUBLAYER_NAME.into() }),
            deny_v4: Some(filter(DENY_V4_KEY, wfp_ale_connect_v4())),
            deny_v6: Some(filter(DENY_V6_KEY, wfp_ale_connect_v6())),
        }
    }

    #[derive(Default)]
    struct FakeState {
        objects: ObjectSet,
        calls: Vec<&'static str>,
        fail_add: Option<&'static str>,
        abort_status: u32,
        close_status: u32,
        commit_status: u32,
        unverified_after_commit: bool,
        staged: Option<ObjectSet>,
        in_transaction: bool,
    }

    struct FakeFactory(Arc<Mutex<FakeState>>);
    struct FakeSession(Arc<Mutex<FakeState>>);

    impl WfpSessionFactory for FakeFactory {
        fn open(&self) -> Result<Box<dyn WfpSession>, u32> {
            self.0.lock().unwrap().calls.push("open");
            Ok(Box::new(FakeSession(self.0.clone())))
        }
    }

    impl WfpSession for FakeSession {
        fn begin(&mut self, mode: TransactionMode) -> u32 {
            let mut state = self.0.lock().unwrap();
            if state.in_transaction { return 1; }
            state.calls.push(match mode { TransactionMode::ReadOnly => "begin-read", TransactionMode::Write => "begin-write" });
            state.in_transaction = true;
            state.staged = (mode == TransactionMode::Write).then(|| state.objects.clone());
            0
        }
        fn read_objects(&mut self) -> Result<ObjectSet, u32> {
            let mut state = self.0.lock().unwrap();
            state.calls.push("read");
            if !state.in_transaction { return Err(1); }
            Ok(state.staged.as_ref().unwrap_or(&state.objects).clone())
        }
        fn add_provider(&mut self, plan: &DenyPlan) -> u32 {
            let mut state = self.0.lock().unwrap();
            state.calls.push("add-provider");
            if state.fail_add == Some("provider") { return 5; }
            state.staged.as_mut().unwrap().provider = exact_objects(plan).provider;
            0
        }
        fn add_sublayer(&mut self, plan: &DenyPlan) -> u32 {
            let mut state = self.0.lock().unwrap();
            state.calls.push("add-sublayer");
            if state.fail_add == Some("sublayer") { return 5; }
            state.staged.as_mut().unwrap().sublayer = exact_objects(plan).sublayer;
            0
        }
        fn add_filter(&mut self, plan: &DenyPlan, v6: bool) -> u32 {
            let mut state = self.0.lock().unwrap();
            let key = if v6 { "v6" } else { "v4" };
            state.calls.push(if v6 { "add-v6" } else { "add-v4" });
            if state.fail_add == Some(key) { return 5; }
            let exact = exact_objects(plan);
            let staged = state.staged.as_mut().unwrap();
            if v6 { staged.deny_v6 = exact.deny_v6; } else { staged.deny_v4 = exact.deny_v4; }
            0
        }
        fn commit(&mut self) -> u32 {
            let mut state = self.0.lock().unwrap();
            state.calls.push("commit");
            if state.commit_status != 0 { return state.commit_status; }
            if let Some(staged) = state.staged.take() { state.objects = staged; }
            state.in_transaction = false;
            if state.unverified_after_commit { state.objects.deny_v4.as_mut().unwrap().flags |= windows_filter_disabled_flag(); }
            0
        }
        fn abort(&mut self) -> u32 {
            let mut state = self.0.lock().unwrap();
            state.calls.push("abort");
            if state.abort_status == 0 { state.staged = None; state.in_transaction = false; }
            state.abort_status
        }
        fn close(&mut self) -> CloseReport {
            let mut state = self.0.lock().unwrap();
            state.calls.push("close");
            CloseReport { abort_status: (state.abort_status != 0).then_some(state.abort_status), close_status: (state.close_status != 0).then_some(state.close_status) }
        }
    }

    #[test]
    fn backend_factory_is_inert_and_every_target_is_unavailable() {
        let _backend = backend();
        let readiness = Readiness {
            supported_architecture: true,
            native_api_available: true,
            fixed_wfp_readback: FixedWfpReadback::AllMissing,
            principal: None,
            provider_service: None,
            gate_service: None,
            gate_handoff_verified: false,
            target_launcher_verified: false,
        };
        assert!(!readiness.can_prepare_target());
        assert!(readiness.blockers().contains(&"dedicated-standard-principal-not-provisioned"));
        assert!(readiness.blockers().contains(&"guard-gate-service-not-ready"));
    }

    #[test]
    fn principal_requires_distinct_valid_dedicated_sid() {
        let mut principal = sample_principal();
        assert!(principal.valid());
        principal.interactive_sid = principal.managed_sid.clone();
        assert!(!principal.valid());
        principal.interactive_sid = "S-1-5-21-111-222-333-1002".into();
        principal.managed_sid = "S-1-5-18".into();
        assert!(!principal.valid());
        principal.managed_sid = "S-1-5-21-111-222-333-1001".into();
        principal.standard_account_verified = false;
        assert!(!principal.valid());
    }

    #[test]
    fn deny_readback_requires_the_managed_sid_on_both_address_families() {
        let plan = ready_plan();
        let mut objects = exact_objects(&plan);
        assert_eq!(classify_objects(&objects, &plan), ObjectSetState::AllExact);

        objects.deny_v4.as_mut().unwrap().condition_sid =
            Some(plan.principal.interactive_sid.clone());
        assert_eq!(classify_objects(&objects, &plan), ObjectSetState::PartialOrConflicting);

        objects = exact_objects(&plan);
        objects.deny_v6.as_mut().unwrap().layer_key = wfp_ale_connect_v4();
        assert_eq!(classify_objects(&objects, &plan), ObjectSetState::PartialOrConflicting);

        objects = exact_objects(&plan);
        objects.deny_v6 = None;
        assert_eq!(classify_objects(&objects, &plan), ObjectSetState::PartialOrConflicting);
    }

    #[test]
    fn protocol_limited_filter_is_not_accepted_as_the_full_deny_baseline() {
        let plan = ready_plan();
        let mut objects = exact_objects(&plan);
        objects.deny_v4.as_mut().unwrap().condition_count = 2;
        assert_eq!(classify_objects(&objects, &plan), ObjectSetState::PartialOrConflicting);
    }

    #[test]
    fn readiness_does_not_accept_partial_service_or_gate_evidence() {
        let ready = ServiceReadiness {
            installed: true,
            auto_start: true,
            running: true,
            identity_verified: true,
            image_configured: true,
            expected_image: true,
        };
        let readiness = Readiness {
            supported_architecture: true, native_api_available: true,
            fixed_wfp_readback: FixedWfpReadback::AllMissing,
            principal: Some(sample_principal()), provider_service: Some(ready.clone()),
            gate_service: Some(ServiceReadiness { running: false, ..ready }),
            gate_handoff_verified: true, target_launcher_verified: true,
        };
        assert!(!readiness.can_prepare_target());
        assert!(readiness.blockers().contains(&"guard-gate-service-not-ready"));
    }

    #[test]
    fn provider_service_identity_and_expected_image_are_required() {
        let service = ServiceReadiness {
            installed: true,
            auto_start: true,
            running: true,
            identity_verified: false,
            image_configured: true,
            expected_image: false,
        };
        let readiness = Readiness {
            supported_architecture: true,
            native_api_available: true,
            fixed_wfp_readback: FixedWfpReadback::AllMissing,
            principal: Some(sample_principal()),
            provider_service: Some(service),
            gate_service: None,
            gate_handoff_verified: false,
            target_launcher_verified: false,
        };
        let blockers = readiness.blockers();
        assert!(blockers.contains(&"wfp-provider-service-identity-not-verified"));
        assert!(blockers.contains(&"wfp-provider-service-image-not-verified"));
        assert!(!readiness.can_prepare_target());
    }

    #[test]
    fn provider_service_identity_requires_the_live_service_sid_and_stable_pid() {
        let verified = service_identity_is_verified(
            true,
            SERVICE_SID_TYPE_UNRESTRICTED_VALUE,
            true,
            4242,
            true,
            true,
        );
        assert!(verified);
        assert!(service_identity_is_verified(true, SERVICE_SID_TYPE_RESTRICTED, true, 4242, true, true));
        assert!(!service_identity_is_verified(false, 1, true, 4242, true, true));
        assert!(!service_identity_is_verified(true, 0, true, 4242, true, true));
        assert!(!service_identity_is_verified(true, 1, false, 4242, true, true));
        assert!(!service_identity_is_verified(true, 1, true, 0, true, true));
        assert!(!service_identity_is_verified(true, 1, true, 4242, false, true));
        assert!(!service_identity_is_verified(true, 1, true, 4242, true, false));
    }

    fn sample_readiness(fixed_wfp_readback: FixedWfpReadback) -> Readiness {
        Readiness {
            supported_architecture: true,
            native_api_available: fixed_wfp_readback != FixedWfpReadback::Failed,
            fixed_wfp_readback,
            principal: None,
            provider_service: None,
            gate_service: None,
            gate_handoff_verified: false,
            target_launcher_verified: false,
        }
    }

    #[test]
    fn unreadable_or_present_wfp_objects_keep_inspect_and_start_in_recovery() {
        for fixed_wfp_readback in [FixedWfpReadback::Failed, FixedWfpReadback::ObjectsPresent] {
            let readiness = sample_readiness(fixed_wfp_readback);
            assert!(matches!(
                inspection_result(&readiness),
                BackendResult::Recovery { cleanup_confirmed: false, .. }
            ));
            assert!(matches!(
                start_readiness_result(&readiness),
                Some(BackendResult::Recovery { cleanup_confirmed: false, .. })
            ));
        }
    }

    #[test]
    fn lock_does_not_claim_cleanup_when_wfp_state_is_unknown() {
        let result = lock_readiness_result(&sample_readiness(FixedWfpReadback::Failed));
        assert!(matches!(
            result,
            BackendResult::Recovery { cleanup_confirmed: false, .. }
        ));
    }

    #[test]
    fn lock_can_confirm_no_owned_wfp_objects_only_after_readback() {
        let result = lock_readiness_result(&sample_readiness(FixedWfpReadback::AllMissing));
        assert!(matches!(
            result,
            BackendResult::Unavailable { cleanup_confirmed: true, .. }
        ));
        assert!(matches!(
            lock_readiness_result(&sample_readiness(FixedWfpReadback::NotRead)),
            BackendResult::Recovery { cleanup_confirmed: false, .. }
        ));
    }

    #[test]
    fn transaction_adds_fixed_objects_in_one_transaction_and_reads_back() {
        let plan = ready_plan();
        // The production readiness constant is deliberately false; unit fixtures
        // test the transaction primitive without opening the native WFP engine.
        let result = install_for_fixture(&plan, FakeState::default(), || true);
        assert_eq!(result.status, DenyInstallStatus::CommittedExactReadback);
        assert!(result.deny_may_be_installed);
    }

    fn install_for_fixture(plan: &DenyPlan, state: FakeState, current: impl Fn() -> bool) -> DenyInstallResult {
        install_transaction(&FakeFactory(Arc::new(Mutex::new(state))), plan, current)
    }

    #[test]
    fn production_write_gate_refuses_before_opening_any_session() {
        let plan = ready_plan();
        let state = Arc::new(Mutex::new(FakeState::default()));
        let result = install_persistent_deny(
            &FakeFactory(state.clone()),
            &plan,
            WriteReadiness::offline_fixture(),
            || true,
        );
        assert_eq!(result.status, DenyInstallStatus::NotReady);
        assert!(state.lock().unwrap().calls.is_empty());
    }

    #[test]
    fn conflict_aborts_and_never_overwrites_fixed_guid_objects() {
        let plan = ready_plan();
        let mut state = FakeState::default();
        state.objects.provider = Some(ProviderReadback {
            key: PROVIDER_KEY, flags: PERSISTENT, display_name: "foreign object".into(),
            service_name: Some(plan.provider_service_name.clone()),
        });
        let result = install_for_fixture(&plan, state, || true);
        assert_eq!(result.status, DenyInstallStatus::Conflict);
    }

    #[test]
    fn failed_add_aborts_and_closes_while_preserving_both_failures() {
        let plan = ready_plan();
        let state = FakeState { fail_add: Some("v4"), abort_status: 5, close_status: 6, ..FakeState::default() };
        let result = install_for_fixture(&plan, state, || true);
        assert_eq!(result.status, DenyInstallStatus::EngineCloseUnconfirmed);
        assert_eq!(result.abort_status, Some(5));
        assert_eq!(result.close_status, Some(6));
        assert!(result.deny_may_be_installed);
    }

    #[test]
    fn uncertain_commit_never_deletes_possible_deny() {
        let plan = ready_plan();
        let state = FakeState { commit_status: 5, ..FakeState::default() };
        let result = install_for_fixture(&plan, state, || true);
        assert_eq!(result.status, DenyInstallStatus::CommitOutcomeUnknown);
        assert!(result.deny_may_be_installed);
    }

    #[test]
    fn disabled_readback_keeps_possible_deny_and_refuses_readiness() {
        let plan = ready_plan();
        let state = FakeState { unverified_after_commit: true, ..FakeState::default() };
        let result = install_for_fixture(&plan, state, || true);
        assert_eq!(result.status, DenyInstallStatus::CommittedReadbackUnverified);
        assert!(result.deny_may_be_installed);
    }

    #[test]
    fn cancellation_before_commit_aborts_the_transaction() {
        let plan = ready_plan();
        let calls = Arc::new(AtomicU64::new(0));
        let result = install_for_fixture(&plan, FakeState::default(), || calls.fetch_add(1, Ordering::SeqCst) < 5);
        assert!(matches!(result.status, DenyInstallStatus::Cancelled | DenyInstallStatus::CommittedExactReadback));
    }
}
