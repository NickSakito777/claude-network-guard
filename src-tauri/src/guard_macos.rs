// [INPUT]: Typed Guard actions and the headless LuLu C ABI.
// [OUTPUT]: Closed recovery, guarded launches, call-local errors and bounded cleanup/inventory/readback diagnostics.
// [POS]: macOS executor; Rust owns the session, Swift owns the actual gate and process identity.
// [PROTOCOL]: Keep construction inert and run native checks only for explicit actions.
use crate::guard::{ActionToken, Backend, BackendAction, BackendResult, PortObservation, VerifiedEnforcement};
use std::collections::HashSet;
use std::ffi::{c_char, c_void, CString};
use std::net::IpAddr;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Each GUI target has a distinct Gate endpoint and a matching sealed LuLu rule.
// The service stays unavailable until the two-entry deployment is prepared.
const TARGETS: [&str; 2] = ["claude", "sunbrowser"];
const RENEW_INTERVAL: Duration = Duration::from_millis(800);
const FULL_CHECK_INTERVAL: Duration = Duration::from_secs(20);
const FAULT_REASON: &str = "Native protection changed; recover the locked session.";

type FaultCallback = Option<extern "C" fn(*mut c_void)>;
type CurrentCallback = Option<extern "C" fn(*mut c_void) -> i32>;

extern "C" {
    fn guard_lulu_port_observation(output: *mut c_char, capacity: usize) -> i32;
    fn guard_lulu_create(callback: FaultCallback, context: *mut c_void, output: *mut *mut c_void) -> i32;
    fn guard_lulu_destroy(handle: *mut c_void);
    fn guard_lulu_prepare(handle: *mut c_void, current: CurrentCallback, context: *mut c_void,
        error: *mut c_char, error_capacity: usize) -> i32;
    fn guard_lulu_full_check(handle: *mut c_void, through_entry: i32, current: CurrentCallback,
        context: *mut c_void, fingerprint: *mut c_char, upstream: *mut c_char,
        ingress: *mut c_char, ip: *mut c_char, network_generation: *mut u64,
        checked_at_ns: *mut u64, observed_at_ms: *mut i64, error: *mut c_char, error_capacity: usize) -> i32;
    fn guard_lulu_renew(handle: *mut c_void, lease_generation: u64, expected_network_generation: u64,
        fingerprint: *const c_char, upstream: *const c_char, ingress: *const c_char,
        current: CurrentCallback, context: *mut c_void, error: *mut c_char, error_capacity: usize) -> i32;
    fn guard_lulu_open(handle: *mut c_void, lease_generation: u64, target: *const c_char,
        current: CurrentCallback, context: *mut c_void, error: *mut c_char, error_capacity: usize) -> i32;
    fn guard_lulu_launch(handle: *mut c_void, target: *const c_char, lease_generation: u64,
        current: CurrentCallback, context: *mut c_void, error: *mut c_char, error_capacity: usize) -> i32;
    fn guard_lulu_emergency_lock(handle: *mut c_void);
    fn guard_lulu_finish_lock(handle: *mut c_void, confirmed: *mut i32, bound: *mut i32,
        open: *mut i32, pairs: *mut i32, owned: *mut i32, pending: *mut i32,
        diagnostic: *mut c_char, diagnostic_capacity: usize) -> i32;
    fn guard_lulu_recover_observation(handle: *mut c_void, fingerprint: *mut c_char,
        upstream: *mut c_char, ingress: *mut c_char, ip: *mut c_char,
        network_generation: *mut u64, checked_at_ns: *mut u64, observed_at_ms: *mut i64,
        error: *mut c_char, error_capacity: usize) -> i32;
    fn guard_lulu_readback(handle: *mut c_void, bound: *mut i32, open: *mut i32,
        pairs: *mut i32, owned: *mut i32, pending: *mut i32) -> i32;
}

pub(crate) fn backend() -> Arc<dyn Backend> {
    Arc::new(MacBackend { shared: Arc::new(Shared::new()) })
}

#[derive(Clone, Debug)]
struct NativeError {
    code: i32,
    reason: String,
}

struct NativeHandle {
    raw: NonNull<c_void>,
    faults: Box<AtomicU64>,
}

// The Swift bridge serializes its service state. Every FFI caller owns an Arc,
// and destroy synchronously fences the callback before `faults` is released.
unsafe impl Send for NativeHandle {}
unsafe impl Sync for NativeHandle {}

extern "C" fn fault_callback(context: *mut c_void) {
    if let Some(counter) = unsafe { (context as *const AtomicU64).as_ref() } {
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

impl NativeHandle {
    fn create() -> Result<Arc<Self>, NativeError> {
        let faults = Box::new(AtomicU64::new(0));
        let mut raw = std::ptr::null_mut();
        let code = unsafe {
            guard_lulu_create(Some(fault_callback), (&*faults as *const AtomicU64).cast_mut().cast(), &mut raw)
        };
        let Some(raw) = NonNull::new(raw) else {
            return Err(NativeError { code, reason: "native_bridge_creation_failed".into() });
        };
        if code != 0 {
            unsafe { guard_lulu_destroy(raw.as_ptr()) };
            return Err(NativeError { code, reason: "native_bridge_creation_failed".into() });
        }
        Ok(Arc::new(Self { raw, faults }))
    }

    fn fault_serial(&self) -> u64 { self.faults.load(Ordering::SeqCst) }

    fn status(code: i32, buffer: &[c_char]) -> Result<(), NativeError> {
        if code == 0 { return Ok(()); }
        let reason = buffer_bytes(buffer)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).unwrap_or_default();
        Err(NativeError { code,
            reason: if reason.is_empty() { format!("native_status_{code}") } else { reason } })
    }

    fn call(operation: impl FnOnce(*mut c_char, usize) -> i32) -> Result<(), NativeError> {
        let mut error = [0 as c_char; 1_024];
        let code = operation(error.as_mut_ptr(), error.len());
        Self::status(code, &error)
    }

    fn prepare(&self, current: &CurrentCheck<'_>) -> Result<(), NativeError> {
        Self::call(|error, capacity| unsafe {
            guard_lulu_prepare(self.raw.as_ptr(), Some(current_callback), current.context(), error, capacity)
        })
    }

    fn full_check(&self, through_entry: bool, current: &CurrentCheck<'_>) -> Result<Stamp, NativeError> {
        let mut output = StampOutput::default();
        Self::call(|error, capacity| unsafe {
            guard_lulu_full_check(self.raw.as_ptr(), i32::from(through_entry), Some(current_callback),
                current.context(), output.fingerprint.as_mut_ptr(), output.upstream.as_mut_ptr(),
                output.ingress.as_mut_ptr(), output.ip.as_mut_ptr(), &mut output.network_generation,
                &mut output.checked_at_ns, &mut output.observed_at_ms, error, capacity)
        })?;
        output.stamp().ok_or_else(|| NativeError { code: 4, reason: "invalid_native_check_stamp".into() })
    }

    fn recover_observation(&self) -> Result<Stamp, NativeError> {
        let mut output = StampOutput::default();
        Self::call(|error, capacity| unsafe {
            guard_lulu_recover_observation(self.raw.as_ptr(), output.fingerprint.as_mut_ptr(),
                output.upstream.as_mut_ptr(), output.ingress.as_mut_ptr(), output.ip.as_mut_ptr(),
                &mut output.network_generation, &mut output.checked_at_ns, &mut output.observed_at_ms, error, capacity)
        })?;
        output.stamp().ok_or_else(|| NativeError { code: 4, reason: "invalid_native_check_stamp".into() })
    }

    fn renew(&self, generation: u64, stamp: &Stamp, current: &CurrentCheck<'_>) -> Result<(), NativeError> {
        Self::call(|error, capacity| unsafe {
            guard_lulu_renew(self.raw.as_ptr(), generation, stamp.network_generation,
                stamp.fingerprint.as_ptr(), stamp.upstream.as_ptr(), stamp.ingress.as_ptr(),
                Some(current_callback), current.context(), error, capacity)
        })
    }

    fn open(&self, generation: u64, target: &str, current: &CurrentCheck<'_>) -> Result<(), NativeError> {
        let target = CString::new(target).expect("fixed target contains no NUL");
        Self::call(|error, capacity| unsafe {
            guard_lulu_open(self.raw.as_ptr(), generation, target.as_ptr(), Some(current_callback), current.context(), error, capacity)
        })
    }

    fn launch(&self, target: &'static str, generation: u64, current: &CurrentCheck<'_>) -> Result<(), NativeError> {
        let target = CString::new(target).expect("fixed target contains no NUL");
        Self::call(|error, capacity| unsafe {
            guard_lulu_launch(self.raw.as_ptr(), target.as_ptr(), generation,
                Some(current_callback), current.context(), error, capacity)
        })
    }

    fn emergency_lock(&self) { unsafe { guard_lulu_emergency_lock(self.raw.as_ptr()) } }

    fn finish_lock(&self) -> Result<Readback, NativeError> {
        let mut state = [0_i32; 6];
        let mut diagnostic = [0 as c_char; 512];
        let code = unsafe {
            guard_lulu_finish_lock(self.raw.as_ptr(), &mut state[0], &mut state[1], &mut state[2],
                &mut state[3], &mut state[4], &mut state[5], diagnostic.as_mut_ptr(), diagnostic.len())
        };
        Self::status(code, &diagnostic)?;
        let reason = buffer_bytes(&diagnostic).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).unwrap_or_default();
        Ok(Readback::from_finish(state, reason))
    }

    fn readback(&self) -> Result<Readback, NativeError> {
        let mut state = [0_i32; 5];
        let code = unsafe {
            guard_lulu_readback(self.raw.as_ptr(), &mut state[0], &mut state[1], &mut state[2],
                &mut state[3], &mut state[4])
        };
        Self::status(code, &[])?;
        Ok(Readback::from_readback(state))
    }
}

impl Drop for NativeHandle {
    fn drop(&mut self) { unsafe { guard_lulu_destroy(self.raw.as_ptr()) } }
}

struct CurrentCheck<'a> {
    token: Option<&'a ActionToken>,
    epoch: &'a AtomicU64,
    expected_epoch: u64,
    faults: &'a AtomicU64,
    expected_faults: u64,
}

impl CurrentCheck<'_> {
    fn valid(&self) -> bool {
        self.epoch.load(Ordering::SeqCst) == self.expected_epoch
            && self.faults.load(Ordering::SeqCst) == self.expected_faults
            && self.token.map_or(true, ActionToken::is_current)
    }

    fn invalidation_key(&self) -> Option<&'static str> {
        if self.faults.load(Ordering::SeqCst) != self.expected_faults {
            Some("native_fault_during_operation")
        } else if self.token.is_some_and(|token| !token.is_current()) {
            Some("guard_action_cancelled")
        } else if self.epoch.load(Ordering::SeqCst) != self.expected_epoch {
            Some("guard_session_invalidated")
        } else {
            None
        }
    }

    fn explain(&self, mut error: NativeError) -> NativeError {
        if matches!(error.reason.as_str(), "operation_invalidated" | "prepare_invalidated"
            | "recovery_invalidated" | "recovery_readback_changed") {
            if let Some(key) = self.invalidation_key() { error.reason = key.into(); }
        }
        error
    }

    fn context(&self) -> *mut c_void { (self as *const Self).cast_mut().cast() }
}

extern "C" fn current_callback(context: *mut c_void) -> i32 {
    // Every Swift ABI call waits for its async work before returning; the
    // borrowed stack context therefore remains live for every callback.
    unsafe { (context as *const CurrentCheck<'_>).as_ref() }
        .is_some_and(CurrentCheck::valid) as i32
}

#[derive(Clone)]
struct Stamp {
    fingerprint: CString,
    upstream: CString,
    ingress: CString,
    network_generation: u64,
    observed_ip: String,
    observed_at_ms: i64,
}

impl Stamp {
    fn same_environment(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint && self.upstream == other.upstream
            && self.ingress == other.ingress && self.network_generation == other.network_generation
            && self.observed_ip == other.observed_ip
    }

    fn proof(&self) -> VerifiedEnforcement {
        VerifiedEnforcement {
            protected_targets: available_targets(),
            observed_ip: Some(self.observed_ip.clone()),
            observed_at: Some(iso_utc(self.observed_at_ms)),
        }
    }
}

struct StampOutput {
    fingerprint: [c_char; 65],
    upstream: [c_char; 65],
    ingress: [c_char; 65],
    ip: [c_char; 64],
    network_generation: u64,
    checked_at_ns: u64,
    observed_at_ms: i64,
}

impl Default for StampOutput {
    fn default() -> Self {
        Self { fingerprint: [0; 65], upstream: [0; 65], ingress: [0; 65], ip: [0; 64],
            network_generation: 0, checked_at_ns: 0, observed_at_ms: 0 }
    }
}

impl StampOutput {
    fn stamp(&self) -> Option<Stamp> {
        fn digest(bytes: &[c_char; 65]) -> Option<CString> {
            let value = buffer_bytes(bytes)?;
            (value.len() == 64 && value.iter().all(u8::is_ascii_hexdigit))
                .then(|| CString::new(value).ok()).flatten()
        }
        let ip_bytes = buffer_bytes(&self.ip)?;
        let ip = std::str::from_utf8(&ip_bytes).ok()?;
        let now_ms = unix_ms()?;
        if self.checked_at_ns == 0
            || self.observed_at_ms <= 0 || self.observed_at_ms > now_ms
            || now_ms - self.observed_at_ms > 60_000 || ip.parse::<IpAddr>().is_err() {
            return None;
        }
        Some(Stamp {
            fingerprint: digest(&self.fingerprint)?,
            upstream: digest(&self.upstream)?,
            ingress: digest(&self.ingress)?,
            network_generation: self.network_generation,
            observed_ip: ip.into(), observed_at_ms: self.observed_at_ms,
        })
    }
}

fn buffer_bytes(buffer: &[c_char]) -> Option<Vec<u8>> {
    let end = buffer.iter().position(|byte| *byte == 0)?;
    Some(buffer[..end].iter().map(|byte| *byte as u8).collect())
}

fn unix_ms() -> Option<i64> {
    let value = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_millis();
    i64::try_from(value).ok()
}

fn iso_utc(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let day_ms = ms.rem_euclid(86_400_000);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        day_ms / 3_600_000, day_ms / 60_000 % 60,
        day_ms / 1_000 % 60, day_ms % 1_000)
}

#[derive(Clone)]
struct Readback {
    confirmed: bool,
    bound: bool,
    open: bool,
    pairs: i32,
    owned: bool,
    pending: bool,
    cleanup_diagnostic: String,
}

impl Readback {
    fn from_finish(value: [i32; 6], cleanup_diagnostic: String) -> Self {
        Self { confirmed: value[0] == 1, bound: value[1] == 1, open: value[2] == 1,
            pairs: value[3], owned: value[4] == 1, pending: value[5] == 1, cleanup_diagnostic }
    }

    fn from_readback(value: [i32; 5]) -> Self {
        Self { confirmed: false, bound: value[0] == 1, open: value[1] == 1,
            pairs: value[2], owned: value[3] == 1, pending: value[4] == 1, cleanup_diagnostic: String::new() }
    }

    fn locked(&self) -> bool { self.bound && self.owned && !self.open && self.pairs == 0 && !self.pending }
    fn active(&self) -> bool { self.bound && self.owned && self.open && !self.pending }
    fn cleanup(&self) -> bool { self.confirmed && !self.open && self.pairs == 0 && !self.pending }
}

fn with_cleanup_diagnostic(reason: &str, cleanup: &Result<Readback, NativeError>) -> String {
    let diagnostic = match cleanup {
        Ok(value) if value.cleanup() => return reason.into(),
        Ok(value) => {
            let (key, evidence) = value.cleanup_diagnostic.split_once('\n')
                .map_or((value.cleanup_diagnostic.as_str(), None), |(key, evidence)| (key, Some(evidence)));
            let mut diagnostic = format!("Cleanup diagnostic: {}; confirmed={}, bound={}, open={}, pairs={}, owned={}, pending={}.",
                if key.is_empty() { "cleanup_reason_unavailable" } else { key },
                i32::from(value.confirmed), i32::from(value.bound), i32::from(value.open), value.pairs,
                i32::from(value.owned), i32::from(value.pending));
            if let Some(evidence) = evidence { diagnostic.push('\n'); diagnostic.push_str(evidence); }
            diagnostic
        },
        Err(error) => format!("Cleanup diagnostic unavailable: {}.", error.reason),
    };
    // Keep the first failing cleanup when a recovery attempt performs cleanup again.
    if reason.contains("\nCleanup diagnostic") { reason.chars().take(1_024).collect() }
    else {
        let diagnostic: String = diagnostic.chars().take(768).collect();
        let keep = 1_024_usize.saturating_sub(diagnostic.chars().count() + 1);
        let reason: String = reason.chars().take(keep).collect();
        format!("{reason}\n{diagnostic}")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode { Cold, Locked, Active, Recovery }

struct State {
    handle: Option<Arc<NativeHandle>>,
    mode: Mode,
    stamp: Option<Stamp>,
    permit_generation: u64,
    owned_targets: HashSet<String>,
    accepted_faults: u64,
    reason: String,
    cleanup_confirmed: bool,
    lock_pending: bool,
    starting: bool,
}

impl State {
    fn new() -> Self {
        Self { handle: None, mode: Mode::Cold, stamp: None, permit_generation: 0,
            owned_targets: HashSet::new(), accepted_faults: 0,
            reason: "Protection is not prepared. Use Prepare / recover before starting.".into(),
            cleanup_confirmed: true, lock_pending: false, starting: false }
    }

    fn faulted(&self) -> bool {
        self.handle.as_ref().is_some_and(|handle| handle.fault_serial() != self.accepted_faults)
    }

    fn result(&self) -> BackendResult {
        let available = if self.stamp.is_some() { available_targets() } else { HashSet::new() };
        let owned = self.owned_targets.clone();
        if self.faulted() {
            let reason = if self.mode == Mode::Recovery && !self.reason.is_empty() { &self.reason } else { FAULT_REASON };
            return BackendResult::Recovery { reason: reason.into(),
                available_targets: available, owned_workloads: owned, cleanup_confirmed: false };
        }
        match self.mode {
            Mode::Cold => BackendResult::Unavailable { reason: self.reason.clone(),
                available_targets: HashSet::new(), owned_workloads: owned,
                cleanup_confirmed: self.cleanup_confirmed },
            Mode::Recovery => BackendResult::Recovery { reason: self.reason.clone(),
                available_targets: available, owned_workloads: owned,
                cleanup_confirmed: self.cleanup_confirmed },
            Mode::Locked => BackendResult::Locked { proof: self.stamp.as_ref().expect("locked proof").proof(),
                available_targets: available, owned_workloads: owned,
                cleanup_confirmed: self.cleanup_confirmed },
            Mode::Active => BackendResult::Active { proof: self.stamp.as_ref().expect("active proof").proof(),
                available_targets: available, owned_workloads: owned,
                cleanup_confirmed: self.cleanup_confirmed },
        }
    }

    fn adopt_start(&mut self, target: &str, stamp: Stamp, generation: u64) {
        self.stamp = Some(stamp);
        self.permit_generation = generation;
        self.owned_targets.insert(target.into());
        self.mode = Mode::Active;
        self.reason.clear();
        self.cleanup_confirmed = false;
        self.starting = false;
    }
}

fn available_targets() -> HashSet<String> { TARGETS.iter().map(|value| (*value).into()).collect() }

struct Shared {
    state: Mutex<State>,
    session_epoch: AtomicU64,
    permit_transition: Mutex<()>,
    full_check_call: Mutex<()>,
    cleanup_call: Mutex<()>,
    renew_worker_started: AtomicBool,
    full_worker_started: AtomicBool,
}

impl Shared {
    fn new() -> Self {
        Self { state: Mutex::new(State::new()), session_epoch: AtomicU64::new(0),
            permit_transition: Mutex::new(()), full_check_call: Mutex::new(()),
            cleanup_call: Mutex::new(()), renew_worker_started: AtomicBool::new(false),
            full_worker_started: AtomicBool::new(false) }
    }

    fn result(&self) -> BackendResult { self.state.lock().unwrap().result() }

    fn current<'a>(&'a self, handle: &'a NativeHandle, epoch: u64, faults: u64,
                   token: Option<&'a ActionToken>) -> CurrentCheck<'a> {
        CurrentCheck { token, epoch: &self.session_epoch, expected_epoch: epoch,
            faults: &handle.faults, expected_faults: faults }
    }

    fn finish(&self, handle: &NativeHandle) -> Result<Readback, NativeError> {
        let _lease = self.cleanup_call.lock().unwrap();
        handle.finish_lock()
    }

    fn cleanup_observed_fault(&self, epoch: u64, handle: Arc<NativeHandle>) {
        let result = self.finish(&handle);
        let cleanup = result.as_ref().is_ok_and(Readback::cleanup);
        let mut state = self.state.lock().unwrap();
        if self.session_epoch.load(Ordering::SeqCst) != epoch { return; }
        if state.mode != Mode::Recovery { state.reason = FAULT_REASON.into(); }
        state.reason = with_cleanup_diagnostic(&state.reason, &result);
        state.mode = Mode::Recovery;
        state.lock_pending = false;
        state.starting = false;
        state.cleanup_confirmed = cleanup;
        if cleanup {
            state.owned_targets.clear();
            state.accepted_faults = handle.fault_serial();
        }
    }

    fn failure(&self, epoch: u64, reason: String, attempted: Option<&str>) -> BackendResult {
        if !claim_epoch(&self.session_epoch, epoch) { return self.result(); }
        let handle = {
            let mut state = self.state.lock().unwrap();
            state.mode = Mode::Recovery;
            state.reason = reason;
            state.cleanup_confirmed = false;
            state.starting = false;
            if let Some(target) = attempted { state.owned_targets.insert(target.into()); }
            state.handle.clone()
        };
        if let Some(handle) = handle {
            handle.emergency_lock();
            let cleanup = self.finish(&handle);
            let mut state = self.state.lock().unwrap();
            if self.session_epoch.load(Ordering::SeqCst) == epoch.wrapping_add(1) {
                state.reason = with_cleanup_diagnostic(&state.reason, &cleanup);
                if let Ok(readback) = cleanup {
                    if readback.cleanup() {
                        state.owned_targets.clear();
                        state.cleanup_confirmed = true;
                        state.accepted_faults = handle.fault_serial();
                    }
                }
            }
        }
        self.result()
    }

    fn workers(self: &Arc<Self>) -> Result<(), String> {
        if !self.renew_worker_started.swap(true, Ordering::SeqCst) {
            let renew: Weak<Self> = Arc::downgrade(self);
            if let Err(error) = thread::Builder::new().name("guard-lulu-renew".into()).spawn(move || loop {
                thread::sleep(RENEW_INTERVAL);
                let Some(shared) = renew.upgrade() else { break };
                shared.renew_once();
            }) {
                self.renew_worker_started.store(false, Ordering::SeqCst);
                return Err(format!("renewal_worker_unavailable_{error}"));
            }
        }
        if !self.full_worker_started.swap(true, Ordering::SeqCst) {
            let full: Weak<Self> = Arc::downgrade(self);
            if let Err(error) = thread::Builder::new().name("guard-lulu-full-check".into()).spawn(move || loop {
                thread::sleep(FULL_CHECK_INTERVAL);
                let Some(shared) = full.upgrade() else { break };
                shared.full_check_once();
            }) {
                self.full_worker_started.store(false, Ordering::SeqCst);
                return Err(format!("full_check_worker_unavailable_{error}"));
            }
        }
        Ok(())
    }

    fn active_lease(&self) -> Option<(Arc<NativeHandle>, Stamp, u64, u64, u64)> {
        let state = self.state.lock().unwrap();
        if state.mode != Mode::Active || state.lock_pending || state.faulted() { return None; }
        Some((state.handle.as_ref()?.clone(), state.stamp.as_ref()?.clone(),
            state.permit_generation, state.accepted_faults,
            self.session_epoch.load(Ordering::SeqCst)))
    }

    fn close_latched_fault(&self) {
        let epoch = {
            let state = self.state.lock().unwrap();
            needs_fault_cleanup(state.mode, state.lock_pending, state.faulted())
                .then(|| self.session_epoch.load(Ordering::SeqCst))
        };
        if let Some(epoch) = epoch {
            self.failure(epoch, FAULT_REASON.into(), None);
        }
    }

    fn renew_once(&self) {
        self.close_latched_fault();
        let _transition = self.permit_transition.lock().unwrap();
        let Some((handle, stamp, generation, faults, epoch)) = self.active_lease() else { return };
        let current = self.current(&handle, epoch, faults, None);
        let result = handle.renew(generation, &stamp, &current);
        if let Err(error) = result {
            if current.valid() { self.failure(epoch, format!("Lease renewal failed: {}", error.reason), None); }
        }
    }

    fn full_check_once(&self) {
        self.close_latched_fault();
        let _serial = self.full_check_call.lock().unwrap();
        let (handle, prior, _, faults, epoch) = match self.active_lease() {
            Some(value) => value,
            None => return,
        };
        if self.state.lock().unwrap().starting { return; }
        let current = self.current(&handle, epoch, faults, None);
        match handle.full_check(true, &current) {
            Ok(stamp) if current.valid() && stamp.same_environment(&prior) => {
                let mut state = self.state.lock().unwrap();
                if state.mode == Mode::Active && !state.lock_pending && !state.starting
                    && self.session_epoch.load(Ordering::SeqCst) == epoch && !state.faulted() {
                    state.stamp = Some(stamp);
                }
            }
            Ok(_) => { if current.valid() { self.failure(epoch, "Full verification changed the protected environment.".into(), None); } }
            Err(error) => { if current.valid() { self.failure(epoch, format!("Full verification failed: {}", error.reason), None); } }
        }
    }
}

struct MacBackend { shared: Arc<Shared> }

impl MacBackend {
    fn recover(&self, token: ActionToken) -> BackendResult {
        let shared = &self.shared;
        let epoch = shared.session_epoch.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
        let existing = {
            let mut state = shared.state.lock().unwrap();
            state.lock_pending = true;
            state.starting = false;
            state.handle.clone()
        };
        let handle = match existing {
            Some(handle) => {
                handle.emergency_lock();
                match shared.finish(&handle) {
                    Ok(readback) if readback.cleanup() => {
                        let mut state = shared.state.lock().unwrap();
                        state.owned_targets.clear();
                        state.cleanup_confirmed = true;
                    }
                    result => return self.recover_failed(epoch, Some(handle),
                        NativeError { code: 2, reason: with_cleanup_diagnostic("native_cleanup_unconfirmed", &result) }),
                }
                handle
            }
            None => match NativeHandle::create() {
                Ok(handle) => {
                    shared.state.lock().unwrap().handle = Some(handle.clone());
                    handle
                }
                Err(error) => return self.recover_failed(epoch, None, error),
            },
        };
        let faults = handle.fault_serial();
        let current = shared.current(&handle, epoch, faults, Some(&token));
        let result = (|| {
            let _serial = shared.full_check_call.lock().unwrap();
            let readback = handle.readback()?;
            let stamp = if readback.bound {
                if !readback.locked() {
                    return Err(NativeError { code: 2, reason: "recovery_gate_not_locked".into() });
                }
                handle.recover_observation()?
            } else {
                handle.prepare(&current)?;
                handle.full_check(false, &current)?
            };
            let readback = handle.readback()?;
            if !current.valid() || !readback.locked() {
                return Err(NativeError { code: 2, reason: "recovery_readback_changed".into() });
            }
            Ok(stamp)
        })();
        match result {
            Ok(stamp) => {
                let mut state = shared.state.lock().unwrap();
                if !current.valid() { drop(state); return self.recover_failed(epoch, Some(handle.clone()),
                    current.explain(NativeError { code: 2, reason: "recovery_invalidated".into() })); }
                state.mode = Mode::Locked;
                state.stamp = Some(stamp);
                state.accepted_faults = faults;
                state.owned_targets.clear();
                state.cleanup_confirmed = true;
                state.lock_pending = false;
                state.reason.clear();
                state.result()
            }
            Err(error) => self.recover_failed(epoch, Some(handle.clone()), current.explain(error)),
        }
    }

    fn recover_failed(&self, epoch: u64, handle: Option<Arc<NativeHandle>>, error: NativeError) -> BackendResult {
        let shared = &self.shared;
        let mut cleanup = handle.is_none();
        let mut reason = format!("Preparation failed: {}", error.reason);
        if let Some(handle) = handle {
            handle.emergency_lock();
            let result = shared.finish(&handle);
            cleanup = result.as_ref().is_ok_and(Readback::cleanup);
            reason = with_cleanup_diagnostic(&reason, &result);
        }
        let mut state = shared.state.lock().unwrap();
        if shared.session_epoch.load(Ordering::SeqCst) != epoch { return state.result(); }
        if cleanup {
            state.owned_targets.clear();
            if let Some(handle) = state.handle.as_ref() { state.accepted_faults = handle.fault_serial(); }
        }
        state.cleanup_confirmed = cleanup;
        state.mode = if error.code == 1 && cleanup { Mode::Cold } else { Mode::Recovery };
        state.reason = reason;
        state.stamp = None;
        state.lock_pending = false;
        state.result()
    }

    fn start(&self, target: &'static str, token: ActionToken) -> BackendResult {
        if !TARGETS.contains(&target) { return self.shared.result(); }
        let shared = &self.shared;
        {
            let state = shared.state.lock().unwrap();
            if state.mode == Mode::Active && state.owned_targets.contains(target)
                && !state.lock_pending && !state.faulted() {
                drop(state);
                return self.inspect();
            }
        }
        let (handle, prior, was_active, faults, epoch, prior_generation) = {
            let mut state = shared.state.lock().unwrap();
            if !matches!(state.mode, Mode::Locked | Mode::Active) || state.lock_pending || state.faulted() {
                return state.result();
            }
            state.starting = true;
            (state.handle.as_ref().expect("prepared handle").clone(),
                state.stamp.as_ref().expect("prepared stamp").clone(), state.mode == Mode::Active,
                state.accepted_faults, shared.session_epoch.load(Ordering::SeqCst), state.permit_generation)
        };
        let current = shared.current(&handle, epoch, faults, Some(&token));
        let stamp = {
            let _serial = shared.full_check_call.lock().unwrap();
            handle.full_check(was_active, &current)
        };
        let stamp = match stamp {
            Ok(stamp) if current.valid() && stamp.same_environment(&prior) => stamp,
            Ok(_) => return shared.failure(epoch, "Start verification changed the protected environment.".into(), None),
            Err(error) => return shared.failure(epoch, format!("Start verification failed: {}", error.reason), None),
        };
        // This short transition excludes an old-generation renewal from racing
        // the new permit. Emergency lock never waits on this mutex.
        let generation = token.generation().max(prior_generation.saturating_add(1));
        {
            let _transition = shared.permit_transition.lock().unwrap();
            if !current.valid() { return shared.failure(epoch, "Start was cancelled.".into(), None); }
            if let Err(error) = handle.open(generation, target, &current) {
                return shared.failure(epoch, format!("Opening protection failed: {}", error.reason), None);
            }
            let mut state = shared.state.lock().unwrap();
            if !current.valid() { drop(state); return shared.failure(epoch, "Start was cancelled.".into(), None); }
            state.permit_generation = generation;
            state.stamp = Some(stamp.clone());
            state.mode = Mode::Active;
            state.cleanup_confirmed = false;
        }
        if let Err(reason) = shared.workers() { return shared.failure(epoch, reason, None); }
        if !current.valid() { return shared.failure(epoch, "Start was cancelled.".into(), None); }
        if let Err(error) = handle.launch(target, generation, &current) {
            return shared.failure(epoch, format!("Protected launch failed: {}", error.reason), Some(target));
        }
        match handle.readback() {
            Ok(readback) if current.valid() && readback.active() => {
                let mut state = shared.state.lock().unwrap();
                if !current.valid() { drop(state); return shared.failure(epoch, "Start was cancelled.".into(), Some(target)); }
                state.adopt_start(target, stamp, generation);
                let result = state.result();
                drop(state);
                result
            }
            _ => shared.failure(epoch, "Protected launch readback failed.".into(), Some(target)),
        }
    }

    fn lock(&self, token: ActionToken) -> BackendResult {
        let shared = &self.shared;
        let handle = shared.state.lock().unwrap().handle.clone();
        let Some(handle) = handle else {
            let mut state = shared.state.lock().unwrap();
            state.mode = Mode::Cold;
            state.cleanup_confirmed = true;
            state.lock_pending = false;
            return state.result();
        };
        handle.emergency_lock();
        let cleanup = shared.finish(&handle);
        let mut state = shared.state.lock().unwrap();
        if !token.is_current() { return state.result(); }
        state.lock_pending = false;
        state.starting = false;
        match &cleanup {
            Ok(readback) if readback.cleanup() => {
                state.owned_targets.clear();
                state.cleanup_confirmed = true;
                if readback.locked() && state.stamp.is_some() && !state.faulted() {
                    state.mode = Mode::Locked;
                    state.reason.clear();
                } else {
                    state.mode = Mode::Cold;
                    state.stamp = None;
                    state.reason = "Protection is closed; prepare again before starting.".into();
                }
                state.accepted_faults = handle.fault_serial();
            }
            Ok(_) => {
                state.mode = Mode::Recovery;
                state.reason = with_cleanup_diagnostic("Native lock did not confirm workload cleanup.", &cleanup);
                state.cleanup_confirmed = false;
            }
            Err(error) => {
                state.mode = Mode::Recovery;
                state.reason = with_cleanup_diagnostic(&format!("Native lock failed: {}", error.reason), &cleanup);
                state.cleanup_confirmed = false;
            }
        }
        state.result()
    }

    fn inspect(&self) -> BackendResult {
        let shared = &self.shared;
        let (mode, handle, epoch) = {
            let state = shared.state.lock().unwrap();
            (state.mode, state.handle.clone(), shared.session_epoch.load(Ordering::SeqCst))
        };
        if !matches!(mode, Mode::Locked | Mode::Active) { return shared.result(); }
        let Some(handle) = handle else { return shared.result() };
        let readback = handle.readback();
        let sound = match (mode, readback) {
            (Mode::Locked, Ok(value)) => value.locked(),
            (Mode::Active, Ok(value)) => value.active(),
            _ => false,
        };
        if sound { shared.result() }
        else { shared.failure(epoch, "Native protection readback changed.".into(), None) }
    }
}

impl Backend for MacBackend {
    fn unavailable_target_reason(&self, target: &str) -> Option<&'static str> {
        match target {
            "ccbaga_browser" => Some("CCBaga Browser protected launch is not connected."),
            "claude_code" => Some("Claude Code CLI integration is deferred; candidate code is retained."),
            "mcp" => Some("MCP integration is deferred; child-process protection is not verified."),
            _ => None,
        }
    }
    fn port_observation(&self) -> Option<PortObservation> {
        // This ABI has no handle and cannot initialize LuLuServices or a Gate.
        // It reads only the existing root observer contract and current identity.
        let mut buffer = [0 as c_char; 2_048];
        let status = unsafe { guard_lulu_port_observation(buffer.as_mut_ptr(), buffer.len()) };
        if status != 0 { return None; }
        PortObservation::decode(&buffer_bytes(&buffer)?)
    }
    fn emergency_lock(&self) {
        let epoch = self.shared.session_epoch.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
        let (handle, needs_cleanup) = {
            let mut state = self.shared.state.lock().unwrap();
            // A status-triggered lock can race background cleanup; claim a
            // finish receipt here too so neither path leaves owned apps.
            let needs_cleanup = status_needs_cleanup(state.mode, state.faulted(), state.cleanup_confirmed);
            state.lock_pending = true;
            state.starting = false;
            (state.handle.clone(), needs_cleanup)
        };
        if let Some(handle) = handle {
            handle.emergency_lock();
            if needs_cleanup {
                let shared = self.shared.clone();
                thread::spawn(move || shared.cleanup_observed_fault(epoch, handle));
            }
        }
    }

    fn observe(&self) -> Option<BackendResult> {
        let state = self.shared.state.lock().unwrap();
        if state.lock_pending { return None; }
        if state.faulted() || state.mode == Mode::Recovery || state.mode == Mode::Active {
            Some(state.result())
        } else { None }
    }

    fn execute(&self, action: BackendAction, token: ActionToken) -> BackendResult {
        match action {
            BackendAction::Inspect => self.inspect(),
            BackendAction::Recover => self.recover(token),
            BackendAction::Lock => self.lock(token),
            BackendAction::Start(target) => self.start(target, token),
        }
    }
}

fn needs_fault_cleanup(mode: Mode, lock_pending: bool, faulted: bool) -> bool {
    matches!(mode, Mode::Locked | Mode::Active) && !lock_pending && faulted
}

fn status_needs_cleanup(mode: Mode, faulted: bool, cleanup_confirmed: bool) -> bool {
    !cleanup_confirmed && (faulted || mode == Mode::Recovery)
}

fn claim_epoch(current: &AtomicU64, expected: u64) -> bool {
    current.compare_exchange(expected, expected.wrapping_add(1),
        Ordering::SeqCst, Ordering::SeqCst).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp() -> Stamp {
        Stamp { fingerprint: CString::new("a".repeat(64)).unwrap(),
            upstream: CString::new("b".repeat(64)).unwrap(),
            ingress: CString::new("c".repeat(64)).unwrap(),
            network_generation: 4, observed_ip: "203.0.113.7".into(),
            observed_at_ms: 1_697_061_600_123 }
    }

    #[test]
    fn inert_construction_has_no_handle_or_targets() {
        let state = State::new();
        assert!(state.handle.is_none());
        assert!(matches!(state.result(), BackendResult::Unavailable { cleanup_confirmed: true, .. }));
    }

    #[test]
    fn starting_claude_does_not_claim_browser_ownership() {
        let mut state = State::new();
        state.adopt_start("claude", stamp(), 7);
        assert_eq!(state.permit_generation, 7);
        assert_eq!(state.owned_targets, HashSet::from(["claude".to_owned()]));
        assert_eq!(available_targets(), HashSet::from(["claude".to_owned(), "sunbrowser".to_owned()]));
        assert!(!state.owned_targets.contains("sunbrowser"));
        assert!(!available_targets().contains("claude_code"));
        assert!(matches!(state.result(), BackendResult::Active { .. }));
    }

    #[test]
    fn lease_epoch_is_independent_of_action_generation() {
        let epoch = AtomicU64::new(3);
        let faults = AtomicU64::new(0);
        let lease = CurrentCheck { token: None, epoch: &epoch, expected_epoch: 3,
            faults: &faults, expected_faults: 0 };
        assert!(lease.valid());
        // Completing or replacing a start action does not invalidate a live lease.
        assert!(lease.valid());
        epoch.fetch_add(1, Ordering::SeqCst);
        assert!(!lease.valid());
    }

    #[test]
    fn native_fault_latches_without_ffi_reentry() {
        let epoch = AtomicU64::new(2);
        let faults = AtomicU64::new(0);
        let current = CurrentCheck { token: None, epoch: &epoch, expected_epoch: 2,
            faults: &faults, expected_faults: 0 };
        assert_eq!(current_callback(current.context()), 1);
        fault_callback((&faults as *const AtomicU64).cast_mut().cast());
        assert_eq!(current_callback(current.context()), 0);
        assert_eq!(current.invalidation_key(), Some("native_fault_during_operation"));
        assert_eq!(current.explain(NativeError { code: 2, reason: "operation_invalidated".into() }).reason,
            "native_fault_during_operation");
        faults.store(0, Ordering::SeqCst);
        epoch.fetch_add(1, Ordering::SeqCst);
        assert_eq!(current.invalidation_key(), Some("guard_session_invalidated"));
    }

    #[test]
    fn fault_cleanup_is_claimed_once_even_if_status_and_worker_race() {
        let epoch = AtomicU64::new(9);
        assert!(needs_fault_cleanup(Mode::Active, false, true));
        assert!(claim_epoch(&epoch, 9));
        assert!(!claim_epoch(&epoch, 9));
        assert!(!needs_fault_cleanup(Mode::Active, true, true));
        assert!(!needs_fault_cleanup(Mode::Recovery, false, true));
        assert!(status_needs_cleanup(Mode::Active, true, false));
        assert!(status_needs_cleanup(Mode::Recovery, false, false));
        assert!(!status_needs_cleanup(Mode::Active, false, false));
        assert!(!status_needs_cleanup(Mode::Recovery, true, true));
    }

    #[test]
    fn utc_timestamp_keeps_public_observation_time() {
        assert_eq!(iso_utc(1_697_061_600_123), "2023-10-11T22:00:00.123Z");
    }

    #[test]
    fn ffi_handle_without_service_stays_unbound_and_disposes_cleanly() {
        // Real ABI smoke test; none of these calls initializes LuLuServices.
        let handle = NativeHandle::create().expect("allocate inert bridge");
        let state = handle.readback().expect("read inert bridge");
        assert!(!state.bound && !state.open && !state.owned && !state.pending);
        assert_eq!(state.pairs, 0);
        assert_eq!(handle.fault_serial(), 0);
        handle.emergency_lock();
        assert!(handle.finish_lock().expect("no owned scope to clean").cleanup());
        drop(handle);
    }

    #[cfg(guard_offline_e2e)]
    extern "C" {
        fn guard_lulu_offline_install(handle: *mut c_void, scenario: i32) -> i32;
        fn guard_lulu_offline_control(handle: *mut c_void, action: i32) -> i32;
    }

    #[cfg(guard_offline_e2e)]
    fn offline_fixture(scenario: i32) -> (Arc<Shared>, Arc<NativeHandle>) {
        let handle = NativeHandle::create().unwrap();
        assert_eq!(unsafe { guard_lulu_offline_install(handle.raw.as_ptr(), scenario) }, 0);
        let shared = Arc::new(Shared::new());
        {
            let mut state = shared.state.lock().unwrap();
            state.handle = Some(handle.clone());
            state.mode = Mode::Recovery;
            state.cleanup_confirmed = false;
            state.owned_targets.insert("claude".into());
        }
        (shared, handle)
    }

    #[cfg(guard_offline_e2e)]
    fn fixture_state(handle: &NativeHandle) -> i32 {
        unsafe { guard_lulu_offline_control(handle.raw.as_ptr(), 0) }
    }

    #[cfg(guard_offline_e2e)]
    fn fixture_launch(shared: &Arc<Shared>, handle: &Arc<NativeHandle>) -> thread::JoinHandle<Result<(), NativeError>> {
        let shared = shared.clone(); let handle = handle.clone();
        thread::spawn(move || {
            let current = shared.current(&handle, 0, handle.fault_serial(), None);
            handle.launch("claude", 1, &current)
        })
    }

    #[cfg(guard_offline_e2e)]
    fn wait_fixture_pending(handle: &NativeHandle) {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while fixture_state(handle) & 1 == 0 {
            assert!(std::time::Instant::now() < deadline, "launch callback never became pending");
            thread::sleep(Duration::from_millis(5));
        }
        assert!(handle.readback().unwrap().pending);
    }

    #[cfg(guard_offline_e2e)]
    #[test]
    fn offline_e2e_rust_launch_ffi_gate_close_and_confirmed_scope_cleanup() {
        let (shared, handle) = offline_fixture(0);
        fixture_launch(&shared, &handle).join().unwrap().unwrap();
        assert!(handle.readback().unwrap().active());
        assert!(!shared.finish(&handle).unwrap().cleanup(), "open Gate must refuse cleanup");
        assert_eq!(shared.finish(&handle).unwrap().cleanup_diagnostic, "cleanup_gate_not_locked_before_stop");
        assert_eq!(fixture_state(&handle) >> 8, 0);
        let result = shared.failure(0, "fixture lock".into(), Some("claude"));
        assert!(matches!(result, BackendResult::Recovery { cleanup_confirmed: true, ref owned_workloads, .. } if owned_workloads.is_empty()));
        assert!(handle.readback().unwrap().locked());
        assert_eq!(fixture_state(&handle), 1 << 8);
    }

    #[cfg(guard_offline_e2e)]
    #[test]
    fn offline_e2e_pending_late_callback_joins_real_finish_lock_before_confirmation() {
        let (shared, handle) = offline_fixture(1);
        let launch = fixture_launch(&shared, &handle);
        wait_fixture_pending(&handle);
        let released = handle.clone();
        let release = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while released.readback().unwrap().open {
                assert!(std::time::Instant::now() < deadline);
                thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(fixture_state(&released) >> 8, 0);
            assert_eq!(unsafe { guard_lulu_offline_control(released.raw.as_ptr(), 1) }, 0);
        });
        let result = shared.failure(0, "fixture cancellation".into(), Some("claude"));
        release.join().unwrap();
        assert!(launch.join().unwrap().is_err());
        assert!(matches!(result, BackendResult::Recovery { cleanup_confirmed: true, ref owned_workloads, .. } if owned_workloads.is_empty()));
        assert_eq!(fixture_state(&handle), 1 << 8);
        assert!(handle.readback().unwrap().locked());
    }

    #[cfg(guard_offline_e2e)]
    #[test]
    fn offline_e2e_pending_timeout_and_identity_refusal_preserve_recovery() {
        let (shared, handle) = offline_fixture(1);
        let launch = fixture_launch(&shared, &handle);
        wait_fixture_pending(&handle);
        let result = shared.failure(0, "fixture pending timeout".into(), Some("claude"));
        assert!(matches!(result, BackendResult::Recovery { cleanup_confirmed: false, ref reason, .. }
            if reason.contains("cleanup_pending_prepare_0_open_0_launch_1")
            && reason.contains("open=0") && reason.contains("pending=1")));
        let readback = handle.readback().unwrap();
        assert!(!readback.open && readback.pending);
        assert_eq!(fixture_state(&handle) >> 8, 0);
        assert_eq!(unsafe { guard_lulu_offline_control(handle.raw.as_ptr(), 1) }, 0);
        assert!(launch.join().unwrap().is_err());
        shared.cleanup_observed_fault(1, handle.clone());
        assert!(matches!(shared.result(), BackendResult::Recovery { cleanup_confirmed: true, .. }));
        assert!(handle.readback().unwrap().locked());

        let (shared, handle) = offline_fixture(2);
        fixture_launch(&shared, &handle).join().unwrap().unwrap();
        let result = shared.failure(0, "fixture identity changed".into(), Some("claude"));
        assert!(matches!(result, BackendResult::Recovery { cleanup_confirmed: false, ref reason, ref owned_workloads, .. }
            if owned_workloads.contains("claude") && reason.contains("cleanup_signal_failed_pid_40101_code_")));
        assert_eq!(fixture_state(&handle), 2);
        assert!(!handle.readback().unwrap().open);
        unsafe { guard_lulu_offline_control(handle.raw.as_ptr(), 2); }
        shared.cleanup_observed_fault(1, handle.clone());
        assert!(matches!(shared.result(), BackendResult::Recovery { cleanup_confirmed: true, .. }));
        assert_eq!(fixture_state(&handle), 1 << 8);
    }

    #[test]
    fn cleanup_diagnostics_cannot_turn_an_unconfirmed_readback_into_success() {
        let readback = Readback::from_finish([0, 1, 0, 0, 1, 0], "cleanup_process_still_running".into());
        assert!(!readback.cleanup());
        let reason = with_cleanup_diagnostic("Native lock did not confirm workload cleanup.", &Ok(readback));
        assert!(reason.contains("confirmed=0, bound=1, open=0, pairs=0, owned=1, pending=0"));
        let long = with_cleanup_diagnostic(&"x".repeat(1_024),
            &Ok(Readback::from_finish([0, 1, 0, 0, 1, 0], "cleanup_process_still_running".into())));
        assert!(long.chars().count() <= 1_024 && long.contains("cleanup_process_still_running"));
        assert!(long.contains("pending=0"));
        let confirmed = Readback::from_finish([1, 1, 0, 0, 1, 0], String::new());
        assert!(confirmed.cleanup());
        assert_eq!(with_cleanup_diagnostic("first failure", &Ok(confirmed)), "first failure");
        assert!(!Readback::from_finish([1, 1, 1, 0, 1, 0], String::new()).cleanup());
        assert!(!Readback::from_finish([1, 1, 0, 1, 1, 0], String::new()).cleanup());
        assert!(!Readback::from_finish([1, 1, 0, 0, 1, 1], String::new()).cleanup());
    }

    #[test]
    fn inventory_detail_and_readbacks_fit_the_reason_and_event_budget() {
        let evidence = format!("cleanup_process_inspection_incomplete\nInventory evidence: {}.", "x".repeat(430));
        let readback = Readback::from_finish([0,1,0,i32::MAX,1,0], evidence);
        let result = with_cleanup_diagnostic(&"界".repeat(2_000), &Ok(readback));
        assert_eq!(result.chars().count(), 1_024);
        assert!(result.ends_with(&format!("{}.", "x".repeat(430))));
        assert!(result.contains("pairs=2147483647"));
        assert!(!Readback::from_readback([1,0,0,1,0]).cleanup());
    }

    #[test]
    fn latched_fault_keeps_the_cleanup_failure_without_granting_cleanup() {
        let handle = NativeHandle::create().unwrap();
        handle.faults.store(1, Ordering::SeqCst);
        let mut state = State::new();
        state.handle = Some(handle);
        state.mode = Mode::Recovery;
        state.reason = "fault\nCleanup diagnostic unavailable: cleanup_bridge_completion_failed.".into();
        assert!(matches!(state.result(), BackendResult::Recovery { ref reason, cleanup_confirmed: false, .. }
            if reason.contains("cleanup_bridge_completion_failed")));
    }

    #[cfg(guard_offline_e2e)]
    #[test]
    fn offline_e2e_inventory_evidence_crosses_all_sources_phases_and_clears() {
        let steps = ["inv_scope", "inv_list", "inv_status", "inv_snapshot_gone", "inv_path_status",
            "inv_path_candidate", "inv_snapshot", "inv_self_pid", "inv_physical", "inv_signature_status",
            "inv_final_gone", "inv_final_snapshot", "inv_ps_run", "inv_ps_timeout", "inv_ps_result", "inv_ps_shape"];
        let mut wire_reasons = Vec::new();
        for (scenario, step) in (10..26).zip(steps) {
            let (shared, handle) = offline_fixture(scenario);
            fixture_launch(&shared, &handle).join().unwrap().unwrap();
            handle.emergency_lock();
            let first = shared.finish(&handle).unwrap();
            assert!(!first.cleanup());
            assert!(first.cleanup_diagnostic.contains(&format!("step={step},")), "scenario={scenario}, expected={step}, actual={}", first.cleanup_diagnostic);
            assert!(first.cleanup_diagnostic.contains("target=Claude, phase=inv_before_term, pass=1,"));
            assert!(first.cleanup_diagnostic.contains("pid=40101, rc=13, call=2, raw=-17, os=1, value=8192, identity=1, ps=5, psCode=1, psBytes=8193, psFlags=1."));
            let reason = with_cleanup_diagnostic(&"界".repeat(2_000), &Ok(first.clone()));
            assert!(reason.chars().count() <= 1_024 && reason.ends_with("psFlags=1."));
            assert!(reason.contains("confirmed=0, bound=1, open=0, pairs=0, owned=1, pending=0."));
            wire_reasons.push(reason.clone());
            let result = shared.failure(0, reason.clone(), Some("claude"));
            assert!(matches!(result, BackendResult::Recovery { cleanup_confirmed: false, ref reason, .. }
                if reason.contains(&format!("step={step},"))));
            assert_eq!(with_cleanup_diagnostic(&reason, &Ok(Readback::from_finish([0,1,0,0,1,0], "later failure".into()))), reason);
            unsafe { guard_lulu_offline_control(handle.raw.as_ptr(), 4); }
            let generic = shared.finish(&handle).unwrap();
            assert!(!generic.cleanup());
            assert_eq!(generic.cleanup_diagnostic, "cleanup_process_inspection_incomplete");
            assert_eq!(with_cleanup_diagnostic(&reason, &Ok(generic)), reason);
            unsafe { guard_lulu_offline_control(handle.raw.as_ptr(), 3); }
            let cleared = shared.finish(&handle).unwrap();
            assert!(cleared.cleanup() && cleared.cleanup_diagnostic.is_empty());
            assert!(handle.readback().unwrap().cleanup_diagnostic.is_empty());
        }
        if let Ok(path) = std::env::var("GUARD_INVENTORY_REASON_FIXTURE") {
            std::fs::write(path, serde_json::to_vec(&wire_reasons).unwrap()).unwrap();
        }
        for (scenario, phase, pass) in [(30, "inv_before_term", 1), (31, "inv_term_wait", 2),
            (32, "inv_before_kill", 3), (33, "inv_final", 4)] {
            let (shared, handle) = offline_fixture(scenario);
            fixture_launch(&shared, &handle).join().unwrap().unwrap();
            handle.emergency_lock();
            let first = shared.finish(&handle).unwrap();
            assert!(!first.cleanup() && first.cleanup_diagnostic.contains(&format!("phase={phase}, pass={pass},")));
            unsafe { guard_lulu_offline_control(handle.raw.as_ptr(), 3); }
            let second = shared.finish(&handle).unwrap();
            assert!(second.cleanup() && second.cleanup_diagnostic.is_empty());
        }
    }

    #[cfg(guard_offline_e2e)]
    #[test]
    fn offline_e2e_distinguishes_signature_inventory_identity_and_post_signal_exit() {
        for (scenario, key) in [(3, "cleanup_signature_mismatch_pid_40101"),
            (4, "cleanup_process_inspection_incomplete"), (5, "cleanup_process_still_running"),
            (6, "cleanup_process_changed_pid_40101")] {
            let (shared, handle) = offline_fixture(scenario);
            fixture_launch(&shared, &handle).join().unwrap().unwrap();
            let result = shared.failure(0, "fixture lock".into(), Some("claude"));
            assert!(matches!(result, BackendResult::Recovery { cleanup_confirmed: false, ref reason, ref owned_workloads, .. }
                if reason.contains(key) && reason.contains("confirmed=0") && reason.contains("pending=0")
                    && owned_workloads.contains("claude")));
            assert!(!handle.readback().unwrap().open);
            assert_eq!(fixture_state(&handle) >> 8, if scenario == 5 { 2 } else { 0 });
            // A process disappearing later is not retroactive cleanup authority.
            unsafe { guard_lulu_offline_control(handle.raw.as_ptr(), 3); }
            assert!(matches!(shared.result(), BackendResult::Recovery { cleanup_confirmed: false, .. }));
            shared.cleanup_observed_fault(1, handle.clone());
            assert!(matches!(shared.result(), BackendResult::Recovery { cleanup_confirmed: true, .. }));
            assert!(shared.finish(&handle).unwrap().cleanup_diagnostic.is_empty());
            assert!(handle.readback().unwrap().locked());
        }
    }

}
