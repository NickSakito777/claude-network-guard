// [INPUT]: Native guard actions and platform enforcement evidence.
// [OUTPUT]: Runtime Guard facts, timestamped failure events, and fail-closed network/local mutation gates.
// [POS]: Business state authority; lazy platform adapters require explicit closed preparation.
// [PROTOCOL]: Update this header when the contract changes, then check CLAUDE.md.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use tauri::Manager;

const MAX_EVENTS: usize = 64;
const MAX_MESSAGE_CHARS: usize = 1_024;
const TARGETS: [(&str, &str); 5] = [
    ("claude", "Claude"),
    ("sunbrowser", "SunBrowser"),
    ("ccbaga_browser", "CCBaga Browser"),
    ("claude_code", "Claude Code"),
    ("mcp", "MCP"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuardState {
    Unavailable,
    Locked,
    Checking,
    Active,
    Recovery,
}

impl GuardState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Locked => "locked",
            Self::Checking => "checking",
            Self::Active => "active",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    schema_version: u8,
    platform: String,
    state: String,
    reason: Option<String>,
    targets: Vec<Target>,
    // Current runtime prerequisites only; never artifact / deployment acceptance.
    enforcement_verified: bool,
    observed_ip: Option<String>,
    observed_at: Option<String>,
    port_observation: Option<PortObservation>,
    events: Vec<Event>,
}

// Display-only wire values. None of these fields are an input to commit_proof,
// target admission, start, renewal, or artifact acceptance.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PortObservation {
    diagnostic_only: bool,
    file_state: FileObservationState,
    schema_state: SchemaObservationState,
    producer_status: Option<String>,
    upstream_state: PortObservationState,
    ingress_state: PortObservationState,
    ingress_owner_state: OwnerObservationState,
    boot_state: BootObservationState,
    wall_freshness: ObservationFreshness,
    monotonic_freshness: ObservationFreshness,
    observed_at_unix_ms: Option<i64>,
    failure: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum FileObservationState { Unreadable, Invalid, Readable }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SchemaObservationState { Unavailable, Invalid, Valid }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum PortObservationState { Unavailable, Missing, Invalid, Present }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum OwnerObservationState { Unchecked, Unavailable, Matches, Mismatch }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum BootObservationState { Unavailable, Invalid, Matches, Mismatch }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ObservationFreshness { Unavailable, Invalid, Fresh, Stale, Future }

impl PortObservation {
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Self = serde_json::from_slice(bytes).ok()?;
        let key = |value: &Option<String>| value.as_deref().map_or(true, |value| {
            !value.is_empty() && value.len() <= 80
                && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        });
        // Keep bounded diagnostic keys and JS-safe milliseconds at the native
        // serialization boundary. No raw executable, credential, or PID fields.
        (value.diagnostic_only && key(&value.producer_status) && key(&value.failure)
            && value.observed_at_unix_ms.map_or(true, |ms| (1..=9_007_199_254_740_991).contains(&ms)))
            .then_some(value)
    }
}

#[derive(Clone, Serialize)]
struct Target {
    id: &'static str,
    label: &'static str,
    available: bool,
    reason: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    sequence: u64,
    recorded_at_unix_ms: Option<u64>,
    level: &'static str,
    message: String,
}

#[derive(Clone)]
// A current adapter check, not evidence that a signed artifact passed live acceptance.
pub(crate) struct VerifiedEnforcement {
    pub(crate) protected_targets: HashSet<String>,
    pub(crate) observed_ip: Option<String>,
    pub(crate) observed_at: Option<String>,
}

pub(crate) enum BackendResult {
    Unavailable {
        reason: String,
        available_targets: HashSet<String>,
        owned_workloads: HashSet<String>,
        cleanup_confirmed: bool,
    },
    Locked {
        proof: VerifiedEnforcement,
        available_targets: HashSet<String>,
        owned_workloads: HashSet<String>,
        cleanup_confirmed: bool,
    },
    Active {
        proof: VerifiedEnforcement,
        available_targets: HashSet<String>,
        owned_workloads: HashSet<String>,
        cleanup_confirmed: bool,
    },
    Recovery {
        reason: String,
        available_targets: HashSet<String>,
        owned_workloads: HashSet<String>,
        cleanup_confirmed: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackendAction {
    Inspect,
    Start(&'static str),
    Lock,
    Recover,
}

pub(crate) trait Backend: Send + Sync {
    // Fast closed-entry signal; never waits for full checks or the operation lease.
    fn emergency_lock(&self) {}
    // Cached platform fault evidence only; no probes, permits or launches.
    fn observe(&self) -> Option<BackendResult> { None }
    // Read-only observer facts for display; never interpreted as BackendResult.
    fn port_observation(&self) -> Option<PortObservation> { None }
    // Capability-specific display reason; never a grant or runtime state.
    fn unavailable_target_reason(&self, _target: &str) -> Option<&'static str> { None }
    // Read-only closed/quiescent admission, independent of public-IP freshness.
    // Called under the existing OperationLease. Must cover the actual target and
    // descendants, reject incomplete inspection / pending launches, and never
    // prepare, bind, stop, renew, open or launch. Unknown coverage refuses.
    fn confirm_local_mutation(&self, _target: &'static str, _token: ActionToken) -> Result<(), String> {
        Err("尚未确认目标及其子进程已完全静止，已阻止本地身份修改。".into())
    }
    // Adapters must check cancellation before any permit or launch and clean up partial setup.
    fn execute(&self, action: BackendAction, token: ActionToken) -> BackendResult;
}

#[derive(Clone)]
pub(crate) struct ActionToken {
    generation: u64,
    current_generation: Arc<AtomicU64>,
}

impl ActionToken {
    pub(crate) fn generation(&self) -> u64 { self.generation }
    pub(crate) fn is_current(&self) -> bool {
        self.current_generation.load(Ordering::SeqCst) == self.generation
    }
}

struct UnavailableBackend;

impl Backend for UnavailableBackend {
    fn execute(&self, _action: BackendAction, _token: ActionToken) -> BackendResult {
        BackendResult::Unavailable {
            reason: "No verified host enforcement adapter is wired into this build.".into(),
            available_targets: HashSet::new(),
            owned_workloads: HashSet::new(),
            cleanup_confirmed: true,
        }
    }
}

struct Inner {
    generation: u64,
    sequence: u64,
    state: GuardState,
    reason: Option<String>,
    available_targets: HashSet<String>,
    proof: Option<VerifiedEnforcement>,
    owned_workloads: HashSet<String>,
    cleanup_confirmed: bool,
    events: Vec<Event>,
}

impl Inner {
    fn event(&mut self, level: &'static str, message: &str) {
        self.sequence = self.sequence.saturating_add(1);
        let message = message.chars().take(MAX_MESSAGE_CHARS).collect();
        self.events.push(Event {
            sequence: self.sequence,
            recorded_at_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH).ok()
                .and_then(|duration| u64::try_from(duration.as_millis()).ok()),
            level,
            message,
        });
        if self.events.len() > MAX_EVENTS {
            self.events.drain(..self.events.len() - MAX_EVENTS);
        }
    }

    fn snapshot(&self) -> Snapshot {
        let available = &self.available_targets;
        let unavailable_reason = self.reason.clone();
        Snapshot {
            schema_version: 1,
            platform: std::env::consts::OS.into(),
            state: self.state.as_str().into(),
            reason: self.reason.clone(),
            targets: TARGETS
                .iter()
                .map(|(id, label)| {
                    let is_available = available.contains(*id);
                    Target {
                        id,
                        label,
                        available: is_available,
                        reason: if is_available {
                            if cfg!(target_os = "macos") && *id == "sunbrowser" {
                                Some("Opens AdsPower Manager only; start the existing SunBrowser environment there.".into())
                            } else { None }
                        } else {
                            Some(unavailable_reason.clone().unwrap_or_else(|| {
                                "No verified enforcement adapter is available for this target.".into()
                            }))
                        },
                    }
                })
                .collect(),
            enforcement_verified: self.proof.is_some()
                && matches!(self.state, GuardState::Locked | GuardState::Active),
            observed_ip: self
                .proof
                .as_ref()
                .and_then(|proof| proof.observed_ip.clone()),
            observed_at: self
                .proof
                .as_ref()
                .and_then(|proof| proof.observed_at.clone()),
            port_observation: None,
            events: self.events.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Guard {
    quit_pending: Arc<AtomicBool>,
    inner: Arc<Mutex<Inner>>,
    backend: Arc<dyn Backend>,
    current_generation: Arc<AtomicU64>,
}

impl Default for Guard {
    fn default() -> Self {
        Self::unavailable()
    }
}

impl Guard {
    pub fn unavailable() -> Self {
        let mut inner = Inner {
            generation: 0,
            sequence: 0,
            state: GuardState::Unavailable,
            reason: Some("Protection is not prepared. Use Prepare / recover before starting.".into()),
            available_targets: HashSet::new(),
            proof: None,
            owned_workloads: HashSet::new(),
            cleanup_confirmed: true,
            events: Vec::new(),
        };
        inner.event("warning", "Host protection is not prepared; guarded operations remain unavailable.");
        Self {
            quit_pending: Arc::new(AtomicBool::new(false)),
            inner: Arc::new(Mutex::new(inner)),
            backend: Arc::new(UnavailableBackend),
            current_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn platform() -> Self {
        let mut guard = Self::unavailable();
        #[cfg(target_os = "macos")]
        { guard.backend = crate::guard_macos::backend(); }
        #[cfg(target_os = "windows")]
        { guard.backend = crate::guard_windows::backend(); }
        guard
    }

    pub fn refresh(&self) -> Snapshot {
        let observed_generation = self.current_generation.load(Ordering::SeqCst);
        if let Some(result) = self.backend.observe() {
            let adverse = match &result {
                BackendResult::Unavailable { reason, .. } | BackendResult::Recovery { reason, .. } => Some(bounded(reason)),
                _ => None,
            };
            if adverse.is_none() {
                if let BackendResult::Active { proof, .. } = &result {
                    let mut inner = self.inner.lock().unwrap();
                    if inner.generation == observed_generation && inner.state == GuardState::Active {
                        if let Some(current) = inner.proof.as_mut() {
                            if current.protected_targets == proof.protected_targets
                                && current.observed_ip == proof.observed_ip {
                                // Only observation metadata can refresh here; no permit, target or state change.
                                current.observed_at = proof.observed_at.as_ref().map(|value| bounded(value));
                            }
                        }
                    }
                }
            }
            if let Some(reason) = adverse {
                let unchanged = {
                    let mut inner = self.inner.lock().unwrap();
                    let same_fault = inner.proof.is_none() && inner.reason.as_deref() == Some(reason.as_str())
                        && matches!(inner.state, GuardState::Unavailable | GuardState::Recovery);
                    if same_fault {
                        match &result {
                            BackendResult::Unavailable { owned_workloads, cleanup_confirmed, .. }
                            | BackendResult::Recovery { owned_workloads, cleanup_confirmed, .. } => {
                                // Native cleanup can complete after the fault; do not issue another lock epoch.
                                inner.owned_workloads = valid_targets(owned_workloads.clone());
                                inner.cleanup_confirmed = *cleanup_confirmed;
                            }
                            _ => {}
                        }
                    }
                    same_fault
                };
                if !unchanged {
                    let generation = self.request_lock();
                    return self.apply_inspection(result, generation);
                }
            }
        }
        self.snapshot()
    }

    pub(crate) fn invalidate_readiness(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.proof = None;
        inner.reason = Some("Environment changed; a fresh check is required before reuse.".into());
        inner.event("info", "Environment mutation invalidated the previous protection evidence.");
    }

    #[cfg(test)]
    fn with_backend(backend: impl Backend + 'static) -> Self {
        let mut guard = Self::unavailable();
        guard.backend = Arc::new(backend);
        guard.inner.lock().unwrap().available_targets = TARGETS
            .iter()
            .map(|(id, _)| (*id).into())
            .collect();
        {
            let mut inner = guard.inner.lock().unwrap();
            inner.state = GuardState::Locked;
            inner.reason = None;
            inner.proof = Some(VerifiedEnforcement {
                protected_targets: inner.available_targets.clone(),
                observed_ip: None,
                observed_at: None,
            });
        }
        guard
    }

    pub fn snapshot(&self) -> Snapshot {
        self.inner.lock().unwrap().snapshot()
    }

    // Attach at the IPC response boundary, outside Inner and the permit path.
    // An absent/malformed diagnostic cannot change the authorized runtime state.
    fn with_platform_details(&self, mut snapshot: Snapshot) -> Snapshot {
        for target in &mut snapshot.targets {
            if !target.available {
                if let Some(reason) = self.backend.unavailable_target_reason(target.id) {
                    target.reason = Some(reason.into());
                }
            }
        }
        snapshot.port_observation = self.backend.port_observation();
        snapshot
    }

    fn run(&self, action: BackendAction) -> Snapshot {
        let generation = {
            let mut inner = self.inner.lock().unwrap();
            inner.generation = inner.generation.saturating_add(1);
            let generation = inner.generation;
            self.current_generation.store(generation, Ordering::SeqCst);
            inner.state = if action == BackendAction::Recover {
                GuardState::Recovery
            } else {
                GuardState::Checking
            };
            inner.proof = None;
            inner.reason = None;
            inner.cleanup_confirmed = false;
            inner.event("info", action_message(action));
            generation
        };

        self.execute_at(action, generation)
    }

    fn execute_at(&self, action: BackendAction, generation: u64) -> Snapshot {
        let token = ActionToken {
            generation,
            current_generation: self.current_generation.clone(),
        };
        let result = self.backend.execute(action, token.clone());
        let mut inner = self.inner.lock().unwrap();
        if !token.is_current() || inner.generation != generation {
            // This rejects stale UI state only; an adapter must serialize or reverse its own host-side effects.
            inner.event("warning", "A stale guard result was ignored.");
            return inner.snapshot();
        }
        if unexpected_result(action, &result) {
            inner.owned_workloads
                .extend(valid_targets(result_owned_workloads(&result).clone()));
            inner.state = GuardState::Recovery;
            inner.reason = Some("The host returned an unexpected Guard state; recovery is required.".into());
            inner.proof = None;
            inner.cleanup_confirmed = false;
            inner.event("error", "An unexpected host state was rejected.");
            return inner.snapshot();
        }
        match result {
            BackendResult::Unavailable {
                reason,
                available_targets,
                owned_workloads,
                cleanup_confirmed,
            } => {
                inner.state = GuardState::Unavailable;
                inner.reason = Some(bounded(&reason));
                inner.available_targets = valid_targets(available_targets);
                inner.proof = None;
                inner.owned_workloads = valid_targets(owned_workloads);
                inner.cleanup_confirmed = cleanup_confirmed;
                inner.event("warning", "Host enforcement could not be verified.");
            }
            BackendResult::Locked {
                proof,
                available_targets,
                owned_workloads,
                cleanup_confirmed,
            } => {
                Self::commit_proof(
                    &mut inner,
                    GuardState::Locked,
                    proof,
                    available_targets,
                    owned_workloads,
                    cleanup_confirmed,
                );
            }
            BackendResult::Active {
                proof,
                available_targets,
                owned_workloads,
                cleanup_confirmed,
            } => {
                Self::commit_proof(
                    &mut inner,
                    GuardState::Active,
                    proof,
                    available_targets,
                    owned_workloads,
                    cleanup_confirmed,
                );
            }
            BackendResult::Recovery {
                reason,
                available_targets,
                owned_workloads,
                cleanup_confirmed,
            } => {
                inner.state = GuardState::Recovery;
                inner.reason = Some(bounded(&reason));
                inner.available_targets = valid_targets(available_targets);
                inner.proof = None;
                inner.owned_workloads = valid_targets(owned_workloads);
                inner.cleanup_confirmed = cleanup_confirmed;
                inner.event("error", &reason);
            }
        }
        inner.snapshot()
    }

    pub fn request_lock(&self) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        inner.generation = inner.generation.saturating_add(1);
        self.current_generation
            .store(inner.generation, Ordering::SeqCst);
        inner.state = GuardState::Checking;
        inner.reason = Some("Lock requested; waiting for native cleanup.".into());
        inner.proof = None;
        inner.cleanup_confirmed = false;
        inner.event("warning", "Lock requested; pending starts were invalidated.");
        let generation = inner.generation;
        drop(inner);
        self.backend.emergency_lock();
        generation
    }

    pub fn lock_after_request(&self, generation: u64) -> Snapshot {
        if self.current_generation.load(Ordering::SeqCst) != generation {
            let mut inner = self.inner.lock().unwrap();
            inner.event("warning", "A stale lock request was ignored.");
            return inner.snapshot();
        }
        self.execute_at(BackendAction::Lock, generation)
    }

    fn commit_proof(
        inner: &mut Inner,
        state: GuardState,
        mut proof: VerifiedEnforcement,
        available_targets: HashSet<String>,
        owned_workloads: HashSet<String>,
        cleanup_confirmed: bool,
    ) {
        proof.protected_targets = valid_targets(proof.protected_targets);
        let available_targets = valid_targets(available_targets);
        let owned_workloads = valid_targets(owned_workloads);
        if state == GuardState::Locked && (!cleanup_confirmed || !owned_workloads.is_empty()) {
            inner.state = GuardState::Recovery;
            inner.reason = Some("Guard lock did not confirm workload cleanup.".into());
            inner.available_targets = available_targets;
            inner.proof = None;
            inner.owned_workloads.extend(owned_workloads);
            inner.cleanup_confirmed = false;
            inner.event("error", "Guard lock requires recovery because cleanup was not confirmed.");
            return;
        }
        if proof.protected_targets.is_empty()
            || !proof
                .protected_targets
                .is_subset(&available_targets)
        {
            inner.state = GuardState::Recovery;
            inner.reason = Some("The host did not verify protection for every reported target.".into());
            inner.available_targets = available_targets;
            inner.proof = None;
            inner.owned_workloads.extend(owned_workloads);
            inner.cleanup_confirmed = false;
            inner.event("error", "Host protection evidence was incomplete.");
            return;
        }
        if proof
            .observed_ip
            .as_deref()
            .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_err())
        {
            proof.observed_ip = None;
        }
        proof.observed_at = proof.observed_at.map(|value| bounded(&value));
        inner.state = state;
        inner.available_targets = available_targets;
        inner.proof = Some(proof);
        inner.owned_workloads = owned_workloads;
        inner.cleanup_confirmed = cleanup_confirmed;
        inner.reason = (state == GuardState::Locked
            && (!cleanup_confirmed || !inner.owned_workloads.is_empty()))
            .then(|| "Protection is locked, but workload cleanup is unconfirmed.".into());
        inner.event("info", if state == GuardState::Locked {
            "Host protection was verified in locked state."
        } else {
            "Host protection was verified in active state."
        });
    }

    pub fn inspect(&self) -> Snapshot {
        let generation = self.current_generation.load(Ordering::SeqCst);
        let token = ActionToken {
            generation,
            current_generation: self.current_generation.clone(),
        };
        let result = self.backend.execute(BackendAction::Inspect, token.clone());
        let adverse = matches!(result, BackendResult::Unavailable { .. } | BackendResult::Recovery { .. });
        if adverse && token.is_current() {
            let generation = self.request_lock();
            self.apply_inspection(result, generation)
        } else {
            self.apply_inspection(result, generation)
        }
    }

    fn apply_inspection(&self, result: BackendResult, generation: u64) -> Snapshot {
        let mut inner = self.inner.lock().unwrap();
        if self.current_generation.load(Ordering::SeqCst) != generation || inner.generation != generation {
            inner.event("warning", "A stale Guard inspection was ignored.");
            return inner.snapshot();
        }
        match result {
            BackendResult::Unavailable {
                reason,
                available_targets,
                owned_workloads,
                cleanup_confirmed,
            } => {
                inner.state = GuardState::Unavailable;
                inner.reason = Some(bounded(&reason));
                inner.available_targets = valid_targets(available_targets);
                inner.proof = None;
                inner.owned_workloads = valid_targets(owned_workloads);
                inner.cleanup_confirmed = cleanup_confirmed;
                inner.event("warning", &reason);
            }
            BackendResult::Recovery {
                reason,
                available_targets,
                owned_workloads,
                cleanup_confirmed,
            } => {
                inner.state = GuardState::Recovery;
                inner.reason = Some(bounded(&reason));
                inner.available_targets = valid_targets(available_targets);
                inner.proof = None;
                inner.owned_workloads = valid_targets(owned_workloads);
                inner.cleanup_confirmed = cleanup_confirmed;
                inner.event("error", &reason);
            }
            BackendResult::Locked {
                proof,
                available_targets,
                owned_workloads,
                cleanup_confirmed,
            } => {
                let available_targets = valid_targets(available_targets);
                let owned_workloads = valid_targets(owned_workloads);
                let matches_current = inner.state == GuardState::Locked
                    && cleanup_confirmed
                    && owned_workloads.is_empty()
                    && inner.proof.as_ref().is_some_and(|current| {
                        let observed = valid_targets(proof.protected_targets.clone());
                        current.protected_targets.is_subset(&observed)
                            && current
                                .protected_targets
                                .is_subset(&available_targets)
                    });
                if matches_current {
                    inner.available_targets = available_targets;
                    inner.owned_workloads = owned_workloads;
                    inner.cleanup_confirmed = true;
                    inner.event("info", "Inspection confirmed the locked state; authorization was unchanged.");
                } else if matches!(inner.state, GuardState::Locked | GuardState::Active) {
                    inner.state = GuardState::Recovery;
                    inner.reason = Some("Inspected protection did not match the authorized state.".into());
                    inner.proof = None;
                    inner.owned_workloads.extend(owned_workloads);
                    inner.cleanup_confirmed = false;
                    inner.event("error", "Inspection found mismatched protection; authorization was revoked.");
                } else {
                    inner.event("info", "Inspection found locked evidence; authorization was unchanged.");
                }
            }
            BackendResult::Active {
                proof,
                available_targets,
                owned_workloads,
                cleanup_confirmed,
            } => {
                let available_targets = valid_targets(available_targets);
                let owned_workloads = valid_targets(owned_workloads);
                let matches_current = inner.state == GuardState::Active
                    && inner.proof.as_ref().is_some_and(|current| {
                        let observed = valid_targets(proof.protected_targets.clone());
                        current.protected_targets.is_subset(&observed)
                            && current
                                .protected_targets
                                .is_subset(&available_targets)
                    });
                if matches_current {
                    inner.available_targets = available_targets;
                    inner.owned_workloads = owned_workloads;
                    inner.cleanup_confirmed = cleanup_confirmed;
                    inner.event("info", "Inspection confirmed the active state; authorization was unchanged.");
                } else if matches!(inner.state, GuardState::Locked | GuardState::Active) {
                    inner.state = GuardState::Recovery;
                    inner.reason = Some("Inspected protection did not match the authorized state.".into());
                    inner.proof = None;
                    inner.owned_workloads.extend(owned_workloads);
                    inner.cleanup_confirmed = false;
                    inner.event("error", "Inspection found mismatched protection; authorization was revoked.");
                } else {
                    inner.event("info", "Inspection found active evidence; authorization was unchanged.");
                }
            }
        }
        inner.snapshot()
    }

    pub fn start(&self, target: &str) -> Snapshot {
        let Some((id, _)) = TARGETS.iter().find(|(id, _)| *id == target) else {
            let mut inner = self.inner.lock().unwrap();
            inner.reason = Some("Unknown guard target.".into());
            inner.event("warning", "A start request used an unknown target.");
            return inner.snapshot();
        };
        {
            let mut inner = self.inner.lock().unwrap();
            if !matches!(inner.state, GuardState::Locked | GuardState::Active) {
                inner.reason = Some("Start requires a locked or active Guard session.".into());
                inner.event("warning", "Start was refused outside an active Guard session.");
                return inner.snapshot();
            }
            if !inner.available_targets.contains(*id) {
                inner.reason = Some("This target has no verified enforcement adapter.".into());
                inner.event("warning", "Start was refused because the target is unavailable.");
                return inner.snapshot();
            }
        }
        self.run(BackendAction::Start(*id))
    }

    #[cfg(test)]
    pub fn lock(&self) -> Snapshot {
        let generation = self.request_lock();
        self.lock_after_request(generation)
    }

    pub fn recover(&self) -> Snapshot {
        {
            let mut inner = self.inner.lock().unwrap();
            if !matches!(inner.state, GuardState::Unavailable | GuardState::Recovery | GuardState::Locked) {
                inner.reason = Some("Preparation or recovery requires an unavailable, locked or recovery session.".into());
                inner.event("warning", "Recovery was refused outside a recoverable session.");
                return inner.snapshot();
            }
        }
        self.run(BackendAction::Recover)
    }

    // Caller owns the shared OperationLease for this check and the complete
    // domain transaction. This is never a fallback for start/system/CLI/browser.
    fn authorize_local_mutation(&self, target: &str) -> Result<(), String> {
        let Some((id, _)) = TARGETS.iter().find(|(id, _)| *id == target) else {
            return Err("This operation has an invalid guard target.".into());
        };
        let generation = {
            let inner = self.inner.lock().unwrap();
            if matches!(inner.state, GuardState::Active | GuardState::Checking)
                || !inner.cleanup_confirmed || !inner.owned_workloads.is_empty() {
                return Err("入口关闭及工作负载清理尚未完成，已阻止本地身份修改。".into());
            }
            inner.generation
        };
        let token = ActionToken { generation, current_generation: self.current_generation.clone() };
        self.backend.confirm_local_mutation(*id, token.clone())?;
        let mut inner = self.inner.lock().unwrap();
        if !token.is_current() || inner.generation != generation {
            return Err("本地身份修改检查已取消，请等待清理完成后重试。".into());
        }
        // Invalidate start readiness before handing control back to the Store;
        // success leaves state/targets/cleanup untouched and grants no permit.
        inner.proof = None;
        inner.reason = Some("Local identity operation admitted; prepare again before starting.".into());
        inner.event("info", "Closed local identity admission confirmed; network readiness was invalidated.");
        Ok(())
    }

    pub(crate) fn authorize_target(&self, target: &str) -> Result<(), String> {
        let Some((id, label)) = TARGETS.iter().find(|(id, _)| *id == target) else {
            return Err("This operation has an invalid guard target.".into());
        };
        let mut inner = self.inner.lock().unwrap();
        let allowed = inner.state == GuardState::Locked
            && inner.cleanup_confirmed
            && inner.owned_workloads.is_empty()
            && inner
                .proof
                .as_ref()
                .is_some_and(|proof| proof.protected_targets.contains(*id));
        if allowed {
            return Ok(());
        }
        inner.event("warning", &format!("Blocked an operation for {label}: target protection is unverified."));
        Err(format!("尚未核验 {label} 的网络防护或工作负载清理，已阻止此操作。"))
    }

    pub(crate) fn authorize_running_target(&self, target: &str) -> Result<(), String> {
        let inner = self.inner.lock().unwrap();
        let allowed = TARGETS.iter().any(|(id, _)| *id == target)
            && inner.state == GuardState::Active
            && inner.owned_workloads.contains(target)
            && inner.available_targets.contains(target)
            && inner.proof.as_ref().is_some_and(|proof| proof.protected_targets.contains(target));
        if allowed { Ok(()) } else {
            Err("请先从保护中心启动此目标；资料设置或检查结果不能授权浏览器联网。".into())
        }
    }

    pub(crate) fn authorize_environment(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        // Optional targets such as MCP must not be mandatory when their adapter is unavailable.
        // Before shipping configurable target profiles, replace this set with the explicit configured set.
        let available_targets_protected = inner.state == GuardState::Locked
            && inner.cleanup_confirmed
            && inner.owned_workloads.is_empty()
            && inner.proof.as_ref().is_some_and(|proof| {
                !inner.available_targets.is_empty()
                    && inner
                        .available_targets
                        .iter()
                        .all(|id| proof.protected_targets.contains(id))
            });
        if available_targets_protected {
            return Ok(());
        }
        inner.event("warning", "Blocked a system operation: configured target protection is unverified.");
        Err("尚未核验已配置目标的网络防护，已阻止此系统操作。".into())
    }

    pub(crate) fn can_quit(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.owned_workloads.is_empty()
            && inner.cleanup_confirmed
            && matches!(inner.state, GuardState::Unavailable | GuardState::Locked | GuardState::Recovery)
    }
}

fn valid_targets(targets: HashSet<String>) -> HashSet<String> {
    targets
        .into_iter()
        .filter(|target| TARGETS.iter().any(|(id, _)| *id == target.as_str()))
        .collect()
}

fn unexpected_result(action: BackendAction, result: &BackendResult) -> bool {
    match action {
        BackendAction::Inspect => true,
        BackendAction::Start(_) => matches!(result, BackendResult::Locked { .. }),
        BackendAction::Lock | BackendAction::Recover => {
            matches!(result, BackendResult::Active { .. })
        }
    }
}

fn result_owned_workloads(result: &BackendResult) -> &HashSet<String> {
    match result {
        BackendResult::Unavailable { owned_workloads, .. }
        | BackendResult::Locked { owned_workloads, .. }
        | BackendResult::Active { owned_workloads, .. }
        | BackendResult::Recovery { owned_workloads, .. } => owned_workloads,
    }
}

fn bounded(value: &str) -> String {
    value.chars().take(MAX_MESSAGE_CHARS).collect()
}

fn action_message(action: BackendAction) -> &'static str {
    match action {
        BackendAction::Inspect => "Inspecting native host protection.",
        BackendAction::Start("claude") => "Starting protection for Claude.",
        BackendAction::Start("sunbrowser") => "Starting protection for SunBrowser.",
        BackendAction::Start("ccbaga_browser") => "Starting protection for CCBaga Browser.",
        BackendAction::Start("claude_code") => "Starting protection for Claude Code.",
        BackendAction::Start("mcp") => "Starting protection for MCP.",
        BackendAction::Start(_) => "Starting protection for a target.",
        BackendAction::Lock => "Locking native host protection.",
        BackendAction::Recover => "Recovering native host protection.",
    }
}

#[tauri::command]
pub fn guard_status(guard: tauri::State<'_, Guard>) -> Snapshot {
    guard.with_platform_details(guard.refresh())
}

#[tauri::command]
pub async fn guard_inspect(app: tauri::AppHandle) -> Result<Snapshot, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = app.state::<crate::cleaner::Cleaner>().lease()?;
        let guard = app.state::<Guard>();
        Ok(guard.with_platform_details(guard.inspect()))
    })
        .await
        .map_err(|_| "Guard inspection was interrupted.".to_string())
        .and_then(|result| result)
}

#[tauri::command]
pub async fn guard_start(app: tauri::AppHandle, target: String) -> Result<Snapshot, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = app.state::<crate::cleaner::Cleaner>().lease()?;
        let guard = app.state::<Guard>();
        Ok(guard.with_platform_details(guard.start(&target)))
    })
        .await
        .map_err(|_| "Guard start was interrupted.".to_string())
        .and_then(|result| result)
}

#[tauri::command]
pub async fn guard_lock(app: tauri::AppHandle) -> Result<Snapshot, String> {
    let generation = app.state::<Guard>().request_lock();
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = app.state::<crate::cleaner::Cleaner>().lease_wait();
        let guard = app.state::<Guard>();
        Ok(guard.with_platform_details(guard.lock_after_request(generation)))
    })
        .await
        .map_err(|_| "Guard lock was interrupted.".to_string())
        .and_then(|result| result)
}

#[tauri::command]
pub async fn guard_recover(app: tauri::AppHandle) -> Result<Snapshot, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = app.state::<crate::cleaner::Cleaner>().lease()?;
        let guard = app.state::<Guard>();
        Ok(guard.with_platform_details(guard.recover()))
    })
        .await
        .map_err(|_| "Guard recovery was interrupted.".to_string())
        .and_then(|result| result)
}

pub(crate) fn require_target(app: &tauri::AppHandle, target: &str) -> Result<(), String> {
    let guard = app.state::<Guard>();
    guard.refresh();
    guard.authorize_target(target)?;
    guard.invalidate_readiness();
    Ok(())
}

/// Only pure local identity/archive transactions may use this admission.
/// Keep this exact lease until Store commit/rollback/recovery bookkeeping ends;
/// never re-enter the mutex or reopen a client after saving. Domain recovery
/// conflicts and browser/CLI descendants still require their own complete check.
pub(crate) fn require_local_mutation(
    app: &tauri::AppHandle,
    target: &str,
    _operation: &crate::cleaner::OperationLease,
) -> Result<(), String> {
    // Do not call refresh here: passive fault handling may schedule cleanup.
    // The backend's narrow check must collect fresh closed-scope facts itself.
    app.state::<Guard>().authorize_local_mutation(target)
}

/// A browser reconnect may only use a target already owned by the active executor.
pub(crate) fn require_running_target(app: &tauri::AppHandle, target: &str) -> Result<(), String> {
    let guard = app.state::<Guard>();
    guard.refresh();
    guard.authorize_running_target(target)
}

pub(crate) fn require_environment(app: &tauri::AppHandle) -> Result<(), String> {
    let guard = app.state::<Guard>();
    guard.refresh();
    guard.authorize_environment()?;
    guard.invalidate_readiness();
    Ok(())
}

pub(crate) fn request_quit(app: tauri::AppHandle) {
    let pending = app.state::<Guard>().quit_pending.clone();
    if pending.swap(true, Ordering::SeqCst) { return; }
    app.state::<crate::cleaner::Cleaner>().begin_shutdown();
    tauri::async_runtime::spawn(async move {
        let result = guard_lock(app.clone()).await;
        pending.store(false, Ordering::SeqCst);
        if result.is_ok() && may_quit(&app) {
            app.exit(0);
        } else {
            app.state::<crate::cleaner::Cleaner>().cancel_shutdown();
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }
    });
}

pub(crate) fn may_quit(app: &tauri::AppHandle) -> bool {
    app.state::<Guard>().can_quit()
        && app.state::<crate::cleaner::Cleaner>().shutdown_ready()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Mutex as StdMutex};
    use std::thread;

    struct FixedBackend(StdMutex<Vec<BackendResult>>);

    impl Backend for FixedBackend {
        fn execute(&self, _action: BackendAction, _token: ActionToken) -> BackendResult {
            self.0.lock().unwrap().remove(0)
        }
    }

    fn available() -> HashSet<String> {
        TARGETS.iter().map(|(id, _)| (*id).into()).collect()
    }

    fn proof(ids: &[&str]) -> VerifiedEnforcement {
        VerifiedEnforcement {
            protected_targets: ids.iter().map(|id| (*id).into()).collect(),
            observed_ip: None,
            observed_at: None,
        }
    }

    fn owned(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|id| (*id).into()).collect()
    }

    fn backend(results: Vec<BackendResult>) -> Guard {
        Guard::with_backend(FixedBackend(StdMutex::new(results)))
    }

    #[test]
    fn target_specific_blockers_do_not_replace_session_failure_or_grant_permission() {
        struct TargetReasons;
        impl Backend for TargetReasons {
            fn unavailable_target_reason(&self, target: &str) -> Option<&'static str> {
                (target == "mcp").then_some("MCP is deferred.")
            }
            fn execute(&self, _: BackendAction, _: ActionToken) -> BackendResult { unreachable!() }
        }
        let mut guard = Guard::unavailable();
        guard.backend = Arc::new(TargetReasons);
        guard.inner.lock().unwrap().reason = Some("cleanup_unconfirmed".into());
        let result = guard.with_platform_details(guard.snapshot());
        assert_eq!(result.reason.as_deref(), Some("cleanup_unconfirmed"));
        assert_eq!(result.targets.iter().find(|t| t.id == "mcp").unwrap().reason.as_deref(), Some("MCP is deferred."));
        assert_eq!(result.targets.iter().find(|t| t.id == "claude").unwrap().reason.as_deref(), Some("cleanup_unconfirmed"));
        assert!(result.targets.iter().all(|t| !t.available));
        assert!(!result.enforcement_verified);
        assert!(guard.authorize_target("mcp").is_err());
        guard.inner.lock().unwrap().available_targets.insert("mcp".into());
        let available = guard.with_platform_details(guard.snapshot());
        assert_eq!(available.targets.iter().find(|t| t.id == "mcp").unwrap().reason, None);
    }

    fn diagnostic_fixture() -> serde_json::Value {
        serde_json::json!({
            "diagnosticOnly": true, "fileState": "readable", "schemaState": "valid",
            "producerStatus": "ok", "upstreamState": "present", "ingressState": "present",
            "ingressOwnerState": "matches", "bootState": "matches", "wallFreshness": "fresh",
            "monotonicFreshness": "fresh", "observedAtUnixMs": 1792020000000_i64, "failure": null
        })
    }

    struct DiagnosticBackend;
    impl Backend for DiagnosticBackend {
        fn execute(&self, _: BackendAction, _: ActionToken) -> BackendResult {
            panic!("diagnostic display must not execute an action")
        }
        fn port_observation(&self) -> Option<PortObservation> {
            PortObservation::decode(&serde_json::to_vec(&diagnostic_fixture()).unwrap())
        }
    }

    #[test]
    fn complete_port_diagnostics_cannot_grant_or_promote_an_unavailable_session() {
        let mut guard = Guard::unavailable();
        guard.backend = Arc::new(DiagnosticBackend);
        let before = guard.current_generation.load(Ordering::SeqCst);
        let snapshot = guard.with_platform_details(guard.snapshot());
        assert!(snapshot.port_observation.is_some());
        assert_eq!(snapshot.state, "unavailable");
        assert!(!snapshot.enforcement_verified);
        assert!(snapshot.targets.iter().all(|target| !target.available));
        assert_eq!(guard.current_generation.load(Ordering::SeqCst), before);
        assert!(guard.authorize_target("claude").is_err());
        assert!(guard.authorize_environment().is_err());
        assert!(guard.authorize_local_mutation("claude").is_err());
    }

    #[test]
    fn port_diagnostic_wire_rejects_authority_fields_invalid_states_and_unbounded_data() {
        let decode = |value: &serde_json::Value| PortObservation::decode(&serde_json::to_vec(value).unwrap());
        assert!(decode(&diagnostic_fixture()).is_some());
        for (field, value) in [
            ("diagnosticOnly", serde_json::json!(false)),
            ("upstreamState", serde_json::json!("verified")),
            ("producerStatus", serde_json::json!("x".repeat(81))),
            ("failure", serde_json::json!("/private/path")),
            ("observedAtUnixMs", serde_json::json!(9_007_199_254_740_992_i64)),
            ("enforcementVerified", serde_json::json!(true)),
        ] {
            let mut value_fixture = diagnostic_fixture();
            value_fixture[field] = value;
            assert!(decode(&value_fixture).is_none(), "{field} must be rejected");
        }
        let mut unknown = diagnostic_fixture();
        unknown["upstreamState"] = serde_json::json!("unavailable");
        unknown["ingressState"] = serde_json::json!("unavailable");
        unknown["producerStatus"] = serde_json::json!("missing_listener");
        assert!(decode(&unknown).is_some());
        let guard = Guard::unavailable();
        assert!(guard.with_platform_details(guard.snapshot()).port_observation.is_none());
    }

    #[test]
    #[ignore = "run-port-observation-transport-tests.sh supplies an actual Swift-encoded fixture"]
    fn native_port_observation_fixture_crosses_the_rust_wire_boundary() {
        let path = std::env::var_os("GUARD_PORT_OBSERVATION_FIXTURE").expect("native fixture path required");
        let bytes = std::fs::read(path).expect("read isolated native fixture");
        let value = PortObservation::decode(&bytes).expect("decode actual Swift payload");
        let json = serde_json::to_value(value).unwrap();
        assert_eq!(json["diagnosticOnly"], true);
        assert_eq!(json["upstreamState"], "present");
        assert_eq!(json["ingressState"], "present");
        assert_eq!(json["producerStatus"], "ok");
        assert!(json.get("enforcementVerified").is_none());
        assert!(json.get("pid").is_none());
    }

    #[test]
    fn port_wire_preserves_one_confirmed_absence_when_the_other_query_fails() {
        let mut fixture = diagnostic_fixture();
        fixture["producerStatus"] = serde_json::json!("netstat_read_failed");
        fixture["upstreamState"] = serde_json::json!("missing");
        fixture["ingressState"] = serde_json::json!("unavailable");
        fixture["failure"] = serde_json::json!("root_observer_netstat_read_failed");
        let decoded = PortObservation::decode(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        let value = serde_json::to_value(decoded).unwrap();
        assert_eq!(value["upstreamState"], "missing");
        assert_eq!(value["ingressState"], "unavailable");
        assert_eq!(value["diagnosticOnly"], true);
    }

    struct LocalMutationBackend { refuse: bool, cancel: bool }
    impl Backend for LocalMutationBackend {
        fn execute(&self, _: BackendAction, _: ActionToken) -> BackendResult {
            panic!("local admission must not execute a Guard action")
        }
        fn confirm_local_mutation(&self, target: &'static str, token: ActionToken) -> Result<(), String> {
            assert_eq!(target, "claude");
            if self.cancel { token.current_generation.fetch_add(1, Ordering::SeqCst); }
            if self.refuse { Err("pending launch / incomplete descendant inspection".into()) } else { Ok(()) }
        }
    }

    #[test]
    fn local_mutation_uses_closed_facts_without_public_proof_and_never_grants() {
        let mut guard = Guard::unavailable();
        guard.backend = Arc::new(LocalMutationBackend { refuse: false, cancel: false });
        assert!(guard.authorize_local_mutation("claude").is_ok());
        let snapshot = guard.snapshot();
        assert_eq!(snapshot.state, "unavailable");
        assert!(!snapshot.enforcement_verified);
        assert!(snapshot.targets.iter().all(|target| !target.available));
        assert_eq!(guard.start("claude").state, "unavailable");
        assert!(guard.authorize_environment().is_err());
        assert!(guard.authorize_running_target("claude").is_err());
    }

    #[test]
    fn local_mutation_invalidates_existing_network_readiness() {
        let guard = Guard::with_backend(LocalMutationBackend { refuse: false, cancel: false });
        assert!(guard.snapshot().enforcement_verified);
        assert!(guard.authorize_local_mutation("claude").is_ok());
        assert!(!guard.snapshot().enforcement_verified);
        assert!(guard.authorize_target("claude").is_err());
    }

    #[test]
    fn local_mutation_rejects_running_checking_and_unconfirmed_cleanup() {
        for state in [GuardState::Active, GuardState::Checking] {
            let guard = Guard::with_backend(LocalMutationBackend { refuse: false, cancel: false });
            guard.inner.lock().unwrap().state = state;
            assert!(guard.authorize_local_mutation("claude").is_err());
        }
        for owned_workload in [false, true] {
            let guard = Guard::with_backend(LocalMutationBackend { refuse: false, cancel: false });
            let mut inner = guard.inner.lock().unwrap();
            if owned_workload { inner.owned_workloads = owned(&["claude"]); }
            else { inner.cleanup_confirmed = false; }
            drop(inner);
            assert!(guard.authorize_local_mutation("claude").is_err());
        }
    }

    #[test]
    fn local_mutation_rejects_unknown_scope_native_refusal_and_stale_check() {
        assert!(Guard::unavailable().authorize_local_mutation("claude").is_err());
        for (refuse, cancel) in [(true, false), (false, true)] {
            let guard = Guard::with_backend(LocalMutationBackend { refuse, cancel });
            assert!(guard.authorize_local_mutation("claude").is_err());
        }
        let guard = Guard::unavailable();
        assert!(guard.authorize_local_mutation("arbitrary").is_err());
    }

    #[test]
    fn verified_target_authorizes_only_covered_operations() {
        let guard = backend(vec![
            BackendResult::Active {
                proof: proof(&["claude"]),
                available_targets: available(),
                owned_workloads: owned(&[]),
                cleanup_confirmed: false,
            },
            BackendResult::Locked {
                proof: proof(&["claude"]),
                available_targets: available(),
                owned_workloads: owned(&[]),
                cleanup_confirmed: true,
            },
        ]);
        let active = guard.start("claude");
        assert_eq!(active.state, "active");
        assert!(active.enforcement_verified);
        assert!(guard.authorize_target("claude").is_err());
        let snapshot = guard.lock();
        assert_eq!(snapshot.state, "locked");
        assert!(snapshot.enforcement_verified);
        assert!(guard.authorize_target("claude").is_ok());
        assert!(guard.authorize_target("ccbaga_browser").is_err());
        assert!(guard.authorize_environment().is_err());
        assert!(guard.can_quit());
    }

    #[test]
    fn browser_reconnect_requires_active_ownership_and_current_evidence() {
        let guard = backend(vec![BackendResult::Active {
            proof: proof(&["ccbaga_browser"]),
            available_targets: available(),
            owned_workloads: owned(&["ccbaga_browser"]),
            cleanup_confirmed: false,
        }]);
        // Locked readiness and a committed identity are not launch authority.
        assert!(guard.authorize_running_target("ccbaga_browser").is_err());
        guard.start("ccbaga_browser");
        assert!(guard.authorize_running_target("ccbaga_browser").is_ok());
        assert!(guard.authorize_running_target("claude").is_err());
        assert!(guard.authorize_running_target("arbitrary").is_err());
        guard.invalidate_readiness();
        assert!(guard.authorize_running_target("ccbaga_browser").is_err());
    }

    #[test]
    fn active_proof_without_owned_browser_cannot_reconnect_it() {
        let guard = backend(vec![BackendResult::Active {
            proof: proof(&["claude", "ccbaga_browser"]),
            available_targets: available(),
            owned_workloads: owned(&["claude"]),
            cleanup_confirmed: false,
        }]);
        guard.start("claude");
        assert!(guard.authorize_running_target("ccbaga_browser").is_err());
    }

    #[test]
    fn unsupported_production_backend_never_claims_protection_or_allows_mutation() {
        let guard = Guard::unavailable();
        let inspected = guard.inspect();
        assert_eq!(inspected.state, "unavailable");
        assert!(!inspected.enforcement_verified);
        let recovered = guard.recover();
        assert_eq!(recovered.state, "unavailable");
        assert!(!recovered.enforcement_verified);
        let snapshot = guard.start("claude");
        assert_eq!(snapshot.state, "unavailable");
        assert!(!snapshot.enforcement_verified);
        assert!(snapshot.targets.iter().all(|target| !target.available));
        assert!(guard.authorize_target("claude").is_err());
        assert!(guard.can_quit());
    }

    #[test]
    fn an_active_result_without_target_evidence_is_recovery_not_protection() {
        let guard = backend(vec![BackendResult::Active {
            proof: proof(&[]),
            available_targets: available(),
            owned_workloads: owned(&[]),
            cleanup_confirmed: false,
        }]);
        let snapshot = guard.start("claude");
        assert_eq!(snapshot.state, "recovery");
        assert!(!snapshot.enforcement_verified);
        assert!(guard.authorize_target("claude").is_err());
    }

    struct DelayedBackend {
        started: mpsc::Sender<()>,
        release: StdMutex<mpsc::Receiver<()>>,
        cancelled: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Backend for DelayedBackend {
        fn execute(&self, action: BackendAction, token: ActionToken) -> BackendResult {
            if action == BackendAction::Start("claude") {
                let _ = self.started.send(());
                let _ = self.release.lock().unwrap().recv();
                self.cancelled
                    .store(!token.is_current(), Ordering::SeqCst);
                BackendResult::Active {
                    proof: proof(&["claude"]),
                    available_targets: available(),
                    owned_workloads: owned(&["claude"]),
                    cleanup_confirmed: false,
                }
            } else if action == BackendAction::Lock {
                BackendResult::Locked {
                    proof: proof(&["claude"]),
                    available_targets: available(),
                    owned_workloads: owned(&[]),
                    cleanup_confirmed: true,
                }
            } else {
                BackendResult::Recovery {
                    reason: "Recovery is required.".into(),
                    available_targets: available(),
                    owned_workloads: owned(&[]),
                    cleanup_confirmed: false,
                }
            }
        }
    }

    #[test]
    fn lock_request_cancels_a_pending_start_then_confirms_cleanup() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = Guard::with_backend(DelayedBackend {
            started: started_tx,
            release: StdMutex::new(release_rx),
            cancelled: cancelled.clone(),
        });
        let older = guard.clone();
        let worker = thread::spawn(move || older.start("claude"));
        started_rx.recv().unwrap();
        let lock_generation = guard.request_lock();
        let requested = guard.snapshot();
        assert_eq!(requested.state, "checking");
        assert!(!requested.enforcement_verified);
        release_tx.send(()).unwrap();
        let stale = worker.join().unwrap();
        assert_eq!(stale.state, "checking");
        assert!(!stale.enforcement_verified);
        assert!(stale.events.iter().any(|event| event.message.contains("stale")));
        assert!(cancelled.load(Ordering::SeqCst));
        let locked = guard.lock_after_request(lock_generation);
        assert_eq!(locked.state, "locked");
        assert!(locked.enforcement_verified);
        assert!(guard.can_quit());
    }

    #[test]
    fn inspect_never_promotes_success_and_revokes_on_adverse_evidence() {
        let mut unavailable = Guard::unavailable();
        unavailable.backend = Arc::new(FixedBackend(StdMutex::new(vec![
            BackendResult::Active {
                proof: proof(&["claude"]),
                available_targets: available(),
                owned_workloads: owned(&["claude"]),
                cleanup_confirmed: false,
            },
        ])));
        let unchanged = unavailable.inspect();
        assert_eq!(unchanged.state, "unavailable");
        assert!(!unchanged.enforcement_verified);
        assert!(unavailable.authorize_target("claude").is_err());

        let adverse = backend(vec![BackendResult::Unavailable {
            reason: "Protection was lost.".into(),
            available_targets: available(),
            owned_workloads: owned(&[]),
            cleanup_confirmed: true,
        }]);
        let revoked = adverse.inspect();
        assert_eq!(revoked.state, "unavailable");
        assert!(!revoked.enforcement_verified);
        assert!(adverse.authorize_target("claude").is_err());
    }

    #[test]
    fn inspect_revokes_state_or_target_coverage_mismatches() {
        let partial = backend(vec![BackendResult::Locked {
            proof: proof(&["claude"]),
            available_targets: available(),
            owned_workloads: owned(&[]),
            cleanup_confirmed: true,
        }]);
        let snapshot = partial.inspect();
        assert_eq!(snapshot.state, "recovery");
        assert!(!snapshot.enforcement_verified);
        assert!(partial.authorize_target("claude").is_err());

        let active_then_locked = backend(vec![
            BackendResult::Active {
                proof: proof(&["claude"]),
                available_targets: available(),
                owned_workloads: owned(&[]),
                cleanup_confirmed: false,
            },
            BackendResult::Locked {
                proof: proof(&["claude"]),
                available_targets: available(),
                owned_workloads: owned(&[]),
                cleanup_confirmed: true,
            },
        ]);
        assert_eq!(active_then_locked.start("claude").state, "active");
        let mismatch = active_then_locked.inspect();
        assert_eq!(mismatch.state, "recovery");
        assert!(!mismatch.enforcement_verified);
    }

    #[test]
    fn unexpected_action_results_enter_recovery_without_enforcement_proof() {
        let unexpected_start = backend(vec![BackendResult::Locked {
            proof: proof(&["claude"]),
            available_targets: available(),
            owned_workloads: owned(&[]),
            cleanup_confirmed: true,
        }]);
        let start = unexpected_start.start("claude");
        assert_eq!(start.state, "recovery");
        assert!(!start.enforcement_verified);

        let unexpected_lock = backend(vec![BackendResult::Active {
            proof: proof(&["claude"]),
            available_targets: available(),
            owned_workloads: owned(&["claude"]),
            cleanup_confirmed: false,
        }]);
        let locked = unexpected_lock.lock();
        assert_eq!(locked.state, "recovery");
        assert!(!locked.enforcement_verified);
        assert!(!unexpected_lock.can_quit());

        let unexpected_recover = backend(vec![BackendResult::Active {
            proof: proof(&["claude"]),
            available_targets: available(),
            owned_workloads: owned(&["claude"]),
            cleanup_confirmed: false,
        }]);
        let recovered = unexpected_recover.recover();
        assert_eq!(recovered.state, "recovery");
        assert!(!recovered.enforcement_verified);
    }

    #[test]
    fn lock_without_cleanup_confirmation_enters_recovery() {
        let guard = backend(vec![BackendResult::Locked {
            proof: proof(&["claude"]),
            available_targets: available(),
            owned_workloads: owned(&["claude"]),
            cleanup_confirmed: false,
        }]);
        let snapshot = guard.lock();
        assert_eq!(snapshot.state, "recovery");
        assert!(!snapshot.enforcement_verified);
        assert!(guard.authorize_target("claude").is_err());
        assert!(!guard.can_quit());
    }

    #[test]
    fn event_history_is_bounded_and_sequence_numbers_increase() {
        let guard = Guard::unavailable();
        for _ in 0..(MAX_EVENTS + 5) {
            let _ = guard.start("unknown");
        }
        let snapshot = guard.snapshot();
        assert_eq!(snapshot.events.len(), MAX_EVENTS);
        assert!(snapshot
            .events
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));
    }

    #[test]
    fn snapshot_serializes_the_public_camel_case_contract() {
        let value = serde_json::to_value(Guard::unavailable().snapshot()).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["state"], "unavailable");
        assert_eq!(value["enforcementVerified"], false);
        assert_eq!(value["observedIp"], serde_json::Value::Null);
        assert_eq!(value["observedAt"], serde_json::Value::Null);
        assert_eq!(value["portObservation"], serde_json::Value::Null);
        assert_eq!(value["targets"].as_array().unwrap().len(), TARGETS.len());
        assert!(value["events"][0]["sequence"].is_number());
        assert!(value["events"][0]["recordedAtUnixMs"].is_number());
    }

    #[test]
    fn inspection_keeps_the_original_failure_in_timestamped_history() {
        let guard = Guard::unavailable();
        let reason = "Full verification failed: observation_https_probe_ipinfo_status_28_cause_curl_timeout_phase_tls_elapsed_ms_5002";
        let snapshot = guard.apply_inspection(BackendResult::Recovery {
            reason: reason.into(), available_targets: HashSet::new(),
            owned_workloads: HashSet::new(), cleanup_confirmed: false,
        }, 0);
        let event = snapshot.events.last().unwrap();
        assert_eq!(event.message, reason);
        assert!(event.recorded_at_unix_ms.is_some_and(|time| time > 0));
        assert_eq!(snapshot.state, "recovery");
        assert!(!snapshot.enforcement_verified);
    }

    #[test]
    fn environment_mutation_discards_previous_readiness() {
        let guard = backend(vec![]);
        assert!(guard.authorize_target("claude").is_ok());
        guard.invalidate_readiness();
        assert!(guard.authorize_target("claude").is_err());
        assert!(!guard.snapshot().enforcement_verified);
    }

    struct FaultObserver(Arc<AtomicU64>);
    impl Backend for FaultObserver {
        fn execute(&self, _: BackendAction, _: ActionToken) -> BackendResult {
            panic!("Cached status must not execute probes or actions")
        }
        fn emergency_lock(&self) { self.0.fetch_add(1, Ordering::SeqCst); }
        fn observe(&self) -> Option<BackendResult> {
            Some(BackendResult::Recovery {
                reason: "Network changed".into(), available_targets: available(),
                owned_workloads: owned(&["claude"]), cleanup_confirmed: false,
            })
        }
    }

    #[test]
    fn cached_platform_fault_revokes_and_locks_without_probing() {
        let closed = Arc::new(AtomicU64::new(0));
        let guard = Guard::with_backend(FaultObserver(closed.clone()));
        let token = ActionToken { generation: 0, current_generation: guard.current_generation.clone() };
        assert_eq!(guard.refresh().state, "recovery");
        assert!(!token.is_current());
        assert!(!guard.snapshot().enforcement_verified);
        assert!(!guard.can_quit());
        let count = guard.snapshot().events.len();
        guard.refresh();
        assert_eq!(closed.load(Ordering::SeqCst), 1);
        assert_eq!(guard.snapshot().events.len(), count);
    }

    #[test]
    fn explicit_recovery_can_prepare_an_unavailable_session_closed() {
        let mut guard = Guard::unavailable();
        guard.backend = Arc::new(FixedBackend(StdMutex::new(vec![BackendResult::Locked {
            proof: proof(&["claude"]), available_targets: available(),
            owned_workloads: owned(&[]), cleanup_confirmed: true,
        }])));
        assert_eq!(guard.snapshot().state, "unavailable");
        assert_eq!(guard.recover().state, "locked");
        assert!(guard.can_quit());
    }


    struct ObservationBackend(StdMutex<Option<BackendResult>>);
    impl Backend for ObservationBackend {
        fn execute(&self, _: BackendAction, _: ActionToken) -> BackendResult { panic!("passive only") }
        fn observe(&self) -> Option<BackendResult> { self.0.lock().unwrap().take() }
    }

    fn observed_active(at: &str) -> BackendResult {
        BackendResult::Active {
            proof: VerifiedEnforcement { protected_targets: owned(&["claude"]),
                observed_ip: Some("192.0.2.1".into()), observed_at: Some(at.into()) },
            available_targets: available(), owned_workloads: owned(&["claude"]), cleanup_confirmed: false,
        }
    }

    #[test]
    fn passive_observation_refreshes_timestamp_but_cannot_create_a_permit() {
        let mut guard = Guard::unavailable();
        guard.backend = Arc::new(ObservationBackend(StdMutex::new(Some(observed_active("later")))));
        assert_eq!(guard.refresh().state, "unavailable");
        assert!(!guard.snapshot().enforcement_verified);
        let guard = Guard::with_backend(ObservationBackend(StdMutex::new(Some(observed_active("later")))));
        {
            let mut inner = guard.inner.lock().unwrap();
            inner.state = GuardState::Active;
            inner.proof = Some(VerifiedEnforcement { protected_targets: owned(&["claude"]),
                observed_ip: Some("192.0.2.1".into()), observed_at: Some("earlier".into()) });
        }
        let refreshed = guard.refresh();
        assert_eq!(refreshed.observed_at.as_deref(), Some("later"));
        assert_eq!(refreshed.state, "active");
        assert_eq!(guard.inner.lock().unwrap().proof.as_ref().unwrap().protected_targets, owned(&["claude"]));
    }


    #[test]
    fn asynchronous_cleanup_updates_same_fault_without_relocking_or_granting() {
        let report = |done| BackendResult::Recovery {
            reason: "Network changed".into(), available_targets: available(),
            owned_workloads: if done { owned(&[]) } else { owned(&["claude"]) },
            cleanup_confirmed: done,
        };
        let mut guard = Guard::with_backend(ObservationBackend(StdMutex::new(Some(report(false)))));
        guard.refresh();
        assert!(!guard.can_quit());
        let generation = guard.current_generation.load(Ordering::SeqCst);
        guard.backend = Arc::new(ObservationBackend(StdMutex::new(Some(report(true)))));
        assert_eq!(guard.refresh().state, "recovery");
        assert!(guard.can_quit());
        assert!(!guard.snapshot().enforcement_verified);
        assert_eq!(guard.current_generation.load(Ordering::SeqCst), generation);
    }


    #[test]
    #[ignore = "requires the explicit synthetic native inventory reason fixture"]
    fn inventory_evidence_fixture_crosses_the_snapshot_wire_boundary() {
        let input = std::env::var("GUARD_INVENTORY_REASON_FIXTURE").expect("native reason fixture");
        let reasons: Vec<String> = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
        assert_eq!(reasons.len(), 16);
        let mut snapshots = Vec::new();
        for reason in reasons {
            let guard = Guard::unavailable();
            let snapshot = guard.apply_inspection(BackendResult::Recovery {
                reason: reason.clone(), available_targets: available(), owned_workloads: owned(&["claude"]),
                cleanup_confirmed: false,
            }, 0);
            assert_eq!(snapshot.reason.as_deref(), Some(reason.as_str()));
            assert_eq!(snapshot.events.last().unwrap().message, reason);
            assert!(snapshot.events.iter().all(|event| event.message.chars().count() <= MAX_MESSAGE_CHARS));
            assert!(!snapshot.enforcement_verified && !guard.can_quit());
            assert!(guard.authorize_target("claude").is_err());
            snapshots.push(serde_json::to_value(snapshot).unwrap());
        }
        let output = std::env::var("GUARD_INVENTORY_SNAPSHOT_FIXTURE").expect("snapshot fixture output");
        std::fs::write(output, serde_json::to_vec(&snapshots).unwrap()).unwrap();
    }

    #[test]
    fn bounded_probe_history_retains_each_site_and_terminal_budget_cause() {
        let site = "https_probe_cloudflare_status_unavailable_cause_process_timeout_phase_proxy_connect_elapsed_ms_999999";
        let reason = format!("Full verification failed: observation_inspection_budget_exceeded_elapsed_ms_25000\n{}", [site; 4].join("\n"));
        assert!(reason.len() > 240 && reason.len() < MAX_MESSAGE_CHARS);
        assert_eq!(bounded(&reason), reason);
        assert_eq!(bounded(&"界".repeat(2_000)).chars().count(), MAX_MESSAGE_CHARS);
    }

}
