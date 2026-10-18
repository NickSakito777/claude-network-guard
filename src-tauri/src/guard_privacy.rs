// [INPUT]: Version-scoped, secret-free telemetry control readbacks and a Guard-owned CLI launch context.
// [OUTPUT]: Child-process environment edits and bounded telemetry configuration diagnostics.
// [POS]: Pure policy only; no environment, config, identity, network, or system access.
// [PROTOCOL]: Keep audit-version bounds explicit; configuration intent never proves runtime enforcement.

pub const AUDITED_DESKTOP_VERSION: &str = "2.9939.2";
pub const AUDITED_CLI_VERSION: &str = "2.1.283";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlState {
    ConfiguredOff,
    Open,
    Unknown,
}

impl ControlState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfiguredOff => "configured_off",
            Self::Open => "open",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionScope {
    AuditVersion,
    CandidateVersion,
    UnknownVersion,
}

impl VersionScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditVersion => "audit_version",
            Self::CandidateVersion => "candidate_version",
            Self::UnknownVersion => "unknown_version",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopDeployment {
    FirstParty,
    ThirdParty,
    Unknown,
}

impl DesktopDeployment {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstParty => "first_party",
            Self::ThirdParty => "third_party",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliLaunchOrigin {
    GuardDirect,
    DesktopManaged,
    Unknown,
}

impl CliLaunchOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GuardDirect => "guard_direct",
            Self::DesktopManaged => "desktop_managed_candidate",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvironmentEdit {
    pub key: &'static str,
    /// `Some(value)` sets the key for one child process; `None` removes only that child key.
    pub value: Option<&'static str>,
}

const CLI_HARDENING_PATCH: &[EnvironmentEdit] = &[
    EnvironmentEdit {
        key: "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        value: Some("1"),
    },
    EnvironmentEdit { key: "DISABLE_GROWTHBOOK", value: Some("1") },
    EnvironmentEdit { key: "DISABLE_ERROR_REPORTING", value: Some("1") },
    EnvironmentEdit { key: "CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS", value: Some("1") },
    EnvironmentEdit {
        key: "CLAUDE_CODE_ENABLE_TELEMETRY",
        value: Some("false"),
    },
    EnvironmentEdit {
        key: "OTEL_LOGS_EXPORTER",
        value: Some("none"),
    },
    EnvironmentEdit {
        key: "ANT_OTEL_LOGS_EXPORTER",
        value: Some("none"),
    },
    EnvironmentEdit {
        key: "OTEL_METRICS_EXPORTER",
        value: Some("none"),
    },
    EnvironmentEdit {
        key: "OTEL_TRACES_EXPORTER",
        value: Some("none"),
    },
    EnvironmentEdit {
        key: "OTEL_LOG_RAW_API_BODIES",
        value: Some("false"),
    },
    EnvironmentEdit {
        key: "OTEL_LOG_USER_PROMPTS",
        value: Some("false"),
    },
    EnvironmentEdit {
        key: "OTEL_LOG_ASSISTANT_RESPONSES",
        value: Some("false"),
    },
    EnvironmentEdit {
        key: "OTEL_LOG_TOOL_CONTENT",
        value: Some("false"),
    },
    EnvironmentEdit {
        key: "OTEL_LOG_TOOL_DETAILS",
        value: Some("false"),
    },
    EnvironmentEdit {
        key: "OTEL_LOG_MANAGED_SETTINGS",
        value: Some("false"),
    },
    EnvironmentEdit {
        key: "ENABLE_BETA_TRACING_DETAILED",
        value: None,
    },
    EnvironmentEdit {
        key: "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA",
        value: None,
    },
    EnvironmentEdit {
        key: "ENABLE_ENHANCED_TELEMETRY_BETA",
        value: None,
    },
    EnvironmentEdit {
        key: "BETA_TRACING_ENDPOINT",
        value: None,
    },
];

/// Return the minimal telemetry edits for a single Claude Code child process.
/// The caller must apply these after inherited/host-composed values and must not mutate its own env.
pub const fn cli_environment_patch() -> &'static [EnvironmentEdit] {
    CLI_HARDENING_PATCH
}

pub fn apply_cli_environment(command: &mut std::process::Command) {
    for edit in cli_environment_patch() {
        match edit.value {
            Some(value) => { command.env(edit.key, value); }
            None => { command.env_remove(edit.key); }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelReport {
    pub channel: &'static str,
    pub state: ControlState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliReadback<'a> {
    pub version: Option<&'a str>,
    pub launch_origin: CliLaunchOrigin,
    /// Combined effect of CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC, DISABLE_TELEMETRY and DO_NOT_TRACK.
    pub nonessential_traffic_disabled: Option<bool>,
    /// Parsed truth state only; never pass the raw environment string.
    pub otel_enabled: Option<bool>,
    /// Whether at least one OTEL exporter is active, based on exporter names only.
    pub otel_exporter_configured: Option<bool>,
    /// Whether a beta tracing enable flag and its required endpoint are both effective.
    pub beta_tracing_configured: Option<bool>,
    /// Presence-only result for remote/gateway OTLP relay prerequisites; do not pass endpoint values.
    pub remote_otlp_relay_configured: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliPrivacyReport {
    pub version_scope: VersionScope,
    pub launch_origin: CliLaunchOrigin,
    pub channels: [ChannelReport; 9],
    /// Configuration-intent summary only. Model requests remain open and runtime enforcement is not measured.
    pub telemetry_channels_configured_off: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopReadback<'a> {
    pub version: Option<&'a str>,
    pub deployment: DesktopDeployment,
    pub disable_essential_telemetry: Option<bool>,
    pub disable_nonessential_telemetry: Option<bool>,
    pub disable_auto_updates: Option<bool>,
    /// Presence-only check. The endpoint itself is never accepted or returned.
    pub otlp_endpoint_configured: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopPrivacyReport {
    pub version_scope: VersionScope,
    pub deployment: DesktopDeployment,
    pub channels: [ChannelReport; 4],
    /// True only for complete off-intent readback on audited Desktop 2.9939.2 in third-party mode.
    /// This does not mean requests were blocked or runtime behavior was verified.
    pub configuration_intent_complete: bool,
}

fn version_scope(version: Option<&str>, audited: &str) -> VersionScope {
    match version {
        Some(version) if version == audited => VersionScope::AuditVersion,
        Some(_) => VersionScope::CandidateVersion,
        None => VersionScope::UnknownVersion,
    }
}

fn disabled_control(value: Option<bool>) -> ControlState {
    match value {
        Some(true) => ControlState::ConfiguredOff,
        Some(false) => ControlState::Open,
        None => ControlState::Unknown,
    }
}

fn configured_presence(value: Option<bool>) -> ControlState {
    match value {
        Some(true) => ControlState::Open,
        Some(false) => ControlState::ConfiguredOff,
        None => ControlState::Unknown,
    }
}

fn prerequisite_pair(first: Option<bool>, second: Option<bool>) -> ControlState {
    match (first, second) {
        (Some(true), Some(true)) => ControlState::Open,
        (Some(false), _) | (_, Some(false)) => ControlState::ConfiguredOff,
        _ => ControlState::Unknown,
    }
}

fn channel(channel: &'static str, state: ControlState) -> ChannelReport {
    ChannelReport { channel, state }
}

/// Diagnose only the provided, secret-free CLI readback. No OS state is read here.
pub fn diagnose_cli(input: CliReadback<'_>) -> CliPrivacyReport {
    let version_scope = version_scope(input.version, AUDITED_CLI_VERSION);
    let host_can_override = input.launch_origin != CliLaunchOrigin::GuardDirect;
    let state = |candidate: ControlState| {
        if host_can_override {
            ControlState::Unknown
        } else {
            candidate
        }
    };
    let nonessential = state(disabled_control(input.nonessential_traffic_disabled));
    let otel = state(prerequisite_pair(input.otel_enabled, input.otel_exporter_configured));
    let beta = state(configured_presence(input.beta_tracing_configured));
    let remote = configured_presence(input.remote_otlp_relay_configured);
    let channels = [
        channel("cli_first_party_events", nonessential),
        channel("cli_datadog_logs", nonessential),
        channel("cli_datadog_errors", nonessential),
        channel("cli_internal_metrics", nonessential),
        channel("cli_growthbook", nonessential),
        channel("cli_otel_exporters", otel),
        channel("cli_beta_tracing", beta),
        channel("cli_remote_gateway_otlp_relay", remote),
        channel("cli_model_requests", ControlState::Open),
    ];
    let telemetry_channels_configured_off = version_scope == VersionScope::AuditVersion
        && input.launch_origin == CliLaunchOrigin::GuardDirect
        && channels[..8]
            .iter()
            .all(|item| item.state == ControlState::ConfiguredOff);
    CliPrivacyReport {
        version_scope,
        launch_origin: input.launch_origin,
        channels,
        telemetry_channels_configured_off,
    }
}

/// Diagnose managed Desktop control readback without reading files or endpoint contents.
pub fn diagnose_desktop(input: DesktopReadback<'_>) -> DesktopPrivacyReport {
    let version_scope = version_scope(input.version, AUDITED_DESKTOP_VERSION);
    let supported_version = version_scope == VersionScope::AuditVersion;
    let third_party_controls_supported = supported_version
        && input.deployment == DesktopDeployment::ThirdParty;
    let deployment_known = input.deployment != DesktopDeployment::Unknown;

    let essential = if third_party_controls_supported {
        disabled_control(input.disable_essential_telemetry)
    } else {
        ControlState::Unknown
    };
    let nonessential = if third_party_controls_supported {
        disabled_control(input.disable_nonessential_telemetry)
    } else {
        ControlState::Unknown
    };
    let updates = if supported_version && deployment_known {
        disabled_control(input.disable_auto_updates)
    } else {
        ControlState::Unknown
    };
    let otlp = if third_party_controls_supported {
        configured_presence(input.otlp_endpoint_configured)
    } else {
        ControlState::Unknown
    };
    let channels = [
        channel("desktop_sentry", essential),
        channel("desktop_product_and_diagnostic_events", nonessential),
        channel("desktop_auto_updates", updates),
        channel("desktop_otlp_export", otlp),
    ];
    let configuration_intent_complete = supported_version
        && input.deployment == DesktopDeployment::ThirdParty
        && channels
            .iter()
            .all(|item| item.state == ControlState::ConfiguredOff);
    DesktopPrivacyReport {
        version_scope,
        deployment: input.deployment,
        channels,
        configuration_intent_complete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel_state(reports: &[ChannelReport], name: &str) -> ControlState {
        reports.iter().find(|item| item.channel == name).unwrap().state
    }

    fn closed_cli_readback() -> CliReadback<'static> {
        CliReadback {
            version: Some(AUDITED_CLI_VERSION),
            launch_origin: CliLaunchOrigin::GuardDirect,
            nonessential_traffic_disabled: Some(true),
            otel_enabled: Some(false),
            otel_exporter_configured: Some(false),
            beta_tracing_configured: Some(false),
            remote_otlp_relay_configured: Some(false),
        }
    }

    #[test]
    fn launch_patch_is_child_scoped_and_covers_the_documented_cli_controls() {
        let patch = cli_environment_patch();
        let value = |key: &str| patch.iter().find(|edit| edit.key == key).unwrap().value;
        assert_eq!(value("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"), Some("1"));
        assert_eq!(value("CLAUDE_CODE_ENABLE_TELEMETRY"), Some("false"));
        assert_eq!(value("OTEL_LOGS_EXPORTER"), Some("none"));
        assert_eq!(value("ANT_OTEL_LOGS_EXPORTER"), Some("none"));
        assert_eq!(value("OTEL_METRICS_EXPORTER"), Some("none"));
        assert_eq!(value("OTEL_TRACES_EXPORTER"), Some("none"));
        for key in [
            "OTEL_LOG_RAW_API_BODIES",
            "OTEL_LOG_USER_PROMPTS",
            "OTEL_LOG_ASSISTANT_RESPONSES",
            "OTEL_LOG_TOOL_CONTENT",
            "OTEL_LOG_TOOL_DETAILS",
            "OTEL_LOG_MANAGED_SETTINGS",
        ] {
            assert_eq!(value(key), Some("false"));
        }
        for key in ["ENABLE_BETA_TRACING_DETAILED", "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA", "ENABLE_ENHANCED_TELEMETRY_BETA"] {
            assert_eq!(value(key), None);
        }
        assert_eq!(value("BETA_TRACING_ENDPOINT"), None);
        assert!(patch.iter().all(|edit| edit.key != "CI"));
        assert!(patch.iter().all(|edit| !edit.key.contains("TOKEN") && !edit.key.contains("KEY")));
    }

    #[test]
    fn child_patch_overrides_tracing_without_touching_credentials_or_parent_environment() {
        use std::ffi::OsStr;
        let parent_before = std::env::var_os("ENABLE_BETA_TRACING_DETAILED");
        let mut command = std::process::Command::new("fixture-not-executed");
        command.env("ANTHROPIC_AUTH_TOKEN", "fixture-secret").env("PATH", "/fixture/bin")
            .env("ENABLE_BETA_TRACING_DETAILED", "1").env("OTEL_LOGS_EXPORTER", "otlp");
        apply_cli_environment(&mut command);
        let env: std::collections::HashMap<_, _> = command.get_envs().collect();
        assert_eq!(env.get(OsStr::new("ANTHROPIC_AUTH_TOKEN")), Some(&Some(OsStr::new("fixture-secret"))));
        assert_eq!(env.get(OsStr::new("PATH")), Some(&Some(OsStr::new("/fixture/bin"))));
        assert_eq!(env.get(OsStr::new("ENABLE_BETA_TRACING_DETAILED")), Some(&None));
        assert_eq!(env.get(OsStr::new("OTEL_LOGS_EXPORTER")), Some(&Some(OsStr::new("none"))));
        assert_eq!(std::env::var_os("ENABLE_BETA_TRACING_DETAILED"), parent_before);
    }

    #[test]
    fn cli_report_separates_telemetry_from_model_requests() {
        let report = diagnose_cli(closed_cli_readback());
        for name in [
            "cli_first_party_events",
            "cli_datadog_logs",
            "cli_datadog_errors",
            "cli_internal_metrics",
            "cli_growthbook",
            "cli_otel_exporters",
            "cli_beta_tracing",
            "cli_remote_gateway_otlp_relay",
        ] {
            assert_eq!(channel_state(&report.channels, name), ControlState::ConfiguredOff);
        }
        assert_eq!(
            channel_state(&report.channels, "cli_model_requests"),
            ControlState::Open
        );
        assert!(report.telemetry_channels_configured_off);
    }

    #[test]
    fn desktop_managed_cli_is_unknown_even_when_parent_readback_looks_closed() {
        let mut input = closed_cli_readback();
        input.launch_origin = CliLaunchOrigin::DesktopManaged;
        let report = diagnose_cli(input);
        assert_eq!(report.launch_origin, CliLaunchOrigin::DesktopManaged);
        assert_eq!(
            channel_state(&report.channels, "cli_first_party_events"),
            ControlState::Unknown
        );
        assert_eq!(
            channel_state(&report.channels, "cli_otel_exporters"),
            ControlState::Unknown
        );
        assert!(!report.telemetry_channels_configured_off);
    }

    #[test]
    fn candidate_cli_version_never_completes_the_audit_configuration() {
        let mut input = closed_cli_readback();
        input.version = Some("2.1.296");
        let report = diagnose_cli(input);
        assert_eq!(report.version_scope, VersionScope::CandidateVersion);
        assert!(!report.telemetry_channels_configured_off);
    }

    #[test]
    fn open_cli_controls_and_remote_relay_are_reported_without_values() {
        let report = diagnose_cli(CliReadback {
            version: Some(AUDITED_CLI_VERSION),
            launch_origin: CliLaunchOrigin::GuardDirect,
            nonessential_traffic_disabled: Some(false),
            otel_enabled: Some(true),
            otel_exporter_configured: Some(true),
            beta_tracing_configured: Some(true),
            remote_otlp_relay_configured: Some(true),
        });
        assert_eq!(
            channel_state(&report.channels, "cli_growthbook"),
            ControlState::Open
        );
        assert_eq!(
            channel_state(&report.channels, "cli_otel_exporters"),
            ControlState::Open
        );
        assert_eq!(
            channel_state(&report.channels, "cli_beta_tracing"),
            ControlState::Open
        );
        assert_eq!(
            channel_state(&report.channels, "cli_remote_gateway_otlp_relay"),
            ControlState::Open
        );
        assert!(!report.telemetry_channels_configured_off);
    }

    #[test]
    fn missing_cli_readback_is_unknown() {
        let report = diagnose_cli(CliReadback {
            version: None,
            launch_origin: CliLaunchOrigin::Unknown,
            nonessential_traffic_disabled: None,
            otel_enabled: None,
            otel_exporter_configured: None,
            beta_tracing_configured: None,
            remote_otlp_relay_configured: None,
        });
        assert_eq!(report.version_scope, VersionScope::UnknownVersion);
        assert_eq!(
            channel_state(&report.channels, "cli_growthbook"),
            ControlState::Unknown
        );
        assert_eq!(
            channel_state(&report.channels, "cli_remote_gateway_otlp_relay"),
            ControlState::Unknown
        );
        assert!(!report.telemetry_channels_configured_off);
    }

    fn closed_desktop_readback() -> DesktopReadback<'static> {
        DesktopReadback {
            version: Some(AUDITED_DESKTOP_VERSION),
            deployment: DesktopDeployment::ThirdParty,
            disable_essential_telemetry: Some(true),
            disable_nonessential_telemetry: Some(true),
            disable_auto_updates: Some(true),
            otlp_endpoint_configured: Some(false),
        }
    }

    #[test]
    fn audited_third_party_desktop_can_report_only_complete_configuration_intent() {
        let report = diagnose_desktop(closed_desktop_readback());
        assert_eq!(report.version_scope, VersionScope::AuditVersion);
        assert!(report.configuration_intent_complete);
        assert!(report
            .channels
            .iter()
            .all(|item| item.state == ControlState::ConfiguredOff));
    }

    #[test]
    fn desktop_version_or_deployment_gaps_stay_unknown_and_never_complete() {
        let mut version_unknown = closed_desktop_readback();
        version_unknown.version = None;
        let report = diagnose_desktop(version_unknown);
        assert_eq!(report.version_scope, VersionScope::UnknownVersion);
        assert!(report
            .channels
            .iter()
            .all(|item| item.state == ControlState::Unknown));
        assert!(!report.configuration_intent_complete);

        let mut deployment_unknown = closed_desktop_readback();
        deployment_unknown.deployment = DesktopDeployment::Unknown;
        let report = diagnose_desktop(deployment_unknown);
        assert!(report
            .channels
            .iter()
            .all(|item| item.state == ControlState::Unknown));
        assert!(!report.configuration_intent_complete);
    }

    #[test]
    fn desktop_candidate_version_and_first_party_mode_do_not_green_light_3p_controls() {
        let mut candidate = closed_desktop_readback();
        candidate.version = Some("2.110.0");
        let report = diagnose_desktop(candidate);
        assert_eq!(report.version_scope, VersionScope::CandidateVersion);
        assert!(report
            .channels
            .iter()
            .all(|item| item.state == ControlState::Unknown));
        assert!(!report.configuration_intent_complete);

        let mut first_party = closed_desktop_readback();
        first_party.deployment = DesktopDeployment::FirstParty;
        let report = diagnose_desktop(first_party);
        assert_eq!(
            channel_state(&report.channels, "desktop_sentry"),
            ControlState::Unknown
        );
        assert_eq!(
            channel_state(&report.channels, "desktop_auto_updates"),
            ControlState::ConfiguredOff
        );
        assert!(!report.configuration_intent_complete);
    }

    #[test]
    fn desktop_reports_open_controls_and_configured_collector() {
        let report = diagnose_desktop(DesktopReadback {
            version: Some(AUDITED_DESKTOP_VERSION),
            deployment: DesktopDeployment::ThirdParty,
            disable_essential_telemetry: Some(false),
            disable_nonessential_telemetry: Some(false),
            disable_auto_updates: Some(true),
            otlp_endpoint_configured: Some(true),
        });
        assert_eq!(
            channel_state(&report.channels, "desktop_sentry"),
            ControlState::Open
        );
        assert_eq!(
            channel_state(&report.channels, "desktop_otlp_export"),
            ControlState::Open
        );
        assert!(!report.configuration_intent_complete);
    }
}
