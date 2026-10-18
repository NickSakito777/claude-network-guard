// [INPUT]: Fixed installed-client metadata and system-managed Desktop settings.
// [OUTPUT]: Bounded configuration diagnostics and a proposed child-only CLI patch.
// [POS]: Read-only UI adapter; never creates a permit or changes client settings.
use crate::guard_privacy::{self as policy, CliLaunchOrigin, CliReadback, DesktopDeployment, DesktopReadback};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacySnapshot {
    desktop: ClientReport,
    cli: ClientReport,
    proposed_cli_environment: Vec<EnvironmentEdit>,
    runtime_verified: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientReport {
    installed_version: Option<String>,
    audited_version: &'static str,
    version_scope: &'static str,
    readback_scope: &'static str,
    channels: Vec<Channel>,
}

#[derive(Serialize)]
struct Channel {
    channel: &'static str,
    state: &'static str,
}

#[derive(Serialize)]
struct EnvironmentEdit {
    key: &'static str,
    value: Option<&'static str>,
}

fn bounded_version(text: &str) -> Option<String> {
    let text = text.trim();
    (text.len() <= 64 && !text.is_empty() && text.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        && text.split('.').all(|part| !part.is_empty()))
        .then(|| text.to_owned())
}

#[cfg(target_os = "macos")]
fn plist_field(path: &Path, key: &str) -> Option<serde_json::Value> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > 2 * 1024 * 1024 { return None; }
    // Only fixed field names reach plutil; no general config or secret dump.
    let output = std::process::Command::new("/usr/bin/plutil")
        .args(["-extract", key, "json", "-o", "-"]).arg(path)
        .env_clear().env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .output().ok()?;
    if !output.status.success() || output.stdout.len() > 8192 { return None; }
    let bytes = zeroize::Zeroizing::new(output.stdout);
    serde_json::from_slice(&bytes).ok()
}

#[cfg(not(target_os = "macos"))]
fn plist_field(_path: &Path, _key: &str) -> Option<serde_json::Value> { None }

fn cli_version_from_link(path: &Path) -> Option<String> {
    let resolved = path.canonicalize().ok()?;
    if !resolved.is_file() { return None; }
    bounded_version(resolved.file_name()?.to_str()?)
}

#[cfg(target_os = "macos")]
fn managed_flag(key: &str) -> Option<bool> {
    plist_field(Path::new("/Library/Managed Preferences/com.anthropic.claudefordesktop.plist"), key)
        .and_then(|value| value.as_bool())
}

#[cfg(target_os = "windows")]
fn managed_flag(key: &str) -> Option<bool> {
    use windows_sys::Win32::System::Registry::*;
    let path: Vec<u16> = "SOFTWARE\\Policies\\Claude\0".encode_utf16().collect();
    let name: Vec<u16> = key.encode_utf16().chain(Some(0)).collect();
    let mut value: u32 = 0;
    let mut size: u32 = 4;
    let status = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, path.as_ptr(), name.as_ptr(),
        RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, std::ptr::null_mut(),
        (&mut value as *mut u32).cast(), &mut size) };
    if status != 0 || size != 4 { return None; }
    match value { 0 => Some(false), 1 => Some(true), _ => None }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn managed_flag(_key: &str) -> Option<bool> { None }

#[cfg(target_os = "macos")]
fn managed_otlp() -> Option<bool> {
    plist_field(Path::new("/Library/Managed Preferences/com.anthropic.claudefordesktop.plist"), "otlpEndpoint")
        .and_then(|value| value.as_str().map(|text| !text.is_empty()))
}

#[cfg(target_os = "windows")]
fn managed_otlp() -> Option<bool> {
    use windows_sys::Win32::System::Registry::*;
    let path: Vec<u16> = "SOFTWARE\\Policies\\Claude\0".encode_utf16().collect();
    let name: Vec<u16> = "otlpEndpoint\0".encode_utf16().collect();
    let mut bytes: u32 = 0;
    let flags = RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY;
    let status = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, path.as_ptr(), name.as_ptr(), flags,
        std::ptr::null_mut(), std::ptr::null_mut(), &mut bytes) };
    if status != 0 || bytes < 2 || bytes > 8192 || bytes % 2 != 0 { return None; }
    let mut buffer = zeroize::Zeroizing::new(vec![0u16; bytes as usize / 2]);
    let capacity = bytes;
    let status = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, path.as_ptr(), name.as_ptr(), flags,
        std::ptr::null_mut(), buffer.as_mut_ptr().cast(), &mut bytes) };
    if status != 0 || bytes > capacity || bytes % 2 != 0 { return None; }
    let count = bytes as usize / 2;
    let end = buffer[..count].iter().position(|unit| *unit == 0)?;
    std::char::decode_utf16(buffer[..end].iter().copied()).collect::<Result<String, _>>()
        .ok().map(|text| !text.is_empty())
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn managed_otlp() -> Option<bool> { None }

fn compose(
    desktop_version: Option<String>, cli_version: Option<String>,
    essential: Option<bool>, nonessential: Option<bool>, updates: Option<bool>,
    otlp: Option<bool>,
) -> PrivacySnapshot {
    // A local preference file alone cannot establish the effective deployment mode
    // or prove that a server policy/another source did not override it.
    let desktop = policy::diagnose_desktop(DesktopReadback {
        version: desktop_version.as_deref(), deployment: DesktopDeployment::Unknown,
        disable_essential_telemetry: essential, disable_nonessential_telemetry: nonessential,
        disable_auto_updates: updates, otlp_endpoint_configured: otlp,
    });
    let cli = policy::diagnose_cli(CliReadback {
        version: cli_version.as_deref(), launch_origin: CliLaunchOrigin::Unknown,
        nonessential_traffic_disabled: None, otel_enabled: None,
        otel_exporter_configured: None, beta_tracing_configured: None,
        remote_otlp_relay_configured: None,
    });
    let channels = |items: &[policy::ChannelReport]| items.iter().map(|item| Channel {
        channel: item.channel, state: item.state.as_str(),
    }).collect();
    PrivacySnapshot {
        desktop: ClientReport {
            installed_version: desktop_version, audited_version: policy::AUDITED_DESKTOP_VERSION,
            version_scope: desktop.version_scope.as_str(),
            readback_scope: if cfg!(windows) { "machine_registry_only_effective_policy_unknown" }
                else { "system_preferences_only_effective_policy_unknown" },
            channels: channels(&desktop.channels),
        },
        cli: ClientReport {
            installed_version: cli_version, audited_version: policy::AUDITED_CLI_VERSION,
            version_scope: cli.version_scope.as_str(),
            readback_scope: "managed_process_not_observed",
            channels: channels(&cli.channels),
        },
        proposed_cli_environment: policy::cli_environment_patch().iter().map(|item| EnvironmentEdit {
            key: item.key, value: item.value,
        }).collect(),
        runtime_verified: false,
    }
}

fn inspect() -> PrivacySnapshot {
    let version_file = Path::new("/Applications/Claude.app/Contents/Info.plist");
    let desktop_version = plist_field(version_file, "CFBundleShortVersionString")
        .as_ref().and_then(serde_json::Value::as_str).and_then(bounded_version);
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" });
    let cli_version = home.map(PathBuf::from)
        .and_then(|home| cli_version_from_link(&home.join(".local/bin/claude")));
    compose(desktop_version, cli_version, managed_flag("disableEssentialTelemetry"),
        managed_flag("disableNonessentialTelemetry"), managed_flag("disableAutoUpdates"), managed_otlp())
}

#[tauri::command]
pub async fn guard_privacy_inspect() -> Result<PrivacySnapshot, String> {
    tauri::async_runtime::spawn_blocking(inspect).await
        .map_err(|_| "遥测配置读取被中断。".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_flags_never_promote_unknown_effective_policy_to_runtime_verification() {
        let snapshot = compose(Some(policy::AUDITED_DESKTOP_VERSION.into()),
            Some(policy::AUDITED_CLI_VERSION.into()), Some(true), Some(true), Some(true), Some(false));
        let json = serde_json::to_value(snapshot).unwrap();
        assert_eq!(json["runtimeVerified"], false);
        assert!(json["desktop"]["channels"].as_array().unwrap().iter().all(|x| x["state"] == "unknown"));
        assert!(json["cli"]["channels"].as_array().unwrap().iter()
            .filter(|x| x["channel"] != "cli_model_requests").all(|x| x["state"] == "unknown"));
    }
    #[test]
    fn versions_are_metadata_not_commands_and_missing_metadata_stays_unknown() {
        assert_eq!(bounded_version(" 2.110.0\n"), Some("2.110.0".into()));
        for bad in ["", "2..1", "2.1;id", "$(id)", "secret=value", "2\n1"] {
            assert!(bounded_version(bad).is_none());
        }
        let snapshot = compose(None, None, None, None, None, None);
        assert_eq!(snapshot.desktop.version_scope, "unknown_version");
        assert!(!snapshot.runtime_verified);
    }
}
