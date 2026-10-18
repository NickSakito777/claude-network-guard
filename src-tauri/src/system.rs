// [INPUT]: macOS/Linux/Windows 电脑设置桥、Cleaner 租约、Guard 状态与 Tauri 后台任务。
// [OUTPUT]: 电脑状态查询、系统设置入口，以及当前可用目标均锁定后的时区/语言/定位/区域修改。
// [POS]: 只读事实和修复设置入口保持可用；系统变更要求已配置目标覆盖且清理已确认。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
#[cfg(target_os = "linux")]
use crate::linux::*;
#[cfg(target_os = "windows")]
use crate::windows::*;
use crate::native::decode;
#[cfg(target_os = "macos")]
use std::ffi::c_char;
use std::ffi::CString;
#[cfg(target_os = "macos")]
extern "C" {
    fn rf_system_region(language: *const c_char, locale: *const c_char) -> *mut c_char;
    fn rf_system_read() -> *mut c_char;
    fn rf_system_open(pane: *const c_char) -> *mut c_char;
    fn rf_system_language(language: *const c_char) -> *mut c_char;
    fn rf_system_timezone(timezone: *const c_char) -> *mut c_char;
    fn rf_system_location() -> *mut c_char;
}
async fn run(
    action: impl FnOnce() -> Result<serde_json::Value, String> + Send + 'static,
) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(action)
        .await
        .map_err(|_| "系统操作被中断，请刷新当前状态。".to_string())?
}
#[tauri::command]
pub async fn system_read() -> Result<serde_json::Value, String> {
    run(|| decode(unsafe { rf_system_read() })).await
}
#[tauri::command]
pub async fn system_open_settings(pane: String) -> Result<serde_json::Value, String> {
    run(move || {
        let pane = CString::new(pane).map_err(|_| "系统设置入口无效。")?;
        decode(unsafe { rf_system_open(pane.as_ptr()) })
    })
    .await
}
#[tauri::command]
pub async fn system_set_language(
    app: tauri::AppHandle,
    language: String,
) -> Result<serde_json::Value, String> {
    run(move || {
        let _operation = crate::cleaner::fully_guarded_lease(&app)?;
        let language = CString::new(language).map_err(|_| "语言无效。")?;
        decode(unsafe { rf_system_language(language.as_ptr()) })
    })
    .await
}
#[tauri::command]
pub async fn system_set_timezone(
    app: tauri::AppHandle,
    timezone: String,
) -> Result<serde_json::Value, String> {
    run(move || {
        let _operation = crate::cleaner::fully_guarded_lease(&app)?;
        let timezone = CString::new(timezone).map_err(|_| "时区无效。")?;
        decode(unsafe { rf_system_timezone(timezone.as_ptr()) })
    })
    .await
}
#[tauri::command]
pub async fn system_disable_location(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    run(move || {
        let _operation = crate::cleaner::fully_guarded_lease(&app)?;
        decode(unsafe { rf_system_location() })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_native_state_and_rejects_invalid_inputs_without_mutation() {
        let state: serde_json::Value = decode(unsafe { rf_system_read() }).unwrap();
        assert!(state["timezone"].as_str().is_some());
        assert!(state["timezones"].as_array().unwrap().len() > if cfg!(windows) { 30 } else { 100 });
        assert!(state["languages"].is_array());
        assert!(state["location_enabled"].is_boolean() || state["location_enabled"].is_null());
        let invalid = CString::new("Invalid/Zone; touch /tmp/rf-injected").unwrap();
        assert!(
            decode::<serde_json::Value>(unsafe { rf_system_timezone(invalid.as_ptr()) }).is_err()
        );
        assert!(
            decode::<serde_json::Value>(unsafe { rf_system_language(invalid.as_ptr()) }).is_err()
        );
        assert!(decode::<serde_json::Value>(unsafe { rf_system_open(invalid.as_ptr()) }).is_err());
    }
}

#[tauri::command]
pub async fn system_set_region(
    app: tauri::AppHandle,
    region: String,
) -> Result<serde_json::Value, String> {
    let region = crate::regions::find(&region)?;
    run(move || {
        let _operation = crate::cleaner::fully_guarded_lease(&app)?;
        let zone = CString::new(region.timezone).unwrap();
        let language = CString::new(region.language).unwrap();
        let locale = CString::new(region.locale).unwrap();
        #[cfg(target_os = "linux")]
        let _: serde_json::Value =
            decode(unsafe { rf_system_region(language.as_ptr(), locale.as_ptr()) })?;
        let _: serde_json::Value = decode(unsafe { rf_system_timezone(zone.as_ptr()) })?;
        let result = decode(unsafe { rf_system_region(language.as_ptr(), locale.as_ptr()) });
        result.map_err(|error| format!("时区已修改；{error}"))
    })
    .await
}
