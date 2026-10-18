// [INPUT]: Platform boundaries, Tauri lifecycle, native Guard state and operation gates, identity/CLI/browser/system commands, and UI language.
// [OUTPUT]: CCBaga-A window and tray, guarded native command registry, identity/CLI operations, fixed resource entry, and startup diagnostics.
// [POS]: 应用编排层；不注册翻译快捷键，不读取翻译设置或 API 密钥。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
// ----- 发布包必须内嵌前端资源，禁止依赖开发服务 -----
#[cfg(all(not(debug_assertions), not(feature = "custom-protocol")))]
compile_error!("发布构建需要 custom-protocol；使用 tauri build 或 cargo build --release --features custom-protocol。");
mod browser;
mod claude_cli;
mod cleaner;
mod guard;
mod guard_privacy;
mod guard_privacy_readback;
#[cfg(target_os = "macos")]
mod guard_macos;
#[cfg(any(target_os = "windows", test))]
mod guard_windows;
#[cfg(any(target_os = "windows", test))]
mod guard_windows_launch;
mod identities;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;
mod native;
mod progress;
mod regions;
mod system;
mod ui_language;
#[cfg(test)]
mod updater_tests;
mod network_links;
use tauri::{tray::TrayIconBuilder, Manager};
fn show(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}
#[tauri::command]
async fn open_permissions(app: tauri::AppHandle) -> Result<(), String> {
    let (send, receive) = tokio::sync::oneshot::channel();
    app.run_on_main_thread(move || {
        let _ = send.send(native::permissions());
    })
    .map_err(|_| "无法打开系统权限设置。")?;
    receive.await.map_err(|_| "无法打开系统权限设置。")?
}
#[tauri::command]
async fn unlock_keychain() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(native::unlock_keychain)
        .await
        .map_err(|_| "钥匙串授权被中断。".to_string())?
}
#[tauri::command]
async fn copy_result(app: tauri::AppHandle, text: String) -> Result<(), String> {
    let (send, receive) = tokio::sync::oneshot::channel();
    app.run_on_main_thread(move || {
        let _ = send.send(native::copy(&text));
    })
    .map_err(|_| "复制失败。")?;
    receive.await.map_err(|_| "复制失败。")?
}
#[tauri::command]
fn runtime_platform() -> &'static str {
    std::env::consts::OS
}
pub(crate) fn startup_trace(stage: &str) {
    #[cfg(windows)]
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        // CI 只记录固定启动阶段，不读取文件正文、参数或凭据。
        let path = std::env::temp_dir().join("ccbaga-ci-startup.log");
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            use std::io::Write;
            let _ = writeln!(file, "{stage}");
        }
    }
    let _ = stage;
}
fn main() {
    startup_trace("host entry");
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _| {
            #[cfg(target_os = "linux")]
            if args.iter().any(|arg| arg == "--browser") {
                browser::open_urls(app.clone(), args);
                return;
            }
            #[cfg(target_os = "windows")]
            if args.iter().any(|arg| arg == "--browser") {
                browser::open_urls(app.clone(), args);
                return;
            }
            let _ = args;
            show(app)
        }))
        .setup(|app| {
            startup_trace("host setup");
            app.manage(ui_language::UiLanguage::load(app.handle()));
            app.manage(cleaner::Cleaner::default());
            app.manage(guard::Guard::platform());
            app.manage(browser::Browser::default());
            #[cfg(target_os = "macos")]
            browser::companion(app.handle().clone());
            #[cfg(target_os = "linux")]
            browser::open_urls(app.handle().clone(), std::env::args().collect());
            #[cfg(target_os = "windows")]
            browser::open_urls(app.handle().clone(), std::env::args().collect());
            let menu = ui_language::menu(
                app.handle(),
                &ui_language::ui_language_read(app.handle().clone()),
            )?;
            TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("Guard")
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "open" => show(app),
                    "quit" => guard::request_quit(app.clone()),
                    _ => {}
                })
                .build(app)?;
            startup_trace("host ready");
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            ui_language::ui_language_read,
            ui_language::ui_language_write,
            runtime_platform,
            guard::guard_status,
            guard::guard_inspect,
            guard::guard_start,
            guard::guard_lock,
            guard::guard_recover,
            guard_privacy_readback::guard_privacy_inspect,
            open_permissions,
            unlock_keychain,
            copy_result,
            cleaner::cleaner_scan,
            cleaner::cleaner_stop,
            cleaner::cleaner_processes,
            identities::identities_read,
            identities::identities_switch,
            identities::identities_rename,
            identities::identities_delete,
            identities::identities_browser,
            claude_cli::claude_cli_read,
            claude_cli::claude_cli_manage,
            regions::get_regions,
            system::system_read,
            system::system_set_timezone,
            system::system_set_language,
            system::system_disable_location,
            system::system_open_settings,
            system::system_set_region,
            browser::browser_read,
            browser::browser_save,
            browser::browser_launch,
            browser::browser_quit,
            browser::browser_clear,
            browser::browser_check,
            browser::browser_align,
            browser::browser_default_read,
            browser::browser_set_default,
            browser::browser_rotate,
            network_links::network_open_resource
        ])
        .build(tauri::generate_context!())
        .expect("无法启动 Guard")
        .run(|app, event| match event {
            tauri::RunEvent::ExitRequested { api, .. } if !guard::may_quit(app) => {
                api.prevent_exit();
                guard::request_quit(app.clone());
            }
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { .. } => show(app),
            tauri::RunEvent::Exit => browser::forget_start_url(app),
            _ => {}
        });
}
