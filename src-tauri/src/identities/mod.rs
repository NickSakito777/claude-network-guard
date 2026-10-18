// [INPUT]: SQLite 身份目录、加密压缩保险库、Cleaner 事务租约、Claude Guard 状态与 Tauri 进度通道。
// [OUTPUT]: 当前/空/已保存身份、HMAC 账号匹配、浏览器资料绑定、用户保留选项、核验后的切换/恢复/直接删除。
// [POS]: GUI 身份管理的原生入口；Claude 身份和浏览器资料变更复用 Cleaner 租约与 Guard 目标授权；不提供凭据读取、任意文件或网络接口。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
mod codec;
mod credentials;
pub(crate) mod database;
pub(crate) mod browser_link;
#[cfg(test)]
mod browser_link_tests;
mod catalog;
#[cfg(test)]
mod optimization_tests;
pub(crate) mod private;
mod profile;
mod store;
#[cfg(test)]
mod tests;
use crate::progress::{Progress, Reporter};
use serde::{Deserialize, Serialize};
use tauri::{ipc::Channel, Manager};
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub skills: bool,
    pub plugins: bool,
    pub mcp: bool,
    pub settings: bool,
    pub projects: bool,
    pub history: bool,
    pub cache: bool,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            skills: true,
            plugins: true,
            mcp: true,
            settings: true,
            projects: true,
            history: false,
            cache: false,
        }
    }
}
impl Policy {
    pub fn all() -> Self {
        Self {
            skills: false,
            plugins: false,
            mcp: false,
            settings: false,
            projects: false,
            history: false,
            cache: false,
        }
    }
    pub fn keeps(&self, category: &str) -> bool {
        match category {
            "skills" => self.skills,
            "plugins" => self.plugins,
            "mcp" => self.mcp,
            "settings" => self.settings,
            "history" => self.history,
            "cache" => self.cache,
            _ => false,
        }
    }
}
#[derive(Serialize)]
pub struct State {
    pub browser: browser_link::BrowserLink,
    pub browser_warning: Option<String>,
    pub records: Vec<database::Record>,
    pub active: String,
    pub recovery: Option<String>,
    pub running: bool,
    pub current: profile::Current,
}
pub(crate) fn new_id() -> Result<String, String> {
    Ok(codec::random::<16>()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn name(value: &str) -> Result<String, String> {
    let n = value.trim();
    if n.is_empty() || n.chars().count() > 64 || n.chars().any(char::is_control) {
        Err("身份名称需要 1–64 个字符。".into())
    } else {
        Ok(n.into())
    }
}
fn vault(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|_| "身份保险库无法定位。")?
        .join("identity-vault"))
}
pub(crate) fn browser_current_key(
    vault: &std::path::Path, home: &std::path::Path,
) -> Result<Option<String>, String> {
    catalog::current_key(vault, home)
}
fn state(app: &tauri::AppHandle) -> Result<State, String> {
    let db = database::Database::open(&vault(app)?)?;
    Ok(State {
        browser: db.browser_link()?,
        browser_warning: crate::browser::pending_warning(app)?.or_else(|| {
            app.state::<crate::browser::Browser>()
                .warning
                .lock()
                .unwrap()
                .clone()
        }),
        records: db.records()?.into_iter().filter(|r| !r.empty).collect(),
        active: catalog::current_id(&vault(app)?, &crate::cleaner::identity::root()?, &db)?
            .unwrap_or_else(|| "current".into()),
        recovery: db.get("recovery")?,
        running: crate::cleaner::identity::processes_running()?,
        current: profile::read(&crate::cleaner::identity::root()?),
    })
}
#[tauri::command]
pub async fn identities_read(app: tauri::AppHandle) -> Result<State, String> {
    tauri::async_runtime::spawn_blocking(move || state(&app))
        .await
        .map_err(|_| "身份列表读取被中断。".to_string())?
}
#[tauri::command]
pub async fn identities_switch(
    app: tauri::AppHandle,
    target_id: String,
    current_name: String,
    policy: Policy,
    recover: bool,
    on_progress: Channel<Progress>,
) -> Result<State, String> {
    let current_name = name(&current_name)?;
    if target_id != "empty" && !valid_id(&target_id) {
        return Err("身份编号无效。".into());
    }
    let worker = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let _operation = worker.state::<crate::cleaner::Cleaner>().lease()?;
        crate::guard::require_target(&worker, "claude")?;
        let reporter = Reporter::channel(Some(on_progress));
        let result = crate::browser::identity_action(&worker, &reporter, || {
            let mut store = store::Store::open(
                &vault(&worker).map_err(crate::browser::IdentityActionError::safe)?,
                &crate::cleaner::identity::root().map_err(crate::browser::IdentityActionError::safe)?,
            ).map_err(crate::browser::IdentityActionError::safe)?;
            let result = if recover {
                store.recover(&current_name, &reporter)
            } else {
                store.switch(&target_id, &current_name, &policy, &reporter)
            };
            result.map_err(|message| crate::browser::IdentityActionError {
                message, safe_after_error: store.safe_after_error,
            })
        })
        .and_then(|_| state(&worker));
        if let Err(e) = &result {
            reporter.fail(e);
        }
        result
    })
    .await
    .map_err(|_| "身份切换中断；请使用恢复操作。".to_string())
    .and_then(|r| r);
    result
}
#[tauri::command]
pub async fn identities_rename(
    app: tauri::AppHandle,
    id: String,
    value: String,
) -> Result<State, String> {
    if !valid_id(&id) {
        return Err("身份编号无效。".into());
    }
    let value = name(&value)?;
    let worker = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let _operation = worker.state::<crate::cleaner::Cleaner>().lease()?;
        let db = database::Database::open(&vault(&worker)?)?;
        if db.get("recovery")?.is_some() {
            return Err("请先恢复未完成的身份切换。".into());
        }
        db.rename(&id, &value)?;
        state(&worker)
    })
    .await
    .map_err(|_| "身份名称保存被中断。".to_string())
    .and_then(|r| r);
    result
}

#[tauri::command]
pub async fn identities_delete(
    app: tauri::AppHandle,
    id: String,
    policy: Policy,
    delete_browser: Option<bool>,
    on_progress: Channel<Progress>,
) -> Result<State, String> {
    if id != "current" && !valid_id(&id) {
        return Err("身份编号无效。".into());
    }
    let current = id == "current";
    let worker = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let _operation = worker.state::<crate::cleaner::Cleaner>().lease()?;
        if current {
            crate::guard::require_target(&worker, "claude")?;
        }
        let reporter = Reporter::channel(Some(on_progress));
        let action = || {
            let mut store = store::Store::open(
                &vault(&worker).map_err(crate::browser::IdentityActionError::safe)?,
                &crate::cleaner::identity::root().map_err(crate::browser::IdentityActionError::safe)?,
            ).map_err(crate::browser::IdentityActionError::safe)?;
            store.delete(&id, &policy, &reporter).map_err(|message| {
                crate::browser::IdentityActionError { message, safe_after_error: store.safe_after_error }
            })
        };
        let result = if current {
            crate::browser::identity_action(&worker, &reporter, action)
        } else {
            crate::browser::delete_saved(&worker, &id, delete_browser.unwrap_or(false), || {
                action().map_err(|error| error.message)
            })
        }
        .and_then(|_| state(&worker));
        if let Err(e) = &result {
            reporter.fail(e);
        }
        result
    })
    .await
    .map_err(|_| "直接删除中断；请刷新检查剩余数据。".to_string())
    .and_then(|r| r);
    result
}

#[tauri::command]
pub async fn identities_browser(
    app: tauri::AppHandle,
    enabled: bool,
    use_existing: bool,
) -> Result<State, String> {
    let worker = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = worker.state::<crate::cleaner::Cleaner>().lease()?;
        crate::guard::require_target(&worker, "ccbaga_browser")?;
        let reporter = Reporter::channel(None);
        crate::browser::configure_identity(&worker, &reporter, || {
            let root = vault(&worker)?;
            let mut db = database::Database::open(&root)?;
            let current = catalog::current_id(
                &root,
                &crate::cleaner::identity::root()?,
                &db,
            )?;
            db.configure_browser(enabled, use_existing, current.as_deref())
        })?;
        state(&worker)
    })
    .await
    .map_err(|_| "浏览器联动设置被中断，请刷新。".to_string())?
}
