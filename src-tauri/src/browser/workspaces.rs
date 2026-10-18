// [INPUT]: 身份 SQLite 绑定、独立浏览器根目录、受限配置和用户确认后的切换事务。
// [OUTPUT]: 每身份独占资料/配置选择、初始稳定种子、安全退出/重开与崩溃时启动阻断。
// [POS]: 身份与浏览器的协调边界；资料不压缩、不复制、不合并 Cookie，失败状态如实返回。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
use super::*;
use crate::identities::{browser_link, database::Database, private};

pub(crate) struct IdentityActionError {
    pub message: String,
    pub safe_after_error: bool,
}
impl IdentityActionError {
    pub(crate) fn safe(message: String) -> Self {
        Self { message, safe_after_error: true }
    }
}
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct IdentityStamp {
    active: String,
    account: Option<String>,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct ReconciledMarker {
    version: u32,
    slot: String,
    identity: IdentityStamp,
}
const RECONCILED_MARKER_VERSION: u32 = 2;
fn marker(root: &Path) -> Result<Option<Vec<u8>>, String> {
    let path = root.join("identity-switch.pending");
    profile::check_path(root, &path)?;
    match fs::read(&path) {
        Ok(bytes) if bytes.len() <= 4096 => Ok(Some(bytes)),
        Ok(_) => Err("浏览器切换状态无效，保持关闭。".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("无法核对浏览器切换状态，保持关闭。".into()),
    }
}
fn current_identity(root: &Path, home: &Path, db: &Database) -> Result<IdentityStamp, String> {
    let vault = root.parent().ok_or("应用目录不可用。")?.join("identity-vault");
    let active = db.get("active")?.unwrap_or_else(|| "current".into());
    if active != "current" && active != "empty" && !crate::identities::valid_id(&active) {
        return Err("身份状态无效，浏览器保持关闭。".into());
    }
    Ok(IdentityStamp {
        active,
        account: crate::identities::browser_current_key(&vault, home)?,
    })
}
fn identity_matches_pointer(
    db: &Database,
    identity: &IdentityStamp,
    slot: &str,
) -> Result<bool, String> {
    let records = db.records()?;
    let linked = db.browser_link()?.enabled;
    match identity.active.as_str() {
        "empty" => Ok(identity.account.is_none()
            && (!linked || !db.browser_slot_is_bound(slot)?)),
        // `current` means the live account is not in the saved catalog. If its
        // HMAC resolves to a saved record, only that record may be the active pointer.
        // Linked `current` profiles also need an unbound slot, or they could reuse
        // cookies retained for a deleted saved identity.
        "current" => Ok(identity.account.as_deref().map_or(true, |account| {
            !records.iter().any(|record| {
                record.account_key.as_deref().filter(|key| !key.is_empty()) == Some(account)
            })
        }) && (!linked || !db.browser_slot_is_bound(slot)?)),
        id => {
            let account_matches = records.iter().find(|record| record.id == id).is_some_and(|record| {
                match (
                    record.account_key.as_deref().filter(|key| !key.is_empty()),
                    identity.account.as_deref(),
                ) {
                    (Some(stored), Some(live)) => stored == live,
                    _ => false,
                }
            });
            let slot_matches = !linked || db.browser_for(id)?.as_deref() == Some(slot);
            Ok(account_matches && slot_matches)
        }
    }
}
// Persist a retry permit only after the identity layer proves that data is unchanged or restored.
// An old/unknown marker and any partial destructive failure never gain this permit.
pub(crate) fn run_action(
    root: &Path,
    home: &Path,
    allow_safe_error: bool,
    action: impl FnOnce() -> Result<(), IdentityActionError>,
) -> Result<(), String> {
    match action() {
        Ok(()) => Ok(()),
        Err(error) => {
            if allow_safe_error && error.safe_after_error {
                let db = database(root)?;
                if db.get("recovery")?.is_none() {
                    let identity = current_identity(root, home, &db)?;
                    let slot = db.browser_slot()?;
                    if !identity_matches_pointer(&db, &identity, &slot)? {
                        return Err("身份与活动账号不一致，浏览器保持关闭。".into());
                    }
                    let retry = ReconciledMarker {
                        version: RECONCILED_MARKER_VERSION,
                        slot,
                        identity,
                    };
                    private::write(&root.join("identity-switch.pending"),
                        &serde_json::to_vec(&retry).map_err(|_| "无法保存浏览器恢复状态。")?)?;
                }
            }
            Err(error.message)
        }
    }
}
pub(super) fn pending_warning(root: &Path, home: &Path) -> Result<Option<String>, String> {
    Ok(marker(root)?.map(|bytes| {
        let retryable = serde_json::from_slice::<ReconciledMarker>(&bytes).is_ok_and(|retry| {
            retry.version == RECONCILED_MARKER_VERSION
                && database(root).is_ok_and(|db| {
                    matches!(db.get("recovery"), Ok(None))
                        && db.browser_slot().is_ok_and(|slot| slot == retry.slot)
                        && current_identity(root, home, &db).is_ok_and(|identity| {
                            identity == retry.identity
                                && identity_matches_pointer(&db, &identity, &retry.slot)
                                    .unwrap_or(false)
                        })
                })
        });
        if retryable {
            "身份数据已保持或恢复，浏览器保持关闭；点击打开浏览器重新核对。".into()
        } else {
            "浏览器保持关闭，请先恢复或重试身份操作。".into()
        }
    }))
}
// Called only by the user's explicit browser-start action, under the existing operation/gate locks.
pub(super) fn reconcile(root: &Path, home: &Path) -> Result<(), String> {
    reconcile_with(root, home, profile::running)
}
pub(crate) fn reconcile_with(
    root: &Path, home: &Path, running: impl FnOnce(&Path) -> Result<bool, String>,
) -> Result<(), String> {
    let Some(bytes) = marker(root)? else { return Ok(()); };
    let retry: ReconciledMarker = serde_json::from_slice(&bytes)
        .map_err(|_| "身份操作结果尚未确认，请先恢复或重试身份操作。")?;
    let db = database(root)?;
    let identity = current_identity(root, home, &db)?;
    if retry.version != RECONCILED_MARKER_VERSION
        || db.get("recovery")?.is_some()
        || db.browser_slot()? != retry.slot
        || identity != retry.identity
        || !identity_matches_pointer(&db, &identity, &retry.slot)?
    {
        return Err("身份或浏览器资料已变化，请先恢复或重试身份操作。".into());
    }
    let path = slot_path(root, &retry.slot)?.join("profile");
    if running(&path)? {
        return Err("浏览器仍在运行，请先正常退出后重试。".into());
    }
    unblock(root)
}

// A disabled browser link can leave a raw marker if the host crashed just after
// committing unlink. Only an explicit identity operation may clear it, after
// proving the shared profile is idle and the DB has no recovery transaction.
pub(crate) fn retry_unlinked_pending_with(
    root: &Path,
    mut running: impl FnMut(&Path) -> Result<bool, String>,
    action: impl FnOnce() -> Result<(), IdentityActionError>,
    refresh: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if marker(root)?.is_none() {
        return Err("没有待恢复的浏览器状态。".into());
    }
    let db = database(root)?;
    if db.browser_link()?.enabled || db.get("recovery")?.is_some() {
        return Err("浏览器保持关闭，请先恢复身份切换。".into());
    }
    let slot = db.browser_slot()?;
    let profile = slot_path(root, &slot)?.join("profile");
    if running(&profile)? {
        return Err("浏览器仍在运行，请先正常退出后重试。".into());
    }
    action().map_err(|error| error.message)?;

    let db = database(root)?;
    if db.browser_link()?.enabled || db.get("recovery")?.is_some() || db.browser_slot()? != slot {
        return Err("身份或浏览器资料已变化，请先恢复或重试身份操作。".into());
    }
    if running(&profile)? {
        return Err("浏览器仍在运行，请先正常退出后重试。".into());
    }
    refresh()?;
    unblock(root)
}

pub(super) fn database(root: &Path) -> Result<Database, String> {
    Database::open(
        &root
            .parent()
            .ok_or("应用目录不可用。")?
            .join("identity-vault"),
    )
}
pub(super) fn slot_path(root: &Path, slot: &str) -> Result<PathBuf, String> {
    if !browser_link::valid_slot(slot) {
        return Err("浏览器资料选择无效。".into());
    }
    let path = if slot == "legacy" {
        root.to_path_buf()
    } else {
        root.join("contexts").join(slot)
    };
    profile::check_path(root, &path)?;
    Ok(path)
}
pub(super) fn scope(root: &Path) -> Result<PathBuf, String> {
    slot_path(root, &database(root)?.browser_slot()?)
}
pub(super) fn ready(root: &Path) -> Result<(), String> {
    let marker = root.join("identity-switch.pending");
    profile::check_path(root, &marker)?;
    match fs::symlink_metadata(&marker) {
        Ok(_) => return Err("浏览器保持关闭，请先恢复身份切换。".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(_) => return Err("无法核对浏览器切换状态，保持关闭。".into()),
    }
    if database(root)?.get("recovery")?.is_some() {
        return Err("浏览器保持关闭，请先恢复身份切换。".into());
    }
    Ok(())
}
pub(super) fn ensure(root: &Path) -> Result<PathBuf, String> {
    let db = database(root)?;
    if db.get("recovery")?.is_some() {
        return Err("浏览器保持关闭，请先恢复身份切换。".into());
    }
    let slot = db.browser_slot()?;
    let path = slot_path(root, &slot)?;
    private::directory(&path)?;
    let seed = match db.browser_seed(&slot)? {
        Some(seed) => seed,
        None => browser_link::seed(&db.browser_draft()?.unwrap_or_else(|| slot.clone()), 0).max(1),
    };
    let stamp = path.join("seed.owner");
    profile::check_path(root, &stamp)?;
    let bound = db.browser_link()?.enabled;
    let first = !path.join("config.json").exists();
    if first || (bound && fs::read_to_string(&stamp).ok().as_deref() != Some(&seed.to_string())) {
        let mut config = if first && slot != "legacy" {
            config::load(root)?
        } else {
            config::load(&path)?
        };
        if bound {
            config.seed = seed;
        }
        config::save(&path, &config)?;
        if bound {
            private::write(&stamp, seed.to_string().as_bytes())?;
        }
    }
    private::directory(&path.join("profile"))?;
    Ok(path)
}
fn block(app: &tauri::AppHandle, root: &Path) -> Result<(), String> {
    private::directory(root)?;
    private::write(&root.join("identity-switch.pending"), b"1")?;
    *app.state::<Browser>().session.lock().unwrap() = None;
    *app.state::<Browser>().host.lock().unwrap() = None;
    forget_start_url(app);
    Ok(())
}
pub(super) fn unblock(root: &Path) -> Result<(), String> {
    let path = root.join("identity-switch.pending");
    profile::check_path(root, &path)?;
    match fs::remove_file(&path) {
        Ok(()) => {
            private::sync_parent(&path);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("无法更新浏览器启动状态。".into()),
    }
}
pub(crate) fn identity_action(
    app: &tauri::AppHandle,
    reporter: &Reporter,
    action: impl FnOnce() -> Result<(), IdentityActionError>,
) -> Result<(), String> {
    transition(app, reporter, false, action)
}
pub(crate) fn delete_saved(
    app: &tauri::AppHandle,
    id: &str,
    remove_profile: bool,
    action: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let browser = app.state::<Browser>();
    let _guard = browser.gate.lock().unwrap();
    let root = root(app)?;
    let db = database(&root)?;
    let slot = db.browser_for(id)?;
    if remove_profile {
        if let Some(slot) = slot.as_deref() {
            if slot == db.browser_slot()? {
                return Err("关联浏览器资料正在使用，不能删除。".into());
            }
            let path = slot_path(&root, slot)?.join("profile");
            if profile::running(&path)? {
                return Err("关联浏览器资料正在使用，不能删除。".into());
            }
        }
    }
    action()?;
    if remove_profile {
        if let Some(slot) = slot {
            let scope = slot_path(&root, &slot)?;
            let target = if slot == "legacy" {
                scope.join("profile")
            } else {
                scope
            };
            profile::check_path(&root, &target)?;
            if target.exists() {
                private::safe(&target)?;
                fs::remove_dir_all(&target)
                    .map_err(|_| "身份已删除，关联浏览器资料未完全删除，请检查。")?;
            }
        }
    }
    Ok(())
}
pub(super) fn transition(
    app: &tauri::AppHandle,
    reporter: &Reporter,
    force: bool,
    action: impl FnOnce() -> Result<(), IdentityActionError>,
) -> Result<(), String> {
    let browser = app.state::<Browser>();
    let _guard = browser.gate.lock().unwrap();
    let root = root(app)?;
    let linked = database(&root)?.browser_link()?.enabled;
    let pending_before = marker(&root)?;
    if !force && !linked {
        if pending_before.is_none() {
            return action().map_err(|error| error.message);
        }
        *browser.warning.lock().unwrap() = None;
        let home = crate::cleaner::identity::root()?;
        let result = retry_unlinked_pending_with(
            &root,
            profile::running,
            action,
            || refresh_launch_args(app),
        );
        if result.is_err() {
            *browser.warning.lock().unwrap() = pending_warning(&root, &home)?;
        }
        return result;
    }
    *browser.warning.lock().unwrap() = None;
    let profile = scope(&root)?.join("profile");
    let was_running = profile::running(&profile)?;
    let allow_safe_error = pending_before.as_deref().map_or(true, |bytes| {
        serde_json::from_slice::<ReconciledMarker>(&bytes)
            .is_ok_and(|marker| marker.version == RECONCILED_MARKER_VERSION)
    });
    block(app, &root)?;
    reporter.log("browser", "running", "正在正常退出关联浏览器。", 0, None);
    if let Err(error) = profile::quit(&profile) {
        let result = run_action(&root, &crate::cleaner::identity::root()?, allow_safe_error,
            || Err(IdentityActionError::safe(error)));
        *browser.warning.lock().unwrap() = pending_warning(
            &root,
            &crate::cleaner::identity::root()?,
        )?;
        return result;
    }
    let result = run_action(&root, &crate::cleaner::identity::root()?, allow_safe_error, action);
    if result.is_err() {
        // A failed destructive action may have changed data without a DB recovery row.
        // Only a successful retry/recovery may replace launch args and clear this marker.
        *browser.warning.lock().unwrap() = pending_warning(
            &root,
            &crate::cleaner::identity::root()?,
        )?;
        return result;
    }
    let finish = (|| {
        if pending_before.is_some() {
            let db = database(&root)?;
            if db.get("recovery")?.is_some() {
                return Err("浏览器保持关闭，请先恢复身份切换。".into());
            }
            if profile::running(&scope(&root)?.join("profile"))? {
                return Err("浏览器仍在运行，请先正常退出后重试。".into());
            }
        }
        refresh_launch_args(app)?;
        if (result.is_ok() && database(&root)?.browser_link()?.enabled) || was_running {
            crate::guard::require_running_target(app, "ccbaga_browser")?;
            launch_locked(app, reporter)?;
        }
        Ok::<_, String>(())
    })();
    if let Err(error) = finish {
        let warning = if marker(&root)?.is_some() {
            pending_warning(&root, &crate::cleaner::identity::root()?)?
                .unwrap_or_else(|| "浏览器保持关闭，请先恢复或重试身份操作。".into())
        } else if database(&root)?.get("recovery")?.is_some() {
            "浏览器保持关闭，请先恢复身份切换。".to_owned()
        } else {
            "身份状态已保存，浏览器保持关闭；请从保护中心重新核验并启动。".to_owned()
        };
        *browser.warning.lock().unwrap() = Some(warning);
        reporter.log("browser", "error", &error, 0, None);
    } else {
        reporter.log("browser", "ok", "浏览器资料已与身份同步。", 1, Some(1));
    }
    result
}
