// [INPUT]: 临时应用数据目录、虚构浏览器资料与身份绑定配置。
// [OUTPUT]: SQLite 句柄释放后的三平台临时目录清理、Cookie/缓存/种子隔离、手动换指纹持久化、旧资料保留与路径逃逸拒绝回归。
// [POS]: 浏览器存储边界的离线证明，不启动真实用户的浏览器或访问钥匙串。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
use super::*;
#[test]
fn linked_profiles_keep_separate_data_and_configs_without_compressing_or_copying() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    crate::identities::private::directory(&root).unwrap();
    let legacy = root.join("profile/Default");
    fs::create_dir_all(&legacy).unwrap();
    fs::write(legacy.join("Bookmarks"), b"old").unwrap();
    let mut db = workspaces::database(&root).unwrap();
    let a = crate::identities::new_id().unwrap();
    let b = crate::identities::new_id().unwrap();
    db.configure_browser(true, false, Some(&a)).unwrap();
    let scope_a = workspaces::ensure(&root).unwrap();
    assert_eq!(
        config::load(&scope_a).unwrap().seed,
        crate::identities::browser_link::seed(&a, 0)
    );
    let data_a = scope_a.join("profile/Default");
    fs::create_dir_all(&data_a).unwrap();
    fs::write(data_a.join("Cookies"), b"A").unwrap();
    let mut config_a = config::load(&scope_a).unwrap();
    config_a.seed = 12345;
    config::save(&scope_a, &config_a).unwrap();
    db.configure_browser(true, false, Some(&b)).unwrap();
    let scope_b = workspaces::ensure(&root).unwrap();
    assert_ne!(scope_a, scope_b);
    let data_b = scope_b.join("profile/Default");
    assert!(!data_b.exists());
    fs::create_dir_all(data_b.join("Cache")).unwrap();
    fs::write(data_b.join("Cookies"), b"B").unwrap();
    fs::write(data_b.join("Cache/data"), b"cache").unwrap();
    profile::clear(&scope_b.join("profile"), false, |_, _| {}).unwrap();
    assert_eq!(fs::read(data_a.join("Cookies")).unwrap(), b"A");
    assert_eq!(fs::read(data_b.join("Cookies")).unwrap(), b"B");
    db.configure_browser(true, false, Some(&a)).unwrap();
    assert_eq!(workspaces::ensure(&root).unwrap(), scope_a);
    assert_eq!(config::load(&scope_a).unwrap().seed, 12345);
    db.configure_browser(false, false, None).unwrap();
    assert_eq!(workspaces::scope(&root).unwrap(), root);
    assert_eq!(fs::read(legacy.join("Bookmarks")).unwrap(), b"old");
    for bad in ["../escape", "/tmp", "", "Default", "AABB"] {
        assert!(workspaces::slot_path(&root, bad).is_err());
    }
    drop(db);
    fs::remove_dir_all(fixture).unwrap();
}
#[test]
fn recovery_refuses_profile_launch_preparation() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    let db = workspaces::database(&root).unwrap();
    drop(db);
    let connection =
        rusqlite::Connection::open(fixture.join("identity-vault/identities.sqlite")).unwrap();
    connection
        .execute(
            "INSERT INTO state VALUES('recovery',?1)",
            [crate::identities::new_id().unwrap()],
        )
        .unwrap();
    assert!(workspaces::ensure(&root).unwrap_err().contains("恢复"));
    drop(connection);
    fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn an_interrupted_profile_transition_refuses_launch_until_explicit_reconciliation() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    let db = workspaces::database(&root).unwrap();
    drop(db);
    crate::identities::private::directory(&root).unwrap();
    crate::identities::private::write(&root.join("identity-switch.pending"), b"1").unwrap();
    assert!(workspaces::ready(&root).is_err());
    // Transaction completion can prepare files while the independent launch gate stays closed.
    workspaces::ensure(&root).unwrap();
    assert!(workspaces::ready(&root).is_err());
    workspaces::unblock(&root).unwrap();
    assert!(workspaces::ready(&root).is_ok());
    fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn relinking_does_not_restore_cookies_from_a_previously_shared_legacy_profile() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    crate::identities::private::directory(&root).unwrap();
    let legacy = root.join("profile/Default");
    fs::create_dir_all(&legacy).unwrap();
    fs::write(legacy.join("Cookies"), b"A").unwrap();
    let mut db = workspaces::database(&root).unwrap();
    let a = crate::identities::new_id().unwrap();
    db.configure_browser(true, true, Some(&a)).unwrap();
    assert_eq!(db.browser_for(&a).unwrap().as_deref(), Some("legacy"));
    db.configure_browser(false, false, None).unwrap();
    assert!(db.browser_for(&a).unwrap().is_none());
    fs::write(legacy.join("Cookies"), b"other-account-during-unlink").unwrap();
    db.configure_browser(true, false, Some(&a)).unwrap();
    let fresh = workspaces::ensure(&root).unwrap();
    assert_ne!(fresh, root);
    assert!(!fresh.join("profile/Default/Cookies").exists());
    assert_eq!(fs::read(legacy.join("Cookies")).unwrap(), b"other-account-during-unlink");
    drop(db);
    fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn explicitly_adopting_shared_data_does_not_silently_reuse_an_old_private_slot() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    crate::identities::private::directory(&root).unwrap();
    let mut db = workspaces::database(&root).unwrap();
    let a = crate::identities::new_id().unwrap();
    db.configure_browser(true, false, Some(&a)).unwrap();
    let previous = workspaces::ensure(&root).unwrap();
    fs::create_dir_all(previous.join("profile/Default")).unwrap();
    fs::write(previous.join("profile/Default/Cookies"), b"private-A").unwrap();
    db.configure_browser(false, false, None).unwrap();
    fs::create_dir_all(root.join("profile/Default")).unwrap();
    fs::write(root.join("profile/Default/Cookies"), b"explicitly-selected-shared").unwrap();
    db.configure_browser(true, true, Some(&a)).unwrap();
    assert_eq!(workspaces::scope(&root).unwrap(), root);
    assert_eq!(fs::read(root.join("profile/Default/Cookies")).unwrap(), b"explicitly-selected-shared");
    assert_eq!(fs::read(previous.join("profile/Default/Cookies")).unwrap(), b"private-A");
    drop(db);
    fs::remove_dir_all(fixture).unwrap();
}


#[test]
fn profile_quit_failure_can_be_retried_after_restart_when_quiescent() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    let home = fixture.join("home");
    crate::identities::private::directory(&root).unwrap();
    let db = workspaces::database(&root).unwrap();
    drop(db);
    let pending = root.join("identity-switch.pending");
    crate::identities::private::write(&pending, b"1").unwrap();
    let error = workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("browser quit failed".into()))
    }).unwrap_err();
    assert_eq!(error, "browser quit failed");
    assert!(workspaces::ready(&root).is_err());
    // No in-memory warning or Tauri state is needed after the host restarts.
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("重新核对"));
    assert!(workspaces::reconcile_with(&root, &home, |_| Ok(true)).is_err());
    assert!(pending.exists());
    workspaces::reconcile_with(&root, &home, |_| Ok(false)).unwrap();
    workspaces::ready(&root).unwrap();
    assert!(!pending.exists());
    fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn current_pointer_allows_retry_for_an_unindexed_live_account() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    let home = fixture.join("home");
    crate::identities::private::directory(&root).unwrap();
    crate::identities::private::directory(&home).unwrap();
    let db = workspaces::database(&root).unwrap();
    let vault = fixture.join("identity-vault");
    crate::identities::private::write(&vault.join("key.bin"), &[37; 32]).unwrap();
    drop(db);

    let identity_path = home.join(".claude.json");
    crate::identities::private::write(
        &identity_path,
        br#"{"oauthAccount":{"accountUuid":"fixture-account-a"}}"#,
    )
    .unwrap();
    let original_account = crate::identities::browser_current_key(&vault, &home).unwrap();
    let marker_path = root.join("identity-switch.pending");
    crate::identities::private::write(&marker_path, b"1").unwrap();
    workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("verified rollback".into()))
    })
    .unwrap_err();
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&marker_path).unwrap()).unwrap();
    assert_eq!(saved["identity"]["active"], "current");
    assert_eq!(saved["identity"]["account"].as_str(), original_account.as_deref());
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("重新核对"));
    workspaces::reconcile_with(&root, &home, |_| Ok(false)).unwrap();
    assert!(!marker_path.exists());

    crate::identities::private::write(&marker_path, b"1").unwrap();
    workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("verified rollback".into()))
    })
    .unwrap_err();
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&marker_path).unwrap()).unwrap();
    assert_eq!(saved["identity"]["account"].as_str(), original_account.as_deref());
    crate::identities::private::write(
        &identity_path,
        br#"{"oauthAccount":{"accountUuid":"fixture-account-b"}}"#,
    )
    .unwrap();
    assert_ne!(original_account, crate::identities::browser_current_key(&vault, &home).unwrap());
    assert!(workspaces::reconcile_with(&root, &home, |_| Ok(false)).is_err());
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("恢复或重试"));
    assert!(marker_path.exists());

    crate::identities::private::write(&marker_path, b"1").unwrap();
    workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("verified rollback".into()))
    })
    .unwrap_err();
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("重新核对"));
    workspaces::reconcile_with(&root, &home, |_| Ok(false)).unwrap();
    fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn saved_active_identity_requires_matching_live_account_before_and_after_restart() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    let home = fixture.join("home");
    let vault = fixture.join("identity-vault");
    crate::identities::private::directory(&root).unwrap();
    crate::identities::private::directory(&home).unwrap();
    let mut db = workspaces::database(&root).unwrap();
    crate::identities::private::write(&vault.join("key.bin"), &[53; 32]).unwrap();
    let identity_path = home.join(".claude.json");
    crate::identities::private::write(
        &identity_path,
        br#"{"oauthAccount":{"accountUuid":"fixture-account-a"}}"#,
    )
    .unwrap();
    let account_a = crate::identities::browser_current_key(&vault, &home).unwrap().unwrap();
    let id_a = crate::identities::new_id().unwrap();
    let record = crate::identities::database::Record {
        id: id_a.clone(),
        name: "Account A".into(),
        archive: format!("{id_a}.baga"),
        saved_at: 1,
        bytes: 0,
        policy: crate::identities::Policy::default(),
        empty: false,
        account_key: Some(account_a.clone()),
    };
    db.remember(&record).unwrap();
    db.complete(&id_a).unwrap();
    let slot_a = db.browser_for(&id_a).unwrap().unwrap();
    drop(db);

    let pending = root.join("identity-switch.pending");
    crate::identities::private::write(&pending, b"1").unwrap();
    workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("pre-mutation failure".into()))
    })
    .unwrap_err();
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&pending).unwrap()).unwrap();
    assert_eq!(saved["identity"]["active"], id_a);
    assert_eq!(saved["identity"]["account"], account_a);
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("重新核对"));
    workspaces::reconcile_with(&root, &home, |_| Ok(false)).unwrap();
    assert!(!pending.exists());

    let connection = rusqlite::Connection::open(vault.join("identities.sqlite")).unwrap();
    connection
        .execute("UPDATE state SET value='current' WHERE key='active'", [])
        .unwrap();
    drop(connection);
    crate::identities::private::write(&pending, b"1").unwrap();
    let error = workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("pre-mutation failure".into()))
    })
    .unwrap_err();
    assert!(error.contains("不一致"));
    assert_eq!(fs::read(&pending).unwrap(), b"1");
    let connection = rusqlite::Connection::open(vault.join("identities.sqlite")).unwrap();
    connection
        .execute("UPDATE state SET value=?1 WHERE key='active'", [&id_a])
        .unwrap();
    drop(connection);

    let wrong_slot = crate::identities::new_id().unwrap();
    let connection = rusqlite::Connection::open(vault.join("identities.sqlite")).unwrap();
    connection
        .execute(
            "UPDATE state SET value=?1 WHERE key='browser.active'",
            [&wrong_slot],
        )
        .unwrap();
    drop(connection);
    crate::identities::private::write(&pending, b"1").unwrap();
    let error = workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("pre-mutation failure".into()))
    })
    .unwrap_err();
    assert!(error.contains("不一致"));
    assert_eq!(fs::read(&pending).unwrap(), b"1");
    let wrong_slot_marker = serde_json::json!({
        "version": 2,
        "slot": wrong_slot,
        "identity": {"active": id_a, "account": account_a},
    });
    crate::identities::private::write(
        &pending,
        &serde_json::to_vec(&wrong_slot_marker).unwrap(),
    )
    .unwrap();
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("恢复或重试"));
    assert!(workspaces::reconcile_with(&root, &home, |_| Ok(false)).is_err());

    let connection = rusqlite::Connection::open(vault.join("identities.sqlite")).unwrap();
    connection
        .execute(
            "UPDATE state SET value=?1 WHERE key='browser.active'",
            [&slot_a],
        )
        .unwrap();
    drop(connection);

    crate::identities::private::write(&pending, b"1").unwrap();
    workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("pre-mutation failure".into()))
    })
    .unwrap_err();
    crate::identities::private::write(
        &identity_path,
        br#"{"oauthAccount":{"accountUuid":"fixture-account-b"}}"#,
    )
    .unwrap();
    assert!(workspaces::reconcile_with(&root, &home, |_| Ok(false)).is_err());
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("恢复或重试"));

    crate::identities::private::write(&pending, b"1").unwrap();
    let error = workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("pre-mutation failure".into()))
    })
    .unwrap_err();
    assert!(error.contains("不一致"));
    assert_eq!(fs::read(&pending).unwrap(), b"1");
    fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn legacy_saved_identity_without_account_key_cannot_gain_retry_permit() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    let home = fixture.join("home");
    crate::identities::private::directory(&root).unwrap();
    crate::identities::private::directory(&home).unwrap();
    let mut db = workspaces::database(&root).unwrap();
    let id = crate::identities::new_id().unwrap();
    db.remember(&crate::identities::database::Record {
        id: id.clone(),
        name: "Unindexed legacy identity".into(),
        archive: format!("{id}.baga"),
        saved_at: 1,
        bytes: 0,
        policy: crate::identities::Policy::default(),
        empty: false,
        account_key: None,
    })
    .unwrap();
    db.complete(&id).unwrap();
    let slot = db.browser_slot().unwrap();
    drop(db);

    let pending = root.join("identity-switch.pending");
    crate::identities::private::write(&pending, b"1").unwrap();
    let error = workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("pre-mutation failure".into()))
    })
    .unwrap_err();
    assert!(error.contains("不一致"));
    assert_eq!(fs::read(&pending).unwrap(), b"1");

    let marker = serde_json::json!({
        "version": 2,
        "slot": slot,
        "identity": {"active": id, "account": null},
    });
    crate::identities::private::write(&pending, &serde_json::to_vec(&marker).unwrap()).unwrap();
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("恢复或重试"));
    assert!(workspaces::reconcile_with(&root, &home, |_| Ok(false)).is_err());
    assert!(pending.exists());
    fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn empty_active_identity_rejects_a_live_account_even_with_a_matching_marker() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    let home = fixture.join("home");
    let vault = fixture.join("identity-vault");
    crate::identities::private::directory(&root).unwrap();
    crate::identities::private::directory(&home).unwrap();
    let mut db = workspaces::database(&root).unwrap();
    crate::identities::private::write(&vault.join("key.bin"), &[59; 32]).unwrap();
    crate::identities::private::write(
        &home.join(".claude.json"),
        br#"{"oauthAccount":{"accountUuid":"unexpected-account"}}"#,
    )
    .unwrap();
    let account = crate::identities::browser_current_key(&vault, &home).unwrap().unwrap();
    db.complete("empty").unwrap();
    let slot = db.browser_slot().unwrap();
    drop(db);

    let pending = root.join("identity-switch.pending");
    crate::identities::private::write(&pending, b"1").unwrap();
    workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("pre-mutation failure".into()))
    })
    .unwrap_err();
    assert_eq!(fs::read(&pending).unwrap(), b"1");

    let marker = serde_json::json!({
        "version": 2,
        "slot": slot,
        "identity": {"active": "empty", "account": account},
    });
    crate::identities::private::write(&pending, &serde_json::to_vec(&marker).unwrap()).unwrap();
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("恢复或重试"));
    assert!(workspaces::reconcile_with(&root, &home, |_| Ok(false)).is_err());
    assert!(pending.exists());
    fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn current_and_empty_retries_reject_slots_retained_for_saved_identities() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    let home = fixture.join("home");
    let vault = fixture.join("identity-vault");
    crate::identities::private::directory(&root).unwrap();
    crate::identities::private::directory(&home).unwrap();
    let mut db = workspaces::database(&root).unwrap();
    crate::identities::private::write(&vault.join("key.bin"), &[61; 32]).unwrap();
    let identity_path = home.join(".claude.json");
    crate::identities::private::write(
        &identity_path,
        br#"{"oauthAccount":{"accountUuid":"retained-account"}}"#,
    )
    .unwrap();
    let account = crate::identities::browser_current_key(&vault, &home).unwrap().unwrap();
    let id = crate::identities::new_id().unwrap();
    db.remember(&crate::identities::database::Record {
        id: id.clone(),
        name: "Retained account".into(),
        archive: format!("{id}.baga"),
        saved_at: 1,
        bytes: 0,
        policy: crate::identities::Policy::default(),
        empty: false,
        account_key: Some(account),
    })
    .unwrap();
    db.complete(&id).unwrap();
    let retained = root.join("profile/Default/Cookies");
    fs::create_dir_all(retained.parent().unwrap()).unwrap();
    fs::write(&retained, b"retained-cookie-fixture").unwrap();
    db.forget(&id).unwrap();
    assert_eq!(db.get("active").unwrap().as_deref(), Some("current"));
    assert_eq!(db.browser_slot().unwrap(), "legacy");
    drop(db);
    fs::remove_file(&identity_path).unwrap();

    let pending = root.join("identity-switch.pending");
    crate::identities::private::write(&pending, b"1").unwrap();
    workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("pre-mutation failure".into()))
    })
    .unwrap_err();
    assert_eq!(fs::read(&pending).unwrap(), b"1");
    let marker = serde_json::json!({
        "version": 2,
        "slot": "legacy",
        "identity": {"active": "current", "account": null},
    });
    crate::identities::private::write(&pending, &serde_json::to_vec(&marker).unwrap()).unwrap();
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("恢复或重试"));
    assert!(workspaces::reconcile_with(&root, &home, |_| Ok(false)).is_err());
    assert_eq!(fs::read(&retained).unwrap(), b"retained-cookie-fixture");
    fs::remove_dir_all(fixture).unwrap();

    let fixture = tests::sample();
    let root = fixture.join("browser");
    let home = fixture.join("home");
    let vault = fixture.join("identity-vault");
    crate::identities::private::directory(&root).unwrap();
    crate::identities::private::directory(&home).unwrap();
    let mut db = workspaces::database(&root).unwrap();
    crate::identities::private::write(&vault.join("key.bin"), &[67; 32]).unwrap();
    crate::identities::private::write(
        &home.join(".claude.json"),
        br#"{"oauthAccount":{"accountUuid":"other-retained-account"}}"#,
    )
    .unwrap();
    let id = crate::identities::new_id().unwrap();
    db.remember(&crate::identities::database::Record {
        id: id.clone(),
        name: "Retained account".into(),
        archive: format!("{id}.baga"),
        saved_at: 1,
        bytes: 0,
        policy: crate::identities::Policy::default(),
        empty: false,
        account_key: crate::identities::browser_current_key(&vault, &home).unwrap(),
    })
    .unwrap();
    db.complete(&id).unwrap();
    db.complete("empty").unwrap();
    drop(db);
    let connection = rusqlite::Connection::open(fixture.join("identity-vault/identities.sqlite")).unwrap();
    connection
        .execute("UPDATE state SET value='legacy' WHERE key='browser.active'", [])
        .unwrap();
    drop(connection);
    fs::remove_file(home.join(".claude.json")).unwrap();

    let retained = root.join("profile/Default/Cookies");
    fs::create_dir_all(retained.parent().unwrap()).unwrap();
    fs::write(&retained, b"empty-slot-retained-cookie-fixture").unwrap();
    let pending = root.join("identity-switch.pending");
    crate::identities::private::write(&pending, b"1").unwrap();
    workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("pre-mutation failure".into()))
    })
    .unwrap_err();
    assert_eq!(fs::read(&pending).unwrap(), b"1");
    let marker = serde_json::json!({
        "version": 2,
        "slot": "legacy",
        "identity": {"active": "empty", "account": null},
    });
    crate::identities::private::write(&pending, &serde_json::to_vec(&marker).unwrap()).unwrap();
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("恢复或重试"));
    assert!(workspaces::reconcile_with(&root, &home, |_| Ok(false)).is_err());
    assert_eq!(fs::read(&retained).unwrap(), b"empty-slot-retained-cookie-fixture");
    fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn partial_or_unknown_action_never_gains_a_retry_permit() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    let home = fixture.join("home");
    crate::identities::private::directory(&root).unwrap();
    drop(workspaces::database(&root).unwrap());
    let pending = root.join("identity-switch.pending");
    crate::identities::private::write(&pending, b"1").unwrap();
    workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError { message: "partial deletion".into(), safe_after_error: false })
    }).unwrap_err();
    assert_eq!(fs::read(&pending).unwrap(), b"1");
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("恢复或重试"));
    // Retrying an unknown transition and failing before mutation cannot certify the old partial result.
    workspaces::run_action(&root, &home, false, || {
        Err(workspaces::IdentityActionError::safe("preflight failed".into()))
    }).unwrap_err();
    assert!(workspaces::reconcile_with(&root, &home, |_| Ok(false)).is_err());
    assert_eq!(fs::read(&pending).unwrap(), b"1");
    fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn reconciliation_refuses_changed_profile_or_database_recovery() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    let home = fixture.join("home");
    crate::identities::private::directory(&root).unwrap();
    let mut db = workspaces::database(&root).unwrap();
    crate::identities::private::write(&root.join("identity-switch.pending"), b"1").unwrap();
    let make_safe = || workspaces::run_action(&root, &home, true, || {
        Err(workspaces::IdentityActionError::safe("rolled back".into()))
    }).unwrap_err();
    make_safe();
    db.configure_browser(true, false, None).unwrap();
    assert!(workspaces::reconcile_with(&root, &home, |_| Ok(false)).is_err());
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("恢复或重试"));
    make_safe();
    drop(db);
    let connection = rusqlite::Connection::open(fixture.join("identity-vault/identities.sqlite")).unwrap();
    connection.execute("INSERT OR REPLACE INTO state VALUES('active','empty')", []).unwrap();
    assert!(workspaces::reconcile_with(&root, &home, |_| Ok(false)).is_err());
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("恢复或重试"));
    connection.execute("UPDATE state SET value='current' WHERE key='active'", []).unwrap();
    connection.execute("INSERT INTO state VALUES('recovery',?1)", [crate::identities::new_id().unwrap()]).unwrap();
    assert!(workspaces::reconcile_with(&root, &home, |_| Ok(false)).is_err());
    assert!(workspaces::pending_warning(&root, &home).unwrap().unwrap().contains("恢复或重试"));
    assert!(root.join("identity-switch.pending").exists());
    drop(connection);
    fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn disabled_link_marker_clears_only_after_explicit_quiescent_success() {
    let fixture = tests::sample();
    let root = fixture.join("browser");
    crate::identities::private::directory(&root).unwrap();
    let mut db = workspaces::database(&root).unwrap();
    db.configure_browser(false, false, None).unwrap();
    drop(db);

    let pending = root.join("identity-switch.pending");
    crate::identities::private::write(&pending, b"1").unwrap();
    assert!(workspaces::ready(&root).is_err());

    let called = std::cell::Cell::new(false);
    assert!(workspaces::retry_unlinked_pending_with(
        &root,
        |_| Ok(true),
        || {
            called.set(true);
            Ok(())
        },
        || Ok(()),
    )
    .is_err());
    assert!(!called.get());
    assert_eq!(fs::read(&pending).unwrap(), b"1");

    assert!(workspaces::retry_unlinked_pending_with(
        &root,
        |_| Ok(false),
        || Err(workspaces::IdentityActionError {
            message: "partial unlink retry".into(),
            safe_after_error: false,
        }),
        || Ok(()),
    )
    .is_err());
    assert_eq!(fs::read(&pending).unwrap(), b"1");

    let connection = rusqlite::Connection::open(fixture.join("identity-vault/identities.sqlite")).unwrap();
    connection
        .execute(
            "INSERT INTO state VALUES('recovery',?1)",
            [crate::identities::new_id().unwrap()],
        )
        .unwrap();
    assert!(workspaces::retry_unlinked_pending_with(
        &root,
        |_| Ok(false),
        || Ok(()),
        || Ok(()),
    )
    .is_err());
    assert_eq!(fs::read(&pending).unwrap(), b"1");
    connection.execute("DELETE FROM state WHERE key='recovery'", []).unwrap();
    drop(connection);

    let refreshed = std::cell::Cell::new(false);
    workspaces::retry_unlinked_pending_with(
        &root,
        |_| Ok(false),
        || Ok(()),
        || {
            refreshed.set(true);
            Ok(())
        },
    )
    .unwrap();
    assert!(refreshed.get());
    assert!(!pending.exists());
    workspaces::ready(&root).unwrap();
    fs::remove_dir_all(fixture).unwrap();
}
