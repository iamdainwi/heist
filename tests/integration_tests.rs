//! Integration tests — end-to-end encrypt/persist/decrypt round-trips.

use std::collections::HashSet;

use heist::{
    store::Store,
    vault::{key_to_env, validate_key, AuditAction, Secret},
};
use tempfile::tempdir;

// ── Store round-trips ─────────────────────────────────────────────────────────

#[test]
fn init_and_open() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.heist");

    Store::init(&path, "passw0rd!", false).unwrap();
    let store = Store::open(&path, "passw0rd!").unwrap();
    assert_eq!(store.secret_count(), 0);
}

#[test]
fn wrong_password_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.heist");

    Store::init(&path, "correct", false).unwrap();
    assert!(Store::open(&path, "wrong").is_err());
}

#[test]
fn secrets_survive_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.heist");

    let mut store = Store::init(&path, "pw", false).unwrap();
    store.data.secrets.insert(
        "github/token".into(),
        Secret::new(
            "ghp_abc123".into(),
            Some("GitHub PAT".into()),
            vec!["github".into()],
        ),
    );
    store.data.secrets.insert(
        "DATABASE_URL".into(),
        Secret::new("postgres://localhost/db".into(), None, vec![]),
    );
    store.save().unwrap();

    let store2 = Store::open(&path, "pw").unwrap();
    assert_eq!(store2.data.secrets["github/token"].value, "ghp_abc123");
    assert_eq!(
        store2.data.secrets["github/token"].description.as_deref(),
        Some("GitHub PAT")
    );
    assert_eq!(
        store2.data.secrets["DATABASE_URL"].value,
        "postgres://localhost/db"
    );
}

#[test]
fn update_secret_preserves_created_at() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.heist");

    let mut store = Store::init(&path, "pw", false).unwrap();
    store.data.secrets.insert(
        "TOKEN".into(),
        Secret::new("old-value".into(), None, vec![]),
    );
    store.save().unwrap();

    let mut store2 = Store::open(&path, "pw").unwrap();
    let created = store2.data.secrets["TOKEN"].created_at;

    let secret = store2.data.secrets.get_mut("TOKEN").unwrap();
    secret.update("new-value".into(), None, None);
    store2.save().unwrap();

    let store3 = Store::open(&path, "pw").unwrap();
    assert_eq!(store3.data.secrets["TOKEN"].value, "new-value");
    assert_eq!(store3.data.secrets["TOKEN"].created_at, created);
    assert!(store3.data.secrets["TOKEN"].updated_at > created);
}

#[test]
fn delete_secret() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.heist");

    let mut store = Store::init(&path, "pw", false).unwrap();
    store
        .data
        .secrets
        .insert("KEY".into(), Secret::new("val".into(), None, vec![]));
    store.save().unwrap();

    let mut store2 = Store::open(&path, "pw").unwrap();
    store2.data.secrets.remove("KEY");
    store2.save().unwrap();

    let store3 = Store::open(&path, "pw").unwrap();
    assert!(!store3.data.secrets.contains_key("KEY"));
}

#[test]
fn force_overwrites_existing_vault() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.heist");

    let mut store = Store::init(&path, "pw1", false).unwrap();
    store
        .data
        .secrets
        .insert("K".into(), Secret::new("v".into(), None, vec![]));
    store.save().unwrap();

    Store::init(&path, "pw2", true).unwrap();

    assert!(Store::open(&path, "pw1").is_err());

    let store2 = Store::open(&path, "pw2").unwrap();
    assert_eq!(store2.secret_count(), 0);
}

#[test]
fn password_rotation() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.heist");

    let mut store = Store::init(&path, "old", false).unwrap();
    store
        .data
        .secrets
        .insert("S".into(), Secret::new("secret".into(), None, vec![]));
    store.rotate_password("new").unwrap();

    assert!(Store::open(&path, "old").is_err());
    let store2 = Store::open(&path, "new").unwrap();
    assert_eq!(store2.data.secrets["S"].value, "secret");
}

// ── Audit log ─────────────────────────────────────────────────────────────────

#[test]
fn audit_log_survives_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.heist");

    let mut store = Store::init(&path, "pw", false).unwrap();
    store.audit.record(AuditAction::Set, "my/key", None);
    store
        .audit
        .record(AuditAction::Get, "my/key", Some("test note".into()));
    store.save().unwrap();

    let store2 = Store::open(&path, "pw").unwrap();
    // Init + 2 explicit records.
    assert!(store2.audit.entries.len() >= 2);
    let actions: Vec<_> = store2.audit.entries.iter().map(|e| &e.action).collect();
    assert!(actions.contains(&&AuditAction::Set));
    assert!(actions.contains(&&AuditAction::Get));
}

#[test]
fn audit_log_caps_at_1000_entries() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.heist");

    let mut store = Store::init(&path, "pw", false).unwrap();
    for i in 0..1200 {
        store
            .audit
            .record(AuditAction::Get, &format!("key/{i}"), None);
    }
    assert!(store.audit.entries.len() <= 1000);
}

// ── Key validation ────────────────────────────────────────────────────────────

#[test]
fn key_validation_allows_valid_keys() {
    let valid = [
        "TOKEN",
        "aws/access-key",
        "prod/db/PASSWORD",
        "x.y.z",
        "A-B_C",
        "user@example",
    ];
    for k in &valid {
        assert!(validate_key(k).is_ok(), "expected '{k}' to be valid");
    }
}

#[test]
fn key_validation_rejects_invalid_keys() {
    let invalid = [
        "",
        "/leading-slash",
        "trailing-slash/",
        "double//slash",
        "has space",
        "has$dollar",
        &"x".repeat(300),
    ];
    for k in &invalid {
        assert!(validate_key(k).is_err(), "expected '{k}' to be invalid");
    }
}

#[test]
fn key_to_env_conversion() {
    assert_eq!(key_to_env("aws/access-key"), "AWS_ACCESS_KEY");
    assert_eq!(key_to_env("prod/db/PASSWORD"), "PROD_DB_PASSWORD");
    assert_eq!(key_to_env("simple"), "SIMPLE");
    assert_eq!(key_to_env("x.y.z"), "X_Y_Z");
}

// ── Multiple saves don't corrupt data ─────────────────────────────────────────

#[test]
fn multiple_consecutive_saves() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.heist");

    let mut store = Store::init(&path, "pw", false).unwrap();

    for i in 0..20 {
        store.data.secrets.insert(
            format!("key/{i}"),
            Secret::new(format!("value-{i}"), None, vec![]),
        );
        store.save().unwrap();
    }

    let store2 = Store::open(&path, "pw").unwrap();
    assert_eq!(store2.secret_count(), 20);

    let keys: HashSet<_> = store2.data.secrets.keys().cloned().collect();
    for i in 0..20 {
        assert!(keys.contains(&format!("key/{i}")));
    }
}

// ── Secret metadata ───────────────────────────────────────────────────────────

#[test]
fn secret_tags_filter() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.heist");

    let mut store = Store::init(&path, "pw", false).unwrap();
    store.data.secrets.insert(
        "prod/api-key".into(),
        Secret::new("key1".into(), None, vec!["prod".into(), "api".into()]),
    );
    store.data.secrets.insert(
        "dev/api-key".into(),
        Secret::new("key2".into(), None, vec!["dev".into(), "api".into()]),
    );
    store.data.secrets.insert(
        "prod/db-pass".into(),
        Secret::new("dbpass".into(), None, vec!["prod".into(), "db".into()]),
    );
    store.save().unwrap();

    let store2 = Store::open(&path, "pw").unwrap();

    let prod_api: Vec<_> = store2
        .data
        .secrets
        .iter()
        .filter(|(_, s)| s.tags.contains(&"prod".into()) && s.tags.contains(&"api".into()))
        .collect();
    assert_eq!(prod_api.len(), 1);
    assert_eq!(prod_api[0].0, "prod/api-key");
}
