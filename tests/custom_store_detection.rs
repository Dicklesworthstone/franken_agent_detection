//! Detection must admit the same configured history stores as the connectors.
//! Environment changes live in child processes so these cases remain isolated
//! from the parallel test suite. SQLite fixtures use the supported engine and
//! are exercised only when their connector's feature is enabled.
//! These cases run on Unix, where the directory resolver honors the isolated
//! HOME; Windows known-folder APIs can resolve outside a supplied test home.

#![cfg(all(feature = "connectors", unix))]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use franken_agent_detection::{
    AgentDetectOptions, AgentDetectRootOverride, Connector, NormalizedConversation, Origin,
    ScanContext, ScanRoot, detect_installed_agents, get_connector_factories,
};
use serde_json::json;
use tempfile::TempDir;

const CHILD_CASE: &str = "FAD_CUSTOM_STORE_CASE";
const OVERRIDES: [&str; 10] = [
    "GEMINI_HOME",
    "OPENCODE_STORAGE_ROOT",
    "OPENCODE_SQLITE_DB",
    "HERMES_HOME",
    "HERMES_SQLITE_DB",
    "CRUSH_SQLITE_DB",
    "GOOSE_PATH_ROOT",
    "GOOSE_SQLITE_DB",
    "CASS_CURSOR_PROJECTS_ROOT",
    "CASS_EXCLUDE_PATHS",
];

struct Fixture {
    dir: TempDir,
    provider: &'static str,
    scoped: PathBuf,
}

impl Fixture {
    fn new(provider: &'static str) -> Self {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("home")).unwrap();
        let scoped = write_store(&dir.path().join("scoped"), provider, "scoped");
        Self {
            dir,
            provider,
            scoped,
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.path().join(relative)
    }

    fn store(&self, relative: &str, id: &str) -> PathBuf {
        write_store(&self.path(relative), self.provider, id)
    }

    fn run(&self, env: &[(&str, OsString)], expected: &[&str], probe: Option<&Path>) {
        self.run_with_handoff(env, expected, probe, expected);
    }

    fn run_with_handoff(
        &self,
        env: &[(&str, OsString)],
        expected: &[&str],
        probe: Option<&Path>,
        handoff_expected: &[&str],
    ) {
        let before = snapshot(self.dir.path());
        let case = json!({
            "root": self.dir.path(), "provider": self.provider,
            "expected": expected, "probe": probe, "scoped": self.scoped,
            "handoff_expected": handoff_expected,
        });
        let home = self.path("home");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "custom_store_child", "--nocapture"])
            .current_dir(self.dir.path())
            .env(CHILD_CASE, case.to_string())
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("APPDATA", home.join("AppData/Roaming"))
            .env("LOCALAPPDATA", home.join("AppData/Local"));
        for variable in OVERRIDES {
            command.env_remove(variable);
        }
        for (key, value) in env {
            command.env(key, value);
        }
        let output = command.output().expect("run isolated custom-store case");
        assert!(
            output.status.success(),
            "provider={} env={env:?} expected={expected:?}\nstdout:\n{}\nstderr:\n{}",
            self.provider,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(
            snapshot(self.dir.path()),
            before,
            "detection and scanning must not change source bytes or create sidecars"
        );
    }
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    walkdir::WalkDir::new(root)
        .into_iter()
        .map(Result::unwrap)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| {
            (
                entry.path().strip_prefix(root).unwrap().to_path_buf(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

fn write_json(path: &Path, value: &serde_json::Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn write_store(root: &Path, provider: &str, id: &str) -> PathBuf {
    match provider {
        "gemini" => {
            write_json(
                &root
                    .join("project/chats")
                    .join(format!("session-{id}.json")),
                &json!({"sessionId": id, "messages": [
                    {"type": "user", "content": id, "timestamp": "2026-10-09T00:00:00Z"}
                ]}),
            );
            root.to_path_buf()
        }
        #[cfg(feature = "cursor")]
        "cursor" => {
            write_json(
                &root
                    .join("project/agent-transcripts")
                    .join(id)
                    .join(format!("{id}.jsonl")),
                &json!({"role": "user", "message": {"content": [
                    {"type": "text", "text": id}
                ]}}),
            );
            root.to_path_buf()
        }
        #[cfg(any(
            feature = "opencode",
            feature = "hermes",
            feature = "crush",
            feature = "goose"
        ))]
        "opencode" | "hermes" | "crush" | "goose" => {
            let filename = match provider {
                "opencode" => "opencode.db",
                "hermes" => "state.db",
                "crush" => "crush.db",
                "goose" => "sessions.db",
                _ => unreachable!(),
            };
            let path = root.join(filename);
            write_sqlite(&path, provider, id);
            path
        }
        other => panic!("unsupported fixture provider {other}"),
    }
}

#[cfg(feature = "opencode")]
fn write_opencode_legacy(root: &Path, id: &str) {
    write_json(
        &root.join("session/project").join(format!("{id}.json")),
        &json!({"id": id, "projectID": "project", "title": id}),
    );
    write_json(
        &root.join("message").join(id).join("message.json"),
        &json!({"id": "message", "sessionID": id, "role": "user"}),
    );
    write_json(
        &root.join("part/message/part.json"),
        &json!({"id": "part", "messageID": "message", "type": "text", "text": id}),
    );
}

#[cfg(any(
    feature = "opencode",
    feature = "hermes",
    feature = "crush",
    feature = "goose"
))]
#[allow(clippy::too_many_lines)]
fn write_sqlite(path: &Path, provider: &str, id: &str) {
    use franken_agent_detection::connectors::sqlite_sync::{Connection, ConnectionExt};
    use frankensqlite::params;

    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let conn = Connection::open(path.to_str().unwrap()).unwrap();
    match provider {
        "opencode" => {
            conn.execute_batch(
                "CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT, title TEXT,
                    directory TEXT, time_created INTEGER, time_updated INTEGER);
                 CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT,
                    time_created INTEGER, time_updated INTEGER);
                 CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT,
                    data TEXT, time_created INTEGER, time_updated INTEGER);",
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO session VALUES (?, 'project', ?, NULL, 1700000000000, 1700000000000)",
                params![id, id],
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO message VALUES ('message', ?, '{\"role\":\"user\"}', 1700000000000, 1700000000000)",
                params![id],
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO part VALUES ('part', 'message', ?, ?, 1700000000000, 1700000000000)",
                params![id, json!({"type": "text", "text": id}).to_string()],
            )
            .unwrap();
        }
        "hermes" => {
            conn.execute_batch(
                "CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT, model TEXT, title TEXT,
                    parent_session_id TEXT, started_at REAL, ended_at REAL, end_reason TEXT,
                    message_count INTEGER, tool_call_count INTEGER, input_tokens INTEGER,
                    output_tokens INTEGER);
                 CREATE TABLE messages (session_id TEXT, role TEXT, content TEXT, tool_calls TEXT,
                    tool_name TEXT, tool_call_id TEXT, reasoning TEXT, timestamp REAL);",
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO sessions VALUES (?, 'cli', 'model', ?, NULL, 1700000000,
                    1700000001, 'completed', 1, 0, 10, 5)",
                params![id, id],
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO messages VALUES (?, 'user', ?, NULL, NULL, NULL, NULL, 1700000000)",
                params![id, id],
            )
            .unwrap();
        }
        "crush" => {
            conn.execute_batch(
                "CREATE TABLE sessions (id TEXT PRIMARY KEY, title TEXT, prompt_tokens INTEGER,
                    completion_tokens INTEGER, cost REAL);
                 CREATE TABLE messages (session_id TEXT, role TEXT, parts TEXT, created_at INTEGER,
                    model TEXT, provider TEXT);",
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO sessions VALUES (?, ?, 10, 5, 0.1)",
                params![id, id],
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO messages VALUES (?, 'user', ?, 1700000000000, 'model', 'provider')",
                params![id, json!([{"type": "text", "text": id}]).to_string()],
            )
            .unwrap();
        }
        "goose" => {
            conn.execute_batch(
                "CREATE TABLE sessions (id TEXT PRIMARY KEY, description TEXT, working_dir TEXT,
                    created_at INTEGER, updated_at INTEGER, provider_name TEXT,
                    model_config_json TEXT, session_type TEXT);
                 CREATE TABLE messages (session_id TEXT, role TEXT, content_json TEXT,
                    created_timestamp INTEGER, tokens INTEGER, metadata_json TEXT,
                    message_id TEXT PRIMARY KEY);",
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO sessions VALUES (?, ?, NULL, 1700000000, 1700000001,
                    'provider', NULL, NULL)",
                params![id, id],
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO messages VALUES (?, 'user', ?, 1700000000, 5, NULL, 'message')",
                params![id, json!([{"type": "text", "text": id}]).to_string()],
            )
            .unwrap();
        }
        other => panic!("unsupported SQLite fixture {other}"),
    }
}

fn assert_conversations(
    conversations: &[NormalizedConversation],
    provider: &str,
    expected: &[&str],
) {
    let mut actual: Vec<_> = conversations
        .iter()
        .map(|conversation| {
            assert_eq!(conversation.agent_slug, provider);
            let id = conversation.external_id.as_deref().unwrap();
            assert_eq!(conversation.messages.len(), 1);
            assert_eq!(conversation.messages[0].role, "user");
            assert_eq!(conversation.messages[0].content, id);
            id
        })
        .collect();
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

fn assert_scan(connector: &dyn Connector, ctx: &ScanContext, provider: &str, expected: &[&str]) {
    let conversations = connector.scan(ctx).unwrap();
    assert_conversations(&conversations, provider, expected);
    let sources = connector.discover_source_files(ctx).unwrap();
    if let Some(scope) = ctx.scan_roots.first() {
        for source in &sources {
            assert!(source.source_path.starts_with(&scope.path));
            assert_eq!(source.origin.source_id, scope.origin.source_id);
        }
    }
    for conversation in conversations {
        assert!(
            sources.iter().any(|source| {
                conversation.source_path == source.source_path
                    || conversation.source_path.starts_with(&source.source_path)
            }),
            "discovery omitted consumed source {}",
            conversation.source_path.display(),
        );
    }
}

#[test]
fn custom_store_child() {
    let Ok(case) = std::env::var(CHILD_CASE) else {
        return;
    };
    let case: serde_json::Value = serde_json::from_str(&case).unwrap();
    let provider = case["provider"].as_str().unwrap();
    let root = PathBuf::from(case["root"].as_str().unwrap());
    let expected: Vec<_> = case["expected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap())
        .collect();
    let factory = get_connector_factories()
        .into_iter()
        .find(|(slug, _)| *slug == provider)
        .unwrap()
        .1;
    let connector = factory();
    let detected = connector.detect();
    assert_eq!(detected.detected, !expected.is_empty(), "{detected:?}");
    if let Some(probe) = case["probe"].as_str() {
        assert!(
            detected.root_paths.contains(&PathBuf::from(probe)),
            "{detected:?}"
        );
    }

    // Exercise the host's public detection gate, followed by the ordinary
    // default scan. A data_dir handoff keeps its existing scope: in particular,
    // passing a Crush database file intentionally selects only that store.
    let ctx = ScanContext::local_default(root.join("cass-state"), None);
    assert_scan(connector.as_ref(), &ctx, provider, &expected);
    if detected.detected {
        let ctx = ScanContext::local_default(detected.root_paths[0].clone(), None);
        let handoff_expected: Vec<_> = case["handoff_expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap())
            .collect();
        assert_scan(connector.as_ref(), &ctx, provider, &handoff_expected);
    }

    // Explicit detector overrides and remote scan scopes must remain isolated
    // from all of the valid environment/default stores above.
    let scoped = PathBuf::from(case["scoped"].as_str().unwrap());
    for (path, should_detect) in [(&scoped, true), (&root.join("absent-scope"), false)] {
        let report = detect_installed_agents(&AgentDetectOptions {
            only_connectors: Some(vec![provider.to_string()]),
            include_undetected: true,
            root_overrides: vec![AgentDetectRootOverride {
                slug: provider.to_string(),
                root: path.clone(),
            }],
        })
        .unwrap();
        assert_eq!(report.installed_agents.len(), 1);
        let entry = &report.installed_agents[0];
        assert_eq!(entry.detected, should_detect);
        assert_eq!(
            entry.root_paths,
            if should_detect {
                vec![path.display().to_string()]
            } else {
                vec![]
            },
        );
    }
    let ctx = ScanContext::with_roots(
        root.join("cass-state"),
        vec![ScanRoot::remote(scoped, Origin::remote("mirror"), None)],
        None,
    );
    assert_scan(connector.as_ref(), &ctx, provider, &["scoped"]);
}

#[test]
fn gemini_custom_home_is_detected_and_remains_a_replacement() {
    let fixture = Fixture::new("gemini");
    let custom = fixture.store("custom", "custom");
    fixture.run(
        &[("GEMINI_HOME", custom.clone().into())],
        &["custom"],
        Some(&custom),
    );

    fixture.store("home/.gemini/tmp", "default");
    fixture.run(&[("GEMINI_HOME", custom.into())], &["custom"], None);
    fixture.run(&[], &["default"], None);
    fixture.run(&[("GEMINI_HOME", " \t ".into())], &["default"], None);
    // An explicit missing root still replaces the default Gemini history.
    fixture.run(&[("GEMINI_HOME", fixture.path("absent").into())], &[], None);
}

#[cfg(feature = "opencode")]
#[test]
fn opencode_configured_sqlite_and_legacy_stores_are_additive() {
    let fixture = Fixture::new("opencode");
    let db = fixture.store("custom-db", "database");
    let storage = fixture.path("custom-storage");
    write_opencode_legacy(&storage, "legacy");
    fixture.run(
        &[("OPENCODE_SQLITE_DB", db.clone().into())],
        &["database"],
        Some(&db),
    );
    fixture.run(
        &[("OPENCODE_STORAGE_ROOT", storage.clone().into())],
        &["legacy"],
        Some(&storage),
    );
    fixture.run(
        &[
            ("OPENCODE_SQLITE_DB", db.clone().into()),
            ("OPENCODE_STORAGE_ROOT", storage.clone().into()),
        ],
        &["database", "legacy"],
        None,
    );
    fixture.store("home/.local/share/opencode", "default-db");
    write_opencode_legacy(
        &fixture.path("home/.local/share/opencode/storage"),
        "default-json",
    );
    fixture.run(
        &[
            ("OPENCODE_SQLITE_DB", db.into()),
            ("OPENCODE_STORAGE_ROOT", storage.into()),
        ],
        &["database", "default-db", "legacy"],
        None,
    );
}

#[test]
fn gemini_explicit_session_file_requires_the_supported_path_shape() {
    let fixture = Fixture::new("gemini");
    let custom = fixture.store("custom", "custom");
    let valid = custom.join("project/chats/session-custom.json");
    fixture.run(
        &[("GEMINI_HOME", valid.clone().into())],
        &["custom"],
        Some(&valid),
    );

    // Valid session JSON alone is insufficient: both the session filename
    // and the enclosing chats directory are part of source admission.
    for invalid in [
        custom.join("project/chats/notes.json"),
        custom.join("session-outside-chats.json"),
    ] {
        fs::copy(&valid, &invalid).unwrap();
        fixture.run(&[("GEMINI_HOME", invalid.into())], &[], None);
    }
}

#[cfg(feature = "opencode")]
#[test]
fn opencode_missing_or_blank_overrides_preserve_default_stores() {
    let fixture = Fixture::new("opencode");
    let db = fixture.store("home/.local/share/opencode", "default-db");
    write_opencode_legacy(
        &fixture.path("home/.local/share/opencode/storage"),
        "default-json",
    );
    let missing = fixture.path("absent");
    for value in [OsString::new(), " \t ".into(), missing.into()] {
        fixture.run(
            &[
                ("OPENCODE_SQLITE_DB", value.clone()),
                ("OPENCODE_STORAGE_ROOT", value),
            ],
            &["default-db", "default-json"],
            Some(&db),
        );
    }
    // A directory is not a SQLite database and a regular file is not storage.
    fs::create_dir(fixture.path("custom-directory")).unwrap();
    fixture.run(
        &[
            (
                "OPENCODE_SQLITE_DB",
                fixture.path("custom-directory").into(),
            ),
            ("OPENCODE_STORAGE_ROOT", db.clone().into()),
        ],
        &["default-db", "default-json"],
        Some(&db),
    );
}

#[cfg(feature = "hermes")]
#[test]
fn hermes_configured_database_precedes_home_and_falls_back_when_missing() {
    let fixture = Fixture::new("hermes");
    let db = fixture.store("custom-db", "database");
    let home_db = fixture.store("custom-home", "home");
    let home = home_db.parent().unwrap().to_path_buf();
    fixture.run(
        &[("HERMES_SQLITE_DB", db.clone().into())],
        &["database"],
        Some(&db),
    );
    fixture.run(
        &[("HERMES_HOME", home.clone().into())],
        &["home"],
        Some(&home_db),
    );
    fixture.run(
        &[
            ("HERMES_SQLITE_DB", db.into()),
            ("HERMES_HOME", home.clone().into()),
        ],
        &["database"],
        None,
    );
    fixture.run(
        &[
            ("HERMES_SQLITE_DB", fixture.path("absent.db").into()),
            ("HERMES_HOME", home.into()),
        ],
        &["home"],
        Some(&home_db),
    );
    fixture.store("home/.hermes", "default");
    fixture.run(&[], &["default"], None);
    fs::create_dir(fixture.path("directory.db")).unwrap();
    for value in [
        OsString::new(),
        " \t ".into(),
        fixture.path("absent").into(),
        fixture.path("directory.db").into(),
    ] {
        fixture.run(
            &[("HERMES_SQLITE_DB", value.clone()), ("HERMES_HOME", value)],
            &["default"],
            None,
        );
    }
}

#[cfg(any(feature = "crush", feature = "goose"))]
fn assert_database_override_and_fallback(provider: &'static str, key: &str, default: &str) {
    let fixture = Fixture::new(provider);
    let db = fixture.store("custom", "custom");
    fixture.run(&[(key, db.clone().into())], &["custom"], Some(&db));
    fixture.store(default, "default");
    fixture.run(&[(key, db.into())], &["custom"], None);
    fixture.run(&[], &["default"], None);
    let wrong_kind = fixture.path("directory.db");
    fs::create_dir(&wrong_kind).unwrap();
    for value in [
        OsString::new(),
        " \t ".into(),
        fixture.path("absent.db").into(),
        wrong_kind.into(),
    ] {
        fixture.run(&[(key, value)], &["default"], None);
    }
}

#[cfg(feature = "crush")]
#[test]
fn crush_configured_database_is_detected_without_losing_default_fallback() {
    assert_database_override_and_fallback("crush", "CRUSH_SQLITE_DB", "home/.crush");
}

#[cfg(feature = "crush")]
#[test]
fn crush_default_scan_keeps_project_store_and_db_handoff_stays_scoped() {
    let fixture = Fixture::new("crush");
    let db = fixture.store("custom", "custom");
    fixture.store(".crush", "project");
    fixture.run_with_handoff(
        &[("CRUSH_SQLITE_DB", db.into())],
        &["custom", "project"],
        None,
        &["custom"],
    );
}

#[cfg(feature = "goose")]
#[test]
fn goose_configured_database_is_detected_without_losing_default_fallback() {
    assert_database_override_and_fallback(
        "goose",
        "GOOSE_SQLITE_DB",
        "home/.local/share/goose/sessions",
    );
}

#[cfg(feature = "goose")]
#[test]
fn goose_explicit_database_survives_an_absent_path_root() {
    let fixture = Fixture::new("goose");
    let db = fixture.store("custom", "custom");
    fixture.run(
        &[
            ("GOOSE_SQLITE_DB", db.clone().into()),
            ("GOOSE_PATH_ROOT", fixture.path("absent").into()),
        ],
        &["custom"],
        Some(&db),
    );
    let path_root = fixture.path("goose-root");
    let legacy = path_root.join("data/sessions/legacy.jsonl");
    write_json(&legacy, &json!({"role": "user", "content": "legacy"}));
    fixture.run(
        &[
            ("GOOSE_SQLITE_DB", db.into()),
            ("GOOSE_PATH_ROOT", path_root.into()),
        ],
        &["custom", "legacy"],
        None,
    );
}

#[cfg(feature = "cursor")]
#[test]
fn cursor_configured_projects_are_detected_and_explicit_scans_stay_scoped() {
    let fixture = Fixture::new("cursor");
    let custom = fixture.store("custom-projects", "custom");
    fixture.run(
        &[("CASS_CURSOR_PROJECTS_ROOT", custom.clone().into())],
        &["custom"],
        Some(&custom),
    );
    fixture.store("home/.cursor/projects", "default");
    fixture.run(
        &[("CASS_CURSOR_PROJECTS_ROOT", custom.into())],
        &["custom"],
        None,
    );
    fixture.run(&[], &["default"], None);
    fixture.run(
        &[("CASS_CURSOR_PROJECTS_ROOT", " \t ".into())],
        &["default"],
        None,
    );
}

#[cfg(feature = "cursor")]
#[test]
fn cursor_missing_projects_override_preserves_independent_composer_store() {
    use franken_agent_detection::connectors::sqlite_sync::{Connection, ConnectionExt};
    use frankensqlite::params;

    let fixture = Fixture::new("cursor");
    fixture.store("home/.cursor/projects", "default");
    let app_base = fixture.path(if cfg!(target_os = "macos") {
        "home/Library/Application Support/Cursor/User"
    } else {
        "home/.config/Cursor/User"
    });
    let db = app_base.join("globalStorage/state.vscdb");
    fs::create_dir_all(db.parent().unwrap()).unwrap();
    let conn = Connection::open(db.to_str().unwrap()).unwrap();
    conn.execute_batch(
        "CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT);
         CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT);",
    )
    .unwrap();
    conn.execute_compat(
        "INSERT INTO cursorDiskKV VALUES (?, ?)",
        params![
            "composerData:composer",
            json!({"text": "composer"}).to_string()
        ],
    )
    .unwrap();
    drop(conn);

    fixture.run(
        &[(
            "CASS_CURSOR_PROJECTS_ROOT",
            fixture.path("absent-projects").into(),
        )],
        &["composer"],
        None,
    );
    fixture.run(
        &[("CASS_CURSOR_PROJECTS_ROOT", " \t ".into())],
        &["composer", "default"],
        None,
    );
}
