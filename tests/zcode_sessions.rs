//! Synthetic persisted ZCode CLI 0.17.1 records from cass #573's verified
//! schema. These exercise real read-only database scans, not mocked queries.
#![cfg(feature = "zcode")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, bail};
use franken_agent_detection::connectors::sqlite_sync::{Connection, ConnectionExt};
use franken_agent_detection::connectors::zcode::{is_zcode_container, is_zcode_database};
use franken_agent_detection::{
    AgentDetectOptions, AgentDetectRootOverride, Connector, NormalizedConversation, Origin,
    ScanContext, ScanRoot, TokenDataSource, ZCodeConnector, detect_installed_agents,
    extract_tokens_for_agent, get_connector_factories,
};
use frankensqlite::params;
use serde_json::{Value, json};

const AT: i64 = 1_767_225_600_000;
const PRIVATE: &str = "zcode-private-runtime-and-credentials-sentinel";
const CHILD: &str = "FAD_ZCODE_TEST_CHILD";

fn database(path: &Path) -> Connection {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    connection
        .execute_batch(include_str!("../fixtures/zcode/schema.sql"))
        .unwrap();
    connection
        .execute_compat(
            "INSERT INTO local_setting VALUES ('credential', ?)",
            params![PRIVATE],
        )
        .unwrap();
    connection
}

fn session(connection: &Connection, id: &str, parent: Option<&str>, deleted: Option<i64>) {
    connection
        .execute_compat(
            "INSERT INTO session (id, project_id, parent_id, slug, directory, title, version,
          time_created, time_updated, time_deleted) VALUES (?, 'project', ?, ?, '/project', '',
          '0.17.1', ?, ?, ?)",
            params![id, parent, id, AT, AT, deleted],
        )
        .unwrap();
    connection
        .execute_compat(
            "INSERT INTO session_entry VALUES (?, ?, 'runtime/prompt_snapshot', ?, ?, ?)",
            params![format!("entry-{id}"), id, AT, AT, PRIVATE],
        )
        .unwrap();
}

fn message(connection: &Connection, session: &str, id: &str, sequence: Option<i64>, data: Value) {
    connection
        .execute_compat(
            "INSERT INTO message VALUES (?, ?, ?, ?, ?, ?)",
            params![id, session, AT, AT, data.to_string(), sequence],
        )
        .unwrap();
}

fn part(
    connection: &Connection,
    session: &str,
    message: &str,
    id: &str,
    sequence: Option<i64>,
    data: Value,
) {
    connection
        .execute_compat(
            "INSERT INTO part VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![id, message, session, AT, AT, data.to_string(), sequence],
        )
        .unwrap();
}

fn exchange(connection: &Connection, id: &str) {
    let user = format!("{id}-user");
    let assistant = format!("{id}-assistant");
    message(
        connection,
        id,
        &user,
        Some(0),
        json!({"role":"user", "semantics":{"origin":"real_user"}}),
    );
    part(
        connection,
        id,
        &user,
        &format!("{id}-prompt"),
        Some(0),
        json!({"type":"text", "text":format!("prompt {id}")}),
    );
    message(
        connection,
        id,
        &assistant,
        Some(1),
        json!({"role":"assistant", "parentID":user}),
    );
    part(
        connection,
        id,
        &assistant,
        &format!("{id}-answer"),
        Some(0),
        json!({"type":"text", "text":format!("answer {id}")}),
    );
}

fn context(root: &Path, since: Option<i64>) -> ScanContext {
    ScanContext::with_roots(
        PathBuf::new(),
        vec![ScanRoot::local(root.to_path_buf())],
        since,
    )
}

fn scan(path: &Path) -> Vec<NormalizedConversation> {
    ZCodeConnector::new().scan(&context(path, None)).unwrap()
}

fn counts(conversation: &NormalizedConversation) -> (i64, i64, i64, i64, i64) {
    conversation
        .messages
        .iter()
        .map(|message| {
            extract_tokens_for_agent("zcode", &message.extra, &message.content, &message.role)
        })
        .fold((0, 0, 0, 0, 0), |sum, usage| {
            (
                sum.0 + usage.input_tokens.unwrap_or(0),
                sum.1 + usage.output_tokens.unwrap_or(0),
                sum.2 + usage.thinking_tokens.unwrap_or(0),
                sum.3 + usage.cache_read_tokens.unwrap_or(0),
                sum.4 + usage.cache_creation_tokens.unwrap_or(0),
            )
        })
}

fn turn(connection: &Connection, session: &str, turn: &str, user: &str) {
    connection
        .execute_compat(
            "INSERT INTO turn_usage (session_id, turn_id, user_message_id, status, started_at,
          completed_at, input_tokens, output_tokens, reasoning_tokens, cache_read_input_tokens,
          cache_creation_input_tokens, computed_total_tokens) VALUES (?, ?, ?, 'completed', ?, ?,
          100, 30, 7, 11, 4, 130)",
            params![session, turn, user, AT, AT + 10],
        )
        .unwrap();
}

#[test]
fn zcode_orders_visible_messages_and_parts_and_keeps_all_tool_states_without_private_payloads() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("db.sqlite");
    let connection = database(&path);
    session(&connection, "ses/escaped", None, None);
    // IDs and JSON timestamps deliberately disagree with SQLite sequence order.
    message(
        &connection,
        "ses/escaped",
        "a-answer",
        Some(9),
        json!({
            "role":"assistant", "time":{"created":AT - 5}, "modelId":"example-model",
            "providerId":"personal:example", "parentID":"z-user",
            "semantics":{"origin":"agent_runtime", "uiVisibility":"visible"},
            "tokens":{"input":100,"output":30,"reasoning":7,"cache":{"read":11,"write":4}}
        }),
    );
    message(
        &connection,
        "ses/escaped",
        "z-user",
        None,
        json!({
            "role":"user", "time":{"created":AT + 5}, "semantics":{"origin":"real_user"}
        }),
    );
    part(
        &connection,
        "ses/escaped",
        "z-user",
        "prompt",
        None,
        json!({"type":"text", "text":"Real prompt first"}),
    );
    for (index, discriminator) in [
        json!({"synthetic":true}),
        json!({"visibility":"model-only"}),
        json!({"metadata":{"visibility":"model-only"}}),
        json!({"semantics":{"origin":"agent_runtime"}}),
        json!({"semantics":{"uiVisibility":"hidden"}}),
        json!({"semantics":{"transcriptVisibility":"hidden"}}),
    ]
    .into_iter()
    .enumerate()
    {
        let mut data = discriminator;
        data["role"] = "user".into();
        let id = format!("injection-{index}");
        message(&connection, "ses/escaped", &id, Some(1), data);
        part(
            &connection,
            "ses/escaped",
            &id,
            &id,
            Some(0),
            json!({"type":"text", "text":PRIVATE}),
        );
    }
    part(
        &connection,
        "ses/escaped",
        "a-answer",
        "a-last",
        Some(20),
        json!({"type":"text", "text":"Visible final answer"}),
    );
    part(
        &connection,
        "ses/escaped",
        "a-answer",
        "z-first",
        None,
        json!({"type":"reasoning", "text":"Visible reasoning first"}),
    );
    for (index, status) in ["pending", "running", "completed", "error"]
        .into_iter()
        .enumerate()
    {
        part(
            &connection,
            "ses/escaped",
            "a-answer",
            &format!("tool-{index}"),
            Some(index as i64 + 1),
            json!({
                "type":"tool", "callID":format!("call-{index}"), "tool":"Read",
                "state":{"status":status, "input":{"file_path":"/project/main.rs"},
                         "output":"Visible tool output", "error":"Visible tool error"}
            }),
        );
    }
    for (index, value) in [
        json!({"type":"text", "text":PRIVATE, "synthetic":true}),
        json!({"type":"reasoning", "text":PRIVATE, "ignored":true}),
        json!({"type":"tool", "tool":PRIVATE, "synthetic":true}),
        json!({"type":"snapshot", "snapshot":PRIVATE}),
        json!({"type":"step-finish", "tokens":{"input":999999,"output":999999}}),
        json!({"type":"file", "filename":"shot.png", "mime":"image/png", "url":format!("data:image/png;base64,{PRIVATE}")}),
    ].into_iter().enumerate() {
        part(&connection, "ses/escaped", "a-answer", &format!("private-{index}"), Some(25), value);
    }
    drop(connection);
    let before = fs::read(&path).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let conversations = scan(&path);
    assert_eq!(conversations.len(), 1);
    let conversation = &conversations[0];
    assert_eq!(conversation.messages.len(), 2);
    assert_eq!(conversation.messages[0].role, "user");
    assert_eq!(conversation.messages[0].created_at, Some(AT + 5));
    assert_eq!(conversation.messages[1].created_at, Some(AT - 5));
    assert_eq!(conversation.title.as_deref(), Some("Real prompt first"));
    assert!(conversation.source_path.ends_with("ses%2Fescaped"));
    let assistant = &conversation.messages[1];
    assert!(
        assistant.content.find("reasoning first").unwrap()
            < assistant.content.find("tool output").unwrap()
    );
    assert!(
        assistant.content.find("tool output").unwrap()
            < assistant.content.find("final answer").unwrap()
    );
    assert_eq!(assistant.invocations.len(), 4);
    assert_eq!(assistant.invocations[2].call_id.as_deref(), Some("call-2"));
    assert_eq!(
        assistant.invocations[2].arguments.as_ref().unwrap()["file_path"],
        "/project/main.rs"
    );
    assert_eq!(counts(conversation), (100, 30, 7, 11, 4));
    let encoded = serde_json::to_string(conversation).unwrap();
    assert!(!encoded.contains(PRIVATE));
    assert!(!encoded.contains("data:image"));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    assert!(!PathBuf::from(format!("{}-wal", path.display())).exists());
}

#[test]
fn zcode_uses_turn_counters_only_when_direct_message_usage_is_absent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("db.sqlite");
    let connection = database(&path);
    for id in ["direct", "fallback", "zero", "partial"] {
        session(&connection, id, None, None);
        exchange(&connection, id);
        turn(
            &connection,
            id,
            &format!("turn-{id}"),
            &format!("{id}-user"),
        );
        let tokens = match id {
            "direct" => {
                Some(json!({"input":100,"output":30,"reasoning":7,"cache":{"read":11,"write":4}}))
            }
            "zero" => {
                Some(json!({"input":0,"output":0,"reasoning":0,"cache":{"read":0,"write":0}}))
            }
            "partial" => Some(json!({"input":25,"output":10})),
            _ => None,
        };
        if let Some(tokens) = tokens {
            connection.execute_compat("UPDATE message SET data = ? WHERE id = ?", params![
                json!({"role":"assistant", "parentID":format!("{id}-user"), "tokens":tokens}).to_string(),
                format!("{id}-assistant")
            ]).unwrap();
        }
        let extra = format!("{id}-tail");
        message(
            &connection,
            id,
            &extra,
            Some(2),
            json!({"role":"assistant", "parentID":format!("{id}-user")}),
        );
        part(
            &connection,
            id,
            &extra,
            &extra,
            Some(0),
            json!({"type":"text", "text":"tail reply"}),
        );
    }
    drop(connection);
    for conversation in scan(&path) {
        let id = conversation.external_id.as_deref().unwrap();
        assert_eq!(conversation.metadata["turn_usage"][0]["input_tokens"], 100);
        assert_eq!(
            counts(&conversation),
            match id {
                "zero" => (0, 0, 0, 0, 0),
                "partial" => (25, 10, 0, 0, 0),
                _ => (100, 30, 7, 11, 4),
            },
            "{id}"
        );
        let usage = extract_tokens_for_agent(
            "zcode",
            &conversation.messages[0].extra,
            &conversation.messages[0].content,
            "user",
        );
        assert!(matches!(usage.data_source, TokenDataSource::Suppressed));
    }
}

#[test]
fn zcode_rejects_opencode_and_unrecognized_schema_but_recognizes_sensitive_container() {
    let directory = tempfile::tempdir().unwrap();
    let native = directory.path().join("opencode.db");
    let connection = database(&native);
    session(&connection, "native", None, None);
    exchange(&connection, "native");
    drop(connection);
    assert!(is_zcode_database(&native));
    assert!(is_zcode_container(&native).unwrap());
    // Generic folder names do not establish ownership. A copied database
    // still needs marker admission before another provider may raw-mirror it.
    let copied = directory.path().join("rollout/custom.sqlite");
    fs::create_dir_all(copied.parent().unwrap()).unwrap();
    fs::copy(&native, &copied).unwrap();
    assert!(is_zcode_container(&copied).unwrap());
    assert!(!is_zcode_database(&copied));
    // Ownership is case-insensitive, and known private locations need no I/O.
    let private = directory.path().join(".ZCODE/credentials.json");
    assert!(!private.exists());
    assert!(is_zcode_container(&private).unwrap());
    #[cfg(feature = "opencode")]
    {
        let root = ScanRoot::remote(native.clone(), Origin::remote("fixture"), None);
        let ctx = ScanContext::with_roots(PathBuf::new(), vec![root], None);
        assert!(
            franken_agent_detection::OpenCodeConnector::new()
                .scan(&ctx)
                .unwrap()
                .is_empty()
        );
        assert!(
            franken_agent_detection::OpenCodeConnector::new()
                .discover_source_files(&ctx)
                .unwrap()
                .is_empty()
        );
    }
    let opencode = directory.path().join("not-zcode.sqlite");
    let connection = Connection::open(opencode.to_str().unwrap()).unwrap();
    connection.execute_batch("CREATE TABLE session (id TEXT); CREATE TABLE message (id TEXT); CREATE TABLE part (id TEXT);").unwrap();
    drop(connection);
    assert!(!is_zcode_database(&opencode));
    assert!(!is_zcode_container(&opencode).unwrap());
    assert!(scan(&opencode).is_empty());
    let unsupported = directory.path().join("future.sqlite");
    let connection = Connection::open(unsupported.to_str().unwrap()).unwrap();
    connection.execute_batch("CREATE TABLE zcode_database_identity (id TEXT); CREATE TABLE session (different TEXT);").unwrap();
    drop(connection);
    assert!(!is_zcode_database(&unsupported));
    assert!(
        is_zcode_container(&unsupported).unwrap(),
        "unknown ZCode remains unsafe to raw-mirror"
    );
    assert!(scan(&unsupported).is_empty());
    assert!(
        get_connector_factories()
            .iter()
            .any(|(slug, _)| *slug == "zcode")
    );
    let detection = detect_installed_agents(&AgentDetectOptions {
        only_connectors: Some(vec!["zcode".into()]),
        include_undetected: true,
        root_overrides: vec![AgentDetectRootOverride {
            slug: "zcode".into(),
            root: opencode,
        }],
    })
    .unwrap();
    assert!(!detection.installed_agents[0].detected);
}

#[test]
fn zcode_skips_malformed_json_without_discarding_healthy_messages_or_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("db.sqlite");
    let connection = database(&path);
    for id in ["malformed", "healthy", "deleted"] {
        session(&connection, id, None, (id == "deleted").then_some(AT));
        exchange(&connection, id);
    }
    connection
        .execute_compat(
            "INSERT INTO message VALUES ('bad', 'malformed', ?, ?, '{broken', 2)",
            params![AT, AT],
        )
        .unwrap();
    connection.execute_compat("INSERT INTO part VALUES ('bad', 'malformed-assistant', 'malformed', ?, ?, '{broken', 1)", params![AT, AT]).unwrap();
    drop(connection);
    let conversations = scan(&path);
    assert_eq!(conversations.len(), 2);
    assert!(
        conversations
            .iter()
            .all(|conversation| conversation.messages.len() == 2)
    );
    assert!(
        conversations
            .iter()
            .all(|conversation| conversation.external_id.as_deref() != Some("deleted"))
    );
}

#[test]
fn zcode_incremental_scan_accounts_for_part_and_turn_updates_and_preserves_millisecond_units() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("db.sqlite");
    let connection = database(&path);
    for id in ["part-update", "turn-update", "old"] {
        session(&connection, id, None, None);
        exchange(&connection, id);
    }
    connection
        .execute_compat(
            "UPDATE part SET time_updated = ? WHERE id = 'part-update-answer'",
            params![AT + 100],
        )
        .unwrap();
    turn(&connection, "turn-update", "turn", "turn-update-user");
    drop(connection);
    let conversations = ZCodeConnector::new()
        .scan(&context(&path, Some(AT + 5)))
        .unwrap();
    assert_eq!(conversations.len(), 2);
    assert!(
        conversations
            .iter()
            .all(|conversation| conversation.started_at == Some(AT))
    );
    assert!(
        ZCodeConnector::new()
            .scan(&context(&path, Some(AT + 101)))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn zcode_shallow_discovery_deduplicates_sources_and_preserves_remote_provenance() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path();
    let path = home.join(".zcode/cli/db/db.sqlite");
    let connection = database(&path);
    session(&connection, "parent", None, None);
    exchange(&connection, "parent");
    connection
        .execute(
            "UPDATE session SET directory = '', path = '/original/project', time_archived = 1000",
        )
        .unwrap();
    drop(connection);
    for relative in [
        ".zcode/v2/credentials.json",
        ".zcode/v2/provider_config.json",
        ".zcode/cli/rollout/model-io-private.jsonl",
    ] {
        let file = home.join(relative);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, PRIVATE).unwrap();
    }
    let root = ScanRoot::remote(home.to_path_buf(), Origin::remote("remote-test"), None)
        .with_rewrite("/original", "/mapped");
    let ctx = ScanContext::with_roots(PathBuf::new(), vec![root.clone(), root], None);
    let files = ZCodeConnector::new().discover_source_files(&ctx).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].source_path, path);
    let conversations = ZCodeConnector::new().scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(
        conversations[0].workspace.as_deref(),
        Some(Path::new("/mapped/project"))
    );
    assert_eq!(
        conversations[0].metadata["origin"]["source_id"],
        "remote-test"
    );
    assert_eq!(conversations[0].metadata["time_archived"], 1000);
    assert!(scan(&home.join(".zcode/v2/credentials.json")).is_empty());
    let mut called = 0;
    let result = ZCodeConnector::new().scan_with_callback(&ctx, &mut |_| -> Result<()> {
        called += 1;
        bail!("host cancellation")
    });
    assert!(result.is_err());
    assert_eq!(called, 1);
}

#[test]
fn zcode_native_overrides_config_and_subagent_policy_use_isolated_processes() {
    if std::env::var_os(CHILD).is_some() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    for relative in [
        "home/.zcode/cli/db/db.sqlite",
        "alternate-store/cli/db/db.sqlite",
        "custom.history",
    ] {
        let connection = database(&root.join(relative));
        session(&connection, "parent", None, None);
        session(&connection, "child", Some("parent"), None);
        exchange(&connection, "parent");
        exchange(&connection, "child");
        drop(connection);
    }
    let run = |overrides: &[(&str, &str)], expected: &str, count: usize| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "zcode_discovery_child", "--nocapture"])
            .current_dir(root)
            .env(CHILD, root)
            .env("HOME", root.join("home"))
            .env("USERPROFILE", root.join("home"))
            .env("FAD_ZCODE_EXPECTED", root.join(expected))
            .env("FAD_ZCODE_COUNT", count.to_string());
        for variable in [
            "ZCODE_SESSION_DB_PATH",
            "ZCODE_SESSION_DB",
            "ZCODE_STORAGE_DIR",
            "CASS_EXCLUDE_PATHS",
            "CASS_SKIP_SUBAGENTS",
        ] {
            command.env_remove(variable);
        }
        for (key, value) in overrides {
            command.env(key, value);
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "overrides={overrides:?}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    };
    run(&[], "home/.zcode/cli/db/db.sqlite", 2);
    run(
        &[("ZCODE_SESSION_DB", "custom.history")],
        "custom.history",
        2,
    );
    run(
        &[
            ("ZCODE_SESSION_DB_PATH", "custom.history"),
            ("ZCODE_SESSION_DB", "missing.sqlite"),
        ],
        "custom.history",
        2,
    );
    run(
        &[("ZCODE_STORAGE_DIR", "alternate-store")],
        "alternate-store/cli/db/db.sqlite",
        2,
    );
    run(
        &[("ZCODE_SESSION_DB_PATH", "missing.sqlite")],
        "missing.sqlite",
        0,
    );
    run(
        &[("CASS_SKIP_SUBAGENTS", "1")],
        "home/.zcode/cli/db/db.sqlite",
        1,
    );
    fs::write(
        root.join("home/.zcode/cli/config.json"),
        json!({"storage":{"sessionDbPath":root.join("custom.history")}}).to_string(),
    )
    .unwrap();
    run(&[], "custom.history", 2);
    run(
        &[("ZCODE_SESSION_DB_PATH", "~/ .missing")],
        "home/ .missing",
        0,
    );
    fs::write(
        root.join("alternate-store/cli/config.json"),
        json!({"storage":{"sessionDbPath":root.join("custom.history")}}).to_string(),
    )
    .unwrap();
    run(
        &[("ZCODE_STORAGE_DIR", "alternate-store")],
        "custom.history",
        2,
    );
}

#[test]
fn zcode_discovery_child() {
    let Some(root) = std::env::var_os(CHILD).map(PathBuf::from) else {
        return;
    };
    let expected = PathBuf::from(std::env::var_os("FAD_ZCODE_EXPECTED").unwrap());
    let count: usize = std::env::var("FAD_ZCODE_COUNT").unwrap().parse().unwrap();
    let configured = ZCodeConnector::configured_db_path().unwrap();
    let configured_absolute = if configured.is_absolute() {
        configured
    } else {
        root.join(configured)
    };
    assert_eq!(configured_absolute, expected);
    let connector = ZCodeConnector::new();
    assert_eq!(connector.detect().detected, count != 0);
    let report = detect_installed_agents(&AgentDetectOptions {
        only_connectors: Some(vec!["zcode".into()]),
        include_undetected: true,
        root_overrides: Vec::new(),
    })
    .unwrap();
    assert_eq!(report.installed_agents[0].detected, count != 0);
    let conversations = connector
        .scan(&ScanContext::local_default(PathBuf::new(), None))
        .unwrap();
    assert_eq!(conversations.len(), count);
    if count == 1 {
        assert_eq!(conversations[0].external_id.as_deref(), Some("parent"));
    }
    assert!(
        connector
            .scan(&context(&root.join("empty-source"), None))
            .unwrap()
            .is_empty(),
        "explicit roots must not pull the process's default history into their source"
    );
}
