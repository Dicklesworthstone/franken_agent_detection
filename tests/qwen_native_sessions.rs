//! Native Qwen Code JSONL ingestion through public connector APIs.
//!
//! Fixtures follow QwenLM/qwen-code a238b91e7c6fc2b0e36e23436b0e4ced5296617b:
//! packages/core/src/services/chatRecordingService.ts,
//! packages/core/src/utils/transcript-records.ts and config/storage.ts.
#![cfg(feature = "connectors")]

use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use franken_agent_detection::token_extraction::{TokenDataSource, extract_tokens_for_agent};
use franken_agent_detection::{
    Connector, DiscoveredSourceFile, DiscoveredSourceRole, NormalizedConversation, Origin,
    Platform, QwenConnector, ScanContext, ScanRoot, SourceCompletion, SourceScanHooks,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const SESSION_ID: &str = "47c09e1e-9b87-401c-bdeb-6c357ab925f9";
const COMPACT_THRESHOLD: u64 = 32 * 1024 * 1024;

fn record(uuid: &str, parent: Option<&str>, kind: &str, parts: &[Value]) -> Value {
    json!({
        "uuid": uuid, "parentUuid": parent, "sessionId": SESSION_ID,
        "timestamp": "2026-10-10T12:00:00Z", "type": kind,
        "cwd": "/home/remote/project", "version": "0.19.0",
        "message": { "role": if kind == "assistant" { "model" } else { "user" }, "parts": parts },
    })
}

fn text_record(uuid: &str, parent: Option<&str>, kind: &str, text: &str) -> Value {
    record(uuid, parent, kind, &[json!({ "text": text })])
}

fn system_record(uuid: &str, parent: Option<&str>, subtype: &str, payload: Value) -> Value {
    let mut record = record(uuid, parent, "system", &[]);
    record.as_object_mut().unwrap().remove("message");
    record["subtype"] = subtype.into();
    record["systemPayload"] = payload;
    record
}

fn encode(records: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for record in records {
        writeln!(bytes, "{record}").unwrap();
    }
    bytes
}

struct Fixture {
    root: TempDir,
    path: PathBuf,
    original: Vec<u8>,
}

impl Fixture {
    fn new(records: &[Value]) -> Self {
        Self::from_bytes(encode(records))
    }

    fn from_bytes(original: Vec<u8>) -> Self {
        let root = TempDir::new().unwrap();
        let path = root.path().join(format!(
            ".qwen/projects/-home-remote-project/chats/{SESSION_ID}.jsonl"
        ));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &original).unwrap();
        Self {
            root,
            path,
            original,
        }
    }

    fn context(&self, path: &Path) -> ScanContext {
        ScanContext::with_roots(
            self.root.path().join("unused-state"),
            vec![ScanRoot::remote(
                path.to_path_buf(),
                Origin::remote_with_host("qwen-native-fixture", "remote-host"),
                Some(Platform::Linux),
            )],
            None,
        )
    }

    fn scan(&self) -> Vec<NormalizedConversation> {
        QwenConnector::new()
            .scan(&self.context(&self.path))
            .unwrap()
    }

    fn assert_unchanged(&self) {
        assert_eq!(fs::read(&self.path).unwrap(), self.original);
    }
}

fn message_ids(conversation: &NormalizedConversation) -> Vec<&str> {
    conversation
        .messages
        .iter()
        .map(|message| {
            message.extra["uuid"]
                .as_str()
                .unwrap_or_else(|| message.extra["cass"]["message_id"].as_str().unwrap())
        })
        .collect()
}

#[test]
fn current_native_history_roundtrips_discovery_at_every_qwen_scope() {
    let fixture = Fixture::new(&[
        text_record("user", None, "user", "Inspect the repository"),
        text_record("assistant", Some("user"), "assistant", "I found the source"),
    ]);
    let connector = QwenConnector::new();
    for path in [
        fixture.root.path().to_path_buf(),
        fixture.root.path().join(".qwen"),
        fixture.root.path().join(".qwen/projects"),
        fixture
            .path
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf(),
        fixture.path.parent().unwrap().to_path_buf(),
        fixture.path.clone(),
    ] {
        let ctx = fixture.context(&path);
        let sources = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(sources.len(), 1, "scope={path:?}");
        assert_eq!(sources[0].provider_slug, "qwen");
        assert_eq!(sources[0].source_path, fixture.path);
        assert_eq!(sources[0].role, DiscoveredSourceRole::PrimarySessionLog);
        assert_eq!(sources[0].origin, ctx.scan_roots[0].origin);
        assert_eq!(sources[0].platform, Some(Platform::Linux));
        assert!(sources[0].required_for_reconstruction);
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1);
        let conversation = &conversations[0];
        assert_eq!(conversation.external_id.as_deref(), Some(SESSION_ID));
        assert_eq!(conversation.source_path, fixture.path);
        assert_eq!(
            conversation.workspace.as_deref(),
            Some(Path::new("/home/remote/project"))
        );
        assert_eq!(
            conversation.title.as_deref(),
            Some("Inspect the repository")
        );
        assert_eq!(message_ids(conversation), ["user", "assistant"]);
        assert!(conversation.started_at.is_some());
        assert!(conversation.ended_at.is_some());
    }
    fixture.assert_unchanged();
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the complete fragment-to-usage scenario together.
fn native_fragments_preserve_thoughts_tools_and_last_usage_once() {
    let mut first = record(
        "assistant",
        Some("user"),
        "assistant",
        &[
            json!({ "thought": true, "text": "Check the relevant file" }),
            json!({ "text": "Searching" }),
        ],
    );
    first["model"] = "qwen3-coder-plus".into();
    first["usageMetadata"] =
        json!({ "promptTokenCount": 100, "candidatesTokenCount": 2, "totalTokenCount": 102 });
    let mut fragment = record(
        "assistant",
        Some("user"),
        "assistant",
        &[
            json!({ "functionCall": { "id": "call-1", "name": "read_file", "args": { "absolute_path": "/home/remote/project/lib.rs" } } }),
        ],
    );
    fragment["timestamp"] = "2026-10-10T12:00:01Z".into();
    fragment["usageMetadata"] =
        json!({ "promptTokenCount": 100, "candidatesTokenCount": 20, "totalTokenCount": 120 });
    let result = record(
        "result",
        Some("assistant"),
        "tool_result",
        &[
            json!({ "functionResponse": { "id": "call-1", "name": "read_file", "response": { "output": "pub fn detected() {}", "error": "cancelled after output", "__binary_injection__": "secret-binary" }, "parts": [{ "inlineData": { "data": "secret-binary" } }] } }),
        ],
    );
    let mut next = text_record("next", Some("result"), "assistant", "Searching");
    next["usageMetadata"] =
        json!({ "promptTokenCount": 100, "candidatesTokenCount": 20, "totalTokenCount": 120 });
    let fixture = Fixture::new(&[
        text_record("user", None, "user", "Inspect the repository"),
        first,
        fragment,
        result,
        next,
    ]);
    let conversations = fixture.scan();
    let conversation = &conversations[0];
    assert_eq!(
        message_ids(conversation),
        ["user", "assistant", "result", "next"]
    );
    let assistant = &conversation.messages[1];
    assert_eq!(
        assistant.content,
        "[Thinking] Check the relevant file\nSearching\n[Tool: read_file]"
    );
    assert_eq!(assistant.invocations.len(), 1);
    assert_eq!(assistant.invocations[0].call_id.as_deref(), Some("call-1"));
    assert_eq!(
        assistant.invocations[0].arguments.as_ref().unwrap()["absolute_path"],
        "/home/remote/project/lib.rs"
    );
    assert_eq!(assistant.extra["model"], "qwen3-coder-plus");
    assert_eq!(assistant.extra["usageMetadata"]["totalTokenCount"], 120);
    assert_eq!(
        assistant.extra["message"]["parts"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(conversation.messages[2].role, "tool");
    assert_eq!(
        conversation.messages[2].author.as_deref(),
        Some("read_file")
    );
    assert_eq!(
        conversation.messages[2].content,
        "[Tool Result: read_file]\npub fn detected() {}\n[Error] cancelled after output"
    );
    assert!(!conversation.messages[2].content.contains("secret-binary"));
    let total: i64 = conversation
        .messages
        .iter()
        .filter_map(|message| {
            message
                .extra
                .pointer("/usageMetadata/totalTokenCount")
                .and_then(Value::as_i64)
        })
        .sum();
    assert_eq!(
        total, 240,
        "each logical reply contributes its final usage once"
    );
    let extracted_total: i64 = conversation
        .messages
        .iter()
        .filter_map(|message| {
            let usage =
                extract_tokens_for_agent("qwen", &message.extra, &message.content, &message.role);
            (usage.data_source == TokenDataSource::Api)
                .then(|| usage.total_tokens())
                .flatten()
        })
        .sum();
    assert_eq!(extracted_total, 240);
    fixture.assert_unchanged();
}

#[test]
fn rewinds_follow_active_parents_without_reviving_abandoned_turns() {
    let fixture = Fixture::new(&[
        text_record("user", None, "user", "Keep this turn"),
        text_record("assistant", Some("user"), "assistant", "Kept reply"),
        text_record(
            "abandoned-user",
            Some("assistant"),
            "user",
            "Discard this branch",
        ),
        text_record(
            "abandoned-reply",
            Some("abandoned-user"),
            "assistant",
            "Discarded reply",
        ),
        system_record(
            "rewind",
            Some("assistant"),
            "rewind",
            json!({ "truncatedCount": 2 }),
        ),
        text_record("replacement-user", Some("rewind"), "user", "New direction"),
        text_record(
            "replacement-reply",
            Some("replacement-user"),
            "assistant",
            "New reply",
        ),
        system_record(
            "title",
            Some("replacement-reply"),
            "custom_title",
            json!({ "customTitle": "Chosen title", "titleSource": "manual" }),
        ),
        // An artifact appended later is a side channel, not a new branch head.
        system_record(
            "artifact",
            Some("abandoned-reply"),
            "session_artifact_snapshot",
            json!({ "large_snapshot": "not conversation text" }),
        ),
        system_record(
            "sources",
            Some("abandoned-reply"),
            "session_sources_snapshot",
            json!({}),
        ),
    ]);
    let conversations = fixture.scan();
    assert_eq!(
        message_ids(&conversations[0]),
        ["user", "assistant", "replacement-user", "replacement-reply"]
    );
    assert_eq!(conversations[0].title.as_deref(), Some("Chosen title"));
    assert_eq!(conversations[0].metadata["active_leaf_uuid"], "title");
    fixture.assert_unchanged();
}

#[test]
fn missing_parents_do_not_resurrect_unrelated_history_and_cycles_terminate() {
    let missing = Fixture::new(&[
        text_record("old-user", None, "user", "Old disconnected history"),
        text_record("new-user", Some("lost-parent"), "user", "Remaining suffix"),
        text_record("reply", Some("new-user"), "assistant", "Suffix reply"),
    ]);
    let conversations = missing.scan();
    assert_eq!(message_ids(&conversations[0]), ["new-user", "reply"]);
    assert_eq!(
        conversations[0].metadata["history_gap_parent_uuid"],
        "lost-parent"
    );
    let cycle = Fixture::new(&[
        text_record("a", Some("b"), "user", "Cycle input"),
        text_record("b", Some("a"), "assistant", "Cycle response"),
    ]);
    assert_eq!(message_ids(&cycle.scan()[0]), ["a", "b"]);
}

#[test]
fn malformed_message_payload_preserves_earlier_parent_links() {
    let mut malformed = text_record("middle", Some("user"), "assistant", "Malformed body");
    malformed["message"]["parts"] = json!({ "invalid": "not a parts array" });
    let fixture = Fixture::new(&[
        text_record("user", None, "user", "Keep the earlier request"),
        malformed,
        text_record("reply", Some("middle"), "assistant", "Keep this reply too"),
    ]);
    assert_eq!(message_ids(&fixture.scan()[0]), ["user", "reply"]);
}

#[test]
fn native_user_projection_preserves_authored_text_without_generated_hook_context() {
    let hook =
        "<qwen:user-prompt-submit-context>\ngenerated context\n</qwen:user-prompt-submit-context>";
    for (payload, expected) in [
        (
            Some(json!({ "displayText": "Actual request", "hookContext": "generated context" })),
            "Actual request",
        ),
        (
            Some(json!({ "displayText": "Released display text" })),
            "Released display text",
        ),
        (None, "Expanded machine prompt"),
    ] {
        let mut user = record(
            "user",
            None,
            "user",
            &[
                json!({ "text": "Expanded machine prompt" }),
                json!({ "text": hook }),
            ],
        );
        if let Some(payload) = payload {
            user["systemPayload"] = payload;
        }
        let fixture = Fixture::new(&[
            user,
            text_record("reply", Some("user"), "assistant", "Reply"),
        ]);
        let conversations = fixture.scan();
        assert_eq!(conversations[0].messages[0].content, expected);
        assert_eq!(conversations[0].title.as_deref(), Some(expected));
        assert!(
            !conversations[0].messages[0]
                .content
                .contains("generated context")
        );
    }
    let mut empty_display = text_record("user", None, "user", "Generated text only");
    empty_display["systemPayload"] = json!({ "displayText": "", "hookContext": "" });
    let fixture = Fixture::new(&[
        empty_display,
        text_record("reply", Some("user"), "assistant", "Reply"),
    ]);
    assert_eq!(message_ids(&fixture.scan()[0]), ["reply"]);

    let mut unpaired = text_record("user", None, "user", "Original visible text");
    unpaired["systemPayload"] = json!({ "displayText": "Unproven replacement" });
    assert_eq!(
        Fixture::new(&[unpaired]).scan()[0].messages[0].content,
        "Original visible text"
    );
}

#[test]
fn usage_only_assistant_survives_and_invalid_records_do_not_replace_native_identity() {
    let mut usage_only = record("usage", Some("user"), "assistant", &[]);
    usage_only.as_object_mut().unwrap().remove("message");
    usage_only["model"] = "qwen3-coder-plus".into();
    usage_only["usageMetadata"] =
        json!({ "promptTokenCount": 12, "candidatesTokenCount": 0, "totalTokenCount": 12 });
    let mut no_id = text_record("invalid", None, "assistant", "No UUID");
    no_id.as_object_mut().unwrap().remove("uuid");
    let mut wrong_parts = text_record("usage", None, "assistant", "Bad replacement");
    wrong_parts["message"] = json!({ "role": "assistant", "content": "Foreign payload" });
    let fixture = Fixture::new(&[
        text_record("user", None, "user", "Cancelled request"),
        usage_only,
        no_id,
        wrong_parts,
    ]);
    let conversations = fixture.scan();
    assert_eq!(message_ids(&conversations[0]), ["user", "usage"]);
    assert_eq!(conversations[0].messages[1].content, "");
    assert_eq!(
        conversations[0].messages[1].extra["usageMetadata"]["totalTokenCount"],
        12
    );
}

#[test]
fn renamed_native_mirrors_and_archives_do_not_admit_foreign_or_sidecar_files() {
    let fixture = Fixture::new(&[
        text_record("user", None, "user", "Mirror me"),
        text_record("reply", Some("user"), "assistant", "Mirrored reply"),
    ]);
    let mirror = fixture.root.path().join("copied-store/projects/project");
    let chats = mirror.join("chats");
    let archive = chats.join("archive");
    fs::create_dir_all(&archive).unwrap();
    let archived = archive.join(format!("{SESSION_ID}.jsonl"));
    fs::copy(&fixture.path, &archived).unwrap();
    let gemini = json!({ "sessionId": "gemini-session", "projectHash": "project", "messages": [{ "id": "user", "type": "user", "content": "Gemini only" }] });
    fs::write(chats.join("session-gemini.json"), gemini.to_string()).unwrap();
    fs::write(chats.join("session-gemini.jsonl"), format!("{gemini}\n")).unwrap();
    fs::write(
        chats.join(format!("{SESSION_ID}.ledger.jsonl")),
        &fixture.original,
    )
    .unwrap();
    fs::write(
        mirror.join(format!("{SESSION_ID}.jsonl")),
        &fixture.original,
    )
    .unwrap();
    let foreign_path = chats.join("07c09e1e-9b87-401c-bdeb-6c357ab925f9.jsonl");
    fs::write(&foreign_path, encode(&[
        json!({ "sessionId": "gemini", "projectHash": "project" }),
        json!({ "id": "foreign", "type": "gemini", "content": "Do not ingest" }),
        json!({ "uuid": "claude", "parentUuid": null, "sessionId": "claude", "type": "assistant", "message": { "role": "assistant", "content": "Not Qwen parts" } }),
    ])).unwrap();
    for scope in [mirror, chats, archive, archived.clone()] {
        let ctx = fixture.context(&scope);
        let sources = QwenConnector::new().discover_source_files(&ctx).unwrap();
        assert!(
            sources
                .iter()
                .all(|source| source.source_path == archived || source.source_path == foreign_path)
        );
        let conversations = QwenConnector::new().scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1, "scope={scope:?}");
        assert_eq!(conversations[0].source_path, archived);
        assert_eq!(message_ids(&conversations[0]), ["user", "reply"]);
    }
}

#[test]
fn discovery_deduplicates_overlapping_roots_and_incremental_scans_agree() {
    let fixture = Fixture::new(&[text_record("user", None, "user", "One source")]);
    let mut ctx = fixture.context(&fixture.path);
    ctx.scan_roots
        .push(ctx.scan_roots[0].with_path(fixture.root.path().join(".qwen")));
    assert_eq!(
        QwenConnector::new()
            .discover_source_files(&ctx)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(QwenConnector::new().scan(&ctx).unwrap().len(), 1);
    ctx.since_ts = Some(i64::MAX);
    assert!(
        QwenConnector::new()
            .discover_source_files(&ctx)
            .unwrap()
            .is_empty()
    );
    assert!(QwenConnector::new().scan(&ctx).unwrap().is_empty());
}

#[test]
fn explicit_scopes_do_not_add_unrelated_data_dir_histories() {
    let fixture = Fixture::new(&[text_record("user", None, "user", "Local history")]);
    let mut ctx = fixture.context(&fixture.root.path().join("missing-remote-store"));
    ctx.data_dir = fixture.root.path().join(".qwen");
    assert!(
        QwenConnector::new()
            .discover_source_files(&ctx)
            .unwrap()
            .is_empty()
    );
    assert!(QwenConnector::new().scan(&ctx).unwrap().is_empty());
}

#[test]
fn qwen_missing_scope_child() {
    let Some(scope) = std::env::var_os("FAD_QWEN_MISSING_SCOPE") else {
        return;
    };
    let ctx = ScanContext::local_default(PathBuf::from(scope), None);
    assert!(
        QwenConnector::new()
            .discover_source_files(&ctx)
            .unwrap()
            .is_empty()
    );
    assert!(QwenConnector::new().scan(&ctx).unwrap().is_empty());
}

#[test]
fn empty_and_missing_recognizable_scopes_never_fall_back_to_live_runtime() {
    let live = Fixture::new(&[text_record(
        "user",
        None,
        "user",
        "Live history must stay out",
    )]);
    let scoped = TempDir::new().unwrap();
    for scope in [
        scoped.path().join("missing/.qwen"),
        scoped.path().join("empty/.qwen"),
        scoped.path().join("empty/chats"),
        scoped
            .path()
            .join(format!("missing/chats/{SESSION_ID}.jsonl")),
    ] {
        if scope.starts_with(scoped.path().join("empty")) {
            fs::create_dir_all(&scope).unwrap();
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "qwen_missing_scope_child", "--nocapture"])
            .env("FAD_QWEN_MISSING_SCOPE", &scope)
            .env("QWEN_RUNTIME_DIR", live.root.path().join(".qwen"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "scope={scope:?}\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    live.assert_unchanged();
}

#[test]
fn current_and_legacy_histories_coexist_without_changing_legacy_metadata() {
    let fixture = Fixture::new(&[text_record("native", None, "user", "Native history")]);
    let legacy = fixture
        .root
        .path()
        .join(".qwen/tmp/project/chats/session-legacy.json");
    fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    fs::write(&legacy, json!({
        "sessionId": "legacy", "projectHash": "project",
        "messages": [{ "id": "old", "type": "qwen", "content": "Legacy answer", "tokens": { "input": 12, "output": 4 } }],
    }).to_string()).unwrap();
    let config = legacy
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("config.json");
    fs::write(&config, r#"{"workspace":"/legacy/workspace"}"#).unwrap();
    let ctx = fixture.context(&fixture.root.path().join(".qwen"));
    let connector = QwenConnector::new();
    let sources = connector.discover_source_files(&ctx).unwrap();
    assert_eq!(sources.len(), 3);
    assert!(sources.iter().any(|source| source.source_path == config
        && source.role == DiscoveredSourceRole::MetadataSidecar));
    let conversations = connector.scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 2);
    let legacy_conversation = conversations
        .iter()
        .find(|conversation| conversation.external_id.as_deref() == Some("legacy"))
        .unwrap();
    assert_eq!(
        legacy_conversation.workspace.as_deref(),
        Some(Path::new("/legacy/workspace"))
    );
    assert_eq!(legacy_conversation.messages[0].role, "assistant");
    assert_eq!(legacy_conversation.messages[0].extra["tokens"]["input"], 12);
}

#[test]
fn malformed_lines_recover_but_mixed_and_managed_sessions_do_not_emit_partial_history() {
    let mut bytes = encode(&[text_record("user", None, "user", "Recover valid suffix")]);
    bytes.extend_from_slice(b"malformed JSON\n\xff invalid UTF-8\n");
    bytes.extend(encode(&[text_record(
        "reply",
        Some("user"),
        "assistant",
        "Recovered reply",
    )]));
    let fixture = Fixture::from_bytes(bytes);
    assert_eq!(message_ids(&fixture.scan()[0]), ["user", "reply"]);
    fixture.assert_unchanged();

    let mut foreign = text_record("foreign", Some("user"), "assistant", "Other session");
    foreign["sessionId"] = "another-session".into();
    let mixed = Fixture::new(&[text_record("user", None, "user", "Prefix"), foreign]);
    assert!(mixed.scan().is_empty());
    for subtype in ["managed_session_header_v1", "session_execution_engine"] {
        let managed = Fixture::new(&[
            text_record(
                "user",
                None,
                "user",
                "Do not report an incomplete managed projection",
            ),
            system_record(
                "managed",
                Some("user"),
                subtype,
                json!({ "engine": "managed" }),
            ),
        ]);
        assert!(managed.scan().is_empty());
    }
}

#[test]
fn streaming_callbacks_cancel_and_unsupported_source_boundaries_remain_truthful() {
    let fixture = Fixture::new(&[text_record("user", None, "user", "Stop here")]);
    let other = fixture
        .path
        .with_file_name("07c09e1e-9b87-401c-bdeb-6c357ab925f9.jsonl");
    fs::copy(&fixture.path, &other).unwrap();
    let ctx = fixture.context(fixture.path.parent().unwrap());
    let connector = QwenConnector::new();
    assert!(connector.supports_streaming_scan());
    assert!(!connector.supports_source_boundaries());
    let mut delivered = 0;
    let result = connector.scan_with_callback(&ctx, &mut |_| {
        delivered += 1;
        anyhow::bail!("cancel after first source")
    });
    assert_eq!(delivered, 1);
    assert_eq!(result.unwrap_err().to_string(), "cancel after first source");
    let mut should_scan =
        |_: &DiscoveredSourceFile| -> bool { panic!("unsupported hook must not run") };
    let mut complete = |_: &SourceCompletion| -> anyhow::Result<()> {
        panic!("unsupported completion must not run")
    };
    let mut delivered = 0;
    connector
        .scan_with_source_boundaries(
            &ctx,
            &mut SourceScanHooks {
                should_scan_source: Some(&mut should_scan),
                on_source_complete: Some(&mut complete),
            },
            &mut |_| {
                delivered += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(delivered, 2);
    fixture.assert_unchanged();
}

fn pad_to_size(path: &Path, size: u64) {
    let current = fs::metadata(path).unwrap().len();
    let mut writer = BufWriter::new(fs::OpenOptions::new().append(true).open(path).unwrap());
    let mut remaining = usize::try_from(size - current).unwrap();
    let mut padding = [b' '; 8192];
    padding[8191] = b'\n';
    while remaining > 0 {
        let count = remaining.min(padding.len());
        writer.write_all(&padding[..count]).unwrap();
        remaining -= count;
    }
    writer.flush().unwrap();
}

fn with_invalid_tool_counts(mut records: Vec<Value>) -> Vec<Value> {
    for (index, invalid) in [json!("bad"), Value::Null, json!(u64::MAX)]
        .into_iter()
        .enumerate()
    {
        let parent = if index == 0 {
            "assistant".to_string()
        } else {
            format!("invalid-tool-{}", index - 1)
        };
        let mut record = text_record(
            &format!("invalid-tool-{index}"),
            Some(&parent),
            "assistant",
            "Unusable tool count",
        );
        record["usageMetadata"] = json!({
            "promptTokenCount": 1, "candidatesTokenCount": 10,
            "thoughtsTokenCount": 5, "totalTokenCount": 16,
            "toolUsePromptTokenCount": invalid,
        });
        records.push(record);
    }
    records
}

#[test]
fn native_metadata_compacts_at_32_mib_without_losing_content_identity_or_usage() {
    for size in [
        COMPACT_THRESHOLD - 1,
        COMPACT_THRESHOLD,
        COMPACT_THRESHOLD + 1,
    ] {
        let mut assistant = record(
            "assistant",
            Some("user"),
            "assistant",
            &[
                json!({ "text": "Content survives" }),
                json!({ "functionCall": { "id": "call-1", "name": "read_file", "args": { "path": "/repo/file" } } }),
            ],
        );
        assistant["model"] = "qwen3-coder-plus".into();
        assistant["usageMetadata"] = json!({
            "promptTokenCount": 10, "candidatesTokenCount": 5, "cachedContentTokenCount": 1,
            "thoughtsTokenCount": 2, "toolUsePromptTokenCount": 0, "totalTokenCount": 15,
            "unbounded_details": "must not survive compact metadata",
        });
        assistant["unknown_large_metadata"] = "raw metadata remains only below the boundary".into();
        let fixture = Fixture::new(&with_invalid_tool_counts(vec![
            text_record("user", None, "user", "Read it"),
            assistant,
        ]));
        pad_to_size(&fixture.path, size);
        let before = fs::metadata(&fixture.path).unwrap().modified().unwrap();
        let conversations = fixture.scan();
        assert_eq!(
            message_ids(&conversations[0]),
            [
                "user",
                "assistant",
                "invalid-tool-0",
                "invalid-tool-1",
                "invalid-tool-2"
            ]
        );
        let message = &conversations[0].messages[1];
        assert_eq!(message.content, "Content survives\n[Tool: read_file]");
        assert_eq!(
            message.invocations[0].arguments.as_ref().unwrap()["path"],
            "/repo/file"
        );
        if size < COMPACT_THRESHOLD {
            assert!(message.extra.get("cass").is_none());
            assert_eq!(message.extra["usageMetadata"]["totalTokenCount"], 15);
            assert!(message.extra.get("message").is_some());
        } else {
            assert_eq!(message.extra["cass"]["message_id"], "assistant");
            assert_eq!(message.extra["cass"]["parent_uuid"], "user");
            assert_eq!(message.extra["cass"]["session_id"], SESSION_ID);
            assert_eq!(message.extra["cass"]["model"], "qwen3-coder-plus");
            assert_eq!(message.extra["cass"]["usage"]["totalTokenCount"], 15);
            assert_eq!(message.extra["cass"]["tool_call_count"], 1);
            assert!(message.extra.get("message").is_none());
            assert!(!message.extra.to_string().contains("unbounded_details"));
            assert!(!message.extra.to_string().contains("unknown_large_metadata"));
            assert!(message.extra.to_string().len() < 1024);
        }
        let usage =
            extract_tokens_for_agent("qwen", &message.extra, &message.content, &message.role);
        assert_eq!(usage.data_source, TokenDataSource::Api);
        assert_eq!(
            usage.total_tokens(),
            Some(15),
            "Responses candidates already include reasoning"
        );
        assert_eq!(usage.tool_call_count, 1);
        for invalid in &conversations[0].messages[2..] {
            let usage =
                extract_tokens_for_agent("qwen", &invalid.extra, &invalid.content, &invalid.role);
            assert_eq!(usage.data_source, TokenDataSource::Api);
            assert_eq!(
                usage.total_tokens(),
                Some(11),
                "invalid tool counts must not become inferred zeroes after compaction"
            );
            if size >= COMPACT_THRESHOLD {
                assert_eq!(
                    invalid.extra.pointer("/cass/usage/toolUsePromptTokenCount"),
                    Some(&Value::Null)
                );
                assert!(invalid.extra.to_string().len() < 1024);
            }
        }
        assert_eq!(fs::metadata(&fixture.path).unwrap().len(), size);
        assert_eq!(
            fs::metadata(&fixture.path).unwrap().modified().unwrap(),
            before
        );
    }
}
