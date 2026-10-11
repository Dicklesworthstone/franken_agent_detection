//! Native Vibe assistant activity must not disappear when content is empty.
//!
//! Fixtures follow mistralai/mistral-vibe at
//! 4ae5c5955da8e761318916bdb1a7f46f0b50c7d0: vibe/core/types.py defines
//! `LLMMessage` and `FunctionCall`, `core/agent_loop/_loop.py` appends tool-only
//! assistant messages, and `core/session/session_logger.py` persists those
//! messages directly into messages.jsonl. Usage is recorded separately in
//! cumulative session metadata, not on these message rows.
#![cfg(feature = "connectors")]

use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use franken_agent_detection::token_extraction::extract_tokens_for_agent;
use franken_agent_detection::{
    Connector, DiscoveredSourceRole, NormalizedConversation, Origin, Platform, ScanContext,
    ScanRoot, SourceScanHooks, TokenDataSource, VibeConnector,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn write_session(sessions: &Path, id: &str, rows: &[Value]) -> PathBuf {
    let directory = sessions.join(id);
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("messages.jsonl");
    let mut file = BufWriter::new(fs::File::create(&path).unwrap());
    for row in rows {
        serde_json::to_writer(&mut file, row).unwrap();
        writeln!(file).unwrap();
    }
    file.flush().unwrap();
    path
}

fn scan(sessions: &Path) -> NormalizedConversation {
    let mut conversations = VibeConnector::new()
        .scan(&ScanContext::local_default(sessions.to_path_buf(), None))
        .unwrap();
    assert_eq!(conversations.len(), 1);
    conversations.pop().unwrap()
}

fn function(name: &str, id: Value, arguments: Value) -> Value {
    let mut call = json!({"type": "function", "function": {"name": name}});
    call["id"] = id;
    call["function"]["arguments"] = arguments;
    call
}

#[test]
fn native_tool_reasoning_and_mixed_turns_keep_one_message_per_row() {
    let temp = TempDir::new().unwrap();
    let sessions = temp.path().join(".vibe/logs/session");
    let rows = vec![
        json!({"role": "user", "message_id": "user-1", "content": "Inspect the parser"}),
        json!({
            "role": "assistant", "message_id": "assistant-1", "content": "",
            "tool_calls": [function("read_file", json!("call-1"), json!(r#"{"path":"src/lib.rs"}"#))],
        }),
        json!({
            "role": "tool", "tool_call_id": "call-1", "name": "read_file",
            "content": "pub fn parse() {}", "tool_result": {"output": {"content": "pub fn parse() {}"}},
        }),
        json!({
            "role": "assistant", "message_id": "assistant-2",
            "reasoning_content": "Check how the parser handles tool calls",
            "reasoning_message_id": "reasoning-1",
        }),
        json!({
            "role": "assistant", "message_id": "assistant-3", "content": "The parser needs a fix.",
            "reasoning_content": "Verify the test coverage",
            "tool_calls": [
                function("grep", json!("call-2"), json!(r#"{"pattern":"tool_calls"}"#)),
                function("run_tests", json!("call-3"), json!(r#"{"suite":"parser"}"#)),
            ],
        }),
    ];
    let path = write_session(&sessions, "session-native", &rows);
    let conversation = scan(&sessions);
    assert_eq!(conversation.source_path, path);
    assert_eq!(conversation.external_id.as_deref(), Some("session-native"));
    assert_eq!(conversation.title.as_deref(), Some("Inspect the parser"));
    assert!(conversation.started_at.is_none());
    assert!(conversation.ended_at.is_none());
    assert_eq!(conversation.messages.len(), rows.len());
    for (index, (message, raw)) in conversation.messages.iter().zip(&rows).enumerate() {
        assert_eq!(message.idx, i64::try_from(index).unwrap());
        assert_eq!(message.extra, *raw);
        assert!(message.created_at.is_none());
        assert!(message.author.is_none());
    }
    assert_eq!(conversation.messages[1].content, "[Tool: read_file]");
    let call = &conversation.messages[1].invocations[0];
    assert_eq!(call.kind, "tool");
    assert_eq!(call.name, "read_file");
    assert_eq!(call.call_id.as_deref(), Some("call-1"));
    assert_eq!(call.arguments, Some(json!({"path": "src/lib.rs"})));
    assert!(call.raw_name.is_none());
    assert_eq!(conversation.messages[2].role, "tool");
    assert_eq!(conversation.messages[2].content, "pub fn parse() {}");
    assert!(conversation.messages[2].invocations.is_empty());
    assert_eq!(
        conversation.messages[3].content,
        "[Thinking] Check how the parser handles tool calls"
    );
    assert!(conversation.messages[3].invocations.is_empty());
    assert_eq!(
        conversation.messages[4].content,
        "[Thinking] Verify the test coverage\nThe parser needs a fix.\n[Tool: grep]\n[Tool: run_tests]"
    );
    assert_eq!(conversation.messages[4].invocations.len(), 2);
}

#[test]
fn malformed_or_unrelated_fields_do_not_create_native_activity() {
    let temp = TempDir::new().unwrap();
    let sessions = temp.path().join(".vibe/logs/session");
    let rows = vec![
        json!({
            "role": "assistant", "content": null,
            "reasoning_payloads": [{"type": "encrypted", "data": "opaque-reasoning"}],
            "images": [{"data": "opaque-image"}],
        }),
        json!({"role": "assistant", "reasoning_content": {"text": "not-native-text"}}),
        json!({
            "role": "assistant", "reasoning_content": " \n ",
            "tool_calls": [null, false, "tool", {},
                {"function": {"name": " "}},
                {"function": {"name": 42}},
                {"type": "image", "function": {"name": "not-a-tool"}},
                {"type": false, "function": {"name": "not-a-tool"}},
                {"type": "function", "name": "wrong-shape"}],
        }),
        json!({"role": "assistant", "tool_calls": {"function": {"name": "not-an-array"}}}),
        json!({
            "role": "user", "content": "Keep user text",
            "reasoning_content": "not-assistant-reasoning",
            "tool_calls": [function("not-a-user-tool", json!("user-call"), json!("{}"))],
        }),
        json!({
            "role": "tool", "content": "Keep tool output", "reasoning_content": "ignored",
            "tool_calls": [function("not-a-tool-result-call", Value::Null, Value::Null)],
        }),
        json!({
            "role": "assistant", "content": "Ordinary answer", "tool_calls": [
                {"type": "image", "function": {"name": "ignored"}},
                {"function": {"name": "legacy_default", "arguments": "{}"}},
            ],
        }),
    ];
    write_session(&sessions, "session-invalid", &rows);
    let conversation = scan(&sessions);
    assert_eq!(conversation.messages.len(), 3);
    assert_eq!(conversation.messages[0].content, "Keep user text");
    assert_eq!(conversation.messages[0].role, "user");
    assert!(conversation.messages[0].invocations.is_empty());
    assert_eq!(conversation.messages[1].content, "Keep tool output");
    assert!(conversation.messages[1].invocations.is_empty());
    assert_eq!(
        conversation.messages[2].content,
        "Ordinary answer\n[Tool: legacy_default]"
    );
    assert_eq!(conversation.messages[2].invocations.len(), 1);
    for (message, raw) in conversation.messages.iter().zip(&rows[4..]) {
        assert_eq!(message.extra, *raw);
    }
}

#[test]
fn native_argument_strings_and_call_ids_preserve_their_meaning() {
    let temp = TempDir::new().unwrap();
    let sessions = temp.path().join(".vibe/logs/session");
    let cases = [
        (
            json!(r#"{"path":"src/lib.rs","line":2}"#),
            Some(json!({"path": "src/lib.rs", "line": 2})),
        ),
        (json!(r#"["src/lib.rs",2]"#), Some(json!(["src/lib.rs", 2]))),
        (json!("null"), Some(Value::Null)),
        (json!("true"), Some(json!(true))),
        (json!("12"), Some(json!(12))),
        (json!(r#""quoted text""#), Some(json!("quoted text"))),
        (json!("{unfinished"), Some(json!("{unfinished"))),
        (json!(""), Some(json!(""))),
        (Value::Null, None),
        (json!({"path": "not-a-native-argument-string"}), None),
        (json!([1, 2]), None),
        (json!(12), None),
        (json!(true), None),
    ];
    let ids = [
        json!("call-1"),
        json!(""),
        json!(" \n "),
        json!(12),
        Value::Null,
    ];
    let rows: Vec<_> = cases
        .iter()
        .enumerate()
        .map(|(index, (arguments, _))| {
            json!({"role": "assistant", "tool_calls": [
                function("inspect", ids[index % ids.len()].clone(), arguments.clone()),
            ]})
        })
        .collect();
    write_session(&sessions, "session-arguments", &rows);
    let conversation = scan(&sessions);
    assert_eq!(conversation.messages.len(), cases.len());
    for (index, (message, (_, expected))) in conversation.messages.iter().zip(&cases).enumerate() {
        assert_eq!(message.content, "[Tool: inspect]");
        assert_eq!(message.invocations.len(), 1);
        assert_eq!(&message.invocations[0].arguments, expected);
        assert_eq!(
            message.invocations[0].call_id.as_deref(),
            (index % ids.len() == 0).then_some("call-1")
        );
        assert_eq!(message.extra, rows[index]);
    }
}

#[test]
fn large_arguments_and_opaque_payloads_do_not_expand_the_projection() {
    let temp = TempDir::new().unwrap();
    let sessions = temp.path().join(".vibe/logs/session");
    let limit = 64 * 1024;
    let at_limit = format!("\"{}\"", "a".repeat(limit - 2));
    let over_limit = format!("\"{}\"", "b".repeat(limit - 1));
    let payload = "opaque-data-".repeat(100_000);
    let row = json!({
        "role": "assistant", "content": null,
        "tool_calls": [
            function("at_limit", json!("call-1"), json!(at_limit)),
            function("over_limit", json!("call-2"), json!(over_limit)),
            function("large", json!("call-3"), json!(payload)),
        ],
        "reasoning_payloads": [{"type": "encrypted", "data": payload}],
        "images": [{"data": payload}],
    });
    write_session(&sessions, "session-large", std::slice::from_ref(&row));
    let conversation = scan(&sessions);
    let message = &conversation.messages[0];
    assert_eq!(
        message.content,
        "[Tool: at_limit]\n[Tool: over_limit]\n[Tool: large]"
    );
    assert_eq!(message.invocations.len(), 3);
    assert_eq!(
        message.invocations[0].arguments,
        Some(json!("a".repeat(limit - 2)))
    );
    assert!(message.invocations[1].arguments.is_none());
    assert!(message.invocations[2].arguments.is_none());
    assert!(serde_json::to_vec(&message.invocations).unwrap().len() < limit + 1024);
    assert_eq!(message.extra, row);
}

#[test]
fn nontext_sessions_survive_all_scan_routes_and_readonly_discovery() {
    let temp = TempDir::new().unwrap();
    let sessions = temp.path().join(".vibe/logs/session");
    let rows = [
        json!({"role": "assistant", "reasoning_content": "A reasoning-only session", "timestamp": 1_760_000_003_000_i64}),
        json!({"role": "assistant", "tool_calls": [function("read_file", json!("call-1"), json!("{}"))], "timestamp": 1_760_000_001_000_i64}),
    ];
    let path = write_session(&sessions, "session-only-activity", &rows);
    let bytes = fs::read(&path).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let origin = Origin::remote_with_host("vibe-fixture", "archived-host");
    let ctx = ScanContext::with_roots(
        temp.path().join("unused-state"),
        vec![ScanRoot::remote(
            sessions,
            origin.clone(),
            Some(Platform::Linux),
        )],
        None,
    );
    let connector = VibeConnector::new();
    let discovered = connector.discover_source_files(&ctx).unwrap();
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].source_path, path);
    assert_eq!(discovered[0].provider_slug, "vibe");
    assert_eq!(discovered[0].role, DiscoveredSourceRole::PrimarySessionLog);
    assert!(discovered[0].required_for_reconstruction);
    assert_eq!(discovered[0].origin, origin);
    assert_eq!(discovered[0].platform, Some(Platform::Linux));
    assert_eq!(
        discovered[0].size_bytes,
        Some(u64::try_from(bytes.len()).unwrap())
    );
    assert!(discovered[0].modified_at_ms.is_some());
    let direct = connector.scan(&ctx).unwrap();
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0].messages.len(), 2);
    assert_eq!(direct[0].messages[0].extra, rows[0]);
    assert_eq!(direct[0].messages[1].extra, rows[1]);
    assert_eq!(direct[0].started_at, Some(1_760_000_001_000));
    assert_eq!(direct[0].ended_at, Some(1_760_000_003_000));
    let mut streamed = Vec::new();
    connector
        .scan_with_callback(&ctx, &mut |conversation| {
            streamed.push(conversation);
            Ok(())
        })
        .unwrap();
    let mut bounded = Vec::new();
    connector
        .scan_with_source_boundaries(&ctx, &mut SourceScanHooks::default(), &mut |conversation| {
            bounded.push(conversation);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        serde_json::to_value(&direct).unwrap(),
        serde_json::to_value(streamed).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&direct).unwrap(),
        serde_json::to_value(bounded).unwrap()
    );
    assert!(!connector.supports_streaming_scan());
    assert!(!connector.supports_source_boundaries());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
}

#[test]
fn ordinary_legacy_projection_and_usage_estimates_remain_unchanged() {
    let temp = TempDir::new().unwrap();
    let sessions = temp.path().join(".vibe/logs/session");
    let rows = [
        json!({"speaker": "user", "text": "Legacy prompt", "createdAt": 1_760_000_000_000_i64}),
        json!({"message": {"role": "assistant", "content": "Nested answer", "timestamp": 1_760_000_001_000_i64}}),
        json!({"content": "Implicit assistant", "reasoning_content": "not-native", "tool_calls": [function("not-native", Value::Null, Value::Null)]}),
        json!({"role": "assistant", "content": "  Ordinary answer  ", "usage": {"prompt_tokens": 99, "completion_tokens": 0}}),
        json!({"role": "assistant", "content": "", "usage": {"prompt_tokens": 0, "completion_tokens": 0}}),
    ];
    write_session(&sessions, "session-legacy", &rows);
    let conversation = scan(&sessions);
    assert_eq!(conversation.messages.len(), 4);
    assert_eq!(conversation.title.as_deref(), Some("Legacy prompt"));
    assert_eq!(conversation.messages[0].role, "user");
    assert_eq!(conversation.messages[1].content, "Nested answer");
    assert_eq!(conversation.messages[2].content, "Implicit assistant");
    assert_eq!(conversation.messages[3].content, "  Ordinary answer  ");
    assert_eq!(conversation.started_at, Some(1_760_000_000_000));
    assert_eq!(conversation.ended_at, Some(1_760_000_001_000));
    for (message, row) in conversation.messages.iter().zip(&rows) {
        assert_eq!(message.extra, *row);
        assert!(message.invocations.is_empty());
        let usage =
            extract_tokens_for_agent("vibe", &message.extra, &message.content, &message.role);
        assert_eq!(usage.data_source, TokenDataSource::Estimated);
    }
}
