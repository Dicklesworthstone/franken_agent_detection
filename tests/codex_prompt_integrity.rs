//! Regression coverage for session-wide text deduplication deleting real turns.
#![cfg(feature = "connectors")]

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use franken_agent_detection::{
    CodexConnector, Connector, NormalizedConversation, ScanContext, ScanRoot, SourceCompletion,
    SourceScanHooks,
};
use serde_json::{Value, json};

fn event(text: &str, timestamp: Option<i64>, turn: Option<&str>) -> Value {
    json!({
        "type": "event_msg", "timestamp": timestamp,
        "payload": {"type": "user_message", "message": text, "turn_id": turn}
    })
}

fn response(text: &str, timestamp: Option<i64>, turn: Option<&str>) -> Value {
    json!({
        "type": "response_item", "timestamp": timestamp,
        "payload": {"type": "message", "role": "user", "turn_id": turn,
                    "content": [{"type": "input_text", "text": text}]}
    })
}

fn assistant(text: &str) -> Value {
    json!({"type": "response_item", "payload": {"role": "assistant", "content": text}})
}

fn write_rollout(path: &Path, records: &[Value], compact: bool) -> io::Result<()> {
    let mut file = fs::File::create(path)?;
    for record in records {
        writeln!(file, "{record}")?;
    }
    if compact {
        // Trigger FAD's 32 MiB raw-extra compaction without huge JSON fixtures.
        // A whitespace-only physical line adds no messages or parsed objects.
        io::copy(&mut io::repeat(b' ').take(32 * 1024 * 1024), &mut file)?;
        file.write_all(b"\n")?;
    }
    file.flush()
}

fn assert_prompt_history(conversations: &[NormalizedConversation], expected: &[&str]) {
    assert_eq!(conversations.len(), 1);
    let conversation = &conversations[0];
    let users: Vec<_> = conversation
        .messages
        .iter()
        .filter(|message| message.role == "user")
        .map(|message| message.content.trim())
        .collect();
    assert_eq!(
        users, expected,
        "a response record must not erase independent prompts"
    );
    for (index, message) in conversation.messages.iter().enumerate() {
        assert_eq!(message.idx, i64::try_from(index).unwrap());
    }
}

fn assert_all_routes(records: &[Value], expected: &[&str]) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join(".codex");
    let sessions = home.join("sessions/2026/09/19");
    fs::create_dir_all(&sessions).unwrap();
    let path = sessions.join("rollout-prompts.jsonl");
    write_rollout(&path, records, false).unwrap();
    let original = fs::read(&path).unwrap();
    let connector = CodexConnector::new();
    for root in [&home, &path] {
        for since in [None, Some(0)] {
            let ctx = ScanContext::with_roots(
                temp.path().join("cass"),
                vec![ScanRoot::local(root.clone())],
                since,
            );
            let collected = connector.scan(&ctx).unwrap();
            assert_prompt_history(&collected, expected);
            let mut streamed = Vec::new();
            connector
                .scan_with_callback(&ctx, &mut |conversation| {
                    streamed.push(conversation);
                    Ok(())
                })
                .unwrap();
            assert_eq!(
                serde_json::to_value(&streamed).unwrap(),
                serde_json::to_value(&collected).unwrap()
            );
            let mut completed = Vec::new();
            let mut bounded = Vec::new();
            {
                let mut complete = |done: &SourceCompletion| {
                    assert_eq!(done.conversations_emitted, 1);
                    completed.push(done.source.source_path.clone());
                    Ok(())
                };
                let mut hooks = SourceScanHooks {
                    should_scan_source: None,
                    on_source_complete: Some(&mut complete),
                };
                connector
                    .scan_with_source_boundaries(&ctx, &mut hooks, &mut |conversation| {
                        bounded.push(conversation);
                        Ok(())
                    })
                    .unwrap();
            }
            assert_eq!(completed.as_slice(), std::slice::from_ref(&path));
            assert_eq!(
                serde_json::to_value(&bounded).unwrap(),
                serde_json::to_value(&collected).unwrap()
            );
        }
    }
    assert_eq!(
        fs::read(path).unwrap(),
        original,
        "scanning cannot edit the rollout"
    );
}

#[test]
fn repeated_continue_prompts_keep_the_unmirrored_middle_turn() {
    assert_all_routes(
        &[
            event("continue", Some(1_700_000_000_000), None),
            response("continue", Some(1_700_000_001_000), None),
            assistant("first reply"),
            event("continue", Some(1_700_000_060_000), None),
            assistant("second reply"),
            event("continue", Some(1_700_000_120_000), None),
            response("continue", Some(1_700_000_121_000), None),
            assistant("third reply"),
        ],
        &["continue", "continue", "continue"],
    );
}

#[test]
fn one_response_consumes_at_most_one_event_even_without_timestamps() {
    for records in [
        vec![
            event("continue", None, None),
            event("continue", None, None),
            response("continue", None, None),
        ],
        vec![
            event("continue", None, None),
            response("continue", None, None),
            event("continue", None, None),
        ],
        vec![
            response("continue", None, None),
            event("continue", None, None),
            event("continue", None, None),
        ],
    ] {
        assert_all_routes(&records, &["continue", "continue"]);
    }
}

#[test]
fn non_user_output_and_raw_turn_boundaries_prevent_cross_turn_matching() {
    for boundary in [
        assistant("turn complete"),
        json!({"type": "event_msg", "payload": {"type": "turn_aborted"}}),
        json!({"type": "turn_context", "payload": {"turn_id": "next-turn"}}),
        json!({"type": "compacted", "payload": {"message": "summary"}}),
    ] {
        assert_all_routes(
            &[
                event("continue", None, None),
                boundary,
                response("continue", None, None),
            ],
            &["continue", "continue"],
        );
    }
}

#[test]
fn opposite_streams_with_incompatible_identity_are_retained() {
    for records in [
        [
            event("continue", Some(1_700_000_000_000), None),
            response("continue", Some(1_700_000_060_000), None),
        ],
        [
            event("continue", None, Some("one")),
            response("continue", None, Some("two")),
        ],
        [
            event("continue", None, Some("one")),
            response("continue", None, None),
        ],
        [
            event("continue", Some(1_700_000_000_000), None),
            response("continue", None, None),
        ],
    ] {
        assert_all_routes(&records, &["continue", "continue"]);
    }
}

#[test]
fn same_stream_repetitions_and_both_pair_orders_keep_their_multiplicity() {
    assert_all_routes(
        &[
            event("event-only", None, None),
            event("event-only", None, None),
            assistant("separator"),
            response("response-only", None, None),
            response("response-only", None, None),
            assistant("separator"),
            event("paired", None, None),
            response("paired", None, None),
            response("paired", None, None),
            event("paired", None, None),
        ],
        &[
            "event-only",
            "event-only",
            "response-only",
            "response-only",
            "paired",
            "paired",
        ],
    );
}

#[test]
fn compaction_does_not_remove_the_stream_or_turn_identity_needed_for_pairing() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("rollout-compacted-prompts.jsonl");
    let records = [
        event("continue", None, Some("one")),
        response("continue", None, Some("two")),
        assistant("separator"),
        event("日本語", None, Some("three")),
        response("日本語", None, Some("three")),
    ];
    write_rollout(&path, &records, true).unwrap();
    let size_before = fs::metadata(&path).unwrap().len();
    let ctx = ScanContext::with_roots(
        temp.path().join("cass"),
        vec![ScanRoot::local(path.clone())],
        None,
    );
    let conversations = CodexConnector::new().scan(&ctx).unwrap();
    assert_prompt_history(&conversations, &["continue", "continue", "日本語"]);
    assert!(
        conversations[0]
            .messages
            .iter()
            .all(|message| message.extra.get("payload").is_none())
    );
    assert_eq!(fs::metadata(path).unwrap().len(), size_before);
}
