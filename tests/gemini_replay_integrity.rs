//! Gemini CLI JSONL replay must emit the final history, not append-log versions.
//!
//! Fixtures follow google-gemini/gemini-cli at
//! 9b6e0265d16bbd29ca51e33c9e0c01dc4cec5e83, specifically
//! packages/core/src/services/chatRecordingService.ts and chatRecordingTypes.ts.
#![cfg(feature = "connectors")]

use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

use franken_agent_detection::{
    Connector, DiscoveredSourceFile, DiscoveredSourceRole, GeminiConnector, NormalizedConversation,
    Origin, Platform, ScanContext, ScanRoot, SourceCompletion, SourceScanHooks,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const COMPACT_THRESHOLD: u64 = 32 * 1024 * 1024;

struct Fixture {
    _root: TempDir,
    path: PathBuf,
    ctx: ScanContext,
    prefix: Vec<u8>,
    size: u64,
}

fn header() -> Value {
    // Current Gemini headers need not have `kind`; subagent headers share
    // the same schema and replay controls as the main conversation.
    json!({
        "sessionId": "replay-session", "projectHash": "replay-project",
        "startTime": "2026-10-09T10:00:00Z",
        "lastUpdated": "2026-10-09T10:00:10Z",
    })
}

fn message(id: &str, kind: &str, content: &str) -> Value {
    json!({
        "id": id, "type": kind, "content": content,
        "timestamp": "2026-10-09T10:00:01Z",
    })
}

fn encode(records: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for record in records {
        writeln!(bytes, "{record}").unwrap();
    }
    bytes
}

const fn padding() -> [u8; 8192] {
    let mut bytes = [b' '; 8192];
    bytes[8191] = b'\n';
    bytes
}

impl Fixture {
    fn new(records: &[Value]) -> Self {
        Self::from_bytes(encode(records), None)
    }

    fn from_bytes(prefix: Vec<u8>, size: Option<u64>) -> Self {
        let root = TempDir::new().unwrap();
        let path = root.path().join("project/chats/session-replay.jsonl");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let size = size.unwrap_or_else(|| u64::try_from(prefix.len()).unwrap());
        let mut remaining = usize::try_from(size).unwrap() - prefix.len();
        let mut writer = BufWriter::new(fs::File::create(&path).unwrap());
        writer.write_all(&prefix).unwrap();
        // Actual file length selects compaction without allocating a giant
        // metadata value or an unbounded physical line.
        let pad = padding();
        while remaining > 0 {
            let len = remaining.min(pad.len());
            writer.write_all(&pad[..len]).unwrap();
            remaining -= len;
        }
        writer.flush().unwrap();
        let scan_root = ScanRoot::remote(
            path.clone(),
            Origin::remote_with_host("gemini-replay-source", "fixture-host"),
            Some(Platform::Linux),
        );
        let ctx =
            ScanContext::with_roots(root.path().join("unrelated-data"), vec![scan_root], None);
        Self {
            _root: root,
            path,
            ctx,
            prefix,
            size,
        }
    }

    fn assert_unchanged(&self, before: &fs::Metadata) {
        let after = fs::metadata(&self.path).unwrap();
        assert_eq!(after.len(), before.len());
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        assert_eq!(
            after.permissions().readonly(),
            before.permissions().readonly()
        );
        let mut reader = BufReader::new(fs::File::open(&self.path).unwrap());
        let mut actual_prefix = vec![0; self.prefix.len()];
        reader.read_exact(&mut actual_prefix).unwrap();
        assert_eq!(actual_prefix, self.prefix);
        let pad = padding();
        let mut buffer = [0; 8192];
        let mut remaining = usize::try_from(self.size).unwrap() - self.prefix.len();
        while remaining > 0 {
            let len = remaining.min(buffer.len());
            reader.read_exact(&mut buffer[..len]).unwrap();
            assert_eq!(&buffer[..len], &pad[..len]);
            remaining -= len;
        }
        assert_eq!(reader.read(&mut buffer).unwrap(), 0);
    }

    fn scan_all_routes(&self) -> NormalizedConversation {
        let before = fs::metadata(&self.path).unwrap();
        let connector = GeminiConnector::new();
        let discovered = connector.discover_source_files(&self.ctx).unwrap();
        assert_eq!(discovered.len(), 1);
        let source = &discovered[0];
        assert_eq!(source.provider_slug, "gemini");
        assert_eq!(source.role, DiscoveredSourceRole::PrimarySessionLog);
        assert_eq!(source.source_path, self.path);
        assert_eq!(source.scan_root, self.path);
        assert_eq!(source.origin, self.ctx.scan_roots[0].origin);
        assert_eq!(source.platform, Some(Platform::Linux));
        assert_eq!(source.size_bytes, Some(self.size));
        assert!(source.required_for_reconstruction);

        let collected = connector.scan(&self.ctx).unwrap();
        assert_eq!(collected.len(), 1);
        let mut streamed = Vec::new();
        connector
            .scan_with_callback(&self.ctx, &mut |conversation| {
                streamed.push(conversation);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            serde_json::to_value(&streamed).unwrap(),
            serde_json::to_value(&collected).unwrap(),
        );
        let mut visited = Vec::new();
        let mut completed = Vec::new();
        let mut bounded = Vec::new();
        {
            let mut should_scan = |source: &DiscoveredSourceFile| {
                visited.push(source.clone());
                true
            };
            let mut complete = |completion: &SourceCompletion| {
                assert_eq!(completion.conversations_emitted, 1);
                assert!(completion.required_sidecars.is_empty());
                completed.push(completion.source.clone());
                Ok(())
            };
            connector
                .scan_with_source_boundaries(
                    &self.ctx,
                    &mut SourceScanHooks {
                        should_scan_source: Some(&mut should_scan),
                        on_source_complete: Some(&mut complete),
                    },
                    &mut |conversation| {
                        bounded.push(conversation);
                        Ok(())
                    },
                )
                .unwrap();
        }
        assert_eq!(visited, discovered);
        assert_eq!(completed, discovered);
        assert_eq!(
            serde_json::to_value(&bounded).unwrap(),
            serde_json::to_value(&collected).unwrap(),
        );
        let conversation = collected.into_iter().next().unwrap();
        assert_eq!(conversation.agent_slug, "gemini");
        assert_eq!(conversation.external_id.as_deref(), Some("replay-session"));
        assert_eq!(conversation.metadata["project_hash"], "replay-project");
        assert_eq!(conversation.source_path, self.path);
        for (index, message) in conversation.messages.iter().enumerate() {
            assert_eq!(message.idx, i64::try_from(index).unwrap());
        }
        self.assert_unchanged(&before);
        conversation
    }
}

fn ids(conversation: &NormalizedConversation) -> Vec<&str> {
    conversation
        .messages
        .iter()
        .map(|message| message.extra["id"].as_str().unwrap())
        .collect()
}

#[test]
fn repeated_message_ids_replace_in_place_without_merging_distinct_replies() {
    let mut draft = message("reply", "gemini", "Draft answer");
    draft["tokens"] = json!({"input": 100, "output": 3, "total": 103});
    draft["obsolete"] = json!("must not survive full replacement");
    let mut final_reply = message("reply", "gemini", "Final answer");
    final_reply["model"] = json!("gemini-2.5-pro");
    final_reply["tokens"] = json!({"input": 100, "output": 8, "total": 108});
    let mut distinct_reply = final_reply.clone();
    distinct_reply["id"] = json!("distinct-reply");
    let fixture = Fixture::new(&[
        header(),
        message("prompt", "user", "Initial question"),
        draft,
        message("follow-up", "user", "Follow-up question"),
        final_reply.clone(),
        distinct_reply,
    ]);
    let conversation = fixture.scan_all_routes();
    assert_eq!(
        ids(&conversation),
        ["prompt", "reply", "follow-up", "distinct-reply"]
    );
    assert_eq!(conversation.messages[1].role, "assistant");
    assert_eq!(conversation.messages[1].content, "Final answer");
    assert_eq!(conversation.messages[1].extra, final_reply);
    assert_eq!(conversation.messages[3].content, "Final answer");
    let total: i64 = conversation
        .messages
        .iter()
        .filter_map(|message| {
            message
                .extra
                .pointer("/tokens/total")
                .and_then(Value::as_i64)
        })
        .sum();
    assert_eq!(total, 216, "one final usage record for each distinct reply");
}

#[test]
fn content_and_tool_result_patches_preserve_unpatched_message_fields() {
    let mut reply = message("reply", "gemini", "");
    reply["model"] = json!("gemini-2.5-pro");
    reply["tokens"] = json!({"input": 20, "output": 5, "total": 25});
    reply["toolCalls"] = json!([
        {"id": "call-one", "name": "read_file", "args": {"path": "src/lib.rs"},
         "status": "success", "timestamp": "2026-10-09T10:00:02Z", "result": "before"},
        {"id": "call-two", "name": "list_directory", "args": {"path": "src"},
         "status": "success", "timestamp": "2026-10-09T10:00:03Z", "result": "before"},
    ]);
    let fixture = Fixture::new(&[
        header(),
        message("prompt", "user", "Original question"),
        reply.clone(),
        json!({"$patch": {
            "id": "reply", "content": [{"text": "Patched answer"}],
            "type": "user", "model": "ignored-model", "tokens": {"total": 999},
            "toolCalls": [
                {"id": "call-one", "result": [{"text": "updated tool result"}],
                 "name": "ignored-name", "args": {"path": "ignored"}, "status": "error"},
                {"id": "missing-call", "result": "must not create a new tool"}
            ]
        }}),
        json!({"$patch": {"updates": [
            {"id": "prompt", "content": "Revised question", "type": "gemini"},
            {"id": "reply", "toolCalls": [{"id": "call-two", "result": null}]},
            {"id": "missing-message", "content": "must not create a new message"}
        ]}}),
    ]);
    let conversation = fixture.scan_all_routes();
    assert_eq!(ids(&conversation), ["prompt", "reply"]);
    assert_eq!(conversation.title.as_deref(), Some("Revised question"));
    assert_eq!(conversation.messages[0].role, "user");
    assert_eq!(conversation.messages[1].role, "assistant");
    assert_eq!(conversation.messages[1].content, "Patched answer");
    reply["content"] = json!([{"text": "Patched answer"}]);
    reply["toolCalls"][0]["result"] = json!([{"text": "updated tool result"}]);
    reply["toolCalls"][1]["result"] = Value::Null;
    assert_eq!(conversation.messages[1].extra, reply);
}

#[test]
fn batch_patches_remove_and_reorder_surviving_messages_before_reinsertion() {
    let fixture = Fixture::new(&[
        header(),
        message("a", "user", "First question"),
        message("b", "gemini", "Obsolete second message"),
        message("c", "info", "Information remains"),
        message("d", "user", "Fourth question"),
        message("e", "gemini", "Last reply"),
        json!({"$patch": {
            "id": "a", "content": "Single update runs first",
            "updates": [{"id": "a", "content": "Batch update runs second"}],
            "removeIds": ["b", "missing", null, 7],
            "orderIds": ["e", "a", "e", "missing", false]
        }}),
        message("b", "gemini", "Reinserted at the end"),
    ]);
    let conversation = fixture.scan_all_routes();
    assert_eq!(ids(&conversation), ["c", "d", "e", "a", "b"]);
    assert_eq!(conversation.messages[0].role, "system");
    assert_eq!(conversation.messages[3].content, "Batch update runs second");
    assert_eq!(conversation.messages[4].content, "Reinserted at the end");
    assert_eq!(conversation.title.as_deref(), Some("Fourth question"));
}

#[test]
fn rewinds_remove_the_target_inclusively_and_unknown_targets_reset_history() {
    for target in ["rewound-question", "unknown-target"] {
        let fixture = Fixture::new(&[
            header(),
            message("retained-question", "user", "Retained question"),
            message("retained-reply", "gemini", "Retained reply"),
            message("rewound-question", "user", "Discarded question"),
            message("discarded-reply", "gemini", "Discarded reply"),
            json!({"$rewindTo": target}),
            message("replacement", "user", "Replacement question"),
        ]);
        let conversation = fixture.scan_all_routes();
        let expected = if target == "unknown-target" {
            vec!["replacement"]
        } else {
            vec!["retained-question", "retained-reply", "replacement"]
        };
        assert_eq!(ids(&conversation), expected);
        assert!(
            conversation
                .messages
                .iter()
                .all(|message| !message.content.contains("Discarded"))
        );
    }
}

#[test]
fn partial_headers_upsert_messages_without_erasing_prior_history() {
    let fixture = Fixture::new(&[
        header(),
        message("prompt", "user", "Original question"),
        message("reply", "gemini", "Retained reply"),
        json!({
            "sessionId": "replay-session", "projectHash": "replay-project",
            "kind": "subagent", "messages": [
                message("prompt", "user", "Updated question"),
                message("later", "gemini", "Additional reply")
            ]
        }),
    ]);
    let conversation = fixture.scan_all_routes();
    assert_eq!(ids(&conversation), ["prompt", "reply", "later"]);
    assert_eq!(conversation.messages[0].content, "Updated question");
    assert_eq!(conversation.messages[1].content, "Retained reply");
}

#[test]
fn legacy_set_checkpoints_replace_history_and_accept_later_message_updates() {
    let fixture = Fixture::new(&[
        header(),
        message("obsolete", "user", "Discarded by checkpoint"),
        json!({"$set": {"messages": [
            message("checkpoint-question", "user", "First checkpoint version"),
            message("checkpoint-question", "user", "Final checkpoint question"),
            message("checkpoint-reply", "gemini", "Checkpoint reply")
        ]}}),
        json!({"$set": {"lastUpdated": "2026-10-09T10:00:20Z"}}),
        json!({"$patch": {"id": "checkpoint-reply", "content": "Patched checkpoint reply"}}),
        message("later", "user", "After checkpoint"),
    ]);
    let conversation = fixture.scan_all_routes();
    assert_eq!(
        ids(&conversation),
        ["checkpoint-question", "checkpoint-reply", "later"]
    );
    assert_eq!(
        conversation.messages[0].content,
        "Final checkpoint question"
    );
    assert_eq!(conversation.messages[1].content, "Patched checkpoint reply");
    assert_eq!(conversation.ended_at, Some(1_791_540_020_000));
}

#[test]
fn snapshot_and_header_messages_ignore_patch_records_and_keep_idless_history() {
    let valid = message("reply", "gemini", "Valid reply");
    for checkpoint in [false, true] {
        let snapshot = json!([
            valid.clone(),
            {"id": "reply", "type": "gemini", "content": "Invalid replacement",
             "$patch": {"content": "Not a message record"}},
            {"id": "reply", "type": "gemini", "content": "Another invalid replacement",
             "$patch": null},
            {"type": "user", "content": "Idless historical question"}
        ]);
        let record = if checkpoint {
            json!({"$set": {"messages": snapshot}})
        } else {
            json!({
                "sessionId": "replay-session", "projectHash": "replay-project",
                "messages": snapshot,
            })
        };
        let fixture = Fixture::new(&[header(), record]);
        let conversation = fixture.scan_all_routes();
        assert_eq!(conversation.messages.len(), 2);
        assert_eq!(conversation.messages[0].extra, valid);
        assert_eq!(conversation.messages[0].content, "Valid reply");
        assert_eq!(conversation.messages[1].role, "user");
        assert_eq!(
            conversation.messages[1].content,
            "Idless historical question"
        );
        assert!(conversation.messages[1].extra.get("id").is_none());
    }
}

#[test]
fn malformed_utf8_and_json_lines_do_not_hide_later_replay_controls() {
    let mut bytes = encode(&[
        header(),
        message("prompt", "user", "Original question"),
        message("obsolete", "gemini", "Must be removed after damaged line"),
    ]);
    bytes.extend_from_slice(b"\xff\xfe\n{\"incomplete\":\n[]\n\n");
    bytes.extend_from_slice(&encode(&[
        json!({"$patch": {"id": "prompt", "content": "Recovered question", "removeIds": ["obsolete"]}}),
        message("reply", "gemini", "Recovered reply"),
    ]));
    // A complete final JSON record remains valid without a trailing newline.
    assert_eq!(bytes.pop(), Some(b'\n'));
    let fixture = Fixture::from_bytes(bytes, None);
    let conversation = fixture.scan_all_routes();
    assert_eq!(ids(&conversation), ["prompt", "reply"]);
    assert_eq!(conversation.messages[0].content, "Recovered question");
    assert_eq!(conversation.messages[1].content, "Recovered reply");
}

#[test]
fn replay_stays_correct_across_the_real_metadata_compaction_boundary() {
    let mut final_reply = message("reply", "gemini", "Final answer");
    final_reply["model"] = json!("gemini-2.5-pro");
    final_reply["bulky_provider_payload"] = json!("x".repeat(64 * 1024));
    let records = [
        header(),
        message("prompt", "user", "Final question"),
        message("reply", "gemini", "Obsolete draft"),
        message("obsolete", "user", "Discarded branch"),
        final_reply,
        json!({"$rewindTo": "obsolete"}),
        json!({"$patch": {"id": "reply", "content": "Final patched answer"}}),
    ];
    for size in [
        COMPACT_THRESHOLD - 1,
        COMPACT_THRESHOLD,
        COMPACT_THRESHOLD + 1,
    ] {
        let fixture = Fixture::from_bytes(encode(&records), Some(size));
        let conversation = fixture.scan_all_routes();
        assert_eq!(conversation.messages.len(), 2);
        assert_eq!(conversation.messages[0].role, "user");
        assert_eq!(conversation.messages[0].content, "Final question");
        assert_eq!(conversation.messages[1].role, "assistant");
        assert_eq!(conversation.messages[1].content, "Final patched answer");
        assert_eq!(conversation.messages[1].extra["model"], "gemini-2.5-pro");
        if size < COMPACT_THRESHOLD {
            assert_eq!(ids(&conversation), ["prompt", "reply"]);
            assert!(
                conversation.messages[1]
                    .extra
                    .get("bulky_provider_payload")
                    .is_some()
            );
        } else {
            assert!(
                conversation.messages[1]
                    .extra
                    .get("bulky_provider_payload")
                    .is_none()
            );
            assert!(
                serde_json::to_vec(&conversation.messages[1].extra)
                    .unwrap()
                    .len()
                    < 1024
            );
        }
    }
}

#[test]
fn skipped_sources_and_failed_callbacks_never_report_replay_completion() {
    let fixture = Fixture::new(&[header(), message("prompt", "user", "Question")]);
    let before = fs::metadata(&fixture.path).unwrap();
    let connector = GeminiConnector::new();
    for should_read in [false, true] {
        let mut called = 0;
        let mut completed = 0;
        let mut should_scan = |_: &DiscoveredSourceFile| should_read;
        let mut complete = |_: &SourceCompletion| {
            completed += 1;
            Ok(())
        };
        let result = connector.scan_with_source_boundaries(
            &fixture.ctx,
            &mut SourceScanHooks {
                should_scan_source: Some(&mut should_scan),
                on_source_complete: Some(&mut complete),
            },
            &mut |_| {
                called += 1;
                anyhow::bail!("replay consumer cancelled")
            },
        );
        if should_read {
            assert_eq!(result.unwrap_err().to_string(), "replay consumer cancelled");
            assert_eq!(called, 1);
        } else {
            result.unwrap();
            assert_eq!(called, 0);
        }
        assert_eq!(completed, 0);
        fixture.assert_unchanged(&before);
    }
}
