//! Claude reply identity must survive large-session compaction for usage consumers.
#![cfg(feature = "connectors")]

use std::collections::HashSet;
use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;

use franken_agent_detection::{
    ClaudeCodeConnector, Connector, NormalizedConversation, ScanContext, ScanRoot,
    SourceCompletion, SourceScanHooks, TokenDataSource, extract_tokens_for_agent,
};
use serde_json::{Value, json};

const COMPACT_THRESHOLD: u64 = 32 * 1024 * 1024;
const MODEL: &str = "claude-opus-4-6";
const PADDING: [u8; 8192] = {
    let mut bytes = [b' '; 8192];
    bytes[8191] = b'\n';
    bytes
};

fn assistant_record(
    uuid: &str,
    message_id: Option<&str>,
    request_id: Option<&str>,
    block: &Value,
) -> Value {
    let mut record = json!({
        "type": "assistant",
        "uuid": uuid,
        "timestamp": 1_700_000_000_000_i64,
        "sessionId": "usage-session",
        "cwd": "/project",
        "gitBranch": "main",
        "message": {
            "role": "assistant",
            "model": MODEL,
            "content": [block],
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_read_input_tokens": 20,
                "cache_creation_input_tokens": 5,
                "service_tier": "standard"
            }
        },
        "summary": "unrelated metadata that compaction must discard ".repeat(128)
    });
    if let Some(id) = message_id {
        record["message"]["id"] = json!(id);
    }
    if let Some(id) = request_id {
        record["requestId"] = json!(id);
    }
    record
}

fn reply_records() -> Vec<Value> {
    let text = |text: &str| json!({"type": "text", "text": text});
    vec![
        assistant_record(
            "text-uuid",
            Some("msg_1"),
            Some("req_1"),
            &text("First block"),
        ),
        assistant_record(
            "tool-uuid",
            Some("msg_1"),
            Some("req_1"),
            &json!({
                "type": "tool_use", "id": "tool_1", "name": "Read",
                "input": {"file_path": "/project/main.rs"}
            }),
        ),
        assistant_record(
            "last-uuid",
            Some("msg_1"),
            Some("req_1"),
            &text("Last block"),
        ),
        assistant_record(
            "request-uuid",
            Some("msg_1"),
            Some("req_2"),
            &text("Next request"),
        ),
        assistant_record(
            "message-uuid",
            Some("msg_2"),
            Some("req_1"),
            &text("Next message"),
        ),
        assistant_record(
            "message-only-1",
            Some("msg_partial"),
            None,
            &text("No request, first"),
        ),
        assistant_record(
            "message-only-2",
            Some("msg_partial"),
            None,
            &text("No request, second"),
        ),
        assistant_record(
            "request-only-1",
            None,
            Some("req_partial"),
            &text("No message, first"),
        ),
        assistant_record(
            "request-only-2",
            None,
            Some("req_partial"),
            &text("No message, second"),
        ),
        assistant_record("no-ids-1", None, None, &text("No identifiers, first")),
        assistant_record("no-ids-2", None, None, &text("No identifiers, second")),
        assistant_record(
            "blank-ids-1",
            Some(""),
            Some(" \t "),
            &text("Blank IDs, first"),
        ),
        assistant_record(
            "blank-ids-2",
            Some(""),
            Some(" \t "),
            &text("Blank IDs, second"),
        ),
    ]
}

fn write_session(path: &Path, records: &[Value], size: u64) -> io::Result<Vec<u8>> {
    let mut prefix = Vec::new();
    for record in records {
        writeln!(prefix, "{record}")?;
    }
    let mut remaining = usize::try_from(size).unwrap() - prefix.len();
    let mut file = BufWriter::new(fs::File::create(path)?);
    file.write_all(&prefix)?;
    // Blank lines change the actual file length without adding records or a
    // giant JSON value; fixed chunks also bound each skipped physical line.
    while remaining > 0 {
        let len = remaining.min(PADDING.len());
        file.write_all(&PADDING[..len])?;
        remaining -= len;
    }
    file.flush()?;
    Ok(prefix)
}

fn assert_source_unchanged(path: &Path, prefix: &[u8], before: &fs::Metadata) {
    let after = fs::metadata(path).unwrap();
    assert_eq!(after.len(), before.len());
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(
        after.permissions().readonly(),
        before.permissions().readonly()
    );

    // Compare every source byte without allocating another 32 MiB copy.
    let mut file = BufReader::new(fs::File::open(path).unwrap());
    let mut actual_prefix = vec![0; prefix.len()];
    file.read_exact(&mut actual_prefix).unwrap();
    assert_eq!(actual_prefix, prefix);
    let mut remaining = usize::try_from(before.len()).unwrap() - prefix.len();
    let mut buffer = [0; PADDING.len()];
    while remaining > 0 {
        let len = remaining.min(buffer.len());
        file.read_exact(&mut buffer[..len]).unwrap();
        assert_eq!(&buffer[..len], &PADDING[..len]);
        remaining -= len;
    }
    assert_eq!(file.read(&mut buffer).unwrap(), 0);
}

fn assert_messages(conversation: &NormalizedConversation, records: &[Value], compact: bool) {
    assert_eq!(conversation.agent_slug, "claude_code");
    assert_eq!(conversation.metadata["sessionId"], "usage-session");
    assert_eq!(conversation.messages.len(), records.len());
    for (index, (message, raw)) in conversation.messages.iter().zip(records).enumerate() {
        assert_eq!(message.idx, i64::try_from(index).unwrap());
        assert_eq!(message.role, "assistant");
        assert_eq!(message.author.as_deref(), Some(MODEL));
        assert_eq!(message.created_at, Some(1_700_000_000_000));
        if compact {
            let extra = message.extra.as_object().unwrap();
            assert_eq!(
                extra.len(),
                1,
                "raw content and arbitrary metadata must be dropped"
            );
            let cass = extra.get("cass").unwrap();
            assert_eq!(cass.get("message_id"), raw.pointer("/message/id"));
            assert_eq!(cass.get("request_id"), raw.get("requestId"));
            assert!(serde_json::to_vec(extra).unwrap().len() < 1024);
        } else {
            assert_eq!(&message.extra, raw);
        }

        let usage = extract_tokens_for_agent(
            &conversation.agent_slug,
            &message.extra,
            &message.content,
            &message.role,
        );
        assert_eq!(usage.data_source, TokenDataSource::Api);
        assert_eq!(usage.model_name.as_deref(), Some(MODEL));
        assert_eq!(usage.provider.as_deref(), Some("anthropic"));
        assert_eq!(usage.service_tier.as_deref(), Some("standard"));
        assert_eq!(
            [
                usage.input_tokens,
                usage.output_tokens,
                usage.cache_read_tokens,
                usage.cache_creation_tokens
            ],
            [Some(100), Some(50), Some(20), Some(5)]
        );
        assert_eq!(usage.total_tokens(), Some(175));
        let block = &raw["message"]["content"][0];
        let is_tool = block["type"] == "tool_use";
        assert_eq!(usage.has_tool_calls, is_tool);
        assert_eq!(usage.tool_call_count, u32::from(is_tool));
        if is_tool {
            assert_eq!(message.content, "[Tool: Read - /project/main.rs]");
            assert_eq!(message.invocations.len(), 1);
            let invocation = &message.invocations[0];
            assert_eq!(invocation.kind, "tool");
            assert_eq!(invocation.name, "Read");
            assert_eq!(invocation.call_id.as_deref(), Some("tool_1"));
            assert_eq!(invocation.arguments.as_ref(), block.get("input"));
        } else {
            assert_eq!(message.content, block["text"].as_str().unwrap());
            assert!(message.invocations.is_empty());
        }
    }
}

fn consumer_token_totals(conversation: &NormalizedConversation) -> (i64, i64) {
    let mut seen = HashSet::new();
    let mut all_records = 0;
    let mut distinct_replies = 0;
    for message in &conversation.messages {
        let extra = &message.extra;
        let message_id = extra
            .pointer("/cass/message_id")
            .and_then(Value::as_str)
            .or_else(|| extra.pointer("/message/id").and_then(Value::as_str))
            .filter(|id| !id.trim().is_empty());
        let request_id = extra
            .pointer("/cass/request_id")
            .and_then(Value::as_str)
            .or_else(|| extra.get("requestId").and_then(Value::as_str))
            .filter(|id| !id.trim().is_empty());
        let tokens = extract_tokens_for_agent(
            &conversation.agent_slug,
            extra,
            &message.content,
            &message.role,
        )
        .total_tokens()
        .unwrap();
        all_records += tokens;
        // Dedup belongs to the consumer. Without a complete nonblank key,
        // records are independent; never invent a shared default identity.
        if message_id
            .zip(request_id)
            .is_none_or(|key| seen.insert(key))
        {
            distinct_replies += tokens;
        }
    }
    (all_records, distinct_replies)
}

fn assert_streaming_parity(
    connector: &ClaudeCodeConnector,
    ctx: &ScanContext,
    collected: &[NormalizedConversation],
    path: &Path,
) {
    let mut streamed = Vec::new();
    connector
        .scan_with_callback(ctx, &mut |conversation| {
            streamed.push(conversation);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        serde_json::to_value(streamed).unwrap(),
        serde_json::to_value(collected).unwrap()
    );

    let mut completed = Vec::new();
    let mut bounded = Vec::new();
    {
        let mut complete = |done: &SourceCompletion| {
            assert_eq!(done.conversations_emitted, 1);
            assert_eq!(done.source.size_bytes, Some(COMPACT_THRESHOLD));
            assert!(done.required_sidecars.is_empty());
            completed.push(done.source.source_path.clone());
            Ok(())
        };
        let mut hooks = SourceScanHooks {
            should_scan_source: None,
            on_source_complete: Some(&mut complete),
        };
        connector
            .scan_with_source_boundaries(ctx, &mut hooks, &mut |conversation| {
                bounded.push(conversation);
                Ok(())
            })
            .unwrap();
    }
    assert_eq!(completed, vec![path.to_path_buf()]);
    assert_eq!(
        serde_json::to_value(bounded).unwrap(),
        serde_json::to_value(collected).unwrap()
    );
}

#[test]
fn claude_reply_usage_deduplicates_across_the_real_compaction_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let records = reply_records();
    let connector = ClaudeCodeConnector::new();
    for size in [
        COMPACT_THRESHOLD - 1,
        COMPACT_THRESHOLD,
        COMPACT_THRESHOLD + 1,
    ] {
        let path = temp.path().join(format!("session-{size}.jsonl"));
        let prefix = write_session(&path, &records, size).unwrap();
        let before = fs::metadata(&path).unwrap();
        assert_eq!(before.len(), size);
        let ctx = ScanContext::with_roots(
            temp.path().join("cass"),
            vec![ScanRoot::local(path.clone())],
            None,
        );
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].source_path, path);
        assert_messages(&conversations[0], &records, size >= COMPACT_THRESHOLD);
        // Three blocks share one reply; two other complete pairs are distinct.
        // Eight partially/unidentified records must each retain their usage.
        assert_eq!(
            consumer_token_totals(&conversations[0]),
            (13 * 175, 11 * 175)
        );
        if size == COMPACT_THRESHOLD {
            assert_streaming_parity(&connector, &ctx, &conversations, &path);
        }
        assert_source_unchanged(&path, &prefix, &before);
    }
}
