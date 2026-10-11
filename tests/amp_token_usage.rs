//! Native Amp snapshots follow the vendor-published
//! `@sourcegraph/amp@0.0.1768996903-g592a3a` artifact, `package/dist/main.js`.
//! Tarball SHA1: `59600df6309ede2a7c92845e3b19f5d6cc2a8ac4`.
//! Its native provider adapters produce four disjoint usage buckets and its
//! assistant-update reducer replaces one message, preserving `messageId`.
//! `W86`/`LY8` map those native counters to the documented stream schema:
//! <https://ampcode.com/docs/cli/streaming-json>.
#![cfg(feature = "connectors")]

use std::fs;

use franken_agent_detection::token_extraction::extract_tokens_for_agent;
use franken_agent_detection::{
    AmpConnector, Connector, ExtractedTokenUsage, NormalizedConversation, NormalizedMessage,
    ScanContext, ScanRoot, TokenDataSource,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn native_usage(input: i64, output: i64, created: i64, read: i64) -> Value {
    json!({
        "model": "claude-haiku-4-5-20251001",
        "inputTokens": input,
        "outputTokens": output,
        "cacheCreationInputTokens": created,
        "cacheReadInputTokens": read,
        "totalInputTokens": input + created + read,
        "maxInputTokens": 200_000,
        "timestamp": "2026-01-19T11:42:10.652Z",
    })
}

fn assistant(id: u64, content: Value, usage: Value) -> Value {
    let mut message = json!({
        "role": "assistant",
        "messageId": id,
        "state": {"type": "complete", "stopReason": "end_turn"},
    });
    message["content"] = content;
    message["usage"] = usage;
    message
}

fn session(messages: Vec<Value>) -> Value {
    json!({
        "id": "T-native-usage",
        "v": 12,
        "created": 1_767_225_600_000_i64,
        "messages": Value::Array(messages),
    })
}

fn scan_session(source: &Value) -> NormalizedConversation {
    let directory = TempDir::new().unwrap();
    let store = directory.path().join("amp/threads");
    fs::create_dir_all(&store).unwrap();
    let file = store.join("T-native-usage.json");
    let bytes = serde_json::to_vec(source).unwrap();
    fs::write(&file, &bytes).unwrap();
    let modified = fs::metadata(&file).unwrap().modified().unwrap();
    let ctx = ScanContext::with_roots(
        directory.path().join("unrelated"),
        vec![ScanRoot::local(file.clone()), ScanRoot::local(store)],
        None,
    );
    let mut conversations = AmpConnector::new().scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1);
    let conversation = conversations.pop().unwrap();
    assert_eq!(conversation.source_path, file);
    assert_eq!(&conversation.metadata, source);
    assert_eq!(fs::read(&file).unwrap(), bytes);
    assert_eq!(fs::metadata(&file).unwrap().modified().unwrap(), modified);
    for (index, message) in conversation.messages.iter().enumerate() {
        assert_eq!(message.idx, i64::try_from(index).unwrap());
    }
    conversation
}

fn scan(messages: Vec<Value>) -> NormalizedConversation {
    scan_session(&session(messages))
}

fn usage(message: &NormalizedMessage) -> ExtractedTokenUsage {
    extract_tokens_for_agent("amp", &message.extra, &message.content, &message.role)
}

fn api_total(conversation: &NormalizedConversation) -> i64 {
    conversation
        .messages
        .iter()
        .map(usage)
        .filter(|usage| usage.data_source == TokenDataSource::Api)
        .filter_map(|usage| usage.total_tokens())
        .sum()
}

#[test]
fn native_usage_counts_one_snapshot_with_multiple_content_blocks() {
    let counts = native_usage(10, 178, 986, 11_372);
    let message = assistant(
        1,
        json!([
            {"type": "text", "text": "Inspecting the project."},
            {"type": "tool_use", "id": "tool-read", "name": "Read",
             "input": {"file_path": "/work/src/main.rs"}},
            {"type": "text", "text": "The file is ready."},
        ]),
        counts.clone(),
    );
    let mut source = session(vec![message.clone()]);
    source["~debug"] = json!({"lastInferenceUsage": counts});
    source["usageLedger"] = json!({"events": [{"usage": counts}]});
    let conversation = scan_session(&source);
    assert_eq!(conversation.messages.len(), 1);
    let normalized = &conversation.messages[0];
    assert_eq!(normalized.extra, message);
    assert_eq!(normalized.invocations.len(), 1);
    assert_eq!(
        normalized.invocations[0].call_id.as_deref(),
        Some("tool-read")
    );
    let extracted = usage(normalized);
    assert_eq!(extracted.data_source, TokenDataSource::Api);
    assert_eq!(extracted.input_tokens, Some(10));
    assert_eq!(extracted.output_tokens, Some(178));
    assert_eq!(extracted.cache_creation_tokens, Some(986));
    assert_eq!(extracted.cache_read_tokens, Some(11_372));
    assert_eq!(extracted.total_tokens(), Some(12_546));
    assert_eq!(
        extracted.model_name.as_deref(),
        Some("claude-haiku-4-5-20251001")
    );
    assert_eq!(extracted.provider.as_deref(), Some("anthropic"));
    assert!(extracted.has_tool_calls);
    assert_eq!(extracted.tool_call_count, 1);
    assert_eq!(api_total(&conversation), 12_546);
}

#[test]
fn equal_counts_on_distinct_requests_are_both_counted() {
    let counts = native_usage(10, 20, 30, 40);
    let conversation = scan(vec![
        assistant(1, json!("First request"), counts.clone()),
        json!({"role": "user", "messageId": 2, "content": "Again"}),
        assistant(3, json!("Second request"), counts),
    ]);
    assert_eq!(conversation.messages.len(), 3);
    assert_eq!(conversation.messages[0].extra["messageId"], 1);
    assert_eq!(conversation.messages[2].extra["messageId"], 3);
    assert_eq!(api_total(&conversation), 200);
}

#[test]
fn normalized_openai_and_gemini_input_buckets_are_disjoint() {
    for (model, created, read, output, expected) in [
        ("gpt-4.1", 60, 40, 20, 120),
        ("gemini-2.5-pro", 70, 30, 35, 135),
    ] {
        // These native adapters put uncached input in the creation bucket.
        // Gemini's output already includes the provider's thought tokens.
        let mut counts = native_usage(0, output, created, read);
        counts["model"] = model.into();
        let conversation = scan(vec![assistant(1, json!("Answer"), counts)]);
        let extracted = usage(&conversation.messages[0]);
        assert_eq!(extracted.input_tokens, Some(0));
        assert_eq!(extracted.cache_creation_tokens, Some(created));
        assert_eq!(extracted.cache_read_tokens, Some(read));
        assert_eq!(extracted.output_tokens, Some(output));
        assert_eq!(extracted.thinking_tokens, None);
        assert_eq!(api_total(&conversation), expected);
    }
}

#[test]
fn usage_only_and_reasoning_only_snapshots_survive_including_zero() {
    let rows = vec![
        assistant(0, json!(" \n"), native_usage(0, 0, 0, 0)),
        json!({"role": "user", "messageId": 1, "content": "Keep this title"}),
        assistant(
            2,
            json!([{"type": "thinking", "thinking": "Private reasoning", "signature": "sig"}]),
            native_usage(2, 3, 0, 0),
        ),
        assistant(3, json!([]), json!({"cacheReadInputTokens": 0})),
    ];
    let conversation = scan(rows.clone());
    assert_eq!(conversation.messages.len(), 4);
    assert_eq!(conversation.title.as_deref(), Some("Keep this title"));
    for index in [0, 2, 3] {
        assert!(conversation.messages[index].content.trim().is_empty());
        assert_eq!(conversation.messages[index].extra, rows[index]);
        assert_eq!(
            usage(&conversation.messages[index]).data_source,
            TokenDataSource::Api
        );
    }
    assert_eq!(usage(&conversation.messages[0]).total_tokens(), Some(0));
    assert_eq!(usage(&conversation.messages[3]).cache_read_tokens, Some(0));
    assert_eq!(api_total(&conversation), 5);
}

#[test]
fn native_tool_only_requests_keep_existing_invocation_behavior() {
    let conversation = scan(vec![assistant(
        1,
        json!([
            {"type": "tool_use", "id": "skill-1", "name": "skill",
             "input": {"name": "review-code"}},
            {"type": "tool_use", "id": "read-1", "name": "Read",
             "input": {"file_path": "/work/src/main.rs"}},
        ]),
        native_usage(1, 2, 3, 4),
    )]);
    let message = &conversation.messages[0];
    assert!(message.content.contains("[Tool: skill]"));
    assert_eq!(message.invocations.len(), 2);
    assert_eq!(message.invocations[0].kind, "skill");
    assert_eq!(message.invocations[0].name, "review-code");
    assert_eq!(message.invocations[0].raw_name.as_deref(), Some("skill"));
    assert_eq!(usage(message).tool_call_count, 2);
    assert_eq!(api_total(&conversation), 10);
}

#[test]
fn invalid_counters_and_context_statistics_do_not_claim_api_usage() {
    for invalid in [
        json!(null),
        json!(-1),
        json!(1.5),
        json!("23"),
        json!(true),
        json!([]),
        json!({}),
        json!(u64::MAX),
    ] {
        let mut counts = native_usage(1, 2, 3, 4);
        for key in [
            "inputTokens",
            "outputTokens",
            "cacheCreationInputTokens",
            "cacheReadInputTokens",
        ] {
            counts[key] = invalid.clone();
        }
        let conversation = scan(vec![assistant(1, json!("An answer"), counts)]);
        let extracted = usage(&conversation.messages[0]);
        assert_eq!(
            extracted.data_source,
            TokenDataSource::Estimated,
            "{invalid}"
        );
        assert_eq!(extracted.input_tokens, None);
        assert_eq!(extracted.cache_creation_tokens, None);
        assert_eq!(extracted.cache_read_tokens, None);
        assert_eq!(api_total(&conversation), 0);
    }
    for counts in [
        json!({}),
        json!(null),
        json!("invalid"),
        json!([]),
        json!({"model": "claude-sonnet-4", "totalInputTokens": 500,
               "maxInputTokens": 200_000, "totalCostUSD": 0.25}),
    ] {
        let conversation = scan(vec![assistant(1, json!("An answer"), counts)]);
        assert_eq!(
            usage(&conversation.messages[0]).data_source,
            TokenDataSource::Estimated
        );
        assert_eq!(api_total(&conversation), 0);
    }
}

#[test]
fn valid_partial_counts_and_explicit_zero_are_api_data() {
    for key in [
        "inputTokens",
        "outputTokens",
        "cacheCreationInputTokens",
        "cacheReadInputTokens",
    ] {
        for count in [0, 17] {
            let mut counts = json!({"inputTokens": -1, "outputTokens": null,
                                    "cacheCreationInputTokens": "9", "cacheReadInputTokens": 1.5});
            counts[key] = count.into();
            let conversation = scan(vec![assistant(1, json!([]), counts)]);
            let extracted = usage(&conversation.messages[0]);
            assert_eq!(extracted.data_source, TokenDataSource::Api, "{key}");
            assert_eq!(extracted.total_tokens(), Some(count));
            assert_eq!(api_total(&conversation), count);
        }
    }
}

#[test]
fn usage_model_is_not_inferred_from_thread_selection_or_debug_calls() {
    for model in [json!(null), json!(""), json!("  "), json!(23)] {
        let mut counts = json!({"outputTokens": 4});
        counts["model"] = model;
        let mut row = assistant(1, json!("Answer"), counts);
        row["model"] = "selected-not-used-model".into();
        row["~debugUsage"] = native_usage(100, 200, 300, 400);
        let mut source = session(vec![row]);
        source["model"] = "claude-opus-4-5".into();
        let conversation = scan_session(&source);
        let extracted = usage(&conversation.messages[0]);
        assert_eq!(extracted.model_name, None);
        assert_eq!(extracted.provider, None);
        assert_eq!(extracted.total_tokens(), Some(4));
    }
}

#[test]
fn user_and_tool_rows_and_missing_usage_remain_estimated() {
    for role in ["user", "human", "tool", "toolResult", "system"] {
        let mut row = assistant(1, json!("Some content"), native_usage(10, 20, 30, 40));
        row["role"] = role.into();
        let conversation = scan(vec![row]);
        assert_eq!(
            usage(&conversation.messages[0]).data_source,
            TokenDataSource::Estimated
        );
        assert_eq!(api_total(&conversation), 0);
    }
    let conversation = scan(vec![
        json!({"role": "user", "content": "Prompt"}),
        json!({"role": "assistant", "content": "Answer", "~debugUsage": native_usage(10, 20, 30, 40)}),
        assistant(2, json!([]), json!({"totalInputTokens": 999})),
        assistant(3, json!([]), json!({"outputTokens": -1})),
    ]);
    assert_eq!(conversation.messages.len(), 2);
    assert_eq!(api_total(&conversation), 0);
}

#[test]
fn native_timestamps_date_each_usage_record_and_keep_legacy_precedence() {
    let mut legacy = assistant(2, json!("Legacy timestamp"), native_usage(1, 2, 3, 4));
    legacy["created_at"] = 1_769_000_000_000_i64.into();
    let conversation = scan(vec![
        json!({"role": "user", "content": "Prompt", "meta": {"sentAt": 1_768_824_000_000_i64}}),
        assistant(1, json!("Native timestamp"), native_usage(1, 2, 3, 4)),
        legacy,
    ]);
    assert_eq!(conversation.messages[0].created_at, Some(1_768_824_000_000));
    assert_eq!(conversation.messages[1].created_at, Some(1_768_822_930_652));
    assert_eq!(conversation.messages[2].created_at, Some(1_769_000_000_000));
    assert_eq!(conversation.started_at, Some(1_768_822_930_652));
    assert_eq!(conversation.ended_at, Some(1_769_000_000_000));
}

#[test]
fn stale_fork_metadata_and_reused_message_ids_do_not_hide_new_requests() {
    // The native writer keeps forkPointIndex after editing/truncating history,
    // and descendants allocate message IDs starting at zero. Neither alone
    // establishes that a current row is a copied request. Cross-conversation
    // fork aggregation needs stronger provenance than this stateless API has.
    let counts = native_usage(1, 2, 3, 4);
    let mut source = session(vec![
        json!({"role": "user", "messageId": 0, "content": "Edited descendant prompt"}),
        assistant(1, json!("New descendant answer"), counts.clone()),
        json!({"role": "user", "messageId": 0, "content": "Another descendant request"}),
        assistant(1, json!("Another new answer"), counts),
    ]);
    source["originThreadID"] = "T-origin".into();
    source["forkPointIndex"] = 3.into();
    let conversation = scan_session(&source);
    assert_eq!(conversation.messages.len(), 4);
    assert_eq!(api_total(&conversation), 20);
    assert_eq!(conversation.messages[1].extra["messageId"], 1);
    assert_eq!(conversation.messages[3].extra["messageId"], 1);
}
