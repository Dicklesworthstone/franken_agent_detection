//! Cline's persisted UI request rows carry usage separately from reply text.
//! Fields and legacy pairing follow cline/cline at
//! c3a40572765b76873c597247941118c1778d02c8, apps/vscode/src/shared/
//! getApiMetrics.ts, combineApiRequests.ts, and ExtensionMessage.ts.
#![cfg(feature = "connectors")]

use std::fs;

use franken_agent_detection::token_extraction::extract_tokens_for_agent;
use franken_agent_detection::{
    ClineConnector, Connector, ExtractedTokenUsage, NormalizedConversation, ScanContext, ScanRoot,
    TokenDataSource,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn row(kind: &str, ts: i64, text: &str) -> Value {
    json!({"type": "say", "say": kind, "ts": ts, "text": text,
           "modelInfo": {"modelId": "claude-sonnet-4-5", "providerId": "anthropic"}})
}

fn counts(input: i64, output: i64, writes: i64, reads: i64) -> String {
    json!({"tokensIn": input, "tokensOut": output,
           "cacheWrites": writes, "cacheReads": reads})
    .to_string()
}

fn extract(extra: &Value) -> ExtractedTokenUsage {
    extract_tokens_for_agent("cline", extra, "Answer text.", "assistant")
}

fn scan(rows: &[Value], api_history: bool) -> NormalizedConversation {
    let dir = TempDir::new().unwrap();
    let task = dir.path().join("saoudrizwan.claude-dev/tasks/usage-task");
    fs::create_dir_all(&task).unwrap();
    let file = task.join(if api_history {
        "api_conversation_history.json"
    } else {
        "ui_messages.json"
    });
    let bytes = serde_json::to_vec(rows).unwrap();
    fs::write(&file, &bytes).unwrap();
    let modified = fs::metadata(&file).unwrap().modified().unwrap();
    let ctx = ScanContext::with_roots(
        dir.path().join("unrelated"),
        vec![ScanRoot::local(file.clone())],
        None,
    );
    let mut conversations = ClineConnector::new().scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(fs::read(&file).unwrap(), bytes);
    assert_eq!(fs::metadata(&file).unwrap().modified().unwrap(), modified);
    conversations.pop().unwrap()
}

fn usages(conversation: &NormalizedConversation) -> Vec<ExtractedTokenUsage> {
    conversation
        .messages
        .iter()
        .map(|message| {
            extract_tokens_for_agent("cline", &message.extra, &message.content, &message.role)
        })
        .collect()
}

fn api_total(usage: &[ExtractedTokenUsage]) -> i64 {
    usage
        .iter()
        .filter(|value| value.data_source == TokenDataSource::Api)
        .filter_map(ExtractedTokenUsage::total_tokens)
        .sum()
}

#[test]
fn native_request_deleted_history_and_subagent_counts_use_disjoint_buckets() {
    for kind in ["api_req_started", "deleted_api_reqs", "subagent_usage"] {
        let usage = extract(&row(kind, 1, &counts(10, 20, 30, 40)));
        assert_eq!(usage.input_tokens, Some(10));
        assert_eq!(usage.output_tokens, Some(20));
        assert_eq!(usage.cache_creation_tokens, Some(30));
        assert_eq!(usage.cache_read_tokens, Some(40));
        assert_eq!(usage.total_tokens(), Some(100));
        assert_eq!(usage.data_source, TokenDataSource::Api);
        assert_eq!(usage.model_name.as_deref(), Some("claude-sonnet-4-5"));
        assert_eq!(usage.provider.as_deref(), Some("anthropic"));
        assert_eq!(usage.thinking_tokens, None);
    }
}

#[test]
fn explicit_zero_partial_and_invalid_fields_preserve_usage_quality() {
    for (payload, total) in [
        (json!({"tokensIn": 0}), 0),
        (json!({"tokensOut": 0}), 0),
        (json!({"cacheWrites": 0}), 0),
        (json!({"cacheReads": 0}), 0),
        (json!({"cacheReads": 40}), 40),
        (
            json!({"tokensIn": 12, "tokensOut": null, "cacheWrites": -1, "cacheReads": "999"}),
            12,
        ),
    ] {
        let usage = extract(&row("api_req_started", 1, &payload.to_string()));
        assert_eq!(usage.data_source, TokenDataSource::Api);
        assert_eq!(usage.total_tokens(), Some(total));
    }
    for payload in [
        "",
        "not json",
        "null",
        "[]",
        "[10,20,30,40]",
        "{}",
        r#"{"total":999}"#,
        r#"{"tokensIn":-1,"tokensOut":"12","cacheWrites":false,"cacheReads":null}"#,
        r#"{"tokensIn":0.5,"tokensOut":18446744073709551615,"cacheWrites":{},"cacheReads":[]}"#,
    ] {
        let usage = extract(&row("api_req_started", 1, payload));
        assert_eq!(usage.data_source, TokenDataSource::Estimated, "{payload}");
        assert_eq!(usage.input_tokens, None);
        assert_eq!(usage.output_tokens, Some(3));
        assert_eq!(usage.cache_read_tokens, None);
        assert_eq!(usage.cache_creation_tokens, None);
        assert_eq!(usage.model_name.as_deref(), Some("claude-sonnet-4-5"));
    }
}

#[test]
fn unrelated_text_context_estimates_and_lookalike_rows_are_not_api_usage() {
    for extra in [
        row("text", 1, &counts(100, 20, 0, 0)),
        row("task", 1, &counts(100, 20, 0, 0)),
        row(
            "compaction",
            1,
            r#"{"status":"completed","tokensBefore":100,"tokensAfter":10}"#,
        ),
        json!({"type": "ask", "say": "api_req_started", "text": counts(100, 20, 0, 0)}),
        json!({"say": "api_req_started", "text": counts(100, 20, 0, 0)}),
        json!({"role": "assistant", "usage": {"tokensIn": 100, "tokensOut": 20}}),
    ] {
        assert_eq!(extract(&extra).data_source, TokenDataSource::Estimated);
    }
}

#[test]
fn finish_rows_never_repeat_usage_or_estimate_bookkeeping_as_reply_text() {
    for payload in [
        counts(100, 20, 30, 40),
        String::from("bad json"),
        String::new(),
    ] {
        let usage = extract(&row("api_req_finished", 1, &payload));
        assert_eq!(usage.data_source, TokenDataSource::Suppressed);
        assert_eq!(usage.total_tokens(), None);
        assert_eq!(usage.model_name.as_deref(), Some("claude-sonnet-4-5"));
    }
}

#[test]
fn malformed_attachments_do_not_fall_back_to_stale_start_counters() {
    for attachment in [
        json!({}),
        Value::Null,
        json!([10, 20, 30, 40]),
        json!("bad"),
    ] {
        let mut extra = row("api_req_started", 1, &counts(100, 20, 30, 40));
        extra["cass"] = json!({"token_usage": attachment});
        let usage = extract(&extra);
        assert_eq!(usage.data_source, TokenDataSource::Estimated);
        assert_eq!(usage.input_tokens, None);
        assert_eq!(usage.output_tokens, Some(3));
        assert_eq!(usage.cache_creation_tokens, None);
        assert_eq!(usage.cache_read_tokens, None);
    }
}

#[test]
fn current_requests_with_equal_counts_remain_distinct_and_aggregate_rows_count_once() {
    let rows = [
        row("task", 1_700_000_000_000, "First question"),
        row(
            "api_req_started",
            1_700_000_000_001,
            &counts(100, 20, 30, 40),
        ),
        row("text", 1_700_000_000_002, "First reply"),
        row("user_feedback", 1_700_000_000_003, "Another question"),
        row(
            "api_req_started",
            1_700_000_000_004,
            &counts(100, 20, 30, 40),
        ),
        row("text", 1_700_000_000_005, "Second reply"),
        row("deleted_api_reqs", 1_700_000_000_006, &counts(10, 5, 0, 0)),
        row("subagent_usage", 1_700_000_000_007, &counts(40, 10, 0, 0)),
    ];
    let conversation = scan(&rows, false);
    assert_eq!(conversation.messages.len(), rows.len());
    assert_eq!(conversation.messages[0].role, "user");
    assert_eq!(conversation.messages[3].role, "user");
    for (message, raw) in conversation.messages.iter().zip(&rows) {
        assert_eq!(&message.extra, raw);
    }
    let usage = usages(&conversation);
    assert_eq!(api_total(&usage), 445);
    assert_eq!(
        usage
            .iter()
            .filter(|value| value.data_source == TokenDataSource::Api)
            .count(),
        4
    );
}

#[test]
fn legacy_pairs_merge_before_timestamp_sort_and_keep_all_transcript_rows() {
    let rows = [
        row("task", 1_700_000_000_000, "Question"),
        row("api_req_started", 1_700_000_000_010, &counts(1, 2, 3, 7)),
        row("text", 1_700_000_000_020, "First reply"),
        row(
            "api_req_finished",
            1_700_000_000_005,
            r#"{"tokensIn":10,"tokensOut":5}"#,
        ),
        row("api_req_started", 1_700_000_000_010, &counts(1, 2, 3, 7)),
        row("text", 1_700_000_000_030, "Second reply"),
        row(
            "api_req_finished",
            1_700_000_000_004,
            r#"{"tokensIn":20,"tokensOut":5}"#,
        ),
    ];
    let conversation = scan(&rows, false);
    assert_eq!(conversation.messages.len(), rows.len());
    let usage = usages(&conversation);
    assert_eq!(api_total(&usage), 60);
    assert_eq!(
        usage
            .iter()
            .filter(|value| value.data_source == TokenDataSource::Api)
            .count(),
        2
    );
    assert_eq!(
        usage
            .iter()
            .filter(|value| value.data_source == TokenDataSource::Suppressed)
            .count(),
        2
    );
    let starts: Vec<_> = conversation
        .messages
        .iter()
        .filter(|message| {
            message.extra.get("say").and_then(Value::as_str) == Some("api_req_started")
        })
        .collect();
    assert_eq!(
        starts[0].extra.pointer("/cass/token_usage/tokensIn"),
        Some(&json!(10))
    );
    assert_eq!(
        starts[1].extra.pointer("/cass/token_usage/tokensIn"),
        Some(&json!(20))
    );
    assert_eq!(starts[0].extra["text"], rows[1]["text"]);
    assert_eq!(starts[1].extra["text"], rows[4]["text"]);
}

#[test]
fn invalid_finish_values_clear_stale_counts_and_malformed_payloads_do_not_abort() {
    let rows = [
        row("api_req_started", 1, &counts(100, 200, 300, 400)),
        row(
            "api_req_finished",
            2,
            r#"{"tokensIn":null,"tokensOut":-1,"cacheWrites":"bad","cacheReads":18446744073709551615}"#,
        ),
        row("api_req_started", 3, r#"{"tokensIn":7}"#),
        row("api_req_finished", 4, "not json"),
        row("api_req_started", 5, "broken start"),
        row("api_req_finished", 6, &counts(999, 999, 999, 999)),
        row("api_req_started", 7, &counts(10, 20, 0, 0)),
    ];
    let conversation = scan(&rows, false);
    let usage = usages(&conversation);
    assert_eq!(
        conversation.messages[0].extra.pointer("/cass/token_usage"),
        Some(&json!({}))
    );
    assert_eq!(usage[0].data_source, TokenDataSource::Estimated);
    assert_eq!(usage[0].input_tokens, None);
    assert_eq!(api_total(&usage), 37);
    assert_eq!(usage[2].total_tokens(), Some(7));
    assert_eq!(usage[6].total_tokens(), Some(30));
}

#[test]
fn blank_legacy_start_retains_its_attached_usage_without_copying_large_requests() {
    let large_request = "request payload ".repeat(70_000);
    let rows = [
        row("api_req_started", 1, ""),
        row("api_req_finished", 2, &counts(0, 0, 0, 0)),
        row(
            "api_req_started",
            3,
            &json!({"request": large_request, "tokensIn": 2}).to_string(),
        ),
        row("text", 4, "The answer"),
        row(
            "api_req_finished",
            5,
            r#"{"tokensOut":5,"unrelated":{"large":"ignored"}}"#,
        ),
    ];
    let conversation = scan(&rows, false);
    assert_eq!(conversation.messages.len(), rows.len());
    let usage = usages(&conversation);
    assert_eq!(usage[0].data_source, TokenDataSource::Api);
    assert_eq!(usage[0].total_tokens(), Some(0));
    assert_eq!(api_total(&usage), 7);
    for message in &conversation.messages {
        if let Some(cass) = message.extra.get("cass") {
            assert!(serde_json::to_vec(cass).unwrap().len() < 128);
            assert_eq!(cass.as_object().unwrap().len(), 1);
            assert!(cass.get("token_usage").is_some());
        }
    }
    assert_eq!(conversation.messages[2].extra["text"], rows[2]["text"]);
}

#[test]
fn api_history_fallback_keeps_existing_content_estimates() {
    let conversation = scan(
        &[
            json!({"role": "user", "content": "Question"}),
            json!({"role": "assistant", "content": "Answer text."}),
        ],
        true,
    );
    let usage = usages(&conversation);
    assert_eq!(usage[0].input_tokens, Some(2));
    assert_eq!(usage[1].output_tokens, Some(3));
    assert!(
        usage
            .iter()
            .all(|value| value.data_source == TokenDataSource::Estimated)
    );
}
