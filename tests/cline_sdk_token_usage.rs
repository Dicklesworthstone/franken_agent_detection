//! Cline SDK metrics use full input, while classic UI counters use uncached
//! input. Follow cline/cline c3a40572765b76873c597247941118c1778d02c8,
//! apps/vscode/src/sdk/message-translator.ts and core/services/session-data.ts.
#![cfg(feature = "connectors")]

use std::fs;

use franken_agent_detection::token_extraction::extract_tokens_for_agent;
use franken_agent_detection::{
    ClineConnector, Connector, ExtractedTokenUsage, NormalizedConversation, ScanContext, ScanRoot,
    TokenDataSource,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn assistant(id: &str, metrics: Value) -> Value {
    let mut message = json!({"id": id, "role": "assistant", "content": "Answer text."});
    message["metrics"] = metrics;
    message
}

fn scan(messages: Vec<Value>) -> NormalizedConversation {
    let temp = TempDir::new().unwrap();
    let directory = temp.path().join(".cline/data/sessions/sdk-usage");
    fs::create_dir_all(&directory).unwrap();
    let file = directory.join("sdk-usage.messages.json");
    fs::write(
        directory.join("sdk-usage.json"),
        json!({"version": 1, "session_id": "sdk-usage", "source": "vscode",
               "model": "claude-sonnet-4", "provider": "anthropic"})
        .to_string(),
    )
    .unwrap();
    let mut snapshot = json!({"version": 1, "sessionId": "sdk-usage", "agent": "lead",
        "origin": {"sessionId": "sdk-usage", "source": "vscode", "mode": "user"}});
    snapshot["messages"] = Value::Array(messages);
    fs::write(&file, snapshot.to_string()).unwrap();
    let mut conversations = ClineConnector::new()
        .scan(&ScanContext::with_roots(
            temp.path().join("unused"),
            vec![ScanRoot::local(file)],
            None,
        ))
        .unwrap();
    assert_eq!(conversations.len(), 1);
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

#[test]
fn sdk_input_contains_both_cache_buckets_and_distinct_replies_still_count() {
    let metrics = json!({"inputTokens": 100, "outputTokens": 20,
                         "cacheReadTokens": 30, "cacheWriteTokens": 10});
    let conversation = scan(vec![
        assistant("reply-1", metrics.clone()),
        assistant("reply-2", metrics),
    ]);
    let usage = usages(&conversation);
    for item in &usage {
        assert_eq!(item.input_tokens, Some(60));
        assert_eq!(item.output_tokens, Some(20));
        assert_eq!(item.cache_read_tokens, Some(30));
        assert_eq!(item.cache_creation_tokens, Some(10));
        assert_eq!(item.total_tokens(), Some(120));
        assert_eq!(item.thinking_tokens, None);
        assert_eq!(item.data_source, TokenDataSource::Api);
    }
    assert_eq!(
        conversation.messages[0].extra["cass"]["message_id"],
        "reply-1"
    );
    assert_eq!(
        conversation.messages[1].extra["cass"]["message_id"],
        "reply-2"
    );
    assert_eq!(
        usage
            .iter()
            .filter_map(ExtractedTokenUsage::total_tokens)
            .sum::<i64>(),
        240
    );
}

#[test]
fn sdk_zero_and_partial_counters_remain_recorded_api_usage() {
    for (metrics, total) in [
        (json!({"inputTokens": 0}), 0),
        (json!({"outputTokens": 0}), 0),
        (json!({"cacheReadTokens": 0}), 0),
        (json!({"cacheWriteTokens": 0}), 0),
        (json!({"inputTokens": 100}), 100),
        (json!({"outputTokens": 20}), 20),
        (json!({"cacheReadTokens": 30, "cacheWriteTokens": 10}), 40),
        (json!({"inputTokens": 100, "cacheReadTokens": 30}), 100),
        (json!({"inputTokens": 100, "cacheWriteTokens": 10}), 100),
        (
            json!({"inputTokens": 100, "cacheReadTokens": null, "outputTokens": 20}),
            120,
        ),
    ] {
        let conversation = scan(vec![assistant("reply", metrics.clone())]);
        let usage = usages(&conversation);
        assert_eq!(usage[0].data_source, TokenDataSource::Api, "{metrics}");
        assert_eq!(usage[0].total_tokens(), Some(total), "{metrics}");
    }
}

#[test]
fn impossible_or_overflowing_sdk_cache_subsets_do_not_inflate_full_input() {
    for metrics in [
        json!({"inputTokens": 100, "outputTokens": 20, "cacheReadTokens": 120}),
        json!({"inputTokens": 100, "outputTokens": 20, "cacheReadTokens": 70, "cacheWriteTokens": 40}),
        json!({"inputTokens": 100, "outputTokens": 20, "cacheReadTokens": i64::MAX, "cacheWriteTokens": 10}),
    ] {
        let conversation = scan(vec![assistant("reply", metrics)]);
        let usage = usages(&conversation);
        assert_eq!(usage[0].input_tokens, Some(100));
        assert_eq!(usage[0].cache_read_tokens, None);
        assert_eq!(usage[0].cache_creation_tokens, None);
        assert_eq!(usage[0].total_tokens(), Some(120));
        assert_eq!(usage[0].data_source, TokenDataSource::Api);
    }
}

#[test]
fn malformed_sdk_metrics_do_not_become_zero_or_cumulative_api_counts() {
    for metrics in [
        Value::Null,
        json!([]),
        json!([10, 20, 30, 40]),
        json!("100"),
        json!({"totalTokens": 1_000_000, "cost": 12}),
        json!({"inputTokens": -1, "outputTokens": 1.5, "cacheReadTokens": "30", "cacheWriteTokens": false}),
        json!({"inputTokens": u64::MAX, "outputTokens": {"value": 20}}),
        json!({"cacheReadTokens": i64::MAX, "cacheWriteTokens": 1}),
    ] {
        let conversation = scan(vec![assistant("reply", metrics.clone())]);
        let usage = usages(&conversation);
        assert_eq!(
            usage[0].data_source,
            TokenDataSource::Estimated,
            "{metrics}"
        );
        assert_eq!(usage[0].input_tokens, None);
        assert_eq!(usage[0].output_tokens, Some(3));
        assert_eq!(usage[0].cache_read_tokens, None);
        assert_eq!(usage[0].cache_creation_tokens, None);
    }
}

#[test]
fn display_only_messages_never_count_usage_or_estimates_for_any_role() {
    let mut assistant = assistant(
        "display-assistant",
        json!({"inputTokens": 100, "outputTokens": 20}),
    );
    assistant["metadata"] = json!({"displayOnly": true});
    let conversation = scan(vec![
        assistant,
        json!({"role": "user", "content": "Display-only user text",
               "metadata": {"displayOnly": true}, "metrics": {"inputTokens": 100}}),
        json!({"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call", "name": "read_file", "content": "Display-only result"}],
               "metadata": {"displayOnly": true}, "metrics": {"outputTokens": 100}}),
        json!({"role": "assistant", "content": "Real answer", "metrics": {"inputTokens": 5, "outputTokens": 2}}),
    ]);
    assert_eq!(conversation.messages.len(), 4);
    assert_eq!(conversation.messages[2].role, "tool");
    let usage = usages(&conversation);
    for item in &usage[..3] {
        assert_eq!(item.data_source, TokenDataSource::Suppressed);
        assert_eq!(item.total_tokens(), None);
    }
    assert_eq!(usage[3].data_source, TokenDataSource::Api);
    assert_eq!(usage[3].total_tokens(), Some(7));
}

#[test]
fn sdk_model_metadata_survives_estimation_and_user_tool_fields_are_not_api_usage() {
    let conversation = scan(vec![
        json!({"role": "user", "content": "Question", "metrics": {"inputTokens": 100}}),
        json!({"role": "user", "content": [{"type": "tool_result", "name": "read_file", "tool_use_id": "call", "content": "File contents"}], "metrics": {"outputTokens": 100}}),
        json!({"role": "assistant", "content": "Selected model", "modelInfo": {"id": "gpt-4o", "provider": "openai"}}),
        json!({"role": "assistant", "content": "Fallback model", "modelInfo": {"id": "", "provider": null}}),
    ]);
    let usage = usages(&conversation);
    assert!(
        usage
            .iter()
            .all(|item| item.data_source == TokenDataSource::Estimated)
    );
    assert_eq!(usage[0].input_tokens, Some(2));
    assert_eq!(usage[1].output_tokens, Some(3));
    assert_eq!(usage[2].model_name.as_deref(), Some("gpt-4o"));
    assert_eq!(usage[2].provider.as_deref(), Some("openai"));
    assert_eq!(usage[3].model_name.as_deref(), Some("claude-sonnet-4"));
    assert_eq!(usage[3].provider.as_deref(), Some("anthropic"));
}

#[test]
fn classic_ui_counts_keep_their_independent_cache_semantics() {
    let classic = json!({"type": "say", "say": "api_req_started",
        "text": json!({"tokensIn": 100, "tokensOut": 20, "cacheReads": 30, "cacheWrites": 10}).to_string(),
        "metrics": {"inputTokens": 1_000_000}, "metadata": {"displayOnly": true}});
    let usage = extract_tokens_for_agent("cline", &classic, "Request", "assistant");
    assert_eq!(usage.data_source, TokenDataSource::Api);
    assert_eq!(usage.input_tokens, Some(100));
    assert_eq!(usage.total_tokens(), Some(160));
}
