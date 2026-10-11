//! Native VS Code Copilot usage belongs to the final saved response, not each
//! response content block or append-log mutation. Fixtures follow
//! microsoft/vscode@cc3fec8846d0e678357e476fa611774da26d7e24:
//! `chatModel.ts`, `chatService.ts`, `claudeMapSessionEvents.ts` and
//! `codexMapAppServerEvents.ts`. Those producers do not share an input/cache
//! convention, so only whole-turn output is normalized as exact usage.
#![cfg(feature = "connectors")]

use std::fs;

use franken_agent_detection::token_extraction::extract_tokens_for_agent;
use franken_agent_detection::{
    Connector, CopilotConnector, ExtractedTokenUsage, NormalizedConversation, NormalizedMessage,
    ScanContext, ScanRoot, SourceScanHooks, TokenDataSource,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn request(id: Option<&str>) -> Value {
    let mut request = json!({
        "timestamp": 1_790_000_000_000_i64,
        "agent": {"extensionId": {"value": "GitHub.copilot-chat"}},
        "modelId": "selected-model-is-not-the-whole-turn-model",
        "message": {"text": "Inspect the project"},
        "response": [{"value": "Answer text."}],
    });
    if let Some(id) = id {
        request["requestId"] = id.into();
    }
    request
}

fn model_total(model: &str, input: i64, cached: i64, output: i64) -> Value {
    json!({"model": model, "inputTokens": input, "cachedTokens": cached,
           "outputTokens": output})
}

fn session(requests: Vec<Value>) -> Value {
    json!({
        "version": 3,
        "sessionId": "native-usage-session",
        "creationDate": 1_790_000_000_000_i64,
        "responderUsername": "GitHub Copilot",
        "requests": Value::Array(requests),
    })
}

fn scan_bytes(bytes: &[u8], suffix: &str) -> NormalizedConversation {
    let directory = TempDir::new().unwrap();
    let store = directory.path().join("chatSessions");
    fs::create_dir_all(&store).unwrap();
    let file = store.join(format!("native.{suffix}"));
    fs::write(&file, bytes).unwrap();
    let modified = fs::metadata(&file).unwrap().modified().unwrap();
    let ctx = ScanContext::with_roots(
        directory.path().join("unrelated"),
        vec![ScanRoot::local(file.clone())],
        None,
    );
    let mut conversations = CopilotConnector::new().scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0].source_path, file);
    assert_eq!(fs::read(&file).unwrap(), bytes);
    assert_eq!(fs::metadata(&file).unwrap().modified().unwrap(), modified);
    conversations.pop().unwrap()
}

fn scan(requests: Vec<Value>) -> NormalizedConversation {
    scan_bytes(&serde_json::to_vec(&session(requests)).unwrap(), "json")
}

fn assistants(conversation: &NormalizedConversation) -> Vec<&NormalizedMessage> {
    conversation
        .messages
        .iter()
        .filter(|message| message.role == "assistant")
        .collect()
}

fn usage(message: &NormalizedMessage) -> ExtractedTokenUsage {
    extract_tokens_for_agent("copilot", &message.extra, &message.content, &message.role)
}

fn api_output(conversation: &NormalizedConversation) -> i64 {
    conversation
        .messages
        .iter()
        .map(usage)
        .filter(|usage| usage.data_source == TokenDataSource::Api)
        .filter_map(|usage| usage.output_tokens)
        .sum()
}

#[test]
fn native_turn_totals_count_output_without_guessing_input_or_model() {
    let mut row = request(Some("request-1"));
    row["modelTotals"] = json!([
        model_total("claude-sonnet-4-5", 10, 40, 20),
        model_total("gpt-4o", 100, 60, 30),
    ]);
    row["promptTokens"] = 999_999.into();
    row["completionTokens"] = 888_888.into();
    row["latestModelCall"] = json!({"reasoningTokens": 777, "cacheWriteTokens": 666});
    row["contextUsage"] = json!({"currentTokens": 555, "tokenLimit": 200_000});
    row["sessionCopilotCredits"] = 444.into();
    let conversation = scan(vec![row]);
    let messages = assistants(&conversation);
    assert_eq!(messages.len(), 1);
    let assistant = messages[0];
    let extracted = usage(assistant);
    assert_eq!(extracted.output_tokens, Some(50));
    assert_eq!(extracted.total_tokens(), Some(50));
    assert_eq!(extracted.input_tokens, None);
    assert_eq!(extracted.cache_read_tokens, None);
    assert_eq!(extracted.cache_creation_tokens, None);
    assert_eq!(extracted.thinking_tokens, None);
    assert_eq!(extracted.model_name, None);
    assert_eq!(extracted.provider, None);
    assert_eq!(extracted.data_source, TokenDataSource::Api);
    assert_eq!(assistant.extra["request_id"], "request-1");
    assert_eq!(assistant.extra["cass"]["token_usage_scope"], "turn");
    assert_eq!(
        assistant.extra["cass"]["model_totals"],
        json!([
            {"model": "claude-sonnet-4-5", "input_tokens": 10,
             "cached_tokens": 40, "output_tokens": 20},
            {"model": "gpt-4o", "input_tokens": 100,
             "cached_tokens": 60, "output_tokens": 30},
        ])
    );
    assert_eq!(assistant.extra.as_object().unwrap().len(), 3);
    assert!(conversation.messages[0].extra.get("cass").is_none());
    assert_eq!(api_output(&conversation), 50);
}

#[test]
fn single_model_totals_keep_model_and_tool_metadata() {
    let mut row = request(Some("tools"));
    row["modelTotals"] = json!([
        model_total("claude-sonnet-4-5", 10, 40, 20),
        model_total("claude-sonnet-4-5", 5, 60, 30),
    ]);
    row["response"] = json!([
        {"value": "One answer"},
        {"kind": "toolInvocationSerialized", "toolId": "read_file", "toolCallId": "call-1"},
        {"value": "with multiple parts."},
        {"kind": "toolInvocationSerialized", "toolId": "list_files", "toolCallId": "call-2"},
    ]);
    let conversation = scan(vec![row]);
    let messages = assistants(&conversation);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].content, "One answer\nwith multiple parts.");
    assert_eq!(messages[0].invocations.len(), 2);
    for slug in ["copilot", "github-copilot"] {
        let extracted =
            extract_tokens_for_agent(slug, &messages[0].extra, &messages[0].content, "assistant");
        assert_eq!(extracted.output_tokens, Some(50));
        assert_eq!(extracted.model_name.as_deref(), Some("claude-sonnet-4-5"));
        assert_eq!(extracted.provider.as_deref(), Some("anthropic"));
        assert!(extracted.has_tool_calls);
        assert_eq!(extracted.tool_call_count, 2);
    }
}

#[test]
fn tools_without_usage_preserve_counts_with_or_without_response_text() {
    for text in [None, Some("Answer text.")] {
        let mut row = request(Some("tools-without-usage"));
        let mut parts = vec![
            json!({"kind": "toolInvocationSerialized", "toolId": "read_file", "toolCallId": "call-1"}),
            json!({"kind": "toolInvocationSerialized", "toolId": "list_files", "toolCallId": "call-2"}),
        ];
        if let Some(text) = text {
            parts.push(json!({"value": text}));
        }
        row["response"] = Value::Array(parts);
        let conversation = scan(vec![row]);
        let messages = assistants(&conversation);
        assert_eq!(messages.len(), 1);
        let message = messages[0];
        assert_eq!(message.content, text.unwrap_or_default());
        assert_eq!(message.invocations.len(), 2);
        assert_eq!(message.extra["cass"]["tool_call_count"], 2);
        assert!(message.extra.pointer("/cass/token_usage_scope").is_none());
        assert!(message.extra.pointer("/cass/token_usage").is_none());
        for slug in ["copilot", "github-copilot"] {
            let extracted =
                extract_tokens_for_agent(slug, &message.extra, &message.content, "assistant");
            assert!(extracted.has_tool_calls);
            assert_eq!(extracted.tool_call_count, 2);
            assert_eq!(extracted.data_source, TokenDataSource::Estimated);
            assert_eq!(extracted.input_tokens, None);
            assert_eq!(extracted.output_tokens, text.map(|_| 3));
        }
        assert_eq!(api_output(&conversation), 0);
    }
}

#[test]
fn replayed_usage_refinements_and_content_blocks_do_not_add_usage() {
    let mut first = request(Some("request-1"));
    first["modelTotals"] = json!([model_total("gpt-4o", 10, 0, 10)]);
    let mut second = request(Some("request-2"));
    second["modelTotals"] = json!([model_total("gpt-4o", 10, 0, 20)]);
    let entries = [
        json!({"kind": 0, "v": session(vec![first])}),
        json!({"kind": 1, "k": ["requests", 0, "modelTotals"],
               "v": [model_total("gpt-4o", 20, 0, 20)]}),
        json!({"kind": 1, "k": ["requests", 0, "modelTotals"],
               "v": [model_total("gpt-4o", 20, 0, 20)]}),
        json!({"kind": 2, "k": ["requests", 0, "response"],
               "v": [{"value": "More response content."}]}),
        json!({"kind": 1, "k": ["requests", 0, "modelTotals"],
               "v": [model_total("gpt-4o", 20, 0, 20)]}),
        json!({"kind": 2, "k": ["requests"], "v": [second]}),
    ];
    let log = entries
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let conversation = scan_bytes(log.as_bytes(), "jsonl");
    let messages = assistants(&conversation);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].extra["request_id"], "request-1");
    assert_eq!(messages[1].extra["request_id"], "request-2");
    assert_eq!(messages[0].content, "Answer text.\nMore response content.");
    assert_eq!(usage(messages[0]).output_tokens, Some(20));
    assert_eq!(usage(messages[1]).output_tokens, Some(20));
    assert_eq!(api_output(&conversation), 40);
}

#[test]
fn generation_priority_counts_a_session_only_once() {
    let directory = TempDir::new().unwrap();
    let store = directory.path().join("chatSessions");
    fs::create_dir_all(&store).unwrap();
    let mut old = request(Some("same-request"));
    old["completionTokens"] = 900.into();
    let mut current = request(Some("same-request"));
    current["modelTotals"] = json!([model_total("gpt-4o", 10, 0, 20)]);
    fs::write(store.join("native.json"), session(vec![old]).to_string()).unwrap();
    let current_file = store.join("native.jsonl");
    fs::write(
        &current_file,
        json!({"kind": 0, "v": session(vec![current])}).to_string(),
    )
    .unwrap();
    let ctx = ScanContext::with_roots(
        directory.path().join("unrelated"),
        vec![ScanRoot::local(store)],
        None,
    );
    let conversations = CopilotConnector::new().scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0].source_path, current_file);
    assert_eq!(api_output(&conversations[0]), 20);
}

#[test]
fn missing_request_identifiers_do_not_merge_distinct_turns() {
    let requests = [
        None,
        None,
        Some(""),
        Some(" "),
        Some("distinct-1"),
        Some("distinct-2"),
    ]
    .into_iter()
    .map(|id| {
        let mut row = request(id);
        row["modelTotals"] = json!([model_total("gpt-4o", 1, 0, 7)]);
        row
    })
    .collect();
    let conversation = scan(requests);
    let messages = assistants(&conversation);
    assert_eq!(messages.len(), 6);
    assert!(messages[0].extra.get("request_id").is_none());
    assert!(messages[1].extra.get("request_id").is_none());
    assert_eq!(messages[2].extra["request_id"], "");
    assert_eq!(messages[3].extra["request_id"], " ");
    assert_eq!(api_output(&conversation), 42);
}

#[test]
fn zero_output_and_empty_totals_keep_usage_only_turns() {
    for totals in [json!([]), json!([model_total("gpt-4o", 0, 0, 0)])] {
        let mut row = request(Some("zero"));
        row["message"] = "".into();
        row["response"] = json!([]);
        row["modelTotals"] = totals;
        let conversation = scan(vec![row]);
        assert_eq!(conversation.messages.len(), 1);
        let message = &conversation.messages[0];
        assert_eq!(message.role, "assistant");
        assert!(message.content.is_empty());
        assert_eq!(usage(message).output_tokens, Some(0));
        assert_eq!(usage(message).data_source, TokenDataSource::Api);
    }
    let mut legacy = request(Some("legacy-zero"));
    legacy["message"] = "".into();
    legacy["response"] = Value::Null;
    legacy["completionTokens"] = 0.into();
    let conversation = scan(vec![legacy]);
    assert_eq!(conversation.messages.len(), 1);
    assert_eq!(usage(&conversation.messages[0]).output_tokens, Some(0));
}

#[test]
fn invalid_totals_never_fall_back_to_stale_completion_tokens() {
    for totals in [
        Value::Null,
        json!({"outputTokens": 100}),
        json!("bad totals"),
        json!([null]),
        json!([{"model": "gpt-4o"}]),
        json!([{"outputTokens": -1}]),
        json!([{"outputTokens": 0.5}]),
        json!([{"outputTokens": "30"}]),
        json!([{"outputTokens": u64::MAX}]),
        json!([model_total("gpt-4o", 10, 0, 20), {"model": "missing-output"}]),
        json!([model_total("gpt-4o", 10, 0, i64::MAX), {"outputTokens": 1}]),
    ] {
        let mut row = request(Some("invalid"));
        row["modelTotals"] = totals.clone();
        row["completionTokens"] = 123_456.into();
        let conversation = scan(vec![row]);
        let messages = assistants(&conversation);
        let extracted = usage(messages[0]);
        assert_eq!(
            extracted.data_source,
            TokenDataSource::Estimated,
            "{totals}"
        );
        assert_eq!(extracted.output_tokens, Some(3), "{totals}");
        assert!(messages[0].extra.pointer("/cass/token_usage").is_none());
        assert_eq!(api_output(&conversation), 0);
        if let Some(array) = totals.as_array() {
            assert_eq!(
                messages[0].extra["cass"]["model_totals"]
                    .as_array()
                    .unwrap()
                    .len(),
                array.len()
            );
        } else {
            assert_eq!(messages[0].extra["cass"]["model_totals"], Value::Null);
        }
    }
}

#[test]
fn legacy_saved_output_is_countable_without_last_call_prompt() {
    let mut legacy = request(Some("legacy"));
    legacy["promptTokens"] = 700.into();
    legacy["completionTokens"] = 40.into();
    let mut partial = request(Some("partial"));
    partial["modelTotals"] = json!([{
        "inputTokens": -1, "cachedTokens": "unknown", "outputTokens": 10,
    }]);
    let conversation = scan(vec![legacy, partial]);
    let messages = assistants(&conversation);
    for (message, output) in messages.iter().zip([40, 10]) {
        let extracted = usage(message);
        assert_eq!(extracted.output_tokens, Some(output));
        assert_eq!(extracted.input_tokens, None);
        assert_eq!(extracted.cache_read_tokens, None);
        assert_eq!(extracted.model_name, None);
        assert_eq!(extracted.data_source, TokenDataSource::Api);
    }
    assert!(messages[0].extra.pointer("/cass/model_totals").is_none());
    assert_eq!(
        messages[1].extra["cass"]["model_totals"],
        json!([{"output_tokens": 10}])
    );
}

#[test]
fn missing_counts_keep_existing_content_estimates() {
    for completion in [
        None,
        Some(Value::Null),
        Some(json!(-1)),
        Some(json!(0.5)),
        Some(json!(u64::MAX)),
    ] {
        let mut row = request(Some("no-usage"));
        row["promptTokens"] = 1_000_000.into();
        if let Some(completion) = completion {
            row["completionTokens"] = completion;
        }
        let conversation = scan(vec![row]);
        assert_eq!(conversation.messages.len(), 2);
        let message = assistants(&conversation)[0];
        assert!(message.extra.get("cass").is_none());
        assert_eq!(usage(message).data_source, TokenDataSource::Estimated);
        assert_eq!(usage(message).output_tokens, Some(3));
    }
    let mut row = request(Some("no-response"));
    row["response"] = json!([]);
    let conversation = scan(vec![row]);
    assert_eq!(conversation.messages.len(), 1);
    assert_eq!(conversation.messages[0].role, "user");
}

#[test]
fn public_extractor_requires_native_scope_and_assistant_role() {
    let attached = json!({"cass": {
        "token_usage_scope": "turn",
        "token_usage": {"output_tokens": 40, "data_source": "api"},
    }});
    for role in ["user", "tool", "system"] {
        let extracted = extract_tokens_for_agent("copilot", &attached, "Answer text.", role);
        assert_eq!(extracted.data_source, TokenDataSource::Estimated);
    }
    for extra in [
        json!({"promptTokens": 100, "completionTokens": 40}),
        json!({"cass": {"token_usage": {"output_tokens": 40}}}),
        json!({"cass": {"token_usage_scope": "call", "token_usage": {"output_tokens": 40}}}),
        json!({"cass": {"token_usage_scope": "turn", "token_usage": {"output_tokens": -1}}}),
        json!({"cass": {"token_usage_scope": "turn", "token_usage": {"output_tokens": 0.5}}}),
    ] {
        let extracted = extract_tokens_for_agent("copilot", &extra, "Answer text.", "assistant");
        assert_eq!(extracted.data_source, TokenDataSource::Estimated);
        assert_eq!(extracted.output_tokens, Some(3));
    }
}

#[test]
fn large_request_payloads_keep_only_small_usage_metadata() {
    let mut row = request(Some("large"));
    let large = "opaque request detail".repeat(64 * 1024);
    row["variableData"] = json!({"variables": [{"value": large}]});
    row["modelTotals"] = json!([{
        "model": "gpt-4o", "inputTokens": 100, "cachedTokens": 60, "outputTokens": 20,
        "unknownDetails": large,
    }]);
    row["latestModelCall"] = json!({"providerDetails": large, "reasoningTokens": 999});
    let mut bytes = serde_json::to_vec(&session(vec![row])).unwrap();
    bytes.resize(32 * 1024 * 1024 + 1, b' ');
    let conversation = scan_bytes(&bytes, "json");
    let message = assistants(&conversation)[0];
    assert_eq!(message.content, "Answer text.");
    assert_eq!(usage(message).output_tokens, Some(20));
    assert!(message.extra.to_string().len() < 512);
    let totals = &message.extra["cass"]["model_totals"][0];
    assert_eq!(totals.as_object().unwrap().len(), 4);
    assert!(totals.get("unknownDetails").is_none());
}

#[test]
fn native_usage_matches_across_all_public_scan_entry_points() {
    let directory = TempDir::new().unwrap();
    let store = directory.path().join("chatSessions");
    fs::create_dir_all(&store).unwrap();
    let file = store.join("native.json");
    let mut row = request(Some("entry-points"));
    row["modelTotals"] = json!([model_total("gpt-4o", 10, 0, 20)]);
    let bytes = serde_json::to_vec(&session(vec![row])).unwrap();
    fs::write(&file, &bytes).unwrap();
    let ctx = ScanContext::with_roots(
        directory.path().join("unrelated"),
        vec![ScanRoot::local(file.clone())],
        None,
    );
    let connector = CopilotConnector::new();
    let plain = connector.scan(&ctx).unwrap();
    let mut callback = Vec::new();
    connector
        .scan_with_callback(&ctx, &mut |conversation| {
            callback.push(conversation);
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
        serde_json::to_value(&plain).unwrap(),
        serde_json::to_value(&callback).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&plain).unwrap(),
        serde_json::to_value(&bounded).unwrap()
    );
    assert_eq!(plain.len(), 1);
    assert_eq!(api_output(&plain[0]), 20);
    assert_eq!(fs::read(&file).unwrap(), bytes);
}
