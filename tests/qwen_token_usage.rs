//! Qwen's `OpenAI` conversions retain reasoning inside candidate usage.
//!
//! Fixtures follow QwenLM/qwen-code at
//! a238b91e7c6fc2b0e36e23436b0e4ced5296617b, specifically the `OpenAI` Chat
//! and Responses converters, their regression tests, and chatRecordingService.
#![cfg(feature = "connectors")]

use franken_agent_detection::token_extraction::extract_tokens_for_agent;
use franken_agent_detection::{ExtractedTokenUsage, TokenDataSource};
use serde_json::{Map, Value, json};

fn snapshot(usage: &ExtractedTokenUsage) -> Value {
    json!({
        "input": usage.input_tokens, "output": usage.output_tokens,
        "cached": usage.cache_read_tokens, "cache_creation": usage.cache_creation_tokens,
        "thinking": usage.thinking_tokens, "total": usage.total_tokens(),
        "model": usage.model_name, "provider": usage.provider,
        "source": usage.data_source.as_str(),
        "has_tool_calls": usage.has_tool_calls, "tool_call_count": usage.tool_call_count,
    })
}

fn wire_variants(usage: &Value) -> [Value; 3] {
    let mut legacy = Map::new();
    for (native, key) in [
        ("promptTokenCount", "input"),
        ("candidatesTokenCount", "output"),
        ("cachedContentTokenCount", "cached"),
        ("thoughtsTokenCount", "thoughts"),
        ("toolUsePromptTokenCount", "tool"),
        ("totalTokenCount", "total"),
    ] {
        if let Some(value) = usage.get(native) {
            legacy.insert(key.to_owned(), value.clone());
        }
    }
    [
        json!({"model": "qwen3-coder-plus", "usageMetadata": usage}),
        json!({"cass": {"model": "qwen3-coder-plus", "usage": usage}}),
        json!({"model": "qwen3-coder-plus", "tokens": legacy}),
    ]
}

fn extract_all(usage: &Value) -> Vec<ExtractedTokenUsage> {
    let extra = wire_variants(usage);
    let extracted: Vec<_> = extra
        .iter()
        .map(|extra| extract_tokens_for_agent("qwen", extra, "Answer text.", "assistant"))
        .collect();
    for usage in &extracted[1..] {
        assert_eq!(snapshot(usage), snapshot(&extracted[0]));
    }
    extracted
}

#[test]
fn openai_responses_reasoning_subset_does_not_turn_fifteen_tokens_into_seventeen() {
    // Exact fixture from Qwen's responses-converter.test.ts: output_tokens
    // already includes output_tokens_details.reasoning_tokens.
    let recorded = json!({
        "promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15,
        "thoughtsTokenCount": 2, "cachedContentTokenCount": 1,
    });
    for usage in extract_all(&recorded) {
        assert_eq!(usage.input_tokens, Some(9));
        assert_eq!(usage.output_tokens, Some(5));
        assert_eq!(usage.cache_read_tokens, Some(1));
        assert_eq!(usage.cache_creation_tokens, None);
        assert_eq!(usage.thinking_tokens, None);
        assert_eq!(usage.total_tokens(), Some(15));
        assert_eq!(usage.data_source, TokenDataSource::Api);
        assert_eq!(usage.model_name.as_deref(), Some("qwen3-coder-plus"));
        assert_eq!(usage.provider.as_deref(), Some("unknown"));
    }
}

#[test]
fn google_separate_thoughts_require_a_reconciled_recorded_total() {
    let recorded = json!({
        "promptTokenCount": 1000, "candidatesTokenCount": 100,
        "cachedContentTokenCount": 600, "thoughtsTokenCount": 50,
        "toolUsePromptTokenCount": 20, "totalTokenCount": 1170,
    });
    for usage in extract_all(&recorded) {
        assert_eq!(usage.input_tokens, Some(420));
        assert_eq!(usage.output_tokens, Some(150));
        assert_eq!(usage.cache_read_tokens, Some(600));
        assert_eq!(usage.thinking_tokens, None);
        assert_eq!(usage.total_tokens(), Some(1170));
        assert_eq!(usage.data_source, TokenDataSource::Api);
    }
}

#[test]
fn locally_estimated_or_ambiguous_thoughts_never_increase_known_usage() {
    for recorded in [
        // The Chat converter can estimate five thinking tokens from text.
        json!({"promptTokenCount": 1, "candidatesTokenCount": 10,
               "thoughtsTokenCount": 5, "totalTokenCount": 11}),
        // A missing total cannot establish overlap, regardless of magnitude.
        json!({"promptTokenCount": 1, "candidatesTokenCount": 10,
               "thoughtsTokenCount": 50}),
        json!({"promptTokenCount": 1, "candidatesTokenCount": 10,
               "thoughtsTokenCount": 10}),
        // Do not assign the unexplained residual to output.
        json!({"promptTokenCount": 1, "candidatesTokenCount": 10,
               "thoughtsTokenCount": 5, "totalTokenCount": 999}),
        // A malformed optional component prevents complete reconciliation.
        json!({"promptTokenCount": 1, "candidatesTokenCount": 10,
               "thoughtsTokenCount": 5, "toolUsePromptTokenCount": -1,
               "totalTokenCount": 16}),
    ] {
        for usage in extract_all(&recorded) {
            assert_eq!(usage.input_tokens, Some(1));
            assert_eq!(usage.output_tokens, Some(10));
            assert_eq!(usage.thinking_tokens, None);
            assert_eq!(usage.total_tokens(), Some(11));
            assert_eq!(usage.data_source, TokenDataSource::Api);
        }
    }
}

#[test]
fn total_only_and_synthetic_auxiliary_zeroes_keep_estimation() {
    for recorded in [
        Value::Null,
        json!({}),
        json!({"totalTokenCount": 999}),
        json!({"totalTokenCount": 5, "cachedContentTokenCount": 0, "thoughtsTokenCount": 0}),
        json!({"thoughtsTokenCount": 7}),
        json!({"cachedContentTokenCount": 0, "toolUsePromptTokenCount": 0}),
        json!({"promptTokenCount": "10", "candidatesTokenCount": null}),
        json!({"promptTokenCount": -1, "candidatesTokenCount": -2, "cachedContentTokenCount": -3}),
        json!({"promptTokenCount": 0.5, "candidatesTokenCount": u64::MAX}),
    ] {
        for usage in extract_all(&recorded) {
            assert_eq!(usage.input_tokens, None);
            assert_eq!(usage.output_tokens, Some(3));
            assert_eq!(usage.cache_read_tokens, None);
            assert_eq!(usage.thinking_tokens, None);
            assert_eq!(usage.total_tokens(), Some(3));
            assert_eq!(usage.data_source, TokenDataSource::Estimated);
        }
    }
}

#[test]
fn explicit_primary_zeroes_and_partial_measured_counts_remain_api_data() {
    for (recorded, input, output, cached, total) in [
        (json!({"promptTokenCount": 0}), Some(0), None, None, 0),
        (json!({"candidatesTokenCount": 0}), None, Some(0), None, 0),
        (json!({"promptTokenCount": 80}), Some(80), None, None, 80),
        (
            json!({"candidatesTokenCount": 17}),
            None,
            Some(17),
            None,
            17,
        ),
        (
            json!({"cachedContentTokenCount": 60}),
            None,
            None,
            Some(60),
            60,
        ),
        (
            json!({"toolUsePromptTokenCount": 11}),
            Some(11),
            None,
            None,
            11,
        ),
        (
            json!({"promptTokenCount": 80, "cachedContentTokenCount": 80,
                   "candidatesTokenCount": 0, "thoughtsTokenCount": 7}),
            Some(0),
            Some(0),
            Some(80),
            80,
        ),
        // A complete prompt is required before thoughts can be reconciled.
        (
            json!({"candidatesTokenCount": 3, "thoughtsTokenCount": 7,
                "totalTokenCount": 10}),
            None,
            Some(3),
            None,
            3,
        ),
    ] {
        for usage in extract_all(&recorded) {
            assert_eq!(usage.input_tokens, input);
            assert_eq!(usage.output_tokens, output);
            assert_eq!(usage.cache_read_tokens, cached);
            assert_eq!(usage.total_tokens(), Some(total));
            assert_eq!(usage.thinking_tokens, None);
            assert_eq!(usage.data_source, TokenDataSource::Api);
        }
    }
}

#[test]
fn invalid_cache_and_checked_overflow_preserve_independent_valid_counts() {
    for usage in extract_all(&json!({
        "promptTokenCount": 10, "cachedContentTokenCount": 20,
        "candidatesTokenCount": 3, "toolUsePromptTokenCount": 2,
    })) {
        assert_eq!(usage.input_tokens, Some(12));
        assert_eq!(usage.cache_read_tokens, None);
        assert_eq!(usage.output_tokens, Some(3));
        assert_eq!(usage.total_tokens(), Some(15));
    }
    for usage in extract_all(&json!({
        "promptTokenCount": i64::MAX, "toolUsePromptTokenCount": 1,
        "candidatesTokenCount": 3, "thoughtsTokenCount": 7, "totalTokenCount": 10,
    })) {
        assert_eq!(usage.input_tokens, None);
        assert_eq!(usage.output_tokens, Some(3));
        assert_eq!(usage.total_tokens(), Some(3));
    }
    for usage in extract_all(&json!({
        "promptTokenCount": 0, "candidatesTokenCount": i64::MAX,
        "thoughtsTokenCount": 1, "totalTokenCount": 0,
    })) {
        assert_eq!(usage.output_tokens, Some(i64::MAX));
        assert_eq!(usage.total_tokens(), Some(i64::MAX));
    }
}

#[test]
fn native_and_compact_model_and_tool_counts_survive_api_and_estimated_paths() {
    let raw = json!({
        "model": "gpt-5", "message": {"parts": [
            {"text": "Answer text."},
            {"functionCall": {"id": "one", "name": "read_file", "args": {"path": "main.rs"}}},
            {"functionCall": {"name": "run_shell_command", "args": {"command": "pwd"}}},
            {"functionCall": {"name": " "}}, {"functionCall": {"name": 7}},
            {"functionResponse": {"name": "not_a_call"}}, null,
        ]},
    });
    let compact = json!({"cass": {"model": "gpt-5", "tool_call_count": 2}});
    for recorded in [
        Value::Null,
        json!({"promptTokenCount": 10, "candidatesTokenCount": 5}),
    ] {
        let mut raw = raw.clone();
        let mut compact = compact.clone();
        raw["usageMetadata"] = recorded.clone();
        compact["cass"]["usage"] = recorded;
        let raw_usage = extract_tokens_for_agent("qwen", &raw, "Answer text.", "assistant");
        let compact_usage = extract_tokens_for_agent("qwen", &compact, "Answer text.", "assistant");
        assert_eq!(snapshot(&raw_usage), snapshot(&compact_usage));
        assert_eq!(raw_usage.model_name.as_deref(), Some("gpt-5"));
        assert_eq!(raw_usage.provider.as_deref(), Some("openai"));
        assert!(raw_usage.has_tool_calls);
        assert_eq!(raw_usage.tool_call_count, 2);
    }
    let user = extract_tokens_for_agent("qwen", &raw, "Question", "user");
    assert_eq!(user.input_tokens, Some(2));
    assert_eq!(user.output_tokens, None);
    assert_eq!(user.data_source, TokenDataSource::Estimated);
}
