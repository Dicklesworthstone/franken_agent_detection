//! Regression coverage for Antigravity's per-step API usage and tool-only
//! planner records, using the payload shapes reported in GH #37.
#![cfg(feature = "connectors")]

use std::fs;

use franken_agent_detection::{
    AntigravityConnector, Connector, ExtractedTokenUsage, NormalizedConversation,
    NormalizedMessage, ScanContext, ScanRoot, TokenDataSource, extract_antigravity_tokens,
    extract_tokens_for_agent,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn scan(records: &[Value]) -> NormalizedConversation {
    let directory = TempDir::new().unwrap();
    let logs = directory
        .path()
        .join("brain/11111111-2222-4333-8444-555555555555/.system_generated/logs");
    fs::create_dir_all(&logs).unwrap();
    let transcript = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(logs.join("transcript.jsonl"), transcript).unwrap();
    let context = ScanContext::with_roots(
        directory.path().join("unrelated"),
        vec![ScanRoot::local(directory.path().to_path_buf())],
        None,
    );
    let mut conversations = AntigravityConnector::new().scan(&context).unwrap();
    assert_eq!(conversations.len(), 1);
    conversations.pop().unwrap()
}

fn message_usage(message: &NormalizedMessage) -> ExtractedTokenUsage {
    extract_tokens_for_agent(
        "antigravity",
        &message.extra,
        &message.content,
        &message.role,
    )
}

const fn counters(usage: &ExtractedTokenUsage) -> [Option<i64>; 5] {
    [
        usage.input_tokens,
        usage.output_tokens,
        usage.cache_read_tokens,
        usage.cache_creation_tokens,
        usage.thinking_tokens,
    ]
}

#[test]
fn scan_keeps_tool_only_planner_and_usage_only_checkpoint_counts() {
    let conversation = scan(&[
        json!({
            "step_index": 0, "source": "USER", "type": "USER_INPUT",
            "content": "Inspect the file.",
        }),
        json!({
            "step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "status": "DONE", "model": "gemini-4-neon-high",
            "input_tokens": 2517, "cache_read_tokens": 12725, "output_tokens": 717,
            "tool_calls": [{"id": "read-1", "name": "read_file", "args": {"Path": "/tmp/code.rs"}}],
        }),
        json!({
            "step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "status": "DONE", "model": "claude-sonnet-4-5", "input_tokens": 0,
            "output_tokens": 0,
        }),
        json!({
            "step_index": 428, "source": "SYSTEM", "type": "CHECKPOINT",
            "status": "DONE", "input_tokens": 6982, "cache_read_tokens": 508_361,
            "output_tokens": 5673,
        }),
    ]);
    assert_eq!(conversation.messages.len(), 4);
    assert_eq!(conversation.metadata["model"], "gemini-4-neon-high");
    let planner = &conversation.messages[1];
    assert_eq!(planner.role, "assistant");
    assert!(planner.content.is_empty());
    assert_eq!(planner.invocations.len(), 1);
    assert_eq!(planner.invocations[0].name, "read_file");
    assert_eq!(planner.invocations[0].call_id.as_deref(), Some("read-1"));
    assert_eq!(
        planner.invocations[0].arguments,
        Some(json!({"Path": "/tmp/code.rs"}))
    );
    let usage = message_usage(planner);
    assert_eq!(
        counters(&usage),
        [Some(2517), Some(717), Some(12725), None, None]
    );
    assert_eq!(usage.model_name.as_deref(), Some("gemini-4-neon-high"));
    assert_eq!(usage.provider.as_deref(), Some("google"));
    assert_eq!(usage.data_source, TokenDataSource::Api);
    assert!(usage.has_tool_calls);
    assert_eq!(usage.tool_call_count, 1);
    assert_eq!(usage.total_tokens(), Some(15_959));

    let zero = message_usage(&conversation.messages[2]);
    assert_eq!(zero.model_name.as_deref(), Some("claude-sonnet-4-5"));
    assert_eq!(zero.provider.as_deref(), Some("anthropic"));
    assert_eq!(zero.data_source, TokenDataSource::Api);
    assert_eq!(zero.total_tokens(), Some(0));
    assert!(!zero.has_tool_calls);

    let checkpoint = &conversation.messages[3];
    assert_eq!(checkpoint.role, "system");
    assert!(checkpoint.content.is_empty());
    let usage = message_usage(checkpoint);
    assert_eq!(
        counters(&usage),
        [Some(6982), Some(5673), Some(508_361), None, None]
    );
    assert_eq!(usage.data_source, TokenDataSource::Api);
    assert_eq!(usage.total_tokens(), Some(521_016));
    assert_eq!(usage.tool_call_count, 0);
}

#[test]
fn raw_and_normalized_usage_preserve_all_buckets_without_double_counting_reasoning() {
    let counts = json!({
        "input_tokens": 10, "output_tokens": 20, "cache_read_tokens": 100,
        "cache_write_tokens": 30, "reasoning_tokens": 5,
    });
    let normalized = json!({"model": "gemini-4-neon-high", "usage": counts});
    for extra in [counts, normalized] {
        let usage = extract_antigravity_tokens(&extra);
        assert_eq!(
            counters(&usage),
            [Some(10), Some(20), Some(100), Some(30), Some(5)]
        );
        assert_eq!(usage.data_source, TokenDataSource::Api);
        assert_eq!(usage.total_tokens(), Some(160));
    }
}

#[test]
fn each_partial_or_zero_api_count_survives_content_estimation() {
    for (index, key) in [
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "reasoning_tokens",
    ]
    .into_iter()
    .enumerate()
    {
        for count in [0, 7] {
            let mut extra = json!({"usage": {}});
            extra["usage"][key] = json!(count);
            let usage =
                extract_tokens_for_agent("antigravity", &extra, "Some response text", "assistant");
            let mut expected = [None; 5];
            expected[index] = Some(count);
            assert_eq!(counters(&usage), expected, "{key}={count}");
            assert_eq!(usage.data_source, TokenDataSource::Api, "{key}={count}");
        }
    }
}

#[test]
fn invalid_api_counts_are_not_reported_or_substituted_for_valid_partial_counts() {
    for invalid in [
        Value::Null,
        json!(false),
        json!(-1),
        json!(1.5),
        json!("3"),
        json!(u64::MAX),
    ] {
        let counts = json!({
            "input_tokens": invalid, "output_tokens": invalid,
            "cache_read_tokens": invalid, "cache_write_tokens": invalid,
            "reasoning_tokens": invalid,
        });
        for extra in [counts.clone(), json!({"usage": counts})] {
            let raw = extract_antigravity_tokens(&extra);
            assert_eq!(counters(&raw), [None; 5], "{extra}");
            assert_eq!(raw.data_source, TokenDataSource::Estimated);
            let fallback = extract_tokens_for_agent("antigravity", &extra, "12345678", "assistant");
            assert_eq!(counters(&fallback), [None, Some(2), None, None, None]);
            assert_eq!(fallback.data_source, TokenDataSource::Estimated);
        }
    }
    let partial = extract_antigravity_tokens(&json!({
        "input_tokens": -1, "output_tokens": 0, "cache_read_tokens": 200,
    }));
    assert_eq!(counters(&partial), [None, Some(0), Some(200), None, None]);
    assert_eq!(partial.data_source, TokenDataSource::Api);
}

#[test]
fn nested_usage_is_authoritative_and_legacy_counter_aliases_remain_readable() {
    let usage = extract_antigravity_tokens(&json!({
        "input_tokens": 999, "output_tokens": 999,
        "usage": {"input_tokens": 3, "cache_creation_tokens": 4, "thinking_tokens": 2},
    }));
    assert_eq!(counters(&usage), [Some(3), None, None, Some(4), Some(2)]);
    let canonical = extract_antigravity_tokens(&json!({
        "cache_write_tokens": 0, "cache_creation_tokens": 4,
        "reasoning_tokens": 0, "thinking_tokens": 2,
    }));
    assert_eq!(counters(&canonical), [None, None, None, Some(0), Some(0)]);
    let raw = extract_antigravity_tokens(&json!({"usage": null, "input_tokens": 3}));
    assert_eq!(raw.input_tokens, Some(3));
}

#[test]
fn missing_usage_preserves_legacy_metadata_and_tool_counts_during_estimation() {
    let extra = json!({
        "model": " ",
        "cass": {"model": " Gemini 2.5 Pro ", "provider": "google", "tool_call_count": 2},
    });
    let usage = extract_tokens_for_agent("antigravity", &extra, "12345678", "assistant");
    assert_eq!(usage.model_name.as_deref(), Some("Gemini 2.5 Pro"));
    assert_eq!(usage.provider.as_deref(), Some("google"));
    assert_eq!(usage.output_tokens, Some(2));
    assert_eq!(usage.data_source, TokenDataSource::Estimated);
    assert_eq!(usage.tool_call_count, 2);
    assert!(usage.has_tool_calls);
    let legacy = extract_tokens_for_agent(
        "antigravity",
        &json!({"agy_type": "RUN_COMMAND"}),
        "done",
        "tool",
    );
    assert_eq!(legacy.tool_call_count, 1);
    assert!(legacy.has_tool_calls);
    assert_eq!(legacy.data_source, TokenDataSource::Estimated);
}

#[test]
fn structured_calls_are_counted_and_compact_counts_remain_authoritative() {
    let mut extra = json!({
        "tool_calls": [
            {"name": "read_file"}, {"tool_name": "run_command"},
            {"function": {"name": "search"}}, {"name": " "},
            {"function": {"arguments": "{}"}}, null, 7,
        ],
    });
    let raw = extract_antigravity_tokens(&extra);
    assert_eq!(raw.tool_call_count, 3);
    assert!(raw.has_tool_calls);

    extra["agy_type"] = json!("RUN_COMMAND");
    extra["cass"] = json!({"tool_call_count": 0});
    let zero = extract_tokens_for_agent("antigravity", &extra, "done", "tool");
    assert_eq!(zero.tool_call_count, 0);
    assert!(!zero.has_tool_calls);

    extra["cass"]["tool_call_count"] = json!(u64::MAX);
    let large = extract_antigravity_tokens(&extra);
    assert_eq!(large.tool_call_count, u32::MAX);
    assert!(large.has_tool_calls);
}

#[test]
fn raw_calls_use_valid_aliases_and_count_each_named_identity_once() {
    let calls = json!([
        // An invalid entry must not reserve the ID of a later valid call.
        {"id": "read-1", "name": null},
        {"id": " ", "call_id": " read-1 ", "name": " ", "tool_name": " read_file "},
        {"tool_call_id": "read-1", "function": {"name": "read_file"}},
        {"id": "run-2", "name": false, "tool_name": null, "function": {"name": "run_command"}},
        // ID-less repeated calls are independent, even with identical inputs.
        {"id": "", "name": "read_file", "args": {"Path": "/synthetic/a.rs"}},
        {"id": "", "name": "read_file", "args": {"Path": "/synthetic/a.rs"}},
        {"name": null}, null, 5,
    ]);
    let raw = extract_antigravity_tokens(&json!({"tool_calls": calls}));
    assert_eq!(raw.tool_call_count, 4);
    assert!(raw.has_tool_calls);

    let conversation = scan(&[json!({
        "step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE",
        "tool_calls": calls,
    })]);
    let normalized = &conversation.messages[0];
    assert_eq!(normalized.invocations.len(), 4);
    assert_eq!(
        message_usage(normalized).tool_call_count,
        raw.tool_call_count
    );
    assert_eq!(normalized.invocations[0].name, "read_file");
    assert_eq!(normalized.invocations[0].call_id.as_deref(), Some("read-1"));
    assert_eq!(normalized.invocations[1].name, "run_command");
    assert_eq!(normalized.invocations[1].call_id.as_deref(), Some("run-2"));
    assert!(
        normalized.invocations[2..]
            .iter()
            .all(|call| call.call_id.is_none())
    );
}

#[test]
fn mixed_model_calls_results_and_compaction_conserve_api_and_invocation_totals() {
    let conversation = scan(&[
        json!({
            "step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT",
            "status": "DONE", "created_at": "2026-11-23T14:57:40Z",
            "content": "<USER_REQUEST>Inspect and verify the example.</USER_REQUEST>\n<USER_SETTINGS_CHANGE>The user changed setting `Model Selection` from None to Legacy Display Model.</USER_SETTINGS_CHANGE>",
        }),
        json!({
            "step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "status": "DONE", "created_at": "2026-11-23T14:57:41Z",
            "model": "gemini-4-neon-high", "input_tokens": 10, "output_tokens": 20,
            "cache_read_tokens": 100, "cache_write_tokens": 30, "reasoning_tokens": 5,
            "tool_calls": [
                {"id": "read-1", "name": "read_file", "args": {"Path": "/synthetic/a.rs"}},
                {"id": "read-2", "name": "read_file", "args": {"Path": "/synthetic/b.rs"}},
            ],
        }),
        json!({
            "step_index": 2, "source": "MODEL", "type": "VIEW_FILE",
            "status": "DONE", "created_at": "2026-11-23T14:57:42Z", "content": "first result",
            "tool_calls": [{"id": "read-1", "name": "read_file", "args": {"Path": "/synthetic/a.rs"}}],
        }),
        json!({
            "step_index": 3, "source": "MODEL", "type": "VIEW_FILE",
            "status": "DONE", "created_at": "2026-11-23T14:57:42Z", "content": "second result",
            "tool_calls": [{"id": "read-2", "name": "read_file", "args": {"Path": "/synthetic/b.rs"}}],
        }),
        json!({
            "step_index": 4, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "status": "DONE", "created_at": "2026-11-23T14:57:43Z", "content": "Run the checks.",
            "model": "claude-sonnet-4-5", "input_tokens": 7, "output_tokens": 11,
            "cache_read_tokens": 50, "cache_write_tokens": 0, "reasoning_tokens": 3,
            "tool_calls": [{"id": "run-3", "function": {"name": "run_command", "arguments": "{\"CommandLine\":\"cargo test\"}"}}],
        }),
        json!({
            "step_index": 5, "source": "MODEL", "type": "RUN_COMMAND",
            "status": "DONE", "created_at": "2026-11-23T14:57:44Z", "content": "checks passed",
            "tool_calls": [{"call_id": "run-3", "name": "run_command"}],
        }),
        json!({
            "step_index": 428, "source": "SYSTEM", "type": "CHECKPOINT",
            "status": "DONE", "created_at": "2026-11-23T14:59:00Z", "content": "Condensed context.",
            "input_tokens": 3, "output_tokens": 4, "cache_read_tokens": 1000,
            "cache_write_tokens": 2, "reasoning_tokens": 0,
        }),
        json!({
            "step_index": 429, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "status": "DONE", "created_at": "2026-11-23T14:59:01Z", "content": "All checks passed.",
            "model": "gemini-2.5-flash", "input_tokens": 5, "output_tokens": 6,
            "cache_read_tokens": 0,
        }),
    ]);
    assert_eq!(conversation.messages.len(), 8);
    let usages: Vec<_> = conversation.messages.iter().map(message_usage).collect();
    let api: Vec<_> = usages
        .iter()
        .filter(|usage| usage.data_source == TokenDataSource::Api)
        .collect();
    assert_eq!(api.len(), 4);
    assert_eq!(
        api.iter()
            .map(|usage| usage.total_tokens().unwrap())
            .sum::<i64>(),
        1248
    );
    assert_eq!(
        api.iter()
            .map(|usage| usage.model_name.as_deref())
            .collect::<Vec<_>>(),
        [
            Some("gemini-4-neon-high"),
            Some("claude-sonnet-4-5"),
            None,
            Some("gemini-2.5-flash"),
        ]
    );
    // A model-less checkpoint must not be assigned to the conversation's first
    // model. Its cache count is an independent bucket, and reasoning is retained
    // without being added to output a second time.
    assert_eq!(
        counters(api[2]),
        [Some(3), Some(4), Some(1000), Some(2), Some(0)]
    );
    assert_eq!(
        usages
            .iter()
            .map(|usage| usage.tool_call_count)
            .sum::<u32>(),
        3
    );
    for index in [2, 3, 5] {
        assert_eq!(conversation.messages[index].role, "tool");
        assert!(!conversation.messages[index].content.is_empty());
        assert_eq!(usages[index].tool_call_count, 0);
        assert!(!usages[index].has_tool_calls);
    }
}

#[test]
fn malformed_tool_result_arrays_do_not_create_phantom_calls() {
    let conversation = scan(&[
        json!({
            "step_index": 0, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "tool_calls": [{"id": "run-1", "name": "run_command", "args": {"CommandLine": "true"}}],
        }),
        json!({
            "step_index": 1, "source": "MODEL", "type": "RUN_COMMAND",
            "content": "command succeeded",
            "tool_calls": [null, 7, {}, {"call_id": "run-1"}],
        }),
        json!({
            "step_index": 2, "source": "MODEL", "type": "RUN_COMMAND",
            "content": "legacy result without a call identity",
            "tool_calls": [null, 7, {}],
        }),
    ]);
    let result = &conversation.messages[1];
    assert!(result.invocations.is_empty());
    assert_eq!(message_usage(result).tool_call_count, 0);
    assert_eq!(
        result.extra["cass"]["referenced_tool_call_ids"],
        json!(["run-1"])
    );
    // Retain the raw payload for hosts that persist only `extra`, while the
    // normalized count stays authoritative over the malformed array length.
    assert_eq!(result.extra["tool_calls"].as_array().unwrap().len(), 4);
    assert_eq!(result.content, "command succeeded");

    let legacy = &conversation.messages[2];
    assert_eq!(legacy.invocations.len(), 1);
    assert_eq!(legacy.invocations[0].name, "run_command");
    assert_eq!(message_usage(legacy).tool_call_count, 1);
    assert_eq!(
        conversation
            .messages
            .iter()
            .map(message_usage)
            .map(|usage| usage.tool_call_count)
            .sum::<u32>(),
        2,
    );
}

#[test]
fn top_level_result_identity_links_to_request_and_survives_extra_only_storage() {
    let conversation = scan(&[
        json!({
            "step_index": 0, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "tool_calls": [{"id": "read-1", "name": "read_file", "args": {"Path": "/synthetic/a.rs"}}],
        }),
        json!({
            "step_index": 1, "source": "MODEL", "type": "VIEW_FILE",
            "content": "read result", "tool_call_id": null, "call_id": "read-1",
        }),
        json!({
            "step_index": 2, "source": "MODEL", "type": "VIEW_FILE",
            "content": "unmatched legacy result", "tool_call_id": "", "call_id": "read-2",
        }),
    ]);
    let result = &conversation.messages[1];
    assert_eq!(message_usage(result).tool_call_count, 0);
    assert_eq!(result.extra["call_id"], "read-1");
    assert_eq!(
        result.extra["cass"]["referenced_tool_call_ids"],
        json!(["read-1"])
    );
    let unmatched = &conversation.messages[2];
    assert_eq!(message_usage(unmatched).tool_call_count, 1);
    assert_eq!(unmatched.invocations[0].call_id.as_deref(), Some("read-2"));
    assert_eq!(unmatched.extra["call_id"], "read-2");
}
