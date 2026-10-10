//! Native Gemini usage must survive replay and compact metadata unchanged.
//!
//! Wire fields follow google-gemini/gemini-cli at
//! 9b6e0265d16bbd29ca51e33c9e0c01dc4cec5e83, specifically
//! packages/core/src/services/chatRecordingService.ts and chatRecordingTypes.ts.
#![cfg(feature = "connectors")]

use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

use franken_agent_detection::token_extraction::extract_tokens_for_agent;
use franken_agent_detection::{
    Connector, ExtractedTokenUsage, GeminiConnector, NormalizedConversation, Origin, Platform,
    ScanContext, ScanRoot, SourceCompletion, SourceScanHooks, TokenDataSource,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const COMPACT_THRESHOLD: u64 = 32 * 1024 * 1024;

const fn padding() -> [u8; 8192] {
    let mut bytes = [b' '; 8192];
    bytes[8191] = b'\n';
    bytes
}

fn extract(tokens: Value) -> ExtractedTokenUsage {
    let mut extra = json!({"model": "gemini-2.5-pro"});
    extra["tokens"] = tokens;
    extract_tokens_for_agent("gemini", &extra, "Answer text.", "assistant")
}

fn snapshot(usage: &ExtractedTokenUsage) -> Value {
    json!({
        "input": usage.input_tokens, "output": usage.output_tokens,
        "cached": usage.cache_read_tokens, "cache_creation": usage.cache_creation_tokens,
        "thoughts": usage.thinking_tokens, "total": usage.total_tokens(),
        "model": usage.model_name, "provider": usage.provider,
        "source": usage.data_source.as_str(),
    })
}

fn native_tokens() -> Value {
    json!({"input": 1000, "output": 100, "cached": 600,
           "thoughts": 50, "tool": 20, "total": 1170})
}

#[test]
fn public_extractor_counts_cached_input_thoughts_and_tool_input_once() {
    let usage = extract(native_tokens());
    assert_eq!(usage.input_tokens, Some(420));
    assert_eq!(usage.output_tokens, Some(150));
    assert_eq!(usage.cache_read_tokens, Some(600));
    assert_eq!(usage.cache_creation_tokens, None);
    assert_eq!(usage.thinking_tokens, Some(50));
    assert_eq!(usage.total_tokens(), Some(1170));
    assert_eq!(usage.data_source, TokenDataSource::Api);
    assert_eq!(usage.model_name.as_deref(), Some("gemini-2.5-pro"));
    assert_eq!(usage.provider.as_deref(), Some("google"));
}

#[test]
fn partial_and_explicit_zero_counts_are_api_data() {
    for (tokens, input, output, cached, thoughts, total) in [
        (json!({"input": 0}), Some(0), None, None, None, 0),
        (json!({"output": 0}), None, Some(0), None, None, 0),
        (json!({"cached": 0}), None, None, Some(0), None, 0),
        (json!({"input": 80}), Some(80), None, None, None, 80),
        (json!({"output": 30}), None, Some(30), None, None, 30),
        (json!({"cached": 60}), None, None, Some(60), None, 60),
        (json!({"thoughts": 7}), None, Some(7), None, Some(7), 7),
        (json!({"tool": 11}), Some(11), None, None, None, 11),
        (
            json!({"input": 80, "cached": 80, "output": 0}),
            Some(0),
            Some(0),
            Some(80),
            None,
            80,
        ),
    ] {
        let usage = extract(tokens);
        assert_eq!(usage.input_tokens, input);
        assert_eq!(usage.output_tokens, output);
        assert_eq!(usage.cache_read_tokens, cached);
        assert_eq!(usage.thinking_tokens, thoughts);
        assert_eq!(usage.total_tokens(), Some(total));
        assert_eq!(usage.data_source, TokenDataSource::Api);
    }
}

#[test]
fn missing_malformed_and_total_only_usage_keep_the_estimation_fallback() {
    for tokens in [
        Value::Null,
        json!({}),
        json!([]),
        json!({"total": 999}),
        json!({"input": "100", "output": null, "cached": false}),
        json!({"input": -1, "output": -2, "thoughts": -3, "tool": -4, "cached": -5}),
        json!({"input": 0.5, "output": u64::MAX}),
    ] {
        let usage = extract(tokens);
        assert_eq!(usage.input_tokens, None);
        assert_eq!(usage.output_tokens, Some(3));
        assert_eq!(usage.cache_read_tokens, None);
        assert_eq!(usage.thinking_tokens, None);
        assert_eq!(usage.data_source, TokenDataSource::Estimated);
        assert_eq!(usage.model_name.as_deref(), Some("gemini-2.5-pro"));
    }
    let no_usage = extract_tokens_for_agent(
        "gemini",
        &json!({"model": "gemini-2.5-pro"}),
        "Answer text.",
        "assistant",
    );
    assert_eq!(snapshot(&no_usage), snapshot(&extract(Value::Null)));
}

#[test]
fn invalid_cache_splits_and_overflow_do_not_invent_api_counts() {
    let invalid_cache = extract(json!({
        "input": 10, "cached": 20, "output": 3, "tool": 2, "total": 999,
    }));
    assert_eq!(invalid_cache.input_tokens, Some(12));
    assert_eq!(invalid_cache.cache_read_tokens, None);
    assert_eq!(invalid_cache.output_tokens, Some(3));
    assert_eq!(invalid_cache.total_tokens(), Some(15));
    assert_eq!(invalid_cache.data_source, TokenDataSource::Api);

    let input_overflow = extract(json!({"input": i64::MAX, "tool": 1, "output": 3}));
    assert_eq!(input_overflow.input_tokens, None);
    assert_eq!(input_overflow.output_tokens, Some(3));
    assert_eq!(input_overflow.total_tokens(), Some(3));
    let output_overflow = extract(json!({"input": 7, "output": i64::MAX, "thoughts": 1}));
    assert_eq!(output_overflow.input_tokens, Some(7));
    assert_eq!(output_overflow.output_tokens, None);
    assert_eq!(output_overflow.total_tokens(), Some(7));

    let partial = extract(json!({"input": "malformed", "output": 17, "cached": -3}));
    assert_eq!(partial.input_tokens, None);
    assert_eq!(partial.output_tokens, Some(17));
    assert_eq!(partial.cache_read_tokens, None);
    assert_eq!(partial.data_source, TokenDataSource::Api);
}

#[test]
fn model_aliases_and_nonassistant_estimation_remain_supported() {
    for mut extra in [
        json!({"model": "gemini-2.5-pro"}),
        json!({"cass": {"model": "gemini-2.5-pro"}}),
        json!({"message": {"model": "gemini-2.5-pro"}}),
        json!({"modelConfig": {"modelName": "gemini-2.5-pro"}}),
        json!({"modelType": "gemini-2.5-pro"}),
        json!({"modelID": "gemini-2.5-pro"}),
    ] {
        extra["tokens"] = native_tokens();
        let assistant = extract_tokens_for_agent("gemini", &extra, "Answer text.", "assistant");
        assert_eq!(assistant.model_name.as_deref(), Some("gemini-2.5-pro"));
        assert_eq!(assistant.provider.as_deref(), Some("google"));
        assert_eq!(assistant.total_tokens(), Some(1170));
        let user = extract_tokens_for_agent("gemini", &extra, "Question", "user");
        assert_eq!(user.input_tokens, Some(2));
        assert_eq!(user.output_tokens, None);
        assert_eq!(user.data_source, TokenDataSource::Estimated);
    }
}

fn header() -> Value {
    json!({"sessionId": "usage-session", "projectHash": "usage-project"})
}

fn reply(id: &str, content: &str, tokens: Value) -> Value {
    let mut record = json!({"id": id, "type": "gemini", "content": content,
                            "model": "gemini-2.5-pro"});
    record["tokens"] = tokens;
    record
}

struct Fixture {
    _dir: TempDir,
    path: PathBuf,
    ctx: ScanContext,
    prefix: Vec<u8>,
    size: u64,
}

impl Fixture {
    fn new(records: &[Value], legacy: bool, size: Option<u64>) -> Self {
        let dir = TempDir::new().unwrap();
        let extension = if legacy { "json" } else { "jsonl" };
        let path = dir
            .path()
            .join("copied-project/chats/session-usage")
            .with_extension(extension);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut prefix = Vec::new();
        if legacy {
            let mut session = header();
            session["messages"] = json!(records);
            serde_json::to_writer(&mut prefix, &session).unwrap();
        } else {
            writeln!(prefix, "{}", header()).unwrap();
            for record in records {
                writeln!(prefix, "{record}").unwrap();
            }
        }
        let size = size.unwrap_or_else(|| u64::try_from(prefix.len()).unwrap());
        let mut remaining = usize::try_from(size).unwrap() - prefix.len();
        let mut writer = BufWriter::new(fs::File::create(&path).unwrap());
        writer.write_all(&prefix).unwrap();
        let padding = padding();
        while remaining > 0 {
            let len = remaining.min(padding.len());
            writer.write_all(&padding[..len]).unwrap();
            remaining -= len;
        }
        writer.flush().unwrap();
        let root = ScanRoot::remote(
            path.clone(),
            Origin::remote_with_host("gemini-usage-copy", "source-host"),
            Some(Platform::Linux),
        );
        let ctx = ScanContext::with_roots(dir.path().join("unrelated"), vec![root], None);
        Self {
            _dir: dir,
            path,
            ctx,
            prefix,
            size,
        }
    }

    fn scan(&self) -> NormalizedConversation {
        let before = fs::metadata(&self.path).unwrap();
        let connector = GeminiConnector::new();
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
            serde_json::to_value(&collected).unwrap(),
            serde_json::to_value(&streamed).unwrap()
        );
        let mut bounded = Vec::new();
        let mut completions = Vec::new();
        connector
            .scan_with_source_boundaries(
                &self.ctx,
                &mut SourceScanHooks {
                    should_scan_source: None,
                    on_source_complete: Some(&mut |completion: &SourceCompletion| {
                        completions.push(completion.clone());
                        Ok(())
                    }),
                },
                &mut |conversation| {
                    bounded.push(conversation);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(&collected).unwrap(),
            serde_json::to_value(&bounded).unwrap()
        );
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].conversations_emitted, 1);
        assert_eq!(completions[0].source.source_path, self.path);
        assert_eq!(completions[0].source.origin, self.ctx.scan_roots[0].origin);
        assert_eq!(
            fs::metadata(&self.path).unwrap().modified().unwrap(),
            before.modified().unwrap()
        );
        assert_eq!(fs::metadata(&self.path).unwrap().len(), self.size);
        let mut reader = BufReader::new(fs::File::open(&self.path).unwrap());
        let mut actual = vec![0; self.prefix.len()];
        reader.read_exact(&mut actual).unwrap();
        assert_eq!(actual, self.prefix);
        let expected_padding = padding();
        let mut padding = [0; 8192];
        let mut remaining = usize::try_from(self.size).unwrap() - self.prefix.len();
        while remaining > 0 {
            let len = remaining.min(padding.len());
            reader.read_exact(&mut padding[..len]).unwrap();
            assert_eq!(&padding[..len], &expected_padding[..len]);
            remaining -= len;
        }
        assert_eq!(reader.read(&mut padding).unwrap(), 0);
        collected.into_iter().next().unwrap()
    }
}

fn extracted_messages(conversation: &NormalizedConversation) -> Vec<Value> {
    conversation
        .messages
        .iter()
        .map(|message| {
            snapshot(&extract_tokens_for_agent(
                "gemini",
                &message.extra,
                &message.content,
                &message.role,
            ))
        })
        .collect()
}

#[test]
fn legacy_json_and_jsonl_keep_exact_usage_on_thought_and_tool_turns() {
    let mut thoughts = reply("thought", "", native_tokens());
    thoughts["thoughts"] = json!([{"subject": "Plan", "description": "Inspect the code"}]);
    let mut tools = reply("tool", "", native_tokens());
    tools["toolCalls"] = json!([{"id": "call", "name": "read_file", "args": {"path": "main.rs"}}]);
    let records = [thoughts, tools];
    for legacy in [true, false] {
        let fixture = Fixture::new(&records, legacy, None);
        let conversation = fixture.scan();
        assert_eq!(conversation.messages.len(), 2);
        assert!(conversation.messages[0].content.starts_with("[Thinking]"));
        assert!(
            conversation.messages[1]
                .content
                .starts_with("[Tool: read_file]")
        );
        assert_eq!(conversation.messages[1].invocations.len(), 1);
        assert_eq!(
            extracted_messages(&conversation),
            vec![snapshot(&extract(native_tokens())); 2]
        );
    }
}

#[test]
fn replay_counts_final_usage_once_and_keeps_distinct_identical_replies() {
    let draft = reply(
        "reply",
        "Draft",
        json!({"input": 100, "output": 3, "total": 103}),
    );
    let final_reply = reply("reply", "Same answer", native_tokens());
    let separate_reply = reply("separate", "Same answer", native_tokens());
    let fixture = Fixture::new(
        &[draft, final_reply.clone(), final_reply, separate_reply],
        false,
        None,
    );
    let conversation = fixture.scan();
    assert_eq!(conversation.messages.len(), 2);
    assert_eq!(conversation.messages[0].extra["id"], "reply");
    assert_eq!(conversation.messages[1].extra["id"], "separate");
    assert_eq!(
        conversation.messages[0].content,
        conversation.messages[1].content
    );
    let usages = extracted_messages(&conversation);
    assert_eq!(usages, vec![snapshot(&extract(native_tokens())); 2]);
    let total: i64 = usages
        .iter()
        .map(|usage| usage["total"].as_i64().unwrap())
        .sum();
    assert_eq!(total, 2340);
}

#[test]
fn real_compaction_boundary_preserves_usage_and_only_scalar_token_metadata() {
    let mut complete = native_tokens();
    complete["unknown_large_field"] = json!({"payload": "x".repeat(64 * 1024)});
    let counts = [
        complete,
        json!({"input": 0, "output": 0, "cached": 0, "thoughts": 0, "tool": 0, "total": 0}),
        json!({"input": 80, "cached": 20}),
        json!({"input": 10, "cached": 20, "output": 3}),
        json!({"input": "malformed", "output": 17, "tool": -1}),
        json!({"thoughts": 7}),
        json!({"total": 999}),
        Value::Null,
    ];
    let records: Vec<_> = counts
        .iter()
        .enumerate()
        .map(|(index, tokens)| reply(&format!("reply-{index}"), "Answer text.", tokens.clone()))
        .collect();
    let expected: Vec<_> = counts
        .iter()
        .map(|tokens| snapshot(&extract(tokens.clone())))
        .collect();
    for size in [
        COMPACT_THRESHOLD - 1,
        COMPACT_THRESHOLD,
        COMPACT_THRESHOLD + 1,
    ] {
        let fixture = Fixture::new(&records, false, Some(size));
        let conversation = fixture.scan();
        assert_eq!(conversation.messages.len(), records.len());
        assert_eq!(extracted_messages(&conversation), expected);
        for (normalized, raw) in conversation.messages.iter().zip(&records) {
            assert_eq!(normalized.content, "Answer text.");
            if size < COMPACT_THRESHOLD {
                assert_eq!(&normalized.extra, raw);
            } else {
                let compact = normalized.extra.as_object().unwrap();
                assert!(compact.keys().all(|key| key == "model" || key == "tokens"));
                if let Some(tokens) = compact.get("tokens") {
                    for (key, count) in tokens.as_object().unwrap() {
                        assert!(
                            ["input", "output", "cached", "thoughts", "tool", "total"]
                                .contains(&key.as_str())
                        );
                        assert!(count.as_i64().is_some_and(|count| count >= 0));
                    }
                }
                assert!(serde_json::to_vec(compact).unwrap().len() < 256);
            }
        }
        if size >= COMPACT_THRESHOLD {
            assert_eq!(conversation.messages[0].extra["tokens"], native_tokens());
            assert!(conversation.messages[7].extra.get("tokens").is_none());
        }
    }
}
