//! Native Continue IDE/CLI snapshots. Fixtures follow `continuedev/continue`
//! at `5522c6f44ca0ac3528b37244818fbfa39b5af470`, `core/util/history.ts`,
//! `core/util/messageConversion.ts`, `gui/src/redux/slices/sessionSlice.ts`, and
//! `extensions/cli/src/{services/ChatHistoryService,stream/streamChatResponse}.ts`.
#![cfg(feature = "connectors")]

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use franken_agent_detection::{
    Connector, ContinueConnector, ExtractedTokenUsage, NormalizedConversation, NormalizedMessage,
    Origin, Platform, ScanContext, ScanRoot, SourceScanHooks, TokenDataSource,
    extract_tokens_for_agent, get_connector_factories,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn snapshot(id: &str, history: Value) -> Value {
    let mut snapshot = json!({
        "sessionId": id, "title": "Continue native session", "workspaceDirectory": "/remote/project",
        "mode": "agent", "chatModelTitle": "My custom alias",
        "usage": {"promptTokens": 999_000, "completionTokens": 777_000, "totalCost": 12.5},
    });
    snapshot["history"] = history;
    snapshot
}

fn write_session(root: &Path, id: &str, history: Value) -> PathBuf {
    fs::create_dir_all(root).unwrap();
    let path = root.join(format!("{id}.json"));
    fs::write(&path, serde_json::to_vec(&snapshot(id, history)).unwrap()).unwrap();
    path
}

fn context(paths: &[PathBuf]) -> ScanContext {
    ScanContext::with_roots(
        PathBuf::from("/unused-cass-state"),
        paths
            .iter()
            .map(|path| ScanRoot::local(path.clone()))
            .collect(),
        None,
    )
}

fn scan(paths: &[PathBuf]) -> Vec<NormalizedConversation> {
    ContinueConnector::new().scan(&context(paths)).unwrap()
}

fn one(path: &Path) -> NormalizedConversation {
    let mut conversations = scan(&[path.to_path_buf()]);
    assert_eq!(conversations.len(), 1);
    conversations.pop().unwrap()
}

fn usage(message: &NormalizedMessage) -> ExtractedTokenUsage {
    extract_tokens_for_agent("continue", &message.extra, &message.content, &message.role)
}

fn tool_call(id: &str) -> Value {
    json!({"id": id, "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"src/main.rs\"}"}})
}

fn tool_state(id: &str, output: &str) -> Value {
    json!({"toolCallId": id, "toolCall": tool_call(id), "status": "done", "parsedArgs": {"path":"src/main.rs"},
        "output": [{"content": output, "name": "Tool Result", "description": "result"}]})
}

#[test]
fn continue_cli_tools_usage_and_session_totals_remain_separate() {
    let fixture = TempDir::new().unwrap();
    let file = write_session(
        fixture.path(),
        "cli",
        json!([
            {"message": {"role":"user", "content":"Read the implementation"}, "contextItems": []},
            {"message": {"role":"assistant", "id":"reply-1", "content":"", "toolCalls":[tool_call("call-1")],
                "usage":{"prompt_tokens":100,"completion_tokens":20,"model":"gpt-4o","cost_cents":1}},
                "toolCallStates":[tool_state("call-1", "fn main() {}")], "contextItems": []},
            {"message": {"role":"assistant", "id":"reply-2", "content":"The file is minimal.",
                "usage":{"prompt_tokens":130,"completion_tokens":10,"model":"gpt-4o"}}}
        ]),
    );
    let conversation = one(&file);
    assert_eq!(conversation.agent_slug, "continue");
    assert_eq!(conversation.external_id.as_deref(), Some("cli"));
    assert_eq!(
        conversation.title.as_deref(),
        Some("Continue native session")
    );
    assert_eq!(
        conversation.workspace,
        Some(PathBuf::from("/remote/project"))
    );
    assert_eq!(conversation.metadata["mode"], "agent");
    assert_eq!(conversation.metadata["chat_model_title"], "My custom alias");
    assert_eq!(
        conversation.metadata["session_usage"]["completionTokens"],
        777_000
    );
    assert_eq!(
        conversation
            .messages
            .iter()
            .map(|m| m.role.as_str())
            .collect::<Vec<_>>(),
        ["user", "assistant", "tool", "assistant"]
    );
    let call = &conversation.messages[1];
    assert_eq!(call.content, "[Tool: read_file]");
    assert_eq!(call.invocations.len(), 1);
    assert_eq!(
        call.invocations[0].arguments,
        Some(json!({"path":"src/main.rs"}))
    );
    assert_eq!(call.invocations[0].call_id.as_deref(), Some("call-1"));
    assert_eq!(call.extra["message"]["id"], "reply-1");
    assert_eq!(conversation.messages[2].content, "fn main() {}");
    assert_eq!(
        conversation.messages[2].extra["message"]["toolCallId"],
        "call-1"
    );
    assert_eq!(usage(call).model_name.as_deref(), Some("gpt-4o"));
    assert_eq!(usage(call).tool_call_count, 1);
    assert!(usage(call).has_tool_calls);
    let total: i64 = conversation
        .messages
        .iter()
        .map(usage)
        .filter(|u| u.data_source == TokenDataSource::Api)
        .filter_map(|u| u.total_tokens())
        .sum();
    assert_eq!(total, 260);
    assert!(conversation.started_at.is_none());
    assert!(conversation.ended_at.is_none());
    assert!(conversation.messages.iter().all(|m| m.created_at.is_none()));
}

#[test]
fn continue_ide_tool_results_are_not_duplicated_from_tool_state() {
    let fixture = TempDir::new().unwrap();
    let file = write_session(
        fixture.path(),
        "ide",
        json!([
            {"message":{"role":"assistant","id":"assistant-id","content":"Reading","toolCalls":[tool_call("one")]},
             "toolCallStates":[tool_state("one", "duplicate output")]},
            {"message":{"role":"tool","id":"result-id","toolCallId":"one","content":"actual output"},
             "contextItems":[{"content":"duplicate output"}]},
            {"message":{"role":"assistant","content":"Done"}}
        ]),
    );
    let conversation = one(&file);
    assert_eq!(conversation.messages.len(), 3);
    assert_eq!(conversation.messages[0].invocations.len(), 1);
    assert_eq!(conversation.messages[1].content, "actual output");
    assert_eq!(conversation.messages[1].extra["message"]["id"], "result-id");
    assert!(
        !serde_json::to_string(&conversation)
            .unwrap()
            .contains("duplicate output")
    );
}

#[test]
fn continue_reasoning_tool_only_usage_only_and_image_only_rows_survive() {
    let fixture = TempDir::new().unwrap();
    let file = write_session(
        fixture.path(),
        "kinds",
        json!([
            {"message":{"role":"user","content":[{"type":"imageUrl","imageUrl":{"url":"data:image/png;base64,SECRET"}}]}},
            {"message":{"role":"thinking","content":"Consider the options","metadata":{"responsesOutputItemId":"rs_1"}}},
            {"message":{"role":"assistant","content":""},"reasoning":{"text":"Separate reasoning","startAt":1_791_700_000_000_i64}},
            {"message":{"role":"assistant","content":""},"toolCallStates":[tool_state("only-state","output")]},
            {"message":{"role":"assistant","content":"","usage":{"completion_tokens":9}}}
        ]),
    );
    let conversation = one(&file);
    assert_eq!(conversation.messages.len(), 6);
    assert_eq!(conversation.messages[0].content, "[Image]");
    assert_eq!(
        conversation.messages[1].content,
        "[Thinking] Consider the options"
    );
    assert_eq!(conversation.messages[1].role, "assistant");
    assert_eq!(
        conversation.messages[1].extra["message"]["role"],
        "thinking"
    );
    assert_eq!(
        conversation.messages[1].extra["message"]["metadata"]["responsesOutputItemId"],
        "rs_1"
    );
    assert_eq!(
        conversation.messages[2].content,
        "[Thinking] Separate reasoning"
    );
    assert_eq!(conversation.messages[3].invocations.len(), 1);
    assert_eq!(conversation.messages[4].role, "tool");
    assert_eq!(usage(&conversation.messages[5]).output_tokens, Some(9));
    assert_eq!(
        usage(&conversation.messages[5]).data_source,
        TokenDataSource::Api
    );
}

#[test]
fn continue_content_blocks_and_equal_usage_do_not_collapse_distinct_requests() {
    let fixture = TempDir::new().unwrap();
    let file = write_session(
        fixture.path(),
        "identities",
        json!([
            {"message":{"role":"assistant","id":"a","content":[{"type":"text","text":"first block"},{"type":"text","text":"second block"}],
                "usage":{"promptTokens":30,"completionTokens":7},"metadata":{"responsesOutputItemIds":["msg_a","fc_a"]}}},
            {"message":{"role":"assistant","id":"b","content":"another request","usage":{"promptTokens":30,"completionTokens":7}}},
            {"message":{"role":"assistant","content":"without an id","usage":{"promptTokens":30,"completionTokens":7}}}
        ]),
    );
    let conversation = one(&file);
    assert_eq!(conversation.messages.len(), 3);
    assert_eq!(
        conversation.messages[0].content,
        "first block\nsecond block"
    );
    assert_eq!(conversation.messages[0].extra["message"]["id"], "a");
    assert_eq!(conversation.messages[1].extra["message"]["id"], "b");
    assert!(
        conversation.messages[2].extra["message"]
            .get("id")
            .is_none()
    );
    assert_eq!(
        conversation.messages[0].extra["message"]["metadata"]["responsesOutputItemIds"],
        json!(["msg_a", "fc_a"])
    );
    assert_eq!(
        conversation
            .messages
            .iter()
            .map(usage)
            .filter_map(|u| u.total_tokens())
            .sum::<i64>(),
        111
    );
}

#[test]
fn continue_cache_bearing_input_is_not_mixed_with_incompatible_provider_totals() {
    let fixture = TempDir::new().unwrap();
    let file = write_session(
        fixture.path(),
        "cache",
        json!([
            {"message":{"role":"assistant","content":"IDE","usage":{"promptTokens":10,"completionTokens":2,
                "promptTokensDetails":{"cachedTokens":90,"cacheWriteTokens":5}}}},
            {"message":{"role":"assistant","content":"CLI","usage":{"prompt_tokens":100,"completion_tokens":3,
                "prompt_tokens_details":{"cached_tokens":90}}}},
            {"message":{"role":"assistant","content":"No cache","usage":{"promptTokens":100,"completionTokens":4,
                "promptTokensDetails":{"cachedTokens":0,"cacheWriteTokens":0}}}}
        ]),
    );
    let conversation = one(&file);
    for message in &conversation.messages[..2] {
        let usage = usage(message);
        assert_eq!(usage.data_source, TokenDataSource::Api);
        assert!(usage.input_tokens.is_none());
        assert!(usage.cache_read_tokens.is_none());
        assert!(usage.cache_creation_tokens.is_none());
    }
    assert_eq!(usage(&conversation.messages[0]).output_tokens, Some(2));
    assert_eq!(usage(&conversation.messages[1]).output_tokens, Some(3));
    assert_eq!(usage(&conversation.messages[2]).input_tokens, Some(100));
    assert_eq!(
        conversation.messages[0].extra["message"]["usage"]["promptTokensDetails"]["cachedTokens"],
        90
    );
}

#[test]
fn continue_invalid_or_missing_counts_are_never_fabricated_from_session_totals() {
    let fixture = TempDir::new().unwrap();
    let invalid = [
        json!(-1),
        json!(1.5),
        json!("100"),
        json!(null),
        json!(u64::MAX),
        json!({"unexpected":999}),
    ];
    let history: Vec<_> = invalid.into_iter().map(|count| json!({"message":{"role":"assistant","content":"",
        "usage":{"prompt_tokens":count,"completion_tokens":count,"promptTokens":500,"completionTokens":400}}})).collect();
    let file = write_session(fixture.path(), "invalid-counts", json!(history));
    let conversation = one(&file);
    assert_eq!(conversation.messages.len(), 6);
    for message in &conversation.messages {
        let usage = usage(message);
        assert_eq!(usage.data_source, TokenDataSource::Estimated);
        assert!(usage.total_tokens().is_none() || usage.total_tokens() == Some(0));
    }
    let file = write_session(
        fixture.path(),
        "missing-counts",
        json!([
            {"message":{"role":"assistant","content":"Ordinary prose"}},
            {"message":{"role":"user","content":"User","usage":{"prompt_tokens":1000,"completion_tokens":1000}}},
            {"message":{"role":"thinking","content":"Reasoning","usage":{"prompt_tokens":1000,"completion_tokens":1000}}}
        ]),
    );
    assert!(
        one(&file)
            .messages
            .iter()
            .map(usage)
            .all(|u| u.data_source == TokenDataSource::Estimated)
    );
}

#[test]
fn continue_zero_usage_is_exact_and_partial_invalid_usage_keeps_valid_output() {
    let fixture = TempDir::new().unwrap();
    let file = write_session(
        fixture.path(),
        "zeros",
        json!([
            {"message":{"role":"assistant","content":"","usage":{"prompt_tokens":0,"completion_tokens":0}}},
            {"message":{"role":"assistant","content":"","usage":{"promptTokens":-2,"completionTokens":5}}}
        ]),
    );
    let conversation = one(&file);
    assert_eq!(usage(&conversation.messages[0]).total_tokens(), Some(0));
    assert_eq!(
        usage(&conversation.messages[0]).data_source,
        TokenDataSource::Api
    );
    assert_eq!(usage(&conversation.messages[1]).input_tokens, None);
    assert_eq!(usage(&conversation.messages[1]).output_tokens, Some(5));
}

#[test]
fn continue_large_context_and_arguments_do_not_expand_retained_metadata() {
    let fixture = TempDir::new().unwrap();
    let large = "DO_NOT_COPY_".repeat(200_000);
    let call = json!({"id":"large-call","type":"function","function":{"name":"write_file","arguments":large}});
    let file = write_session(
        fixture.path(),
        "large",
        json!([
            {"message":{"role":"user","content":[{"type":"text","text":"Inspect attachment"},{"type":"imageUrl","imageUrl":{"url":large}}]},
                "contextItems":[{"content":large}],"editorState":{"text":large}},
            {"message":{"role":"assistant","id":"large-reply","content":"Reply","toolCalls":[call],
                "usage":{"prompt_tokens":10,"completion_tokens":2,"arbitrary":large}},
                "promptLogs":[{"modelTitle":"Display alias","modelProvider":"openai","prompt":large,"completion":large}],
                "toolCallStates":[{"toolCallId":"large-call","toolCall":call,"status":"done","parsedArgs":{"text":large},
                    "tool":{"description":large},"output":[{"content":"actual output","name":"result"}]}]}
        ]),
    );
    assert!(fs::metadata(&file).unwrap().len() > 10 * 1024 * 1024);
    let conversation = one(&file);
    let encoded = serde_json::to_string(&conversation).unwrap();
    assert!(encoded.len() < 5000, "retained {} bytes", encoded.len());
    assert!(!encoded.contains("DO_NOT_COPY_"));
    assert_eq!(conversation.messages[1].invocations.len(), 1);
    assert!(conversation.messages[1].invocations[0].arguments.is_none());
    assert_eq!(
        conversation.messages[1].extra["message"]["id"],
        "large-reply"
    );
    assert_eq!(usage(&conversation.messages[1]).total_tokens(), Some(12));
    assert_eq!(conversation.messages[2].content, "actual output");
    assert!(usage(&conversation.messages[1]).model_name.is_none());
}

#[test]
fn continue_scopes_discovery_streaming_and_provenance_agree() {
    let fixture = TempDir::new().unwrap();
    let global = fixture.path().join("profile/.continue");
    let sessions = global.join("sessions");
    let file = write_session(
        &sessions,
        "scope",
        json!([{"message":{"role":"user","content":"scoped"}}]),
    );
    let bytes = fs::read(&file).unwrap();
    let modified = fs::metadata(&file).unwrap().modified().unwrap();
    for root in [
        fixture.path().join("profile"),
        global,
        sessions,
        file.clone(),
    ] {
        let ctx = ScanContext::with_roots(
            PathBuf::from("/unused"),
            vec![
                ScanRoot::remote(
                    root,
                    Origin::remote_with_host("continue-host", "host.example"),
                    Some(Platform::Linux),
                )
                .with_rewrite("/remote", "/mapped"),
            ],
            None,
        );
        let connector = ContinueConnector::new();
        let discovered = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].source_path, file.canonicalize().unwrap());
        assert_eq!(discovered[0].origin.source_id, "continue-host");
        let collected = connector.scan(&ctx).unwrap();
        let mut streamed = Vec::new();
        connector
            .scan_with_callback(&ctx, &mut |c| {
                streamed.push(c);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            serde_json::to_value(&collected).unwrap(),
            serde_json::to_value(&streamed).unwrap()
        );
        assert_eq!(
            collected[0].workspace,
            Some(PathBuf::from("/mapped/project"))
        );
        assert_eq!(
            collected[0].metadata["cass"]["workspace_original"],
            "/remote/project"
        );
        assert_eq!(
            collected[0].metadata["origin"]["source_id"],
            "continue-host"
        );
        assert_eq!(collected[0].messages[0].idx, 0);
    }
    assert_eq!(fs::read(&file).unwrap(), bytes);
    assert_eq!(fs::metadata(&file).unwrap().modified().unwrap(), modified);
}

#[test]
fn continue_exact_file_never_imports_siblings_or_sessions_index() {
    let fixture = TempDir::new().unwrap();
    let store = fixture.path().join("renamed-session-store");
    let selected = write_session(
        &store,
        "selected",
        json!([{"message":{"role":"user","content":"one"}}]),
    );
    write_session(
        &store,
        "sibling",
        json!([{"message":{"role":"user","content":"two"}}]),
    );
    fs::write(
        store.join("sessions.json"),
        r#"[{"sessionId":"selected","dateCreated":"1791700000000"}]"#,
    )
    .unwrap();
    write_session(
        &store.join("archive"),
        "archived",
        json!([{"message":{"role":"user","content":"archive"}}]),
    );
    assert_eq!(one(&selected).external_id.as_deref(), Some("selected"));
    assert_eq!(scan(std::slice::from_ref(&store)).len(), 2);
    assert!(scan(&[store.join("sessions.json")]).is_empty());
    assert_eq!(
        ContinueConnector::new()
            .discover_source_files(&context(&[store]))
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn continue_overlapping_roots_do_not_repeat_usage() {
    let fixture = TempDir::new().unwrap();
    let store = fixture.path().join(".continue/sessions");
    let file = write_session(
        &store,
        "overlap",
        json!([{"message":{"role":"assistant","content":"one","usage":{"completion_tokens":11}}}]),
    );
    let mut roots = vec![
        fixture.path().to_path_buf(),
        fixture.path().join(".continue"),
        store,
        file,
    ];
    #[cfg(unix)]
    {
        let alias = fixture.path().join("session-alias");
        std::os::unix::fs::symlink(fixture.path().join(".continue/sessions"), &alias).unwrap();
        roots.push(alias);
    }
    assert_eq!(
        ContinueConnector::new()
            .discover_source_files(&context(&roots))
            .unwrap()
            .len(),
        1
    );
    let conversations = scan(&roots);
    assert_eq!(conversations.len(), 1);
    assert_eq!(usage(&conversations[0].messages[0]).output_tokens, Some(11));
}

#[test]
fn continue_incremental_filter_matches_discovery_and_boundaries() {
    let fixture = TempDir::new().unwrap();
    for (id, seconds) in [("old", 1000), ("new", 2000)] {
        let file = write_session(
            fixture.path(),
            id,
            json!([{"message":{"role":"user","content":id}}]),
        );
        fs::File::options()
            .write(true)
            .open(file)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(seconds)))
            .unwrap();
    }
    let mut ctx = context(&[fixture.path().to_path_buf()]);
    ctx.since_ts = Some(1_500_000);
    let connector = ContinueConnector::new();
    let sources = connector.discover_source_files(&ctx).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].source_path.file_stem().unwrap(), "new");
    let mut completions = Vec::new();
    let mut complete = |c: &franken_agent_detection::SourceCompletion| {
        completions.push(c.clone());
        Ok(())
    };
    let mut emitted = Vec::new();
    connector
        .scan_with_source_boundaries(
            &ctx,
            &mut SourceScanHooks {
                should_scan_source: None,
                on_source_complete: Some(&mut complete),
            },
            &mut |c| {
                emitted.push(c);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].external_id.as_deref(), Some("new"));
    assert_eq!(completions[0].source, sources[0]);
}

#[test]
fn continue_source_callbacks_observe_skip_then_delivery_then_completion() {
    let fixture = TempDir::new().unwrap();
    let good = write_session(
        fixture.path(),
        "good",
        json!([{"message":{"role":"user","content":"hello"}}]),
    );
    fs::write(fixture.path().join("skipped.json"), "not JSON").unwrap();
    let events = RefCell::new(Vec::new());
    let ctx = context(&[fixture.path().to_path_buf()]);
    let connector = ContinueConnector::new();
    let sources = connector.discover_source_files(&ctx).unwrap();
    let mut should_scan = |source: &franken_agent_detection::DiscoveredSourceFile| {
        events.borrow_mut().push(format!(
            "check:{}",
            source.source_path.file_stem().unwrap().to_string_lossy()
        ));
        source.source_path == good
    };
    let mut complete = |completion: &franken_agent_detection::SourceCompletion| {
        assert_eq!(completion.source, sources[0]);
        assert_eq!(completion.conversations_emitted, 1);
        assert!(completion.required_sidecars.is_empty());
        events.borrow_mut().push("complete".into());
        Ok(())
    };
    connector
        .scan_with_source_boundaries(
            &ctx,
            &mut SourceScanHooks {
                should_scan_source: Some(&mut should_scan),
                on_source_complete: Some(&mut complete),
            },
            &mut |_| {
                events.borrow_mut().push("emit".into());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        *events.borrow(),
        ["check:good", "emit", "complete", "check:skipped"]
    );
    assert!(connector.supports_streaming_scan());
    assert!(connector.supports_source_boundaries());
}

#[test]
fn continue_parse_failures_never_complete_or_hide_healthy_sources() {
    let fixture = TempDir::new().unwrap();
    write_session(
        fixture.path(),
        "healthy",
        json!([{"message":{"role":"user","content":"healthy"}}]),
    );
    for (id, value) in [
        (
            "foreign",
            json!({"messages":[{"role":"user","content":"not Continue"}]}),
        ),
        (
            "wrong-id",
            snapshot(
                "some-other-id",
                json!([{"message":{"role":"user","content":"wrong"}}]),
            ),
        ),
        ("future", {
            let mut v = snapshot("future", json!([]));
            v["version"] = json!(2);
            v
        }),
        (
            "legacy",
            json!({"session_id":"legacy","history":[{"content":"old schema"}]}),
        ),
    ] {
        fs::write(
            fixture.path().join(format!("{id}.json")),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }
    fs::write(fixture.path().join("truncated.json"), "{\"sessionId\":").unwrap();
    let connector = ContinueConnector::new();
    let mut completed = Vec::new();
    let mut complete = |c: &franken_agent_detection::SourceCompletion| {
        completed.push(c.source.source_path.clone());
        Ok(())
    };
    let mut delivered = Vec::new();
    connector
        .scan_with_source_boundaries(
            &context(&[fixture.path().to_path_buf()]),
            &mut SourceScanHooks {
                should_scan_source: None,
                on_source_complete: Some(&mut complete),
            },
            &mut |c| {
                delivered.push(c);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(delivered.len(), 1);
    assert_eq!(completed, std::slice::from_ref(&delivered[0].source_path));
}

#[test]
fn continue_delivery_failure_or_changed_snapshot_cannot_authorize_resume() {
    let fixture = TempDir::new().unwrap();
    let file = write_session(
        fixture.path(),
        "changing",
        json!([{"message":{"role":"user","content":"before"}}]),
    );
    let ctx = context(std::slice::from_ref(&file));
    let connector = ContinueConnector::new();
    let mut count = 0;
    let mut complete = |_: &franken_agent_detection::SourceCompletion| {
        count += 1;
        Ok(())
    };
    let result = connector.scan_with_source_boundaries(
        &ctx,
        &mut SourceScanHooks {
            should_scan_source: None,
            on_source_complete: Some(&mut complete),
        },
        &mut |_| anyhow::bail!("delivery cancelled"),
    );
    assert!(result.is_err());
    assert_eq!(count, 0);
    let mut complete = |_: &franken_agent_detection::SourceCompletion| {
        count += 1;
        Ok(())
    };
    connector
        .scan_with_source_boundaries(
            &ctx,
            &mut SourceScanHooks {
                should_scan_source: None,
                on_source_complete: Some(&mut complete),
            },
            &mut |_| {
                fs::write(&file, "{rewritten}").unwrap();
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn continue_empty_valid_source_completes_without_inventing_messages() {
    let fixture = TempDir::new().unwrap();
    let file = write_session(fixture.path(), "empty", json!([]));
    let mut completions = Vec::new();
    let mut complete = |c: &franken_agent_detection::SourceCompletion| {
        completions.push(c.clone());
        Ok(())
    };
    ContinueConnector::new()
        .scan_with_source_boundaries(
            &context(&[file]),
            &mut SourceScanHooks {
                should_scan_source: None,
                on_source_complete: Some(&mut complete),
            },
            &mut |_| anyhow::bail!("empty source must not emit"),
        )
        .unwrap();
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0].conversations_emitted, 0);
}

#[test]
fn continue_factory_is_registered_once_with_base_connector_features() {
    let factories = get_connector_factories();
    let matched: Vec<_> = factories
        .iter()
        .filter(|(slug, _)| *slug == "continue")
        .collect();
    assert_eq!(matched.len(), 1);
    assert!(matched[0].1().supports_streaming_scan());
    assert!(matched[0].1().supports_source_boundaries());
}
