//! Canonical Qwen subagent histories through public connector APIs.
//!
//! Producer: `QwenLM/qwen-code@a8990042e648a7807e251d99b3d37c0ee8c16100`,
//! `packages/core/src/agents/agent-transcript.ts` (paths, identity, bootstrap,
//! round usage and tools) and `agents/runtime/agent-core.ts` (one final usage
//! observation per completed model round). These are independent fixture
//! records following the producer, not exported user histories.
#![cfg(feature = "connectors")]

use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use franken_agent_detection::token_extraction::{TokenDataSource, extract_tokens_for_agent};
use franken_agent_detection::{
    Connector, DiscoveredSourceRole, NormalizedConversation, Origin, Platform, QwenConnector,
    ScanContext, ScanRoot,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const PARENT: &str = "47c09e1e-9b87-401c-bdeb-6c357ab925f9";
const AGENT: &str = "explore-1";
const COMPACT_THRESHOLD: u64 = 32 * 1024 * 1024;

fn row(id: &str, previous: Option<&str>, role: &str, parts: &[Value]) -> Value {
    json!({
        "uuid": id, "parentUuid": previous, "sessionId": PARENT,
        "type": role, "timestamp": "2026-10-11T10:00:00Z",
        "cwd": "/home/remote/project", "version": "0.19.0",
        "agentId": AGENT, "agentName": "explore", "isSidechain": true,
        "message": { "role": if role == "assistant" { "model" } else { "user" }, "parts": parts },
    })
}

fn text_row(id: &str, previous: Option<&str>, role: &str, text: &str) -> Value {
    row(id, previous, role, &[json!({ "text": text })])
}

fn round(id: &str, previous: Option<&str>, number: u64) -> Value {
    let mut record = row(
        id,
        previous,
        "assistant",
        &[
            json!({ "thought": true, "text": "Inspect the implementation" }),
            json!({ "text": "Found the relevant source" }),
        ],
    );
    record["agentRunId"] = "native-run-1".into();
    record["agentRound"] = number.into();
    record["usageMetadata"] = json!({
        "promptTokenCount": 100, "candidatesTokenCount": 20,
        "cachedContentTokenCount": 30, "totalTokenCount": 120,
    });
    record
}

fn basic_records() -> Vec<Value> {
    vec![
        text_row("user", None, "user", "Inspect the source"),
        round("reply", Some("user"), 1),
    ]
}

fn encode(records: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for record in records {
        writeln!(&mut bytes, "{record}").unwrap();
    }
    bytes
}

struct Fixture {
    home: TempDir,
    runtime: PathBuf,
    transcript: PathBuf,
}

impl Fixture {
    fn new(records: &[Value]) -> Self {
        let home = TempDir::new().unwrap();
        let runtime = home.path().join(".qwen");
        let transcript = runtime.join(format!(
            "projects/project/subagents/{PARENT}/agent-{AGENT}.jsonl"
        ));
        fs::create_dir_all(transcript.parent().unwrap()).unwrap();
        fs::write(&transcript, encode(records)).unwrap();
        Self {
            home,
            runtime,
            transcript,
        }
    }

    fn metadata(&self) -> PathBuf {
        self.transcript.with_extension("meta.json")
    }

    fn write_metadata(&self, value: &Value) {
        fs::write(self.metadata(), serde_json::to_vec(value).unwrap()).unwrap();
    }

    fn context(&self, path: &Path) -> ScanContext {
        ScanContext::with_roots(
            self.home.path().join("unused-state"),
            vec![ScanRoot::remote(
                path.to_path_buf(),
                Origin::remote_with_host("qwen-subagent-fixture", "worker-one"),
                Some(Platform::Linux),
            )],
            None,
        )
    }

    fn scan(&self) -> Vec<NormalizedConversation> {
        QwenConnector::new()
            .scan(&self.context(&self.transcript))
            .unwrap()
    }
}

fn api_total(conversations: &[NormalizedConversation]) -> i64 {
    conversations
        .iter()
        .flat_map(|conversation| &conversation.messages)
        .filter_map(|message| {
            let usage =
                extract_tokens_for_agent("qwen", &message.extra, &message.content, &message.role);
            (usage.data_source == TokenDataSource::Api)
                .then(|| usage.total_tokens())
                .flatten()
        })
        .sum()
}

fn message_ids(conversation: &NormalizedConversation) -> Vec<&str> {
    conversation
        .messages
        .iter()
        .map(|message| {
            message.extra["uuid"]
                .as_str()
                .or_else(|| message.extra["cass"]["message_id"].as_str())
                .unwrap()
        })
        .collect()
}

fn metadata() -> Value {
    json!({
        "agentId": AGENT, "parentSessionId": PARENT, "parentAgentId": "lead-worker",
        "agentType": "explore", "description": "Find the ingestion gap", "toolUseId": "launch-call",
        "createdAt": "2026-10-11T09:00:00Z", "lastUpdatedAt": "2026-10-11T10:00:00Z",
        "status": "completed", "model": "qwen3-coder-plus",
        "stats": { "totalTokens": 9_999_999, "outputTokens": 8_888_888, "toolUses": 1, "durationMs": 5000 },
        "persistedCliFlags": { "irrelevant": "do not copy launch configuration" },
    })
}

#[test]
fn canonical_subagents_are_discovered_and_scanned_at_every_native_scope() {
    let fixture = Fixture::new(&basic_records());
    fixture.write_metadata(&metadata());
    let connector = QwenConnector::new();
    for scope in [
        fixture.home.path().to_path_buf(),
        fixture.runtime.clone(),
        fixture.runtime.join("projects"),
        fixture.runtime.join("projects/project"),
        fixture.runtime.join("projects/project/subagents"),
        fixture.transcript.parent().unwrap().to_path_buf(),
        fixture.transcript.clone(),
    ] {
        let ctx = fixture.context(&scope);
        let sources = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(sources.len(), 2, "scope={scope:?}");
        assert_eq!(sources[0].source_path, fixture.transcript);
        assert_eq!(sources[0].role, DiscoveredSourceRole::PrimarySessionLog);
        assert!(sources[0].required_for_reconstruction);
        assert_eq!(sources[1].source_path, fixture.metadata());
        assert_eq!(sources[1].role, DiscoveredSourceRole::MetadataSidecar);
        assert!(!sources[1].required_for_reconstruction);
        for source in &sources {
            assert_eq!(source.provider_slug, "qwen");
            assert_eq!(source.origin, ctx.scan_roots[0].origin);
            assert_eq!(source.platform, Some(Platform::Linux));
            assert!(source.size_bytes.is_some());
            assert!(source.modified_at_ms.is_some());
        }
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1, "scope={scope:?}");
        let conversation = &conversations[0];
        assert_eq!(
            conversation.external_id,
            Some(format!("subagent:[\"{PARENT}\",\"{AGENT}\"]"))
        );
        assert_eq!(conversation.source_path, fixture.transcript);
        assert_eq!(
            conversation.workspace.as_deref(),
            Some(Path::new("/home/remote/project"))
        );
        assert_eq!(
            conversation.title.as_deref(),
            Some("Find the ingestion gap")
        );
        assert_eq!(conversation.metadata["format"], "subagent-jsonl");
        assert_eq!(conversation.metadata["parent_session_id"], PARENT);
        assert_eq!(conversation.metadata["agent_id"], AGENT);
        assert_eq!(conversation.metadata["parent_agent_id"], "lead-worker");
        assert_eq!(conversation.metadata["tool_use_id"], "launch-call");
        assert_eq!(conversation.metadata["model"], "qwen3-coder-plus");
        assert_eq!(message_ids(conversation), ["user", "reply"]);
        assert_eq!(api_total(&conversations), 120);
        assert!(conversation.metadata.get("stats").is_none());
        assert!(
            !conversation
                .metadata
                .to_string()
                .contains("persistedCliFlags")
        );
        if scope != fixture.home.path() {
            let scoped = ScanContext::local_default(scope.clone(), None);
            assert_eq!(
                serde_json::to_value(connector.scan(&scoped).unwrap()).unwrap(),
                serde_json::to_value(&conversations).unwrap()
            );
        }
    }
}

#[test]
fn round_usage_is_counted_once_without_bootstrap_stream_or_terminal_summary_usage() {
    let mut bootstrap = row("bootstrap", None, "system", &[]);
    bootstrap.as_object_mut().unwrap().remove("message");
    bootstrap["subtype"] = "agent_bootstrap".into();
    bootstrap["systemPayload"] = json!({ "kind": "fork", "history": [
        { "role": "model", "parts": [{ "text": "Copied parent answer" }], "usageMetadata": { "promptTokenCount": 100_000_000 } },
    ] });
    let call = row(
        "call",
        Some("first-round"),
        "assistant",
        &[
            json!({ "functionCall": { "id": "call-1", "name": "read_file", "args": { "absolute_path": "/home/remote/project/src/lib.rs" } } }),
        ],
    );
    let result = row(
        "result",
        Some("call"),
        "tool_result",
        &[
            json!({ "functionResponse": { "id": "call-1", "name": "read_file", "response": { "output": "pub fn detect() {}" }, "parts": [{ "inlineData": { "data": "binary-hidden" } }] } }),
        ],
    );
    let fixture = Fixture::new(&[
        bootstrap,
        text_row("user", Some("bootstrap"), "user", "Inspect the source"),
        round("first-round", Some("user"), 1),
        call,
        result,
        round("second-round", Some("result"), 2),
    ]);
    fixture.write_metadata(&metadata());
    fs::write(
        fixture.transcript.with_extension("jsonl.stream"),
        encode(&[round("stream-copy", None, 2)]),
    )
    .unwrap();
    let conversations = QwenConnector::new()
        .scan(&fixture.context(&fixture.runtime))
        .unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(
        message_ids(&conversations[0]),
        ["user", "first-round", "call", "result", "second-round"]
    );
    assert_eq!(api_total(&conversations), 240);
    assert_eq!(
        conversations[0].messages[2].invocations[0].name,
        "read_file"
    );
    assert_eq!(
        conversations[0].messages[2].invocations[0]
            .call_id
            .as_deref(),
        Some("call-1")
    );
    assert_eq!(conversations[0].messages[3].role, "tool");
    assert!(
        conversations[0].messages[3]
            .content
            .contains("pub fn detect() {}")
    );
    assert!(
        conversations[0].messages[1]
            .content
            .contains("[Thinking] Inspect the implementation")
    );
    let visible = serde_json::to_string(&conversations).unwrap();
    assert!(!visible.contains("Copied parent answer"));
    assert!(!visible.contains("stream-copy"));
    assert!(
        !conversations[0].messages[3]
            .content
            .contains("binary-hidden")
    );
    let discovered = QwenConnector::new()
        .discover_source_files(&fixture.context(&fixture.runtime))
        .unwrap();
    assert_eq!(discovered.len(), 2);
}

#[test]
fn parent_and_sibling_agents_keep_distinct_identity_and_usage() {
    let fixture = Fixture::new(&basic_records());
    let other = fixture.transcript.with_file_name("agent-review-2.jsonl");
    let mut sibling = basic_records();
    for record in &mut sibling {
        record["agentId"] = "review-2".into();
    }
    fs::write(&other, encode(&sibling)).unwrap();
    let parent_file = fixture
        .runtime
        .join(format!("projects/project/chats/{PARENT}.jsonl"));
    fs::create_dir_all(parent_file.parent().unwrap()).unwrap();
    let mut parent_records = basic_records();
    for record in &mut parent_records {
        let object = record.as_object_mut().unwrap();
        object.remove("agentId");
        object.remove("agentName");
        object.remove("isSidechain");
    }
    fs::write(&parent_file, encode(&parent_records)).unwrap();
    let conversations = QwenConnector::new()
        .scan(&fixture.context(&fixture.runtime))
        .unwrap();
    assert_eq!(conversations.len(), 3);
    let ids: std::collections::HashSet<_> = conversations
        .iter()
        .map(|c| c.external_id.as_deref().unwrap())
        .collect();
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(PARENT));
    assert_eq!(api_total(&conversations), 360);
    let parent = conversations
        .iter()
        .find(|c| c.source_path == parent_file)
        .unwrap();
    assert_eq!(parent.metadata["format"], "jsonl");
    assert!(parent.metadata.get("parent_session_id").is_none());
    assert_eq!(parent.messages[1].extra, parent_records[1]);
}

#[test]
fn resumed_subagent_replays_the_native_parent_branch() {
    let mut retry = row("retry", Some("user"), "system", &[]);
    retry.as_object_mut().unwrap().remove("message");
    retry["subtype"] = "agent_retry".into();
    retry["systemPayload"] = json!({ "attempt": 2 });
    let fixture = Fixture::new(&[
        text_row("user", None, "user", "Inspect the source"),
        round("abandoned", Some("user"), 1),
        retry,
        round("resumed", Some("retry"), 1),
    ]);
    let conversations = fixture.scan();
    assert_eq!(message_ids(&conversations[0]), ["user", "resumed"]);
    assert_eq!(api_total(&conversations), 120);
}

#[test]
fn subagent_identity_is_collision_free_for_ids_with_delimiters_and_unicode() {
    let fixture = Fixture::new(&[]);
    let root = fixture.runtime.join("projects/project/subagents");
    // Colliding sanitized agent spellings are stored in different project
    // directories here; normalized identity still retains the original IDs.
    for (index, (parent, agent, directory, name)) in [
        ("parent:one", "worker/two", "parent_one", "worker_two"),
        ("parent", "one:worker/two", "parent", "one_worker_two"),
        ("parent:one", "worker_two", "parent_one", "worker_two"),
        (
            "parent-unicode",
            "worker-\"😀",
            "parent-unicode",
            "worker-___",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let path = root.parent().unwrap().parent().unwrap().join(format!(
            "copy-{index}/subagents/{directory}/agent-{name}.jsonl"
        ));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut records = basic_records();
        for record in &mut records {
            record["sessionId"] = parent.into();
            record["agentId"] = agent.into();
        }
        fs::write(path, encode(&records)).unwrap();
    }
    let conversations = QwenConnector::new()
        .scan(&fixture.context(&fixture.runtime))
        .unwrap();
    assert_eq!(conversations.len(), 4);
    let ids: std::collections::HashSet<_> = conversations
        .iter()
        .map(|c| c.external_id.clone())
        .collect();
    assert_eq!(ids.len(), 4);
    for conversation in &conversations {
        let id = conversation
            .external_id
            .as_deref()
            .unwrap()
            .strip_prefix("subagent:")
            .unwrap();
        let parts: Vec<String> = serde_json::from_str(id).unwrap();
        assert_eq!(
            parts[0].as_str(),
            conversation.metadata["parent_session_id"].as_str().unwrap()
        );
        assert_eq!(
            parts[1].as_str(),
            conversation.metadata["agent_id"].as_str().unwrap()
        );
    }
}

#[test]
fn malformed_lines_recover_but_inconsistent_subagent_ownership_fails_closed() {
    let fixture = Fixture::new(&basic_records());
    let mut bytes = encode(&basic_records()[..1]);
    bytes.extend_from_slice(b"{bad json\n\xff invalid UTF-8\n");
    bytes.extend(encode(&basic_records()[1..]));
    fs::write(&fixture.transcript, bytes).unwrap();
    assert_eq!(message_ids(&fixture.scan()[0]), ["user", "reply"]);
    for replacement in [json!(null), json!("different-agent"), json!(42)] {
        let mut records = basic_records();
        records[1]["agentId"] = replacement;
        fs::write(&fixture.transcript, encode(&records)).unwrap();
        assert!(fixture.scan().is_empty());
    }
    for (field, value) in [
        ("isSidechain", json!(false)),
        ("sessionId", json!("other-parent")),
    ] {
        let mut records = basic_records();
        records[1][field] = value;
        fs::write(&fixture.transcript, encode(&records)).unwrap();
        assert!(fixture.scan().is_empty());
    }
    let mut records = basic_records();
    records[0]["agentId"] = "same/id".into();
    records[1]["agentId"] = "same_id".into();
    let collided = fixture.transcript.with_file_name("agent-same_id.jsonl");
    fs::write(&collided, encode(&records)).unwrap();
    assert!(
        QwenConnector::new()
            .scan(&fixture.context(&collided))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn missing_invalid_or_foreign_metadata_does_not_erase_self_identifying_messages() {
    let fixture = Fixture::new(&basic_records());
    for contents in [
        None,
        Some("malformed json"),
        Some("null"),
        Some(
            "{\"agentId\":\"other\",\"parentSessionId\":\"other\",\"description\":\"wrong title\"}",
        ),
    ] {
        if let Some(contents) = contents {
            fs::write(fixture.metadata(), contents).unwrap();
        }
        let conversations = fixture.scan();
        assert_eq!(conversations.len(), 1);
        assert_eq!(
            conversations[0].title.as_deref(),
            Some("Inspect the source")
        );
        assert_eq!(api_total(&conversations), 120);
        assert!(conversations[0].metadata.get("model").is_none());
    }
    let oversized = File::create(fixture.metadata()).unwrap();
    oversized.set_len(1024 * 1024 + 1).unwrap();
    assert_eq!(api_total(&fixture.scan()), 120);
}

#[test]
fn sidecar_model_does_not_fabricate_per_reply_model_or_usage() {
    let mut records = basic_records();
    let mut recorded_model = round("own-model", Some("reply"), 2);
    recorded_model["model"] = "recorded-model".into();
    records.push(recorded_model);
    let fixture = Fixture::new(&records);
    fixture.write_metadata(&metadata());
    let conversations = fixture.scan();
    let first = &conversations[0].messages[1];
    let usage = extract_tokens_for_agent("qwen", &first.extra, &first.content, &first.role);
    assert_eq!(usage.model_name, None);
    assert_eq!(usage.input_tokens, Some(70));
    assert_eq!(usage.cache_read_tokens, Some(30));
    let second = &conversations[0].messages[2];
    let usage = extract_tokens_for_agent("qwen", &second.extra, &second.content, &second.role);
    assert_eq!(usage.model_name.as_deref(), Some("recorded-model"));
    assert_eq!(api_total(&conversations), 240);
}

#[test]
fn usage_only_zero_rounds_remain_explicit_api_observations() {
    let mut empty = row("zero", None, "assistant", &[]);
    empty["usageMetadata"] =
        json!({ "promptTokenCount": 0, "candidatesTokenCount": 0, "totalTokenCount": 0 });
    let fixture = Fixture::new(&[empty]);
    let conversations = fixture.scan();
    assert_eq!(conversations[0].messages.len(), 1);
    let message = &conversations[0].messages[0];
    let usage = extract_tokens_for_agent("qwen", &message.extra, &message.content, &message.role);
    assert_eq!(usage.data_source, TokenDataSource::Api);
    assert_eq!(usage.total_tokens(), Some(0));
}

#[test]
fn compaction_boundary_preserves_subagent_round_identity_and_exact_usage() {
    for length in [
        COMPACT_THRESHOLD - 1,
        COMPACT_THRESHOLD,
        COMPACT_THRESHOLD + 1,
    ] {
        let fixture = Fixture::new(&basic_records());
        let initial = fs::metadata(&fixture.transcript).unwrap().len();
        let mut file = OpenOptions::new()
            .append(true)
            .open(&fixture.transcript)
            .unwrap();
        let padding = vec![b' '; usize::try_from(length - initial - 1).unwrap()];
        file.write_all(&padding).unwrap();
        file.write_all(b"\n").unwrap();
        drop(file);
        drop(padding);
        let conversations = fixture.scan();
        assert_eq!(message_ids(&conversations[0]), ["user", "reply"]);
        assert_eq!(api_total(&conversations), 120);
        let extra = &conversations[0].messages[1].extra;
        if length >= COMPACT_THRESHOLD {
            assert!(extra.get("message").is_none());
            assert_eq!(extra["cass"]["session_id"], PARENT);
            assert_eq!(extra["cass"]["agent_id"], AGENT);
            assert_eq!(extra["cass"]["is_sidechain"], true);
            assert_eq!(extra["cass"]["agent_run_id"], "native-run-1");
            assert_eq!(extra["cass"]["agent_round"], 1);
            assert!(extra.to_string().len() < 1024);
        } else {
            assert_eq!(extra["sessionId"], PARENT);
            assert_eq!(extra["agentId"], AGENT);
            assert_eq!(extra["isSidechain"], true);
            assert_eq!(extra["agentRunId"], "native-run-1");
            assert_eq!(extra["agentRound"], 1);
        }
        assert_eq!(fs::metadata(&fixture.transcript).unwrap().len(), length);
    }
}

#[test]
fn metadata_changes_reingest_the_complete_agent_and_preserve_source_bytes_and_mtime() {
    let fixture = Fixture::new(&basic_records());
    fixture.write_metadata(&metadata());
    let past = UNIX_EPOCH + Duration::from_secs(1_000_000);
    for path in [&fixture.transcript, &fixture.metadata()] {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(past))
            .unwrap();
    }
    let mut ctx = fixture.context(&fixture.transcript);
    ctx.since_ts = Some(1_500_000_000);
    let connector = QwenConnector::new();
    assert!(connector.scan(&ctx).unwrap().is_empty());
    assert!(connector.discover_source_files(&ctx).unwrap().is_empty());
    let current = UNIX_EPOCH + Duration::from_secs(2_000_000);
    File::options()
        .write(true)
        .open(fixture.metadata())
        .unwrap()
        .set_times(FileTimes::new().set_modified(current))
        .unwrap();
    let originals: Vec<_> = [&fixture.transcript, &fixture.metadata()]
        .into_iter()
        .map(|path| {
            (
                path.clone(),
                fs::read(path).unwrap(),
                fs::metadata(path).unwrap().modified().unwrap(),
            )
        })
        .collect();
    assert_eq!(api_total(&connector.scan(&ctx).unwrap()), 120);
    assert_eq!(connector.discover_source_files(&ctx).unwrap().len(), 2);
    for (path, bytes, modified) in originals {
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), modified);
    }
}

#[test]
fn discovered_sources_reconstruct_an_unmarked_copied_store() {
    let fixture = Fixture::new(&basic_records());
    fixture.write_metadata(&metadata());
    let connector = QwenConnector::new();
    let sources = connector
        .discover_source_files(&fixture.context(&fixture.runtime))
        .unwrap();
    let exported = TempDir::new().unwrap();
    for source in sources {
        let target = exported
            .path()
            .join(source.source_path.strip_prefix(&fixture.runtime).unwrap());
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(source.source_path, target).unwrap();
    }
    let restored = connector.scan(&fixture.context(exported.path())).unwrap();
    let original = fixture.scan();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].external_id, original[0].external_id);
    assert_eq!(restored[0].metadata, original[0].metadata);
    assert_eq!(
        serde_json::to_value(&restored[0].messages).unwrap(),
        serde_json::to_value(&original[0].messages).unwrap()
    );
    assert_eq!(restored[0].title, original[0].title);
}

#[test]
fn overlapping_scopes_emit_each_physical_agent_once_and_callbacks_cancel() {
    let fixture = Fixture::new(&basic_records());
    fixture.write_metadata(&metadata());
    let mut ctx = fixture.context(&fixture.runtime);
    ctx.scan_roots
        .push(ctx.scan_roots[0].with_path(fixture.transcript.clone()));
    ctx.scan_roots
        .push(ctx.scan_roots[0].with_path(fixture.transcript.parent().unwrap().to_path_buf()));
    let connector = QwenConnector::new();
    assert_eq!(connector.scan(&ctx).unwrap().len(), 1);
    assert_eq!(connector.discover_source_files(&ctx).unwrap().len(), 2);
    assert!(connector.supports_streaming_scan());
    assert!(!connector.supports_source_boundaries());
    let mut delivered = 0;
    let result = connector.scan_with_callback(&ctx, &mut |_| {
        delivered += 1;
        anyhow::bail!("cancel subagent scan")
    });
    assert_eq!(delivered, 1);
    assert_eq!(result.unwrap_err().to_string(), "cancel subagent scan");
}

#[test]
fn explicit_missing_scopes_do_not_leak_unrelated_subagents() {
    let fixture = Fixture::new(&basic_records());
    for scope in [
        fixture.runtime.join("projects/project/subagents/missing"),
        fixture.transcript.with_file_name("agent-missing.jsonl"),
        fixture.home.path().join("other/subagents"),
    ] {
        let mut ctx = fixture.context(&scope);
        ctx.data_dir.clone_from(&fixture.runtime);
        assert!(QwenConnector::new().scan(&ctx).unwrap().is_empty());
        assert!(
            QwenConnector::new()
                .discover_source_files(&ctx)
                .unwrap()
                .is_empty()
        );
    }
}

#[cfg(unix)]
#[test]
fn ancestor_symlink_aliases_share_one_subagent_source() {
    let fixture = Fixture::new(&basic_records());
    fixture.write_metadata(&metadata());
    let alias = fixture.home.path().join("runtime-alias");
    std::os::unix::fs::symlink(&fixture.runtime, &alias).unwrap();
    let mut ctx = fixture.context(&fixture.runtime);
    ctx.scan_roots.push(ctx.scan_roots[0].with_path(alias));
    let connector = QwenConnector::new();
    assert_eq!(connector.scan(&ctx).unwrap().len(), 1);
    assert_eq!(connector.discover_source_files(&ctx).unwrap().len(), 2);
}

#[cfg(unix)]
#[test]
fn qwen_subagent_default_child() {
    let Some(expected) = std::env::var_os("FAD_QWEN_SUBAGENT_DEFAULT_EXPECTED") else {
        return;
    };
    let ctx = ScanContext::local_default(PathBuf::from("unrelated-state"), None);
    let conversations = QwenConnector::new().scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0].source_path, PathBuf::from(expected));
    assert_eq!(api_total(&conversations), 120);
}

#[cfg(unix)]
#[test]
fn default_scans_follow_home_and_runtime_override_for_subagents() {
    let fixture = Fixture::new(&basic_records());
    for configured in [false, true] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "qwen_subagent_default_child", "--nocapture"])
            .current_dir(fixture.home.path())
            .env("HOME", fixture.home.path())
            .env("USERPROFILE", fixture.home.path())
            .env_remove("QWEN_HOME")
            .env_remove("QWEN_RUNTIME_DIR")
            .env("FAD_QWEN_SUBAGENT_DEFAULT_EXPECTED", &fixture.transcript);
        if configured {
            command.env("QWEN_RUNTIME_DIR", &fixture.runtime);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "configured={configured}\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
