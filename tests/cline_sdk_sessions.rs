//! Cline SDK v1 lead-session snapshots, including legacy resume boundaries.
//! Fixtures follow `cline/cline` at `c3a40572765b76873c597247941118c1778d02c8`:
//! `sdk/packages/core/src/services/session-{artifacts,data}.ts`,
//! `sdk/packages/shared/src/llms/messages.ts` and
//! `apps/vscode/src/sdk/legacy-task-handling.ts`.
#![cfg(feature = "connectors")]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use franken_agent_detection::token_extraction::extract_tokens_for_agent;
use franken_agent_detection::{
    ClineConnector, Connector, DiscoveredSourceRole, ExtractedTokenUsage, NormalizedConversation,
    Origin, Platform, ScanContext, ScanRoot, SourceScanHooks, TokenDataSource,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const WARNING: &str = "Warning: this is a legacy conversation, which means tool names may have changed. Please use the most up-to-date tools you are aware of.";
const EXTENSION: &str = ".config/Code/User/globalStorage/saoudrizwan.claude-dev";

fn manifest(id: &str) -> Value {
    json!({
        "version": 1, "session_id": id, "source": "vscode", "pid": 123,
        "started_at": "2026-10-11T00:00:00Z", "ended_at": "2026-10-11T00:01:00Z",
        "status": "completed", "interactive": true, "provider": "anthropic",
        "model": "claude-sonnet-4", "cwd": "/remote/project", "workspace_root": "/remote/project",
        "enable_tools": true, "enable_spawn": false, "enable_teams": false,
        "prompt": "Inspect the SDK transcript", "metadata": {"title": "SDK task"},
        "messages_path": "/old-host/path/should-not-be-opened.messages.json",
    })
}

fn snapshot(id: &str, messages: Value) -> Value {
    let mut snapshot = json!({
        "version": 1, "updated_at": "2026-10-11T00:01:00Z", "agent": "lead",
        "sessionId": id, "origin": {"source": "vscode", "mode": "user", "sessionId": id},
    });
    snapshot["messages"] = messages;
    snapshot
}

fn write_json(path: &Path, value: &Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn write_sdk(home: &Path, id: &str, messages: Value) -> (PathBuf, PathBuf) {
    let task = home.join(".cline/data/sessions").join(id);
    let manifest_file = task.join(format!("{id}.json"));
    let messages_file = task.join(format!("{id}.messages.json"));
    write_json(&manifest_file, &manifest(id));
    write_json(&messages_file, &snapshot(id, messages));
    (messages_file, manifest_file)
}

fn context(paths: &[PathBuf], since: Option<i64>) -> ScanContext {
    ScanContext::with_roots(
        PathBuf::from("/unused-cass-state"),
        paths
            .iter()
            .map(|path| {
                ScanRoot::remote(
                    path.clone(),
                    Origin::remote_with_host("sdk-host", "remote.example"),
                    Some(Platform::Linux),
                )
            })
            .collect(),
        since,
    )
}

fn scan(ctx: &ScanContext) -> Vec<NormalizedConversation> {
    ClineConnector::new().scan(ctx).unwrap()
}

fn single(ctx: &ScanContext) -> NormalizedConversation {
    let mut conversations = scan(ctx);
    assert_eq!(
        conversations.len(),
        1,
        "data_dir={}, roots={:?}",
        ctx.data_dir.display(),
        ctx.scan_roots
    );
    conversations.pop().unwrap()
}

fn usage(conversation: &NormalizedConversation) -> Vec<ExtractedTokenUsage> {
    conversation
        .messages
        .iter()
        .map(|message| {
            extract_tokens_for_agent("cline", &message.extra, &message.content, &message.role)
        })
        .collect()
}

fn api_total(conversation: &NormalizedConversation) -> i64 {
    usage(conversation)
        .iter()
        .filter(|usage| usage.data_source == TokenDataSource::Api)
        .filter_map(ExtractedTokenUsage::total_tokens)
        .sum()
}

fn set_modified(path: &Path, seconds: u64) {
    fs::File::open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(seconds))
        .unwrap();
}

#[test]
#[allow(clippy::too_many_lines)]
fn sdk_native_scopes_preserve_order_roles_identifiers_tools_and_usage() {
    let root = TempDir::new().unwrap();
    let (file, meta) = write_sdk(
        root.path(),
        "sdk-native",
        json!([
            {"id":"user-a", "role":"user", "content":"Inspect the native SDK", "ts":1_760_000_000_300_i64},
            {"id":"reply-a", "role":"assistant", "ts":1_760_000_000_100_i64,
             "content":[{"type":"thinking", "thinking":"Read the source carefully", "signature":"opaque"},
                        {"type":"tool_use", "id":"tool-a", "name":"read_file", "input":{"path":"lib.rs"}}],
             "metrics":{"inputTokens":100,"outputTokens":20,"cacheReadTokens":30,"cacheWriteTokens":10},
             "modelInfo":{"id":"claude-opus-4","provider":"anthropic"}},
            {"id":"tool-result-a", "role":"user", "content":[{"type":"tool_result", "name":"read_file",
             "tool_use_id":"tool-a", "content":[{"type":"text","text":"fn sdk_history() {}"},
              {"type":"image","mediaType":"image/png","data":"IMAGE_BYTES_MUST_NOT_APPEAR"}]}]},
            {"id":"reply-b", "role":"assistant", "content":"", "metrics":{"outputTokens":0}},
        ]),
    );
    let original = fs::read(&file).unwrap();
    let original_meta = fs::read(&meta).unwrap();
    let modified = fs::metadata(&file).unwrap().modified().unwrap();
    let meta_modified = fs::metadata(&meta).unwrap().modified().unwrap();
    for path in [
        root.path().to_path_buf(),
        root.path().join(".cline"),
        root.path().join(".cline/data"),
        root.path().join(".cline/data/sessions"),
        file.parent().unwrap().to_path_buf(),
        file.clone(),
        meta.clone(),
    ] {
        for ctx in [
            context(std::slice::from_ref(&path), None),
            ScanContext::local_default(path.clone(), None),
        ] {
            let sources = ClineConnector::new().discover_source_files(&ctx).unwrap();
            assert_eq!(sources.len(), 2, "scope {path:?}");
            assert_eq!(sources[0].source_path, file);
            assert_eq!(sources[0].role, DiscoveredSourceRole::PrimarySessionLog);
            assert_eq!(sources[1].source_path, meta);
            assert_eq!(sources[1].role, DiscoveredSourceRole::MetadataSidecar);
            assert!(
                sources
                    .iter()
                    .all(|source| source.required_for_reconstruction)
            );
            if !ctx.scan_roots.is_empty() {
                assert!(
                    sources
                        .iter()
                        .all(|source| source.origin == ctx.scan_roots[0].origin)
                );
            }
            let conversation = single(&ctx);
            assert_eq!(conversation.external_id.as_deref(), Some("sdk-native"));
            assert_eq!(conversation.source_path, file);
            assert_eq!(conversation.title.as_deref(), Some("SDK task"));
            assert_eq!(
                conversation.workspace.as_deref(),
                Some(Path::new("/remote/project"))
            );
            assert_eq!(conversation.metadata["format"], "cline_sdk_v1");
            assert_eq!(conversation.messages.len(), 4);
            for (index, (message, role)) in conversation
                .messages
                .iter()
                .zip(["user", "assistant", "tool", "assistant"])
                .enumerate()
            {
                assert_eq!(message.idx, i64::try_from(index).unwrap());
                assert_eq!(message.role, role);
                assert!(message.extra["cass"]["cline_sdk"].as_bool().unwrap());
                assert_eq!(message.extra["cass"]["session_id"], "sdk-native");
                assert!(message.extra.get("content").is_none());
            }
            let reply = &conversation.messages[1];
            assert_eq!(reply.extra["cass"]["message_id"], "reply-a");
            assert_eq!(
                reply.content,
                "Read the source carefully\n[Tool: read_file]"
            );
            assert_eq!(reply.invocations.len(), 1);
            assert_eq!(reply.invocations[0].call_id.as_deref(), Some("tool-a"));
            assert_eq!(
                reply.invocations[0].arguments.as_ref().unwrap()["path"],
                "lib.rs"
            );
            assert_eq!(conversation.messages[2].content, "fn sdk_history() {}");
            let usages = usage(&conversation);
            assert_eq!(usages[1].input_tokens, Some(60));
            assert_eq!(usages[1].cache_read_tokens, Some(30));
            assert_eq!(usages[1].cache_creation_tokens, Some(10));
            assert_eq!(usages[1].output_tokens, Some(20));
            assert_eq!(usages[1].model_name.as_deref(), Some("claude-opus-4"));
            assert_eq!(usages[1].tool_call_count, 1);
            assert_eq!(usages[3].data_source, TokenDataSource::Api);
            assert_eq!(usages[3].total_tokens(), Some(0));
            assert_eq!(api_total(&conversation), 120);
        }
    }
    assert_eq!(fs::read(&file).unwrap(), original);
    assert_eq!(fs::read(&meta).unwrap(), original_meta);
    assert_eq!(fs::metadata(file).unwrap().modified().unwrap(), modified);
    assert_eq!(
        fs::metadata(meta).unwrap().modified().unwrap(),
        meta_modified
    );
}

#[test]
fn sdk_distinct_requests_and_content_blocks_do_not_repeat_usage() {
    let root = TempDir::new().unwrap();
    let (file, _) = write_sdk(
        root.path(),
        "requests",
        json!([
            {"id":"reply-one","role":"assistant","ts":100,"content":[
                {"type":"text","text":"first part"},{"type":"text","text":"second part"},
                {"type":"thinking","thinking":"reasoning part"}],
                "metrics":{"inputTokens":100,"outputTokens":20,"cacheReadTokens":30,"cacheWriteTokens":10}},
            {"id":"reply-two","role":"assistant","ts":100,"content":"same usage, distinct reply",
                "metrics":{"inputTokens":100,"outputTokens":20,"cacheReadTokens":30,"cacheWriteTokens":10}},
        ]),
    );
    let conversation = single(&context(&[file], None));
    assert_eq!(conversation.messages.len(), 2);
    assert_ne!(
        conversation.messages[0].extra["cass"]["message_id"],
        conversation.messages[1].extra["cass"]["message_id"]
    );
    assert_eq!(api_total(&conversation), 240);
}

#[test]
fn sdk_callback_routes_match_collecting_and_preserve_cancellation() {
    let root = TempDir::new().unwrap();
    let (file, _) = write_sdk(
        root.path(),
        "routes",
        json!([{"role":"user","content":"Route history"}]),
    );
    let ctx = context(&[file], None);
    let expected = scan(&ctx);
    let connector = ClineConnector::new();
    let mut callback = Vec::new();
    connector
        .scan_with_callback(&ctx, &mut |conversation| {
            callback.push(conversation);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        serde_json::to_value(&expected).unwrap(),
        serde_json::to_value(callback).unwrap()
    );
    let mut bounded = Vec::new();
    connector
        .scan_with_source_boundaries(&ctx, &mut SourceScanHooks::default(), &mut |conversation| {
            bounded.push(conversation);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        serde_json::to_value(expected).unwrap(),
        serde_json::to_value(bounded).unwrap()
    );
    assert!(connector.supports_streaming_scan());
    assert!(!connector.supports_source_boundaries());
    let error = connector
        .scan_with_callback(&ctx, &mut |_| anyhow::bail!("stop after first SDK session"))
        .unwrap_err();
    assert!(error.to_string().contains("stop after first"));
}

#[test]
fn sdk_validation_rejects_foreign_versions_mismatched_ids_and_nonlead_artifacts() {
    let root = TempDir::new().unwrap();
    let (file, meta) = write_sdk(
        root.path(),
        "validated",
        json!([{"role":"assistant","content":"Valid"}]),
    );
    let original = snapshot("validated", json!([{"role":"assistant","content":"Valid"}]));
    for (pointer, value) in [
        ("/version", json!(2)),
        ("/version", json!("1")),
        ("/sessionId", json!("foreign")),
        ("/origin/sessionId", json!("foreign")),
        ("/origin/source", json!("cli")),
        ("/agent", json!("subagent")),
        ("/agent", json!("teammate")),
        ("/messages", json!({})),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        write_json(&file, &changed);
        assert!(
            scan(&context(std::slice::from_ref(&file), None)).is_empty(),
            "{pointer}"
        );
    }
    write_json(&file, &original);
    for (pointer, value) in [
        ("/version", json!(2)),
        ("/session_id", json!("foreign")),
        ("/source", json!("cli")),
    ] {
        let mut changed = manifest("validated");
        *changed.pointer_mut(pointer).unwrap() = value;
        write_json(&meta, &changed);
        assert!(
            scan(&context(std::slice::from_ref(&file), None)).is_empty(),
            "manifest {pointer}"
        );
    }
    write_json(&meta, &manifest("validated"));
    let task = file.parent().unwrap();
    let compaction = task.join("validated.compaction.json");
    write_json(
        &compaction,
        &json!({"version":1,"messages":[{"role":"assistant","content":"Context-only replacement"}]}),
    );
    write_json(
        &task.join("child.messages.json"),
        &snapshot(
            "child",
            json!([{"role":"assistant","content":"Child result"}]),
        ),
    );
    assert_eq!(
        single(&context(&[task.to_path_buf()], None)).messages.len(),
        1
    );
    assert!(
        ClineConnector::new()
            .discover_source_files(&context(&[compaction], None))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn sdk_malformed_rows_do_not_prevent_healthy_rows_and_missing_ids_remain_missing() {
    let root = TempDir::new().unwrap();
    let (file, _) = write_sdk(
        root.path(),
        "rows",
        json!([
            null, {}, {"role":"system","content":"foreign role"}, {"role":"user","content":{}},
            {"role":"assistant","content":[]},
            {"role":"assistant","id":17,"content":"No valid identifier","metrics":{"outputTokens":3}},
            {"role":"assistant","content":"Also no identifier","metrics":{"outputTokens":3}},
            {"role":"assistant","id":"healthy","content":"Healthy row","metrics":{"outputTokens":3}},
        ]),
    );
    let conversation = single(&context(&[file], None));
    assert_eq!(conversation.messages.len(), 3);
    assert!(
        conversation.messages[0].extra["cass"]
            .get("message_id")
            .is_none()
    );
    assert!(
        conversation.messages[1].extra["cass"]
            .get("message_id")
            .is_none()
    );
    assert_eq!(api_total(&conversation), 9);
}

#[test]
fn sdk_metadata_stays_small_with_large_binary_and_provider_payloads() {
    let root = TempDir::new().unwrap();
    let payload = "BINARY_DATA".repeat(120_000);
    let (file, meta) = write_sdk(
        root.path(),
        "compact",
        json!([
            {"id":"large","role":"assistant","content":[
                {"type":"text","text":"Readable SDK answer"},
                {"type":"image","mediaType":"image/png","data":payload},
                {"type":"redacted_thinking","data":payload}],
                "metadata":{"request":payload},
                "metrics":{"inputTokens":100,"outputTokens":20,"cacheReadTokens":30,"cacheWriteTokens":10,"request":payload}},
        ]),
    );
    let mut header = manifest("compact");
    header["metadata"]["request"] = json!(payload);
    write_json(&meta, &header);
    let conversation = single(&context(&[file], None));
    let message = &conversation.messages[0];
    assert_eq!(message.content, "Readable SDK answer");
    assert!(message.extra.to_string().len() < 512);
    assert!(!message.extra.to_string().contains("BINARY_DATA"));
    assert!(conversation.metadata.to_string().len() < 256);
    assert_eq!(api_total(&conversation), 120);
}

#[test]
fn sdk_metadata_rejects_oversized_inputs_without_expanding_the_read_budget() {
    let root = TempDir::new().unwrap();
    let (file, meta) = write_sdk(
        root.path(),
        "capped",
        json!([{"role":"user","content":"Valid"}]),
    );
    fs::OpenOptions::new()
        .write(true)
        .open(&meta)
        .unwrap()
        .set_len(100 * 1024 * 1024 + 1)
        .unwrap();
    assert!(scan(&context(std::slice::from_ref(&file), None)).is_empty());
    write_json(&meta, &manifest("capped"));
    fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .unwrap()
        .set_len(100 * 1024 * 1024 + 1)
        .unwrap();
    assert!(scan(&context(&[file], None)).is_empty());
}

#[test]
fn sdk_snapshot_and_manifest_changes_reingest_the_whole_session() {
    let root = TempDir::new().unwrap();
    let (file, meta) = write_sdk(
        root.path(),
        "incremental",
        json!([
            {"role":"user","content":"Old prompt","ts":10}, {"role":"assistant","content":"Old reply","ts":20},
        ]),
    );
    set_modified(&file, 100);
    set_modified(&meta, 100);
    assert!(scan(&context(std::slice::from_ref(&file), Some(200_000))).is_empty());
    set_modified(&meta, 300);
    assert_eq!(
        single(&context(std::slice::from_ref(&file), Some(200_000)))
            .messages
            .len(),
        2
    );
    set_modified(&meta, 100);
    set_modified(&file, 300);
    assert_eq!(single(&context(&[file], Some(200_000))).messages.len(), 2);
}

fn write_migrated(home: &Path, id: &str) -> (PathBuf, PathBuf, PathBuf) {
    let (file, meta) = write_sdk(
        home,
        id,
        json!([
            {"id":"sdk-old-prompt","role":"user","content":"Old prompt"},
            {"id":"sdk-old-totals","role":"assistant","content":"Retained old context",
                "metrics":{"inputTokens":100,"outputTokens":20,"cacheReadTokens":30,"cacheWriteTokens":10}},
            {"id":"sdk-warning","role":"user","content":WARNING},
            {"id":"sdk-new-prompt","role":"user","content":"Continue working"},
            {"id":"sdk-new-reply","role":"assistant","content":"New SDK reply",
                "metrics":{"inputTokens":50,"outputTokens":5,"cacheReadTokens":10,"cacheWriteTokens":5}},
        ]),
    );
    let mut header = manifest(id);
    header["metadata"]["migratedFromLegacyTask"] = json!(true);
    write_json(&meta, &header);
    let ui = home
        .join(EXTENSION)
        .join("tasks")
        .join(id)
        .join("ui_messages.json");
    write_json(
        &ui,
        &json!([
            {"ts":1,"type":"say","say":"task","text":"Original full UI prompt"},
            {"ts":2,"type":"say","say":"api_req_started",
             "text":"{\"tokensIn\":60,\"tokensOut\":20,\"cacheReads\":30,\"cacheWrites\":10}"},
            {"ts":3,"type":"say","say":"text","text":"Middle UI history lost from working context"},
        ]),
    );
    (file, meta, ui)
}

#[test]
fn sdk_legacy_resume_merges_full_ui_then_new_sdk_messages_and_counts_usage_once() {
    let root = TempDir::new().unwrap();
    let (file, _, ui) = write_migrated(root.path(), "migrated");
    let original_ui = fs::read(&ui).unwrap();
    let original_sdk = fs::read(&file).unwrap();
    let ctx = context(&[root.path().to_path_buf()], None);
    let sources = ClineConnector::new().discover_source_files(&ctx).unwrap();
    assert_eq!(sources.len(), 3);
    assert_eq!(
        sources
            .iter()
            .filter(|source| source.role == DiscoveredSourceRole::PrimarySessionLog)
            .count(),
        1
    );
    assert!(
        sources
            .iter()
            .any(|source| source.source_path == ui && source.required_for_reconstruction)
    );
    let conversation = single(&ctx);
    assert_eq!(conversation.source_path, file);
    assert_eq!(conversation.metadata["legacy_merge"], "ui_history");
    assert_eq!(conversation.messages.len(), 5);
    assert_eq!(conversation.messages[0].content, "Original full UI prompt");
    assert_eq!(
        conversation.messages[2].content,
        "Middle UI history lost from working context"
    );
    assert_eq!(conversation.messages[3].content, "Continue working");
    assert_eq!(conversation.messages[4].content, "New SDK reply");
    assert_eq!(api_total(&conversation), 175);
    assert_eq!(fs::read(file).unwrap(), original_sdk);
    assert_eq!(fs::read(ui).unwrap(), original_ui);
}

#[test]
fn sdk_migration_groups_before_incremental_filtering_and_preserves_old_ui() {
    let root = TempDir::new().unwrap();
    let (file, meta, ui) = write_migrated(root.path(), "migrated-incremental");
    for path in [&file, &meta, &ui] {
        set_modified(path, 100);
    }
    let ctx = context(&[root.path().to_path_buf()], Some(200_000));
    assert!(scan(&ctx).is_empty());
    for changed in [&file, &meta, &ui] {
        set_modified(changed, 300);
        assert_eq!(
            ClineConnector::new()
                .discover_source_files(&ctx)
                .unwrap()
                .len(),
            3
        );
        let conversation = single(&ctx);
        assert_eq!(conversation.messages.len(), 5);
        assert_eq!(api_total(&conversation), 175);
        set_modified(changed, 100);
    }
}

#[test]
fn sdk_standalone_migration_keeps_saved_context_and_legacy_total() {
    let root = TempDir::new().unwrap();
    let (file, _, _) = write_migrated(root.path(), "standalone");
    // Exact SDK selection cannot reach into an unselected legacy store.
    let ctx = context(std::slice::from_ref(&file), None);
    assert_eq!(
        ClineConnector::new()
            .discover_source_files(&ctx)
            .unwrap()
            .len(),
        2
    );
    let conversation = single(&ctx);
    assert_eq!(conversation.messages.len(), 5);
    assert_eq!(conversation.messages[1].content, "Retained old context");
    assert_eq!(api_total(&conversation), 175);
    assert_eq!(conversation.source_path, file);
}

#[test]
fn sdk_migration_invalid_old_ui_keeps_saved_sdk_prefix_and_does_not_double_count() {
    let root = TempDir::new().unwrap();
    let (file, _, ui) = write_migrated(root.path(), "bad-legacy");
    fs::write(ui, b"not JSON").unwrap();
    let conversation = single(&context(&[root.path().to_path_buf()], None));
    assert_eq!(conversation.source_path, file);
    assert_eq!(conversation.messages[1].content, "Retained old context");
    assert_eq!(api_total(&conversation), 175);
}

#[test]
fn sdk_invalid_migration_snapshot_falls_back_to_readable_legacy_ui() {
    let root = TempDir::new().unwrap();
    let (file, _, ui) = write_migrated(root.path(), "bad-sdk");
    fs::write(file, b"{truncated").unwrap();
    let conversation = single(&context(&[root.path().to_path_buf()], None));
    assert_eq!(conversation.source_path, ui);
    assert_eq!(conversation.messages.len(), 3);
    assert_eq!(api_total(&conversation), 120);
}

#[test]
fn sdk_migration_without_warning_does_not_guess_a_cutoff() {
    let root = TempDir::new().unwrap();
    let (file, _, _) = write_migrated(root.path(), "no-boundary");
    write_json(
        &file,
        &snapshot(
            "no-boundary",
            json!([
                {"role":"assistant","content":"Unambiguous saved snapshot",
                 "metrics":{"inputTokens":10,"outputTokens":2}},
            ]),
        ),
    );
    let conversation = single(&context(&[root.path().to_path_buf()], None));
    assert_eq!(conversation.messages.len(), 1);
    assert_eq!(
        conversation.messages[0].content,
        "Unambiguous saved snapshot"
    );
    assert_eq!(
        conversation.metadata["legacy_merge"],
        "missing_resume_boundary"
    );
    assert_eq!(api_total(&conversation), 12);
}

#[test]
fn sdk_migration_does_not_merge_same_ids_from_distinct_remote_hosts() {
    let root = TempDir::new().unwrap();
    let (file, _, ui) = write_migrated(root.path(), "host-specific");
    let ctx = ScanContext::with_roots(
        root.path().join("unused"),
        vec![
            ScanRoot::remote(file, Origin::remote("sdk-host"), Some(Platform::Linux)),
            ScanRoot::remote(
                ui,
                Origin::remote("different-legacy-host"),
                Some(Platform::Linux),
            ),
        ],
        None,
    );
    let conversations = scan(&ctx);
    assert_eq!(conversations.len(), 2);
    assert_eq!(conversations.iter().map(api_total).sum::<i64>(), 295);
    assert!(
        conversations
            .iter()
            .all(|conversation| conversation.metadata.get("legacy_merge").is_none())
    );
}

#[cfg(unix)]
#[test]
fn sdk_overlapping_roots_and_ancestor_symlinks_select_one_physical_session() {
    let root = TempDir::new().unwrap();
    let (file, meta) = write_sdk(
        root.path(),
        "aliased",
        json!([{"role":"user","content":"One physical source"}]),
    );
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(root.path().join(".cline"), &alias).unwrap();
    let ctx = context(
        &[
            file.clone(),
            meta,
            file.parent().unwrap().to_path_buf(),
            root.path().join(".cline"),
            alias.join("data/sessions"),
        ],
        None,
    );
    assert_eq!(
        ClineConnector::new()
            .discover_source_files(&ctx)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(scan(&ctx).len(), 1);
}

#[test]
fn sdk_copied_exact_files_use_adjacent_manifest_instead_of_recorded_absolute_paths() {
    let root = TempDir::new().unwrap();
    let (file, meta) = write_sdk(
        root.path(),
        "copied",
        json!([{"role":"user","content":"Copied source"}]),
    );
    let archive = root.path().join("renamed-archive");
    fs::create_dir_all(&archive).unwrap();
    let copy = archive.join("copied.messages.json");
    let copied_meta = archive.join("copied.json");
    fs::copy(file, &copy).unwrap();
    fs::copy(meta, &copied_meta).unwrap();
    for selected in [copy.clone(), copied_meta] {
        let conversation = single(&context(&[selected], None));
        assert_eq!(conversation.source_path, copy);
        assert_eq!(conversation.messages[0].content, "Copied source");
    }
}

#[test]
fn legacy_exact_transcripts_and_tasks_under_a_sessions_archive_remain_readable() {
    let root = TempDir::new().unwrap();
    for filename in ["ui_messages.json", "api_conversation_history.json"] {
        let task = root.path().join("backup/sessions").join(filename);
        let file = task.join(filename);
        write_json(
            &file,
            &json!([{"role":"user", "content":"Archived legacy transcript"}]),
        );
        for selected in [file.clone(), task] {
            for ctx in [
                context(std::slice::from_ref(&selected), None),
                ScanContext::local_default(selected, None),
            ] {
                let conversation = single(&ctx);
                assert_eq!(conversation.source_path, file);
                assert_eq!(
                    conversation.messages[0].content,
                    "Archived legacy transcript"
                );
                assert_eq!(conversation.metadata, json!({"source":"cline"}));
            }
        }
    }
}

#[test]
fn sdk_distinct_copied_sessions_in_one_archive_are_not_deduplicated_by_parent() {
    let root = TempDir::new().unwrap();
    let archive = root.path().join("archive");
    fs::create_dir_all(&archive).unwrap();
    let mut selected = Vec::new();
    for id in ["copied-one", "copied-two"] {
        let (file, meta) = write_sdk(
            root.path(),
            id,
            json!([
                {"role":"assistant","content":id,"metrics":{"outputTokens":10}},
            ]),
        );
        let copy = archive.join(format!("{id}.messages.json"));
        fs::copy(file, &copy).unwrap();
        fs::copy(meta, archive.join(format!("{id}.json"))).unwrap();
        selected.push(copy);
    }
    let ctx = context(&selected, None);
    assert_eq!(
        ClineConnector::new()
            .discover_source_files(&ctx)
            .unwrap()
            .len(),
        4
    );
    let conversations = scan(&ctx);
    assert_eq!(conversations.len(), 2);
    assert_eq!(conversations.iter().map(api_total).sum::<i64>(), 20);
    assert_ne!(conversations[0].external_id, conversations[1].external_id);
}

#[test]
fn sdk_migration_with_only_api_history_keeps_one_saved_sdk_snapshot() {
    let root = TempDir::new().unwrap();
    let (file, _, ui) = write_migrated(root.path(), "api-only");
    let api = ui.with_file_name("api_conversation_history.json");
    fs::rename(ui, &api).unwrap();
    write_json(
        &api,
        &json!([
            {"role":"user","content":"Legacy API prompt"},
            {"role":"assistant","content":"Legacy API reply"},
        ]),
    );
    let conversation = single(&context(&[root.path().to_path_buf()], None));
    assert_eq!(conversation.source_path, file);
    assert_eq!(conversation.messages.len(), 5);
    assert_eq!(conversation.messages[1].content, "Retained old context");
    assert_eq!(api_total(&conversation), 175);
}

#[test]
fn sdk_sanitized_legacy_warning_inside_text_blocks_still_recovers_full_ui() {
    let root = TempDir::new().unwrap();
    let (file, _, _) = write_migrated(root.path(), "sanitized-warning");
    let mut saved: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    // initial-message-sanitizer.ts consolidates non-tool blocks from all
    // consecutive user rows after an assistant tool call into one user row.
    saved["messages"][2]["content"] = json!([
        {"type":"text","text":"Legacy environment context"},
        {"type":"text","text":WARNING},
    ]);
    write_json(&file, &saved);
    let conversation = single(&context(&[root.path().to_path_buf()], None));
    assert_eq!(conversation.metadata["legacy_merge"], "ui_history");
    assert_eq!(conversation.messages.len(), 5);
    assert_eq!(
        conversation.messages[2].content,
        "Middle UI history lost from working context"
    );
    assert_eq!(api_total(&conversation), 175);

    // A tool's quoted output is not the user-text migration boundary.
    saved["messages"][2]["content"] = json!([
        {"type":"tool_result","tool_use_id":"quoted-warning","name":"read_file","content":WARNING},
    ]);
    write_json(&file, &saved);
    let conversation = single(&context(&[root.path().to_path_buf()], None));
    assert_eq!(
        conversation.metadata["legacy_merge"],
        "missing_resume_boundary"
    );
    assert_eq!(conversation.messages[1].content, "Retained old context");
    assert_eq!(api_total(&conversation), 175);
}

#[test]
fn sdk_migration_does_not_replace_roo_history_with_the_same_task_id() {
    let root = TempDir::new().unwrap();
    let (file, _, ui) = write_migrated(root.path(), "separate-roo");
    let roo = root.path().join(".config/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks/separate-roo/ui_messages.json");
    fs::create_dir_all(roo.parent().unwrap()).unwrap();
    fs::rename(ui, &roo).unwrap();
    let conversations = scan(&context(&[root.path().to_path_buf()], None));
    assert_eq!(conversations.len(), 2);
    assert!(
        conversations
            .iter()
            .any(|conversation| conversation.source_path == file)
    );
    assert!(
        conversations
            .iter()
            .any(|conversation| conversation.source_path == roo)
    );
    assert_eq!(conversations.iter().map(api_total).sum::<i64>(), 295);
    assert!(
        conversations
            .iter()
            .all(|conversation| conversation.metadata.get("legacy_merge").is_none())
    );
}
