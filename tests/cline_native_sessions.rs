//! Native Cline task stores through the public scan/discovery APIs.
//!
//! Fixtures follow cline/cline c3a40572765b76873c597247941118c1778d02c8:
//! apps/vscode/src/core/storage/disk.ts, shared/ExtensionMessage.ts and
//! sdk/message-translator.ts. VS Code task files still live in its extension
//! globalStorage/tasks directory, as documented by vscode-to-file-migration.ts.
#![cfg(feature = "connectors")]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use franken_agent_detection::{
    ClineConnector, Connector, DiscoveredSourceRole, NormalizedConversation, Origin, Platform,
    ScanContext, ScanRoot, SourceScanHooks,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const EXTENSION: &str = ".config/Code/User/globalStorage/saoudrizwan.claude-dev";

fn native_messages(prompt: &str) -> Value {
    json!([
        {"ts": 1_760_000_000_000_i64, "type": "say", "say": "task", "text": prompt},
        {"ts": 1_760_000_000_001_i64, "type": "say", "say": "text", "text": "Found the history"},
        {"ts": 1_760_000_000_002_i64, "type": "ask", "ask": "followup", "text": "Which file?"},
        {"ts": 1_760_000_000_003_i64, "type": "say", "say": "user_feedback", "text": "Read lib.rs"},
        {"ts": 1_760_000_000_004_i64, "type": "say", "say": "mcp_server_response", "text": "pub fn detected() {}"},
    ])
}

fn write_transcript(directory: &Path, filename: &str, messages: &Value) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let path = directory.join(filename);
    fs::write(&path, serde_json::to_vec(messages).unwrap()).unwrap();
    path
}

fn remote_context(data_dir: &Path, paths: &[PathBuf], since_ts: Option<i64>) -> ScanContext {
    ScanContext::with_roots(
        data_dir.to_path_buf(),
        paths
            .iter()
            .map(|path| {
                ScanRoot::remote(
                    path.clone(),
                    Origin::remote_with_host("cline-fixture", "archived-host"),
                    Some(Platform::Linux),
                )
            })
            .collect(),
        since_ts,
    )
}

fn scan_routes(ctx: &ScanContext) -> Vec<NormalizedConversation> {
    let connector = ClineConnector::new();
    let direct = connector.scan(ctx).unwrap();
    let mut callback = Vec::new();
    connector
        .scan_with_callback(ctx, &mut |conversation| {
            callback.push(conversation);
            Ok(())
        })
        .unwrap();
    let mut boundaries = Vec::new();
    let mut should_scan_calls = 0;
    let mut complete_calls = 0;
    let mut should_scan = |_: &_| {
        should_scan_calls += 1;
        true
    };
    let mut completed = |_: &_| {
        complete_calls += 1;
        Ok(())
    };
    connector
        .scan_with_source_boundaries(
            ctx,
            &mut SourceScanHooks {
                should_scan_source: Some(&mut should_scan),
                on_source_complete: Some(&mut completed),
            },
            &mut |conversation| {
                boundaries.push(conversation);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(&direct).unwrap(),
        serde_json::to_value(callback).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&direct).unwrap(),
        serde_json::to_value(boundaries).unwrap()
    );
    assert!(connector.supports_streaming_scan());
    assert!(!connector.supports_source_boundaries());
    assert_eq!(should_scan_calls, 0);
    assert_eq!(complete_calls, 0);
    direct
}

fn assert_unchanged(path: &Path, bytes: &[u8], modified: std::time::SystemTime) {
    assert_eq!(fs::read(path).unwrap(), bytes);
    assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), modified);
}

#[test]
fn native_tasks_roundtrip_every_store_scope_with_metadata_and_roles() {
    let root = TempDir::new().unwrap();
    let extension = root.path().join(EXTENSION);
    let task = extension.join("tasks/1760000000000");
    let records = native_messages("Inspect the native task");
    let path = write_transcript(&task, "ui_messages.json", &records);
    let metadata = task.join("task_metadata.json");
    fs::write(
        &metadata,
        r#"{"title":"Native task","cwd":"/remote/my-project"}"#,
    )
    .unwrap();
    let original = fs::read(&path).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let metadata_original = fs::read(&metadata).unwrap();
    let metadata_modified = fs::metadata(&metadata).unwrap().modified().unwrap();
    for scope in [
        root.path().to_path_buf(),
        root.path().join(".config"),
        root.path().join(".config/Code"),
        root.path().join(".config/Code/User"),
        root.path().join(".config/Code/User/globalStorage"),
        extension.clone(),
        extension.join("tasks"),
        task,
        path.clone(),
    ] {
        for ctx in [
            remote_context(
                &root.path().join("unused-state"),
                std::slice::from_ref(&scope),
                None,
            ),
            ScanContext::local_default(scope.clone(), None),
        ] {
            let sources = ClineConnector::new().discover_source_files(&ctx).unwrap();
            assert_eq!(sources.len(), 2, "scope={scope:?}");
            assert_eq!(sources[0].source_path, path);
            assert_eq!(sources[0].role, DiscoveredSourceRole::PrimarySessionLog);
            assert!(sources[0].required_for_reconstruction);
            assert_eq!(sources[1].source_path, metadata);
            assert_eq!(sources[1].role, DiscoveredSourceRole::MetadataSidecar);
            assert!(!sources[1].required_for_reconstruction);
            for source in &sources {
                assert_eq!(source.provider_slug, "cline");
                assert!(source.size_bytes.unwrap() > 0);
                assert!(source.modified_at_ms.is_some());
                if let Some(scan_root) = ctx.scan_roots.first() {
                    assert_eq!(source.origin, scan_root.origin);
                    assert_eq!(source.platform, Some(Platform::Linux));
                } else {
                    assert_eq!(source.origin, Origin::local());
                }
            }
            let conversations = scan_routes(&ctx);
            assert_eq!(conversations.len(), 1, "scope={scope:?}");
            let conversation = &conversations[0];
            assert_eq!(conversation.agent_slug, "cline");
            assert_eq!(conversation.external_id.as_deref(), Some("1760000000000"));
            assert_eq!(conversation.source_path, path);
            assert_eq!(conversation.title.as_deref(), Some("Native task"));
            assert_eq!(
                conversation.workspace.as_deref(),
                Some(Path::new("/remote/my-project"))
            );
            assert_eq!(conversation.messages.len(), 5);
            for (index, (message, role)) in conversation
                .messages
                .iter()
                .zip(["user", "assistant", "assistant", "user", "tool"])
                .enumerate()
            {
                assert_eq!(message.idx, i64::try_from(index).unwrap());
                assert_eq!(message.role, role);
                assert_eq!(message.extra, records[index]);
                assert_eq!(message.content, records[index]["text"]);
            }
        }
    }
    assert_unchanged(&path, &original, modified);
    assert_unchanged(&metadata, &metadata_original, metadata_modified);
}

#[test]
fn native_and_legacy_tasks_coexist_without_recursive_decoy_ingestion() {
    let root = TempDir::new().unwrap();
    let extension = root.path().join(EXTENSION);
    let legacy = write_transcript(
        &extension.join("legacy"),
        "ui_messages.json",
        &json!([{"role":"user","content":"Legacy task"}]),
    );
    let native = write_transcript(
        &extension.join("tasks/native"),
        "ui_messages.json",
        &native_messages("Native task"),
    );
    for decoy in [
        "cache/nested",
        "checkpoints/nested",
        "tasks/native/nested",
        "tasks/taskHistory.json",
    ] {
        write_transcript(
            &extension.join(decoy),
            "ui_messages.json",
            &native_messages("Excluded nested payload"),
        );
    }
    let ctx = remote_context(&root.path().join("unused-state"), &[extension], None);
    let sources = ClineConnector::new().discover_source_files(&ctx).unwrap();
    assert_eq!(
        sources
            .iter()
            .map(|source| &source.source_path)
            .collect::<Vec<_>>(),
        [&legacy, &native]
    );
    let conversations = scan_routes(&ctx);
    assert_eq!(
        conversations
            .iter()
            .map(|conversation| &conversation.source_path)
            .collect::<Vec<_>>(),
        [&legacy, &native]
    );
}

#[test]
fn exact_transcripts_and_task_directories_keep_the_requested_scope() {
    let root = TempDir::new().unwrap();
    let tasks = root.path().join(EXTENSION).join("tasks");
    let task = tasks.join("selected");
    let ui = write_transcript(&task, "ui_messages.json", &native_messages("UI selected"));
    let api = write_transcript(
        &task,
        "api_conversation_history.json",
        &json!([{"role":"user","content":"API selected"}]),
    );
    write_transcript(
        &tasks.join("sibling"),
        "ui_messages.json",
        &native_messages("Unrelated sibling"),
    );
    for (scope, expected) in [(&ui, &ui), (&api, &api), (&task, &ui)] {
        for ctx in [
            remote_context(
                &root.path().join("unused-state"),
                std::slice::from_ref(scope),
                None,
            ),
            ScanContext::local_default(scope.clone(), None),
        ] {
            let sources = ClineConnector::new().discover_source_files(&ctx).unwrap();
            assert_eq!(sources.len(), 1);
            assert_eq!(&sources[0].source_path, expected);
            assert_eq!(&sources[0].scan_root, scope);
            let conversations = scan_routes(&ctx);
            assert_eq!(conversations.len(), 1);
            assert_eq!(&conversations[0].source_path, expected);
            assert_eq!(conversations[0].external_id.as_deref(), Some("selected"));
        }
    }
    let empty_task = tasks.join("empty-task");
    write_transcript(
        &empty_task.join("nested"),
        "ui_messages.json",
        &native_messages("Do not replace empty selected task"),
    );
    for ctx in [
        remote_context(
            &root.path().join("unused-state"),
            std::slice::from_ref(&empty_task),
            None,
        ),
        ScanContext::local_default(empty_task, None),
    ] {
        assert!(
            ClineConnector::new()
                .discover_source_files(&ctx)
                .unwrap()
                .is_empty()
        );
        assert!(scan_routes(&ctx).is_empty());
    }
}

#[test]
fn unrelated_tasks_directory_does_not_hide_a_real_extension_store() {
    let root = TempDir::new().unwrap();
    fs::create_dir_all(root.path().join("tasks/work")).unwrap();
    fs::write(root.path().join("tasks/work/notes.json"), "{}").unwrap();
    let source = write_transcript(
        &root.path().join(EXTENSION).join("tasks/native"),
        "ui_messages.json",
        &native_messages("Real extension history"),
    );
    for ctx in [
        remote_context(
            &root.path().join("unused-state"),
            &[root.path().to_path_buf()],
            None,
        ),
        ScanContext::local_default(root.path().to_path_buf(), None),
    ] {
        let sources = ClineConnector::new().discover_source_files(&ctx).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source_path, source);
        let conversations = scan_routes(&ctx);
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].source_path, source);
    }
}

#[test]
fn copied_native_stores_and_cursor_containers_are_admitted() {
    let root = TempDir::new().unwrap();
    let copied = root.path().join("copied-store");
    let source = write_transcript(
        &copied.join("tasks/native"),
        "ui_messages.json",
        &native_messages("Copied native"),
    );
    for scope in [&copied, &copied.join("tasks")] {
        let conversations = scan_routes(&ScanContext::local_default(scope.clone(), None));
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].source_path, source);
    }
    let cursor = root.path().join(".config/Cursor");
    let source = write_transcript(
        &cursor.join("User/globalStorage/rooveterinaryinc.roo-cline/tasks/native"),
        "ui_messages.json",
        &native_messages("Cursor native"),
    );
    for scope in [
        root.path().join(".config"),
        cursor.clone(),
        cursor.join("User"),
        cursor.join("User/globalStorage"),
    ] {
        let ctx = remote_context(&copied, &[scope], None);
        let conversations = scan_routes(&ctx);
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].source_path, source);
    }
}

#[test]
fn overlapping_roots_deduplicate_native_tasks_with_stable_provenance() {
    let root = TempDir::new().unwrap();
    let extension = root.path().join(EXTENSION);
    let task = extension.join("tasks/native");
    let ui = write_transcript(
        &task,
        "ui_messages.json",
        &native_messages("Selected native"),
    );
    let api = write_transcript(
        &task,
        "api_conversation_history.json",
        &json!([{"role":"user","content":"API fallback"}]),
    );
    let mut roots = vec![
        extension.clone(),
        extension.join("tasks"),
        task.clone(),
        ui,
        api,
    ];
    #[cfg(unix)]
    {
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&extension, &alias).unwrap();
        roots.push(alias);
    }
    let unrelated = root.path().join("unrelated");
    write_transcript(
        &unrelated.join("tasks/unrelated"),
        "ui_messages.json",
        &native_messages("Unrelated local"),
    );
    let mut expected = None;
    for _ in 0..2 {
        roots.reverse();
        let ctx = remote_context(&unrelated, &roots, None);
        let sources = ClineConnector::new().discover_source_files(&ctx).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].origin, ctx.scan_roots[0].origin);
        assert_eq!(sources[0].platform, Some(Platform::Linux));
        assert_eq!(
            fs::canonicalize(sources[0].source_path.parent().unwrap()).unwrap(),
            fs::canonicalize(&task).unwrap()
        );
        let conversations = scan_routes(&ctx);
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].source_path, sources[0].source_path);
        let result = serde_json::to_value(conversations).unwrap();
        if let Some(previous) = expected {
            assert_eq!(result, previous);
        }
        expected = Some(result);
    }
}

#[test]
fn incremental_scans_select_complete_transcripts_by_primary_file_mtime() {
    let root = TempDir::new().unwrap();
    let tasks = root.path().join(EXTENSION).join("tasks");
    let source = write_transcript(
        &tasks.join("native"),
        "ui_messages.json",
        &native_messages("All messages survive"),
    );
    let original = fs::read(&source).unwrap();
    let modified = fs::metadata(&source).unwrap().modified().unwrap();
    let modified_ms =
        i64::try_from(modified.duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap();
    for (since, expected) in [(modified_ms - 1000, 1), (modified_ms + 60_000, 0)] {
        let ctx = remote_context(
            &root.path().join("unused-state"),
            std::slice::from_ref(&tasks),
            Some(since),
        );
        assert_eq!(
            ClineConnector::new()
                .discover_source_files(&ctx)
                .unwrap()
                .len(),
            expected
        );
        let conversations = scan_routes(&ctx);
        assert_eq!(conversations.len(), expected);
        if let Some(conversation) = conversations.first() {
            assert_eq!(conversation.messages.len(), 5);
            assert!(
                conversation
                    .messages
                    .iter()
                    .all(|message| message.created_at.unwrap() < since)
            );
        }
    }
    assert_unchanged(&source, &original, modified);
}

#[test]
fn malformed_ui_and_capped_native_sources_preserve_existing_failure_behavior() {
    let root = TempDir::new().unwrap();
    let extension = root.path().join(EXTENSION);
    let malformed = extension.join("tasks/malformed");
    let malformed_path = write_transcript(&malformed, "ui_messages.json", &Value::Null);
    fs::write(&malformed_path, "[{\"type\":").unwrap();
    write_transcript(
        &malformed,
        "api_conversation_history.json",
        &json!([{"role":"user","content":"Do not substitute API after malformed UI"}]),
    );
    let capped = write_transcript(
        &extension.join("tasks/capped"),
        "ui_messages.json",
        &Value::Null,
    );
    fs::OpenOptions::new()
        .write(true)
        .open(&capped)
        .unwrap()
        .set_len(100 * 1024 * 1024 + 1)
        .unwrap();
    let capped_modified = fs::metadata(&capped).unwrap().modified().unwrap();
    let healthy = write_transcript(
        &extension.join("tasks/healthy"),
        "api_conversation_history.json",
        &json!([{"role":"user","content":"Healthy API fallback"}]),
    );
    let ctx = remote_context(&root.path().join("unused-state"), &[extension], None);
    assert_eq!(
        ClineConnector::new()
            .discover_source_files(&ctx)
            .unwrap()
            .len(),
        3
    );
    let conversations = scan_routes(&ctx);
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0].source_path, healthy);
    assert_eq!(fs::metadata(&capped).unwrap().len(), 100 * 1024 * 1024 + 1);
    assert_eq!(
        fs::metadata(&capped).unwrap().modified().unwrap(),
        capped_modified
    );
    assert_eq!(fs::read_to_string(&malformed_path).unwrap(), "[{\"type\":");
}

#[test]
fn explicit_legacy_roles_remain_authoritative() {
    let root = TempDir::new().unwrap();
    let path = write_transcript(
        root.path(),
        "ui_messages.json",
        &json!([
            {"role":"user", "type":"say", "say":"text", "text":"Explicit user"},
            {"type":"say", "say":"reasoning", "text":"Assistant reasoning"},
            {"type":"say", "say":"command_output", "text":"Tool output"},
            {"type":"say", "say":"user_feedback_diff", "text":"User diff"},
            {"type":"userMessage", "content":"Legacy role spelling"},
            {"content":"Legacy missing role"}
        ]),
    );
    let conversations = scan_routes(&ScanContext::local_default(path, None));
    assert_eq!(
        conversations[0]
            .messages
            .iter()
            .map(|message| message.role.as_str())
            .collect::<Vec<_>>(),
        ["user", "assistant", "tool", "user", "userMessage", "agent"]
    );
}

#[cfg(unix)]
#[test]
fn missing_selected_stores_do_not_fall_back_to_live_home() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("home");
    let live = write_transcript(
        &home.join(EXTENSION).join("tasks/live"),
        "ui_messages.json",
        &native_messages("Unrelated live home"),
    );
    let original = fs::read(&live).unwrap();
    let modified = fs::metadata(&live).unwrap().modified().unwrap();
    fs::create_dir_all(root.path().join("empty/tasks")).unwrap();
    // A missing requested UI file must not substitute the API sibling.
    write_transcript(
        &root.path().join("copied/tasks/api-only"),
        "api_conversation_history.json",
        &json!([{"role":"user","content":"Wrong sibling"}]),
    );
    for selection in [
        "missing/saoudrizwan.claude-dev",
        "missing/tasks",
        "copied/tasks/missing",
        "copied/tasks/api-only/ui_messages.json",
        "missing/api_conversation_history.json",
        "missing/.config/Code/User/globalStorage",
        "missing/.config/Cursor",
        "empty/tasks",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cline_missing_scope_child", "--nocapture"])
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("FAD_CLINE_MISSING_SCOPE", root.path().join(selection))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "selection={selection}, stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_unchanged(&live, &original, modified);
}

#[cfg(unix)]
#[test]
fn cline_missing_scope_child() {
    let Some(scope) = std::env::var_os("FAD_CLINE_MISSING_SCOPE") else {
        return;
    };
    let ctx = ScanContext::local_default(PathBuf::from(scope), None);
    assert!(
        ClineConnector::new()
            .discover_source_files(&ctx)
            .unwrap()
            .is_empty()
    );
    assert!(scan_routes(&ctx).is_empty());
}
