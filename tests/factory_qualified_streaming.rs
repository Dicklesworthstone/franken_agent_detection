//! GH520: qualified Factory roots stay narrow and large mirrors really stream.
#![cfg(feature = "connectors")]

use std::fs;
use std::path::{Path, PathBuf};

use franken_agent_detection::{
    Connector, FactoryConnector, Origin, Platform, ScanContext, ScanRoot,
};

fn put(path: &Path, id: &str, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let header = serde_json::json!({"type": "session_start", "id": id});
    let message = serde_json::json!({
        "type": "message", "timestamp": 1_700_000_000_000_i64,
        "message": {"role": "user", "content": text}
    });
    fs::write(path, format!("{header}\n{message}\n")).unwrap();
}

fn remote(path: PathBuf, source: &str) -> ScanRoot {
    ScanRoot::remote(
        path,
        Origin::remote_with_host("laptop", "alice@laptop"),
        Some(Platform::Linux),
    )
    .with_mirrored_source_path(source)
}

fn context(root: ScanRoot) -> ScanContext {
    let state = root.path.parent().unwrap().join("state");
    ScanContext::with_roots(state, vec![root.clone(), root], None)
}

fn assert_empty(ctx: &ScanContext) {
    let connector = FactoryConnector::new();
    assert!(connector.discover_source_files(ctx).unwrap().is_empty());
    assert!(connector.scan(ctx).unwrap().is_empty());
    let mut emitted = 0;
    connector
        .scan_with_callback(ctx, &mut |_| {
            emitted += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(emitted, 0);
}

#[test]
fn qualified_payloads_ignore_parseable_wrapper_siblings_in_all_copy_layouts() {
    for (source, below_leaf) in [
        ("~/.factory", "sessions/project"),
        ("~/.factory/sessions", "project"),
        ("~/.factory/sessions/project", ""),
    ] {
        for (slash, retained) in [(false, true), (true, true), (true, false)] {
            let temp = tempfile::tempdir().unwrap();
            let container = temp.path().join("opaque_hash");
            let payload = if retained {
                container.join(Path::new(source).file_name().unwrap())
            } else {
                container.clone()
            };
            let file = payload.join(below_leaf).join("selected.jsonl");
            put(&file, "selected", "selected transcript");
            // In contents-only mode the container itself is the selected store;
            // a direct transcript there is not outside scope. Test siblings only
            // when the selected payload is a narrower directory.
            if retained || source == "~/.factory" {
                put(&container.join("outside.jsonl"), "outside", "not selected");
            }
            let configured = format!("{source}{}", if slash { "/" } else { "" });
            let ctx = context(remote(container, &configured));
            let connector = FactoryConnector::new();
            let discovered = connector.discover_source_files(&ctx).unwrap();
            assert_eq!(discovered.len(), 1, "{configured}, retained={retained}");
            assert_eq!(discovered[0].source_path, file);
            assert_eq!(discovered[0].origin, ctx.scan_roots[0].origin);
            assert_eq!(discovered[0].platform, Some(Platform::Linux));
            let scanned = connector.scan(&ctx).unwrap();
            assert_eq!(scanned.len(), 1, "{configured}, retained={retained}");
            assert_eq!(scanned[0].external_id.as_deref(), Some("selected"));
            assert_eq!(scanned[0].source_path, file);
            assert_eq!(scanned[0].messages[0].content, "selected transcript");
            let before = fs::read(&file).unwrap();
            let mut streamed = Vec::new();
            connector
                .scan_with_callback(&ctx, &mut |conversation| {
                    streamed.push(conversation);
                    Ok(())
                })
                .unwrap();
            assert_eq!(streamed.len(), 1);
            assert_eq!(streamed[0].external_id, scanned[0].external_id);
            assert_eq!(fs::read(file).unwrap(), before);
            let mut incremental = ctx.clone();
            incremental.since_ts = Some(i64::MAX);
            assert_empty(&incremental);
        }
    }
}

#[test]
fn rejected_owned_mirrors_cannot_use_generic_jsonl_or_home_probes() {
    for source in [
        "~/.factory/sessions",
        "~/.factory/sessions/project",
        "~/.factory/sessions/../project/",
        "~/.factory/sessions/\nproject/",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let container = temp.path().join("opaque_hash");
        put(&container.join("outside.jsonl"), "outside", "must not be read");
        put(
            &container.join(".factory/sessions/also-outside.jsonl"),
            "also-outside",
            "must not be read either",
        );
        assert_empty(&context(remote(container, source)));
    }
    let temp = tempfile::tempdir().unwrap();
    let container = temp.path().join("opaque_hash");
    put(&container.join("outside.jsonl"), "outside", "must not be read");
    fs::write(container.join("sessions"), b"not a directory").unwrap();
    assert_empty(&context(remote(container, "~/.factory/sessions/")));
}

#[cfg(unix)]
#[test]
fn linked_payloads_cannot_reenter_through_legacy_detection() {
    use std::os::unix::fs::symlink;

    for existing_target in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let container = temp.path().join("opaque_hash");
        let target = temp.path().join("elsewhere");
        put(&container.join("outside.jsonl"), "outside", "must not be read");
        if existing_target {
            put(&target.join("private.jsonl"), "private", "must not be followed");
        }
        symlink(&target, container.join("sessions")).unwrap();
        assert_empty(&context(remote(container, "~/.factory/sessions/")));
    }
}

#[test]
fn native_and_unannotated_custom_roots_keep_existing_behavior() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("arbitrary-store");
    put(&root.join("local.jsonl"), "local", "legacy explicit root");
    for scan_root in [
        ScanRoot::local(root.clone()),
        ScanRoot::remote(root.clone(), Origin::remote("laptop"), None),
        ScanRoot::local(root.clone()).with_mirrored_source_path("~/.factory/sessions"),
        remote(root.clone(), "/backups/custom-transcripts"),
    ] {
        let conversations = FactoryConnector::new().scan(&context(scan_root)).unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].external_id.as_deref(), Some("local"));
    }
}

#[test]
fn callback_yields_before_the_next_transcript_is_parsed() {
    let temp = tempfile::tempdir().unwrap();
    let container = temp.path().join("opaque_hash");
    let first = container.join("sessions/a.jsonl");
    let later = container.join("sessions/z.jsonl");
    put(&first, "first", "first transcript");
    put(&later, "later", "before callback");
    let ctx = context(remote(container, "~/.factory/sessions"));
    let connector = FactoryConnector::new();
    assert!(connector.supports_streaming_scan());
    // No per-source completion is fabricated by this streaming-only change.
    assert!(!connector.supports_source_boundaries());
    let mut seen = Vec::new();
    connector
        .scan_with_callback(&ctx, &mut |conversation| {
            if seen.is_empty() {
                assert_eq!(conversation.source_path, first);
                // Real file mutation by the consumer distinguishes streaming
                // from scan-then-emit without a timing or memory heuristic.
                put(&later, "later", "written during first callback");
            }
            seen.push(conversation);
            Ok(())
        })
        .unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].source_path, later);
    assert_eq!(seen[1].messages[0].content, "written during first callback");
}

#[test]
fn callback_failure_propagates_without_emitting_the_remaining_corpus() {
    let temp = tempfile::tempdir().unwrap();
    let container = temp.path().join("opaque_hash");
    for index in 0..128 {
        let id = format!("session-{index:04}");
        put(&container.join("sessions").join(format!("{id}.jsonl")), &id, "body");
    }
    let ctx = context(remote(container, "~/.factory/sessions"));
    let connector = FactoryConnector::new();
    let mut emitted = 0;
    let error = connector
        .scan_with_callback(&ctx, &mut |_| {
            emitted += 1;
            anyhow::bail!("consumer stopped")
        })
        .unwrap_err();
    assert_eq!(emitted, 1);
    assert_eq!(error.to_string(), "consumer stopped");
    // Cancellation does not mutate the source or the connector: a fresh scan
    // can still read every session, exactly once despite the repeated roots.
    assert_eq!(connector.scan(&ctx).unwrap().len(), 128);
}
