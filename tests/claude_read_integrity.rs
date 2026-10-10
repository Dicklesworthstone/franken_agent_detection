//! Source read failures must not hide healthy Claude sessions or certify a prefix.
#![cfg(feature = "connectors")]

use std::fs;
use std::io;
use std::path::PathBuf;

use franken_agent_detection::{
    ClaudeCodeConnector, Connector, DiscoveredSourceFile, ScanContext, ScanRoot, SourceCompletion,
    SourceScanHooks,
};
use tempfile::TempDir;

struct Fixture {
    _root: TempDir,
    files: Vec<PathBuf>,
    ctx: ScanContext,
}

impl Fixture {
    fn new(names: &[&str]) -> Self {
        let root = TempDir::new().unwrap();
        let files: Vec<_> = names.iter().map(|name| root.path().join(name)).collect();
        for path in &files {
            fs::write(
                path,
                b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"healthy prompt\"}}\n",
            )
            .unwrap();
        }
        let ctx = ScanContext::with_roots(
            root.path().join("data"),
            files.iter().cloned().map(ScanRoot::local).collect(),
            None,
        );
        Self {
            _root: root,
            files,
            ctx,
        }
    }
}

#[test]
fn missing_source_does_not_abort_healthy_streaming_or_complete_the_failed_source() {
    // Cover both file-open branches through the real public API. Renaming in
    // should_scan happens after discovery but before the source is opened.
    for extension in ["jsonl", "json"] {
        let fixture = Fixture::new(&[&format!("a-bad.{extension}"), "b-healthy.jsonl"]);
        let connector = ClaudeCodeConnector::new();
        assert_eq!(
            connector.discover_source_files(&fixture.ctx).unwrap().len(),
            2
        );
        let bad = &fixture.files[0];
        let moved = bad.with_extension("moved");
        let original = fs::read(bad).unwrap();
        let mut visited = Vec::new();
        let mut emitted = Vec::new();
        let mut completed = Vec::new();
        let error = {
            let mut should_scan = |source: &DiscoveredSourceFile| {
                visited.push(source.source_path.clone());
                if source.source_path == *bad {
                    fs::rename(bad, &moved).unwrap();
                }
                true
            };
            let mut on_complete = |completion: &SourceCompletion| {
                completed.push(completion.source.source_path.clone());
                assert_eq!(completion.conversations_emitted, 1);
                Ok(())
            };
            connector
                .scan_with_source_boundaries(
                    &fixture.ctx,
                    &mut SourceScanHooks {
                        should_scan_source: Some(&mut should_scan),
                        on_source_complete: Some(&mut on_complete),
                    },
                    &mut |conversation| {
                        assert_eq!(conversation.messages[0].content, "healthy prompt");
                        emitted.push(conversation.source_path);
                        Ok(())
                    },
                )
                .unwrap_err()
        };
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::NotFound
        );
        assert!(format!("{error:#}").contains(bad.to_str().unwrap()));
        assert_eq!(visited, fixture.files);
        assert_eq!(emitted, [fixture.files[1].clone()]);
        assert_eq!(completed, emitted);
        assert_eq!(fs::read(&moved).unwrap(), original);
    }
}

#[test]
fn unreadable_whole_json_preserves_healthy_streaming_and_collecting_returns_error() {
    let fixture = Fixture::new(&["a-bad.json", "b-healthy.jsonl"]);
    // read_to_string fails after opening a real file, independently of the
    // JSONL reader. This is an I/O InvalidData, not a malformed JSON record.
    fs::write(&fixture.files[0], b"{\"messages\":[\xff").unwrap();
    let before: Vec<_> = fixture
        .files
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect();
    let connector = ClaudeCodeConnector::new();
    let mut emitted = Vec::new();
    let error = connector
        .scan_with_callback(&fixture.ctx, &mut |conversation| {
            emitted.push(conversation.source_path);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(emitted, [fixture.files[1].clone()]);
    // The existing collecting API is all-or-error; a caller cannot mistake
    // an incomplete corpus for a successfully returned conversation vector.
    let collected_error = connector.scan(&fixture.ctx).unwrap_err();
    assert_eq!(
        collected_error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::InvalidData
    );
    for (path, original) in fixture.files.iter().zip(before) {
        assert_eq!(fs::read(path).unwrap(), original);
    }
}

#[test]
fn callback_errors_stop_immediately_even_after_a_deferred_source_failure() {
    for fail_completion in [false, true] {
        let fixture = Fixture::new(&["a-bad.jsonl", "b-healthy.jsonl", "c-unvisited.jsonl"]);
        let mut visited = Vec::new();
        let mut emitted = Vec::new();
        let mut completed = Vec::new();
        let error = {
            let mut should_scan = |source: &DiscoveredSourceFile| {
                visited.push(source.source_path.clone());
                if source.source_path == fixture.files[0] {
                    fs::rename(
                        &source.source_path,
                        source.source_path.with_extension("moved"),
                    )
                    .unwrap();
                }
                true
            };
            let mut on_complete = |completion: &SourceCompletion| {
                completed.push(completion.source.source_path.clone());
                anyhow::bail!("completion cancelled")
            };
            ClaudeCodeConnector::new()
                .scan_with_source_boundaries(
                    &fixture.ctx,
                    &mut SourceScanHooks {
                        should_scan_source: Some(&mut should_scan),
                        on_source_complete: Some(&mut on_complete),
                    },
                    &mut |conversation| {
                        emitted.push(conversation.source_path);
                        if !fail_completion {
                            anyhow::bail!("conversation cancelled");
                        }
                        Ok(())
                    },
                )
                .unwrap_err()
        };
        assert_eq!(visited, fixture.files[..2]);
        assert_eq!(emitted, [fixture.files[1].clone()]);
        if fail_completion {
            assert_eq!(error.to_string(), "completion cancelled");
            assert_eq!(completed, emitted);
        } else {
            assert_eq!(error.to_string(), "conversation cancelled");
            assert!(completed.is_empty());
        }
    }
}
