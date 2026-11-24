//! Selected transcript I/O failures must remain visible to the scan caller.
#![cfg(feature = "connectors")]

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use franken_agent_detection::{
    AntigravityConnector, Connector, DiscoveredSourceFile, ScanContext, ScanRoot,
    SourceCompletion, SourceScanHooks,
};
use serde_json::json;
use tempfile::TempDir;

const IDS: [&str; 3] = [
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
];

#[derive(Clone, Copy)]
enum Failure {
    Missing,
    #[cfg(unix)]
    Directory,
}

struct Fixture {
    root: TempDir,
    files: Vec<PathBuf>,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let files: Vec<_> = IDS
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let path = root
                    .path()
                    .join("brain")
                    .join(id)
                    .join(".system_generated/logs/transcript.jsonl");
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(
                    &path,
                    json!({
                        "step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT",
                        "content": format!("Healthy synthetic prompt {index}."),
                    })
                    .to_string(),
                )
                .unwrap();
                // Once the primary is selected, an I/O failure must not switch
                // authority to this readable alternative.
                fs::write(
                    path.with_file_name("transcript_full.jsonl"),
                    json!({
                        "step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT",
                        "content": "The unselected full transcript must not be emitted.",
                    })
                    .to_string(),
                )
                .unwrap();
                path
            })
            .collect();
        Self { root, files }
    }

    fn context(&self) -> ScanContext {
        ScanContext::with_roots(
            self.root.path().join("unused-index"),
            vec![ScanRoot::local(self.root.path().to_path_buf())],
            None,
        )
    }

    fn failing_context(
        &self,
        failure: Failure,
        failure_count: usize,
    ) -> (ScanContext, Arc<AtomicUsize>) {
        let files = self.files.clone();
        let ticks = Arc::new(AtomicUsize::new(0));
        let progress = Arc::clone(&ticks);
        let context = self.context().with_progress_tick(Arc::new(move || {
            // The connector ticks after selecting a transcript and immediately
            // before opening it. Deterministically induce a real filesystem
            // failure at that point, without relying on permission bits.
            let index = progress.fetch_add(1, Ordering::SeqCst);
            if index < failure_count {
                let path = &files[index];
                fs::rename(path, path.with_extension("saved")).unwrap();
                match failure {
                    Failure::Missing => {}
                    #[cfg(unix)]
                    Failure::Directory => fs::create_dir(path).unwrap(),
                }
            }
        }));
        (context, ticks)
    }

    fn restore(&self, count: usize) {
        for path in self.files.iter().take(count) {
            if path.is_dir() {
                fs::remove_dir(path).unwrap();
            }
            fs::rename(path.with_extension("saved"), path).unwrap();
        }
    }
}

fn assert_io_kind(error: &anyhow::Error, kind: io::ErrorKind) {
    assert_eq!(
        error.downcast_ref::<io::Error>().map(io::Error::kind),
        Some(kind),
        "{error:#}"
    );
}

#[test]
fn missing_selected_sources_keep_healthy_streaming_and_return_the_first_error() {
    for boundaries in [false, true] {
        let fixture = Fixture::new();
        let (context, ticks) = fixture.failing_context(Failure::Missing, 2);
        let connector = AntigravityConnector::new();
        let mut emitted = Vec::new();
        let mut callback = |conversation: franken_agent_detection::NormalizedConversation| {
            assert_eq!(conversation.messages[0].content, "Healthy synthetic prompt 2.");
            emitted.push(conversation.source_path);
            Ok(())
        };
        let error = if boundaries {
            assert!(!connector.supports_source_boundaries());
            let mut should_scan = |_source: &DiscoveredSourceFile| -> bool {
                panic!("the conservative boundary fallback must not invoke source hooks");
            };
            let mut complete = |_source: &SourceCompletion| -> anyhow::Result<()> {
                panic!("the conservative boundary fallback must not certify a source");
            };
            connector
                .scan_with_source_boundaries(
                    &context,
                    &mut SourceScanHooks {
                        should_scan_source: Some(&mut should_scan),
                        on_source_complete: Some(&mut complete),
                    },
                    &mut callback,
                )
                .unwrap_err()
        } else {
            connector
                .scan_with_callback(&context, &mut callback)
                .unwrap_err()
        };
        assert_io_kind(&error, io::ErrorKind::NotFound);
        assert!(format!("{error:#}").contains(fixture.files[0].to_str().unwrap()));
        assert!(error.to_string().contains("2 Antigravity transcript source(s)"));
        assert_eq!(emitted, fixture.files[2..]);
        assert_eq!(ticks.load(Ordering::SeqCst), 3);

        fixture.restore(2);
        let repaired = connector.scan(&fixture.context()).unwrap();
        assert_eq!(repaired.len(), 3);
        assert!(
            repaired
                .iter()
                .all(|conversation| fixture.files.contains(&conversation.source_path))
        );
    }
}

#[test]
fn collecting_scan_returns_an_error_instead_of_a_partial_conversation_vector() {
    let fixture = Fixture::new();
    let (context, ticks) = fixture.failing_context(Failure::Missing, 1);
    let error = AntigravityConnector::new().scan(&context).unwrap_err();
    assert_io_kind(&error, io::ErrorKind::NotFound);
    assert!(format!("{error:#}").contains(fixture.files[0].to_str().unwrap()));
    assert_eq!(ticks.load(Ordering::SeqCst), 3);
    fixture.restore(1);
    assert_eq!(
        AntigravityConnector::new()
            .scan(&fixture.context())
            .unwrap()
            .len(),
        3
    );
}

#[cfg(unix)]
#[test]
fn selected_transcript_read_errors_do_not_hide_healthy_sources() {
    let fixture = Fixture::new();
    let (context, ticks) = fixture.failing_context(Failure::Directory, 1);
    let mut emitted = Vec::new();
    let error = AntigravityConnector::new()
        .scan_with_callback(&context, &mut |conversation| {
            emitted.push(conversation.source_path);
            Ok(())
        })
        .unwrap_err();
    assert_io_kind(&error, io::ErrorKind::IsADirectory);
    assert_eq!(emitted, fixture.files[1..]);
    assert_eq!(ticks.load(Ordering::SeqCst), 3);
    fixture.restore(1);
}

#[test]
fn callback_cancellation_takes_priority_over_a_deferred_source_error() {
    let fixture = Fixture::new();
    let (context, ticks) = fixture.failing_context(Failure::Missing, 1);
    let mut emitted = Vec::new();
    let error = AntigravityConnector::new()
        .scan_with_callback(&context, &mut |conversation| {
            emitted.push(conversation.source_path);
            anyhow::bail!("synthetic sink stopped")
        })
        .unwrap_err();
    assert!(
        error
            .chain()
            .any(|cause| cause.to_string() == "synthetic sink stopped")
    );
    assert!(error.downcast_ref::<io::Error>().is_none());
    assert_eq!(emitted, fixture.files[1..2]);
    assert_eq!(ticks.load(Ordering::SeqCst), 2);
    fixture.restore(1);
}

#[test]
fn intentional_transcript_skips_and_optional_metadata_failures_remain_best_effort() {
    for kind in ["empty", "malformed", "oversized"] {
        let fixture = Fixture::new();
        match kind {
            "empty" => fs::write(&fixture.files[0], "").unwrap(),
            "malformed" => fs::write(&fixture.files[0], "{unfinished\n").unwrap(),
            _ => fs::File::create(&fixture.files[0])
                .unwrap()
                .set_len(100 * 1024 * 1024 + 1)
                .unwrap(),
        }
        let annotation = fixture
            .root
            .path()
            .join("annotations")
            .join(format!("{}.pbtxt", IDS[1]));
        fs::create_dir_all(annotation.parent().unwrap()).unwrap();
        fs::write(annotation, b"\xff").unwrap();
        let conversations = AntigravityConnector::new()
            .scan(&fixture.context())
            .unwrap();
        assert_eq!(conversations.len(), 2, "{kind}");
        assert_eq!(
            conversations[0].title.as_deref(),
            Some("Healthy synthetic prompt 1."),
            "{kind}"
        );
        assert!(
            conversations
                .iter()
                .all(|conversation| fixture.files[1..].contains(&conversation.source_path)),
            "{kind}"
        );
    }
}
