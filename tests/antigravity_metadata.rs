//! Antigravity metadata participates in discovery and incremental scans.
//! Cross-directory metadata requires the plain streaming fallback until source
//! receipts can represent newly created sidecars. Exclusions use child processes.

#![cfg(feature = "connectors")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use franken_agent_detection::{
    AntigravityConnector, Connector, DiscoveredSourceFile, DiscoveredSourceRole, ScanContext,
    ScanRoot, SourceCompletion, SourceScanHooks,
};
use tempfile::TempDir;

const UUID: &str = "11111111-2222-4333-8444-555555555555";
const PROMPT: &str = "Original prompt title";
const CHILD_ROOT: &str = "FAD_ANTIGRAVITY_METADATA_ROOT";
const CHILD_CASE: &str = "FAD_ANTIGRAVITY_METADATA_CASE";

struct Fixture {
    root: TempDir,
    transcript: PathBuf,
    annotation: PathBuf,
    summary: PathBuf,
    wal: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let transcript = root
            .path()
            .join("brain")
            .join(UUID)
            .join(".system_generated/logs/transcript.jsonl");
        std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
        std::fs::write(
            &transcript,
            format!(
                "{}\n",
                serde_json::json!({
                    "step_index": 0,
                    "source": "USER_EXPLICIT",
                    "type": "USER_INPUT",
                    "status": "DONE",
                    "created_at": "2026-11-23T14:57:40Z",
                    "content": PROMPT
                })
            ),
        )
        .unwrap();
        let annotation = root
            .path()
            .join("annotations")
            .join(format!("{UUID}.pbtxt"));
        std::fs::create_dir_all(annotation.parent().unwrap()).unwrap();
        let summary = root.path().join("conversation_summaries.db");
        let wal = root.path().join("conversation_summaries.db-wal");
        Self {
            root,
            transcript,
            annotation,
            summary,
            wal,
        }
    }

    fn context(&self, since: Option<i64>) -> ScanContext {
        context(self.root.path(), since)
    }

    fn write_sidecars(&self) {
        std::fs::write(&self.annotation, "title:\"Saved annotation title\"\n").unwrap();
        // Deliberately unreadable optional SQLite files still participate in
        // discovery and freshness. SQL normalization and live WAL reads have separate
        // unit coverage; these fixtures need only the base connectors feature.
        std::fs::write(&self.summary, b"unavailable summary database").unwrap();
        std::fs::write(&self.wal, b"unavailable summary wal").unwrap();
    }
}

fn context(root: &Path, since: Option<i64>) -> ScanContext {
    ScanContext::with_roots(
        root.join("cass-state"),
        vec![ScanRoot::local(root.to_path_buf())],
        since,
    )
}

fn set_modified(path: &Path, millis: u64) {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_millis(millis))
        .unwrap();
}

#[test]
fn annotation_utf8_title_overrides_prompt_without_changing_sources() {
    let fixture = Fixture::new();
    let transcript = std::fs::read(&fixture.transcript).unwrap();
    for annotation in [
        r#"title:"caf\303\251 \"fix\"""#,
        r#"title: "caf\xc3\xa9 \"fix\"""#,
    ] {
        std::fs::write(&fixture.annotation, annotation).unwrap();
        let conversations = AntigravityConnector::new()
            .scan(&fixture.context(None))
            .unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].title.as_deref(), Some("café \"fix\""));
        assert_eq!(conversations[0].messages[0].content, PROMPT);
        assert_eq!(std::fs::read(&fixture.transcript).unwrap(), transcript);
        assert_eq!(
            std::fs::read_to_string(&fixture.annotation).unwrap(),
            annotation
        );
    }
}

#[test]
fn metadata_is_discovered_and_boundary_fallback_ignores_source_hooks() {
    let fixture = Fixture::new();
    fixture.write_sidecars();
    let connector = AntigravityConnector::new();
    let ctx = fixture.context(None);
    let discovered = connector.discover_source_files(&ctx).unwrap();
    assert!(!connector.supports_source_boundaries());
    let primary = discovered
        .iter()
        .find(|source| source.source_path == fixture.transcript)
        .unwrap();
    assert_eq!(primary.role, DiscoveredSourceRole::PrimarySessionLog);
    assert!(primary.required_for_reconstruction);
    for (path, role) in [
        (&fixture.annotation, DiscoveredSourceRole::MetadataSidecar),
        (&fixture.summary, DiscoveredSourceRole::SqliteDatabase),
        (&fixture.wal, DiscoveredSourceRole::MetadataSidecar),
    ] {
        let sidecar = discovered
            .iter()
            .find(|source| &source.source_path == path)
            .unwrap();
        assert_eq!(sidecar.role, role);
        assert!(!sidecar.required_for_reconstruction);
    }
    assert_eq!(discovered.len(), 4);
    let mut completed = 0;
    let mut visited = 0;
    let mut emitted = 0;
    {
        let mut should_scan = |_: &DiscoveredSourceFile| {
            visited += 1;
            false
        };
        let mut complete = |_: &SourceCompletion| {
            completed += 1;
            Ok(())
        };
        connector
            .scan_with_source_boundaries(
                &ctx,
                &mut SourceScanHooks {
                    should_scan_source: Some(&mut should_scan),
                    on_source_complete: Some(&mut complete),
                },
                &mut |conversation| {
                    assert_eq!(
                        conversation.title.as_deref(),
                        Some("Saved annotation title")
                    );
                    emitted += 1;
                    Ok(())
                },
            )
            .unwrap();
    }
    assert_eq!(emitted, 1);
    assert_eq!(visited, 0, "fallback must ignore the source veto");
    assert_eq!(completed, 0, "fallback must not invent a source receipt");
}

#[test]
fn metadata_changes_refresh_an_unchanged_transcript() {
    const OLD: u64 = 1_700_000_000_000;
    const SINCE: i64 = 1_700_000_005_000;
    const NEW: u64 = 1_700_000_010_000;

    for changed in ["annotation", "summary", "wal"] {
        let fixture = Fixture::new();
        fixture.write_sidecars();
        for path in [
            &fixture.transcript,
            &fixture.annotation,
            &fixture.summary,
            &fixture.wal,
        ] {
            set_modified(path, OLD);
        }
        let connector = AntigravityConnector::new();
        let ctx = fixture.context(Some(SINCE));
        assert!(connector.scan(&ctx).unwrap().is_empty());
        assert!(connector.discover_source_files(&ctx).unwrap().is_empty());
        let changed_path = match changed {
            "annotation" => &fixture.annotation,
            "summary" => &fixture.summary,
            "wal" => &fixture.wal,
            _ => unreachable!(),
        };
        set_modified(changed_path, NEW);
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1, "changed {changed}");
        assert_eq!(
            conversations[0].title.as_deref(),
            Some("Saved annotation title")
        );
        let sources = connector.discover_source_files(&ctx).unwrap();
        assert!(sources.iter().any(|s| s.source_path == fixture.transcript));
        assert!(sources.iter().any(|s| &s.source_path == changed_path));
    }
}

#[test]
fn newly_created_metadata_refreshes_an_unchanged_transcript() {
    const OLD: u64 = 1_700_000_000_000;
    const SINCE: i64 = 1_700_000_005_000;
    const NEW: u64 = 1_700_000_010_000;

    for created in ["annotation", "summary", "wal"] {
        let fixture = Fixture::new();
        set_modified(&fixture.transcript, OLD);
        if created == "wal" {
            std::fs::write(&fixture.summary, b"unavailable summary database").unwrap();
            set_modified(&fixture.summary, OLD);
        }
        let connector = AntigravityConnector::new();
        let ctx = fixture.context(Some(SINCE));
        assert!(connector.scan(&ctx).unwrap().is_empty());
        assert!(connector.discover_source_files(&ctx).unwrap().is_empty());
        let (created_path, contents) = match created {
            "annotation" => (&fixture.annotation, "title:\"New annotation title\"\n"),
            "summary" => (&fixture.summary, "new summary database"),
            "wal" => (&fixture.wal, "new summary wal"),
            _ => unreachable!(),
        };
        std::fs::write(created_path, contents).unwrap();
        set_modified(created_path, NEW);
        let mut conversations = Vec::new();
        connector
            .scan_with_source_boundaries(
                &ctx,
                &mut SourceScanHooks::default(),
                &mut |conversation| {
                    conversations.push(conversation);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(conversations.len(), 1, "created {created}");
        assert_eq!(
            conversations[0].title.as_deref(),
            Some(if created == "annotation" {
                "New annotation title"
            } else {
                PROMPT
            })
        );
        let sources = connector.discover_source_files(&ctx).unwrap();
        assert!(sources.iter().any(|s| s.source_path == fixture.transcript));
        assert!(sources.iter().any(|s| &s.source_path == created_path));
    }
}

#[test]
fn excluded_annotation_and_summary_wal_do_not_enter_metadata_or_sources() {
    let fixture = Fixture::new();
    fixture.write_sidecars();
    for (case, excluded) in [("annotation", &fixture.annotation), ("wal", &fixture.wal)] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "antigravity_metadata_exclusion_child",
                "--nocapture",
            ])
            .current_dir(fixture.root.path())
            .env(CHILD_ROOT, fixture.root.path())
            .env(CHILD_CASE, case)
            .env("CASS_EXCLUDE_PATHS", excluded)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "excluded {case}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
fn excluded_primary_suppresses_its_sidecars_and_excluded_full_cannot_trigger_refresh() {
    let fixture = Fixture::new();
    fixture.write_sidecars();
    let full = fixture.transcript.with_file_name("transcript_full.jsonl");
    std::fs::copy(&fixture.transcript, &full).unwrap();
    for path in [
        &fixture.transcript,
        &fixture.annotation,
        &fixture.summary,
        &fixture.wal,
    ] {
        set_modified(path, 1_700_000_000_000);
    }
    set_modified(&full, 1_700_000_010_000);
    for (case, excluded) in [("primary", &fixture.transcript), ("full", &full)] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "antigravity_metadata_exclusion_child",
                "--nocapture",
            ])
            .current_dir(fixture.root.path())
            .env(CHILD_ROOT, fixture.root.path())
            .env(CHILD_CASE, case)
            .env("CASS_EXCLUDE_PATHS", excluded)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn antigravity_metadata_exclusion_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT).map(PathBuf::from) else {
        return;
    };
    let case = std::env::var(CHILD_CASE).unwrap();
    if matches!(case.as_str(), "primary" | "full") {
        let since = (case == "full").then_some(1_700_000_005_000);
        let ctx = context(&root, since);
        let connector = AntigravityConnector::new();
        assert!(connector.discover_source_files(&ctx).unwrap().is_empty());
        assert!(connector.scan(&ctx).unwrap().is_empty());
        return;
    }
    let forbidden = match case.as_str() {
        "annotation" => vec![root.join("annotations").join(format!("{UUID}.pbtxt"))],
        "wal" => vec![
            root.join("conversation_summaries.db"),
            root.join("conversation_summaries.db-wal"),
        ],
        _ => panic!("unexpected exclusion case: {case}"),
    };
    let expected_title = if case == "annotation" {
        PROMPT
    } else {
        "Saved annotation title"
    };
    let ctx = context(&root, None);
    let connector = AntigravityConnector::new();
    let discovered = connector.discover_source_files(&ctx).unwrap();
    assert!(
        discovered
            .iter()
            .all(|s| !forbidden.contains(&s.source_path))
    );
    let conversations = connector.scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0].title.as_deref(), Some(expected_title));
    let mut completed = 0;
    let mut complete = |_: &SourceCompletion| {
        completed += 1;
        Ok(())
    };
    connector
        .scan_with_source_boundaries(
            &ctx,
            &mut SourceScanHooks {
                should_scan_source: None,
                on_source_complete: Some(&mut complete),
            },
            &mut |conversation| {
                assert_eq!(conversation.title.as_deref(), Some(expected_title));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(completed, 0);
}
