//! Qualified mirrors retain their selected source scope when optional metadata
//! or unrelated conversations happen to be present beside the copied source.
#![cfg(feature = "connectors")]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use franken_agent_detection::{AntigravityConnector, Connector, Origin, ScanContext, ScanRoot};
use tempfile::TempDir;

const CHILD: &str = "11111111-2222-4333-8444-555555555555";
const OTHER: &str = "22222222-3333-4444-8555-666666666666";
const OLD: u64 = 1_700_000_000_000;
const SINCE: i64 = 1_700_000_005_000;
const NEW: u64 = 1_700_000_010_000;

fn transcript_at(conversation: &Path, content: &str) -> PathBuf {
    let transcript = conversation.join(".system_generated/logs/transcript.jsonl");
    fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    fs::write(
        &transcript,
        serde_json::json!({
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "content": content,
        })
        .to_string(),
    )
    .unwrap();
    modified(&transcript, OLD);
    transcript
}

fn modified(path: &Path, millis: u64) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_millis(millis))
        .unwrap();
}

fn decoy_metadata(base: &Path, id: &str) {
    let annotation = base.join("annotations").join(format!("{id}.pbtxt"));
    fs::create_dir_all(annotation.parent().unwrap()).unwrap();
    fs::write(
        &annotation,
        b"title: \"Metadata outside the selected source\"\n",
    )
    .unwrap();
    let summary = base.join("conversation_summaries.db");
    let wal = base.join("conversation_summaries.db-wal");
    fs::write(&summary, b"unrelated optional summary database").unwrap();
    fs::write(&wal, b"unrelated optional WAL").unwrap();
    for path in [&annotation, &summary, &wal] {
        modified(path, NEW);
    }
}

fn context(container: &Path, source: &str, since: Option<i64>) -> ScanContext {
    ScanContext::with_roots(
        container.to_path_buf(),
        vec![
            ScanRoot::remote(
                container.to_path_buf(),
                Origin::remote("synthetic-antigravity-host"),
                None,
            )
            .with_mirrored_source_path(source),
        ],
        since,
    )
}

fn assert_only_selected_transcript(container: &Path, source: &str, transcript: &Path) {
    let connector = AntigravityConnector::new();
    let ctx = context(container, source, None);
    let conversations = connector.scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1, "{source}");
    assert_eq!(conversations[0].source_path, transcript);
    assert_eq!(
        conversations[0].title.as_deref(),
        Some("Selected transcript")
    );
    assert_eq!(
        conversations[0].external_id.as_deref(),
        Some(format!("ide/{CHILD}").as_str())
    );
    let sources = connector.discover_source_files(&ctx).unwrap();
    assert_eq!(sources.len(), 1, "{source}: {sources:?}");
    assert_eq!(sources[0].source_path, transcript);

    // New metadata outside the copied source must not make an old selected
    // transcript eligible for incremental replay or export.
    let incremental = context(container, source, Some(SINCE));
    assert!(connector.scan(&incremental).unwrap().is_empty(), "{source}");
    assert!(
        connector
            .discover_source_files(&incremental)
            .unwrap()
            .is_empty(),
        "{source}"
    );
}

#[test]
fn brain_only_mirrors_do_not_adopt_sibling_metadata_or_freshness() {
    for contents_only in [false, true] {
        let temp = TempDir::new().unwrap();
        // A contents-copy container may itself be named `brain`; that name is
        // not evidence that its parent owns provider sidecars.
        let container = temp
            .path()
            .join(if contents_only { "brain" } else { "opaque" });
        let selected_brain = if contents_only {
            container.clone()
        } else {
            container.join("brain")
        };
        let selected = transcript_at(&selected_brain.join(CHILD), "Selected transcript");
        decoy_metadata(selected_brain.parent().unwrap(), CHILD);
        transcript_at(
            &temp.path().join("unrelated/brain").join(OTHER),
            "Unselected sibling",
        );
        let source = format!(
            "~/.gemini/antigravity/brain{}",
            if contents_only { "/" } else { "" }
        );
        assert_only_selected_transcript(&container, &source, &selected);
    }
}

#[test]
fn conversation_only_mirrors_do_not_adopt_ancestor_metadata() {
    for contents_only in [false, true] {
        let temp = TempDir::new().unwrap();
        let container = temp.path().join("nested").join(if contents_only {
            "opaque_contents"
        } else {
            "brain"
        });
        let conversation = if contents_only {
            container.clone()
        } else {
            container.join(CHILD)
        };
        let selected = transcript_at(&conversation, "Selected transcript");
        let apparent_base = conversation.parent().unwrap().parent().unwrap();
        decoy_metadata(apparent_base, CHILD);
        // Also expose the physical basename used by historical guessing for
        // an opaque contents copy; neither spelling authorizes metadata.
        decoy_metadata(
            apparent_base,
            conversation.file_name().unwrap().to_str().unwrap(),
        );
        let source = format!(
            "~/.gemini/antigravity/brain/{CHILD}{}",
            if contents_only { "/" } else { "" }
        );
        assert_only_selected_transcript(&container, &source, &selected);
    }
}

fn unselected_sibling(container: &Path) {
    transcript_at(
        &container.join("unrelated/brain").join(OTHER),
        "A failed selection must not ingest this sibling",
    );
}

fn assert_rejected(container: &Path, source: &str) {
    let connector = AntigravityConnector::new();
    let ctx = context(container, source, None);
    assert!(connector.scan(&ctx).unwrap().is_empty(), "{source}");
    assert!(
        connector.discover_source_files(&ctx).unwrap().is_empty(),
        "{source}"
    );
}

#[test]
fn a_qualified_mirror_with_a_file_leaf_does_not_widen_to_its_container() {
    for slash in ["", "/"] {
        let temp = TempDir::new().unwrap();
        let container = temp.path().join("opaque");
        unselected_sibling(&container);
        fs::write(
            container.join(CHILD),
            b"a file is not the selected conversation directory",
        )
        .unwrap();
        assert_rejected(
            &container,
            &format!("~/.gemini/antigravity/brain/{CHILD}{slash}"),
        );
    }
}

#[test]
fn malformed_qualified_mirror_declarations_do_not_widen_to_the_container() {
    let temp = TempDir::new().unwrap();
    let container = temp.path().join("opaque");
    unselected_sibling(&container);
    transcript_at(&container.join(CHILD), "Selected transcript");
    for source in [
        format!("~/.gemini/antigravity/brain/../{CHILD}"),
        format!("~/.gemini/antigravity/brain/./{CHILD}"),
        format!("~/.gemini/antigravity/brain/\n{CHILD}"),
    ] {
        assert_rejected(&container, &source);
    }
}

#[cfg(unix)]
#[test]
fn a_qualified_mirror_with_a_symlink_leaf_does_not_widen_to_its_container() {
    use std::os::unix::fs::symlink;

    for target_exists in [false, true] {
        let temp = TempDir::new().unwrap();
        let container = temp.path().join("opaque");
        unselected_sibling(&container);
        let target = temp.path().join("outside");
        if target_exists {
            transcript_at(&target, "Unselected link target");
        }
        symlink(&target, container.join(CHILD)).unwrap();
        for slash in ["", "/"] {
            assert_rejected(
                &container,
                &format!("~/.gemini/antigravity/brain/{CHILD}{slash}"),
            );
        }
    }
}
