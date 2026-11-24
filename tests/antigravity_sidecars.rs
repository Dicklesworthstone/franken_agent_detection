//! Synthetic Antigravity metadata, watcher routing, and stock SQLite WAL cases.
#![cfg(feature = "connectors")]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use franken_agent_detection::{
    AntigravityConnector, Connector, NormalizedConversation, ScanContext, ScanRoot,
};
use tempfile::TempDir;

const UUID: &str = "11111111-2222-4333-8444-555555555555";
const OTHER: &str = "22222222-3333-4444-8555-666666666666";
const OLD: u64 = 1_700_000_000_000;
const SINCE: i64 = 1_700_000_005_000;
const NEW: u64 = 1_700_000_010_000;

fn transcript(base: &Path, id: &str) -> PathBuf {
    let path = base
        .join("brain")
        .join(id)
        .join(".system_generated/logs/transcript.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        "{\"step_index\":0,\"type\":\"USER_INPUT\",\"source\":\"USER_EXPLICIT\",\"content\":\"Synthetic prompt\"}\n",
    )
    .unwrap();
    path
}

fn context(root: &Path, since: Option<i64>) -> ScanContext {
    ScanContext::with_roots(
        root.to_path_buf(),
        vec![ScanRoot::local(root.to_path_buf())],
        since,
    )
}

fn scan(root: &Path, since: Option<i64>) -> Vec<NormalizedConversation> {
    AntigravityConnector::new()
        .scan(&context(root, since))
        .unwrap()
}

fn annotation(base: &Path, bytes: &[u8]) -> PathBuf {
    let path = base.join("annotations").join(format!("{UUID}.pbtxt"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    path
}

fn modified(path: &Path, millis: u64) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_millis(millis))
        .unwrap();
}

#[test]
fn exact_transcript_and_metadata_event_paths_resolve_their_owning_conversations() {
    let temp = TempDir::new().unwrap();
    let primary = transcript(temp.path(), UUID);
    transcript(temp.path(), OTHER);
    let full = primary.with_file_name("transcript_full.jsonl");
    fs::copy(&primary, &full).unwrap();
    let title = annotation(temp.path(), b"title: \"Changed title\"\n");
    for path in [&primary, &full, &title] {
        let conversations = scan(path, None);
        assert_eq!(conversations.len(), 1, "{}", path.display());
        assert_eq!(conversations[0].external_id.as_deref(), Some(UUID));
        assert_eq!(conversations[0].title.as_deref(), Some("Changed title"));
        let sources = AntigravityConnector::new()
            .discover_source_files(&context(path, None))
            .unwrap();
        assert!(sources.iter().any(|source| source.source_path == primary));
        assert!(
            !sources
                .iter()
                .any(|source| { source.source_path.to_string_lossy().contains(OTHER) })
        );
    }
    let summary = temp.path().join("conversation_summaries.db");
    let wal = temp.path().join("conversation_summaries.db-wal");
    fs::write(&summary, b"malformed optional database").unwrap();
    fs::write(&wal, b"malformed optional WAL").unwrap();
    for path in [&summary, &wal] {
        assert_eq!(
            scan(path, None).len(),
            2,
            "shared source {}",
            path.display()
        );
    }
}

#[test]
fn malformed_annotations_keep_the_transcript_and_valid_escaped_titles_survive() {
    let temp = TempDir::new().unwrap();
    let primary = transcript(temp.path(), UUID);
    let original = fs::read(&primary).unwrap();
    for bytes in [
        &b"title: \"bad\\qescape\"\n"[..],
        &b"title: \"bad\\777\"\n"[..],
        &b"title: \"unterminated"[..],
        &b"title: \"bad\xff\"\n"[..],
        &b"title: \"\"\n"[..],
    ] {
        let path = annotation(temp.path(), bytes);
        let conversations = scan(temp.path(), None);
        assert_eq!(conversations[0].title.as_deref(), Some("Synthetic prompt"));
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    annotation(temp.path(), b"title : \"caf\\303\\251 \\\"review\\\"\"\n");
    assert_eq!(
        scan(temp.path(), None)[0].title.as_deref(),
        Some("café \"review\"")
    );
    assert_eq!(fs::read(primary).unwrap(), original);
}

#[test]
fn targeted_annotation_event_reindexes_an_unchanged_transcript_once() {
    let temp = TempDir::new().unwrap();
    let primary = transcript(temp.path(), UUID);
    let title = annotation(temp.path(), b"title: \"Renamed\"\n");
    modified(&primary, OLD);
    modified(&title, OLD);
    assert!(scan(&title, Some(SINCE)).is_empty());
    modified(&title, NEW);
    let updated = scan(&title, Some(SINCE));
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].title.as_deref(), Some("Renamed"));
    assert!(scan(&title, Some(i64::try_from(NEW + 5_000).unwrap())).is_empty());
}

#[test]
fn removed_annotation_event_refreshes_the_fallback_title_without_a_fresh_mtime() {
    let temp = TempDir::new().unwrap();
    let primary = transcript(temp.path(), UUID);
    let title = annotation(temp.path(), b"title: \"Old annotation title\"\n");
    modified(&primary, OLD);
    modified(&title, OLD);
    assert_eq!(
        scan(temp.path(), None)[0].title.as_deref(),
        Some("Old annotation title")
    );
    fs::remove_file(&title).unwrap();
    let conversations = scan(&title, Some(SINCE));
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0].title.as_deref(), Some("Synthetic prompt"));
    let sources = AntigravityConnector::new()
        .discover_source_files(&context(&title, Some(SINCE)))
        .unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].source_path, primary);
    let overlapping = ScanContext::with_roots(
        temp.path().to_path_buf(),
        vec![
            ScanRoot::local(temp.path().to_path_buf()),
            ScanRoot::local(title),
        ],
        Some(SINCE),
    );
    let connector = AntigravityConnector::new();
    assert_eq!(connector.scan(&overlapping).unwrap().len(), 1);
    assert_eq!(
        connector.discover_source_files(&overlapping).unwrap().len(),
        1
    );
}

#[cfg(any(feature = "antigravity-sqlite", feature = "zcode"))]
mod sqlite {
    use super::*;
    use franken_agent_detection::{
        Origin,
        connectors::sqlite_sync::{Connection, ConnectionExt},
    };

    const PARENT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    fn copy_stock_wal(base: &Path) -> (PathBuf, PathBuf) {
        let db = base.join("conversation_summaries.db");
        let wal = base.join("conversation_summaries.db-wal");
        fs::write(&db, include_bytes!("fixtures/antigravity/summary-wal.db")).unwrap();
        fs::write(
            &wal,
            include_bytes!("fixtures/antigravity/summary-wal.db-wal"),
        )
        .unwrap();
        (db, wal)
    }

    #[test]
    fn stock_sqlite_wal_is_visible_read_only_and_refreshes_without_transcript_changes() {
        let temp = TempDir::new().unwrap();
        let primary = transcript(temp.path(), UUID);
        let (db, wal) = copy_stock_wal(temp.path());
        modified(&primary, OLD);
        modified(&db, OLD);
        modified(&wal, NEW);
        let before: Vec<_> = [&primary, &db, &wal]
            .into_iter()
            .map(|path| {
                (
                    path.clone(),
                    fs::read(path).unwrap(),
                    fs::metadata(path).unwrap().modified().unwrap(),
                )
            })
            .collect();
        let entries = fs::read_dir(temp.path()).unwrap().count();
        let conversations = scan(&wal, Some(SINCE));
        assert_eq!(conversations.len(), 1);
        assert_eq!(
            conversations[0].title.as_deref(),
            Some("Committed in stock SQLite WAL")
        );
        assert_eq!(
            conversations[0].workspace.as_deref(),
            Some(Path::new("/synthetic/work tree"))
        );
        assert_eq!(conversations[0].metadata["parent_conversation_id"], PARENT);
        for (path, bytes, mtime) in before {
            assert_eq!(fs::read(&path).unwrap(), bytes, "{}", path.display());
            assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), mtime);
        }
        assert_eq!(
            fs::read_dir(temp.path()).unwrap().count(),
            entries,
            "no new sidecars"
        );
        let rewritten = ScanContext::with_roots(
            temp.path().to_path_buf(),
            vec![ScanRoot::local(temp.path().to_path_buf()).with_rewrite("/synthetic", "/mapped")],
            None,
        );
        // Explicit mappings apply to local and remote roots alike, while
        // preserving the provider's original workspace in metadata.
        let rewritten_conversation = AntigravityConnector::new()
            .scan(&rewritten)
            .unwrap()
            .remove(0);
        assert_eq!(
            rewritten_conversation.workspace.as_deref(),
            Some(Path::new("/mapped/work tree"))
        );
        assert_eq!(
            rewritten_conversation.metadata["cass"]["workspace_original"],
            "/synthetic/work tree"
        );
    }

    #[test]
    fn older_summary_schema_and_bad_workspace_elements_do_not_erase_valid_metadata() {
        let temp = TempDir::new().unwrap();
        transcript(temp.path(), UUID);
        let db = temp.path().join("conversation_summaries.db");
        let conn = Connection::open(db.to_str().unwrap()).unwrap();
        conn.execute("CREATE TABLE conversation_summaries (conversation_id TEXT PRIMARY KEY, title TEXT, workspace_uris TEXT)").unwrap();
        conn.execute_compat(
            "INSERT INTO conversation_summaries VALUES (?1, 'Older schema title', ?2)",
            frankensqlite::params![
                UUID,
                "[null, 42, \"file:///bad%00\", \"file:///synthetic/valid%20path\"]"
            ],
        )
        .unwrap();
        drop(conn);
        let conversation = scan(temp.path(), None).remove(0);
        assert_eq!(conversation.title.as_deref(), Some("Older schema title"));
        assert_eq!(
            conversation.workspace.as_deref(),
            Some(Path::new("/synthetic/valid path"))
        );
        assert!(
            conversation
                .metadata
                .get("parent_conversation_id")
                .is_none()
        );
    }

    #[test]
    fn malformed_summary_parents_do_not_override_a_valid_system_sender() {
        let temp = TempDir::new().unwrap();
        let primary = transcript(temp.path(), UUID);
        fs::write(
            &primary,
            include_str!("fixtures/antigravity/child_transcript.jsonl"),
        )
        .unwrap();
        let db = temp.path().join("conversation_summaries.db");
        let conn = Connection::open(db.to_str().unwrap()).unwrap();
        conn.execute("CREATE TABLE conversation_summaries (conversation_id TEXT PRIMARY KEY, title TEXT, workspace_uris TEXT, parent_conversation_id TEXT)").unwrap();
        conn.execute_compat(
            "INSERT INTO conversation_summaries VALUES (?1, 'Summary title', NULL, ?2)",
            frankensqlite::params![UUID, "not-a-uuid"],
        )
        .unwrap();
        drop(conn);
        let conversation = scan(temp.path(), None).remove(0);
        assert_eq!(conversation.title.as_deref(), Some("Summary title"));
        assert_eq!(conversation.metadata["parent_conversation_id"], PARENT);
        assert_eq!(conversation.metadata["raw_parent_conversation_id"], PARENT);
    }

    #[test]
    fn remote_mirrors_keep_transcripts_and_annotations_but_do_not_read_sqlite() {
        let temp = TempDir::new().unwrap();
        transcript(temp.path(), UUID);
        annotation(temp.path(), b"title: \"Portable annotation\"\n");
        let (db, wal) = copy_stock_wal(temp.path());
        let before_db = fs::read(&db).unwrap();
        let before_wal = fs::read(&wal).unwrap();
        let ctx = ScanContext::with_roots(
            temp.path().to_path_buf(),
            vec![ScanRoot::remote(
                temp.path().to_path_buf(),
                Origin::remote("synthetic-host"),
                None,
            )],
            None,
        );
        let conversations = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(
            conversations[0].title.as_deref(),
            Some("Portable annotation")
        );
        assert!(conversations[0].workspace.is_none());
        assert!(
            conversations[0]
                .metadata
                .get("parent_conversation_id")
                .is_none()
        );
        assert_eq!(fs::read(db).unwrap(), before_db);
        assert_eq!(fs::read(wal).unwrap(), before_wal);
    }

    #[test]
    fn corrupt_summaries_do_not_override_annotation_or_transcript_data() {
        let temp = TempDir::new().unwrap();
        transcript(temp.path(), UUID);
        annotation(temp.path(), b"title: \"Valid title\"\n");
        let db = temp.path().join("conversation_summaries.db");
        fs::write(&db, b"not sqlite").unwrap();
        let conversation = scan(temp.path(), None).remove(0);
        assert_eq!(conversation.title.as_deref(), Some("Valid title"));
        assert_eq!(conversation.messages[0].content, "Synthetic prompt");
        assert!(conversation.workspace.is_none());
        assert_eq!(fs::read(db).unwrap(), b"not sqlite");
    }
}
