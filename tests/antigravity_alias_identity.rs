//! Physical ancestor aliases must share Antigravity source ownership.
#![cfg(all(feature = "connectors", unix))]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use franken_agent_detection::{
    AntigravityConnector, Connector, Origin, Platform, ScanContext, ScanRoot,
};
use serde_json::json;
use tempfile::TempDir;

const CHILD: &str = "11111111-2222-4333-8444-555555555555";
const PARENT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const OTHER: &str = "22222222-3333-4444-8555-666666666666";
const OLD: u64 = 1_700_000_000_000;
const SINCE: i64 = 1_700_000_005_000;
const NEW: u64 = 1_700_000_010_000;
const EXCLUSION_CHILD: &str = "FAD_ANTIGRAVITY_ALIAS_EXCLUSION_CHILD";

fn modified(path: &Path, millis: u64) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_millis(millis))
        .unwrap();
}

fn transcript(base: &Path, id: &str) -> PathBuf {
    let path = base
        .join("brain")
        .join(id)
        .join(".system_generated/logs/transcript.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let records = [
        json!({
            "step_index": 0, "source": "SYSTEM", "type": "SYSTEM_MESSAGE",
            "content": format!("[Message] sender={PARENT} content=Inspect the synthetic project"),
        }),
        json!({
            "step_index": 1, "source": "USER_EXPLICIT", "type": "USER_INPUT",
            "content": "Selected transcript",
        }),
        json!({
            "step_index": 2, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "model": "gemini-4-neon-high", "input_tokens": 7, "output_tokens": 3,
            "tool_calls": [{
                "id": "inspect-1",
                "name": "read_file",
                "args": {"Path": "/synthetic/file"}
            }],
        }),
    ];
    let lines: Vec<_> = records.iter().map(ToString::to_string).collect();
    fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
    modified(&path, OLD);
    path
}

fn annotation(base: &Path) -> PathBuf {
    let path = base.join("annotations").join(format!("{CHILD}.pbtxt"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "title: \"Selected annotation\"\n").unwrap();
    modified(&path, NEW);
    path
}

fn context(base: &Path, roots: Vec<ScanRoot>, since: Option<i64>) -> ScanContext {
    ScanContext::with_roots(base.to_path_buf(), roots, since)
}

fn qualified(path: &Path, source: &str) -> ScanRoot {
    ScanRoot::remote(
        path.to_path_buf(),
        Origin::remote("selected-host"),
        Some(Platform::Linux),
    )
    .with_mirrored_source_path(source)
}

#[test]
fn real_and_ancestor_symlink_roots_emit_one_history_and_preserve_exclusions() {
    let connector = AntigravityConnector::new();
    if let Some(directory) = std::env::var_os(EXCLUSION_CHILD) {
        let directory = PathBuf::from(directory);
        let roots = vec![
            ScanRoot::local(directory.join("real/.gemini/antigravity-cli")),
            ScanRoot::local(directory.join("alias/.gemini/antigravity-cli")),
        ];
        let ctx = context(&directory, roots, None);
        assert!(connector.scan(&ctx).unwrap().is_empty());
        assert!(connector.discover_source_files(&ctx).unwrap().is_empty());
        return;
    }

    let temp = TempDir::new().unwrap();
    let product = temp.path().join("real/.gemini/antigravity-cli");
    let primary = transcript(&product, CHILD);
    let original = fs::read(&primary).unwrap();
    annotation(&product);
    let full = primary.with_file_name("transcript_full.jsonl");
    fs::write(
        &full,
        json!({
            "step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT",
            "content": "Non-authoritative full sibling",
        })
        .to_string(),
    )
    .unwrap();
    modified(&full, OLD);
    symlink(temp.path().join("real"), temp.path().join("alias")).unwrap();
    let alias = temp.path().join("alias/.gemini/antigravity-cli");
    let alias_primary = alias.join(primary.strip_prefix(&product).unwrap());

    // A single ordinary selection retains its original path spelling.
    let ordinary = connector
        .scan(&context(
            temp.path(),
            vec![ScanRoot::local(product.clone())],
            None,
        ))
        .unwrap();
    assert_eq!(ordinary.len(), 1);
    assert_eq!(ordinary[0].source_path, primary);
    assert_eq!(ordinary[0].messages.len(), 3);

    for roots in [
        vec![
            ScanRoot::local(product.clone()),
            ScanRoot::local(alias.clone()),
        ],
        vec![
            ScanRoot::local(alias.clone()),
            ScanRoot::local(product.clone()),
        ],
    ] {
        let ctx = context(temp.path(), roots, None);
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(
            conversations.len(),
            1,
            "one physical transcript must produce one history"
        );
        let conversation = &conversations[0];
        assert_eq!(conversation.external_id.as_deref(), Some(CHILD));
        assert_eq!(conversation.messages.len(), 3);
        assert_eq!(conversation.messages[2].extra["usage"]["input_tokens"], 7);
        assert_eq!(conversation.messages[2].invocations.len(), 1);
        // Equal-priority roots already use lexical ordering. Identity keys
        // should not rewrite the selected source's locator or provenance.
        assert_eq!(conversation.source_path, alias_primary);
        let sources = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(sources.len(), 3, "primary, optional full sibling, annotation");
        assert!(
            sources
                .iter()
                .all(|source| source.source_path.starts_with(&alias))
        );
        assert_eq!(
            sources
                .iter()
                .filter(|source| source.required_for_reconstruction)
                .count(),
            1
        );
    }

    // Exclusion aliases already share canonical policy semantics. Keep that
    // independent of the source-ownership fix, in isolated subprocesses.
    for excluded in [&primary, &alias_primary] {
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("real_and_ancestor_symlink_roots_emit_one_history_and_preserve_exclusions")
            .arg("--nocapture")
            .env(EXCLUSION_CHILD, temp.path())
            .env("CASS_EXCLUDE_PATHS", excluded)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "exclusion subprocess failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(fs::read(&primary).unwrap(), original);
}

#[test]
fn qualified_owner_beats_structural_alias_before_freshness_and_deleted_events() {
    let temp = TempDir::new().unwrap();
    let product = temp.path().join("physical/payload");
    let primary = transcript(&product, CHILD);
    let title = annotation(&product);
    symlink(temp.path().join("physical"), temp.path().join("logical")).unwrap();
    let alias = temp.path().join("logical/payload");
    let structural = ScanRoot::remote(alias.clone(), Origin::remote("alias-host"), None);
    let whole = qualified(&product, "~/.gemini/antigravity/");
    let narrow = qualified(&product.join("brain"), "~/.gemini/antigravity/brain/");
    let connector = AntigravityConnector::new();

    for roots in [
        vec![structural.clone(), whole.clone()],
        vec![whole.clone(), structural.clone()],
    ] {
        let ctx = context(temp.path(), roots, None);
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(
            conversations.len(),
            1,
            "an alias must not create an unqualified duplicate"
        );
        assert_eq!(
            conversations[0].external_id.as_deref(),
            Some(format!("ide/{CHILD}").as_str())
        );
        assert_eq!(
            conversations[0].metadata["parent_conversation_id"],
            format!("ide/{PARENT}")
        );
        assert_eq!(conversations[0].source_path, primary);
        assert_eq!(
            conversations[0].title.as_deref(),
            Some("Selected annotation")
        );
        let sources = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(sources.len(), 2);
        assert!(sources.iter().all(|source| {
            source.origin == Origin::remote("selected-host")
                && source.platform == Some(Platform::Linux)
                && source.scan_root == product.join("brain")
                && source.source_path.starts_with(&product)
        }));
    }

    for roots in [
        vec![structural.clone(), narrow.clone()],
        vec![narrow.clone(), structural],
    ] {
        let full = context(temp.path(), roots.clone(), None);
        let conversations = connector.scan(&full).unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].source_path, primary);
        assert_eq!(
            conversations[0].title.as_deref(),
            Some("Selected transcript")
        );
        assert_eq!(connector.discover_source_files(&full).unwrap().len(), 1);
        let incremental = context(temp.path(), roots, Some(SINCE));
        assert!(connector.scan(&incremental).unwrap().is_empty());
        assert!(
            connector
                .discover_source_files(&incremental)
                .unwrap()
                .is_empty()
        );
    }

    fs::remove_file(title).unwrap();
    let removed_alias = alias.join("annotations").join(format!("{CHILD}.pbtxt"));
    let event = ScanRoot::remote(removed_alias, Origin::remote("alias-host"), None);
    for roots in [
        vec![whole.clone(), event.clone()],
        vec![event.clone(), whole],
    ] {
        let incremental = context(temp.path(), roots, Some(SINCE));
        let conversations = connector.scan(&incremental).unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(
            conversations[0].external_id.as_deref(),
            Some(format!("ide/{CHILD}").as_str())
        );
        assert_eq!(conversations[0].source_path, primary);
        let sources = connector.discover_source_files(&incremental).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].origin, Origin::remote("selected-host"));
        assert_eq!(sources[0].source_path, primary);
    }

    // The same missing path is outside a selected brain-only copy's ownership.
    let outside = context(temp.path(), vec![narrow, event], Some(SINCE));
    assert!(connector.scan(&outside).unwrap().is_empty());
    assert!(
        connector
            .discover_source_files(&outside)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn distinct_aliased_conversations_discover_each_shared_database_and_wal_once() {
    let temp = TempDir::new().unwrap();
    let product = temp.path().join("physical/payload");
    let primary = transcript(&product, CHILD);
    let other = transcript(&product, OTHER);
    let db = product.join("conversation_summaries.db");
    let wal = product.join("conversation_summaries.db-wal");
    // Remote roots preserve summary artifacts without opening optional SQLite.
    fs::write(&db, b"opaque summary database").unwrap();
    fs::write(&wal, b"opaque summary WAL").unwrap();
    symlink(temp.path().join("physical"), temp.path().join("logical")).unwrap();
    let alias = temp.path().join("logical/payload");
    let alias_other = alias.join(other.strip_prefix(&product).unwrap());
    let roots = [
        ScanRoot::remote(
            product.join("brain").join(CHILD),
            Origin::remote("shared-host"),
            None,
        ),
        ScanRoot::remote(
            alias.join("brain").join(OTHER),
            Origin::remote("shared-host"),
            None,
        ),
    ];
    let connector = AntigravityConnector::new();

    for ordered in [
        vec![roots[0].clone(), roots[1].clone()],
        vec![roots[1].clone(), roots[0].clone()],
    ] {
        let ctx = context(temp.path(), ordered, None);
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(
            conversations.len(),
            2,
            "distinct conversations remain distinct"
        );
        assert!(conversations.iter().any(|conv| conv.source_path == primary));
        assert!(
            conversations
                .iter()
                .any(|conv| conv.source_path == alias_other)
        );
        let sources = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(sources.len(), 4, "two transcripts and one shared DB/WAL pair");
        assert_eq!(
            sources
                .iter()
                .filter(|source| source.required_for_reconstruction)
                .count(),
            2
        );
        for name in ["conversation_summaries.db", "conversation_summaries.db-wal"] {
            assert_eq!(
                sources
                    .iter()
                    .filter(|source| {
                        source
                            .source_path
                            .file_name()
                            .is_some_and(|actual| actual == name)
                    })
                    .count(),
                1
            );
        }
    }
    assert_eq!(fs::read(&db).unwrap(), b"opaque summary database");
    assert_eq!(fs::read(&wal).unwrap(), b"opaque summary WAL");
}

#[test]
fn durable_wal_alias_events_preserve_selected_owner_even_after_parent_removal() {
    for remove_directory in [false, true] {
        let temp = TempDir::new().unwrap();
        let product = temp.path().join("physical/payload");
        let primary = transcript(&product, CHILD);
        let db = product.join("conversations").join(format!("{CHILD}.db"));
        let wal = db.with_extension("db-wal");
        fs::create_dir_all(db.parent().unwrap()).unwrap();
        fs::write(&db, b"opaque durable database").unwrap();
        fs::write(&wal, b"opaque durable WAL").unwrap();
        modified(&db, OLD);
        modified(&wal, OLD);
        let original = fs::read(&primary).unwrap();
        symlink(temp.path().join("physical"), temp.path().join("logical")).unwrap();
        let alias_wal = temp
            .path()
            .join("logical/payload/conversations")
            .join(format!("{CHILD}.db-wal"));
        let whole = qualified(&product, "~/.gemini/antigravity/");
        let narrow = qualified(&product.join("brain"), "~/.gemini/antigravity/brain/");
        let event = ScanRoot::remote(alias_wal, Origin::remote("event-host"), None);
        let connector = AntigravityConnector::new();
        let stale = context(
            temp.path(),
            vec![whole.clone(), event.clone()],
            Some(SINCE),
        );
        assert!(connector.scan(&stale).unwrap().is_empty());
        assert!(connector.discover_source_files(&stale).unwrap().is_empty());

        modified(&wal, NEW);
        for roots in [
            vec![whole.clone(), event.clone()],
            vec![event.clone(), whole.clone()],
        ] {
            let ctx = context(temp.path(), roots, Some(SINCE));
            let conversations = connector.scan(&ctx).unwrap();
            assert_eq!(conversations.len(), 1);
            assert_eq!(
                conversations[0].external_id.as_deref(),
                Some(format!("ide/{CHILD}").as_str())
            );
            assert_eq!(conversations[0].source_path, primary);
            let sources = connector.discover_source_files(&ctx).unwrap();
            assert_eq!(sources.len(), 3, "transcript and durable DB/WAL pair");
            assert!(sources.iter().all(|source| {
                source.origin == Origin::remote("selected-host")
                    && source.source_path.starts_with(&product)
            }));
        }
        modified(&wal, OLD);
        if remove_directory {
            fs::remove_dir_all(db.parent().unwrap()).unwrap();
        } else {
            fs::remove_file(&wal).unwrap();
        }

        for roots in [
            vec![whole.clone(), event.clone()],
            vec![event.clone(), whole.clone()],
        ] {
            let ctx = context(temp.path(), roots, Some(SINCE));
            let conversations = connector.scan(&ctx).unwrap();
            assert_eq!(conversations.len(), 1);
            assert_eq!(
                conversations[0].external_id.as_deref(),
                Some(format!("ide/{CHILD}").as_str())
            );
            assert_eq!(conversations[0].source_path, primary);
            let sources = connector.discover_source_files(&ctx).unwrap();
            assert_eq!(sources.len(), if remove_directory { 1 } else { 2 });
            assert!(sources.iter().all(|source| {
                source.origin == Origin::remote("selected-host")
                    && source.source_path.starts_with(&product)
            }));
        }
        let outside = context(temp.path(), vec![narrow, event], Some(SINCE));
        assert!(connector.scan(&outside).unwrap().is_empty());
        assert!(
            connector
                .discover_source_files(&outside)
                .unwrap()
                .is_empty()
        );
        assert_eq!(fs::read(&primary).unwrap(), original);
    }
}
