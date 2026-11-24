//! Durable Antigravity SQLite artifacts are mirrored without being opened.
//! The transcript remains the normalized source; DB and WAL changes refresh it.
#![cfg(feature = "connectors")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use franken_agent_detection::{
    AntigravityConnector, Connector, DiscoveredSourceRole, Origin, Platform, ScanContext, ScanRoot,
};
use tempfile::TempDir;

const UUID: &str = "11111111-2222-4333-8444-555555555555";
const OTHER: &str = "22222222-3333-4444-8555-666666666666";
const OLD: u64 = 1_700_000_000_000;
const SINCE: i64 = 1_700_000_005_000;
const NEW: u64 = 1_700_000_010_000;
const CHILD_ROOT: &str = "FAD_ANTIGRAVITY_DURABLE_ROOT";
const CHILD_CASE: &str = "FAD_ANTIGRAVITY_DURABLE_CASE";

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
    fs::write(
        &path,
        concat!(
            "{\"step_index\":0,\"type\":\"USER_INPUT\",\"source\":\"USER_EXPLICIT\",",
            "\"content\":\"Transcript remains authoritative\"}\n",
            "{\"step_index\":1,\"type\":\"PLANNER_RESPONSE\",\"source\":\"AGENT\",",
            "\"content\":\"Synthetic answer\"}\n",
        ),
    )
    .unwrap();
    modified(&path, OLD);
    path
}

fn durable_pair(base: &Path, id: &str) -> (PathBuf, PathBuf) {
    let db = base.join("conversations").join(format!("{id}.db"));
    let wal = db.with_extension("db-wal");
    fs::create_dir_all(db.parent().unwrap()).unwrap();
    // Reuse stock SQLite/WAL bytes: the durable payload's schema is irrelevant
    // because discovery and normalization must not open these databases.
    fs::write(&db, include_bytes!("fixtures/antigravity/summary-wal.db")).unwrap();
    fs::write(
        &wal,
        include_bytes!("fixtures/antigravity/summary-wal.db-wal"),
    )
    .unwrap();
    modified(&db, OLD);
    modified(&wal, OLD);
    (db, wal)
}

fn context(base: &Path, roots: Vec<ScanRoot>, since: Option<i64>) -> ScanContext {
    ScanContext::with_roots(base.to_path_buf(), roots, since)
}

fn local(path: &Path, since: Option<i64>) -> ScanContext {
    context(path, vec![ScanRoot::local(path.to_path_buf())], since)
}

fn mirrored(path: &Path, original: &str) -> ScanRoot {
    ScanRoot::remote(
        path.to_path_buf(),
        Origin::remote("durable-host"),
        Some(Platform::Linux),
    )
    .with_mirrored_source_path(original)
}

fn assert_paths(ctx: &ScanContext, expected: &[&Path]) {
    let mut actual: Vec<_> = AntigravityConnector::new()
        .discover_source_files(ctx)
        .unwrap()
        .into_iter()
        .map(|source| source.source_path)
        .collect();
    let mut expected: Vec<_> = expected.iter().map(|path| path.to_path_buf()).collect();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
}

fn assert_empty(ctx: &ScanContext) {
    assert!(AntigravityConnector::new().scan(ctx).unwrap().is_empty());
    assert_paths(ctx, &[]);
}

#[test]
fn complete_durable_pair_is_optional_and_does_not_change_or_mutate_transcript_ingestion() {
    let temp = TempDir::new().unwrap();
    let primary = transcript(temp.path(), UUID);
    let full = primary.with_file_name("transcript_full.jsonl");
    fs::write(
        &full,
        "{\"step_index\":0,\"type\":\"USER_INPUT\",\"content\":\"Duplicate full transcript\"}\n",
    )
    .unwrap();
    modified(&full, OLD);
    let ctx = local(temp.path(), None);
    let connector = AntigravityConnector::new();
    let before = serde_json::to_value(connector.scan(&ctx).unwrap()).unwrap();
    let (db, wal) = durable_pair(temp.path(), UUID);

    // Cover a valid SQLite pair and opaque/corrupt provider data without
    // depending on the optional summary-SQLite feature.
    for opaque in [false, true] {
        if opaque {
            fs::write(&db, b"\xffopaque provider protobuf database").unwrap();
            fs::write(&wal, b"\xffopaque provider WAL").unwrap();
            modified(&db, OLD);
            modified(&wal, OLD);
        }
        let snapshot: Vec<_> = [&primary, &full, &db, &wal]
            .into_iter()
            .map(|path| {
                (
                    path,
                    fs::read(path).unwrap(),
                    fs::metadata(path).unwrap().modified().unwrap(),
                )
            })
            .collect();
        assert_paths(&ctx, &[&primary, &full, &db, &wal]);
        let sources = connector.discover_source_files(&ctx).unwrap();
        for (path, role) in [
            (&db, DiscoveredSourceRole::SqliteDatabase),
            (&wal, DiscoveredSourceRole::MetadataSidecar),
        ] {
            let source = sources
                .iter()
                .find(|source| &source.source_path == path)
                .unwrap();
            assert_eq!(source.role, role);
            assert!(!source.required_for_reconstruction);
            assert_eq!(source.size_bytes, Some(fs::metadata(path).unwrap().len()));
            assert_eq!(source.modified_at_ms, Some(i64::try_from(OLD).unwrap()));
        }
        assert_eq!(
            serde_json::to_value(connector.scan(&ctx).unwrap()).unwrap(),
            before
        );
        for (path, bytes, mtime) in snapshot {
            assert_eq!(fs::read(path).unwrap(), bytes);
            assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), mtime);
        }
        assert_eq!(fs::read_dir(db.parent().unwrap()).unwrap().count(), 2);
        assert!(!db.with_extension("db-shm").exists());
        assert!(!db.with_extension("db-journal").exists());
    }
}

#[test]
fn durable_db_and_wal_changes_or_creation_refresh_only_their_conversation() {
    for changed in ["db", "wal"] {
        let temp = TempDir::new().unwrap();
        let primary = transcript(temp.path(), UUID);
        transcript(temp.path(), OTHER);
        let (db, wal) = durable_pair(temp.path(), UUID);
        durable_pair(temp.path(), OTHER);
        let ctx = local(temp.path(), Some(SINCE));
        assert_empty(&ctx);

        let path = if changed == "db" { &db } else { &wal };
        modified(path, NEW);
        let conversations = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1, "{changed}");
        assert_eq!(conversations[0].source_path, primary);
        assert_paths(&ctx, &[&primary, &db, &wal]);

        let bytes = fs::read(path).unwrap();
        fs::remove_file(path).unwrap();
        assert_empty(&ctx);
        fs::write(path, bytes).unwrap();
        modified(path, NEW);
        assert_eq!(AntigravityConnector::new().scan(&ctx).unwrap().len(), 1);
        assert_paths(&ctx, &[&primary, &db, &wal]);
    }
}

#[test]
fn durable_exact_and_removed_events_select_one_conversation_and_preserve_full_only_fallback() {
    for full_only in [false, true] {
        for removed in ["db", "wal"] {
            let temp = TempDir::new().unwrap();
            let primary = transcript(temp.path(), UUID);
            let selected = if full_only {
                let full = primary.with_file_name("transcript_full.jsonl");
                fs::rename(primary, &full).unwrap();
                full
            } else {
                primary
            };
            transcript(temp.path(), OTHER);
            let (db, wal) = durable_pair(temp.path(), UUID);
            durable_pair(temp.path(), OTHER);
            for event in [&db, &wal] {
                assert_empty(&local(event, Some(SINCE)));
                let ctx = local(event, None);
                let conversations = AntigravityConnector::new().scan(&ctx).unwrap();
                assert_eq!(conversations.len(), 1);
                assert_eq!(conversations[0].source_path, selected);
                assert_paths(&ctx, &[&selected, &db, &wal]);
            }

            let event = if removed == "db" { &db } else { &wal };
            fs::remove_file(event).unwrap();
            let ctx = local(event, Some(SINCE));
            let conversations = AntigravityConnector::new().scan(&ctx).unwrap();
            assert_eq!(
                conversations.len(),
                1,
                "removed {removed}, full_only={full_only}"
            );
            assert_eq!(conversations[0].source_path, selected);
            assert_eq!(conversations[0].external_id.as_deref(), Some(UUID));
            if removed == "db" {
                // Match summary-pair discovery: an orphan WAL is not a
                // reconstructable pair, but its DB deletion still refreshes.
                assert_paths(&ctx, &[&selected]);
            } else {
                assert_paths(&ctx, &[&selected, &db]);
            }
            // Directory scans cannot infer deletions from unchanged files.
            assert_empty(&local(temp.path(), Some(SINCE)));
        }
    }

    let temp = TempDir::new().unwrap();
    transcript(temp.path(), UUID);
    for event in [
        temp.path().join(format!("{UUID}.db")),
        temp.path().join("unrelated").join(format!("{UUID}.db-wal")),
        temp.path()
            .join("conversations")
            .join(format!("{UUID}.db-shm")),
        temp.path()
            .join("conversations")
            .join(format!("{UUID}.db-journal")),
    ] {
        assert_empty(&local(&event, None));
    }
}

#[test]
fn product_mirrors_keep_durable_pairs_and_exact_event_identity() {
    for (product, layout, external) in [
        ("antigravity", "ide", format!("ide/{UUID}")),
        ("antigravity-cli", "cli", UUID.to_string()),
    ] {
        for preserve_basename in [false, true] {
            let temp = TempDir::new().unwrap();
            let transport = temp.path().join("opaque_transport");
            let base = if preserve_basename {
                transport.join(product)
            } else {
                transport.clone()
            };
            let primary = transcript(&base, UUID);
            transcript(&base, OTHER);
            let (db, wal) = durable_pair(&base, UUID);
            let original = format!("~/.gemini/{product}/");
            modified(&wal, NEW);
            let ctx = context(
                temp.path(),
                vec![mirrored(&transport, &original)],
                Some(SINCE),
            );
            assert_paths(&ctx, &[&primary, &db, &wal]);
            let conversations = AntigravityConnector::new().scan(&ctx).unwrap();
            assert_eq!(conversations.len(), 1);
            assert_eq!(
                conversations[0].external_id.as_deref(),
                Some(external.as_str())
            );
            assert_eq!(conversations[0].metadata["layout"], layout);
            for source in AntigravityConnector::new()
                .discover_source_files(&ctx)
                .unwrap()
            {
                assert_eq!(source.origin, Origin::remote("durable-host"));
                assert_eq!(source.platform, Some(Platform::Linux));
            }

            for event in [&db, &wal] {
                let targeted = context(temp.path(), vec![mirrored(event, &original)], Some(SINCE));
                assert_paths(&targeted, &[&primary, &db, &wal]);
                let conversations = AntigravityConnector::new().scan(&targeted).unwrap();
                assert_eq!(conversations.len(), 1);
                assert_eq!(
                    conversations[0].external_id.as_deref(),
                    Some(external.as_str())
                );
            }
            modified(&wal, OLD);
            for event in [&db, &wal] {
                let bytes = fs::read(event).unwrap();
                fs::remove_file(event).unwrap();
                let removed = context(temp.path(), vec![mirrored(event, &original)], Some(SINCE));
                if event == &db {
                    assert_paths(&removed, &[&primary]);
                } else {
                    assert_paths(&removed, &[&primary, &db]);
                }
                let conversations = AntigravityConnector::new().scan(&removed).unwrap();
                assert_eq!(conversations.len(), 1);
                assert_eq!(
                    conversations[0].external_id.as_deref(),
                    Some(external.as_str())
                );
                fs::write(event, bytes).unwrap();
                modified(event, OLD);
            }
        }
    }
}

#[test]
fn partial_mirrors_cannot_adopt_or_be_refreshed_by_outside_durable_artifacts() {
    for scope in ["brain", "conversation"] {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("opaque_transport");
        let primary = transcript(&base, UUID);
        let (db, wal) = durable_pair(&base, UUID);
        modified(&wal, NEW);
        let (path, original) = if scope == "brain" {
            (
                base.join("brain"),
                "~/.gemini/antigravity/brain/".to_string(),
            )
        } else {
            (
                base.join("brain").join(UUID),
                format!("~/.gemini/antigravity/brain/{UUID}/"),
            )
        };
        let narrow = mirrored(&path, &original);
        let broad = ScanRoot::local(base.clone());
        for roots in [
            vec![narrow.clone()],
            vec![broad.clone(), narrow.clone()],
            vec![narrow.clone(), broad.clone()],
        ] {
            assert_paths(&context(temp.path(), roots.clone(), None), &[&primary]);
            assert_empty(&context(temp.path(), roots, Some(SINCE)));
        }
        for event in [&db, &wal] {
            assert_empty(&context(
                temp.path(),
                vec![mirrored(event, &original)],
                None,
            ));
        }

        // A broader deletion event is change evidence only if the selected
        // owner includes that artifact in its declared copied scope.
        fs::remove_file(&wal).unwrap();
        for roots in [
            vec![broad.clone(), narrow.clone(), ScanRoot::local(wal.clone())],
            vec![ScanRoot::local(wal.clone()), narrow.clone(), broad.clone()],
        ] {
            assert_empty(&context(temp.path(), roots, Some(SINCE)));
        }
    }
}

#[test]
fn excluding_either_durable_member_excludes_the_pair_without_losing_the_transcript() {
    let temp = TempDir::new().unwrap();
    transcript(temp.path(), UUID);
    let (db, wal) = durable_pair(temp.path(), UUID);
    modified(&db, NEW);
    modified(&wal, NEW);
    for (case, excluded) in [
        ("db", db.clone()),
        ("wal", wal.clone()),
        ("directory", temp.path().join("conversations")),
        ("control", temp.path().join("unrelated")),
    ] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "antigravity_durable_exclusion_child",
                "--nocapture",
            ])
            .current_dir(temp.path())
            .env(CHILD_ROOT, temp.path())
            .env(CHILD_CASE, case)
            .env("CASS_EXCLUDE_PATHS", excluded)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
fn antigravity_durable_exclusion_child() {
    let Some(base) = std::env::var_os(CHILD_ROOT).map(PathBuf::from) else {
        return;
    };
    let case = std::env::var(CHILD_CASE).unwrap();
    let primary = base
        .join("brain")
        .join(UUID)
        .join(".system_generated/logs/transcript.jsonl");
    let db = base.join("conversations").join(format!("{UUID}.db"));
    let wal = db.with_extension("db-wal");
    let ctx = local(&base, None);
    let conversations = AntigravityConnector::new().scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(
        conversations[0].title.as_deref(),
        Some("Transcript remains authoritative")
    );
    if case == "control" {
        assert_paths(&ctx, &[&primary, &db, &wal]);
        assert_eq!(
            AntigravityConnector::new()
                .scan(&local(&base, Some(SINCE)))
                .unwrap()
                .len(),
            1
        );
        return;
    }
    assert_paths(&ctx, &[&primary]);
    assert_empty(&local(&base, Some(SINCE)));
    for event in [&db, &wal] {
        assert_empty(&local(event, Some(SINCE)));
    }

    // An excluded pair cannot force a refresh through a deletion event either.
    // Each child recreates its own event after checking it, so cases stay isolated.
    let bytes = fs::read(&wal).unwrap();
    fs::remove_file(&wal).unwrap();
    assert_empty(&local(&wal, Some(SINCE)));
    fs::write(&wal, bytes).unwrap();
    modified(&wal, NEW);
}
