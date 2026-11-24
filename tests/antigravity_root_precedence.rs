//! Overlapping scan roots must not change a copied conversation's identity or
//! broaden the metadata scope of its explicitly selected provider source.
#![cfg(feature = "connectors")]

use std::fs;
use std::path::{Path, PathBuf};
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

fn transcript(conversation: &Path) -> PathBuf {
    let path = conversation.join(".system_generated/logs/transcript.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let records = [
        json!({
            "step_index": 0,
            "source": "SYSTEM",
            "type": "SYSTEM_MESSAGE",
            "content": format!("[Message] sender={PARENT} content=Inspect the synthetic project"),
        }),
        json!({
            "step_index": 1,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "content": "Selected transcript",
        }),
    ];
    let lines: Vec<_> = records.iter().map(ToString::to_string).collect();
    fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
    modified(&path, OLD);
    path
}

fn annotation(base: &Path, title: &str) -> PathBuf {
    let path = base.join("annotations").join(format!("{CHILD}.pbtxt"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, format!("title: \"{title}\"\n")).unwrap();
    modified(&path, NEW);
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

fn broad(path: &Path) -> ScanRoot {
    ScanRoot::remote(path.to_path_buf(), Origin::remote("broad-host"), None)
        .with_rewrite("/synthetic", "/broad")
}

fn qualified(path: &Path, source: &str) -> ScanRoot {
    ScanRoot::remote(
        path.to_path_buf(),
        Origin::remote("selected-host"),
        Some(Platform::Linux),
    )
    .with_mirrored_source_path(source)
    .with_rewrite("/synthetic", "/selected")
}

fn context(base: &Path, roots: Vec<ScanRoot>, since: Option<i64>) -> ScanContext {
    ScanContext::with_roots(base.to_path_buf(), roots, since)
}

#[test]
fn qualified_mirror_identity_and_provenance_win_over_an_overlapping_broad_root() {
    let temp = TempDir::new().unwrap();
    let product = temp.path().join("opaque_transport");
    let primary = transcript(&product.join("brain").join(CHILD));
    let title = annotation(&product, "Selected IDE title");
    let sibling = transcript(&temp.path().join("other/brain").join(OTHER));
    let specific = qualified(&product, "~/.gemini/antigravity/");
    let broad = broad(temp.path());
    let connector = AntigravityConnector::new();

    let selected = connector
        .scan(&context(temp.path(), vec![specific.clone()], None))
        .unwrap()
        .remove(0);
    assert_eq!(selected.external_id.as_deref(), Some(format!("ide/{CHILD}").as_str()));

    for roots in [
        vec![broad.clone(), specific.clone()],
        vec![specific.clone(), broad.clone()],
    ] {
        let ctx = context(temp.path(), roots, None);
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 2, "nonoverlapping broad-root history survives");
        let child = conversations.iter().find(|c| c.source_path == primary).unwrap();
        assert_eq!(child.external_id, selected.external_id);
        assert_eq!(child.metadata["parent_conversation_id"], format!("ide/{PARENT}"));
        assert_eq!(child.metadata["layout"], "ide");
        assert_eq!(child.title.as_deref(), Some("Selected IDE title"));

        // This is the shared ScanContext mapping policy for the same source.
        // Antigravity's owning root should agree for metadata and provenance.
        let mut mapped = child.clone();
        mapped.workspace = Some(PathBuf::from("/synthetic/project"));
        ctx.apply_workspace_rewrite_for_path(&primary, &mut mapped);
        assert_eq!(mapped.workspace.as_deref(), Some(Path::new("/selected/project")));

        let sources = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(sources.len(), 3, "two transcripts and one annotation");
        for source in &sources {
            if source.source_path == primary || source.source_path == title {
                assert_eq!(source.origin, Origin::remote("selected-host"));
                assert_eq!(source.platform, Some(Platform::Linux));
                assert_eq!(source.scan_root, product.join("brain"));
            } else {
                assert_eq!(source.source_path, sibling);
                assert_eq!(source.origin, Origin::remote("broad-host"));
            }
        }
    }
}

#[test]
fn qualified_context_wins_equal_resolved_paths_in_either_input_order() {
    let temp = TempDir::new().unwrap();
    let product = temp.path().join("opaque_transport");
    let primary = transcript(&product.join("brain").join(CHILD));
    let specific = qualified(&product, "~/.gemini/antigravity/");
    let structural = broad(&product.join("brain"));
    let connector = AntigravityConnector::new();

    for roots in [
        vec![structural.clone(), specific.clone()],
        vec![specific.clone(), structural.clone()],
    ] {
        let ctx = context(temp.path(), roots, None);
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(
            conversations[0].external_id.as_deref(),
            Some(format!("ide/{CHILD}").as_str())
        );
        let sources = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source_path, primary);
        assert_eq!(sources[0].origin, Origin::remote("selected-host"));
        assert_eq!(sources[0].platform, Some(Platform::Linux));
    }
}

#[test]
fn broader_fresh_metadata_cannot_replay_or_enrich_a_narrow_brain_copy() {
    let temp = TempDir::new().unwrap();
    let product = temp.path().join("opaque_transport");
    let brain = product.join("brain");
    let primary = transcript(&brain.join(CHILD));
    annotation(&product, "Outside the copied brain");
    let narrow = qualified(&brain, "~/.gemini/antigravity/brain/");
    let broad = broad(&product);
    let connector = AntigravityConnector::new();

    let selected = context(temp.path(), vec![narrow.clone()], Some(SINCE));
    assert!(connector.scan(&selected).unwrap().is_empty());
    assert!(connector.discover_source_files(&selected).unwrap().is_empty());

    for roots in [
        vec![broad.clone(), narrow.clone()],
        vec![narrow.clone(), broad.clone()],
    ] {
        let full = context(temp.path(), roots.clone(), None);
        let conversations = connector.scan(&full).unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].title.as_deref(), Some("Selected transcript"));
        assert_eq!(
            conversations[0].external_id.as_deref(),
            Some(format!("ide/{CHILD}").as_str())
        );
        let sources = connector.discover_source_files(&full).unwrap();
        assert_eq!(sources.len(), 1, "outside metadata must not become a dependency");
        assert_eq!(sources[0].source_path, primary);

        // Ownership must be selected before freshness filtering. Merely visiting
        // the narrow root first lets this stale source fall through to the broad
        // root, which would use the fresh annotation outside its selected scope.
        let incremental = context(temp.path(), roots, Some(SINCE));
        assert!(connector.scan(&incremental).unwrap().is_empty());
        assert!(
            connector
                .discover_source_files(&incremental)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn narrower_original_scope_wins_when_configured_and_resolved_paths_are_equal() {
    let temp = TempDir::new().unwrap();
    let product = temp.path().join("opaque_transport");
    let primary = transcript(&product.join("brain").join(CHILD));
    let title = annotation(&product, "Outside the copied brain");
    // These declarations have the same configured local container and resolve
    // to the same local brain directory. Only the original source identifies
    // which copy owns the surrounding product metadata.
    let whole_product = qualified(&product, "~/.gemini/antigravity/");
    let only_brain = qualified(&product, "~/.gemini/antigravity/brain");
    let connector = AntigravityConnector::new();

    for roots in [
        vec![whole_product.clone(), only_brain.clone()],
        vec![only_brain.clone(), whole_product.clone()],
    ] {
        let full = context(temp.path(), roots.clone(), None);
        let conversations = connector.scan(&full).unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].title.as_deref(), Some("Selected transcript"));
        assert!(conversations[0].metadata.get("data_root").is_none());
        let sources = connector.discover_source_files(&full).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source_path, primary);
        let incremental = context(temp.path(), roots, Some(SINCE));
        assert!(connector.scan(&incremental).unwrap().is_empty());
        assert!(
            connector
                .discover_source_files(&incremental)
                .unwrap()
                .is_empty()
        );
    }

    fs::remove_file(&title).unwrap();
    let outside_deletion = context(
        temp.path(),
        vec![whole_product, only_brain, broad(&title)],
        Some(SINCE),
    );
    assert!(connector.scan(&outside_deletion).unwrap().is_empty());
    assert!(
        connector
            .discover_source_files(&outside_deletion)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn owned_annotation_deletion_refreshes_the_qualified_source_with_its_identity() {
    for full_only in [false, true] {
        let temp = TempDir::new().unwrap();
        let product = temp.path().join("opaque_transport");
        let primary = transcript(&product.join("brain").join(CHILD));
        let selected_transcript = if full_only {
            let full = primary.with_file_name("transcript_full.jsonl");
            fs::rename(primary, &full).unwrap();
            full
        } else {
            primary
        };
        let title = annotation(&product, "Previous annotation title");
        fs::remove_file(&title).unwrap();
        let specific = qualified(&product, "~/.gemini/antigravity/");
        let event = broad(&title);
        let connector = AntigravityConnector::new();
        assert!(
            connector
                .scan(&context(temp.path(), vec![specific.clone()], Some(SINCE)))
                .unwrap()
                .is_empty()
        );

        for roots in [
            vec![specific.clone(), event.clone()],
            vec![event.clone(), specific.clone()],
        ] {
            let ctx = context(temp.path(), roots, Some(SINCE));
            let conversations = connector.scan(&ctx).unwrap();
            assert_eq!(conversations.len(), 1);
            let child = &conversations[0];
            assert_eq!(
                child.external_id.as_deref(),
                Some(format!("ide/{CHILD}").as_str())
            );
            assert_eq!(
                child.metadata["parent_conversation_id"],
                format!("ide/{PARENT}")
            );
            assert_eq!(child.source_path, selected_transcript);
            assert_eq!(child.title.as_deref(), Some("Selected transcript"));
            let sources = connector.discover_source_files(&ctx).unwrap();
            assert_eq!(sources.len(), 1);
            assert_eq!(sources[0].source_path, selected_transcript);
            assert_eq!(sources[0].origin, Origin::remote("selected-host"));
            assert_eq!(sources[0].scan_root, product.join("brain"));
        }
    }
}

#[test]
fn structural_metadata_events_do_not_replace_containing_root_provenance() {
    let temp = TempDir::new().unwrap();
    let product = temp.path().join("ordinary_store");
    let primary = transcript(&product.join("brain").join(CHILD));
    let title = annotation(&product, "Selected annotation");
    let directory = ScanRoot::remote(
        product.clone(),
        Origin::remote("directory-host"),
        Some(Platform::Linux),
    )
    .with_rewrite("/synthetic", "/directory");
    let event = ScanRoot::remote(title, Origin::remote("event-host"), None)
        .with_rewrite("/synthetic", "/event");
    let connector = AntigravityConnector::new();

    for roots in [
        vec![directory.clone(), event.clone()],
        vec![event.clone(), directory.clone()],
    ] {
        let ctx = context(temp.path(), roots, Some(SINCE));
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].title.as_deref(), Some("Selected annotation"));
        let mut mapped = conversations[0].clone();
        mapped.workspace = Some(PathBuf::from("/synthetic/project"));
        ctx.apply_workspace_rewrite_for_path(&primary, &mut mapped);
        assert_eq!(
            mapped.workspace.as_deref(),
            Some(Path::new("/directory/project"))
        );
        let sources = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(sources.len(), 2);
        for source in sources {
            assert_eq!(source.origin, Origin::remote("directory-host"));
            assert_eq!(source.platform, Some(Platform::Linux));
            assert_eq!(source.scan_root, product);
        }
    }
}
