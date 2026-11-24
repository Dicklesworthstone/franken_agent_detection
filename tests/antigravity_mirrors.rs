//! Provider-shaped SSH mirrors preserve both products and their logical IDs.
#![cfg(feature = "connectors")]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use franken_agent_detection::{
    AntigravityConnector, Connector, NormalizedConversation, Origin, Platform, ScanContext,
    ScanRoot,
};
use serde_json::json;
use tempfile::TempDir;

const CHILD: &str = "11111111-2222-4333-8444-555555555555";
const PARENT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const OTHER: &str = "22222222-3333-4444-8555-666666666666";
const CHILD_TRANSCRIPT: &str = include_str!("fixtures/antigravity/child_transcript.jsonl");

fn transcript(conversation_dir: &Path, content: &str) -> PathBuf {
    let path = conversation_dir.join(".system_generated/logs/transcript.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, content).unwrap();
    path
}

fn parent_transcript() -> String {
    json!({
        "step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT",
        "content": "Synthetic parent conversation",
    })
    .to_string()
}

fn store(base: &Path, title: &str) -> PathBuf {
    transcript(&base.join("brain").join(PARENT), &parent_transcript());
    let child = transcript(&base.join("brain").join(CHILD), CHILD_TRANSCRIPT);
    let annotation = base.join("annotations").join(format!("{CHILD}.pbtxt"));
    fs::create_dir_all(annotation.parent().unwrap()).unwrap();
    fs::write(annotation, format!("title: \"{title}\"\n")).unwrap();
    child
}

fn context(path: &Path, source: &str) -> ScanContext {
    ScanContext::with_roots(
        path.to_path_buf(),
        vec![
            ScanRoot::remote(
                path.to_path_buf(),
                Origin::remote("synthetic-host"),
                Some(Platform::Linux),
            )
            .with_mirrored_source_path(source)
            .with_rewrite("/synthetic", "/mapped"),
        ],
        None,
    )
}

fn scan(path: &Path, source: &str) -> Vec<NormalizedConversation> {
    AntigravityConnector::new()
        .scan(&context(path, source))
        .unwrap()
}

fn identities(conversations: &[NormalizedConversation]) -> BTreeSet<String> {
    conversations
        .iter()
        .map(|conversation| conversation.external_id.clone().unwrap())
        .collect()
}

fn expected_identities() -> BTreeSet<String> {
    [
        CHILD.to_string(),
        PARENT.to_string(),
        format!("ide/{CHILD}"),
        format!("ide/{PARENT}"),
    ]
    .into_iter()
    .collect()
}

#[test]
fn shared_gemini_mirrors_keep_both_products_parent_links_and_provenance() {
    for contents_copy in [false, true] {
        let temp = TempDir::new().unwrap();
        let container = temp.path().join("opaque_transport");
        let gemini = if contents_copy {
            container.clone()
        } else {
            container.join(".gemini")
        };
        let ide = gemini.join("antigravity");
        let cli = gemini.join("antigravity-cli");
        store(&ide, "IDE title");
        store(&cli, "CLI title");
        // A safe provider expansion must not scan unrelated sibling stores.
        transcript(
            &container.join("noise/brain").join(OTHER),
            &parent_transcript(),
        );
        let source = if contents_copy {
            "~/.gemini/"
        } else {
            "~/.gemini"
        };
        let conversations = scan(&container, source);
        assert_eq!(conversations.len(), 4);
        assert_eq!(identities(&conversations), expected_identities());
        for (prefix, layout, title) in [("ide/", "ide", "IDE title"), ("", "cli", "CLI title")] {
            let child_id = format!("{prefix}{CHILD}");
            let child = conversations
                .iter()
                .find(|conversation| conversation.external_id.as_deref() == Some(&child_id))
                .unwrap();
            assert_eq!(child.metadata["layout"], layout);
            assert_eq!(
                child.metadata["parent_conversation_id"],
                format!("{prefix}{PARENT}")
            );
            assert_eq!(child.metadata["raw_parent_conversation_id"], PARENT);
            assert_eq!(child.title.as_deref(), Some(title));
        }
        let sources = AntigravityConnector::new()
            .discover_source_files(&context(&container, source))
            .unwrap();
        assert_eq!(
            sources
                .iter()
                .filter(|source| source.required_for_reconstruction)
                .count(),
            4
        );
        assert_eq!(sources.len(), 6, "four transcripts and two annotations");
        for source in sources {
            assert_eq!(source.origin, Origin::remote("synthetic-host"));
            assert_eq!(source.platform, Some(Platform::Linux));
            assert!(source.source_path.starts_with(&ide) || source.source_path.starts_with(&cli));
            assert!(source.scan_root == ide.join("brain") || source.scan_root == cli.join("brain"));
        }
    }
}

#[test]
fn single_product_mirrors_preserve_ids_at_base_brain_and_conversation_depths() {
    for (product, prefix, layout) in [
        ("antigravity", "ide/", "ide"),
        ("antigravity-cli", "", "cli"),
    ] {
        for depth in 0..3 {
            for contents_copy in [false, true] {
                let temp = TempDir::new().unwrap();
                let container = temp.path().join("opaque_transport");
                let (suffix, leaf) = match depth {
                    0 => (product.to_string(), product),
                    1 => (format!("{product}/brain"), "brain"),
                    _ => (format!("{product}/brain/{CHILD}"), CHILD),
                };
                let selected = if contents_copy {
                    container.clone()
                } else {
                    container.join(leaf)
                };
                let conversation = match depth {
                    0 => selected.join("brain").join(CHILD),
                    1 => selected.join(CHILD),
                    _ => selected,
                };
                let primary = transcript(&conversation, CHILD_TRANSCRIPT);
                let source = format!("~/.gemini/{suffix}{}", if contents_copy { "/" } else { "" });
                let conversations = scan(&container, &source);
                assert_eq!(conversations.len(), 1, "{source}");
                let child = &conversations[0];
                assert_eq!(
                    child.external_id.as_deref(),
                    Some(format!("{prefix}{CHILD}").as_str()),
                    "{source}"
                );
                assert_eq!(child.metadata["layout"], layout, "{source}");
                assert_eq!(
                    child.metadata["parent_conversation_id"],
                    format!("{prefix}{PARENT}"),
                    "{source}"
                );
                assert_eq!(child.source_path, primary);
                let sources = AntigravityConnector::new()
                    .discover_source_files(&context(&container, &source))
                    .unwrap();
                assert_eq!(sources.len(), 1, "{source}");
                assert_eq!(sources[0].source_path, primary);
                assert_eq!(sources[0].origin, Origin::remote("synthetic-host"));
            }
        }
    }
}

#[test]
fn broader_home_mirrors_retain_bounded_structural_discovery() {
    for (source, leaf) in [("/home/synthetic", Some("synthetic")), ("~/", None)] {
        let temp = TempDir::new().unwrap();
        let container = temp.path().join("opaque_transport");
        let home = leaf.map_or_else(|| container.clone(), |leaf| container.join(leaf));
        store(&home.join(".gemini/antigravity"), "IDE title");
        store(&home.join(".gemini/antigravity-cli"), "CLI title");
        let conversations = scan(&container, source);
        assert_eq!(identities(&conversations), expected_identities());
        let sources = AntigravityConnector::new()
            .discover_source_files(&context(&container, source))
            .unwrap();
        assert_eq!(
            sources
                .iter()
                .filter(|source| source.required_for_reconstruction)
                .count(),
            4
        );
        assert!(
            sources
                .iter()
                .all(|source| source.origin == Origin::remote("synthetic-host"))
        );
    }
}

#[test]
fn exact_mirror_events_keep_ids_when_original_source_context_is_retained() {
    let temp = TempDir::new().unwrap();
    let base = temp.path().join("opaque_transport");
    let primary = store(&base, "Remote title");
    let full = primary.with_file_name("transcript_full.jsonl");
    fs::copy(&primary, &full).unwrap();
    let annotation = base.join("annotations").join(format!("{CHILD}.pbtxt"));
    let source = "~/.gemini/antigravity/";
    let baseline = scan(&base, source);
    let child = baseline
        .iter()
        .find(|conversation| {
            conversation.external_id.as_deref() == Some(format!("ide/{CHILD}").as_str())
        })
        .unwrap();
    for path in [&primary, &full, &annotation] {
        let replay = scan(path, source);
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].external_id, child.external_id);
        assert_eq!(
            replay[0].metadata["parent_conversation_id"],
            child.metadata["parent_conversation_id"]
        );
        assert_eq!(replay[0].title.as_deref(), Some("Remote title"));
    }
    for name in ["conversation_summaries.db", "conversation_summaries.db-wal"] {
        let path = base.join(name);
        fs::write(&path, b"optional remote database is never opened").unwrap();
        let replay = scan(&path, source);
        assert_eq!(identities(&replay), identities(&baseline));
        assert!(
            replay
                .iter()
                .all(|conversation| conversation.workspace.is_none())
        );
    }
    // with_path intentionally drops transport identity. An opaque path cannot
    // supply an IDE identity after the host discards that original context.
    let narrowed = context(&base, source).scan_roots[0].with_path(primary);
    assert!(narrowed.mirrored_source_path.is_none());
}

#[test]
fn selected_conversation_events_cannot_relabel_other_ids_or_expand_to_shared_metadata() {
    let temp = TempDir::new().unwrap();
    let base = temp.path().join("opaque_transport");
    let primary = store(&base, "Not owned by a brain-only mirror");
    let other = transcript(&base.join("brain").join(OTHER), &parent_transcript());
    let source = format!("~/.gemini/antigravity/brain/{CHILD}");
    let child = scan(&primary, &source);
    assert_eq!(child.len(), 1);
    assert_eq!(
        child[0].external_id.as_deref(),
        Some(format!("ide/{CHILD}").as_str())
    );
    assert_ne!(
        child[0].title.as_deref(),
        Some("Not owned by a brain-only mirror")
    );
    let annotation = base.join("annotations").join(format!("{CHILD}.pbtxt"));
    let summary = base.join("conversation_summaries.db");
    let wal = base.join("conversation_summaries.db-wal");
    for path in [&summary, &wal] {
        fs::write(path, b"not selected").unwrap();
    }
    for path in [&other, &annotation, &summary, &wal] {
        let ctx = context(path, &source);
        let connector = AntigravityConnector::new();
        assert!(
            connector.scan(&ctx).unwrap().is_empty(),
            "{}",
            path.display()
        );
        assert!(
            connector.discover_source_files(&ctx).unwrap().is_empty(),
            "{}",
            path.display()
        );
    }
}
