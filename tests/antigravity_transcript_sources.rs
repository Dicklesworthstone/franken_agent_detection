//! Full-only transcript recovery must agree with discovery, source selection,
//! incremental refresh, mirror identity, and the existing exclusion policy.
#![cfg(feature = "connectors")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use franken_agent_detection::{
    AntigravityConnector, Connector, NormalizedConversation, Origin, ScanContext, ScanRoot,
    extract_tokens_for_agent,
};
use tempfile::TempDir;

const CHILD: &str = "11111111-2222-4333-8444-555555555555";
const PARENT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const TRANSCRIPT: &str = include_str!("fixtures/antigravity/child_transcript.jsonl");
const OLD: u64 = 1_700_000_000_000;
const SINCE: i64 = 1_700_000_005_000;
const NEW: u64 = 1_700_000_010_000;
const CHILD_ROOT: &str = "FAD_ANTIGRAVITY_TRANSCRIPT_SOURCE_ROOT";
const CHILD_CASE: &str = "FAD_ANTIGRAVITY_TRANSCRIPT_SOURCE_CASE";

fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn full_at(conversation: &Path) -> PathBuf {
    let full = conversation.join(".system_generated/logs/transcript_full.jsonl");
    write(&full, TRANSCRIPT);
    full
}

fn context(root: &Path, since: Option<i64>) -> ScanContext {
    ScanContext::with_roots(
        root.to_path_buf(),
        vec![ScanRoot::local(root.to_path_buf())],
        since,
    )
}

fn one(ctx: &ScanContext) -> NormalizedConversation {
    let mut conversations = AntigravityConnector::new().scan(ctx).unwrap();
    assert_eq!(conversations.len(), 1, "roots: {:?}", ctx.scan_roots);
    conversations.pop().unwrap()
}

fn modified(path: &Path, millis: u64) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_millis(millis))
        .unwrap();
}

fn assert_selected(ctx: &ScanContext, source: &Path, id: &str) -> NormalizedConversation {
    let conversation = one(ctx);
    assert_eq!(conversation.source_path, source);
    assert_eq!(conversation.external_id.as_deref(), Some(id));
    assert_eq!(conversation.messages.len(), 7);
    assert_eq!(conversation.metadata["model"], "gemini-4-neon-high");
    let count: u32 = conversation
        .messages
        .iter()
        .map(|message| {
            extract_tokens_for_agent(
                "antigravity",
                &message.extra,
                &message.content,
                &message.role,
            )
            .tool_call_count
        })
        .sum();
    assert_eq!(count, 3);
    let sources = AntigravityConnector::new()
        .discover_source_files(ctx)
        .unwrap();
    let required: Vec<_> = sources
        .iter()
        .filter(|file| file.required_for_reconstruction)
        .collect();
    assert_eq!(required.len(), 1);
    assert_eq!(required[0].source_path, source);
    conversation
}

#[test]
fn full_only_transcripts_scan_from_local_directories_and_exact_events() {
    let temp = TempDir::new().unwrap();
    let base = temp.path().join(".gemini/antigravity");
    let brain = base.join("brain");
    let conversation = brain.join(CHILD);
    let full = full_at(&conversation);
    let absent_primary = full.with_file_name("transcript.jsonl");
    let annotation = base.join("annotations").join(format!("{CHILD}.pbtxt"));
    write(&annotation, "title: \"Preserved full-only conversation\"\n");
    let before = fs::read(&full).unwrap();
    for root in [
        temp.path(),
        &base,
        &brain,
        &conversation,
        &full,
        &absent_primary,
        &annotation,
    ] {
        let normalized = assert_selected(&context(root, None), &full, &format!("ide/{CHILD}"));
        assert_eq!(
            normalized.title.as_deref(),
            Some("Preserved full-only conversation")
        );
        assert_eq!(
            normalized.metadata["parent_conversation_id"],
            format!("ide/{PARENT}")
        );
    }
    let ctx = ScanContext::local_default(base, None);
    let collecting = assert_selected(&ctx, &full, &format!("ide/{CHILD}"));
    let mut streamed = Vec::new();
    AntigravityConnector::new()
        .scan_with_callback(&ctx, &mut |conversation| {
            streamed.push(conversation);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        serde_json::to_value(streamed).unwrap(),
        serde_json::to_value([collecting]).unwrap()
    );
    assert_eq!(fs::read(full).unwrap(), before);
    assert!(!absent_primary.exists());
}

#[test]
fn primary_remains_authoritative_and_the_two_transcripts_are_never_combined() {
    let temp = TempDir::new().unwrap();
    let full = full_at(&temp.path().join("brain").join(CHILD));
    let primary = full.with_file_name("transcript.jsonl");
    write(&primary, TRANSCRIPT);
    write(
        &full,
        &TRANSCRIPT.replace(
            "The synthetic fixture is valid.",
            "The backup must not replace the primary.",
        ),
    );
    modified(&primary, OLD);
    modified(&full, NEW);
    for root in [temp.path(), &primary, &full] {
        let ctx = context(root, Some(SINCE));
        let normalized = assert_selected(&ctx, &primary, CHILD);
        assert_eq!(
            normalized.messages.last().unwrap().content,
            "The synthetic fixture is valid."
        );
        let sources = AntigravityConnector::new()
            .discover_source_files(&ctx)
            .unwrap();
        assert_eq!(sources.len(), 2);
        assert!(
            sources
                .iter()
                .any(|file| file.source_path == full && !file.required_for_reconstruction)
        );
    }
    let overlap = ScanContext::with_roots(
        temp.path().to_path_buf(),
        [temp.path(), &primary, &full]
            .into_iter()
            .map(|path| ScanRoot::local(path.to_path_buf()))
            .collect(),
        None,
    );
    assert_selected(&overlap, &primary, CHILD);
}

#[test]
fn full_only_freshness_and_authority_changes_follow_the_selected_source() {
    let temp = TempDir::new().unwrap();
    let full = full_at(&temp.path().join("brain").join(CHILD));
    let primary = full.with_file_name("transcript.jsonl");
    let annotation = temp
        .path()
        .join("annotations")
        .join(format!("{CHILD}.pbtxt"));
    let connector = AntigravityConnector::new();
    let ctx = context(temp.path(), Some(SINCE));
    modified(&full, OLD);
    assert!(connector.scan(&ctx).unwrap().is_empty());
    assert!(connector.discover_source_files(&ctx).unwrap().is_empty());

    modified(&full, NEW);
    assert_selected(&ctx, &full, CHILD);
    modified(&full, OLD);
    write(&annotation, "title: \"Only the metadata changed\"\n");
    modified(&annotation, NEW);
    assert_eq!(
        assert_selected(&ctx, &full, CHILD).title.as_deref(),
        Some("Only the metadata changed")
    );

    fs::remove_file(&annotation).unwrap();
    let deleted_annotation = assert_selected(&context(&annotation, Some(SINCE)), &full, CHILD);
    assert_eq!(
        deleted_annotation.title.as_deref(),
        Some("Inspect the parser fixture and verify it twice.")
    );
    assert!(connector.scan(&ctx).unwrap().is_empty());

    write(&primary, TRANSCRIPT);
    modified(&primary, NEW);
    assert_selected(&ctx, &primary, CHILD);
    fs::remove_file(&primary).unwrap();
    assert_selected(&context(&primary, Some(SINCE)), &full, CHILD);
}

#[test]
fn full_only_qualified_mirrors_preserve_ids_at_each_copy_depth() {
    for product in ["antigravity", "antigravity-cli"] {
        for scope in ["base", "brain", "conversation"] {
            for contents_only in [false, true] {
                let temp = TempDir::new().unwrap();
                let container = temp.path().join("opaque_transport");
                let basename = match scope {
                    "base" => product,
                    "brain" => "brain",
                    _ => CHILD,
                };
                let selected = if contents_only {
                    container.clone()
                } else {
                    container.join(basename)
                };
                let conversation = match scope {
                    "base" => selected.join("brain").join(CHILD),
                    "brain" => selected.join(CHILD),
                    _ => selected,
                };
                let full = full_at(&conversation);
                let suffix = match scope {
                    "base" => String::new(),
                    "brain" => "/brain".to_string(),
                    _ => format!("/brain/{CHILD}"),
                };
                let source = format!(
                    "~/.gemini/{product}{suffix}{}",
                    if contents_only { "/" } else { "" }
                );
                let prefix = if product == "antigravity" { "ide/" } else { "" };
                for path in [&container, &full] {
                    let ctx = ScanContext::with_roots(
                        path.to_path_buf(),
                        vec![
                            ScanRoot::remote(
                                path.to_path_buf(),
                                Origin::remote("synthetic-host"),
                                None,
                            )
                            .with_mirrored_source_path(&source),
                        ],
                        None,
                    );
                    let normalized = assert_selected(&ctx, &full, &format!("{prefix}{CHILD}"));
                    assert_eq!(
                        normalized.metadata["parent_conversation_id"],
                        format!("{prefix}{PARENT}")
                    );
                    assert!(
                        AntigravityConnector::new()
                            .discover_source_files(&ctx)
                            .unwrap()
                            .iter()
                            .all(|file| file.origin == Origin::remote("synthetic-host"))
                    );
                }
            }
        }
    }
}

#[test]
fn full_only_shared_mirrors_keep_both_product_histories() {
    for contents_only in [false, true] {
        let temp = TempDir::new().unwrap();
        let container = temp.path().join("opaque_transport");
        let gemini = if contents_only {
            container.clone()
        } else {
            container.join(".gemini")
        };
        for product in ["antigravity", "antigravity-cli"] {
            full_at(&gemini.join(product).join("brain").join(CHILD));
        }
        let ctx = ScanContext::with_roots(
            container.clone(),
            vec![
                ScanRoot::remote(container, Origin::remote("synthetic-host"), None)
                    .with_mirrored_source_path(if contents_only {
                        "~/.gemini/"
                    } else {
                        "~/.gemini"
                    }),
            ],
            None,
        );
        let connector = AntigravityConnector::new();
        let conversations = connector.scan(&ctx).unwrap();
        let mut identities: Vec<_> = conversations
            .iter()
            .map(|c| c.external_id.as_deref().unwrap())
            .collect();
        identities.sort_unstable();
        assert_eq!(identities, [CHILD, &format!("ide/{CHILD}")]);
        let files = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|file| file.required_for_reconstruction));
    }
}

#[test]
fn an_existing_unusable_primary_does_not_authorize_full_fallback() {
    for kind in ["empty", "malformed", "oversized", "directory"] {
        let temp = TempDir::new().unwrap();
        let full = full_at(&temp.path().join("brain").join(CHILD));
        let primary = full.with_file_name("transcript.jsonl");
        match kind {
            "empty" => write(&primary, ""),
            "malformed" => write(&primary, "{unfinished\n"),
            "oversized" => fs::File::create(&primary)
                .unwrap()
                .set_len(100 * 1024 * 1024 + 1)
                .unwrap(),
            _ => fs::create_dir(&primary).unwrap(),
        }
        assert!(
            AntigravityConnector::new()
                .scan(&context(temp.path(), None))
                .unwrap()
                .is_empty(),
            "{kind}"
        );
    }
    #[cfg(unix)]
    {
        let temp = TempDir::new().unwrap();
        let full = full_at(&temp.path().join("brain").join(CHILD));
        std::os::unix::fs::symlink(
            temp.path().join("missing"),
            full.with_file_name("transcript.jsonl"),
        )
        .unwrap();
        assert!(
            AntigravityConnector::new()
                .scan(&context(temp.path(), None))
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn exclusions_cannot_be_bypassed_through_the_full_transcript() {
    let temp = TempDir::new().unwrap();
    let conversation = temp.path().join("brain").join(CHILD);
    let full = full_at(&conversation);
    for (case, excluded) in [
        ("primary", full.with_file_name("transcript.jsonl")),
        ("full", full),
        ("conversation", conversation),
        ("unrelated", temp.path().join("not-selected")),
    ] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "transcript_source_exclusion_child",
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
            "{case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn transcript_source_exclusion_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT).map(PathBuf::from) else {
        return;
    };
    let ctx = context(&root, None);
    let connector = AntigravityConnector::new();
    if std::env::var(CHILD_CASE).unwrap() == "unrelated" {
        let full = root
            .join("brain")
            .join(CHILD)
            .join(".system_generated/logs/transcript_full.jsonl");
        assert_selected(&ctx, &full, CHILD);
    } else {
        assert!(connector.scan(&ctx).unwrap().is_empty());
        assert!(connector.discover_source_files(&ctx).unwrap().is_empty());
    }
}
