//! Regression coverage for coding_agent_session_search#486.
//!
//! Exercise the public APIs with the real environment reader. Each case runs in
//! a child test process: changing a process-global environment variable in a
//! parallel Rust test suite would race unrelated connector tests.

#![cfg(feature = "connectors")]

use std::path::{Path, PathBuf};
use std::process::Command;

use franken_agent_detection::{
    CodexConnector, Connector, DiscoveredSourceFile, NormalizedConversation, ScanContext, ScanRoot,
    SourceCompletion, SourceScanHooks,
};
use tempfile::TempDir;

const CHILD_ROOT: &str = "FAD_CODEX_EXCLUSION_TEST_ROOT";
const CHILD_MODE: &str = "FAD_CODEX_EXCLUSION_TEST_MODE";
const CHILD_EXPECTED: &str = "FAD_CODEX_EXCLUSION_TEST_EXPECTED";

struct Fixture {
    root: TempDir,
    files: Vec<PathBuf>,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let month = root.path().join(".codex/sessions/2026/09");
        let private = month.join("18");
        let files = vec![
            private.join("rollout-private.jsonl"),
            private.join("rollout-legacy.json"),
            private.join("rollout-private.jsonl-copy.jsonl"),
            month.join("18-copy/rollout-sibling.jsonl"),
            month.join("19/rollout-public.jsonl"),
        ];
        for file in &files {
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            let content = if file.extension().unwrap() == "json" {
                r#"{"items":[{"role":"user","content":"fixture message"}]}"#
            } else {
                r#"{"type":"response_item","payload":{"role":"user","content":"fixture message"}}"#
            };
            std::fs::write(file, content).unwrap();
        }
        Self { root, files }
    }

    fn run(&self, exclusions: &str, expected_indices: &[usize]) {
        let expected: Vec<_> = expected_indices.iter().map(|&i| &self.files[i]).collect();
        let expected = serde_json::to_string(&expected).unwrap();
        let files = serde_json::to_string(&self.files).unwrap();
        for mode in ["default", "home", "codex", "sessions", "files", "overlapping"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "codex_exclusions_child", "--nocapture"])
                .current_dir(self.root.path())
                .env(CHILD_ROOT, self.root.path())
                .env(CHILD_MODE, mode)
                .env(CHILD_EXPECTED, &expected)
                .env("FAD_CODEX_EXCLUSION_TEST_FILES", &files)
                .env("CODEX_HOME", self.root.path().join(".codex"))
                .env("CASS_EXCLUDE_PATHS", exclusions)
                .output()
                .expect("run isolated Codex exclusion regression");
            assert!(
                output.status.success(),
                "mode={mode}, exclusions={exclusions:?}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }
}

fn context(root: &Path, files: &[PathBuf], mode: &str, since: Option<i64>) -> ScanContext {
    let data_dir = root.join("cass");
    let home = root.join(".codex");
    let sessions = home.join("sessions");
    let paths = match mode {
        "default" => return ScanContext::local_default(data_dir, since),
        "home" => vec![root.to_path_buf()],
        "codex" => vec![home],
        "sessions" => vec![sessions],
        "files" => files.to_vec(),
        "overlapping" => {
            let mut paths = vec![root.to_path_buf(), home, sessions];
            paths.extend_from_slice(files);
            paths
        }
        _ => panic!("unknown root mode: {mode}"),
    };
    ScanContext::with_roots(data_dir, paths.into_iter().map(ScanRoot::local).collect(), since)
}

fn assert_paths(mut actual: Vec<PathBuf>, expected: &[PathBuf], operation: &str) {
    let mut expected = expected.to_vec();
    actual.sort();
    expected.sort();
    // Do not deduplicate: overlapping roots must emit each admitted source once.
    assert_eq!(actual, expected, "{operation}");
}

fn assert_conversations(conversations: &[NormalizedConversation], expected: &[PathBuf]) {
    for conversation in conversations {
        assert_eq!(conversation.agent_slug, "codex");
        assert_eq!(conversation.messages.len(), 1);
        assert_eq!(conversation.messages[0].content, "fixture message");
    }
    assert_paths(
        conversations.iter().map(|c| c.source_path.clone()).collect(),
        expected,
        "parsed conversations",
    );
}

fn assert_source_boundaries(connector: &CodexConnector, ctx: &ScanContext, expected: &[PathBuf]) {
    let mut visited = Vec::new();
    let mut completed = Vec::new();
    let mut conversations = Vec::new();
    {
        let mut should_scan = |source: &DiscoveredSourceFile| {
            assert!(
                expected.contains(&source.source_path),
                "excluded source reached the pre-parse hook: {:?}",
                source.source_path,
            );
            visited.push(source.source_path.clone());
            true
        };
        let mut on_complete = |completion: &SourceCompletion| {
            assert_eq!(completion.conversations_emitted, 1);
            assert!(completion.required_sidecars.is_empty());
            completed.push(completion.source.source_path.clone());
            Ok(())
        };
        let mut hooks = SourceScanHooks {
            should_scan_source: Some(&mut should_scan),
            on_source_complete: Some(&mut on_complete),
        };
        connector
            .scan_with_source_boundaries(ctx, &mut hooks, &mut |conversation| {
                conversations.push(conversation);
                Ok(())
            })
            .unwrap();
    }
    assert_paths(visited, expected, "pre-parse hooks");
    assert_paths(completed, expected, "source completions");
    assert_conversations(&conversations, expected);
}

#[test]
fn codex_exclusions_child() {
    // The ordinary test-suite invocation is a no-op. Only Fixture::run supplies
    // this marker and selects this one test, so children cannot recurse.
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let mode = std::env::var(CHILD_MODE).unwrap();
    let expected: Vec<PathBuf> =
        serde_json::from_str(&std::env::var(CHILD_EXPECTED).unwrap()).unwrap();
    let files: Vec<PathBuf> = serde_json::from_str(
        &std::env::var("FAD_CODEX_EXCLUSION_TEST_FILES").unwrap(),
    )
    .unwrap();
    let connector = CodexConnector::new();
    // Cover both a full scan and an incremental scan that admits these files.
    for since in [None, Some(0)] {
        let ctx = context(&root, &files, &mode, since);
        let discovered = connector.discover_source_files(&ctx).unwrap();
        assert_paths(
            discovered.into_iter().map(|source| source.source_path).collect(),
            &expected,
            "discovery/pre-mirroring",
        );
        assert_conversations(&connector.scan(&ctx).unwrap(), &expected);
        let mut streamed = Vec::new();
        connector
            .scan_with_callback(&ctx, &mut |conversation| {
                streamed.push(conversation);
                Ok(())
            })
            .unwrap();
        assert_conversations(&streamed, &expected);
        assert_source_boundaries(&connector, &ctx, &expected);
    }
}

#[test]
fn codex_exclusions_exact_files_preserve_siblings() {
    let fixture = Fixture::new();
    // Mixed delimiters, whitespace and empty entries exercise the real reader.
    let exclusions = format!(
        " , {} ,\n {} \n, ",
        fixture.files[0].display(),
        fixture.files[1].display(),
    );
    fixture.run(&exclusions, &[2, 3, 4]);
}

#[test]
fn codex_exclusions_parent_directory_preserves_prefix_sibling() {
    let fixture = Fixture::new();
    fixture.run(fixture.files[0].parent().unwrap().to_str().unwrap(), &[3, 4]);
}

#[test]
fn codex_exclusions_sessions_root() {
    let fixture = Fixture::new();
    fixture.run(fixture.root.path().join(".codex/sessions").to_str().unwrap(), &[]);
}

#[test]
fn codex_exclusions_codex_home() {
    let fixture = Fixture::new();
    fixture.run(fixture.root.path().join(".codex").to_str().unwrap(), &[]);
}

#[test]
fn codex_exclusions_codex_parent() {
    let fixture = Fixture::new();
    fixture.run(fixture.root.path().to_str().unwrap(), &[]);
}

#[test]
fn codex_exclusions_empty_or_unrelated_preserve_all_sources() {
    let fixture = Fixture::new();
    for exclusions in ["", " , \n , "] {
        fixture.run(exclusions, &[0, 1, 2, 3, 4]);
    }
    fixture.run(
        fixture.root.path().join("unrelated").to_str().unwrap(),
        &[0, 1, 2, 3, 4],
    );
}
