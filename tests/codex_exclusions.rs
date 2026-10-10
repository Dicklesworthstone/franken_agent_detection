//! Regression coverage for `coding_agent_session_search#486` and
//! `franken_agent_detection#29` (compressed representation exclusions).
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
        Self::with_paths(
            [
                "18/rollout-private.jsonl",
                "18/rollout-legacy.json",
                "18/rollout-private.jsonl-copy.jsonl",
                "18-copy/rollout-sibling.jsonl",
                "19/rollout-public.jsonl",
            ]
            .map(|path| PathBuf::from(".codex/sessions/2026/09").join(path)),
        )
    }

    fn with_paths(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let root = TempDir::new().unwrap();
        let files: Vec<_> = paths
            .into_iter()
            .map(|path| root.path().join(path))
            .collect();
        for file in &files {
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            write_rollout(file);
        }
        Self { root, files }
    }

    fn run(&self, exclusions: &str, expected_indices: &[usize]) {
        self.run_modes(
            exclusions,
            expected_indices,
            &[
                "default",
                "home",
                "codex",
                "sessions",
                "files",
                "overlapping",
            ],
        );
    }

    fn run_modes(&self, exclusions: &str, expected_indices: &[usize], modes: &[&str]) {
        let expected: Vec<_> = expected_indices.iter().map(|&i| &self.files[i]).collect();
        let expected = serde_json::to_string(&expected).unwrap();
        let files = serde_json::to_string(&self.files).unwrap();
        let before: Vec<_> = self
            .files
            .iter()
            .map(|file| std::fs::read(file).unwrap())
            .collect();
        for mode in modes {
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
        for (file, expected_bytes) in self.files.iter().zip(before) {
            assert_eq!(
                std::fs::read(file).unwrap(),
                expected_bytes,
                "source changed: {}",
                file.display()
            );
        }
    }
}

fn write_rollout(file: &Path) {
    let content = if file.extension().unwrap() == "json" {
        r#"{"items":[{"role":"user","content":"fixture message"}]}"#
    } else {
        r#"{"type":"response_item","payload":{"role":"user","content":"fixture message"}}"#
    };
    #[cfg(feature = "codex-zstd")]
    if franken_agent_detection::connectors::codex::is_compressed_rollout(file) {
        // Real zstd frames, consumed through the production decoder in baseline
        // scans before testing the pre-parse exclusion gates.
        let compressed = zstd::stream::encode_all(content.as_bytes(), 0).unwrap();
        std::fs::write(file, compressed).unwrap();
        return;
    }
    std::fs::write(file, content).unwrap();
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
    ScanContext::with_roots(
        data_dir,
        paths.into_iter().map(ScanRoot::local).collect(),
        since,
    )
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
        conversations
            .iter()
            .map(|c| c.source_path.clone())
            .collect(),
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
                "excluded source reached the pre-parse hook: {}",
                source.source_path.display(),
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
    let files: Vec<PathBuf> =
        serde_json::from_str(&std::env::var("FAD_CODEX_EXCLUSION_TEST_FILES").unwrap()).unwrap();
    let connector = CodexConnector::new();
    // Cover both a full scan and an incremental scan that admits these files.
    for since in [None, Some(0)] {
        let ctx = context(&root, &files, &mode, since);
        let discovered = connector.discover_source_files(&ctx).unwrap();
        assert_paths(
            discovered
                .into_iter()
                .map(|source| source.source_path)
                .collect(),
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
    fixture.run(
        fixture.files[0].parent().unwrap().to_str().unwrap(),
        &[3, 4],
    );
}

#[test]
fn codex_exclusions_sessions_root() {
    let fixture = Fixture::new();
    fixture.run(
        fixture
            .root
            .path()
            .join(".codex/sessions")
            .to_str()
            .unwrap(),
        &[],
    );
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

#[test]
fn codex_exclusions_resolve_relative_dotdot_and_alias_spellings() {
    let fixture = Fixture::new();
    // Children run with the fixture root as their working directory.
    fixture.run(".codex/sessions/2026/09/18", &[3, 4]);
    let dotdot = fixture.root.path().join(".codex/sessions/2026/09/19/../18");
    fixture.run(dotdot.to_str().unwrap(), &[3, 4]);
    #[cfg(unix)]
    {
        // Keep the alias outside every scan root so no walker can reach it.
        let elsewhere = TempDir::new().unwrap();
        let alias = elsewhere.path().join("private-alias");
        std::os::unix::fs::symlink(fixture.files[0].parent().unwrap(), &alias).unwrap();
        fixture.run(alias.to_str().unwrap(), &[3, 4]);
    }
}

fn ascii_case_spellings(word: &str) -> Vec<String> {
    (0..(1 << word.len()))
        .map(|mask| {
            word.bytes()
                .enumerate()
                .map(|(bit, byte)| {
                    char::from(if mask & (1 << bit) == 0 {
                        byte
                    } else {
                        byte.to_ascii_uppercase()
                    })
                })
                .collect()
        })
        .collect()
}

fn representation_fixture(compressed: bool) -> (Fixture, String) {
    let mut paths = Vec::new();
    let mut aliases = Vec::new();
    // The reader accepts all 32 JSONL spellings and all 8 ZST spellings.
    // Give every pair a distinct stem so this also works on case-insensitive
    // filesystems without inventing multiple files with the same identity.
    for jsonl in ascii_case_spellings("jsonl") {
        for zst in ascii_case_spellings("zst") {
            let id = paths.len();
            let plain = PathBuf::from(format!(".codex/sessions/rollout-private-{id}.{jsonl}"));
            let encoded = plain.with_extension(format!("{jsonl}.{zst}"));
            if compressed {
                paths.push(encoded);
                aliases.push(plain);
            } else {
                paths.push(plain);
                aliases.push(encoded);
            }
        }
    }
    paths.push(PathBuf::from(".codex/sessions/rollout-public.jsonl"));
    paths.push(PathBuf::from(
        ".codex/sessions/rollout-private-0.jsonl-copy.jsonl",
    ));
    let fixture = Fixture::with_paths(paths);
    let exclusions = aliases
        .into_iter()
        .map(|path| fixture.root.path().join(path).to_str().unwrap().to_owned())
        .collect::<Vec<_>>()
        .join("\n");
    (fixture, exclusions)
}

#[test]
fn codex_exclusions_compressed_names_cover_plain_twins_for_every_suffix_spelling() {
    let (fixture, exclusions) = representation_fixture(false);
    fixture.run("", &(0..fixture.files.len()).collect::<Vec<_>>());
    fixture.run(&exclusions, &[256, 257]);
}

#[test]
#[cfg(feature = "codex-zstd")]
fn codex_exclusions_plain_names_cover_compressed_twins_for_every_suffix_spelling() {
    let (fixture, exclusions) = representation_fixture(true);
    // Establish that all 256 frames really decode and emit the same fixture
    // record before any policy is configured.
    fixture.run("", &(0..fixture.files.len()).collect::<Vec<_>>());
    fixture.run(&exclusions, &[256, 257]);
}

#[test]
#[cfg(feature = "codex-zstd")]
fn codex_exclusions_cover_coexisting_twins_and_explicit_compressed_roots() {
    let mut fixture = Fixture::new();
    let plain = fixture.files[0].clone();
    let compressed = plain.with_extension("jsonl.zst");
    write_rollout(&compressed);

    // Directory discovery prefers the plain twin, and the compressed spelling
    // must still exclude it. The unrelated legacy JSON and siblings survive.
    fixture.run("", &[0, 1, 2, 3, 4]);
    fixture.run(compressed.to_str().unwrap(), &[1, 2, 3, 4]);

    // Explicitly scoping the compressed file bypasses directory twin selection.
    // Its plain spelling must exclude it at the same public API gates.
    fixture.files[0] = compressed;
    fixture.run_modes("", &[0, 1, 2, 3, 4], &["files"]);
    fixture.run_modes(plain.to_str().unwrap(), &[1, 2, 3, 4], &["files"]);
}

#[test]
#[cfg(feature = "codex-zstd")]
fn codex_exclusions_compressed_twins_keep_relative_dotdot_and_symlink_resolution() {
    let fixture = Fixture::with_paths([
        PathBuf::from(".codex/sessions/private/rollout-private.JSONL.zSt"),
        PathBuf::from(".codex/sessions/public/rollout-public.jsonl"),
    ]);
    fixture.run("", &[0, 1]);
    fixture.run(".codex/sessions/private/rollout-private.JSONL", &[1]);
    fixture.run(
        ".codex/sessions/public/../private/rollout-private.JSONL",
        &[1],
    );
    #[cfg(unix)]
    {
        let elsewhere = TempDir::new().unwrap();
        let alias = elsewhere.path().join("private-alias");
        std::os::unix::fs::symlink(fixture.files[0].parent().unwrap(), &alias).unwrap();
        fixture.run(alias.join("rollout-private.JSONL").to_str().unwrap(), &[1]);
    }
}

#[test]
#[cfg(all(feature = "codex-zstd", unix))]
fn codex_exclusions_resolve_leaf_symlinks_before_matching_compressed_twins() {
    let mut fixture = Fixture::new();
    let plain = fixture.files[0].clone();
    let compressed = plain.with_extension("jsonl.zst");
    write_rollout(&compressed);
    let elsewhere = TempDir::new().unwrap();

    // A policy can be a leaf symlink with no rollout-shaped filename. The
    // canonical compressed target also excludes its selected plain twin.
    let policy_alias = elsewhere.path().join("private-policy");
    std::os::unix::fs::symlink(&compressed, &policy_alias).unwrap();
    fixture.run(policy_alias.to_str().unwrap(), &[1, 2, 3, 4]);

    // Conversely, an explicitly scoped compressed source can have a different
    // stem. Excluding the canonical target's plain twin must still block it.
    let source_alias = elsewhere.path().join("rollout-other-name.jsonl.zst");
    std::os::unix::fs::symlink(&compressed, &source_alias).unwrap();
    fixture.files[0] = source_alias;
    fixture.run_modes("", &[0, 1, 2, 3, 4], &["files"]);
    fixture.run_modes(plain.to_str().unwrap(), &[1, 2, 3, 4], &["files"]);
}

#[test]
fn codex_exclusions_representation_aliases_do_not_expand_directory_policies() {
    let fixture = Fixture::with_paths([
        PathBuf::from(".codex/sessions/rollout-folder.jsonl/rollout-public.jsonl"),
        PathBuf::from(".codex/sessions/rollout-public.jsonl"),
    ]);
    let compressed_directory = fixture
        .root
        .path()
        .join(".codex/sessions/rollout-folder.jsonl.zst");
    std::fs::create_dir_all(&compressed_directory).unwrap();
    fixture.run(compressed_directory.to_str().unwrap(), &[0, 1]);

    // Even a missing compressed spelling is an exact logical-file alias. It
    // does not become a prefix exclusion for a similarly named directory.
    let missing_compressed = fixture.files[0]
        .parent()
        .unwrap()
        .with_extension("jsonl.ZST");
    fixture.run(missing_compressed.to_str().unwrap(), &[0, 1]);
}

#[test]
#[cfg(unix)]
fn codex_exclusions_representation_aliases_preserve_stem_and_jsonl_case() {
    use std::os::unix::fs::MetadataExt;

    let fixture = Fixture::with_paths([
        PathBuf::from(".codex/sessions/rollout-Private.jsonl"),
        PathBuf::from(".codex/sessions/rollout-private.jsonl"),
        PathBuf::from(".codex/sessions/rollout-Private.JSONL"),
        PathBuf::from(".codex/sessions/rollout-Private.json"),
    ]);
    // macOS may use a case-insensitive filesystem. Its case variants name the
    // same file, so only assert distinct-file behavior where they are distinct.
    let first = std::fs::metadata(&fixture.files[0]).unwrap();
    if fixture.files[1..=2].iter().any(|path| {
        let other = std::fs::metadata(path).unwrap();
        (first.dev(), first.ino()) == (other.dev(), other.ino())
    }) {
        return;
    }
    let excluded = fixture.files[0].with_extension("jsonl.zst");
    fixture.run(excluded.to_str().unwrap(), &[1, 2, 3]);
}
