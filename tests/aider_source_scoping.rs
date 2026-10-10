//! Public Aider source selection with isolated cwd and environment settings.
//! Unix home lookup honors HOME; Windows uses the known-folder API instead.
#![cfg(all(feature = "connectors", unix))]

use std::path::{Path, PathBuf};
use std::process::Command;

use franken_agent_detection::{
    AiderConnector, Connector, DiscoveredSourceRole, NormalizedConversation, Origin, Platform,
    ScanContext, ScanRoot, SourceScanHooks,
};
use tempfile::TempDir;

const CHILD_ROOT: &str = "FAD_AIDER_SCOPE_ROOT";
const CHILD_DATA: &str = "FAD_AIDER_SCOPE_DATA";
const CHILD_ROOTS: &str = "FAD_AIDER_SCOPE_EXPLICIT_ROOTS";
const CHILD_EXPECTED: &str = "FAD_AIDER_SCOPE_EXPECTED";
const CHILD_SINCE: &str = "FAD_AIDER_SCOPE_SINCE";
const HISTORY: &str = ".aider.chat.history.md";

struct Fixture {
    root: TempDir,
    files: Vec<PathBuf>,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let files = [
            "home",
            "home/project",
            "cwd",
            "selected",
            "selected/nested",
            "cassie/project",
            "cassette-player",
            "CASSANDRA/project",
            "cass-state/mirror/project",
            ".cass/mirror/project",
            "archive.CASS.state/mirror/project",
            "marked-state/mirror/project",
            "configured",
            "configured/nested",
        ]
        .into_iter()
        .map(|directory| {
            let parent = root.path().join(directory);
            std::fs::create_dir_all(&parent).unwrap();
            let path = parent.join(HISTORY);
            std::fs::write(
                &path,
                format!("> User in {directory}\nAssistant in {directory}\n"),
            )
            .unwrap();
            path
        })
        .collect();
        std::fs::write(root.path().join("marked-state/agent_search.db"), []).unwrap();
        Self { root, files }
    }

    fn run(
        &self,
        data_dir: &str,
        override_root: Option<&str>,
        explicit_roots: &[&str],
        expected: &[(&str, &str)],
        since_ts: Option<i64>,
    ) {
        let original: Vec<_> = self
            .files
            .iter()
            .map(|path| {
                (
                    std::fs::read(path).unwrap(),
                    std::fs::metadata(path).unwrap().modified().unwrap(),
                )
            })
            .collect();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "aider_scope_child", "--nocapture"])
            .current_dir(self.root.path().join("cwd"))
            .env("HOME", self.root.path().join("home"))
            .env("USERPROFILE", self.root.path().join("home"))
            .env(CHILD_ROOT, self.root.path())
            .env(CHILD_DATA, data_dir)
            .env(CHILD_ROOTS, serde_json::to_string(explicit_roots).unwrap())
            .env(CHILD_EXPECTED, serde_json::to_string(expected).unwrap())
            .env(CHILD_SINCE, serde_json::to_string(&since_ts).unwrap())
            .env_remove("CASS_AIDER_DATA_ROOT");
        if let Some(override_root) = override_root {
            command.env("CASS_AIDER_DATA_ROOT", self.root.path().join(override_root));
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "data_dir={data_dir:?}, override={override_root:?}, roots={explicit_roots:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        for (path, (bytes, modified)) in self.files.iter().zip(original) {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
            assert_eq!(
                std::fs::metadata(path).unwrap().modified().unwrap(),
                modified
            );
        }
    }
}

fn assert_conversations(conversations: &[NormalizedConversation], expected: &[PathBuf]) {
    let actual: Vec<_> = conversations
        .iter()
        .map(|conversation| {
            assert_eq!(conversation.agent_slug, "aider");
            assert_eq!(
                conversation.external_id.as_deref(),
                conversation.source_path.to_str(),
            );
            assert_eq!(
                conversation.workspace.as_deref(),
                conversation.source_path.parent(),
            );
            assert_eq!(conversation.messages.len(), 2);
            assert_eq!(conversation.messages[0].idx, 0);
            assert_eq!(conversation.messages[0].role, "user");
            assert!(conversation.messages[0].content.starts_with("User in "));
            assert_eq!(conversation.messages[1].idx, 1);
            assert_eq!(conversation.messages[1].role, "assistant");
            assert!(
                conversation.messages[1]
                    .content
                    .starts_with("Assistant in ")
            );
            conversation.source_path.clone()
        })
        .collect();
    // Comparing vectors checks both stable traversal order and no duplicates.
    assert_eq!(actual, expected);
}

#[test]
fn aider_scope_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let data_dir = root.join(std::env::var(CHILD_DATA).unwrap());
    let explicit_roots: Vec<String> =
        serde_json::from_str(&std::env::var(CHILD_ROOTS).unwrap()).unwrap();
    let since_ts: Option<i64> = serde_json::from_str(&std::env::var(CHILD_SINCE).unwrap()).unwrap();
    let mut expected: Vec<(String, String)> =
        serde_json::from_str(&std::env::var(CHILD_EXPECTED).unwrap()).unwrap();
    expected.sort_by(|left, right| left.1.cmp(&right.1));
    let expected_sources: Vec<_> = expected.iter().map(|(_, path)| root.join(path)).collect();
    let remote = Origin::remote_with_host("archived-machine", "remote.example");
    let ctx = ScanContext::with_roots(
        data_dir,
        explicit_roots
            .iter()
            .map(|path| ScanRoot::remote(root.join(path), remote.clone(), Some(Platform::Linux)))
            .collect(),
        since_ts,
    );

    let connector = AiderConnector::new();
    let discovered = connector.discover_source_files(&ctx).unwrap();
    assert_eq!(discovered.len(), expected.len());
    for (source, (scan_root, source_path)) in discovered.iter().zip(&expected) {
        assert_eq!(source.provider_slug, "aider");
        assert_eq!(source.scan_root, root.join(scan_root));
        assert_eq!(source.source_path, root.join(source_path));
        assert_eq!(source.role, DiscoveredSourceRole::PrimarySessionLog);
        assert!(source.required_for_reconstruction);
        assert!(source.size_bytes.unwrap() > 0);
        assert!(source.modified_at_ms.is_some());
        assert_eq!(
            source.origin,
            if explicit_roots.is_empty() {
                Origin::local()
            } else {
                remote.clone()
            },
        );
        assert_eq!(
            source.platform,
            (!explicit_roots.is_empty()).then_some(Platform::Linux),
        );
    }

    let conversations = connector.scan(&ctx).unwrap();
    assert_conversations(&conversations, &expected_sources);
    let mut callback = Vec::new();
    connector
        .scan_with_callback(&ctx, &mut |conversation| {
            callback.push(conversation);
            Ok(())
        })
        .unwrap();
    assert_conversations(&callback, &expected_sources);
    assert_eq!(
        serde_json::to_value(&callback).unwrap(),
        serde_json::to_value(&conversations).unwrap(),
    );
    assert!(!connector.supports_source_boundaries());
    let mut boundary_fallback = Vec::new();
    connector
        .scan_with_source_boundaries(&ctx, &mut SourceScanHooks::default(), &mut |conversation| {
            boundary_fallback.push(conversation);
            Ok(())
        })
        .unwrap();
    assert_conversations(&boundary_fallback, &expected_sources);
}

#[test]
fn exact_history_file_does_not_expand_to_sibling_projects() {
    Fixture::new().run(
        "selected/.aider.chat.history.md",
        None,
        &[],
        &[(
            "selected/.aider.chat.history.md",
            "selected/.aider.chat.history.md",
        )],
        None,
    );
}

#[test]
fn missing_exact_history_file_stays_scoped() {
    let fixture = Fixture::new();
    std::fs::remove_file(fixture.root.path().join("selected/.aider.chat.history.md")).unwrap();
    // Retain the nested project's history, which the previous parent expansion
    // incorrectly emitted in place of the requested missing file.
    let fixture = Fixture {
        files: fixture
            .files
            .into_iter()
            .filter(|path| path != &fixture.root.path().join("selected/.aider.chat.history.md"))
            .collect(),
        root: fixture.root,
    };
    fixture.run("selected/.aider.chat.history.md", None, &[], &[], None);
}

#[test]
fn cass_substrings_in_user_and_project_names_do_not_redirect_scans() {
    let fixture = Fixture::new();
    for directory in ["cassie/project", "cassette-player", "CASSANDRA/project"] {
        let history = Path::new(directory).join(HISTORY);
        fixture.run(
            directory,
            None,
            &[],
            &[(directory, history.to_str().unwrap())],
            None,
        );
    }
}

#[test]
fn state_directory_names_and_database_marker_keep_live_fallback() {
    let fixture = Fixture::new();
    for directory in [
        "cass-state",
        "cass-state/mirror",
        ".cass",
        "archive.CASS.state",
        "marked-state",
    ] {
        fixture.run(
            directory,
            None,
            &[],
            &[
                ("cwd", "cwd/.aider.chat.history.md"),
                ("home", "home/.aider.chat.history.md"),
                ("home", "home/project/.aider.chat.history.md"),
            ],
            None,
        );
    }
}

#[test]
fn exact_file_in_state_directory_takes_precedence_over_name_heuristic() {
    let history = "cass-state/mirror/project/.aider.chat.history.md";
    Fixture::new().run(history, None, &[], &[(history, history)], None);
}

#[test]
fn environment_override_keeps_precedence_and_supports_exact_files() {
    let fixture = Fixture::new();
    for data_dir in ["cass-state", "selected/.aider.chat.history.md"] {
        let history = "configured/.aider.chat.history.md";
        fixture.run(data_dir, Some(history), &[], &[(history, history)], None);
    }
    fixture.run(
        "selected/.aider.chat.history.md",
        Some("configured"),
        &[],
        &[
            ("configured", "configured/.aider.chat.history.md"),
            ("configured", "configured/nested/.aider.chat.history.md"),
        ],
        None,
    );
    fixture.run("selected", Some("missing-override"), &[], &[], None);
}

#[test]
fn explicit_remote_roots_remain_exclusive_and_deduplicated() {
    let fixture = Fixture::new();
    let history = "cass-state/mirror/project/.aider.chat.history.md";
    fixture.run(
        "selected",
        Some("configured"),
        &[history, "cass-state/mirror", history],
        &[(history, history)],
        None,
    );
    fixture.run("selected", Some("configured"), &["missing-root"], &[], None);
}

#[test]
fn incremental_scan_filters_the_same_sources_as_discovery() {
    let history = "selected/.aider.chat.history.md";
    Fixture::new().run(history, None, &[], &[], Some(i64::MAX));
}
