//! Pi environment precedence through public detection and real session scans.
//! Child processes isolate environment changes from parallel test execution.
//! Unix home lookup honors HOME; Windows uses the known-folder API instead.
#![cfg(all(feature = "connectors", unix))]

use std::path::{Path, PathBuf};
use std::process::Command;

use franken_agent_detection::{
    AgentDetectOptions, AgentDetectRootOverride, Connector, InstalledAgentDetectionEntry,
    NormalizedConversation, PiAgentConnector, ScanContext, ScanRoot, detect_installed_agents,
};
use serde_json::json;
use tempfile::TempDir;

const CHILD_ROOT: &str = "FAD_PI_DETECTION_TEST_ROOT";
const CHILD_ROOTS: &str = "FAD_PI_DETECTION_TEST_EXPECTED_ROOTS";
const CHILD_SOURCES: &str = "FAD_PI_DETECTION_TEST_EXPECTED_SOURCES";
const CHILD_SCOPE: &str = "FAD_PI_DETECTION_TEST_SCOPE";

struct Fixture {
    root: TempDir,
    files: Vec<PathBuf>,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let directories = [
            "home/.pi/agent/sessions/project",
            "configured-sessions/project",
            "configured-agent/sessions/project",
            "scoped-home/.pi/agent/sessions/project",
            // The other Pi-family provider must not leak into Pi's default scan.
            "home/.omp/agent/sessions/project",
        ];
        let files = directories
            .iter()
            .enumerate()
            .map(|(index, directory)| {
                let path = root
                    .path()
                    .join(directory)
                    .join(format!("2026-10-09T10-00-00_fixture-{index}.jsonl"));
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                let header = json!({
                    "type": "session", "version": 3, "id": format!("fixture-{index}"),
                    "timestamp": "2026-10-09T10:00:00Z", "cwd": root.path(),
                });
                let message = json!({
                    "type": "message", "id": format!("message-{index}"),
                    "timestamp": "2026-10-09T10:00:01Z",
                    "message": {"role": "user", "content": format!("fixture-{index}")},
                });
                std::fs::write(&path, format!("{header}\n{message}\n")).unwrap();
                path
            })
            .collect();
        // Detection probes these durable roots separately from ordinary Pi
        // sessions. Their precedence must not be affected by PI_SESSIONS_DIR.
        for directory in ["home/.pi/agent", "configured-agent"] {
            std::fs::create_dir_all(
                root.path()
                    .join(directory)
                    .join("experimental/durable-sessions"),
            )
            .unwrap();
        }
        Self { root, files }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    fn default_sessions(&self) -> PathBuf {
        self.path("home/.pi/agent/sessions")
    }

    fn run(
        &self,
        sessions_dir: Option<&Path>,
        agent_dir: Option<&Path>,
        expected_roots: &[PathBuf],
        expected_indices: &[usize],
        scope: Option<&Path>,
    ) {
        let expected_sources: Vec<_> = expected_indices
            .iter()
            .map(|&index| &self.files[index])
            .collect();
        let before: Vec<_> = self
            .files
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "pi_detection_child", "--nocapture"])
            .current_dir(self.root.path())
            .env(CHILD_ROOT, self.root.path())
            .env(CHILD_ROOTS, serde_json::to_string(expected_roots).unwrap())
            .env(
                CHILD_SOURCES,
                serde_json::to_string(&expected_sources).unwrap(),
            )
            .env("HOME", self.path("home"))
            .env("USERPROFILE", self.path("home"))
            .env("XDG_DATA_HOME", self.path("empty-xdg"));
        for key in [
            "PI_SESSIONS_DIR",
            "PI_CODING_AGENT_DIR",
            "PI_CODING_AGENT_SESSION_DIR",
            "CASS_OMP_DATA_ROOT",
            "CASS_EXCLUDE_PATHS",
            "OMP_PROFILE",
            "PI_PROFILE",
            "PI_CONFIG_DIR",
            CHILD_SCOPE,
        ] {
            command.env_remove(key);
        }
        if let Some(path) = sessions_dir {
            command.env("PI_SESSIONS_DIR", path);
        }
        if let Some(path) = agent_dir {
            command.env("PI_CODING_AGENT_DIR", path);
        }
        if let Some(path) = scope {
            command.env(CHILD_SCOPE, path);
        }
        let output = command
            .output()
            .expect("run isolated Pi detection regression");
        assert!(
            output.status.success(),
            "sessions={sessions_dir:?} agent={agent_dir:?} scope={scope:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        for (path, original) in self.files.iter().zip(before) {
            assert_eq!(
                std::fs::read(path).unwrap(),
                original,
                "source changed: {}",
                path.display(),
            );
        }
    }
}

fn detect(slug: &str, scope: Option<&Path>) -> InstalledAgentDetectionEntry {
    let report = detect_installed_agents(&AgentDetectOptions {
        only_connectors: Some(vec![slug.into()]),
        include_undetected: true,
        root_overrides: scope
            .map(|root| AgentDetectRootOverride {
                slug: slug.into(),
                root: root.to_path_buf(),
            })
            .into_iter()
            .collect(),
    })
    .unwrap();
    assert_eq!(report.summary.total_count, 1);
    assert_eq!(report.installed_agents.len(), 1);
    let entry = report.installed_agents.into_iter().next().unwrap();
    assert_eq!(report.summary.detected_count, usize::from(entry.detected));
    entry
}

fn assert_sources(conversations: &[NormalizedConversation], expected: &[PathBuf], root: &Path) {
    let mut actual: Vec<_> = conversations
        .iter()
        .map(|conversation| {
            assert_eq!(conversation.agent_slug, "pi_agent");
            assert_eq!(conversation.workspace.as_deref(), Some(root));
            assert_eq!(conversation.messages.len(), 1);
            assert_eq!(conversation.messages[0].idx, 0);
            assert_eq!(
                conversation.metadata["session_id"],
                conversation.messages[0].content,
            );
            conversation.source_path.clone()
        })
        .collect();
    let mut expected = expected.to_vec();
    actual.sort();
    expected.sort();
    // Do not deduplicate: each admitted file must produce exactly one session.
    assert_eq!(actual, expected);
}

#[test]
fn pi_detection_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let expected_roots: Vec<PathBuf> =
        serde_json::from_str(&std::env::var(CHILD_ROOTS).unwrap()).unwrap();
    let expected_sources: Vec<PathBuf> =
        serde_json::from_str(&std::env::var(CHILD_SOURCES).unwrap()).unwrap();
    let scope = std::env::var_os(CHILD_SCOPE).map(PathBuf::from);
    let entry = detect("pi-agent", scope.as_deref());
    assert_eq!(entry.slug, "pi_agent");
    assert_eq!(entry.detected, !expected_sources.is_empty());
    assert_eq!(
        entry
            .root_paths
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>(),
        expected_roots,
    );

    let connector = PiAgentConnector::new();
    if scope.is_none() {
        let detected = connector.detect();
        assert_eq!(detected.detected, entry.detected);
        assert_eq!(detected.root_paths, expected_roots);
    }
    let ctx = scope.map_or_else(
        || ScanContext::local_default(root.join("cass-state"), None),
        |scope| {
            ScanContext::with_roots(root.join("cass-state"), vec![ScanRoot::local(scope)], None)
        },
    );
    // Model a host that only scans providers which pass detection. The missing
    // additive root regression used to drop the healthy default session here.
    let gated = if entry.detected {
        connector.scan(&ctx).unwrap()
    } else {
        Vec::new()
    };
    assert_sources(&gated, &expected_sources, &root);
    // Also confirm detection and the scanner agree when the detector says no.
    let scanned = connector.scan(&ctx).unwrap();
    assert_sources(&scanned, &expected_sources, &root);
    let mut discovered: Vec<_> = connector
        .discover_source_files(&ctx)
        .unwrap()
        .into_iter()
        .map(|source| source.source_path)
        .collect();
    let mut expected_sorted = expected_sources;
    discovered.sort();
    expected_sorted.sort();
    assert_eq!(discovered, expected_sorted);

    let omp = detect("omp", None);
    assert_eq!(
        omp.root_paths,
        ["home/.omp/agent/sessions", "home/.omp/agent"]
            .map(|relative| root.join(relative).display().to_string()),
    );
    let durable = detect("pi_durable", None);
    let agent = std::env::var_os("PI_CODING_AGENT_DIR")
        .filter(|value| !value.is_empty())
        .map_or_else(|| root.join("home/.pi/agent"), PathBuf::from);
    let durable_root = agent.join("experimental/durable-sessions");
    assert_eq!(durable.detected, durable_root.exists());
    assert_eq!(
        durable.root_paths,
        if durable_root.exists() {
            vec![durable_root.display().to_string()]
        } else {
            Vec::new()
        },
    );
}

#[test]
fn unset_overrides_detect_and_scan_default_pi_history() {
    let fixture = Fixture::new();
    fixture.run(None, None, &[fixture.default_sessions()], &[0], None);
}

#[test]
fn empty_overrides_preserve_default_pi_history() {
    let fixture = Fixture::new();
    fixture.run(
        Some(Path::new("")),
        Some(Path::new("")),
        &[fixture.default_sessions()],
        &[0],
        None,
    );
}

#[test]
fn sessions_override_adds_history_without_hiding_default_history() {
    let fixture = Fixture::new();
    let sessions = fixture.path("configured-sessions");
    fixture.run(
        Some(&sessions),
        None,
        &[sessions.clone(), fixture.default_sessions()],
        &[0, 1],
        None,
    );
}

#[test]
fn missing_sessions_override_keeps_default_history_detected_and_scanned() {
    let fixture = Fixture::new();
    fixture.run(
        Some(&fixture.path("missing-sessions")),
        None,
        &[fixture.default_sessions()],
        &[0],
        None,
    );
}

#[test]
fn coding_agent_override_replaces_default_pi_history() {
    let fixture = Fixture::new();
    let agent = fixture.path("configured-agent");
    fixture.run(None, Some(&agent), &[agent.join("sessions")], &[2], None);
}

#[test]
fn both_overrides_keep_both_custom_roots_and_suppress_default_history() {
    let fixture = Fixture::new();
    let sessions = fixture.path("configured-sessions");
    let agent = fixture.path("configured-agent");
    fixture.run(
        Some(&sessions),
        Some(&agent),
        &[sessions.clone(), agent.join("sessions")],
        &[1, 2],
        None,
    );
}

#[test]
fn missing_coding_agent_override_still_suppresses_default_history() {
    let fixture = Fixture::new();
    let agent = fixture.path("missing-agent");
    fixture.run(None, Some(&agent), &[], &[], None);
    let sessions = fixture.path("configured-sessions");
    fixture.run(
        Some(&sessions),
        Some(&agent),
        std::slice::from_ref(&sessions),
        &[1],
        None,
    );
}

#[test]
fn explicit_detection_and_scan_roots_exclude_environment_and_default_history() {
    let fixture = Fixture::new();
    let scope = fixture.path("scoped-home");
    fixture.run(
        Some(&fixture.path("configured-sessions")),
        Some(&fixture.path("configured-agent")),
        std::slice::from_ref(&scope),
        &[3],
        Some(&scope),
    );
    let missing_scope = fixture.path("missing-home");
    fixture.run(
        Some(&fixture.path("configured-sessions")),
        Some(&fixture.path("configured-agent")),
        &[],
        &[],
        Some(&missing_scope),
    );
}
