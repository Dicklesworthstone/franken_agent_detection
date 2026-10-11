//! Copilot CLI history belongs to its own detector, including remote probes.
//! Subprocesses isolate home lookup without requiring connector features.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

use franken_agent_detection::{
    AgentDetectOptions, AgentDetectRootOverride, default_probe_paths_tilde, detect_installed_agents,
};
use tempfile::TempDir;

const CHILD: &str = "FAD_COPILOT_DETECTION_CHILD";
const EXPECTED_CLI: &str = "FAD_COPILOT_DETECTION_EXPECTED_CLI";
const EXPECTED_VSCODE: &str = "FAD_COPILOT_DETECTION_EXPECTED_VSCODE";
const CLI_SCOPE: &str = "FAD_COPILOT_DETECTION_CLI_SCOPE";
const VSCODE_SCOPE: &str = "FAD_COPILOT_DETECTION_VSCODE_SCOPE";

const CLI_PROBES: [&str; 5] = [
    ".copilot/session-state",
    ".copilot/history-session-state",
    ".config/gh-copilot",
    ".config/gh/copilot",
    ".local/share/github-copilot",
];
const VSCODE_PROBES: [&str; 11] = [
    ".github-copilot",
    ".config/github-copilot",
    ".config/Code/User/globalStorage/github.copilot-chat",
    ".config/Code - Insiders/User/globalStorage/github.copilot-chat",
    ".config/VSCodium/User/globalStorage/github.copilot-chat",
    "Library/Application Support/Code/User/globalStorage/github.copilot-chat",
    "Library/Application Support/Code - Insiders/User/globalStorage/github.copilot-chat",
    "Library/Application Support/VSCodium/User/globalStorage/github.copilot-chat",
    "AppData/Roaming/Code/User/globalStorage/github.copilot-chat",
    "AppData/Roaming/Code - Insiders/User/globalStorage/github.copilot-chat",
    "AppData/Roaming/VSCodium/User/globalStorage/github.copilot-chat",
];

struct Fixture(TempDir);

impl Fixture {
    fn new() -> Self {
        let fixture = Self(TempDir::new().unwrap());
        std::fs::create_dir(fixture.0.path().join("home")).unwrap();
        fixture
    }

    fn create_probes(&self, probes: &[&str]) -> Vec<PathBuf> {
        probes
            .iter()
            .map(|relative| {
                let path = self.0.path().join("home").join(relative);
                std::fs::create_dir_all(&path).unwrap();
                path
            })
            .collect()
    }

    fn run(
        &self,
        expected_cli: &[PathBuf],
        expected_vscode: &[PathBuf],
        cli_scope: Option<&Path>,
        vscode_scope: Option<&Path>,
    ) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "copilot_detection_child", "--nocapture"])
            .current_dir(self.0.path())
            .env(CHILD, "1")
            .env("HOME", self.0.path().join("home"))
            .env("USERPROFILE", self.0.path().join("home"))
            .env(EXPECTED_CLI, std::env::join_paths(expected_cli).unwrap())
            .env(
                EXPECTED_VSCODE,
                std::env::join_paths(expected_vscode).unwrap(),
            )
            .env_remove(CLI_SCOPE)
            .env_remove(VSCODE_SCOPE);
        if let Some(path) = cli_scope {
            command.env(CLI_SCOPE, path);
        }
        if let Some(path) = vscode_scope {
            command.env(VSCODE_SCOPE, path);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "cli={expected_cli:?}, vscode={expected_vscode:?}, cli_scope={cli_scope:?}, vscode_scope={vscode_scope:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
fn copilot_detection_child() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    let report = detect_installed_agents(&AgentDetectOptions {
        only_connectors: Some(
            [
                "copilot",
                "github-copilot",
                "copilot_cli",
                "copilot-cli",
                "gh-copilot",
            ]
            .map(String::from)
            .to_vec(),
        ),
        include_undetected: true,
        root_overrides: [(CLI_SCOPE, "gh-copilot"), (VSCODE_SCOPE, "copilot")]
            .into_iter()
            .filter_map(|(key, slug)| {
                std::env::var_os(key).map(|path| AgentDetectRootOverride {
                    slug: slug.into(),
                    root: PathBuf::from(path),
                })
            })
            .collect(),
    })
    .unwrap();
    assert_eq!(report.summary.total_count, 2);
    assert_eq!(report.installed_agents.len(), 2);
    let mut detected_count = 0;
    for (entry, (slug, expected_key)) in report.installed_agents.iter().zip([
        ("copilot_cli", EXPECTED_CLI),
        ("github-copilot", EXPECTED_VSCODE),
    ]) {
        let expected: Vec<_> = std::env::split_paths(&std::env::var_os(expected_key).unwrap())
            .filter(|path| !path.as_os_str().is_empty())
            .map(|path| path.display().to_string())
            .collect();
        assert_eq!(entry.slug, slug);
        assert_eq!(entry.detected, !expected.is_empty(), "{slug}");
        assert_eq!(entry.root_paths, expected, "{slug}");
        detected_count += usize::from(entry.detected);
    }
    assert_eq!(report.summary.detected_count, detected_count);
}

#[test]
fn cli_only_history_does_not_detect_vscode_copilot() {
    let fixture = Fixture::new();
    let cli = fixture.create_probes(&CLI_PROBES);
    fixture.run(&cli, &[], None, None);
}

#[test]
fn vscode_extension_and_legacy_probes_remain_available() {
    let fixture = Fixture::new();
    let vscode = fixture.create_probes(&VSCODE_PROBES);
    fixture.run(&[], &vscode, None, None);
}

#[test]
fn mixed_installation_keeps_each_providers_roots_separate() {
    let fixture = Fixture::new();
    let cli = fixture.create_probes(&CLI_PROBES);
    let vscode = fixture.create_probes(&VSCODE_PROBES);
    fixture.run(&cli, &vscode, None, None);
}

#[test]
fn aliased_explicit_roots_replace_only_the_selected_provider() {
    let fixture = Fixture::new();
    let cli = fixture.create_probes(&CLI_PROBES);
    let vscode = fixture.create_probes(&VSCODE_PROBES);
    let scope = fixture.0.path().join("copied-store");
    std::fs::create_dir(&scope).unwrap();
    let missing = fixture.0.path().join("missing-store");

    fixture.run(std::slice::from_ref(&scope), &vscode, Some(&scope), None);
    fixture.run(&cli, std::slice::from_ref(&scope), None, Some(&scope));
    fixture.run(
        std::slice::from_ref(&scope),
        &[],
        Some(&scope),
        Some(&missing),
    );
    fixture.run(
        &[],
        std::slice::from_ref(&scope),
        Some(&missing),
        Some(&scope),
    );
}

#[test]
fn remote_tilde_probes_assign_cli_history_to_cli_only() {
    let probes: std::collections::HashMap<_, _> = default_probe_paths_tilde().into_iter().collect();
    assert_eq!(
        probes["copilot_cli"],
        CLI_PROBES.map(|relative| format!("~/{relative}")),
    );
    assert_eq!(
        probes["github-copilot"],
        VSCODE_PROBES.map(|relative| format!("~/{relative}")),
    );
}
