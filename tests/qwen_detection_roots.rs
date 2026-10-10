//! Qwen runtime-store precedence through the feature-independent detector.
//! Child processes isolate environment and home-directory resolution.
#![cfg(unix)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use franken_agent_detection::{
    AgentDetectOptions, AgentDetectRootOverride, detect_installed_agents,
};
use tempfile::TempDir;

const CHILD_ROOT: &str = "FAD_QWEN_DETECT_ROOT";
const CHILD_EXPECTED: &str = "FAD_QWEN_DETECT_EXPECTED";
const CHILD_SCOPE: &str = "FAD_QWEN_DETECT_SCOPE";

struct Fixture(TempDir);

impl Fixture {
    fn new() -> Self {
        let fixture = Self(TempDir::new().unwrap());
        for base in [
            "home/.qwen",
            "configured",
            "runtime",
            "home/tilde-root",
            "scoped",
        ] {
            for store in ["projects", "tmp"] {
                std::fs::create_dir_all(fixture.path(base).join(store)).unwrap();
            }
        }
        std::fs::write(fixture.path("not-a-directory"), "unrelated").unwrap();
        fixture
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.0.path().join(relative)
    }

    fn run(&self, env: &[(&str, OsString)], expected_base: Option<&str>, scope: Option<&str>) {
        let expected: Vec<_> = expected_base
            .into_iter()
            .flat_map(|base| {
                let root = self.path(base);
                if scope.is_some() {
                    vec![root]
                } else {
                    vec![root.join("projects"), root.join("tmp"), root]
                }
            })
            .collect();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "qwen_detection_child", "--nocapture"])
            .current_dir(self.0.path())
            .env("HOME", self.path("home"))
            .env("USERPROFILE", self.path("home"))
            .env(CHILD_ROOT, self.0.path())
            .env(CHILD_EXPECTED, std::env::join_paths(&expected).unwrap())
            .env_remove(CHILD_SCOPE)
            .env_remove("QWEN_RUNTIME_DIR")
            .env_remove("QWEN_HOME");
        for (key, value) in env {
            command.env(key, value);
        }
        if let Some(scope) = scope {
            command.env(CHILD_SCOPE, self.path(scope));
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "env={env:?}, expected={expected:?}, scope={scope:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(
            std::fs::read(self.path("not-a-directory")).unwrap(),
            b"unrelated"
        );
    }
}

#[test]
fn qwen_detection_child() {
    if std::env::var_os(CHILD_ROOT).is_none() {
        return;
    }
    let expected: Vec<_> = std::env::split_paths(&std::env::var_os(CHILD_EXPECTED).unwrap())
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| path.display().to_string())
        .collect();
    let report = detect_installed_agents(&AgentDetectOptions {
        only_connectors: Some(vec!["qwen-code".into()]),
        include_undetected: true,
        root_overrides: std::env::var_os(CHILD_SCOPE)
            .map(|path| AgentDetectRootOverride {
                slug: "qwen".into(),
                root: PathBuf::from(path),
            })
            .into_iter()
            .collect(),
    })
    .unwrap();
    assert_eq!(report.summary.total_count, 1);
    assert_eq!(
        report.summary.detected_count,
        usize::from(!expected.is_empty())
    );
    assert_eq!(report.installed_agents.len(), 1);
    let entry = &report.installed_agents[0];
    assert_eq!(entry.slug, "qwen");
    assert_eq!(entry.detected, !expected.is_empty());
    assert_eq!(entry.root_paths, expected);
}

#[test]
fn qwen_runtime_directory_replaces_home_and_default_stores() {
    let fixture = Fixture::new();
    fixture.run(&[], Some("home/.qwen"), None);
    fixture.run(
        &[("QWEN_HOME", fixture.path("configured").into())],
        Some("configured"),
        None,
    );
    fixture.run(
        &[
            ("QWEN_HOME", fixture.path("configured").into()),
            ("QWEN_RUNTIME_DIR", fixture.path("runtime").into()),
        ],
        Some("runtime"),
        None,
    );
}

#[test]
fn qwen_missing_or_non_directory_runtime_does_not_fall_back() {
    let fixture = Fixture::new();
    for root in ["missing", "not-a-directory"] {
        fixture.run(
            &[
                ("QWEN_HOME", fixture.path("configured").into()),
                ("QWEN_RUNTIME_DIR", fixture.path(root).into()),
            ],
            None,
            None,
        );
    }
}

#[test]
fn qwen_env_paths_expand_tilde_and_resolve_relative_to_cwd() {
    let fixture = Fixture::new();
    for path in ["~/tilde-root", "~\\tilde-root"] {
        fixture.run(
            &[("QWEN_RUNTIME_DIR", path.into())],
            Some("home/tilde-root"),
            None,
        );
    }
    fixture.run(
        &[("QWEN_HOME", "configured".into())],
        Some("configured"),
        None,
    );
    fixture.run(
        &[("QWEN_RUNTIME_DIR", "missing/../configured".into())],
        Some("configured"),
        None,
    );
    fixture.run(
        &[("QWEN_RUNTIME_DIR", "~/absent/../tilde-root".into())],
        Some("home/tilde-root"),
        None,
    );
    std::os::unix::fs::symlink(fixture.path("configured/projects"), fixture.path("link")).unwrap();
    // Native path.resolve removes link/.. without following the symlink.
    for value in [
        OsString::from("link/../runtime"),
        fixture.path("link/../runtime").into_os_string(),
    ] {
        fixture.run(&[("QWEN_RUNTIME_DIR", value)], Some("runtime"), None);
    }
    fixture.run(
        &[
            ("QWEN_RUNTIME_DIR", "".into()),
            ("QWEN_HOME", "configured".into()),
        ],
        Some("configured"),
        None,
    );
}

#[test]
fn qwen_explicit_detector_roots_take_precedence_over_environment() {
    let fixture = Fixture::new();
    fixture.run(
        &[("QWEN_RUNTIME_DIR", fixture.path("runtime").into())],
        Some("scoped"),
        Some("scoped"),
    );
    fixture.run(
        &[("QWEN_RUNTIME_DIR", fixture.path("runtime").into())],
        None,
        Some("absent-scope"),
    );
}
