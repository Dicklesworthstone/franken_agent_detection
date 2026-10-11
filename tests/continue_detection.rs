//! Continue's native `CONTINUE_GLOBAL_DIR` precedence, shared by detection and
//! ingestion. Child processes isolate HOME/CWD/environment for every case.
//! Source: continuedev/continue@5522c6f44ca0ac3528b37244818fbfa39b5af470,
//! core/util/paths.ts (relative resolution, literal tilde, empty-value fallback).
#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

use franken_agent_detection::{
    AgentDetectOptions, AgentDetectRootOverride, detect_installed_agents,
};
use tempfile::TempDir;

const CHILD: &str = "FAD_CONTINUE_DETECTION_CHILD";
const EXPECTED: &str = "FAD_CONTINUE_DETECTION_EXPECTED";
const SCOPE: &str = "FAD_CONTINUE_DETECTION_SCOPE";
const SESSION: &str = r#"{"sessionId":"env-session","title":"Saved Continue history","workspaceDirectory":"/project","history":[{"message":{"role":"user","content":"native prompt"}},{"message":{"role":"assistant","content":"native reply","usage":{"prompt_tokens":10,"completion_tokens":5}}}]}"#;

struct Fixture {
    directory: TempDir,
    files: Vec<(PathBuf, SystemTime)>,
}

impl Fixture {
    fn new() -> Self {
        let directory = TempDir::new().unwrap();
        let mut files = Vec::new();
        for root in ["home/.continue", "work profile", "selected", "~/literal"] {
            let sessions = directory.path().join(root).join("sessions");
            fs::create_dir_all(&sessions).unwrap();
            let file = sessions.join("env-session.json");
            fs::write(&file, SESSION).unwrap();
            files.push((
                file.clone(),
                fs::metadata(file).unwrap().modified().unwrap(),
            ));
        }
        fs::write(directory.path().join("not-a-directory"), "unrelated").unwrap();
        Self { directory, files }
    }

    fn path(&self, path: &str) -> PathBuf {
        self.directory.path().join(path)
    }

    fn run(&self, configured: Option<&OsStr>, expected: Option<&str>, scope: Option<&str>) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "continue_detection_child", "--nocapture"])
            .current_dir(self.directory.path())
            .env("HOME", self.path("home"))
            .env("USERPROFILE", self.path("home"))
            .env(CHILD, self.directory.path())
            .env_remove("CONTINUE_GLOBAL_DIR")
            .env_remove(EXPECTED)
            .env_remove(SCOPE);
        if let Some(configured) = configured {
            command.env("CONTINUE_GLOBAL_DIR", configured);
        }
        if let Some(expected) = expected {
            command.env(EXPECTED, self.path(expected));
        }
        if let Some(scope) = scope {
            command.env(SCOPE, self.path(scope));
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "configured={configured:?} expected={expected:?} scope={scope:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        for (file, modified) in &self.files {
            assert_eq!(fs::read(file).unwrap(), SESSION.as_bytes());
            assert_eq!(fs::metadata(file).unwrap().modified().unwrap(), *modified);
        }
        assert!(!self.path("missing").exists());
        assert_eq!(
            fs::read(self.path("not-a-directory")).unwrap(),
            b"unrelated"
        );
    }
}

#[test]
fn continue_detection_child() {
    let Some(directory) = std::env::var_os(CHILD).map(PathBuf::from) else {
        return;
    };
    let expected = std::env::var_os(EXPECTED).map(PathBuf::from);
    let scope = std::env::var_os(SCOPE).map(PathBuf::from);
    let expected_roots: Vec<_> = scope.as_ref().map_or_else(
        || {
            expected
                .iter()
                .flat_map(|root| [root.join("sessions"), root.clone()])
                .collect()
        },
        |scope| {
            scope
                .exists()
                .then_some(scope.clone())
                .into_iter()
                .collect()
        },
    );
    let report = detect_installed_agents(&AgentDetectOptions {
        only_connectors: Some(vec!["continue-dev".into()]),
        include_undetected: true,
        root_overrides: scope
            .iter()
            .map(|root| AgentDetectRootOverride {
                slug: "continue".into(),
                root: root.clone(),
            })
            .collect(),
    })
    .unwrap();
    assert_eq!(report.installed_agents.len(), 1);
    let entry = &report.installed_agents[0];
    assert_eq!(entry.slug, "continue");
    assert_eq!(entry.detected, !expected_roots.is_empty());
    assert_eq!(
        entry.root_paths,
        expected_roots
            .iter()
            .map(|root| root.display().to_string())
            .collect::<Vec<_>>()
    );
    #[cfg(feature = "connectors")]
    {
        use franken_agent_detection::{
            Connector, ContinueConnector, ScanContext, ScanRoot, TokenDataSource,
            extract_tokens_for_agent,
        };
        let connector = ContinueConnector::new();
        if scope.is_none() {
            assert_eq!(connector.detect().root_paths, expected_roots);
        }
        let ctx = ScanContext::with_roots(
            directory.join("cass-state"),
            scope
                .iter()
                .map(|root| ScanRoot::local(root.clone()))
                .collect(),
            None,
        );
        let sources = connector.discover_source_files(&ctx).unwrap();
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(sources.len(), usize::from(expected.is_some()));
        assert_eq!(conversations.len(), usize::from(expected.is_some()));
        if let Some(expected) = expected {
            let expected_file = expected.join("sessions/env-session.json");
            assert_eq!(sources[0].source_path, expected_file);
            assert_eq!(conversations[0].source_path, expected_file);
            assert_eq!(conversations[0].external_id.as_deref(), Some("env-session"));
            let message = &conversations[0].messages[1];
            let usage = extract_tokens_for_agent(
                "continue",
                &message.extra,
                &message.content,
                &message.role,
            );
            assert_eq!(usage.data_source, TokenDataSource::Api);
            assert_eq!(usage.total_tokens(), Some(15));
        }
    }
    #[cfg(not(feature = "connectors"))]
    let _ = directory;
}

#[test]
fn continue_default_and_empty_override_use_native_home() {
    let fixture = Fixture::new();
    fixture.run(None, Some("home/.continue"), None);
    fixture.run(Some(OsStr::new("")), Some("home/.continue"), None);
}

#[test]
fn continue_absolute_relative_and_literal_tilde_overrides_match_producer() {
    let fixture = Fixture::new();
    fixture.run(
        Some(fixture.path("work profile").as_os_str()),
        Some("work profile"),
        None,
    );
    fixture.run(Some(OsStr::new("work profile")), Some("work profile"), None);
    fixture.run(Some(OsStr::new("~/literal")), Some("~/literal"), None);
}

#[test]
fn continue_missing_or_file_override_never_falls_back_to_default_history() {
    let fixture = Fixture::new();
    fixture.run(Some(fixture.path("missing").as_os_str()), None, None);
    fixture.run(
        Some(fixture.path("not-a-directory").as_os_str()),
        None,
        None,
    );
}

#[test]
fn continue_explicit_scopes_remain_isolated_from_environment() {
    let fixture = Fixture::new();
    for scope in [
        "selected",
        "selected/sessions",
        "selected/sessions/env-session.json",
    ] {
        fixture.run(
            Some(fixture.path("work profile").as_os_str()),
            Some("selected"),
            Some(scope),
        );
    }
    fixture.run(
        Some(fixture.path("work profile").as_os_str()),
        None,
        Some("missing"),
    );
}
