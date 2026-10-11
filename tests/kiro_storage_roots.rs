//! Kiro 2.3+ moves the supported v2 JSONL store with `KIRO_HOME`.
//! Isolated children exercise the feature-independent detector and, when
//! enabled, the connector without changing the test process's environment.
#![cfg(unix)]

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

use franken_agent_detection::{
    AgentDetectOptions, AgentDetectRootOverride, detect_installed_agents,
};
use tempfile::TempDir;

const CHILD: &str = "FAD_KIRO_STORAGE_CHILD";
const EXPECTED: &str = "FAD_KIRO_STORAGE_EXPECTED";
const SCOPE: &str = "FAD_KIRO_STORAGE_SCOPE";
const LOG: &str = concat!(
    "{\"version\":\"v1\",\"kind\":\"Prompt\",\"data\":{\"content\":[{\"kind\":\"text\",\"data\":\"Saved prompt\"}],\"meta\":{\"timestamp\":1785939877}}}\n",
    "{\"version\":\"v1\",\"kind\":\"AssistantMessage\",\"data\":{\"content\":[{\"kind\":\"text\",\"data\":\"Saved reply\"}]}}\n",
);
const METADATA: &str = r#"{"session_id":"session-one","cwd":"/work/project","title":"Saved Kiro session","created_at":"2026-08-05T12:00:00Z","session_state":{"version":"v1","model_info":{"model_id":"claude-sonnet"}}}"#;

struct Fixture {
    directory: TempDir,
    files: Vec<(PathBuf, &'static str, SystemTime)>,
}

impl Fixture {
    fn new() -> Self {
        let directory = TempDir::new().unwrap();
        let mut files = Vec::new();
        for home in ["home/.kiro", "work profile", "selected"] {
            let cli = directory.path().join(home).join("sessions/cli");
            std::fs::create_dir_all(&cli).unwrap();
            for (name, bytes) in [("session-one.jsonl", LOG), ("session-one.json", METADATA)] {
                let path = cli.join(name);
                std::fs::write(&path, bytes).unwrap();
                let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
                files.push((path, bytes, modified));
            }
        }
        let unrelated = directory.path().join("not-a-directory");
        std::fs::write(&unrelated, "unrelated file").unwrap();
        let modified = std::fs::metadata(&unrelated).unwrap().modified().unwrap();
        files.push((unrelated, "unrelated file", modified));
        Self { directory, files }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.directory.path().join(relative)
    }

    fn run(&self, kiro_home: Option<&OsStr>, expected_home: Option<&str>, scope: Option<&str>) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "kiro_storage_child", "--nocapture"])
            .current_dir(self.directory.path())
            .env("HOME", self.path("home"))
            .env("USERPROFILE", self.path("home"))
            .env(CHILD, self.directory.path())
            .env_remove("KIRO_HOME")
            .env_remove(EXPECTED)
            .env_remove(SCOPE);
        if let Some(home) = &kiro_home {
            command.env("KIRO_HOME", home);
        }
        if let Some(expected) = expected_home {
            command.env(EXPECTED, self.path(expected));
        }
        if let Some(scope) = scope {
            command.env(SCOPE, self.path(scope));
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "KIRO_HOME={kiro_home:?}, expected={expected_home:?}, scope={scope:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        for (path, bytes, modified) in &self.files {
            assert_eq!(std::fs::read(path).unwrap(), bytes.as_bytes());
            assert_eq!(
                std::fs::metadata(path).unwrap().modified().unwrap(),
                *modified
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn kiro_storage_child() {
    let Some(directory) = std::env::var_os(CHILD).map(PathBuf::from) else {
        return;
    };
    let expected_home = std::env::var_os(EXPECTED).map(PathBuf::from);
    let scope = std::env::var_os(SCOPE).map(PathBuf::from);
    let expected_roots: Vec<PathBuf> = scope.as_ref().map_or_else(
        || {
            expected_home
                .iter()
                .flat_map(|home| [home.join("sessions/cli"), home.clone()])
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
        only_connectors: Some(vec!["kiro-cli".into()]),
        include_undetected: true,
        root_overrides: scope
            .iter()
            .map(|root| AgentDetectRootOverride {
                slug: "kiro".into(),
                root: root.clone(),
            })
            .collect(),
    })
    .unwrap();
    assert_eq!(report.installed_agents.len(), 1);
    assert_eq!(report.installed_agents[0].slug, "kiro");
    assert_eq!(
        report.installed_agents[0].detected,
        !expected_roots.is_empty()
    );
    assert_eq!(
        report.installed_agents[0].root_paths,
        expected_roots
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
    );

    #[cfg(feature = "connectors")]
    {
        use franken_agent_detection::{
            Connector, DiscoveredSourceRole, KiroConnector, ScanContext, ScanRoot, SourceScanHooks,
        };

        let ctx = scope.as_ref().map_or_else(
            || ScanContext::local_default(directory.join("cass-state"), None),
            |root| {
                ScanContext::with_roots(
                    directory.join("cass-state"),
                    vec![ScanRoot::local(root.clone())],
                    None,
                )
            },
        );
        let connector = KiroConnector::new();
        if scope.is_none() {
            assert_eq!(connector.detect().root_paths, expected_roots);
        }
        let expected_file = expected_home
            .as_ref()
            .map(|home| home.join("sessions/cli/session-one.jsonl"));
        let discovered = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(
            discovered.len(),
            if expected_file.is_some() { 2 } else { 0 }
        );
        if let Some(file) = &expected_file {
            assert!(discovered.iter().any(|source| {
                source.source_path == *file
                    && source.role == DiscoveredSourceRole::PrimarySessionLog
            }));
            assert!(discovered.iter().any(|source| {
                source.source_path == file.with_extension("json")
                    && source.role == DiscoveredSourceRole::MetadataSidecar
            }));
        }
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(conversations.len(), usize::from(expected_file.is_some()));
        if let Some(file) = &expected_file {
            let conversation = &conversations[0];
            assert_eq!(conversation.source_path, *file);
            assert!(!conversation.external_id.as_ref().unwrap().is_empty());
            assert_eq!(conversation.title.as_deref(), Some("Saved Kiro session"));
            assert_eq!(conversation.messages.len(), 2);
            assert_eq!(conversation.messages[0].content, "Saved prompt");
            assert_eq!(conversation.messages[1].content, "Saved reply");
        }
        let mut emitted = Vec::new();
        let mut completions = Vec::new();
        let mut complete = |completion: &franken_agent_detection::SourceCompletion| {
            completions.push(completion.source.source_path.clone());
            Ok(())
        };
        connector
            .scan_with_source_boundaries(
                &ctx,
                &mut SourceScanHooks {
                    on_source_complete: Some(&mut complete),
                    ..SourceScanHooks::default()
                },
                &mut |conversation| {
                    emitted.push(conversation.source_path);
                    Ok(())
                },
            )
            .unwrap();
        let expected_files: Vec<_> = expected_file.into_iter().collect();
        assert_eq!(emitted, expected_files);
        assert_eq!(completions, expected_files);
    }

    #[cfg(not(feature = "connectors"))]
    let _ = directory;
}

#[test]
fn kiro_home_relocates_detection_discovery_and_scan() {
    let fixture = Fixture::new();
    fixture.run(None, Some("home/.kiro"), None);
    fixture.run(Some(OsStr::new("")), Some("home/.kiro"), None);
    fixture.run(
        Some(fixture.path("work profile").as_os_str()),
        Some("work profile"),
        None,
    );
}

#[test]
fn kiro_missing_or_file_home_does_not_fall_back_to_another_profile() {
    let fixture = Fixture::new();
    for home in ["missing", "not-a-directory"] {
        fixture.run(Some(fixture.path(home).as_os_str()), None, None);
    }
}

#[test]
fn kiro_explicit_roots_override_the_environment_without_widening() {
    let fixture = Fixture::new();
    for scope in [
        "selected",
        "selected/sessions",
        "selected/sessions/cli",
        "selected/sessions/cli/session-one.jsonl",
    ] {
        fixture.run(
            Some(fixture.path("work profile").as_os_str()),
            Some("selected"),
            Some(scope),
        );
    }
    for scope in ["missing", "missing/sessions/cli", "missing/.kiro"] {
        fixture.run(
            Some(fixture.path("work profile").as_os_str()),
            None,
            Some(scope),
        );
    }
}
