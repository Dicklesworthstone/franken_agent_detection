//! Cline SDK storage resolution through the feature-independent detector and,
//! when enabled, the public connector. Child processes isolate `HOME` and all
//! `CLINE_*` overrides. The static fixtures follow cline/cline at
//! c3a40572765b76873c597247941118c1778d02c8, `shared/storage/paths.ts` and
//! `core/services/session-{artifacts,data}.ts`; they need no optional JSON crate
//! in a detection-only build.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use franken_agent_detection::{
    AgentDetectOptions, AgentDetectRootOverride, default_probe_paths_tilde, detect_installed_agents,
};
use tempfile::TempDir;

const CHILD: &str = "FAD_CLINE_SDK_DETECTION_CHILD";
const EXPECTED_ROOTS: &str = "FAD_CLINE_SDK_DETECTION_ROOTS";
const EXPECTED_SOURCES: &str = "FAD_CLINE_SDK_DETECTION_SOURCES";
const SCOPE: &str = "FAD_CLINE_SDK_DETECTION_SCOPE";
const LEGACY_ROOT: &str = "home/.config/Code/User/globalStorage/saoudrizwan.claude-dev";
const MANIFEST: &str = r#"{
    "version":1,"session_id":"session-native","source":"vscode","pid":1,
    "started_at":"2026-10-11T10:00:00.000Z","ended_at":"2026-10-11T10:00:01.000Z",
    "status":"completed","provider":"anthropic","model":"claude-sonnet-4",
    "cwd":"/work","workspace_root":"/work","prompt":"SDK prompt",
    "metadata":{"title":"SDK session"}
}"#;
const MESSAGES: &str = r#"{
    "version":1,"agent":"lead","sessionId":"session-native",
    "origin":{"source":"vscode","mode":"user","sessionId":"session-native"},
    "messages":[
        {"id":"sdk-user","role":"user","content":[{"type":"text","text":"SDK prompt"}],
         "ts":1791712800000},
        {"id":"sdk-assistant","role":"assistant","content":[{"type":"text","text":"SDK reply"}],
         "ts":1791712801000,"modelInfo":{"id":"claude-sonnet-4","provider":"anthropic"},
         "metrics":{"inputTokens":100,"outputTokens":20,"cacheReadTokens":30,"cacheWriteTokens":10}}
    ]
}"#;
const LEGACY_MESSAGES: &str = r#"[
    {"type":"say","say":"task","text":"Legacy prompt","ts":1791712800000},
    {"type":"say","say":"text","text":"Legacy reply","ts":1791712801000}
]"#;

struct SourceFile {
    path: PathBuf,
    bytes: &'static str,
    modified: SystemTime,
}

struct Fixture {
    directory: TempDir,
    files: Vec<SourceFile>,
    legacy: bool,
}

impl Fixture {
    fn new(legacy: bool) -> Self {
        let mut fixture = Self {
            directory: TempDir::new().unwrap(),
            files: Vec::new(),
            legacy,
        };
        for root in [
            "home/.cline/data/sessions",
            "profile/.cline/data/sessions",
            "drive/home/.cline/data/sessions",
            "configured-sessions",
            "configured-data/sessions",
            "configured-cline/data/sessions",
            "selected/sessions",
            "~/literal-sessions",
            "home/literal-sessions",
        ] {
            fixture.write(
                &format!("{root}/session-native/session-native.json"),
                MANIFEST,
            );
            fixture.write(
                &format!("{root}/session-native/session-native.messages.json"),
                MESSAGES,
            );
        }
        if legacy {
            fixture.write(
                &format!("{LEGACY_ROOT}/tasks/legacy-task/ui_messages.json"),
                LEGACY_MESSAGES,
            );
        }
        fixture.write("not-a-directory", "unrelated file");
        std::fs::create_dir(fixture.path("empty-sessions")).unwrap();
        fixture
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.directory.path().join(relative)
    }

    fn write(&mut self, relative: &str, bytes: &'static str) {
        let path = self.path(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        self.files.push(SourceFile {
            path,
            bytes,
            modified,
        });
    }

    fn run(
        &self,
        env: &[(&str, OsString)],
        expected_sdk_root: Option<&Path>,
        scope: Option<&Path>,
        sdk_has_messages: bool,
    ) {
        let mut expected_roots: Vec<PathBuf> = expected_sdk_root
            .map(|root| scope.unwrap_or(root).to_path_buf())
            .into_iter()
            .collect();
        let mut expected_sources: Vec<PathBuf> = expected_sdk_root
            .filter(|_| sdk_has_messages)
            .map(|root| root.join("session-native/session-native.messages.json"))
            .into_iter()
            .collect();
        if self.legacy && scope.is_none() {
            expected_roots.push(self.path(LEGACY_ROOT));
            expected_sources
                .push(self.path(&format!("{LEGACY_ROOT}/tasks/legacy-task/ui_messages.json")));
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "cline_sdk_detection_child", "--nocapture"])
            .current_dir(self.directory.path())
            .env(CHILD, self.directory.path())
            .env("HOME", self.path("home"))
            .env("USERPROFILE", self.path("home"))
            .env(
                EXPECTED_ROOTS,
                std::env::join_paths(&expected_roots).unwrap(),
            )
            .env(
                EXPECTED_SOURCES,
                std::env::join_paths(&expected_sources).unwrap(),
            )
            .env_remove(SCOPE)
            .env_remove("HOMEDRIVE")
            .env_remove("HOMEPATH")
            .env_remove("CLINE_SESSION_DATA_DIR")
            .env_remove("CLINE_DATA_DIR")
            .env_remove("CLINE_DIR");
        for (key, value) in env {
            command.env(key, value);
        }
        if let Some(scope) = scope {
            command.env(SCOPE, scope);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "env={env:?}, roots={expected_roots:?}, sources={expected_sources:?}, scope={scope:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        for file in &self.files {
            assert_eq!(std::fs::read(&file.path).unwrap(), file.bytes.as_bytes());
            assert_eq!(
                std::fs::metadata(&file.path).unwrap().modified().unwrap(),
                file.modified,
            );
        }
    }
}

fn paths_from_env(key: &str) -> Vec<PathBuf> {
    std::env::split_paths(&std::env::var_os(key).unwrap())
        .filter(|path| !path.as_os_str().is_empty())
        .collect()
}

#[test]
fn cline_sdk_detection_child() {
    let Some(directory) = std::env::var_os(CHILD).map(PathBuf::from) else {
        return;
    };
    let scope = std::env::var_os(SCOPE).map(PathBuf::from);
    let expected = paths_from_env(EXPECTED_ROOTS);
    let report = detect_installed_agents(&AgentDetectOptions {
        only_connectors: Some(vec!["cline".into()]),
        include_undetected: true,
        root_overrides: scope
            .as_ref()
            .map(|root| AgentDetectRootOverride {
                slug: "cline".into(),
                root: root.clone(),
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
    assert_eq!(entry.slug, "cline");
    assert_eq!(entry.detected, !expected.is_empty());
    assert_eq!(
        entry
            .root_paths
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>(),
        expected
    );

    #[cfg(feature = "connectors")]
    scanner::assert_scans(&directory, scope.as_deref());
    #[cfg(not(feature = "connectors"))]
    let _ = directory;
}

#[cfg(feature = "connectors")]
mod scanner {
    use super::{EXPECTED_SOURCES, Path, PathBuf, paths_from_env};
    use franken_agent_detection::token_extraction::extract_tokens_for_agent;
    use franken_agent_detection::{
        ClineConnector, Connector, ExtractedTokenUsage, ScanContext, ScanRoot, TokenDataSource,
    };

    pub fn assert_scans(directory: &Path, scope: Option<&Path>) {
        let expected: Vec<_> = paths_from_env(EXPECTED_SOURCES);
        let context = ScanContext::with_roots(
            directory.join("cass-state"),
            scope
                .map(|scope| ScanRoot::local(scope.to_path_buf()))
                .into_iter()
                .collect(),
            None,
        );
        let mut contexts = vec![context];
        if let Some(scope) = scope {
            contexts.push(ScanContext::local_default(scope.to_path_buf(), None));
        }
        for context in contexts {
            let conversations = ClineConnector::new().scan(&context).unwrap();
            let mut actual_sources: Vec<_> = conversations
                .iter()
                .map(|conversation| conversation.source_path.canonicalize().unwrap())
                .collect();
            let mut expected_sources: Vec<_> = expected
                .iter()
                .map(|path| path.canonicalize().unwrap())
                .collect();
            actual_sources.sort();
            expected_sources.sort();
            assert_eq!(actual_sources, expected_sources);
            assert_eq!(conversations.len(), expected.len());
            for conversation in conversations {
                assert_eq!(conversation.agent_slug, "cline");
                if conversation.external_id.as_deref() == Some("session-native") {
                    assert_eq!(conversation.title.as_deref(), Some("SDK session"));
                    assert_eq!(conversation.workspace, Some(PathBuf::from("/work")));
                    assert_eq!(conversation.messages.len(), 2);
                    assert_eq!(conversation.messages[0].content, "SDK prompt");
                    assert_eq!(conversation.messages[0].role, "user");
                    assert_eq!(conversation.messages[1].content, "SDK reply");
                    assert_eq!(conversation.messages[1].role, "assistant");
                    let usages: Vec<_> = conversation
                        .messages
                        .iter()
                        .map(|message| {
                            extract_tokens_for_agent(
                                "cline",
                                &message.extra,
                                &message.content,
                                &message.role,
                            )
                        })
                        .collect();
                    assert_eq!(usages[0].data_source, TokenDataSource::Estimated);
                    assert_eq!(usages[1].data_source, TokenDataSource::Api);
                    assert_eq!(usages[1].input_tokens, Some(60));
                    assert_eq!(usages[1].output_tokens, Some(20));
                    assert_eq!(usages[1].cache_read_tokens, Some(30));
                    assert_eq!(usages[1].cache_creation_tokens, Some(10));
                    assert_eq!(
                        usages
                            .iter()
                            .filter(|usage| usage.data_source == TokenDataSource::Api)
                            .filter_map(ExtractedTokenUsage::total_tokens)
                            .sum::<i64>(),
                        120
                    );
                } else {
                    assert_eq!(conversation.external_id.as_deref(), Some("legacy-task"));
                    assert_eq!(conversation.messages.len(), 2);
                    assert_eq!(conversation.messages[0].content, "Legacy prompt");
                    assert_eq!(conversation.messages[1].content, "Legacy reply");
                }
            }
        }
    }
}

#[test]
fn native_sdk_default_store_is_detected_and_scanned() {
    let fixture = Fixture::new(false);
    fixture.run(
        &[],
        Some(&fixture.path("home/.cline/data/sessions")),
        None,
        true,
    );
}

#[test]
fn sdk_environment_precedence_and_blank_overrides_match_writer() {
    let fixture = Fixture::new(false);
    let cline = fixture.path("configured-cline");
    let data = fixture.path("configured-data");
    let sessions = fixture.path("configured-sessions");
    let mut env = vec![("CLINE_DIR", cline.clone().into_os_string())];
    fixture.run(&env, Some(&cline.join("data/sessions")), None, true);
    env.push(("CLINE_DATA_DIR", data.clone().into_os_string()));
    fixture.run(&env, Some(&data.join("sessions")), None, true);
    env.push(("CLINE_SESSION_DATA_DIR", sessions.clone().into_os_string()));
    fixture.run(&env, Some(&sessions), None, true);
    env[2].1 = format!("  {} \n", sessions.display()).into();
    fixture.run(&env, Some(&sessions), None, true);
    env[2].1 = " \t ".into();
    fixture.run(&env, Some(&data.join("sessions")), None, true);
    env[1].1 = "".into();
    fixture.run(&env, Some(&cline.join("data/sessions")), None, true);
    env[0].1 = " \n ".into();
    fixture.run(
        &env,
        Some(&fixture.path("home/.cline/data/sessions")),
        None,
        true,
    );
}

#[test]
fn sdk_literal_tilde_and_relative_roots_follow_node_paths() {
    let fixture = Fixture::new(false);
    for (key, value, expected) in [
        (
            "CLINE_SESSION_DATA_DIR",
            "~/literal-sessions",
            "~/literal-sessions",
        ),
        (
            "CLINE_SESSION_DATA_DIR",
            "missing/../configured-sessions",
            "configured-sessions",
        ),
        (
            "CLINE_DATA_DIR",
            "missing/../configured-data",
            "configured-data/sessions",
        ),
        (
            "CLINE_DIR",
            "missing/../configured-cline",
            "configured-cline/data/sessions",
        ),
    ] {
        fixture.run(
            &[(key, value.into())],
            Some(Path::new(expected)),
            None,
            true,
        );
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(fixture.path("home/.cline"), fixture.path("link")).unwrap();
        fixture.run(
            &[(
                "CLINE_SESSION_DATA_DIR",
                "link/../configured-sessions".into(),
            )],
            Some(Path::new("configured-sessions")),
            None,
            true,
        );
    }
}

#[test]
fn sdk_invalid_override_never_falls_back_but_keeps_legacy() {
    for legacy in [false, true] {
        let fixture = Fixture::new(legacy);
        for invalid in ["missing-sessions", "not-a-directory"] {
            fixture.run(
                &[
                    ("CLINE_DIR", fixture.path("configured-cline").into()),
                    ("CLINE_DATA_DIR", fixture.path("configured-data").into()),
                    ("CLINE_SESSION_DATA_DIR", fixture.path(invalid).into()),
                ],
                None,
                None,
                false,
            );
        }
    }
}

#[test]
fn sdk_explicit_roots_and_files_ignore_environment_and_home() {
    let fixture = Fixture::new(true);
    let env = [(
        "CLINE_SESSION_DATA_DIR",
        fixture.path("configured-sessions").into(),
    )];
    let sessions = fixture.path("selected/sessions");
    for relative in [
        "selected/sessions",
        "selected/sessions/session-native",
        "selected/sessions/session-native/session-native.messages.json",
        "selected/sessions/session-native/session-native.json",
    ] {
        fixture.run(&env, Some(&sessions), Some(&fixture.path(relative)), true);
    }
    for relative in [
        "missing/.cline/data/sessions",
        "selected/sessions/missing-session",
        "selected/sessions/session-native/missing.messages.json",
    ] {
        fixture.run(&env, None, Some(&fixture.path(relative)), false);
    }
}

#[test]
fn empty_sdk_directory_is_installation_evidence_without_transcripts() {
    let fixture = Fixture::new(false);
    let empty = fixture.path("empty-sessions");
    fixture.run(
        &[("CLINE_SESSION_DATA_DIR", empty.clone().into())],
        Some(&empty),
        None,
        false,
    );
}

#[test]
fn sdk_home_precedence_matches_shared_storage_paths() {
    let fixture = Fixture::new(false);
    let profile = fixture.path("profile");
    fixture.run(
        &[
            (
                "HOME",
                format!("  {}  ", fixture.path("home").display()).into(),
            ),
            ("USERPROFILE", profile.clone().into()),
        ],
        Some(&fixture.path("home/.cline/data/sessions")),
        None,
        true,
    );
    for home in ["~", "", " \t "] {
        fixture.run(
            &[
                ("HOME", home.into()),
                ("USERPROFILE", format!("  {}  ", profile.display()).into()),
            ],
            Some(&profile.join(".cline/data/sessions")),
            None,
            true,
        );
    }
    fixture.run(
        &[
            ("HOME", "".into()),
            ("USERPROFILE", "".into()),
            ("HOMEDRIVE", fixture.path("drive").into()),
            (
                "HOMEPATH",
                format!("{}home", std::path::MAIN_SEPARATOR).into(),
            ),
        ],
        Some(&fixture.path("drive/home/.cline/data/sessions")),
        None,
        true,
    );
}

#[test]
fn remote_cline_probes_include_sdk_and_legacy_stores() {
    let (_, paths) = default_probe_paths_tilde()
        .into_iter()
        .find(|(slug, _)| *slug == "cline")
        .unwrap();
    assert!(paths.iter().any(|path| path == "~/.cline/data/sessions"));
    assert!(
        paths
            .iter()
            .any(|path| path == "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev")
    );
}
