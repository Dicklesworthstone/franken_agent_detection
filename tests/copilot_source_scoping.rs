//! Public Copilot source ownership and scoped-store regression tests.
//!
//! Native fixtures follow microsoft/vscode cc3fec8846d0e678357e476fa611774da26d7e24,
//! chatSessionStore.ts and chatModel.ts. CLI locations follow github/copilot-cli's
//! 0.0.342 migration notes. Each scenario isolates the platform home in a child
//! process; no process-global environment is changed by parallel Rust tests.
#![cfg(all(feature = "connectors", unix))]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use franken_agent_detection::{
    Connector, CopilotConnector, DiscoveredSourceRole, NormalizedConversation, Origin, Platform,
    ScanContext, ScanRoot, SourceScanHooks, get_connector_factories,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tempfile::TempDir;

const CHILD_ROOT: &str = "FAD_COPILOT_SCOPE_ROOT";
const CHILD_DATA: &str = "FAD_COPILOT_SCOPE_DATA";
const CHILD_ROOTS: &str = "FAD_COPILOT_SCOPE_EXPLICIT_ROOTS";
const CHILD_EXPECTED: &str = "FAD_COPILOT_SCOPE_EXPECTED";
const CHILD_DUAL: &str = "FAD_COPILOT_SCOPE_DUAL";
const CHILD_SINCE: &str = "FAD_COPILOT_SCOPE_SINCE";
const USER_ROOT: &str = "selected/.config/Code/User";
const NATIVE_DIR: &str = "selected/.config/Code/User/workspaceStorage/project/chatSessions";
const EXTENSION_DIR: &str = "selected/.config/Code/User/globalStorage/github.copilot-chat";

#[derive(Clone, Serialize, Deserialize)]
struct ExpectedSource {
    provider: String,
    path: PathBuf,
    session_id: Option<String>,
    sidecar: bool,
    workspace: bool,
}

struct Fixture {
    root: TempDir,
    sources: BTreeMap<String, ExpectedSource>,
}

fn native_session(id: &str) -> Value {
    json!({
        "version": 3,
        "sessionId": id,
        "creationDate": 1_790_000_000_000_i64,
        "responderUsername": "GitHub Copilot",
        "requests": [{
            "requestId": format!("request-{id}"),
            "timestamp": 1_790_000_000_000_i64,
            "agent": {"extensionId": {"value": "GitHub.copilot-chat"}, "name": "GitHub Copilot"},
            "message": {"text": "Inspect the project"},
            "response": [{"value": "Reviewed the project."}],
        }],
    })
}

fn legacy_session(id: &str) -> Value {
    json!({
        "id": id,
        "cwd": "/workspace/project",
        "workspaceFolder": "/workspace/project",
        "messages": [
            {"role": "user", "content": "Inspect the project"},
            {"role": "assistant", "content": "Reviewed the project."},
        ],
    })
}

impl Fixture {
    fn new() -> Self {
        let mut fixture = Self {
            root: TempDir::new().unwrap(),
            sources: BTreeMap::new(),
        };
        for base in ["home", "selected"] {
            fixture.add_tree(base);
        }
        fixture.add(
            "archived",
            "selected/archive/chatSessions/archived.jsonl",
            &format!("{}\n", json!({"kind": 0, "v": native_session("archived")})),
            Some("archived"),
            false,
            false,
            false,
        );
        let mut foreign = native_session("foreign");
        foreign["responderUsername"] = "Other provider".into();
        foreign["requests"][0]["agent"] = json!({"extensionId": {"value": "other.chat"}});
        fixture.add(
            "foreign",
            "selected/filtered/chatSessions/foreign.json",
            &foreign.to_string(),
            None,
            false,
            false,
            false,
        );
        for suffix in ["json", "jsonl"] {
            fixture.add(
                &format!("malformed-{suffix}"),
                &format!("selected/filtered/chatSessions/malformed.{suffix}"),
                "{incomplete",
                None,
                false,
                false,
                false,
            );
        }
        for directory in [
            "cwd",
            "selected/empty/chatSessions",
            "selected/empty/copilot-chat",
        ] {
            std::fs::create_dir_all(fixture.root.path().join(directory)).unwrap();
        }
        fixture
    }

    #[allow(clippy::too_many_lines)] // Keep both provider layouts visible in one fixture.
    fn add_tree(&mut self, base: &str) {
        let user = format!("{base}/.config/Code/User");
        for (kind, relative, workspace) in [
            (
                "native",
                "workspaceStorage/project/chatSessions/native.json",
                true,
            ),
            (
                "neighbor",
                "workspaceStorage/neighbor/chatSessions/neighbor.jsonl",
                true,
            ),
            (
                "empty",
                "globalStorage/emptyWindowChatSessions/empty.json",
                false,
            ),
            (
                "transferred",
                "globalStorage/transferredChatSessions/transferred.jsonl",
                false,
            ),
        ] {
            let id = format!("{base}-{kind}");
            let session = native_session(&id);
            let content = if Path::new(relative)
                .extension()
                .is_some_and(|extension| extension == "jsonl")
            {
                format!("{}\n", json!({"kind": 0, "v": session}))
            } else {
                session.to_string()
            };
            self.add(
                &id,
                &format!("{user}/{relative}"),
                &content,
                Some(&id),
                false,
                false,
                workspace,
            );
        }
        for project in ["project", "neighbor"] {
            self.add(
                &format!("{base}-{project}-workspace"),
                &format!("{user}/workspaceStorage/{project}/workspace.json"),
                r#"{"folder":"file:///workspace/project"}"#,
                None,
                false,
                true,
                false,
            );
        }
        let id = format!("{base}-extension");
        self.add(
            &id,
            &format!("{user}/globalStorage/github.copilot-chat/export.json"),
            &legacy_session(&id).to_string(),
            Some(&id),
            false,
            false,
            true,
        );
        for (kind, relative) in [
            ("legacy-cli", ".copilot/history-session-state/legacy.json"),
            ("gh-cli", ".config/gh-copilot/history.json"),
            ("nested-gh-cli", ".config/gh/copilot/history.json"),
            ("share-cli", ".local/share/github-copilot/history.json"),
        ] {
            let id = format!("{base}-{kind}");
            self.add(
                &id,
                &format!("{base}/{relative}"),
                &legacy_session(&id).to_string(),
                Some(&id),
                true,
                false,
                true,
            );
        }
        let id = format!("{base}-current-cli");
        let events = [
            json!({"type": "session.start", "data": {"sessionId": id, "cwd": "/workspace/project"}}),
            json!({"type": "user.message", "data": {"content": "Inspect the project"}}),
            json!({"type": "assistant.message", "data": {"content": "Reviewed the project."}}),
        ]
        .into_iter()
        .fold(String::new(), |mut output, event| {
            writeln!(output, "{event}").unwrap();
            output
        });
        self.add(
            &id,
            &format!("{base}/.copilot/session-state/current/events.jsonl"),
            &events,
            Some(&id),
            true,
            false,
            true,
        );
    }

    #[allow(clippy::too_many_arguments)] // One fixture entry carries source and projection expectations.
    fn add(
        &mut self,
        name: &str,
        relative: &str,
        content: &str,
        session_id: Option<&str>,
        cli: bool,
        sidecar: bool,
        workspace: bool,
    ) {
        let path = self.root.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        self.sources.insert(
            name.to_string(),
            ExpectedSource {
                provider: if cli { "copilot_cli" } else { "copilot" }.to_string(),
                path,
                session_id: session_id.map(String::from),
                sidecar,
                workspace,
            },
        );
    }

    fn run(
        &self,
        data_dir: &str,
        roots: &[&str],
        names: &[&str],
        dual: bool,
        since_ts: Option<i64>,
    ) {
        let expected: Vec<_> = names.iter().map(|name| &self.sources[*name]).collect();
        let original: Vec<_> = self
            .sources
            .values()
            .map(|source| {
                (
                    source.path.clone(),
                    std::fs::read(&source.path).unwrap(),
                    std::fs::metadata(&source.path).unwrap().modified().unwrap(),
                )
            })
            .collect();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "copilot_scope_child", "--nocapture"])
            .current_dir(self.root.path().join("cwd"))
            .env("HOME", self.root.path().join("home"))
            .env("USERPROFILE", self.root.path().join("home"))
            .env("XDG_CONFIG_HOME", self.root.path().join("home/.config"))
            .env("APPDATA", self.root.path().join("home/AppData/Roaming"))
            .env(CHILD_ROOT, self.root.path())
            .env(CHILD_DATA, data_dir)
            .env(CHILD_ROOTS, serde_json::to_string(roots).unwrap())
            .env(CHILD_EXPECTED, serde_json::to_string(&expected).unwrap())
            .env(CHILD_DUAL, dual.to_string())
            .env(CHILD_SINCE, serde_json::to_string(&since_ts).unwrap())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "data_dir={data_dir:?}, roots={roots:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for (path, bytes, modified) in original {
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert_eq!(
                std::fs::metadata(&path).unwrap().modified().unwrap(),
                modified
            );
        }
    }
}

fn assert_conversations(conversations: &[NormalizedConversation], expected: &[&ExpectedSource]) {
    let expected: BTreeMap<_, _> = expected
        .iter()
        .filter_map(|source| {
            source
                .session_id
                .as_ref()
                .map(|id| (source.path.as_path(), (id, *source)))
        })
        .collect();
    assert_eq!(conversations.len(), expected.len());
    let actual_paths: std::collections::BTreeSet<_> = conversations
        .iter()
        .map(|conversation| conversation.source_path.as_path())
        .collect();
    assert_eq!(
        actual_paths.len(),
        conversations.len(),
        "a source must emit once"
    );
    for conversation in conversations {
        let (id, source) = expected[conversation.source_path.as_path()];
        assert_eq!(conversation.agent_slug, source.provider);
        assert_eq!(conversation.external_id.as_ref(), Some(id));
        assert_eq!(conversation.title.as_deref(), Some("Inspect the project"));
        assert_eq!(
            conversation.workspace.as_deref(),
            source.workspace.then_some(Path::new("/workspace/project"))
        );
        assert_eq!(conversation.messages.len(), 2);
        for (idx, (role, content)) in [
            ("user", "Inspect the project"),
            ("assistant", "Reviewed the project."),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(conversation.messages[idx].idx, i64::try_from(idx).unwrap());
            assert_eq!(conversation.messages[idx].role, role);
            assert_eq!(conversation.messages[idx].content, content);
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Every public scan route shares the same isolated expectations.
fn copilot_scope_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let roots: Vec<String> = serde_json::from_str(&std::env::var(CHILD_ROOTS).unwrap()).unwrap();
    let expected: Vec<ExpectedSource> =
        serde_json::from_str(&std::env::var(CHILD_EXPECTED).unwrap()).unwrap();
    let since_ts: Option<i64> = serde_json::from_str(&std::env::var(CHILD_SINCE).unwrap()).unwrap();
    let dual = std::env::var(CHILD_DUAL).unwrap() == "true";
    let remote = Origin::remote_with_host("copilot-archive", "copilot.example");
    let ctx = ScanContext::with_roots(
        root.join(std::env::var(CHILD_DATA).unwrap()),
        roots
            .iter()
            .map(|path| ScanRoot::remote(root.join(path), remote.clone(), Some(Platform::Linux)))
            .collect(),
        since_ts,
    );
    let factories: Vec<_> = get_connector_factories()
        .into_iter()
        .filter(|(slug, _)| *slug == "copilot" || (dual && *slug == "copilot_cli"))
        .collect();
    assert_eq!(factories.len(), if dual { 2 } else { 1 });
    for (slug, factory) in factories {
        let connector = factory();
        let expected: Vec<_> = expected
            .iter()
            .filter(|source| source.provider == slug)
            .collect();
        let discovered = connector.discover_source_files(&ctx).unwrap();
        let expected_paths: std::collections::BTreeSet<_> = expected
            .iter()
            .map(|source| source.path.as_path())
            .collect();
        let actual_paths: std::collections::BTreeSet<_> = discovered
            .iter()
            .map(|source| source.source_path.as_path())
            .collect();
        assert_eq!(discovered.len(), expected.len(), "provider={slug}");
        assert_eq!(actual_paths, expected_paths, "provider={slug}");
        for source in discovered {
            let wanted = expected
                .iter()
                .find(|wanted| wanted.path == source.source_path)
                .unwrap();
            assert_eq!(source.provider_slug, slug);
            assert_eq!(
                source.role,
                if wanted.sidecar {
                    DiscoveredSourceRole::MetadataSidecar
                } else {
                    DiscoveredSourceRole::PrimarySessionLog
                }
            );
            assert_eq!(source.required_for_reconstruction, !wanted.sidecar);
            assert_eq!(
                source.origin,
                if roots.is_empty() {
                    Origin::local()
                } else {
                    remote.clone()
                }
            );
            assert_eq!(
                source.platform,
                (!roots.is_empty()).then_some(Platform::Linux)
            );
            assert!(source.size_bytes.unwrap() > 0);
            assert!(source.modified_at_ms.is_some());
            if !roots.is_empty() {
                assert!(
                    ctx.scan_roots
                        .iter()
                        .any(|scan_root| source.scan_root.starts_with(&scan_root.path))
                );
            }
        }
        let conversations = connector.scan(&ctx).unwrap();
        assert_conversations(&conversations, &expected);
        let mut callback = Vec::new();
        connector
            .scan_with_callback(&ctx, &mut |conversation| {
                callback.push(conversation);
                Ok(())
            })
            .unwrap();
        assert_conversations(&callback, &expected);
        assert_eq!(
            serde_json::to_value(&callback).unwrap(),
            serde_json::to_value(&conversations).unwrap()
        );
        assert!(connector.supports_streaming_scan());
        assert_eq!(
            connector.supports_source_boundaries(),
            slug == "copilot_cli"
        );
        let mut boundary = Vec::new();
        connector
            .scan_with_source_boundaries(
                &ctx,
                &mut SourceScanHooks::default(),
                &mut |conversation| {
                    boundary.push(conversation);
                    Ok(())
                },
            )
            .unwrap();
        assert_conversations(&boundary, &expected);
    }
}

fn vscode_names(base: &str) -> Vec<String> {
    [
        "native",
        "neighbor",
        "empty",
        "transferred",
        "extension",
        "project-workspace",
        "neighbor-workspace",
    ]
    .into_iter()
    .map(|name| format!("{base}-{name}"))
    .collect()
}

fn all_names(base: &str) -> Vec<String> {
    let mut names = vscode_names(base);
    names.extend(
        [
            "legacy-cli",
            "current-cli",
            "gh-cli",
            "nested-gh-cli",
            "share-cli",
        ]
        .map(|name| format!("{base}-{name}")),
    );
    names
}

#[test]
fn default_registry_assigns_each_cli_source_only_to_cli() {
    let names = all_names("home");
    Fixture::new().run(
        "cass-state",
        &[],
        &names.iter().map(String::as_str).collect::<Vec<_>>(),
        true,
        None,
    );
}

#[test]
fn broad_explicit_registry_separates_cli_and_vscode_sources() {
    let fixture = Fixture::new();
    let names = all_names("selected");
    fixture.run(
        "cass-state",
        &["selected"],
        &names.iter().map(String::as_str).collect::<Vec<_>>(),
        true,
        None,
    );
    let mut config_names = vscode_names("selected");
    config_names.extend(["selected-gh-cli".into(), "selected-nested-gh-cli".into()]);
    fixture.run(
        "cass-state",
        &["selected/.config"],
        &config_names.iter().map(String::as_str).collect::<Vec<_>>(),
        true,
        None,
    );
    fixture.run(
        "cass-state",
        &["selected/.copilot"],
        &["selected-legacy-cli", "selected-current-cli"],
        true,
        None,
    );
    fixture.run(
        "cass-state",
        &["selected/.config/gh"],
        &["selected-nested-gh-cli"],
        true,
        None,
    );
}

#[test]
fn native_context_files_containers_and_workspace_directories_stay_scoped() {
    let fixture = Fixture::new();
    let path = format!("{NATIVE_DIR}/native.json");
    for scope in [
        path.as_str(),
        NATIVE_DIR,
        "selected/.config/Code/User/workspaceStorage/project",
    ] {
        for explicit in [false, true] {
            fixture.run(
                scope,
                if explicit {
                    std::slice::from_ref(&scope)
                } else {
                    &[]
                },
                &["selected-native", "selected-project-workspace"],
                false,
                None,
            );
        }
    }
    fixture.run(
        "selected/.config/Code/User/workspaceStorage",
        &[],
        &[
            "selected-native",
            "selected-neighbor",
            "selected-project-workspace",
            "selected-neighbor-workspace",
        ],
        false,
        None,
    );
}

#[test]
fn native_global_containers_keep_their_own_scope() {
    let fixture = Fixture::new();
    for (container, name, file) in [
        ("emptyWindowChatSessions", "selected-empty", "empty.json"),
        (
            "transferredChatSessions",
            "selected-transferred",
            "transferred.jsonl",
        ),
    ] {
        let path = format!("{USER_ROOT}/globalStorage/{container}");
        fixture.run(&path, &[], &[name], false, None);
        fixture.run(&format!("{path}/{file}"), &[], &[name], false, None);
        fixture.run("cass-state", &[&path], &[name], false, None);
    }
}

#[test]
fn shared_native_bases_keep_scoped_extension_exports() {
    let fixture = Fixture::new();
    let names = vscode_names("selected");
    for scope in ["selected/.config", "selected/.config/Code", USER_ROOT] {
        fixture.run(
            scope,
            &[],
            &names.iter().map(String::as_str).collect::<Vec<_>>(),
            false,
            None,
        );
    }
    fixture.run(
        "selected/.config/Code/User/globalStorage",
        &[],
        &[
            "selected-extension",
            "selected-empty",
            "selected-transferred",
        ],
        false,
        None,
    );
}

#[test]
fn supplied_missing_and_empty_stores_do_not_read_live_history() {
    let fixture = Fixture::new();
    for scope in [
        "missing/chatSessions",
        "missing/workspaceStorage/project",
        "missing/Code/User",
        "missing/globalStorage",
        "missing/github.copilot-chat",
        "missing/github.copilot-chat/absent.json",
        "selected/.config/Code/User/workspaceStorage/project/chatSessions/absent.jsonl",
        "selected/empty/chatSessions",
        "selected/empty/copilot-chat",
        "selected/.copilot",
        "selected/.config/gh",
    ] {
        fixture.run(scope, &[], &[], false, None);
        fixture.run("cass-state", &[scope], &[], false, None);
    }
}

#[test]
fn archive_directory_names_do_not_override_explicit_vscode_evidence() {
    let mut fixture = Fixture::new();
    fixture.add_tree("archive/github-copilot");
    let base = "archive/github-copilot/.config/Code/User";
    let native = format!("{base}/workspaceStorage/project/chatSessions/native.json");
    let extension = format!("{base}/globalStorage/github.copilot-chat/export.json");
    for (path, expected) in [
        (
            native.as_str(),
            vec![
                "archive/github-copilot-native",
                "archive/github-copilot-project-workspace",
            ],
        ),
        (extension.as_str(), vec!["archive/github-copilot-extension"]),
    ] {
        fixture.run(path, &[], &expected, false, None);
        fixture.run("cass-state", &[path], &expected, false, None);
    }
    let names = vscode_names("archive/github-copilot");
    fixture.run(
        base,
        &[],
        &names.iter().map(String::as_str).collect::<Vec<_>>(),
        false,
        None,
    );
    fixture.run(
        "cass-state",
        &["archive/github-copilot"],
        &names.iter().map(String::as_str).collect::<Vec<_>>(),
        false,
        None,
    );
}

#[test]
fn exact_extension_files_are_discovered_and_emitted_once() {
    let fixture = Fixture::new();
    let path = format!("{EXTENSION_DIR}/export.json");
    fixture.run(&path, &[], &["selected-extension"], false, None);
    fixture.run("cass-state", &[&path], &["selected-extension"], false, None);
    fixture.run(EXTENSION_DIR, &[], &["selected-extension"], false, None);
}

#[test]
fn exact_cli_files_and_directories_are_exclusive_to_cli() {
    let fixture = Fixture::new();
    for (scope, name) in [
        (
            "selected/.copilot/history-session-state/legacy.json",
            "selected-legacy-cli",
        ),
        (
            "selected/.copilot/session-state/current/events.jsonl",
            "selected-current-cli",
        ),
        ("selected/.config/gh-copilot", "selected-gh-cli"),
        (
            "selected/.config/gh/copilot/history.json",
            "selected-nested-gh-cli",
        ),
        (
            "selected/.local/share/github-copilot/history.json",
            "selected-share-cli",
        ),
    ] {
        fixture.run(scope, &[], &[name], true, None);
        fixture.run("cass-state", &[scope], &[name], true, None);
    }
}

#[test]
fn overlapping_roots_do_not_duplicate_extension_or_native_files() {
    let fixture = Fixture::new();
    let names = vscode_names("selected");
    fixture.run(
        "cass-state",
        &[
            USER_ROOT,
            EXTENSION_DIR,
            &format!("{EXTENSION_DIR}/export.json"),
            NATIVE_DIR,
            &format!("{NATIVE_DIR}/native.json"),
        ],
        &names.iter().map(String::as_str).collect::<Vec<_>>(),
        false,
        None,
    );
}

#[test]
fn ancestor_symlink_aliases_do_not_duplicate_copilot_sources() {
    let fixture = Fixture::new();
    std::os::unix::fs::symlink(
        fixture.root.path().join("selected"),
        fixture.root.path().join("zz-copy"),
    )
    .unwrap();
    let names = vscode_names("selected");
    fixture.run(
        "cass-state",
        &["zz-copy", "selected"],
        &names.iter().map(String::as_str).collect::<Vec<_>>(),
        false,
        None,
    );
}

#[test]
fn archived_and_rejected_exact_sources_remain_scoped() {
    let fixture = Fixture::new();
    fixture.run(
        "selected/archive/chatSessions/archived.jsonl",
        &[],
        &["archived"],
        false,
        None,
    );
    fixture.run(
        "cass-state",
        &["selected/archive/chatSessions/archived.jsonl"],
        &["archived"],
        false,
        None,
    );
    for (name, file) in [
        ("foreign", "foreign.json"),
        ("malformed-json", "malformed.json"),
        ("malformed-jsonl", "malformed.jsonl"),
    ] {
        fixture.run(
            &format!("selected/filtered/chatSessions/{file}"),
            &[],
            &[name],
            false,
            None,
        );
    }
    fixture.run(
        "selected/filtered/chatSessions",
        &[],
        &["foreign", "malformed-json", "malformed-jsonl"],
        false,
        None,
    );
}

#[test]
fn scoped_sources_keep_incremental_filtering() {
    let fixture = Fixture::new();
    fixture.run(USER_ROOT, &[], &[], false, Some(i64::MAX));
    fixture.run("cass-state", &["selected"], &[], true, Some(i64::MAX));
}

#[test]
fn callback_cancellation_stops_after_the_first_conversation() {
    let fixture = Fixture::new();
    let ctx = ScanContext::with_roots(
        fixture.root.path().join("unused"),
        vec![ScanRoot::local(fixture.root.path().join(USER_ROOT))],
        None,
    );
    let mut count = 0;
    let result = CopilotConnector::new().scan_with_callback(&ctx, &mut |_| {
        count += 1;
        anyhow::bail!("stop this scan");
    });
    assert_eq!(count, 1);
    assert_eq!(result.unwrap_err().to_string(), "stop this scan");
}
