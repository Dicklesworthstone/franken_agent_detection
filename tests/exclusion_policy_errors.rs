//! Invalid exclusion input must stop every affected public entry point before
//! source callbacks. Child processes isolate environment and working-directory
//! changes from the parallel test suite. Deleted working directories are a
//! Unix-only regression; all fixtures remain at separate absolute paths.

#![cfg(feature = "connectors")]

use std::cell::Cell;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use franken_agent_detection::connectors::{
    claude_code::ClaudeCodeConnector, codex::CodexConnector, omp::OmpConnector,
    pi_agent::PiAgentConnector, pi_durable::PiDurableConnector, pi_wire,
};
use franken_agent_detection::{
    Connector, DiscoveredSourceFile, NormalizedConversation, ScanContext, ScanRoot,
    SourceCompletion, SourceScanHooks,
};
use serde_json::json;
use tempfile::TempDir;

const CHILD_ROOT: &str = "FAD_INVALID_POLICY_TEST_ROOT";
const CHILD_EXPECTED: &str = "FAD_INVALID_POLICY_TEST_EXPECTED";
const CHILD_DROP_CWD: &str = "FAD_INVALID_POLICY_TEST_DROP_CWD";
const PROVIDERS: [&str; 5] = ["claude", "codex", "pi_agent", "omp", "pi_durable"];

struct Case {
    provider: &'static str,
    connector: Box<dyn Connector>,
    ctx: ScanContext,
    sources: Vec<PathBuf>,
}

fn context(root: &Path, paths: impl IntoIterator<Item = PathBuf>) -> ScanContext {
    ScanContext::with_roots(
        root.join("cass-state"),
        paths.into_iter().map(ScanRoot::local).collect(),
        None,
    )
}

fn case(root: &Path, provider: &'static str) -> Case {
    let (connector, directory, filename): (Box<dyn Connector>, &str, &str) = match provider {
        "claude" => (
            Box::new(ClaudeCodeConnector::new()),
            "claude",
            "session.jsonl",
        ),
        "codex" => (
            Box::new(CodexConnector::new()),
            "codex",
            "rollout-policy.jsonl",
        ),
        "pi_agent" => (
            Box::new(PiAgentConnector::new()),
            ".pi/agent",
            "sessions/2026-10-09T00-00-00_policy.jsonl",
        ),
        "omp" => (
            Box::new(OmpConnector::new()),
            ".omp/agent",
            "sessions/2026-10-09T00-00-00_policy.jsonl",
        ),
        "pi_durable" => (Box::new(PiDurableConnector::new()), "durable", "main.jsonl"),
        other => panic!("unknown provider: {other}"),
    };
    let roots: Vec<_> = ["private", "public"]
        .map(|visibility| root.join(visibility).join(directory))
        .into_iter()
        .collect();
    Case {
        provider,
        connector,
        sources: roots.iter().map(|path| path.join(filename)).collect(),
        ctx: context(root, roots),
    }
}

struct Fixture(TempDir);

impl Fixture {
    fn new() -> Self {
        let fixture = Self(TempDir::new().unwrap());
        for provider in PROVIDERS {
            for (visibility, path) in ["private", "public"]
                .into_iter()
                .zip(case(fixture.0.path(), provider).sources)
            {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                let text = format!("policy-{visibility}-{provider}");
                let record = match provider {
                    "claude" => json!({"type": "user", "sessionId": text,
                        "message": {"role": "user", "content": text}}),
                    "codex" => json!({"type": "response_item", "payload": {
                        "type": "message", "role": "user", "content": text}}),
                    "pi_agent" | "omp" => json!({"type": "message", "id": "message-1",
                        "message": {"role": "user", "content": text}}),
                    "pi_durable" => json!({"format": 1, "type": "commit", "seq": 1,
                    "writes": [
                        {"type": "conversation", "value": {"id": 1}},
                        {"type": "entry", "value": {"id": 2, "conversationId": 1,
                            "kind": "pi.user", "model": [{"role": "user", "content": text}]}}
                    ]}),
                    _ => unreachable!(),
                };
                let mut content = String::new();
                if matches!(provider, "pi_agent" | "omp") {
                    writeln!(
                        content,
                        "{}",
                        json!({"type": "session",
                        "id": text, "cwd": fixture.0.path(), "version": 3})
                    )
                    .unwrap();
                }
                writeln!(content, "{record}").unwrap();
                std::fs::write(path, content).unwrap();
            }
        }
        // A compatibility diagnostics call must produce a visible result with
        // a valid policy, and no result when invalid policy prevents opening it.
        let diagnostic = fixture.0.path().join("durable-diagnostic/main.jsonl");
        std::fs::create_dir_all(diagnostic.parent().unwrap()).unwrap();
        std::fs::write(
            diagnostic,
            "{\"format\":999,\"type\":\"commit\",\"seq\":1,\"writes\":[]}\n",
        )
        .unwrap();
        fixture
    }

    fn run(&self, policy: Option<&OsStr>, expected: &str, drop_cwd: bool) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "exclusion_policy_child", "--nocapture"])
            .current_dir(self.0.path())
            .env(CHILD_ROOT, self.0.path())
            .env(CHILD_EXPECTED, expected)
            .env(CHILD_DROP_CWD, if drop_cwd { "1" } else { "0" })
            .env_remove("CASS_EXCLUDE_PATHS");
        if let Some(policy) = policy {
            command.env("CASS_EXCLUDE_PATHS", policy);
        }
        let output = command
            .output()
            .expect("run isolated exclusion-policy regression");
        assert!(
            output.status.success(),
            "expected={expected} drop_cwd={drop_cwd}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn assert_policy_error<T>(result: anyhow::Result<T>, provider: &str, operation: &str) {
    match result {
        Err(error) => assert!(
            format!("{error:#}").contains("CASS_EXCLUDE_PATHS"),
            "{provider} {operation}: wrong error: {error:#}"
        ),
        Ok(_) => panic!("{provider} {operation}: invalid policy was accepted"),
    }
}

fn assert_paths(mut actual: Vec<PathBuf>, expected: &[PathBuf]) {
    let mut expected = expected.to_vec();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
}

fn assert_conversations(conversations: &[NormalizedConversation], expected: &[PathBuf]) {
    assert_paths(
        conversations
            .iter()
            .map(|conversation| conversation.source_path.clone())
            .collect(),
        expected,
    );
    for conversation in conversations {
        assert_eq!(conversation.messages.len(), 1);
        assert!(conversation.messages[0].content.starts_with("policy-"));
    }
}

fn assert_invalid_case(case: &Case) {
    let connector = case.connector.as_ref();
    assert_policy_error(
        connector.discover_source_files(&case.ctx),
        case.provider,
        "discovery",
    );
    assert_policy_error(connector.scan(&case.ctx), case.provider, "collecting scan");
    let emitted = Cell::new(0);
    let mut on_conversation = |_: NormalizedConversation| {
        emitted.set(emitted.get() + 1);
        Ok(())
    };
    assert_policy_error(
        connector.scan_with_callback(&case.ctx, &mut on_conversation),
        case.provider,
        "callback scan",
    );
    let visited = Cell::new(0);
    let completed = Cell::new(0);
    let mut should_scan = |_: &DiscoveredSourceFile| {
        visited.set(visited.get() + 1);
        true
    };
    let mut on_complete = |_: &SourceCompletion| {
        completed.set(completed.get() + 1);
        Ok(())
    };
    let mut hooks = SourceScanHooks {
        should_scan_source: Some(&mut should_scan),
        on_source_complete: Some(&mut on_complete),
    };
    assert_policy_error(
        connector.scan_with_source_boundaries(&case.ctx, &mut hooks, &mut on_conversation),
        case.provider,
        "source-boundary scan",
    );
    assert_eq!(
        (visited.get(), emitted.get(), completed.get()),
        (0, 0, 0),
        "{} emitted callbacks under invalid policy",
        case.provider
    );
}

fn assert_valid_case(case: &Case, public_only: bool) {
    let expected = if public_only {
        &case.sources[1..]
    } else {
        &case.sources[..]
    };
    let connector = case.connector.as_ref();
    assert_paths(
        connector
            .discover_source_files(&case.ctx)
            .unwrap()
            .into_iter()
            .map(|source| source.source_path)
            .collect(),
        expected,
    );
    assert_conversations(&connector.scan(&case.ctx).unwrap(), expected);
    let mut conversations = Vec::new();
    connector
        .scan_with_callback(&case.ctx, &mut |conversation| {
            conversations.push(conversation);
            Ok(())
        })
        .unwrap();
    assert_conversations(&conversations, expected);
    conversations.clear();
    let mut visited = Vec::new();
    let mut completed = Vec::new();
    {
        let mut should_scan = |source: &DiscoveredSourceFile| {
            visited.push(source.source_path.clone());
            true
        };
        let mut on_complete = |completion: &SourceCompletion| {
            assert_eq!(completion.conversations_emitted, 1);
            completed.push(completion.source.source_path.clone());
            Ok(())
        };
        let mut hooks = SourceScanHooks {
            should_scan_source: Some(&mut should_scan),
            on_source_complete: Some(&mut on_complete),
        };
        connector
            .scan_with_source_boundaries(&case.ctx, &mut hooks, &mut |conversation| {
                conversations.push(conversation);
                Ok(())
            })
            .unwrap();
    }
    assert_paths(visited, expected);
    assert_paths(completed, expected);
    assert_conversations(&conversations, expected);
}

#[test]
fn exclusion_policy_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let expected = std::env::var(CHILD_EXPECTED).unwrap();
    let drop_cwd = std::env::var(CHILD_DROP_CWD).unwrap() == "1";
    if drop_cwd {
        #[cfg(unix)]
        {
            let removed = root.join("removed-child-cwd");
            std::fs::create_dir(&removed).unwrap();
            std::env::set_current_dir(&removed).unwrap();
            std::fs::remove_dir(&removed).unwrap();
            assert!(std::env::current_dir().is_err());
        }
        #[cfg(not(unix))]
        panic!("deleted working-directory fixture is only supported on Unix");
    }
    let invalid = expected == "error";
    for provider in PROVIDERS {
        let case = case(&root, provider);
        let before: Vec<_> = case
            .sources
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect();
        if invalid {
            assert_invalid_case(&case);
        } else {
            assert_valid_case(&case, expected == "public");
        }
        if matches!(provider, "pi_agent" | "omp") {
            let checked = pi_wire::try_discover_sources(&case.ctx.scan_roots, &case.ctx, provider);
            let compatible = pi_wire::discover_sources(&case.ctx.scan_roots, &case.ctx, provider);
            if invalid {
                assert_policy_error(checked, provider, "shared checked discovery");
                assert!(compatible.is_empty());
                let homes: Vec<_> = case
                    .ctx
                    .scan_roots
                    .iter()
                    .map(|root| root.path.clone())
                    .collect();
                assert_policy_error(
                    pi_wire::scan_homes(&homes, &case.ctx, provider),
                    provider,
                    "shared scan",
                );
            } else {
                let expected = if expected == "public" {
                    &case.sources[1..]
                } else {
                    &case.sources[..]
                };
                assert_paths(
                    checked
                        .unwrap()
                        .into_iter()
                        .map(|source| source.source_path)
                        .collect(),
                    expected,
                );
                assert_paths(
                    compatible
                        .into_iter()
                        .map(|source| source.source_path)
                        .collect(),
                    expected,
                );
            }
        }
        for (path, bytes) in case.sources.iter().zip(before) {
            assert_eq!(
                std::fs::read(path).unwrap(),
                bytes,
                "source changed: {}",
                path.display()
            );
        }
    }
    let diagnostic_ctx = context(&root, [root.join("durable-diagnostic/main.jsonl")]);
    let diagnostics = PiDurableConnector::new().store_diagnostics(&diagnostic_ctx);
    assert_eq!(diagnostics.len(), usize::from(!invalid));
}

#[test]
fn unset_and_empty_exclusion_policies_preserve_all_real_sources() {
    let fixture = Fixture::new();
    fixture.run(None, "all", false);
    for policy in ["", " , \n , "] {
        fixture.run(Some(OsStr::new(policy)), "all", false);
    }
    fixture.run(
        Some(fixture.0.path().join("private").as_os_str()),
        "public",
        false,
    );
}

#[test]
#[cfg(any(unix, windows))]
fn mixed_unicode_and_non_unicode_exclusions_fail_before_every_source_callback() {
    let fixture = Fixture::new();
    let mut policy = fixture.0.path().join("private").into_os_string();
    policy.push(",");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        policy.push(std::ffi::OsString::from_vec(vec![b'/', b'p', 0xff]));
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        policy.push(std::ffi::OsString::from_wide(&[0xd800]));
    }
    fixture.run(Some(&policy), "error", false);
}

#[test]
#[cfg(unix)]
fn unresolvable_exclusion_entry_rejects_the_entire_policy() {
    let fixture = Fixture::new();
    let not_a_directory = fixture.0.path().join("not-a-directory");
    std::fs::write(&not_a_directory, "regular file").unwrap();
    let policy = format!(
        "{},{}",
        fixture.0.path().join("private").display(),
        not_a_directory.join("child").display()
    );
    fixture.run(Some(OsStr::new(&policy)), "error", false);
}

#[test]
#[cfg(unix)]
fn exclusion_policy_with_unavailable_cwd_accepts_absolute_and_rejects_relative_paths() {
    let fixture = Fixture::new();
    fixture.run(
        Some(fixture.0.path().join("private").as_os_str()),
        "public",
        true,
    );
    fixture.run(Some(OsStr::new("private")), "error", true);
    fixture.run(None, "all", true);
    fixture.run(Some(OsStr::new(" , \n , ")), "all", true);
}
