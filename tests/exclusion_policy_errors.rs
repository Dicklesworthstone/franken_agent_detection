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

#[cfg(feature = "chatgpt")]
use franken_agent_detection::connectors::chatgpt::ChatGptConnector;
#[cfg(feature = "codebuff")]
use franken_agent_detection::connectors::codebuff::CodebuffConnector;
#[cfg(feature = "goose")]
use franken_agent_detection::connectors::goose::GooseConnector;
#[cfg(feature = "grok-bot")]
use franken_agent_detection::connectors::grok_bot::GrokBotConnector;
use franken_agent_detection::connectors::{
    aider::AiderConnector, amp::AmpConnector, antigravity::AntigravityConnector,
    claude_code::ClaudeCodeConnector, clawdbot::ClawdbotConnector, codex::CodexConnector,
    continue_dev::ContinueConnector, copilot::CopilotConnector, copilot_cli::CopilotCliConnector,
    factory::FactoryConnector, gemini::GeminiConnector, get_connector_factories,
    grok::GrokConnector, kimi::KimiConnector, kiro::KiroConnector, muse::MuseConnector,
    omp::OmpConnector, openclaw::OpenClawConnector, openhands::OpenHandsConnector,
    pi_agent::PiAgentConnector, pi_durable::PiDurableConnector, pi_wire,
    prime_agent::PrimeAgentConnector, qwen::QwenConnector, vibe::VibeConnector,
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
const PROVIDERS: &[&str] = &[
    "claude",
    "codex",
    "pi_agent",
    "omp",
    "pi_durable",
    "continue",
    "kiro",
    "grok",
    "muse",
    "factory",
    "qwen",
    "prime_agent",
    "vibe",
    "kimi",
    "clawdbot",
    "antigravity",
    #[cfg(feature = "codebuff")]
    "codebuff",
    "openclaw",
    "openhands",
    "aider",
    "amp",
    #[cfg(feature = "chatgpt")]
    "chatgpt",
    "copilot",
    "copilot_cli",
    "gemini",
    #[cfg(feature = "goose")]
    "goose",
    #[cfg(feature = "grok-bot")]
    "grok_bot",
];

#[cfg(feature = "grok-bot")]
fn grok_bot_replica_filename() -> String {
    const KEY: &str = "sand.client.slice.account.auth0%7Cuser_00000000000000000000000000.transcript.replicas.81da155f-cc4c-58b3-aadf-770858d5e55c";
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let bits: Vec<bool> = KEY
        .bytes()
        .flat_map(|byte| (0..8).rev().map(move |bit| byte & (1 << bit) != 0))
        .collect();
    let encoded: String = bits
        .chunks(5)
        .map(|chunk| {
            let value = chunk
                .iter()
                .fold(0_usize, |v, bit| (v << 1) | usize::from(*bit))
                << (5 - chunk.len());
            char::from(ALPHABET[value])
        })
        .collect();
    format!("{encoded}.blob")
}

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

#[allow(clippy::too_many_lines)]
fn case(root: &Path, provider: &'static str) -> Case {
    let (connector, directory, filename): (Box<dyn Connector>, &str, String) = match provider {
        "claude" => (
            Box::new(ClaudeCodeConnector::new()),
            "claude",
            "session.jsonl".to_string(),
        ),
        "codex" => (
            Box::new(CodexConnector::new()),
            "codex",
            "rollout-policy.jsonl".to_string(),
        ),
        "pi_agent" => (
            Box::new(PiAgentConnector::new()),
            ".pi/agent",
            "sessions/2026-10-09T00-00-00_policy.jsonl".to_string(),
        ),
        "omp" => (
            Box::new(OmpConnector::new()),
            ".omp/agent",
            "sessions/2026-10-09T00-00-00_policy.jsonl".to_string(),
        ),
        "pi_durable" => (
            Box::new(PiDurableConnector::new()),
            "durable",
            "main.jsonl".to_string(),
        ),
        "continue" => (
            Box::new(ContinueConnector::new()),
            ".continue/sessions",
            "session-1.json".to_string(),
        ),
        "kiro" => (
            Box::new(KiroConnector::new()),
            ".kiro/sessions/cli",
            "session.jsonl".to_string(),
        ),
        "grok" => (
            Box::new(GrokConnector::new()),
            ".grok/sessions",
            "group-1/sess-1/updates.jsonl".to_string(),
        ),
        "muse" => (
            Box::new(MuseConnector::new()),
            ".local/share/muse/sessions",
            "019cccd3-9f97-7351-824f-6b1eb5f199f2/session.jsonl".to_string(),
        ),
        "factory" => (
            Box::new(FactoryConnector::new()),
            ".factory/sessions",
            "-work-demo/sess-1.jsonl".to_string(),
        ),
        "qwen" => (
            Box::new(QwenConnector::new()),
            ".qwen",
            "projects/demo/chats/11111111-2222-3333-4444-555555555555.jsonl".to_string(),
        ),
        "prime_agent" => (
            Box::new(PrimeAgentConnector::new()),
            ".prime/agent/sessions",
            "0192aa11-0000-7000-8000-000000000001.jsonl".to_string(),
        ),
        "vibe" => (
            Box::new(VibeConnector::new()),
            ".vibe/logs/session",
            "sess-1/messages.jsonl".to_string(),
        ),
        "kimi" => (
            Box::new(KimiConnector::new()),
            ".kimi-code/sessions",
            "workdir/sess-1/agents/main/wire.jsonl".to_string(),
        ),
        "clawdbot" => (
            Box::new(ClawdbotConnector::new()),
            ".clawdbot/sessions",
            "sess-1.jsonl".to_string(),
        ),
        "antigravity" => (
            Box::new(AntigravityConnector::new()),
            ".gemini/antigravity-cli",
            "brain/00000000-0000-0000-0000-000000000001/.system_generated/logs/transcript.jsonl"
                .to_string(),
        ),
        #[cfg(feature = "codebuff")]
        "codebuff" => (
            Box::new(CodebuffConnector::new()),
            ".config/manicode/projects",
            "demo/chats/2026-10-09T00-00-00.000Z/chat-messages.json".to_string(),
        ),
        "openclaw" => (
            Box::new(OpenClawConnector::new()),
            ".openclaw/agents/main/sessions",
            "sess-1.jsonl".to_string(),
        ),
        "openhands" => (
            Box::new(OpenHandsConnector::new()),
            ".openhands/conversations",
            "conv-1/events/event-00000-1.json".to_string(),
        ),
        "aider" => (
            Box::new(AiderConnector::new()),
            "aider-project",
            ".aider.chat.history.md".to_string(),
        ),
        "amp" => (
            Box::new(AmpConnector::new()),
            ".local/share/amp",
            "thread-1.json".to_string(),
        ),
        #[cfg(feature = "chatgpt")]
        "chatgpt" => (
            Box::new(ChatGptConnector::new()),
            "com.openai.chat",
            "conversations-v1/conv-1.json".to_string(),
        ),
        "copilot" => (
            Box::new(CopilotConnector::new()),
            "Code/User/workspaceStorage",
            "ws-1/chatSessions/sess-1.json".to_string(),
        ),
        "copilot_cli" => (
            Box::new(CopilotCliConnector::new()),
            ".copilot/session-state",
            "sess-1/events.jsonl".to_string(),
        ),
        "gemini" => (
            Box::new(GeminiConnector::new()),
            ".gemini/tmp",
            "project-1/chats/session-1.json".to_string(),
        ),
        #[cfg(feature = "goose")]
        "goose" => (
            Box::new(GooseConnector::new()),
            ".local/share/goose/sessions",
            "sess.jsonl".to_string(),
        ),
        #[cfg(feature = "grok-bot")]
        "grok_bot" => (
            Box::new(GrokBotConnector::new()),
            "Grok Bot/sand-client-persistence",
            grok_bot_replica_filename(),
        ),
        other => panic!("unknown provider: {other}"),
    };
    let visibilities = ["private", "public"];
    let roots: Vec<_> = visibilities
        .map(|visibility| root.join(visibility).join(directory))
        .into_iter()
        .collect();
    let sources = match provider {
        "goose" => visibilities
            .into_iter()
            .zip(&roots)
            .map(|(visibility, path)| path.join(format!("sess-{visibility}.jsonl")))
            .collect(),
        "copilot" => visibilities
            .into_iter()
            .zip(&roots)
            .map(|(visibility, path)| {
                path.join(format!("ws-1/chatSessions/sess-{visibility}.json"))
            })
            .collect(),
        _ => roots.iter().map(|path| path.join(&filename)).collect(),
    };
    Case {
        provider,
        connector,
        sources,
        ctx: context(root, roots),
    }
}

struct Fixture(TempDir);

impl Fixture {
    #[allow(clippy::too_many_lines)]
    fn new() -> Self {
        let fixture = Self(TempDir::new().unwrap());
        for &provider in PROVIDERS {
            for (visibility, path) in ["private", "public"]
                .into_iter()
                .zip(case(fixture.0.path(), provider).sources)
            {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                let text = format!("policy-{visibility}-{provider}");
                if provider == "aider" {
                    std::fs::write(path, format!("> {text}\n")).unwrap();
                    continue;
                }
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
                    "continue" => json!({
                        "sessionId": "session-1",
                        "title": "Policy",
                        "workspaceDirectory": "/work",
                        "history": [{"message": {"role": "user", "content": text}}]
                    }),
                    "kiro" => json!({"kind": "Prompt", "data": {"content": text}}),
                    "grok" => json!({
                        "timestamp": "2026-10-09T00:00:00Z",
                        "update": {
                            "sessionUpdate": "user_message_chunk",
                            "content": {"type": "text", "text": text}
                        }
                    }),
                    "muse" => json!({
                        "schema_version": "v1",
                        "stream_id": "019cccd3-9f97-7351-824f-6b1eb5f199f2",
                        "seq": 1,
                        "recorded_at_ms": 1_772_962_994_000_i64,
                        "payload_type": "runtime.session",
                        "payload": {"kind": "run", "event": {"kind": "started", "prompt": text}}
                    }),
                    "factory" | "openclaw" => json!({
                        "type": "message",
                        "id": "m1",
                        "timestamp": "2026-10-09T00:00:00Z",
                        "message": {"role": "user", "content": text}
                    }),
                    "openhands" => json!({
                        "kind": "MessageEvent",
                        "source": "user",
                        "timestamp": "2026-10-09T00:00:00Z",
                        "llm_message": {
                            "role": "user",
                            "content": [{"type": "text", "text": text}]
                        }
                    }),
                    "qwen" => json!({
                        "uuid": "u1",
                        "parentUuid": null,
                        "sessionId": "11111111-2222-3333-4444-555555555555",
                        "timestamp": "2026-10-09T00:00:00Z",
                        "cwd": "/work/demo",
                        "type": "user",
                        "message": {"role": "user", "parts": [{"text": text}]}
                    }),
                    "prime_agent" => json!({
                        "type": "message",
                        "id": "a1b2c3d4",
                        "parentId": null,
                        "timestamp": "2026-10-09T00:00:01Z",
                        "message": {"role": "user", "content": text}
                    }),
                    "vibe" | "clawdbot" => json!({
                        "role": "user",
                        "content": text,
                        "timestamp": "2026-10-09T00:00:00Z"
                    }),
                    "kimi" => json!({
                        "type": "turn.prompt",
                        "time": "2026-10-09T00:00:00Z",
                        "input": text
                    }),
                    "antigravity" => json!({
                        "step_index": 0,
                        "source": "USER_EXPLICIT",
                        "type": "USER_INPUT",
                        "status": "DONE",
                        "created_at": "2026-10-09T00:00:00Z",
                        "content": text
                    }),
                    "codebuff" => json!([{
                        "id": "user-1700000000000",
                        "variant": "user",
                        "content": text,
                        "timestamp": "2026-10-09T00:00:00.000Z"
                    }]),
                    "amp" => json!({
                        "id": "thread-1",
                        "title": "Policy",
                        "messages": [{
                            "role": "user",
                            "content": text,
                            "createdAt": 1_700_000_000_000_i64
                        }]
                    }),
                    "chatgpt" => json!({
                        "id": "conv-1",
                        "title": "Policy",
                        "create_time": 1_700_000_000.0,
                        "mapping": {
                            "node-1": {
                                "id": "node-1",
                                "message": {
                                    "id": "msg-1",
                                    "author": {"role": "user"},
                                    "create_time": 1_700_000_000.0,
                                    "content": {"content_type": "text", "parts": [text]}
                                }
                            }
                        }
                    }),
                    "copilot" => json!({
                        "sessionId": format!("sess-{visibility}"),
                        "responderUsername": "GitHub Copilot",
                        "requests": [{
                            "requestId": "req-1",
                            "timestamp": 1_700_000_000_000_i64,
                            "message": {"text": text},
                            "response": []
                        }]
                    }),
                    "copilot_cli" => json!({
                        "type": "user.message",
                        "id": "e1",
                        "timestamp": "2026-10-09T00:00:00Z",
                        "data": {"content": text}
                    }),
                    "gemini" => json!({
                        "sessionId": "sess-1",
                        "messages": [{
                            "id": "m1",
                            "type": "user",
                            "timestamp": "2026-10-09T00:00:00Z",
                            "content": text
                        }]
                    }),
                    "goose" => json!({
                        "role": "user",
                        "content": [{"type": "text", "text": text}],
                        "created_at": 1_700_000_000_i64
                    }),
                    "grok_bot" => json!({
                        "schemaVersion": 1,
                        "value": {
                            "entries": [{
                                "id": "e1",
                                "kind": "message",
                                "role": "user",
                                "content": text,
                                "timestampMs": 1_700_000_000_000_i64
                            }]
                        }
                    }),
                    _ => unreachable!(),
                };
                let mut content = String::new();
                if matches!(provider, "pi_agent" | "omp" | "prime_agent") {
                    writeln!(
                        content,
                        "{}",
                        json!({"type": "session",
                        "id": "0192aa11-0000-7000-8000-000000000001", "cwd": fixture.0.path(), "version": 3})
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
    if connector.supports_source_boundaries() {
        assert_paths(visited, expected);
        assert_paths(completed, expected);
    } else {
        assert!(visited.is_empty());
        assert!(completed.is_empty());
    }
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
    for &provider in PROVIDERS {
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
    if invalid {
        for (slug, factory) in get_connector_factories() {
            let connector = factory();
            assert!(
                connector.supports_streaming_scan(),
                "connector {slug} must support streaming scan"
            );
            let factory_case = Case {
                provider: slug,
                connector,
                ctx: context(&root, [root.join("private"), root.join("public")]),
                sources: Vec::new(),
            };
            assert_invalid_case(&factory_case);
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
