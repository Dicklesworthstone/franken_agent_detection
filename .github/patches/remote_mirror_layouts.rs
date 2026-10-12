#![cfg(feature = "connectors")]

use std::fs;
use std::path::{Path, PathBuf};

use franken_agent_detection::connectors::{
    Connector, ScanContext, ScanRoot, factory::FactoryConnector,
    gemini::GeminiConnector, prime_agent::PrimeAgentConnector, vibe::VibeConnector,
};
use franken_agent_detection::types::{Origin, SourceKind};
use tempfile::TempDir;

const FACTORY: &str = concat!(
    "{\"type\":\"session_start\",\"id\":\"factory-mirror\",\"cwd\":\"/remote/project\"}\n",
    "{\"type\":\"message\",\"timestamp\":\"2026-01-01T00:00:01Z\",\"message\":{\"role\":\"user\",\"content\":\"mirror user\"}}\n",
    "{\"type\":\"message\",\"timestamp\":\"2026-01-01T00:00:02Z\",\"message\":{\"role\":\"assistant\",\"content\":\"mirror assistant\"}}\n",
);
const GEMINI: &str = r#"{"sessionId":"gemini-mirror","messages":[{"id":"u","type":"user","timestamp":"2026-01-01T00:00:01Z","content":"mirror user"},{"id":"a","type":"gemini","timestamp":"2026-01-01T00:00:02Z","content":"mirror assistant"}]}"#;
const VIBE: &str = concat!(
    "{\"role\":\"user\",\"content\":\"mirror user\",\"timestamp\":\"2026-01-01T00:00:01Z\"}\n",
    "{\"role\":\"assistant\",\"content\":\"mirror assistant\",\"timestamp\":\"2026-01-01T00:00:02Z\"}\n",
);
const PRIME: &str = concat!(
    "{\"type\":\"session\",\"version\":3,\"id\":\"prime-mirror\",\"cwd\":\"/remote/project\",\"timestamp\":\"2026-01-01T00:00:00Z\"}\n",
    "{\"type\":\"message\",\"id\":\"u\",\"parentId\":null,\"message\":{\"role\":\"user\",\"content\":\"mirror user\",\"timestamp\":\"2026-01-01T00:00:01Z\"}}\n",
    "{\"type\":\"message\",\"id\":\"a\",\"parentId\":\"u\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"mirror assistant\"}],\"timestamp\":\"2026-01-01T00:00:02Z\"}}\n",
);

// Same byte-level FNV and native-component cleaning as CASS path_to_safe_dirname.
// The downstream CASS test exercises that real function rather than this copy.
fn safe_name(path: &str) -> String {
    use std::path::Component;
    let cleaned = Path::new(path).components().filter_map(|c| match c {
        Component::Normal(name) => name.to_str().filter(|s| !s.is_empty() && *s != "~"),
        _ => None,
    }).collect::<Vec<_>>().join("_").replace([' ', '\\'], "_");
    let hash = path.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    format!("{cleaned}_{hash:08x}")
}

fn remote(path: PathBuf) -> ScanRoot {
    ScanRoot::remote(path, Origin {
        source_id: "mirror-host".to_owned(),
        kind: SourceKind::Ssh,
        host: Some("user@example.test".to_owned()),
    }, None).with_rewrite("/remote", "/local")
}

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn assert_scan(connector: &dyn Connector, temp: &Path, roots: Vec<ScanRoot>, file: &Path) {
    let ctx = ScanContext::with_roots(temp.join("cass-state"), roots, None);
    let conversations = connector.scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1, "file={} ctx={ctx:?}", file.display());
    assert_eq!(conversations[0].messages.len(), 2);
    assert_eq!(conversations[0].messages[0].content, "mirror user");
    assert_eq!(conversations[0].messages[1].content, "mirror assistant");
    let sources = connector.discover_source_files(&ctx).unwrap();
    let primary: Vec<_> = sources.iter().filter(|s| s.source_path == file).collect();
    assert_eq!(primary.len(), 1, "discovery must agree with scan and deduplicate");
    assert_eq!(primary[0].origin, remote(PathBuf::new()).origin);
    assert!(file.starts_with(&primary[0].scan_root));
}

fn check_layout(connector: &dyn Connector, configured: &str, payload_file: &str, bytes: &[u8]) {
    let tmp = TempDir::new().unwrap();
    let mirror = tmp.path().join("remotes/host/mirror");
    let wrapper = mirror.join(safe_name(configured));
    let file = wrapper.join(payload_file);
    write(&file, bytes);
    assert_scan(connector, tmp.path(), vec![remote(wrapper.clone())], &file);
    assert_scan(connector, tmp.path(), vec![remote(mirror.clone())], &file);
    let payload = wrapper.join(payload_file.split('/').next().unwrap());
    assert_scan(connector, tmp.path(), vec![remote(payload)], &file);
    assert_scan(connector, tmp.path(), vec![remote(mirror), remote(wrapper.clone())], &file);
    let ctx = ScanContext::with_roots(tmp.path().join("cass-state"), vec![ScanRoot::local(wrapper)], None);
    assert!(connector.scan(&ctx).unwrap().is_empty(), "do not broaden local wrapper detection");
}

#[test]
fn factory_mirrored_nested_workspaces() {
    for configured in ["~/.factory/sessions", "/home/a/.factory/sessions", "/home/a b/.factory/sessions"] {
        check_layout(&FactoryConnector::new(), configured, "sessions/-remote-project/s.jsonl", FACTORY.as_bytes());
    }
    check_layout(&FactoryConnector::new(), "~/.factory", ".factory/sessions/-remote-project/s.jsonl", FACTORY.as_bytes());
}

#[test]
fn gemini_mirrored_project_chats() {
    check_layout(&GeminiConnector::new(), "~/.gemini/tmp", "tmp/project-hash/chats/session-test.json", GEMINI.as_bytes());
    check_layout(&GeminiConnector::new(), "~/.gemini", ".gemini/tmp/project-hash/chats/session-test.json", GEMINI.as_bytes());
}

#[test]
fn vibe_mirrored_sessions_and_parent_containers() {
    for (remote_path, file) in [
        ("~/.vibe/logs/session", "session/run/messages.jsonl"),
        ("~/.vibe/logs", "logs/session/run/messages.jsonl"),
        ("~/.vibe", ".vibe/logs/session/run/messages.jsonl"),
    ] {
        check_layout(&VibeConnector::new(), remote_path, file, VIBE.as_bytes());
    }
}

#[test]
fn prime_mirrored_sessions_and_parent_containers() {
    for (remote_path, file) in [
        ("~/.prime/agent/sessions", "sessions/s.jsonl"),
        ("~/.prime/agent", "agent/sessions/s.jsonl"),
        ("~/.prime", ".prime/agent/sessions/s.jsonl"),
    ] {
        check_layout(&PrimeAgentConnector::new(), remote_path, file, PRIME.as_bytes());
    }
}

#[test]
fn mixed_mirror_preserves_provider_ownership() {
    let tmp = TempDir::new().unwrap();
    let mirror = tmp.path().join("mirror");
    let cases: Vec<(Box<dyn Connector>, &str, &str, &str)> = vec![
        (Box::new(FactoryConnector::new()), "~/.factory/sessions", "sessions/-remote-project/s.jsonl", FACTORY),
        (Box::new(GeminiConnector::new()), "~/.gemini/tmp", "tmp/hash/chats/session-test.json", GEMINI),
        (Box::new(VibeConnector::new()), "~/.vibe/logs/session", "session/run/messages.jsonl", VIBE),
        (Box::new(PrimeAgentConnector::new()), "~/.prime/agent/sessions", "sessions/s.jsonl", PRIME),
    ];
    for (_, configured, tail, content) in &cases {
        write(&mirror.join(safe_name(configured)).join(tail), content.as_bytes());
    }
    for (connector, configured, tail, _) in cases {
        assert_scan(connector.as_ref(), tmp.path(), vec![remote(mirror.clone())], &mirror.join(safe_name(configured)).join(tail));
    }
}

#[test]
fn prime_narrow_file_does_not_scan_siblings() {
    let tmp = TempDir::new().unwrap();
    let sessions = tmp.path().join(safe_name("~/.prime/agent/sessions")).join("sessions");
    let selected = sessions.join("selected.jsonl");
    write(&selected, PRIME.as_bytes());
    write(&sessions.join("sibling.jsonl"), PRIME.as_bytes());
    assert_scan(&PrimeAgentConnector::new(), tmp.path(), vec![remote(selected.clone())], &selected);
}

#[test]
fn reject_lookalike_wrappers_and_wrong_payloads() {
    for wrapper in [".vibe_logs_session_backup_12345678", ".vibe-backup_logs_session_12345678", ".vibe_logs_session_notahash", ".vibe_logs_session_1234567", ".vibe_logs_session_1234567890abcdef0"] {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join(wrapper);
        write(&root.join("session/run/messages.jsonl"), VIBE.as_bytes());
        let ctx = ScanContext::with_roots(tmp.path().join("data"), vec![remote(root)], None);
        assert!(VibeConnector::new().scan(&ctx).unwrap().is_empty());
    }
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join(safe_name("~/.vibe/logs/session"));
    write(&root.join("unrelated/run/messages.jsonl"), VIBE.as_bytes());
    let ctx = ScanContext::with_roots(tmp.path().join("data"), vec![remote(root)], None);
    assert!(VibeConnector::new().scan(&ctx).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn reject_payload_symlinks_and_parent_traversal() {
    use std::os::unix::fs::symlink;
    let tmp = TempDir::new().unwrap();
    let outside = tmp.path().join("outside");
    write(&outside.join("run/messages.jsonl"), VIBE.as_bytes());
    let wrapper = tmp.path().join(safe_name("~/.vibe/logs/session"));
    fs::create_dir_all(&wrapper).unwrap();
    symlink(&outside, wrapper.join("session")).unwrap();
    for selected in [wrapper.clone(), wrapper.join("session"), wrapper.join("../outside")] {
        let ctx = ScanContext::with_roots(tmp.path().join("data"), vec![remote(selected)], None);
        assert!(VibeConnector::new().scan(&ctx).unwrap().is_empty());
    }
    let linked = tmp.path().join("linked").join(safe_name("~/.vibe/logs/session"));
    fs::create_dir_all(linked.parent().unwrap()).unwrap();
    symlink(&wrapper, &linked).unwrap();
    let ctx = ScanContext::with_roots(tmp.path().join("data"), vec![remote(linked)], None);
    assert!(VibeConnector::new().scan(&ctx).unwrap().is_empty());
}

#[cfg(feature = "cursor")]
#[test]
fn cursor_mirrored_user_and_storage_directories() {
    use franken_agent_detection::connectors::cursor::CursorConnector;
    let bytes = include_bytes!("fixtures/remote-mirror-cursor.vscdb");
    for configured in ["~/.config/Cursor/User", "~/Library/Application Support/Cursor/User", "C:\\Users\\Alice\\AppData\\Roaming\\Cursor\\User"] {
        check_layout(&CursorConnector::new(), configured, "User/globalStorage/state.vscdb", bytes);
        check_layout(&CursorConnector::new(), configured, "User/workspaceStorage/hash/state.vscdb", bytes);
    }
    check_layout(&CursorConnector::new(), "~/.config/Cursor/User/globalStorage", "globalStorage/state.vscdb", bytes);
    check_layout(&CursorConnector::new(), "~/.config/Cursor/User/workspaceStorage", "workspaceStorage/hash/state.vscdb", bytes);
}
