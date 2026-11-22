//! The Codebuff / Freebuff CLI relocates its shared store with the native
//! `FREEBUFF_CONFIG_DIR` setting. Default scans must read that store and must
//! not fall back to the home-directory default while the setting applies.
//! A child process isolates HOME and the environment from parallel tests.

#![cfg(all(feature = "codebuff", unix))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use franken_agent_detection::{CodebuffConnector, Connector, ScanContext};
use serde_json::json;
use tempfile::TempDir;

const CHILD_ROOT: &str = "FAD_CODEBUFF_CONFIG_TEST_ROOT";
const CHILD_EXPECTED: &str = "FAD_CODEBUFF_CONFIG_TEST_EXPECTED";

fn write_chat(config_dir: &Path, text: &str) {
    let chat = config_dir.join("projects/demo/chats/2026-09-01T12-00-00.000Z");
    fs::create_dir_all(&chat).unwrap();
    let records = json!([{
        "id": "user-1",
        "variant": "user",
        "content": text,
        "timestamp": "2026-09-01T12:00:00.000Z"
    }]);
    fs::write(
        chat.join("chat-messages.json"),
        serde_json::to_vec(&records).unwrap(),
    )
    .unwrap();
}

fn run(root: &Path, setting: Option<PathBuf>, expected: &[&str]) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "codebuff_config_child", "--nocapture"])
        .current_dir(root)
        .env(CHILD_ROOT, root)
        .env(CHILD_EXPECTED, expected.join(","))
        .env("HOME", root.join("home"))
        .env_remove("CASS_CODEBUFF_DATA_ROOT")
        .env_remove("FREEBUFF_CONFIG_DIR")
        .env_remove("CASS_EXCLUDE_PATHS");
    if let Some(setting) = setting {
        command.env("FREEBUFF_CONFIG_DIR", setting);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "expected={expected:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn codebuff_config_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let expected: Vec<String> = std::env::var(CHILD_EXPECTED)
        .unwrap()
        .split(',')
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .collect();
    let connector = CodebuffConnector::new();
    let detected = connector.detect();
    assert_eq!(detected.detected, !expected.is_empty(), "{detected:?}");
    let ctx = ScanContext::local_default(PathBuf::from(root).join("cass-state"), None);
    let mut actual: Vec<String> = connector
        .scan(&ctx)
        .unwrap()
        .into_iter()
        .map(|conversation| conversation.messages[0].content.clone())
        .collect();
    actual.sort();
    assert_eq!(actual, expected);
}

#[test]
fn native_config_dir_selects_the_relocated_store() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    write_chat(&root.join("home/.config/manicode"), "default");
    write_chat(&root.join("relocated"), "relocated");

    run(root, None, &["default"]);
    run(root, Some(root.join("relocated")), &["relocated"]);
    // A configured but missing directory replaces the default store.
    run(root, Some(root.join("absent")), &[]);
    // The CLI refuses relative values, so the default store still applies.
    run(root, Some(PathBuf::from("relocated")), &["default"]);
}
