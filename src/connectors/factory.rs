//! Factory Droid connector for JSONL session files.
//!
//! Factory (https://factory.ai) is an AI coding assistant that stores sessions
//! at `~/.factory/sessions/` using a JSONL format similar to Claude Code.
//!
//! Directory structure:
//!   - ~/.factory/sessions/{workspace-path-slug}/{session-uuid}.jsonl
//!   - ~/.factory/sessions/{workspace-path-slug}/{session-uuid}.settings.json
//!
//! The workspace path slug encodes the original working directory path,
//! e.g., `-Users-alice-Dev-myproject` for `/Users/alice/Dev/myproject`.

use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::ScanContext;
use super::{
    Connector, file_modified_since, flatten_content, franken_detection_for_connector,
    parse_timestamp,
};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct FactoryConnector;

impl Default for FactoryConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl FactoryConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Get the Factory sessions directory.
    /// Factory stores sessions in ~/.factory/sessions/
    fn sessions_root() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".factory/sessions"))
    }

    /// Decode a workspace path slug back to a path.
    /// e.g., `-Users-alice-Dev-myproject` -> `/Users/alice/Dev/myproject`
    fn decode_workspace_slug(slug: &str) -> Option<PathBuf> {
        if slug.starts_with('-') {
            // Replace leading dash and internal dashes with path separators
            let path_str = slug.replacen('-', "/", 1).replace('-', "/");
            Some(PathBuf::from(path_str))
        } else {
            None
        }
    }
}

impl Connector for FactoryConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("factory").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        // Determine scan root
        let root = if ctx.use_default_detection() {
            // First check if data_dir looks like factory storage (for testing)
            if looks_like_factory_storage(&ctx.data_dir) && ctx.data_dir.exists() {
                ctx.data_dir.clone()
            } else {
                // Fall back to default sessions root
                match Self::sessions_root() {
                    Some(r) if r.exists() => r,
                    _ => return Ok(Vec::new()),
                }
            }
        } else {
            // Check scan_roots for factory sessions
            let factory_root = ctx.scan_roots.iter().find_map(|sr| {
                let factory_path = sr.path.join(".factory/sessions");
                if factory_path.exists() {
                    Some(factory_path)
                } else if looks_like_factory_storage(&sr.path) {
                    Some(sr.path.clone())
                } else {
                    None
                }
            });
            match factory_root {
                Some(r) => r,
                None => return Ok(Vec::new()),
            }
        };

        if !root.exists() {
            return Ok(Vec::new());
        }

        let mut convs = Vec::new();

        for entry in WalkDir::new(&root).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }

            // Only process .jsonl files (skip .settings.json)
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
                continue;
            }

            // Skip files not modified since last scan (incremental indexing)
            if !file_modified_since(path, ctx.since_ts) {
                continue;
            }

            match parse_factory_session(path) {
                Ok(Some(conv)) => convs.push(conv),
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!(path = %path.display(), error = %e, "factory parse error");
                }
            }
        }

        Ok(convs)
    }
}

/// Check if a directory looks like Factory storage
fn looks_like_factory_storage(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("factory") && path_str.contains("sessions")
}

fn update_time_bounds(started_at: &mut Option<i64>, ended_at: &mut Option<i64>, ts: Option<i64>) {
    if let Some(ts) = ts {
        *started_at = Some(started_at.map_or(ts, |curr| curr.min(ts)));
        *ended_at = Some(ended_at.map_or(ts, |curr| curr.max(ts)));
    }
}

/// Parse a Factory session JSONL file into a NormalizedConversation.
fn parse_factory_session(path: &Path) -> Result<Option<NormalizedConversation>> {
    let file =
        fs::File::open(path).with_context(|| format!("open session file {}", path.display()))?;
    let reader = std::io::BufReader::new(file);

    let mut messages = Vec::new();
    let mut session_id: Option<String> = None;
    let mut title: Option<String> = None;
    let mut workspace: Option<PathBuf> = None;
    let mut owner: Option<String> = None;
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;

    // Try to infer workspace from parent directory name if not in session_start
    let parent_dir_name = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str());

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        if line.trim().is_empty() {
            continue;
        }

        let val: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let entry_type = val.get("type").and_then(|v| v.as_str());

        match entry_type {
            Some("session_start") => {
                // Extract session metadata
                session_id = val.get("id").and_then(|v| v.as_str()).map(String::from);
                title = val.get("title").and_then(|v| v.as_str()).map(String::from);
                owner = val.get("owner").and_then(|v| v.as_str()).map(String::from);
                workspace = val
                    .get("cwd")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .or_else(|| {
                        // Fallback: decode workspace from parent directory name
                        parent_dir_name.and_then(FactoryConnector::decode_workspace_slug)
                    });
            }
            Some("message") => {
                // Parse timestamp
                let created = val.get("timestamp").and_then(parse_timestamp);

                // Track session bounds robustly even if events are out of order.
                update_time_bounds(&mut started_at, &mut ended_at, created);

                // Extract role from message.role
                let role = val
                    .get("message")
                    .and_then(|m| m.get("role"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                // Extract content from message.content
                let content_val = val.get("message").and_then(|m| m.get("content"));
                let content_str = content_val.map(flatten_content).unwrap_or_default();

                // Skip entries with empty content
                if content_str.trim().is_empty() {
                    continue;
                }

                // Extract model for author field (from message if present)
                let author = val
                    .get("message")
                    .and_then(|m| m.get("model"))
                    .and_then(|v| v.as_str())
                    .map(String::from);

                messages.push(NormalizedMessage {
                    idx: 0, // Will be reassigned after collection
                    role: role.to_string(),
                    author,
                    created_at: created,
                    content: content_str,
                    extra: val,
                    snippets: Vec::new(),
                });
            }
            // Skip other types: todo_state, tool_result, etc.
            _ => {}
        }
    }

    // Reassign sequential indices
    crate::types::reindex_messages(&mut messages);

    if messages.is_empty() {
        return Ok(None);
    }

    // Infer workspace from parent directory name if not set by session_start
    if workspace.is_none() {
        workspace = parent_dir_name.and_then(FactoryConnector::decode_workspace_slug);
    }

    // Generate title from first user message if not in session_start
    let final_title = title.or_else(|| {
        messages
            .iter()
            .find(|m| m.role == "user")
            .map(|m| {
                m.content
                    .lines()
                    .next()
                    .unwrap_or(&m.content)
                    .chars()
                    .take(100)
                    .collect::<String>()
            })
            .or_else(|| {
                // Fallback to workspace directory name
                workspace
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .map(String::from)
            })
    });

    // Load settings file if it exists for additional metadata
    let settings_path = path.with_extension("settings.json");
    let model_info = if settings_path.exists() {
        fs::read_to_string(&settings_path)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v.get("model").and_then(|m| m.as_str()).map(String::from))
    } else {
        None
    };

    Ok(Some(NormalizedConversation {
        agent_slug: "factory".into(),
        external_id: session_id
            .clone()
            .or_else(|| path.file_stem().and_then(|s| s.to_str()).map(String::from)),
        title: final_title,
        workspace,
        source_path: path.to_path_buf(),
        started_at,
        ended_at,
        metadata: serde_json::json!({
            "source": "factory",
            "sessionId": session_id,
            "owner": owner,
            "model": model_info,
        }),
        messages,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // =========================================================================
    // Constructor tests
    // =========================================================================

    #[test]
    fn new_creates_connector() {
        let connector = FactoryConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = FactoryConnector;
        let _ = connector;
    }

    #[test]
    fn sessions_root_returns_factory_sessions_path() {
        if let Some(root) = FactoryConnector::sessions_root() {
            assert!(root.ends_with(".factory/sessions"));
        }
    }

    // =========================================================================
    // Workspace slug decoding tests
    // =========================================================================

    #[test]
    fn decode_workspace_slug_basic() {
        let result = FactoryConnector::decode_workspace_slug("-Users-alice-Dev-myproject");
        assert_eq!(result, Some(PathBuf::from("/Users/alice/Dev/myproject")));
    }

    #[test]
    fn decode_workspace_slug_deep_path() {
        let result = FactoryConnector::decode_workspace_slug("-Users-bob-Dev-sites-example.com");
        assert_eq!(
            result,
            Some(PathBuf::from("/Users/bob/Dev/sites/example.com"))
        );
    }

    #[test]
    fn decode_workspace_slug_no_leading_dash() {
        let result = FactoryConnector::decode_workspace_slug("invalid-path");
        assert_eq!(result, None);
    }

    #[test]
    fn decode_workspace_slug_empty() {
        let result = FactoryConnector::decode_workspace_slug("");
        assert_eq!(result, None);
    }

    // =========================================================================
    // Detection tests
    // =========================================================================

    #[test]
    fn detect_not_found_without_sessions_dir() {
        let connector = FactoryConnector::new();
        let result = connector.detect();
        // Just verify detect() doesn't panic
        let _ = result.detected;
    }

    // =========================================================================
    // JSONL parsing tests
    // =========================================================================

    fn create_factory_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join(".factory").join("sessions");
        fs::create_dir_all(&storage).unwrap();
        storage
    }

    fn write_session_file(storage: &Path, workspace_slug: &str, session_id: &str, lines: &[&str]) {
        let session_dir = storage.join(workspace_slug);
        fs::create_dir_all(&session_dir).unwrap();
        let file_path = session_dir.join(format!("{session_id}.jsonl"));
        fs::write(&file_path, lines.join("\n")).unwrap();
    }

    #[test]
    fn scan_parses_session_start_and_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);

        let lines = vec![
            r#"{"type":"session_start","id":"sess-001","title":"Test Session","owner":"testuser","cwd":"/home/user/project"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello Factory"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:05Z","message":{"role":"assistant","content":"Hello! How can I help?"}}"#,
        ];
        write_session_file(&storage, "-home-user-project", "sess-001", &lines);

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].title, Some("Test Session".to_string()));
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/project"))
        );
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Factory");
        assert_eq!(convs[0].messages[1].role, "assistant");
    }

    #[test]
    fn scan_extracts_session_metadata() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);

        let lines = vec![
            r#"{"type":"session_start","id":"sess-meta","title":"Metadata Test","owner":"alice","cwd":"/projects/app"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
        ];
        write_session_file(&storage, "-projects-app", "sess-meta", &lines);

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["sessionId"], "sess-meta");
        assert_eq!(convs[0].metadata["owner"], "alice");
        assert_eq!(convs[0].external_id, Some("sess-meta".to_string()));
    }

    #[test]
    fn scan_handles_array_content() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);

        let lines = vec![
            r#"{"type":"session_start","id":"sess-arr","cwd":"/test"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":[{"type":"text","text":"First part"},{"type":"tool_use","name":"Read"},{"type":"text","text":"Second part"}]}}"#,
        ];
        write_session_file(&storage, "-test", "sess-arr", &lines);

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages.len(), 1);
        let msg_content = &convs[0].messages[0].content;
        assert!(msg_content.contains("First part"));
        assert!(msg_content.contains("Read"));
    }

    #[test]
    fn scan_infers_workspace_from_directory() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);

        // Session without cwd field
        let lines = vec![
            r#"{"type":"session_start","id":"sess-no-cwd"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
        ];
        write_session_file(&storage, "-Users-test-myproject", "sess-no-cwd", &lines);

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/Users/test/myproject"))
        );
    }

    #[test]
    fn scan_empty_messages_returns_none() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);

        let lines = vec![r#"{"type":"session_start","id":"sess-empty","cwd":"/test"}"#];
        write_session_file(&storage, "-test", "sess-empty", &lines);

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs.is_empty());
    }

    #[test]
    fn scan_reads_model_from_settings() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);

        let lines = vec![
            r#"{"type":"session_start","id":"sess-model","cwd":"/test"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello"}}"#,
        ];
        write_session_file(&storage, "-test", "sess-model", &lines);

        // Write settings file
        let settings_path = storage.join("-test").join("sess-model.settings.json");
        fs::write(&settings_path, r#"{"model":"claude-opus-4-5-20251101"}"#).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["model"], "claude-opus-4-5-20251101");
    }

    // =========================================================================
    // Edge case tests — malformed input robustness (br-27y8)
    // =========================================================================

    #[test]
    fn edge_truncated_jsonl_mid_json_returns_partial_results() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        // First line valid, second truncated mid-JSON
        let content = br#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Valid"}}
{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","con"#;
        fs::write(session_dir.join("truncated.jsonl"), content).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "truncated file should not cause an error");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            1,
            "should yield only the 1 valid message from truncated file"
        );
        assert_eq!(convs[0].messages[0].content, "Valid");
    }

    #[test]
    fn edge_truncated_mid_utf8_does_not_panic() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            br#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"OK"}}"#,
        );
        bytes.push(b'\n');
        // Incomplete 4-byte UTF-8 sequence (U+1F600 = F0 9F 98 80, only 2 bytes)
        bytes.extend_from_slice(b"\xF0\x9F");

        fs::write(session_dir.join("utf8trunc.jsonl"), &bytes).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "truncated mid-UTF8 should not panic");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "OK");
    }

    #[test]
    fn edge_invalid_utf8_skips_corrupted_lines() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            br#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Before"}}"#,
        );
        bytes.push(b'\n');
        bytes.extend_from_slice(b"\xFF\xFE invalid utf8 line\n");
        bytes.extend_from_slice(
            br#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"After"}}"#,
        );
        bytes.push(b'\n');

        fs::write(session_dir.join("badbytes.jsonl"), &bytes).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "invalid UTF-8 should not cause a panic");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            2,
            "should extract valid messages around invalid UTF-8"
        );
        assert_eq!(convs[0].messages[0].content, "Before");
        assert_eq!(convs[0].messages[1].content, "After");
    }

    #[test]
    fn edge_empty_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        fs::write(session_dir.join("empty.jsonl"), b"").unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "empty file should not cause errors");
        let convs = result.unwrap();
        assert!(
            convs.is_empty(),
            "empty file should produce no conversations"
        );
    }

    #[test]
    fn edge_whitespace_only_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        fs::write(session_dir.join("whitespace.jsonl"), "  \n\n  \t\n").unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "whitespace-only file should not cause errors"
        );
        let convs = result.unwrap();
        assert!(
            convs.is_empty(),
            "whitespace-only file should produce no conversations"
        );
    }

    #[test]
    fn edge_json_type_mismatch_skips_gracefully() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let content = concat!(
            // message field is a string instead of object
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":"not an object"}"#,
            "\n",
            // type is a number
            r#"{"type":123,"message":{"role":"user","content":"num type"}}"#,
            "\n",
            // content is a number
            r#"{"type":"message","message":{"role":"user","content":99}}"#,
            "\n",
            // Correct entry
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Correct"}}"#,
            "\n",
        );
        fs::write(session_dir.join("types.jsonl"), content).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "type mismatches should not cause errors");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert!(
            convs[0].messages.iter().any(|m| m.content == "Correct"),
            "should extract the correctly typed entry"
        );
    }

    #[test]
    fn edge_deeply_nested_json_does_not_stack_overflow() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        // serde_json has a recursion limit of 128; 200 levels will trigger parse error
        let mut nested = String::new();
        for _ in 0..200 {
            nested.push_str(r#"{"a":"#);
        }
        nested.push('1');
        for _ in 0..200 {
            nested.push('}');
        }

        let content = format!(
            "{}\n{}\n",
            nested,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"After nesting"}}"#
        );
        fs::write(session_dir.join("deep.jsonl"), &content).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "deeply nested JSON should not cause stack overflow"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "After nesting");
    }

    #[test]
    fn edge_large_message_body_handled_without_oom() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let large_content = "x".repeat(1_000_000);
        let line = format!(
            r#"{{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{{"role":"user","content":"{}"}}}}"#,
            large_content
        );
        fs::write(session_dir.join("large.jsonl"), &line).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "large message body should not cause OOM");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content.len(), 1_000_000);
    }

    #[test]
    fn edge_null_bytes_embedded_in_content_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let content = concat!(
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"before\u0000after"}}"#,
            "\n",
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"Clean"}}"#,
            "\n"
        );
        fs::write(session_dir.join("null.jsonl"), content).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "null bytes in content should not cause errors"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert!(!convs[0].messages.is_empty());
    }

    #[test]
    fn edge_bom_marker_at_file_start_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xEF\xBB\xBF"); // UTF-8 BOM
        bytes.extend_from_slice(
            br#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"BOM line"}}"#,
        );
        bytes.push(b'\n');
        bytes.extend_from_slice(
            br#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"Second"}}"#,
        );
        bytes.push(b'\n');
        fs::write(session_dir.join("bom.jsonl"), &bytes).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "BOM marker should not cause errors");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert!(
            !convs[0].messages.is_empty(),
            "should extract at least the second line after BOM"
        );
        assert!(
            convs[0].messages.iter().any(|m| m.content == "Second"),
            "second line should parse correctly regardless of BOM"
        );
    }

    #[test]
    fn edge_missing_message_field_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let content = concat!(
            // message type without message field
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z"}"#,
            "\n",
            // session_start without required fields
            r#"{"type":"session_start"}"#,
            "\n",
            // Valid message
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"Has message"}}"#,
            "\n",
        );
        fs::write(session_dir.join("nomsg.jsonl"), content).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "missing message field should not cause errors"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Has message");
    }

    #[test]
    fn edge_empty_content_messages_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let content = concat!(
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Has content"}}"#,
            "\n",
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","content":""}}"#,
            "\n",
            r#"{"type":"message","timestamp":"2025-12-01T10:00:02Z","message":{"role":"assistant","content":"   "}}"#,
            "\n",
        );
        fs::write(session_dir.join("empty-content.jsonl"), content).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "empty content should not cause errors");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            1,
            "empty content messages should be skipped"
        );
        assert_eq!(convs[0].messages[0].content, "Has content");
    }

    #[test]
    fn edge_unknown_entry_types_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let content = concat!(
            r#"{"type":"todo_state","tasks":[]}"#,
            "\n",
            r#"{"type":"tool_result","name":"bash","output":"ok"}"#,
            "\n",
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Real message"}}"#,
            "\n",
        );
        fs::write(session_dir.join("unknown.jsonl"), content).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "unknown entry types should not cause errors"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Real message");
    }

    #[test]
    fn edge_timestamp_parsing_variations() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let content = concat!(
            // ISO 8601 with milliseconds
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00.123Z","message":{"role":"user","content":"ms precision"}}"#,
            "\n",
            // ISO 8601 with timezone offset
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00+05:30","message":{"role":"user","content":"tz offset"}}"#,
            "\n",
            // Unix epoch milliseconds as number
            r#"{"type":"message","timestamp":1700000000000,"message":{"role":"user","content":"epoch millis"}}"#,
            "\n",
            // No timestamp
            r#"{"type":"message","message":{"role":"user","content":"no timestamp"}}"#,
            "\n",
            // Null timestamp
            r#"{"type":"message","timestamp":null,"message":{"role":"user","content":"null ts"}}"#,
            "\n",
        );
        fs::write(session_dir.join("timestamps.jsonl"), content).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "varied timestamp formats should not cause errors"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            5,
            "all 5 messages should be extracted regardless of timestamp format"
        );
        // Messages with valid timestamps should have created_at set
        assert!(convs[0].messages[0].created_at.is_some());
        assert!(convs[0].messages[1].created_at.is_some());
        assert!(convs[0].messages[2].created_at.is_some());
    }

    #[test]
    fn edge_timestamp_bounds_handle_out_of_order_events() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let content = concat!(
            r#"{"type":"message","timestamp":"2025-12-01T11:00:00Z","message":{"role":"assistant","content":"Later event first"}}"#,
            "\n",
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Earlier event second"}}"#,
            "\n",
        );
        fs::write(session_dir.join("out-of-order.jsonl"), content).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        let expected_start = conv.messages.iter().filter_map(|m| m.created_at).min();
        let expected_end = conv.messages.iter().filter_map(|m| m.created_at).max();

        assert_eq!(conv.started_at, expected_start);
        assert_eq!(conv.ended_at, expected_end);
        assert!(conv.ended_at >= conv.started_at);
    }

    #[test]
    fn edge_workspace_path_with_special_chars() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        // Workspace path with spaces and unicode
        let content = concat!(
            r#"{"type":"session_start","id":"sess-special","cwd":"/home/user/my project/src"}"#,
            "\n",
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Spaces path"}}"#,
            "\n",
        );
        fs::write(session_dir.join("special.jsonl"), content).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/my project/src"))
        );
    }

    #[test]
    fn edge_model_in_message_extracted_as_author() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let content = concat!(
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":"Response","model":"claude-opus-4-5"}}"#,
            "\n",
        );
        fs::write(session_dir.join("model.jsonl"), content).unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages[0].author,
            Some("claude-opus-4-5".to_string())
        );
    }

    #[test]
    fn edge_settings_file_malformed_ignored() {
        let dir = TempDir::new().unwrap();
        let storage = create_factory_storage(&dir);
        let session_dir = storage.join("-test");
        fs::create_dir_all(&session_dir).unwrap();

        let lines = vec![
            r#"{"type":"session_start","id":"sess-bad-settings","cwd":"/test"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello"}}"#,
        ];
        write_session_file(&storage, "-test", "sess-bad-settings", &lines);

        // Write malformed settings file
        let settings_path = session_dir.join("sess-bad-settings.settings.json");
        fs::write(&settings_path, "not valid json {{{").unwrap();

        let connector = FactoryConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "malformed settings file should not cause errors"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert!(
            convs[0].metadata["model"].is_null(),
            "model should be null when settings file is malformed"
        );
    }
}
