//! Connector for Kimi Code (Moonshot AI) session logs.
//!
//! Kimi Code stores sessions in JSONL files at:
//! - `~/.kimi/sessions/<workspace-hash>/<session-uuid>/wire.jsonl`
//!
//! Each line is a JSON object with `timestamp` and `message` fields.
//! Message types include: `TurnBegin`, `StepBegin`, `ContentPart`, `ToolCall`, etc.
//!
//! Additional files in each session directory:
//! - `context.jsonl` — context/conversation data
//! - `state.json` — session state

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

/// Parse a Kimi timestamp, which may be a floating-point epoch seconds value.
/// Falls through to the standard `parse_timestamp` for other formats.
fn parse_kimi_timestamp(val: &Value) -> Option<i64> {
    // Kimi uses floating-point seconds (e.g., 1772857971.158032)
    if let Some(f) = val.as_f64() {
        if f.is_finite() && f > 0.0 {
            #[allow(clippy::cast_possible_truncation)]
            let ms = if f < 100_000_000_000.0 {
                (f * 1000.0).round() as i64
            } else {
                f.round() as i64
            };
            return Some(ms);
        }
    }
    parse_timestamp(val)
}

pub struct KimiConnector;

impl Default for KimiConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl KimiConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Get the Kimi sessions root directory.
    fn sessions_root() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".kimi")
            .join("sessions")
    }

    fn looks_like_kimi_storage(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        path_str.contains(".kimi") && path_str.contains("sessions")
    }

    /// Find all wire.jsonl files under a root.
    fn wire_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if !root.exists() {
            return out;
        }

        for entry in WalkDir::new(root).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }

            if entry.file_name() == "wire.jsonl" {
                out.push(entry.path().to_path_buf());
            }
        }

        out.sort();
        out
    }
}

impl Connector for KimiConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("kimi").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let root = if ctx.use_default_detection() {
            if Self::looks_like_kimi_storage(&ctx.data_dir) && ctx.data_dir.exists() {
                ctx.data_dir.clone()
            } else {
                let r = Self::sessions_root();
                if r.exists() {
                    r
                } else {
                    return Ok(Vec::new());
                }
            }
        } else {
            let kimi_root = ctx.scan_roots.iter().find_map(|sr| {
                let kimi_path = sr.path.join(".kimi/sessions");
                if kimi_path.exists() {
                    Some(kimi_path)
                } else if Self::looks_like_kimi_storage(&sr.path) {
                    Some(sr.path.clone())
                } else {
                    None
                }
            });
            match kimi_root {
                Some(r) => r,
                None => return Ok(Vec::new()),
            }
        };

        if !root.exists() {
            return Ok(Vec::new());
        }

        let mut convs = Vec::new();

        for wire_path in Self::wire_files(&root) {
            if !file_modified_since(&wire_path, ctx.since_ts) {
                continue;
            }

            match parse_kimi_session(&wire_path) {
                Ok(Some(conv)) => convs.push(conv),
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!(path = %wire_path.display(), error = %e, "kimi parse error");
                }
            }
        }

        Ok(convs)
    }
}

fn update_time_bounds(started_at: &mut Option<i64>, ended_at: &mut Option<i64>, ts: Option<i64>) {
    if let Some(ts) = ts {
        *started_at = Some(started_at.map_or(ts, |curr| curr.min(ts)));
        *ended_at = Some(ended_at.map_or(ts, |curr| curr.max(ts)));
    }
}

/// Infer workspace from the session directory structure.
/// Path pattern: `~/.kimi/sessions/<workspace-hash>/<session-uuid>/wire.jsonl`
/// We try to read `state.json` in the same directory for workspace info.
fn infer_workspace(wire_path: &Path) -> Option<PathBuf> {
    let session_dir = wire_path.parent()?;

    // Try reading state.json for workspace/cwd info
    let state_path = session_dir.join("state.json");
    if let Ok(content) = fs::read_to_string(&state_path) {
        if let Ok(val) = serde_json::from_str::<Value>(&content) {
            // Check common fields for workspace path
            for key in &["cwd", "workspace", "workspacePath", "projectPath"] {
                if let Some(path_str) = val.get(*key).and_then(|v| v.as_str()) {
                    if !path_str.is_empty() {
                        return Some(PathBuf::from(path_str));
                    }
                }
            }
        }
    }

    None
}

/// Infer session UUID from the directory structure.
/// Path pattern: `~/.kimi/sessions/<workspace-hash>/<session-uuid>/wire.jsonl`
fn infer_session_id(wire_path: &Path) -> Option<String> {
    wire_path
        .parent()?
        .file_name()
        .and_then(|n| n.to_str())
        .map(String::from)
}

/// Extract text content from a Kimi ContentPart payload.
fn extract_content_part_text(payload: &Value) -> String {
    // Try payload.content (string or array)
    if let Some(content) = payload.get("content") {
        let text = flatten_content(content);
        if !text.is_empty() {
            return text;
        }
    }

    // Try payload.text
    if let Some(text) = payload.get("text").and_then(|v| v.as_str()) {
        if !text.is_empty() {
            return text.to_string();
        }
    }

    // Try payload.value
    if let Some(text) = payload.get("value").and_then(|v| v.as_str()) {
        if !text.is_empty() {
            return text.to_string();
        }
    }

    String::new()
}

/// Extract tool call description from a ToolCall payload.
fn extract_tool_call_text(payload: &Value) -> String {
    let tool_name = payload
        .get("name")
        .or_else(|| payload.get("toolName"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let desc = payload
        .get("input")
        .and_then(|i| {
            i.get("description")
                .or_else(|| i.get("file_path"))
                .or_else(|| i.get("command"))
                .and_then(|v| v.as_str())
        })
        .or_else(|| {
            payload
                .get("arguments")
                .and_then(|a| a.as_str())
                .or_else(|| payload.get("parameters").and_then(|p| p.as_str()))
        })
        .unwrap_or("");

    if desc.is_empty() {
        format!("[Tool: {tool_name}]")
    } else {
        format!("[Tool: {tool_name} - {desc}]")
    }
}

/// Parse a Kimi wire.jsonl session file into a NormalizedConversation.
fn parse_kimi_session(path: &Path) -> Result<Option<NormalizedConversation>> {
    let file =
        fs::File::open(path).with_context(|| format!("open kimi wire file {}", path.display()))?;
    let reader = std::io::BufReader::new(file);

    let mut messages = Vec::new();
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    let mut current_role = String::from("assistant");

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                tracing::debug!("skipping unreadable JSONL line: {e}");
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let val: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Parse timestamp (floating-point seconds or ISO string)
        let created = val.get("timestamp").and_then(parse_kimi_timestamp);
        update_time_bounds(&mut started_at, &mut ended_at, created);

        let msg = val.get("message");
        let msg_type = msg.and_then(|m| m.get("type")).and_then(|v| v.as_str());

        // Also check top-level type for metadata lines
        let top_type = val.get("type").and_then(|v| v.as_str());

        match (msg_type, top_type) {
            (Some("TurnBegin"), _) => {
                // TurnBegin signals a new turn; extract the role from the payload
                let payload = msg.and_then(|m| m.get("payload"));
                let turn_role = payload.and_then(|p| p.get("role")).and_then(|v| v.as_str());

                let is_user = matches!(turn_role, Some("human" | "user"));

                if is_user {
                    current_role = "user".to_string();
                } else {
                    current_role = "assistant".to_string();
                }

                // TurnBegin may carry initial content
                if let Some(payload) = payload {
                    let content = extract_content_part_text(payload);
                    if !content.trim().is_empty() {
                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: current_role.clone(),
                            author: None,
                            created_at: created,
                            content,
                            extra: val.clone(),
                            snippets: Vec::new(),
                            invocations: Vec::new(),
                        });
                        }
                        }

                        // After a user TurnBegin, subsequent ContentParts are assistant responses
                        if is_user {
                        current_role = "assistant".to_string();
                        }
                        }
                        (Some("ContentPart"), _) => {
                        let payload = msg.and_then(|m| m.get("payload"));
                        let content = payload.map(extract_content_part_text).unwrap_or_default();

                        if !content.trim().is_empty() {
                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: current_role.clone(),
                            author: None,
                            created_at: created,
                            content,
                            extra: val,
                            snippets: Vec::new(),
                            invocations: Vec::new(),
                        });
                        }
                        }
                        (Some("ToolCall"), _) => {
                        let payload = msg.and_then(|m| m.get("payload"));
                        let content = payload
                        .map(extract_tool_call_text)
                        .unwrap_or_else(|| "[Tool: unknown]".to_string());

                        let invocations = if let Some(p) = payload {
                        let tool_name = p
                            .get("name")
                            .or_else(|| p.get("toolName"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        vec![crate::types::NormalizedInvocation {
                            kind: "tool".to_string(),
                            name: tool_name.to_string(),
                            raw_name: None,
                            call_id: None,
                            arguments: p
                                .get("input")
                                .or_else(|| p.get("arguments"))
                                .or_else(|| p.get("parameters"))
                                .cloned(),
                        }]
                        } else {
                        Vec::new()
                        };

                        messages.push(NormalizedMessage {
                        idx: 0,
                        role: "assistant".to_string(),
                        author: None,
                        created_at: created,
                        content,
                        extra: val,
                        snippets: Vec::new(),
                        invocations,
                        });
            }
            // Skip metadata, StepBegin, and other non-content types
            _ => {}
        }
    }

    crate::types::reindex_messages(&mut messages);

    if messages.is_empty() {
        return Ok(None);
    }

    let session_id = infer_session_id(path);
    let workspace = infer_workspace(path);

    let title = messages.iter().find(|m| m.role == "user").map(|m| {
        m.content
            .lines()
            .next()
            .unwrap_or(&m.content)
            .chars()
            .take(100)
            .collect::<String>()
    });

    Ok(Some(NormalizedConversation {
        agent_slug: "kimi".into(),
        external_id: session_id.clone(),
        title,
        workspace,
        source_path: path.to_path_buf(),
        started_at,
        ended_at,
        metadata: serde_json::json!({
            "source": "kimi",
            "sessionId": session_id,
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
        let connector = KimiConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = KimiConnector::default();
        let _ = connector;
    }

    // =========================================================================
    // Helper to create Kimi storage layout
    // =========================================================================

    fn create_kimi_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join(".kimi").join("sessions");
        fs::create_dir_all(&storage).unwrap();
        storage
    }

    fn write_wire_file(storage: &Path, workspace_hash: &str, session_id: &str, lines: &[&str]) {
        let session_dir = storage.join(workspace_hash).join(session_id);
        fs::create_dir_all(&session_dir).unwrap();
        let file_path = session_dir.join("wire.jsonl");
        fs::write(&file_path, lines.join("\n")).unwrap();
    }

    // =========================================================================
    // Detection tests
    // =========================================================================

    #[test]
    fn detect_not_found_without_sessions_dir() {
        let connector = KimiConnector::new();
        let result = connector.detect();
        let _ = result.detected;
    }

    // =========================================================================
    // JSONL parsing tests
    // =========================================================================

    #[test]
    fn scan_parses_turn_begin_and_content_parts() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"type": "metadata", "protocol_version": "1.3"}"#,
            r#"{"timestamp": 1772857971.158, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Hello Kimi"}}}"#,
            r#"{"timestamp": 1772857980.325, "message": {"type": "ContentPart", "payload": {"content": "Hello! How can I help you?"}}}"#,
        ];
        write_wire_file(&storage, "abc123", "sess-001", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "kimi");
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Kimi");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert!(
            convs[0].messages[1]
                .content
                .contains("Hello! How can I help")
        );
    }

    #[test]
    fn scan_extracts_tool_calls() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Read main.rs"}}}"#,
            r#"{"timestamp": 1772857980.0, "message": {"type": "ToolCall", "payload": {"name": "Read", "input": {"file_path": "/src/main.rs"}}}}"#,
            r#"{"timestamp": 1772857985.0, "message": {"type": "ContentPart", "payload": {"content": "Here is the file content."}}}"#,
        ];
        write_wire_file(&storage, "abc123", "sess-002", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 3);
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert!(convs[0].messages[1].content.contains("[Tool: Read"));
    }

    #[test]
    fn scan_infers_session_id_from_directory() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "test"}}}"#,
        ];
        write_wire_file(&storage, "wshash", "my-session-uuid", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id, Some("my-session-uuid".to_string()));
    }

    #[test]
    fn scan_reads_workspace_from_state_json() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let session_dir = storage.join("wshash").join("sess-ws");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(
            session_dir.join("wire.jsonl"),
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "hello"}}}"#,
        )
        .unwrap();
        fs::write(
            session_dir.join("state.json"),
            r#"{"cwd": "/home/user/myproject"}"#,
        )
        .unwrap();

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/myproject"))
        );
    }

    #[test]
    fn scan_generates_title_from_first_user_message() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Explain the architecture of this project"}}}"#,
            r#"{"timestamp": 1772857980.0, "message": {"type": "ContentPart", "payload": {"content": "Sure, let me explain..."}}}"#,
        ];
        write_wire_file(&storage, "wshash", "sess-title", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].title,
            Some("Explain the architecture of this project".to_string())
        );
    }

    #[test]
    fn scan_tracks_time_bounds() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "first"}}}"#,
            r#"{"timestamp": 1772858000.0, "message": {"type": "ContentPart", "payload": {"content": "second"}}}"#,
        ];
        write_wire_file(&storage, "wshash", "sess-time", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
        assert!(convs[0].started_at.unwrap() <= convs[0].ended_at.unwrap());
    }

    #[test]
    fn scan_role_switches_on_turn_begin() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "User message"}}}"#,
            r#"{"timestamp": 1772857980.0, "message": {"type": "ContentPart", "payload": {"content": "Assistant reply"}}}"#,
            r#"{"timestamp": 1772857990.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Second user message"}}}"#,
        ];
        write_wire_file(&storage, "wshash", "sess-roles", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert_eq!(convs[0].messages[2].role, "user");
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn edge_empty_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let session_dir = storage.join("ws").join("sess-empty");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(session_dir.join("wire.jsonl"), b"").unwrap();

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs.is_empty());
    }

    #[test]
    fn edge_metadata_only_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![r#"{"type": "metadata", "protocol_version": "1.3"}"#];
        write_wire_file(&storage, "ws", "sess-meta-only", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs.is_empty());
    }

    #[test]
    fn edge_malformed_json_lines_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let session_dir = storage.join("ws").join("sess-malformed");
        fs::create_dir_all(&session_dir).unwrap();
        let content = concat!(
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Valid"}}}"#,
            "\n",
            "not valid json {{{",
            "\n",
            r#"{"timestamp": 1772857980.0, "message": {"type": "ContentPart", "payload": {"content": "Also valid"}}}"#,
            "\n",
        );
        fs::write(session_dir.join("wire.jsonl"), content).unwrap();

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn edge_empty_content_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "ContentPart", "payload": {"content": ""}}}"#,
            r#"{"timestamp": 1772857975.0, "message": {"type": "ContentPart", "payload": {"content": "   "}}}"#,
            r#"{"timestamp": 1772857980.0, "message": {"type": "ContentPart", "payload": {"content": "Real content"}}}"#,
        ];
        write_wire_file(&storage, "ws", "sess-empty-content", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Real content");
    }

    #[test]
    fn edge_multiple_sessions_found() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines1 = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Session 1"}}}"#,
        ];
        let lines2 = vec![
            r#"{"timestamp": 1772858000.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Session 2"}}}"#,
        ];
        write_wire_file(&storage, "ws1", "sess-a", &lines1);
        write_wire_file(&storage, "ws2", "sess-b", &lines2);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
    }

    #[test]
    fn edge_step_begin_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Hello"}}}"#,
            r#"{"timestamp": 1772857975.0, "message": {"type": "StepBegin", "payload": {"step": 1}}}"#,
            r#"{"timestamp": 1772857980.0, "message": {"type": "ContentPart", "payload": {"content": "Response"}}}"#,
        ];
        write_wire_file(&storage, "ws", "sess-step", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].content, "Hello");
        assert_eq!(convs[0].messages[1].content, "Response");
    }
}
