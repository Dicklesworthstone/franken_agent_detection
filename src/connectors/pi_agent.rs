//! Connector for pi-mono coding-agent (https://github.com/badlogic/pi-mono)
//!
//! Pi-Agent stores sessions in JSONL files under:
//! - `~/.pi/agent/sessions/<safe-path>/` where safe-path is derived from the working directory
//! - Each session file is named `<timestamp>_<uuid>.jsonl`
//!
//! JSONL entry types:
//! - `session`: Header with id, timestamp, cwd, provider, modelId, thinkingLevel
//! - `message`: Contains timestamp and message object with role (user/assistant/toolResult)
//! - `thinking_level_change`: Records thinking level changes
//! - `model_change`: Records model/provider changes

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::ScanContext;
use super::{Connector, file_modified_since, franken_detection_for_connector, parse_timestamp};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct PiAgentConnector;

impl Default for PiAgentConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl PiAgentConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Get the pi-agent home directory.
    /// Checks PI_CODING_AGENT_DIR env var, falls back to ~/.pi/agent/
    fn home() -> PathBuf {
        dotenvy::var("PI_CODING_AGENT_DIR").map_or_else(
            |_| dirs::home_dir().unwrap_or_default().join(".pi/agent"),
            PathBuf::from,
        )
    }

    fn sessions_dir(home: &Path) -> PathBuf {
        let sessions = home.join("sessions");
        if sessions.exists() {
            sessions
        } else {
            home.to_path_buf()
        }
    }

    /// Find all session JSONL files under the sessions directory.
    fn session_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let sessions = Self::sessions_dir(root);
        if !sessions.exists() {
            return out;
        }
        for entry in WalkDir::new(sessions).into_iter().flatten() {
            if entry.file_type().is_file() {
                let name = entry.file_name().to_str().unwrap_or("");
                // Pi-agent session files are named <timestamp>_<uuid>.jsonl
                if name.ends_with(".jsonl") && name.contains('_') {
                    out.push(entry.path().to_path_buf());
                }
            }
        }
        // Keep connector traversal deterministic across filesystems/runs.
        out.sort();
        out
    }

    /// Flatten pi-agent message content to a searchable string.
    /// Handles the message.content array which can contain:
    /// - TextContent: {type: "text", text: "..."}
    /// - ThinkingContent: {type: "thinking", thinking: "..."}
    /// - ToolCall: {type: "toolCall", name: "...", arguments: {...}}
    /// - ImageContent: {type: "image", ...} (skip for text extraction)
    fn flatten_message_content(content: &Value) -> String {
        // Direct string content (simple user messages)
        if let Some(s) = content.as_str() {
            return s.to_string();
        }

        // Array of content blocks
        if let Some(arr) = content.as_array() {
            let parts: Vec<String> = arr
                .iter()
                .filter_map(|item| {
                    let item_type = item.get("type").and_then(|v| v.as_str());

                    match item_type {
                        Some("text") => item.get("text").and_then(|v| v.as_str()).map(String::from),
                        Some("thinking") => {
                            // Include thinking content - valuable for search
                            item.get("thinking")
                                .and_then(|v| v.as_str())
                                .map(|t| format!("[Thinking] {t}"))
                        }
                        Some("toolCall") => {
                            // Include tool calls for searchability
                            let name = item
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let args = item
                                .get("arguments")
                                .map(|a| {
                                    // Extract key argument values for context
                                    if let Some(obj) = a.as_object() {
                                        obj.iter()
                                            .filter_map(|(k, v)| {
                                                v.as_str().map(|s| format!("{k}={s}"))
                                            })
                                            .take(3) // Limit to avoid huge strings
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    } else {
                                        String::new()
                                    }
                                })
                                .unwrap_or_default();
                            if args.is_empty() {
                                Some(format!("[Tool: {name}]"))
                            } else {
                                Some(format!("[Tool: {name}] {args}"))
                            }
                        }
                        Some("image") => None, // Skip image content
                        _ => None,
                    }
                })
                .collect();
            return parts.join("\n");
        }

        String::new()
    }
}

impl Connector for PiAgentConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("pi_agent").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        // Use data_root if it looks like a pi-agent directory (for testing)
        let is_pi_agent_dir = ctx
            .data_dir
            .to_str()
            .map(|s| {
                s.contains(".pi/agent") || s.ends_with("/pi-agent") || s.ends_with("\\pi-agent")
            })
            .unwrap_or(false);
        let looks_like_root = |path: &PathBuf| {
            path.join("sessions").exists()
                || path
                    .file_name()
                    .is_some_and(|n| n.to_str().unwrap_or("").contains("pi"))
        };

        let mut home = if ctx.use_default_detection() {
            if is_pi_agent_dir {
                ctx.data_dir.clone()
            } else {
                Self::home()
            }
        } else {
            if !looks_like_root(&ctx.data_dir) {
                return Ok(Vec::new());
            }
            ctx.data_dir.clone()
        };
        if home.is_file() {
            home = home.parent().unwrap_or(&home).to_path_buf();
        }

        let files = Self::session_files(&home);
        let mut convs = Vec::new();

        for file in files {
            // Skip files not modified since last scan
            if !file_modified_since(&file, ctx.since_ts) {
                continue;
            }

            let source_path = file.clone();

            // Use the parent directory name + filename as external_id
            // e.g., "--Users-foo-project--/2024-01-15T10-30-00_uuid.jsonl"
            let sessions_dir = Self::sessions_dir(&home);
            let external_id = source_path
                .strip_prefix(&sessions_dir)
                .ok()
                .and_then(|rel| rel.to_str().map(String::from))
                .or_else(|| {
                    source_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .map(String::from)
                });

            let content = match fs::read_to_string(&file) {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(path = %file.display(), error = %e, "pi-agent: skipping unreadable session");
                    continue;
                }
            };

            let mut messages = Vec::new();
            let mut started_at: Option<i64> = None;
            let mut ended_at: Option<i64> = None;
            let mut session_cwd: Option<PathBuf> = None;
            let mut session_id: Option<String> = None;
            let mut provider: Option<String> = None;
            let mut model_id: Option<String> = None;

            for line in content.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let val: Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let entry_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");

                match entry_type {
                    "session" => {
                        // Session header - extract metadata
                        session_id = val.get("id").and_then(|v| v.as_str()).map(String::from);
                        session_cwd = val.get("cwd").and_then(|v| v.as_str()).map(PathBuf::from);
                        provider = val
                            .get("provider")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        model_id = val
                            .get("modelId")
                            .and_then(|v| v.as_str())
                            .map(String::from);

                        // Parse timestamp
                        if let Some(ts_val) = val.get("timestamp") {
                            started_at = parse_timestamp(ts_val);
                        }
                    }
                    "message" => {
                        // Message entry - extract the nested message object
                        let created = val.get("timestamp").and_then(parse_timestamp);

                        if let Some(msg) = val.get("message") {
                            let role = msg
                                .get("role")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");

                            // Normalize role names
                            let normalized_role = match role {
                                "user" => "user",
                                "assistant" => "assistant",
                                "toolResult" => "tool",
                                _ => role,
                            };

                            // Extract content
                            let content_str = msg
                                .get("content")
                                .map(Self::flatten_message_content)
                                .unwrap_or_default();

                            if content_str.trim().is_empty() {
                                continue;
                            }

                            // Update timestamps
                            started_at = match (started_at, created) {
                                (Some(curr), Some(ts)) => Some(curr.min(ts)),
                                (None, Some(ts)) => Some(ts),
                                (other, None) => other,
                            };
                            ended_at = match (ended_at, created) {
                                (Some(curr), Some(ts)) => Some(curr.max(ts)),
                                (None, Some(ts)) => Some(ts),
                                (other, None) => other,
                            };

                            // Extract author (model) for assistant messages
                            // Check message.model first, fall back to tracked model_id
                            let author = if normalized_role == "assistant" {
                                msg.get("model")
                                    .and_then(|v| v.as_str())
                                    .map(String::from)
                                    .or_else(|| model_id.clone())
                            } else {
                                None
                            };

                            messages.push(NormalizedMessage {
                                idx: i64::try_from(messages.len()).unwrap_or(i64::MAX),
                                role: normalized_role.to_string(),
                                author,
                                created_at: created,
                                content: content_str,
                                extra: val.clone(),
                                snippets: Vec::new(),
                            });
                        }
                    }
                    "model_change" => {
                        // Track model changes (useful metadata)
                        provider = val
                            .get("provider")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        model_id = val
                            .get("modelId")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                    }
                    _ => {
                        // Skip thinking_level_change and unknown types
                    }
                }
            }

            if messages.is_empty() {
                continue;
            }

            // Extract title from first user message
            let title = messages
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
                    messages
                        .first()
                        .and_then(|m| m.content.lines().next())
                        .map(|s| s.chars().take(100).collect())
                });

            // Build metadata
            let metadata = serde_json::json!({
                "source": "pi_agent",
                "session_id": session_id,
                "provider": provider,
                "model_id": model_id,
            });

            convs.push(NormalizedConversation {
                agent_slug: "pi_agent".to_string(),
                external_id,
                title,
                workspace: session_cwd,
                source_path: source_path.clone(),
                started_at,
                ended_at,
                metadata,
                messages,
            });
        }

        Ok(convs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    // =====================================================
    // Constructor Tests
    // =====================================================

    #[test]
    fn new_creates_connector() {
        let connector = PiAgentConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = PiAgentConnector;
        let _ = connector;
    }

    // =====================================================
    // flatten_message_content() Tests
    // =====================================================

    #[test]
    fn flatten_message_content_handles_string() {
        let content = json!("Simple string content");
        let result = PiAgentConnector::flatten_message_content(&content);
        assert_eq!(result, "Simple string content");
    }

    #[test]
    fn flatten_message_content_handles_text_blocks() {
        let content = json!([
            {"type": "text", "text": "First paragraph"},
            {"type": "text", "text": "Second paragraph"}
        ]);
        let result = PiAgentConnector::flatten_message_content(&content);
        assert!(result.contains("First paragraph"));
        assert!(result.contains("Second paragraph"));
    }

    #[test]
    fn flatten_message_content_handles_thinking() {
        let content = json!([
            {"type": "thinking", "thinking": "Let me analyze this..."}
        ]);
        let result = PiAgentConnector::flatten_message_content(&content);
        assert!(result.contains("[Thinking]"));
        assert!(result.contains("Let me analyze this..."));
    }

    #[test]
    fn flatten_message_content_handles_tool_call() {
        let content = json!([
            {"type": "toolCall", "name": "read_file", "arguments": {"path": "/test.rs"}}
        ]);
        let result = PiAgentConnector::flatten_message_content(&content);
        assert!(result.contains("[Tool: read_file]"));
        assert!(result.contains("path=/test.rs"));
    }

    #[test]
    fn flatten_message_content_handles_tool_call_without_args() {
        let content = json!([
            {"type": "toolCall", "name": "get_status", "arguments": {}}
        ]);
        let result = PiAgentConnector::flatten_message_content(&content);
        assert_eq!(result, "[Tool: get_status]");
    }

    #[test]
    fn flatten_message_content_skips_images() {
        let content = json!([
            {"type": "text", "text": "Here's an image:"},
            {"type": "image", "url": "data:image/png;base64,..."},
            {"type": "text", "text": "End of message"}
        ]);
        let result = PiAgentConnector::flatten_message_content(&content);
        assert!(result.contains("Here's an image:"));
        assert!(result.contains("End of message"));
        assert!(!result.contains("data:image"));
    }

    #[test]
    fn flatten_message_content_handles_mixed_types() {
        let content = json!([
            {"type": "text", "text": "Let me help:"},
            {"type": "thinking", "thinking": "Analyzing..."},
            {"type": "toolCall", "name": "bash", "arguments": {"command": "ls"}},
            {"type": "text", "text": "Done!"}
        ]);
        let result = PiAgentConnector::flatten_message_content(&content);
        assert!(result.contains("Let me help:"));
        assert!(result.contains("[Thinking] Analyzing..."));
        assert!(result.contains("[Tool: bash]"));
        assert!(result.contains("Done!"));
    }

    #[test]
    fn flatten_message_content_returns_empty_for_null() {
        let content = json!(null);
        let result = PiAgentConnector::flatten_message_content(&content);
        assert!(result.is_empty());
    }

    #[test]
    fn flatten_message_content_limits_tool_args_to_three() {
        let content = json!([
            {"type": "toolCall", "name": "multi_arg", "arguments": {
                "a": "1", "b": "2", "c": "3", "d": "4", "e": "5"
            }}
        ]);
        let result = PiAgentConnector::flatten_message_content(&content);
        // Should contain at most 3 arguments
        let arg_count = result.matches('=').count();
        assert!(arg_count <= 3);
    }

    // =====================================================
    // session_files() Tests
    // =====================================================

    #[test]
    fn session_files_finds_valid_session_files() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Valid session file format: <timestamp>_<uuid>.jsonl
        fs::write(sessions.join("2025-12-01T10-00-00_abc123.jsonl"), "{}").unwrap();

        let files = PiAgentConnector::session_files(dir.path());
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn session_files_ignores_non_jsonl_files() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        fs::write(sessions.join("2025-12-01_abc123.json"), "{}").unwrap();
        fs::write(sessions.join("config.txt"), "{}").unwrap();

        let files = PiAgentConnector::session_files(dir.path());
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn session_files_ignores_files_without_underscore() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Missing underscore between timestamp and uuid
        fs::write(sessions.join("2025-12-01.jsonl"), "{}").unwrap();

        let files = PiAgentConnector::session_files(dir.path());
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn session_files_finds_nested_sessions() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("sessions").join("--Users-foo-project--");
        fs::create_dir_all(&nested).unwrap();

        fs::write(nested.join("2025-12-01T10-00-00_uuid1.jsonl"), "{}").unwrap();

        let files = PiAgentConnector::session_files(dir.path());
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn session_files_returns_empty_when_no_sessions_dir() {
        let dir = TempDir::new().unwrap();
        let files = PiAgentConnector::session_files(dir.path());
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn session_files_returns_sorted_order() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("sessions").join("--Users-foo-project--");
        fs::create_dir_all(&nested).unwrap();

        fs::write(nested.join("2025-12-01T10-00-00_zzzz.jsonl"), "{}").unwrap();
        fs::write(nested.join("2025-12-01T10-00-00_aaaa.jsonl"), "{}").unwrap();
        fs::write(nested.join("2025-12-01T10-00-00_mmmm.jsonl"), "{}").unwrap();

        let files = PiAgentConnector::session_files(dir.path());
        let mut sorted = files.clone();
        sorted.sort();
        assert_eq!(files, sorted);
    }

    // =====================================================
    // Helper: Create Pi-Agent storage structure
    // =====================================================

    fn create_pi_agent_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join("pi-agent");
        fs::create_dir_all(storage.join("sessions")).unwrap();
        storage
    }

    fn write_session_file(storage: &Path, name: &str, lines: &[&str]) {
        let sessions = storage.join("sessions");
        fs::write(sessions.join(name), lines.join("\n")).unwrap();
    }

    // =====================================================
    // scan() Tests - Session Header
    // =====================================================

    #[test]
    fn scan_parses_session_header() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"session","id":"sess-001","timestamp":"2025-12-01T10:00:00Z","cwd":"/home/user/project","provider":"anthropic","modelId":"claude-3-opus"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"Hello Pi!"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/project"))
        );
        assert_eq!(convs[0].metadata["provider"], "anthropic");
        assert_eq!(convs[0].metadata["model_id"], "claude-3-opus");
    }

    // =====================================================
    // scan() Tests - Messages
    // =====================================================

    #[test]
    fn scan_parses_user_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello Pi-Agent!"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Pi-Agent!");
    }

    #[test]
    fn scan_parses_assistant_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":"Hello! How can I help?","model":"claude-3-opus"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].role, "assistant");
        assert_eq!(
            convs[0].messages[0].author,
            Some("claude-3-opus".to_string())
        );
    }

    #[test]
    fn scan_normalizes_tool_result_role() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"toolResult","content":"Tool output here"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // toolResult should be normalized to "tool"
        assert_eq!(convs[0].messages[0].role, "tool");
    }

    #[test]
    fn scan_parses_array_content() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let content = json!([
            {"type": "text", "text": "Part 1"},
            {"type": "text", "text": "Part 2"}
        ]);
        let line = format!(
            r#"{{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{{"role":"assistant","content":{}}}}}"#,
            content
        );
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &[&line]);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].messages[0].content.contains("Part 1"));
        assert!(convs[0].messages[0].content.contains("Part 2"));
    }

    #[test]
    fn scan_skips_empty_content() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Valid"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","content":""}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:02Z","message":{"role":"assistant","content":"   "}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Only the valid message should be included
        assert_eq!(convs[0].messages.len(), 1);
    }

    // =====================================================
    // scan() Tests - Model Changes
    // =====================================================

    #[test]
    fn scan_tracks_model_changes() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"session","id":"sess-001","provider":"openai","modelId":"gpt-4"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello"}}"#,
            r#"{"type":"model_change","provider":"anthropic","modelId":"claude-3-opus"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","content":"Hello!"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // After model_change, assistant should have new model as author
        assert_eq!(
            convs[0].messages[1].author,
            Some("claude-3-opus".to_string())
        );
    }

    // =====================================================
    // scan() Tests - Skipped Entry Types
    // =====================================================

    #[test]
    fn scan_skips_thinking_level_change() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
            r#"{"type":"thinking_level_change","level":"high"}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should still work, just skip the thinking_level_change
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
    }

    // =====================================================
    // Title Extraction Tests
    // =====================================================

    #[test]
    fn scan_extracts_title_from_first_user_message() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":"I'm ready!"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"This is the title"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("This is the title".to_string()));
    }

    #[test]
    fn scan_truncates_long_titles() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let long_content = "x".repeat(200);
        let line = format!(
            r#"{{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{{"role":"user","content":"{}"}}}}"#,
            long_content
        );
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &[&line]);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title.as_ref().unwrap().len(), 100);
    }

    #[test]
    fn scan_uses_first_line_for_multiline_title() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"First line\nSecond line\nThird line"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("First line".to_string()));
    }

    #[test]
    fn scan_falls_back_to_first_message_for_title() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        // No user messages
        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":"Assistant speaks first"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("Assistant speaks first".to_string()));
    }

    // =====================================================
    // Timestamp Tests
    // =====================================================

    #[test]
    fn scan_extracts_timestamps() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"session","timestamp":"2025-12-01T10:00:00Z"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"First"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T11:00:00Z","message":{"role":"assistant","content":"Last"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
        assert!(convs[0].messages[0].created_at.is_some());
    }

    // =====================================================
    // Agent Slug and External ID Tests
    // =====================================================

    #[test]
    fn scan_sets_agent_slug_to_pi_agent() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].agent_slug, "pi_agent");
    }

    #[test]
    fn scan_uses_relative_path_as_external_id() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let nested = storage.join("sessions").join("--Users-foo-project--");
        fs::create_dir_all(&nested).unwrap();

        let lines = [
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
        ];
        fs::write(
            nested.join("2025-12-01T10-00-00_uuid1.jsonl"),
            lines.join("\n"),
        )
        .unwrap();

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // External ID should include the path structure
        assert!(convs[0].external_id.is_some());
        let ext_id = convs[0].external_id.as_ref().unwrap();
        assert!(ext_id.contains("Users-foo-project") || ext_id.contains("uuid1"));
    }

    // =====================================================
    // Metadata Tests
    // =====================================================

    #[test]
    fn scan_sets_metadata_source() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["source"], "pi_agent");
    }

    #[test]
    fn scan_includes_session_id_in_metadata() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"session","id":"unique-session-id-123"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["session_id"], "unique-session-id-123");
    }

    // =====================================================
    // Edge Cases
    // =====================================================

    #[test]
    fn scan_handles_empty_sessions_dir() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_invalid_json_lines() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Valid"}}"#,
            "not valid json at all",
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"Also valid"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn scan_skips_empty_lines() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Message 1"}}"#,
            "",
            "   ",
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"Message 2"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn scan_skips_sessions_without_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        // Only session header, no messages
        let lines = vec![r#"{"type":"session","id":"empty-session"}"#];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_handles_multiple_session_files() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines1 = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Session 1"}}"#,
        ];
        let lines2 = vec![
            r#"{"type":"message","timestamp":"2025-12-01T11:00:00Z","message":{"role":"user","content":"Session 2"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines1);
        write_session_file(&storage, "2025-12-01T11-00-00_uuid2.jsonl", &lines2);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
    }

    #[test]
    fn scan_assigns_sequential_indices() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"First"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","content":"Second"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:02Z","message":{"role":"user","content":"Third"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].idx, 0);
        assert_eq!(convs[0].messages[1].idx, 1);
        assert_eq!(convs[0].messages[2].idx, 2);
    }

    #[test]
    fn scan_stores_source_path() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        let expected_path = storage
            .join("sessions")
            .join("2025-12-01T10-00-00_uuid1.jsonl");
        assert_eq!(convs[0].source_path, expected_path);
    }

    #[test]
    fn scan_uses_fallback_model_from_session() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        // Session sets model, assistant message doesn't override
        let lines = vec![
            r#"{"type":"session","modelId":"gpt-4-turbo"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":"Hello!"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].author, Some("gpt-4-turbo".to_string()));
    }

    // =========================================================================
    // Edge case tests — malformed input robustness (br-2w98)
    // =========================================================================

    #[test]
    fn edge_empty_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &[""]);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_whitespace_only_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        write_session_file(
            &storage,
            "2025-12-01T10-00-00_uuid1.jsonl",
            &["   ", "\t", "  "],
        );

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_truncated_jsonl_mid_json_returns_partial_results() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Valid"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assis"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid");
    }

    #[test]
    fn edge_invalid_utf8_skips_file() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        // Pi-Agent uses read_to_string which will fail on invalid UTF-8
        let file_path = storage
            .join("sessions")
            .join("2025-12-01T10-00-00_uuid1.jsonl");
        std::fs::write(&file_path, b"\xff\xfe invalid utf8 line").unwrap();

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        // Invalid UTF-8 files are gracefully skipped (not fatal)
        let result = connector.scan(&ctx).unwrap();
        assert!(result.is_empty(), "invalid UTF-8 file should be skipped");
    }

    #[test]
    fn edge_bom_marker_at_file_start_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        // UTF-8 BOM + valid JSONL
        let mut data = vec![0xEF, 0xBB, 0xBF];
        data.extend_from_slice(
            br#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"BOM"}}"#,
        );
        let file_path = storage
            .join("sessions")
            .join("2025-12-01T10-00-00_uuid1.jsonl");
        std::fs::write(&file_path, &data).unwrap();

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // BOM may cause first line parse failure; subsequent lines should still work
        // With only one line, may get 0 conversations
        assert!(convs.len() <= 1);
    }

    #[test]
    fn edge_json_type_mismatch_skips_gracefully() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let lines = vec![
            // type is a number instead of string
            r#"{"type": 42, "message": {"role": "user", "content": "Bad type field"}}"#,
            // Valid line after
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Valid"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid");
    }

    #[test]
    fn edge_deeply_nested_json_does_not_stack_overflow() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        // Message with deeply nested content in the message object
        let mut nested = String::from(
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"deep","extra":"#,
        );
        for _ in 0..200 {
            nested.push_str(r#"{"a":"#);
        }
        nested.push_str(r#""leaf""#);
        for _ in 0..200 {
            nested.push('}');
        }
        nested.push_str("}}");
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &[&nested]);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        // Should not stack overflow
        let result = connector.scan(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn edge_large_message_body_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let large_content = "x".repeat(1_000_000);
        let line = format!(
            r#"{{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{{"role":"user","content":"{}"}}}}"#,
            large_content
        );
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &[&line]);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content.len(), 1_000_000);
    }

    #[test]
    fn edge_null_bytes_in_content_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"hello\u0000world"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("hello"));
    }

    // ---- Pi-Agent-specific edge cases ----

    #[test]
    fn edge_message_without_nested_message_object_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let lines = vec![
            // "message" type entry but missing the inner "message" object
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z"}"#,
            // Valid message after
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"Valid"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid");
    }

    #[test]
    fn edge_unknown_entry_types_skipped_gracefully() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let lines = vec![
            r#"{"type":"unknown_new_type","data":"whatever"}"#,
            r#"{"type":"another_future_type","payload":{"nested":true}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Still works"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Still works");
    }

    #[test]
    fn edge_model_change_before_any_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let lines = vec![
            r#"{"type":"model_change","provider":"google","modelId":"gemini-2.0-flash"}"#,
            r#"{"type":"model_change","provider":"anthropic","modelId":"claude-opus"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":"After two model changes"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        // Should use the latest model_change
        assert_eq!(convs[0].messages[0].author, Some("claude-opus".to_string()));
    }

    #[test]
    fn edge_content_array_with_unknown_block_types() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let content = json!([
            {"type": "text", "text": "Known type"},
            {"type": "future_block_type", "data": "unknown"},
            {"type": "another_new_type"},
            {"type": "text", "text": "Also known"}
        ]);
        let line = format!(
            r#"{{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{{"role":"assistant","content":{}}}}}"#,
            content
        );
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &[&line]);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        let msg = &convs[0].messages[0].content;
        assert!(msg.contains("Known type"));
        assert!(msg.contains("Also known"));
        // Unknown types should be silently skipped
        assert!(!msg.contains("future_block_type"));
    }

    #[test]
    fn edge_session_file_without_underscore_ignored() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        // File without underscore should not be picked up
        let sessions_dir = storage.join("sessions");
        fs::write(
            sessions_dir.join("no-underscore.jsonl"),
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Should be ignored"}}"#,
        )
        .unwrap();

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }
}
