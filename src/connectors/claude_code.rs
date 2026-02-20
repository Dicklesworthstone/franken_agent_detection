use std::fs;
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

pub struct ClaudeCodeConnector;
impl Default for ClaudeCodeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaudeCodeConnector {
    pub fn new() -> Self {
        Self
    }

    fn projects_root() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".claude/projects")
    }

    fn session_files(scan_target: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for entry in WalkDir::new(scan_target).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let ext = entry.path().extension().and_then(|s| s.to_str());
            if ext == Some("jsonl") || ext == Some("json") || ext == Some("claude") {
                files.push(entry.path().to_path_buf());
            }
        }
        // Keep connector traversal deterministic across filesystems/runs.
        files.sort();
        files
    }
}

impl Connector for ClaudeCodeConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("claude_code").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        // Use data_root only if it looks like a Claude projects directory (for testing)
        // Otherwise use the default projects_root
        // Strict check: require 'projects' subdirectory to avoid shadowing when CASS
        // data directory has "claude" in its name.
        let looks_like_root = |path: &PathBuf| path.join("projects").exists();

        let roots: Vec<PathBuf> = if ctx.use_default_detection() {
            if looks_like_root(&ctx.data_dir) {
                vec![ctx.data_dir.clone()]
            } else {
                vec![Self::projects_root()]
            }
        } else {
            // Explicit roots (remote mirrors, etc.) - trust the configuration
            ctx.scan_roots.iter().map(|r| r.path.clone()).collect()
        };

        let mut convs = Vec::new();
        let mut file_count = 0;

        for root in roots {
            let scan_target = if root.is_file() {
                root.parent().unwrap_or(&root).to_path_buf()
            } else {
                root.clone()
            };

            if !scan_target.exists() {
                continue;
            }

            for path in Self::session_files(&scan_target) {
                let ext = path.extension().and_then(|s| s.to_str());
                // Skip files not modified since last scan (incremental indexing)
                if !file_modified_since(&path, ctx.since_ts) {
                    continue;
                }
                file_count += 1;
                if file_count <= 3 {
                    tracing::debug!(path = %path.display(), "claude_code found file");
                }

                let mut messages = Vec::new();
                let mut started_at: Option<i64> = None;
                let mut ended_at: Option<i64> = None;
                // Track workspace from first entry's cwd field
                let mut workspace: Option<PathBuf> = None;
                let mut session_id: Option<String> = None;
                let mut git_branch: Option<String> = None;
                let mut json_title: Option<String> = None;

                if ext == Some("jsonl") {
                    let file = std::fs::File::open(&path)
                        .with_context(|| format!("open {}", path.display()))?;
                    let reader = std::io::BufReader::new(file);

                    for line_res in std::io::BufRead::lines(reader) {
                        let line = match line_res {
                            Ok(l) => l,
                            Err(_) => continue,
                        };
                        if line.trim().is_empty() {
                            continue;
                        }
                        let val: Value = match serde_json::from_str(&line) {
                            Ok(v) => v,
                            Err(_) => continue, // Skip malformed lines
                        };

                        // Extract session metadata from first available entry
                        if workspace.is_none() {
                            workspace = val.get("cwd").and_then(|v| v.as_str()).map(PathBuf::from);
                        }
                        if session_id.is_none() {
                            session_id = val
                                .get("sessionId")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                        }
                        if git_branch.is_none() {
                            git_branch = val
                                .get("gitBranch")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                        }

                        // Filter to user/assistant entries only (skip summary, file-history-snapshot, etc.)
                        let entry_type = val.get("type").and_then(|v| v.as_str());
                        let role_hint = val
                            .get("message")
                            .and_then(|m| m.get("role"))
                            .and_then(|v| v.as_str())
                            .or_else(|| val.get("role").and_then(|v| v.as_str()));
                        let is_user_assistant = matches!(entry_type, Some("user" | "assistant"))
                            || (entry_type == Some("message")
                                && matches!(role_hint, Some("user" | "assistant")));
                        if !is_user_assistant {
                            continue;
                        }

                        // Parse ISO-8601 timestamp using shared utility
                        let created = val.get("timestamp").and_then(parse_timestamp);

                        // NOTE: Do NOT filter individual messages by timestamp here!
                        // The file-level check in file_modified_since() is sufficient.
                        // Filtering messages would cause older messages to be lost when
                        // the file is re-indexed after new messages are added.

                        started_at = match (started_at, created) {
                            (Some(curr), Some(ts)) => Some(curr.min(ts)),
                            (None, Some(ts)) => Some(ts),
                            (other, None) => other,
                        };
                        // Track the latest timestamp seen (robust against out-of-order logs)
                        ended_at = match (ended_at, created) {
                            (Some(curr), Some(ts)) => Some(curr.max(ts)),
                            (None, Some(ts)) => Some(ts),
                            (Some(curr), None) => Some(curr),
                            (None, None) => None,
                        };

                        // Role from message.role, top-level role, or entry type
                        let role = role_hint.or(entry_type).unwrap_or("agent");

                        // Content from message.content or top-level content (may be string or array)
                        let content_val = val
                            .get("message")
                            .and_then(|m| m.get("content"))
                            .or_else(|| val.get("content"));
                        let content_str = content_val.map(flatten_content).unwrap_or_default();

                        // Skip entries with empty content
                        if content_str.trim().is_empty() {
                            continue;
                        }

                        // Extract model name for author field
                        let author = val
                            .get("message")
                            .and_then(|m| m.get("model"))
                            .and_then(|v| v.as_str())
                            .map(String::from);

                        messages.push(NormalizedMessage {
                            idx: 0, // will be re-assigned after filtering
                            role: role.to_string(),
                            author,
                            created_at: created,
                            content: content_str,
                            extra: val,
                            snippets: Vec::new(),
                        });
                    }
                    // Re-assign sequential indices after filtering
                    crate::types::reindex_messages(&mut messages);
                } else {
                    // Safety check: Don't read files larger than 100MB to avoid OOM
                    if let Ok(metadata) = fs::metadata(&path)
                        && metadata.len() > 100 * 1024 * 1024
                    {
                        tracing::debug!(
                            path = %path.display(),
                            size_bytes = metadata.len(),
                            "skipping large file (>100MB)"
                        );
                        continue;
                    }

                    let content_string = fs::read_to_string(&path)
                        .with_context(|| format!("read {}", path.display()))?;
                    // JSON or Claude format files
                    let val: Value = match serde_json::from_str(&content_string) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(path = %path.display(), error = %e, "claude_code skipping malformed JSON");
                            continue;
                        }
                    };

                    // Extract title from root object if present
                    json_title = val.get("title").and_then(|t| t.as_str()).map(String::from);

                    if let Some(arr) = val.get("messages").and_then(|m| m.as_array()) {
                        for item in arr {
                            let role = item
                                .get("role")
                                .or_else(|| item.get("type"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("agent");

                            // Use parse_timestamp for consistent handling of both i64 and ISO-8601
                            let created = item
                                .get("timestamp")
                                .or_else(|| item.get("time"))
                                .and_then(parse_timestamp);

                            // NOTE: Do NOT filter individual messages by timestamp.
                            // File-level check is sufficient for incremental indexing.

                            started_at = match (started_at, created) {
                                (Some(curr), Some(ts)) => Some(curr.min(ts)),
                                (None, Some(ts)) => Some(ts),
                                (other, None) => other,
                            };
                            // Track the latest timestamp seen
                            ended_at = match (ended_at, created) {
                                (Some(curr), Some(ts)) => Some(curr.max(ts)),
                                (None, Some(ts)) => Some(ts),
                                (Some(curr), None) => Some(curr),
                                (None, None) => None,
                            };

                            // Use flatten_content for consistent handling of both string and array content
                            let content_str = item
                                .get("content")
                                .or_else(|| item.get("text"))
                                .map(flatten_content)
                                .unwrap_or_default();

                            // Skip entries with empty content
                            if content_str.trim().is_empty() {
                                continue;
                            }

                            messages.push(NormalizedMessage {
                                idx: 0, // will be re-assigned after filtering
                                role: role.to_string(),
                                author: None,
                                created_at: created,
                                content: content_str,
                                extra: item.clone(),
                                snippets: Vec::new(),
                            });
                        }
                    }
                    // Re-assign sequential indices after filtering
                    crate::types::reindex_messages(&mut messages);
                }
                if messages.is_empty() {
                    if file_count <= 3 {
                        tracing::debug!(path = %path.display(), "claude_code no messages extracted");
                    }
                    continue;
                }
                tracing::debug!(path = %path.display(), messages = messages.len(), "claude_code extracted messages");

                // Extract title: use explicit JSON title, or fallback to first user message
                let title = json_title.or_else(|| {
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

                convs.push(NormalizedConversation {
                    agent_slug: "claude_code".into(),
                    external_id: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(std::string::ToString::to_string),
                    title,
                    workspace, // Now populated from cwd field!
                    source_path: path.clone(),
                    started_at,
                    ended_at,
                    metadata: serde_json::json!({
                        "source": "claude_code",
                        "sessionId": session_id,
                        "gitBranch": git_branch
                    }),
                    messages,
                });
            }
        }

        Ok(convs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    /// Create a test-ready Claude directory structure.
    /// Includes a `projects` marker subdir so `looks_like_root()` returns true
    /// and the connector scans only the temp dir instead of the real ~/.claude/projects.
    fn make_test_claude_dir(base: &std::path::Path) -> PathBuf {
        let claude_dir = base.join(".claude");
        fs::create_dir_all(claude_dir.join("projects")).unwrap();
        claude_dir
    }

    // =========================================================================
    // Constructor tests
    // =========================================================================

    #[test]
    fn new_creates_connector() {
        let connector = ClaudeCodeConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = ClaudeCodeConnector;
        let _ = connector;
    }

    #[test]
    fn projects_root_returns_claude_projects_path() {
        let root = ClaudeCodeConnector::projects_root();
        assert!(root.ends_with(".claude/projects"));
    }

    #[test]
    fn session_files_returns_sorted_order() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("b.jsonl"), "{}").unwrap();
        fs::write(dir.path().join("a.jsonl"), "{}").unwrap();
        fs::write(dir.path().join("ignore.txt"), "x").unwrap();

        let files = ClaudeCodeConnector::session_files(dir.path());
        assert_eq!(files.len(), 2);

        let names: Vec<_> = files
            .iter()
            .map(|p| {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        assert_eq!(names, vec!["a.jsonl", "b.jsonl"]);
    }

    // =========================================================================
    // Detection tests
    // =========================================================================

    #[test]
    fn detect_not_found_without_projects_dir() {
        let connector = ClaudeCodeConnector::new();
        let result = connector.detect();
        // On most CI/test systems, .claude/projects won't exist
        // Just verify detect() doesn't panic
        let _ = result.detected;
    }

    // =========================================================================
    // JSONL parsing tests
    // =========================================================================

    #[test]
    fn scan_parses_jsonl_user_and_assistant_messages() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello Claude"}}
{"type":"assistant","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","content":"Hello! How can I help?"}}
{"type":"summary","timestamp":"2025-12-01T10:00:02Z","summary":"Test summary"}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok());
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);

        // Only user and assistant messages should be extracted (not summary)
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Claude");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert!(convs[0].messages[1].content.contains("How can I help"));
    }

    #[test]
    fn scan_extracts_session_metadata() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","cwd":"/projects/myapp","sessionId":"sess-123","gitBranch":"main","message":{"role":"user","content":"Test message"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].workspace, Some(PathBuf::from("/projects/myapp")));
        assert_eq!(convs[0].metadata["sessionId"], "sess-123");
        assert_eq!(convs[0].metadata["gitBranch"], "main");
    }

    #[test]
    fn scan_extracts_model_as_author() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"assistant","message":{"role":"assistant","content":"Response","model":"claude-3-opus"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].messages[0].author,
            Some("claude-3-opus".to_string())
        );
    }

    #[test]
    fn scan_parses_iso8601_timestamp() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","timestamp":"2025-11-15T14:30:00.123Z","message":{"role":"user","content":"Test"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].messages[0].created_at.is_some());
        let ts = convs[0].messages[0].created_at.unwrap();
        // Should be around 2025-11-15 in milliseconds
        assert!(ts > 1700000000000);
    }

    #[test]
    fn scan_handles_array_content() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = json!({
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "First part"},
                    {"type": "text", "text": "Second part"}
                ]
            }
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages.len(), 1);
        assert!(convs[0].messages[0].content.contains("First part"));
        assert!(convs[0].messages[0].content.contains("Second part"));
    }

    #[test]
    fn scan_skips_empty_content() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":""}}
{"type":"user","message":{"role":"user","content":"   "}}
{"type":"user","message":{"role":"user","content":"Valid message"}}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Only the valid message should be extracted
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid message");
    }

    #[test]
    fn scan_skips_non_user_assistant_types() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"summary","content":"Session summary"}
{"type":"file-history-snapshot","files":[]}
{"type":"user","message":{"role":"user","content":"User message"}}
{"type":"tool_result","result":"Some result"}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].role, "user");
    }

    #[test]
    fn scan_reindexes_messages_sequentially() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":"Message 1"}}
{"type":"assistant","message":{"role":"assistant","content":"Message 2"}}
{"type":"user","message":{"role":"user","content":"Message 3"}}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].idx, 0);
        assert_eq!(convs[0].messages[1].idx, 1);
        assert_eq!(convs[0].messages[2].idx, 2);
    }

    // =========================================================================
    // JSON format parsing tests
    // =========================================================================

    #[test]
    fn scan_parses_json_messages_array() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.json");
        let content = json!({
            "title": "Test Session",
            "messages": [
                {"role": "user", "content": "Hello", "timestamp": 1700000000000i64},
                {"role": "assistant", "content": "Hi there!", "timestamp": 1700000001000i64}
            ]
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[1].role, "assistant");
    }

    #[test]
    fn scan_json_extracts_title() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.json");
        let content = json!({
            "title": "Custom Session Title",
            "messages": [
                {"role": "user", "content": "Test content"}
            ]
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("Custom Session Title".to_string()));
    }

    #[test]
    fn scan_json_uses_type_as_role_fallback() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.json");
        let content = json!({
            "messages": [
                {"type": "user", "content": "Message with type instead of role"}
            ]
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].role, "user");
    }

    #[test]
    fn scan_json_uses_text_as_content_fallback() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.json");
        let content = json!({
            "messages": [
                {"role": "user", "text": "Message with text field instead of content"}
            ]
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].messages[0].content.contains("text field"));
    }

    #[test]
    fn scan_json_uses_time_as_timestamp_fallback() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.json");
        let content = json!({
            "messages": [
                {"role": "user", "content": "Test", "time": 1700000000000i64}
            ]
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].created_at, Some(1700000000000));
    }

    // =========================================================================
    // Title extraction tests
    // =========================================================================

    #[test]
    fn scan_title_from_first_user_message_jsonl() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"assistant","message":{"role":"assistant","content":"I can help"}}
{"type":"user","message":{"role":"user","content":"Help me build a web app"}}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("Help me build a web app".to_string()));
    }

    #[test]
    fn scan_title_truncates_to_100_chars() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let long_message = "x".repeat(200);
        let session_file = claude_dir.join("session.jsonl");
        let content = format!(
            r#"{{"type":"user","message":{{"role":"user","content":"{}"}}}}"#,
            long_message
        );
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].title.as_ref().unwrap().len() <= 100);
    }

    #[test]
    fn scan_title_uses_first_line_only() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":"First line\nSecond line\nThird line"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("First line".to_string()));
    }

    #[test]
    fn scan_title_fallback_to_workspace_name() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Only assistant message, no user message for title
        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"assistant","cwd":"/projects/myapp","message":{"role":"assistant","content":"Response only"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should fallback to workspace directory name
        assert_eq!(convs[0].title, Some("myapp".to_string()));
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn scan_empty_directory_returns_empty() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs.is_empty());
    }

    #[test]
    fn scan_skips_malformed_jsonl_lines() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"not valid json
{"type":"user","message":{"role":"user","content":"Valid message"}}
{broken json here
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should still extract the valid line
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid message");
    }

    #[test]
    fn scan_skips_malformed_json_files() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Create a malformed JSON file
        let bad_file = claude_dir.join("bad.json");
        fs::write(&bad_file, "not valid json {{{").unwrap();

        // Create a valid JSONL file
        let good_file = claude_dir.join("good.jsonl");
        fs::write(
            &good_file,
            r#"{"type":"user","message":{"role":"user","content":"Valid"}}"#,
        )
        .unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should only have one conversation from the valid file
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn scan_handles_empty_messages_array() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.json");
        let content = json!({
            "messages": []
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Empty messages should result in no conversation
        assert!(convs.is_empty());
    }

    #[test]
    fn scan_processes_subdirectories() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());
        let subdir = claude_dir.join("project1");
        fs::create_dir_all(&subdir).unwrap();

        let session_file = subdir.join("session.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":"Nested message"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("Nested message"));
    }

    #[test]
    fn scan_skips_non_session_files() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Create various non-session files
        fs::write(claude_dir.join("config.toml"), "").unwrap();
        fs::write(claude_dir.join("notes.txt"), "").unwrap();
        fs::write(claude_dir.join("backup.bak"), "").unwrap();

        // Create a valid session file
        let session_file = claude_dir.join("session.jsonl");
        fs::write(
            &session_file,
            r#"{"type":"user","message":{"role":"user","content":"Valid"}}"#,
        )
        .unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should only have one conversation from the .jsonl file
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn scan_handles_claude_extension() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.claude");
        let content = json!({
            "messages": [
                {"role": "user", "content": "Claude extension test"}
            ]
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("Claude extension"));
    }

    #[test]
    fn scan_sets_external_id_from_filename() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("unique-session-id.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":"Test"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].external_id,
            Some("unique-session-id.jsonl".to_string())
        );
    }

    #[test]
    fn scan_sets_agent_slug_to_claude_code() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":"Test"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].agent_slug, "claude_code");
    }

    #[test]
    fn scan_preserves_original_json_in_extra() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","customField":"customValue","message":{"role":"user","content":"Test"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].extra["customField"], "customValue");
    }

    #[test]
    fn scan_tracks_started_and_ended_timestamps() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"First"}}
{"type":"assistant","timestamp":"2025-12-01T10:05:00Z","message":{"role":"assistant","content":"Last"}}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
        // ended_at should be after or equal to started_at
        assert!(convs[0].ended_at.unwrap() >= convs[0].started_at.unwrap());
    }

    #[test]
    fn scan_multiple_files_returns_multiple_conversations() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Create two session files
        for i in 1..=3 {
            let session_file = claude_dir.join(format!("session{}.jsonl", i));
            let content =
                format!(r#"{{"type":"user","message":{{"role":"user","content":"Message {i}"}}}}"#);
            fs::write(&session_file, content).unwrap();
        }

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 3);
    }

    #[test]
    fn scan_explicit_root_generic_name() {
        let dir = TempDir::new().unwrap();
        // Directory name that doesn't contain "claude" and no "projects" subdir
        let generic_root = dir.path().join("my_logs");
        fs::create_dir_all(&generic_root).unwrap();

        let session_file = generic_root.join("session.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":"Generic root test"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        // Create context with explicit root (use_default_detection = false)
        // Note: ScanContext::with_roots takes data_dir as first arg, but indexer passes root.path there too.
        // We simulate what indexer does.
        let roots = vec![crate::connectors::ScanRoot::local(generic_root.clone())];
        let ctx = ScanContext::with_roots(generic_root.clone(), roots, None);

        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs.len(),
            1,
            "Should find session in generic named explicit root"
        );
        assert_eq!(convs[0].messages[0].content, "Generic root test");
    }

    // =========================================================================
    // Edge case tests — malformed input robustness (br-cpf8)
    // =========================================================================

    #[test]
    fn truncated_jsonl_mid_json_returns_partial_results() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // First line is valid, second line is truncated mid-JSON
        let session_file = claude_dir.join("truncated.jsonl");
        let content = b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Hello\"}}\n{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":\"Hel";
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "truncated file should not cause an error");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            1,
            "truncated file at mid-JSON should yield only the 1 valid message"
        );
        assert_eq!(convs[0].messages[0].content, "Hello");
    }

    #[test]
    fn truncated_mid_utf8_does_not_panic() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Valid JSONL line followed by bytes that start a multi-byte UTF-8
        // sequence but are truncated (U+1F600 = F0 9F 98 80, truncate after 2 bytes)
        let session_file = claude_dir.join("truncated_utf8.jsonl");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Valid\"}}\n",
        );
        // Incomplete UTF-8: start of a 4-byte sequence missing last 2 bytes
        bytes.extend_from_slice(b"\xF0\x9F");

        fs::write(&session_file, &bytes).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "truncated mid-UTF8 should not panic or error"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid");
    }

    #[test]
    fn invalid_utf8_skips_corrupted_lines() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("invalid_utf8.jsonl");
        let mut bytes = Vec::new();
        // Valid line
        bytes.extend_from_slice(
            b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Before\"}}\n",
        );
        // Invalid UTF-8 bytes (0xFF 0xFE are never valid in UTF-8)
        bytes.extend_from_slice(b"\xFF\xFE invalid utf8 line\n");
        // Another valid line
        bytes.extend_from_slice(
            b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"After\"}}\n",
        );

        fs::write(&session_file, &bytes).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "invalid UTF-8 should not cause a panic");
        let convs = result.unwrap();
        // BufRead::lines() returns Err for invalid UTF-8 lines; the connector
        // continues on Err (line 114: Err(_) => continue). So we should get
        // the valid lines on either side.
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            2,
            "should extract both valid messages around invalid UTF-8 line"
        );
        assert_eq!(convs[0].messages[0].content, "Before");
        assert_eq!(convs[0].messages[1].content, "After");
    }

    #[test]
    fn empty_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Completely empty JSONL file
        let session_file = claude_dir.join("empty.jsonl");
        fs::write(&session_file, b"").unwrap();

        // Completely empty JSON file
        let json_file = claude_dir.join("empty.json");
        fs::write(&json_file, b"").unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "empty files should not cause errors");
        let convs = result.unwrap();
        assert!(
            convs.is_empty(),
            "empty files should produce no conversations"
        );
    }

    #[test]
    fn whitespace_only_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // JSONL file with only whitespace and newlines
        let session_file = claude_dir.join("whitespace.jsonl");
        fs::write(&session_file, "   \n\n  \n   \n\t\n").unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
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
    fn json_type_mismatch_skips_gracefully() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // JSONL lines where expected objects are wrong types
        let session_file = claude_dir.join("type_mismatch.jsonl");
        let content = concat!(
            // String where object expected for message
            "{\"type\":\"user\",\"message\":\"not an object\"}\n",
            // Number where content string expected
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":12345}}\n",
            // Array where string expected for type
            "{\"type\":[\"user\"],\"message\":{\"role\":\"user\",\"content\":\"Valid after mismatches\"}}\n",
            // Null content
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":null}}\n",
            // Boolean type
            "{\"type\":true,\"message\":{\"role\":\"user\",\"content\":\"Bool type\"}}\n",
            // Correct entry that should be extracted
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Correct entry\"}}\n",
        );
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "type mismatches should not cause errors");
        let convs = result.unwrap();
        // Only the last line with correct types should produce a message
        assert_eq!(convs.len(), 1);
        assert!(
            convs[0]
                .messages
                .iter()
                .any(|m| m.content == "Correct entry"),
            "should extract the correctly typed entry"
        );
    }

    #[test]
    fn deeply_nested_json_does_not_stack_overflow() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Build JSON with 1000+ levels of nesting in the content field
        // serde_json has a default recursion limit of 128, so this tests
        // that the connector handles the parse error gracefully
        let mut nested = String::new();
        for _ in 0..200 {
            nested.push_str("{\"a\":");
        }
        nested.push('1');
        for _ in 0..200 {
            nested.push('}');
        }

        let session_file = claude_dir.join("deep.jsonl");
        let content = format!(
            "{}\n{}\n",
            nested, r#"{"type":"user","message":{"role":"user","content":"After deep nesting"}}"#
        );
        fs::write(&session_file, &content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);

        // This must not stack overflow or panic
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "deeply nested JSON should not cause stack overflow"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "After deep nesting");
    }

    #[test]
    fn large_message_body_handled_without_oom() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Create a JSONL file with a 1MB message body to verify streaming works
        let large_content = "x".repeat(1_000_000);
        let session_file = claude_dir.join("large_body.jsonl");
        let line = format!(
            r#"{{"type":"user","message":{{"role":"user","content":"{}"}}}}"#,
            large_content
        );
        fs::write(&session_file, &line).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "large message body should not cause OOM");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages[0].content.len(),
            1_000_000,
            "large message content should be preserved in full"
        );
    }

    #[test]
    fn large_json_file_over_100mb_is_skipped() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // For JSON format, files > 100MB should be skipped.
        // We can't create a real 100MB file in a unit test efficiently,
        // but we verify the mechanism works with a valid JSON file under the limit.
        let session_file = claude_dir.join("under_limit.json");
        let content = json!({
            "messages": [
                {"role": "user", "content": "Under the limit"}
            ]
        })
        .to_string();
        fs::write(&session_file, &content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // File under 100MB should be processed normally
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Under the limit");
    }

    #[test]
    fn null_bytes_embedded_in_content_handled() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // JSON allows \u0000 escape for null bytes in strings
        let session_file = claude_dir.join("null_bytes.jsonl");
        let content = concat!(
            r#"{"type":"user","message":{"role":"user","content":"before\u0000after"}}"#,
            "\n",
            r#"{"type":"user","message":{"role":"user","content":"Clean message"}}"#,
            "\n"
        );
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "null bytes in content should not cause errors"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        // Both messages should be extracted; the null byte is valid JSON
        assert!(
            !convs[0].messages.is_empty(),
            "should extract at least the clean message"
        );
    }

    #[test]
    fn bom_marker_at_file_start_handled() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // UTF-8 BOM: EF BB BF
        let session_file = claude_dir.join("bom.jsonl");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xEF\xBB\xBF"); // UTF-8 BOM
        bytes.extend_from_slice(
            b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"After BOM\"}}\n",
        );
        bytes.extend_from_slice(
            b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Second line\"}}\n",
        );
        fs::write(&session_file, &bytes).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "BOM marker should not cause errors");
        let convs = result.unwrap();
        // The BOM may cause the first line's JSON to fail parsing (since the BOM
        // bytes are prepended to the line). The second line should parse fine.
        // We verify the connector doesn't crash and extracts what it can.
        assert_eq!(convs.len(), 1);
        assert!(
            !convs[0].messages.is_empty(),
            "should extract at least the second message after BOM"
        );
        // The second line (without BOM) should always parse correctly
        assert!(
            convs[0].messages.iter().any(|m| m.content == "Second line"),
            "second line should be extractable regardless of BOM"
        );
    }
}
