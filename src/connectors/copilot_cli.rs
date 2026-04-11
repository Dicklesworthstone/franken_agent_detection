//! Connector for GitHub Copilot CLI (`gh copilot`) event logs.
//!
//! The `gh copilot` extension and standalone Copilot CLI binary store session
//! history as JSONL event logs in several platform-specific locations:
//!
//! - `~/.copilot/session-state/{session-id}/events.jsonl`  (v2, since 0.0.342)
//! - `~/.copilot/history-session-state/{session-id}.json`  (v1, legacy)
//! - `~/.copilot/command-history-state.json`
//! - `~/.config/gh-copilot/`
//! - `~/.config/gh/copilot/`
//! - `~/.local/share/github-copilot/`
//!
//! Each line in `events.jsonl` is a JSON object with a `type` field identifying
//! the event kind. Conversation events use `user.message` and `assistant.message`
//! types with `content`, `role`, and `timestamp` fields.
//!
//! This connector is separate from `CopilotConnector` (which handles VS Code
//! Copilot Chat JSON files) so that CLI-specific event logs are discovered and
//! indexed independently.

use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::ScanContext;
use super::{Connector, file_modified_since, flatten_content, parse_timestamp};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct CopilotCliConnector;

impl Default for CopilotCliConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl CopilotCliConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Candidate paths where `gh copilot` CLI stores session data.
    fn cli_candidate_paths() -> Vec<PathBuf> {
        let Some(home) = dirs::home_dir() else {
            return Vec::new();
        };
        vec![
            // Copilot CLI v2 session storage (since 0.0.342)
            home.join(".copilot/session-state"),
            // Copilot CLI v1 legacy session storage
            home.join(".copilot/history-session-state"),
            // gh copilot extension config/history
            home.join(".config/gh-copilot"),
            home.join(".config/gh/copilot"),
            // XDG data directory (Linux)
            home.join(".local/share/github-copilot"),
        ]
    }

    /// Check whether a path looks like Copilot CLI storage.
    fn looks_like_cli_storage(path: &Path) -> bool {
        let segments: Vec<String> = path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect();

        // ~/.copilot/session-state or ~/.copilot/history-session-state
        if segments.windows(2).any(|pair| {
            pair[0] == ".copilot"
                && (pair[1] == "session-state" || pair[1] == "history-session-state")
        }) {
            return true;
        }

        // ~/.config/gh-copilot
        if segments.iter().any(|s| s == "gh-copilot") {
            return true;
        }

        // ~/.config/gh/copilot
        if segments
            .windows(2)
            .any(|pair| pair[0] == "gh" && pair[1] == "copilot")
        {
            return true;
        }

        // ~/.local/share/github-copilot
        if segments.iter().any(|s| s == "github-copilot") {
            return true;
        }

        false
    }

    fn append_explicit_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        if base.exists() && Self::looks_like_cli_storage(base) {
            roots.push(base.to_path_buf());
        }

        if base.file_name().is_some_and(|n| n == ".copilot") {
            let session_state = base.join("session-state");
            if session_state.exists() {
                roots.push(session_state);
            }
            let history_state = base.join("history-session-state");
            if history_state.exists() {
                roots.push(history_state);
            }
        }

        if base.file_name().is_some_and(|n| n == ".config") {
            let gh_copilot = base.join("gh-copilot");
            if gh_copilot.exists() {
                roots.push(gh_copilot);
            }
            let gh_copilot_nested = base.join("gh").join("copilot");
            if gh_copilot_nested.exists() {
                roots.push(gh_copilot_nested);
            }
        }

        if base.file_name().is_some_and(|n| n == "gh") {
            let gh_copilot = base.join("copilot");
            if gh_copilot.exists() {
                roots.push(gh_copilot);
            }
        }

        if base.file_name().is_some_and(|n| n == ".local") {
            let github_copilot = base.join("share").join("github-copilot");
            if github_copilot.exists() {
                roots.push(github_copilot);
            }
        }

        if base.file_name().is_some_and(|n| n == "share")
            && base
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".local"))
        {
            let github_copilot = base.join("github-copilot");
            if github_copilot.exists() {
                roots.push(github_copilot);
            }
        }
    }

    /// Find JSON and JSONL files that may contain CLI session data.
    fn find_event_files(root: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        if !root.exists() {
            return files;
        }

        if root.is_file() {
            if root
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "json" || e == "jsonl")
            {
                files.push(root.to_path_buf());
            }
            return files;
        }

        for entry in WalkDir::new(root)
            .max_depth(4)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_file())
        {
            let name = entry.file_name().to_string_lossy();
            if name.ends_with(".json") || name.ends_with(".jsonl") {
                files.push(entry.path().to_path_buf());
            }
        }

        // Keep traversal deterministic.
        files.sort();
        files
    }

    /// Parse a JSONL event log file into conversations.
    ///
    /// Each line is a JSON event. We extract events with message-like types
    /// (`user.message`, `assistant.message`, or events with `role`+`content`
    /// fields) and assemble them into a single conversation per session file.
    fn parse_event_log(&self, path: &Path) -> Result<Vec<NormalizedConversation>> {
        let content = fs::read_to_string(path)?;

        // If it looks like a single JSON document, try the legacy session format.
        let trimmed = content.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(val) = serde_json::from_str::<Value>(&content) {
                return self.parse_session_json(&val, path);
            }
        }

        // JSONL: each line is a separate JSON event.
        let reader = std::io::BufReader::new(content.as_bytes());
        let mut messages = Vec::new();
        let mut started_at: Option<i64> = None;
        let mut ended_at: Option<i64> = None;
        let mut session_id: Option<String> = None;
        let mut workspace: Option<PathBuf> = None;

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if session_id.is_none() {
                session_id = event
                    .get("session_id")
                    .or_else(|| event.get("sessionId"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
            }

            if workspace.is_none() {
                workspace = event
                    .get("cwd")
                    .or_else(|| event.get("workingDirectory"))
                    .or_else(|| event.get("workspace"))
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from);
            }

            let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let ts = Self::extract_timestamp(&event);

            started_at = match (started_at, ts) {
                (Some(curr), Some(t)) => Some(curr.min(t)),
                (None, Some(t)) => Some(t),
                (other, None) => other,
            };
            ended_at = match (ended_at, ts) {
                (Some(curr), Some(t)) => Some(curr.max(t)),
                (None, Some(t)) => Some(t),
                (other, None) => other,
            };

            let (role, content) = Self::extract_event_message(&event, event_type);
            if role.is_empty() || content.trim().is_empty() {
                continue;
            }

            messages.push(NormalizedMessage {
                idx: i64::try_from(messages.len()).unwrap_or(i64::MAX),
                role: role.clone(),
                author: Some(if role == "user" {
                    "user".to_string()
                } else {
                    "copilot-cli".to_string()
                }),
                created_at: ts,
                content,
                extra: event,
                invocations: Vec::new(),
                snippets: Vec::new(),
            });
        }

        if messages.is_empty() {
            return Ok(Vec::new());
        }

        // Fall back to parent directory name as session ID.
        if session_id.is_none() {
            session_id = path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .map(String::from);
        }

        if started_at.is_none() {
            started_at = ended_at;
        }
        if ended_at.is_none() {
            ended_at = started_at;
        }

        let title = messages.iter().find(|m| m.role == "user").map(|m| {
            m.content
                .lines()
                .next()
                .unwrap_or(&m.content)
                .chars()
                .take(120)
                .collect::<String>()
        });

        let metadata = serde_json::json!({
            "source": "copilot-cli",
        });

        Ok(vec![NormalizedConversation {
            agent_slug: "copilot_cli".to_string(),
            external_id: session_id,
            title,
            workspace,
            source_path: path.to_path_buf(),
            started_at,
            ended_at,
            metadata,
            messages,
        }])
    }

    /// Parse a legacy CLI session-state JSON file (single JSON document).
    fn parse_session_json(&self, val: &Value, path: &Path) -> Result<Vec<NormalizedConversation>> {
        // Try extracting messages from "events" or "history" arrays.
        let events = val
            .get("events")
            .and_then(|v| v.as_array())
            .or_else(|| val.get("history").and_then(|v| v.as_array()));

        // Try "messages" array as well (chat-style session state).
        let events = events.or_else(|| val.get("messages").and_then(|v| v.as_array()));

        // Also check for "conversation" array wrapper.
        let events = events.or_else(|| val.get("conversation").and_then(|v| v.as_array()));

        let events = match events {
            Some(e) => e,
            None => {
                // If there's a top-level array, try each element.
                if let Some(arr) = val.as_array() {
                    return self.parse_session_array(arr, path);
                }
                return Ok(Vec::new());
            }
        };

        let mut messages = Vec::new();
        let mut started_at: Option<i64> = None;
        let mut ended_at: Option<i64> = None;

        for event in events {
            let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let ts = Self::extract_timestamp(event);

            started_at = match (started_at, ts) {
                (Some(curr), Some(t)) => Some(curr.min(t)),
                (None, Some(t)) => Some(t),
                (other, None) => other,
            };
            ended_at = match (ended_at, ts) {
                (Some(curr), Some(t)) => Some(curr.max(t)),
                (None, Some(t)) => Some(t),
                (other, None) => other,
            };

            let (role, content) = Self::extract_event_message(event, event_type);
            if role.is_empty() || content.trim().is_empty() {
                continue;
            }

            messages.push(NormalizedMessage {
                idx: i64::try_from(messages.len()).unwrap_or(i64::MAX),
                role: role.clone(),
                author: Some(if role == "user" {
                    "user".to_string()
                } else {
                    "copilot-cli".to_string()
                }),
                created_at: ts,
                content,
                extra: event.clone(),
                invocations: Vec::new(),
                snippets: Vec::new(),
            });
        }

        if messages.is_empty() {
            return Ok(Vec::new());
        }

        let session_id = val
            .get("session_id")
            .or_else(|| val.get("sessionId"))
            .or_else(|| val.get("id"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| path.file_stem().and_then(|n| n.to_str()).map(String::from));

        let workspace = val
            .get("cwd")
            .or_else(|| val.get("workingDirectory"))
            .or_else(|| val.get("workspace"))
            .and_then(|v| v.as_str())
            .map(PathBuf::from);

        if started_at.is_none() {
            started_at = ended_at;
        }
        if ended_at.is_none() {
            ended_at = started_at;
        }

        let title = messages.iter().find(|m| m.role == "user").map(|m| {
            m.content
                .lines()
                .next()
                .unwrap_or(&m.content)
                .chars()
                .take(120)
                .collect::<String>()
        });

        let metadata = serde_json::json!({
            "source": "copilot-cli",
        });

        Ok(vec![NormalizedConversation {
            agent_slug: "copilot_cli".to_string(),
            external_id: session_id,
            title,
            workspace,
            source_path: path.to_path_buf(),
            started_at,
            ended_at,
            metadata,
            messages,
        }])
    }

    /// Parse a top-level JSON array where each element may be a conversation.
    fn parse_session_array(
        &self,
        arr: &[Value],
        path: &Path,
    ) -> Result<Vec<NormalizedConversation>> {
        let mut conversations = Vec::new();
        for (i, element) in arr.iter().enumerate() {
            if let Ok(mut convs) = self.parse_session_json(element, path) {
                // Assign external_id from array index if not set.
                for conv in &mut convs {
                    if conv.external_id.is_none() {
                        conv.external_id = Some(format!(
                            "{}-{i}",
                            path.file_stem()
                                .and_then(|n| n.to_str())
                                .unwrap_or("session")
                        ));
                    }
                }
                conversations.extend(convs);
            }
        }
        Ok(conversations)
    }

    /// Extract role and content from a CLI event log entry.
    fn extract_event_message(event: &Value, event_type: &str) -> (String, String) {
        let type_lower = event_type.to_lowercase();

        let role_from_type = if type_lower.contains("user")
            || type_lower == "userpromptsubmitted"
            || type_lower == "prompt"
        {
            Some("user".to_string())
        } else if type_lower.contains("assistant")
            || type_lower == "assistantresponse"
            || type_lower == "response"
            || type_lower == "completion"
        {
            Some("assistant".to_string())
        } else {
            None
        };

        // Explicit role field takes precedence.
        let role = event
            .get("role")
            .and_then(|v| v.as_str())
            .map(|r| {
                if r == "user" || r == "human" {
                    "user".to_string()
                } else {
                    "assistant".to_string()
                }
            })
            .or(role_from_type);

        let role = match role {
            Some(r) => r,
            None => return (String::new(), String::new()),
        };

        let content = Self::extract_content(event);

        // If standard extraction failed, try event-specific fields.
        if content.trim().is_empty() {
            if let Some(prompt) = event.get("prompt").or_else(|| event.get("initialPrompt")) {
                let text = flatten_content(prompt);
                if !text.is_empty() {
                    return (role, text);
                }
            }
            if let Some(output) = event.get("output").or_else(|| event.get("result")) {
                let text = flatten_content(output);
                if !text.is_empty() {
                    return (role, text);
                }
            }
        }

        (role, content)
    }

    /// Extract message content from various possible field names.
    fn extract_content(val: &Value) -> String {
        for key in ["message", "content", "text", "value"] {
            if let Some(field) = val.get(key) {
                let text = flatten_content(field);
                if !text.is_empty() {
                    return text;
                }
            }
        }
        String::new()
    }

    /// Extract timestamp from an event object.
    fn extract_timestamp(val: &Value) -> Option<i64> {
        for key in ["timestamp", "createdAt", "created_at", "time", "ts", "date"] {
            if let Some(ts) = val.get(key).and_then(parse_timestamp) {
                return Some(ts);
            }
        }
        None
    }
}

impl Connector for CopilotCliConnector {
    fn detect(&self) -> DetectionResult {
        // Probe CLI-specific paths.
        let paths = Self::cli_candidate_paths();
        let mut evidence = Vec::new();
        let mut root_paths = Vec::new();

        for path in &paths {
            if path.exists() {
                evidence.push(format!("copilot CLI root exists: {}", path.display()));
                root_paths.push(path.clone());
            } else {
                evidence.push(format!("copilot CLI root missing: {}", path.display()));
            }
        }

        // Also check for the `gh` CLI in common locations.
        let gh_paths = ["/usr/bin/gh", "/usr/local/bin/gh"];
        for gh_path in &gh_paths {
            if Path::new(gh_path).exists() {
                evidence.push(format!("gh CLI found at {gh_path}"));
                break;
            }
        }

        let detected = !root_paths.is_empty();
        if evidence.is_empty() {
            evidence.push("no copilot CLI probe roots available".to_string());
        }

        DetectionResult {
            detected,
            evidence,
            root_paths,
        }
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut roots: Vec<PathBuf> = Vec::new();

        if ctx.use_default_detection() {
            if Self::looks_like_cli_storage(&ctx.data_dir) && ctx.data_dir.exists() {
                roots.push(ctx.data_dir.clone());
            } else {
                for path in Self::cli_candidate_paths() {
                    if path.exists() {
                        roots.push(path);
                    }
                }
            }
        } else {
            for scan_root in &ctx.scan_roots {
                let candidates = [
                    scan_root.path.join(".copilot/session-state"),
                    scan_root.path.join(".copilot/history-session-state"),
                    scan_root.path.join(".config/gh-copilot"),
                    scan_root.path.join(".config/gh/copilot"),
                    scan_root.path.join(".local/share/github-copilot"),
                ];

                for candidate in &candidates {
                    if candidate.exists() {
                        roots.push(candidate.clone());
                    }
                }

                Self::append_explicit_roots(&mut roots, &scan_root.path);
            }
        }

        if roots.is_empty() {
            return Ok(Vec::new());
        }

        let mut all_conversations = Vec::new();

        for root in roots {
            let files = Self::find_event_files(&root);
            tracing::debug!(
                root = %root.display(),
                file_count = files.len(),
                "copilot_cli: scanning event files"
            );

            for file in files {
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }

                match self.parse_event_log(&file) {
                    Ok(convs) => {
                        tracing::debug!(
                            file = %file.display(),
                            conversations = convs.len(),
                            "copilot_cli: parsed event file"
                        );
                        all_conversations.extend(convs);
                    }
                    Err(e) => {
                        tracing::debug!(
                            file = %file.display(),
                            error = %e,
                            "copilot_cli: skipping unparseable file"
                        );
                    }
                }
            }
        }

        Ok(all_conversations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(dir: &Path, filename: &str, content: &str) -> PathBuf {
        let path = dir.join(filename);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn detect_returns_result_without_panic() {
        let connector = CopilotCliConnector::new();
        let result = connector.detect();
        assert!(!result.evidence.is_empty());
    }

    #[test]
    fn scan_empty_dir_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join(".copilot/session-state");
        fs::create_dir_all(&root).unwrap();

        let connector = CopilotCliConnector::new();
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn scan_parses_jsonl_events() {
        let tmp = TempDir::new().unwrap();
        let session_dir = tmp.path().join(".copilot/session-state/abc-123");
        fs::create_dir_all(&session_dir).unwrap();

        let events = r#"{"type":"sessionStart","session_id":"abc-123","timestamp":1700000000000,"cwd":"/home/user/myproject"}
{"type":"user.message","role":"user","content":"How do I read a file in Rust?","timestamp":1700000001000}
{"type":"assistant.message","role":"assistant","content":"You can use std::fs::read_to_string().","timestamp":1700000002000}
{"type":"user.message","role":"user","content":"Show me an example","timestamp":1700000003000}
{"type":"assistant.message","role":"assistant","content":"let contents = std::fs::read_to_string(\"file.txt\")?;","timestamp":1700000004000}
"#;

        write_file(&session_dir, "events.jsonl", events);

        let connector = CopilotCliConnector::new();
        let root = tmp.path().join(".copilot/session-state");
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "copilot_cli");
        assert_eq!(convs[0].external_id.as_deref(), Some("abc-123"));
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/myproject"))
        );
        assert_eq!(convs[0].messages.len(), 4);
        assert_eq!(convs[0].messages[0].role, "user");
        assert!(convs[0].messages[0].content.contains("read a file"));
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert_eq!(convs[0].started_at, Some(1_700_000_000_000));
        assert_eq!(convs[0].ended_at, Some(1_700_000_004_000));
        assert!(convs[0].title.as_ref().unwrap().contains("read a file"));
        assert_eq!(convs[0].metadata["source"], "copilot-cli");
    }

    #[test]
    fn scan_parses_hook_event_types() {
        let tmp = TempDir::new().unwrap();
        let session_dir = tmp.path().join(".copilot/session-state/def-456");
        fs::create_dir_all(&session_dir).unwrap();

        let events = r#"{"type":"userPromptSubmitted","content":"Explain ownership","timestamp":1700000010000}
{"type":"assistantResponse","content":"Ownership is Rust's memory management model.","timestamp":1700000011000}
"#;

        write_file(&session_dir, "events.jsonl", events);

        let connector = CopilotCliConnector::new();
        let root = tmp.path().join(".copilot/session-state");
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert!(convs[0].messages[0].content.contains("ownership"));
        assert_eq!(convs[0].messages[1].role, "assistant");
    }

    #[test]
    fn scan_parses_legacy_session_json() {
        let tmp = TempDir::new().unwrap();
        let legacy_dir = tmp.path().join(".copilot/history-session-state");
        fs::create_dir_all(&legacy_dir).unwrap();

        let session_json = r#"{
            "session_id": "legacy-001",
            "cwd": "/home/user/legacy-project",
            "events": [
                {"type": "user.message", "content": "What is a trait?", "timestamp": 1700000020000},
                {"type": "assistant.message", "content": "A trait defines shared behavior.", "timestamp": 1700000021000}
            ]
        }"#;

        write_file(&legacy_dir, "legacy-001.json", session_json);

        let connector = CopilotCliConnector::new();
        let root = tmp.path().join(".copilot/history-session-state");
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("legacy-001"));
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/legacy-project"))
        );
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert!(convs[0].messages[0].content.contains("trait"));
    }

    #[test]
    fn scan_parses_prompt_field() {
        let tmp = TempDir::new().unwrap();
        let session_dir = tmp.path().join(".copilot/session-state/ghi-789");
        fs::create_dir_all(&session_dir).unwrap();

        let events = r#"{"type":"user.message","prompt":"Deploy to production","timestamp":1700000030000}
{"type":"assistant.message","output":"Running deployment script...","timestamp":1700000031000}
"#;

        write_file(&session_dir, "events.jsonl", events);

        let connector = CopilotCliConnector::new();
        let root = tmp.path().join(".copilot/session-state");
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert!(convs[0].messages[0].content.contains("Deploy"));
        assert!(convs[0].messages[1].content.contains("deployment"));
    }

    #[test]
    fn scan_skips_non_message_events() {
        let tmp = TempDir::new().unwrap();
        let session_dir = tmp.path().join(".copilot/session-state/skip-test");
        fs::create_dir_all(&session_dir).unwrap();

        let events = r#"{"type":"sessionStart","timestamp":1700000040000}
{"type":"preToolUse","toolName":"shell","timestamp":1700000041000}
{"type":"user.message","content":"Hello","timestamp":1700000042000}
{"type":"postToolUse","toolName":"shell","timestamp":1700000043000}
{"type":"assistant.message","content":"Hi there!","timestamp":1700000044000}
{"type":"errorOccurred","error":"some error","timestamp":1700000045000}
"#;

        write_file(&session_dir, "events.jsonl", events);

        let connector = CopilotCliConnector::new();
        let root = tmp.path().join(".copilot/session-state");
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].content, "Hello");
        assert_eq!(convs[0].messages[1].content, "Hi there!");
    }

    #[test]
    fn scan_empty_events_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let session_dir = tmp.path().join(".copilot/session-state/empty");
        fs::create_dir_all(&session_dir).unwrap();

        let events = r#"{"type":"sessionStart","timestamp":1700000050000}
{"type":"sessionEnd","timestamp":1700000051000}
"#;

        write_file(&session_dir, "events.jsonl", events);

        let connector = CopilotCliConnector::new();
        let root = tmp.path().join(".copilot/session-state");
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn scan_multiple_sessions() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join(".copilot/session-state");

        let session_a = root.join("session-a");
        let session_b = root.join("session-b");
        fs::create_dir_all(&session_a).unwrap();
        fs::create_dir_all(&session_b).unwrap();

        write_file(
            &session_a,
            "events.jsonl",
            r#"{"type":"user.message","content":"Question A","timestamp":1700000070000}
{"type":"assistant.message","content":"Answer A","timestamp":1700000071000}
"#,
        );

        write_file(
            &session_b,
            "events.jsonl",
            r#"{"type":"user.message","content":"Question B","timestamp":1700000080000}
{"type":"assistant.message","content":"Answer B","timestamp":1700000081000}
"#,
        );

        let connector = CopilotCliConnector::new();
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
        let ids: Vec<_> = convs
            .iter()
            .filter_map(|c| c.external_id.as_deref())
            .collect();
        assert!(ids.contains(&"session-a"));
        assert!(ids.contains(&"session-b"));
    }

    #[test]
    fn scan_handles_malformed_lines() {
        let tmp = TempDir::new().unwrap();
        let session_dir = tmp.path().join(".copilot/session-state/malformed");
        fs::create_dir_all(&session_dir).unwrap();

        let events = r#"not valid json
{"type":"user.message","content":"valid msg","timestamp":1700000090000}
{incomplete json...
{"type":"assistant.message","content":"also valid","timestamp":1700000091000}

"#;

        write_file(&session_dir, "events.jsonl", events);

        let connector = CopilotCliConnector::new();
        let root = tmp.path().join(".copilot/session-state");
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].content, "valid msg");
        assert_eq!(convs[0].messages[1].content, "also valid");
    }

    #[test]
    fn scan_with_scan_roots() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("fakehome");
        let session_dir = home.join(".copilot/session-state/remote-sess");
        fs::create_dir_all(&session_dir).unwrap();

        let events = r#"{"type":"user.message","content":"from remote","timestamp":1700000060000}
{"type":"assistant.message","content":"acknowledged","timestamp":1700000061000}
"#;

        write_file(&session_dir, "events.jsonl", events);

        let connector = CopilotCliConnector::new();
        let scan_root = crate::connectors::ScanRoot::local(home);
        let ctx = ScanContext::with_roots(tmp.path().to_path_buf(), vec![scan_root], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn scan_with_copilot_root_scan_root() {
        let tmp = TempDir::new().unwrap();
        let copilot_root = tmp.path().join(".copilot");
        let session_dir = copilot_root.join("session-state/root-sess");
        fs::create_dir_all(&session_dir).unwrap();

        let events = r#"{"type":"user.message","content":"root msg","timestamp":1700000060000}
{"type":"assistant.message","content":"root ack","timestamp":1700000061000}
"#;

        write_file(&session_dir, "events.jsonl", events);

        let connector = CopilotCliConnector::new();
        let scan_root = crate::connectors::ScanRoot::local(copilot_root);
        let ctx = ScanContext::with_roots(tmp.path().to_path_buf(), vec![scan_root], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn looks_like_cli_storage_works() {
        assert!(CopilotCliConnector::looks_like_cli_storage(Path::new(
            "/home/user/.copilot/session-state"
        )));
        assert!(CopilotCliConnector::looks_like_cli_storage(Path::new(
            "/home/user/.copilot/history-session-state"
        )));
        assert!(CopilotCliConnector::looks_like_cli_storage(Path::new(
            "/home/user/.config/gh-copilot"
        )));
        assert!(CopilotCliConnector::looks_like_cli_storage(Path::new(
            "/home/user/.config/gh/copilot"
        )));
        assert!(CopilotCliConnector::looks_like_cli_storage(Path::new(
            "/home/user/.local/share/github-copilot"
        )));
        assert!(!CopilotCliConnector::looks_like_cli_storage(Path::new(
            "/home/user/.config/Code/User/globalStorage/github.copilot-chat"
        )));
    }

    #[test]
    fn default_impl() {
        let _connector = CopilotCliConnector::default();
    }

    #[test]
    fn agent_slug_is_copilot_cli() {
        let tmp = TempDir::new().unwrap();
        let session_dir = tmp.path().join(".copilot/session-state/slug-test");
        fs::create_dir_all(&session_dir).unwrap();

        let events = r#"{"type":"user.message","content":"test","timestamp":1700000100000}
{"type":"assistant.message","content":"reply","timestamp":1700000101000}
"#;

        write_file(&session_dir, "events.jsonl", events);

        let connector = CopilotCliConnector::new();
        let root = tmp.path().join(".copilot/session-state");
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "copilot_cli");
        assert_eq!(convs[0].metadata["source"], "copilot-cli");
    }

    #[test]
    fn scan_respects_since_ts() {
        let tmp = TempDir::new().unwrap();
        let session_dir = tmp.path().join(".copilot/session-state/ts-test");
        fs::create_dir_all(&session_dir).unwrap();

        write_file(
            &session_dir,
            "events.jsonl",
            r#"{"type":"user.message","content":"old","timestamp":1700000000000}
{"type":"assistant.message","content":"reply","timestamp":1700000001000}
"#,
        );

        let connector = CopilotCliConnector::new();
        let root = tmp.path().join(".copilot/session-state");
        let far_future = chrono::Utc::now().timestamp_millis() + 86_400_000;
        let ctx = ScanContext::local_default(root, Some(far_future));
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }
}
