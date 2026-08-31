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

use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::read_capped;
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

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots: Vec<ScanRoot> = Vec::new();

        if ctx.use_default_detection() {
            if Self::looks_like_cli_storage(&ctx.data_dir) && ctx.data_dir.exists() {
                roots.push(ScanRoot::local(ctx.data_dir.clone()));
            } else {
                roots.extend(
                    Self::cli_candidate_paths()
                        .into_iter()
                        .filter(|path| path.exists())
                        .map(ScanRoot::local),
                );
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
                        roots.push(scan_root.with_path(candidate.clone()));
                    }
                }

                let mut explicit = Vec::new();
                Self::append_explicit_roots(&mut explicit, &scan_root.path);
                roots.extend(explicit.into_iter().map(|path| scan_root.with_path(path)));
            }
        }

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        for root in Self::source_roots(ctx) {
            for file in Self::find_event_files(&root.path) {
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "copilot_cli",
                        &root,
                        file,
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }
        }
        out
    }

    /// Parse a JSONL event log file into conversations.
    ///
    /// Each line is a JSON event. We extract events with message-like types
    /// (`user.message`, `assistant.message`, or events with `role`+`content`
    /// fields) and assemble them into a single conversation per session file.
    #[allow(clippy::too_many_lines)]
    fn parse_event_log(&self, path: &Path) -> Result<Vec<NormalizedConversation>> {
        // Event logs accumulate; enforce the project's 100MB scan cap.
        let content = match read_capped(path) {
            Ok(Some(content)) => content,
            Ok(None) => {
                tracing::warn!(
                    path = %path.display(),
                    "copilot_cli: event log exceeds the scan size cap; skipping"
                );
                return Ok(Vec::new());
            }
            Err(e) => return Err(e.into()),
        };

        // Single-document dispatch is for legacy `.json` session-state files
        // only. A ONE-LINE `events.jsonl` also starts with `{` and parses as
        // a bare object, but parse_session_json finds no event arrays in it
        // and returns empty — silently dropping the session. (.jsonl is
        // always line-delimited; copilot.rs gates the same dispatch with
        // !is_jsonl.)
        let is_jsonl = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"));
        let trimmed = content.trim_start();
        if !is_jsonl && (trimmed.starts_with('{') || trimmed.starts_with('[')) {
            if let Ok(val) = serde_json::from_str::<Value>(&content) {
                return Ok(self.parse_session_json(&val, path));
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
            let Ok(line) = line else {
                continue;
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let Ok(event) = serde_json::from_str::<Value>(line) else {
                continue;
            };

            if session_id.is_none() {
                session_id =
                    Self::find_nested_str(&event, &["session_id", "sessionId", "sessionID", "id"])
                        .map(String::from);
            }

            if workspace.is_none() {
                workspace = Self::find_nested_str(
                    &event,
                    &[
                        "cwd",
                        "workingDirectory",
                        "working_directory",
                        "workspace",
                        "workspaceRoot",
                        "workspace_root",
                        "projectPath",
                        "project_path",
                    ],
                )
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
    fn parse_session_json(&self, val: &Value, path: &Path) -> Vec<NormalizedConversation> {
        // Try extracting messages from "events" or "history" arrays.
        let events = val
            .get("events")
            .and_then(|v| v.as_array())
            .or_else(|| val.get("history").and_then(|v| v.as_array()));

        // Try "messages" array as well (chat-style session state).
        let events = events.or_else(|| val.get("messages").and_then(|v| v.as_array()));

        // Also check for "conversation" array wrapper.
        let events = events.or_else(|| val.get("conversation").and_then(|v| v.as_array()));

        let Some(events) = events else {
            // If there's a top-level array, try each element.
            if let Some(arr) = val.as_array() {
                return self.parse_session_array(arr, path);
            }
            return Vec::new();
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
            return Vec::new();
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

        vec![NormalizedConversation {
            agent_slug: "copilot_cli".to_string(),
            external_id: session_id,
            title,
            workspace,
            source_path: path.to_path_buf(),
            started_at,
            ended_at,
            metadata,
            messages,
        }]
    }

    /// Parse a top-level JSON array where each element may be a conversation.
    fn parse_session_array(&self, arr: &[Value], path: &Path) -> Vec<NormalizedConversation> {
        let mut conversations = Vec::new();
        for (i, element) in arr.iter().enumerate() {
            let mut convs = self.parse_session_json(element, path);
            if convs.is_empty() {
                continue;
            }
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
        conversations
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

        // Explicit role field takes precedence. Chronicle-format events also
        // allow `role` under a nested `data` or `payload` object.
        let explicit_role = Self::find_nested_str(event, &["role", "author", "sender"]);
        let role = explicit_role
            .map(|r| {
                if r == "user" || r == "human" {
                    "user".to_string()
                } else {
                    "assistant".to_string()
                }
            })
            .or(role_from_type);

        let Some(role) = role else {
            return (String::new(), String::new());
        };

        let content = Self::extract_content(event);

        // If standard extraction failed, try event-specific fields at both
        // the top level and inside `data`/`payload` envelopes.
        if content.trim().is_empty() {
            let wrappers: [Option<&Value>; 3] =
                [Some(event), event.get("data"), event.get("payload")];
            for wrapper in wrappers.into_iter().flatten() {
                for key in ["prompt", "initialPrompt", "initial_prompt"] {
                    if let Some(prompt) = wrapper.get(key) {
                        let text = flatten_content(prompt);
                        if !text.is_empty() {
                            return (role, text);
                        }
                    }
                }
                for key in ["output", "result", "response"] {
                    if let Some(output) = wrapper.get(key) {
                        let text = flatten_content(output);
                        if !text.is_empty() {
                            return (role, text);
                        }
                    }
                }
            }
        }

        (role, content)
    }

    /// Extract message content from various possible field names.
    ///
    /// Copilot CLI's Chronicle-format events (since ~0.0.342) nest the message
    /// payload under a `data` object — e.g.
    /// `{"type":"user.message","data":{"content":"..."}}`. Older formats place
    /// `content` at the top level. We check both shapes plus well-known
    /// alternative keys, preferring the top-level fields first for
    /// backwards compatibility.
    fn extract_content(val: &Value) -> String {
        const CONTENT_KEYS: &[&str] = &["message", "content", "text", "value", "body"];

        // 1. Top-level keys (legacy and some newer events).
        for key in CONTENT_KEYS {
            if let Some(field) = val.get(*key) {
                let text = flatten_content(field);
                if !text.is_empty() {
                    return text;
                }
            }
        }

        // 2. Nested `data` payload (Chronicle v2 format).
        if let Some(data) = val.get("data") {
            // If `data` is itself a string, treat it as the content directly.
            if data.is_string() {
                let text = flatten_content(data);
                if !text.is_empty() {
                    return text;
                }
            }
            for key in CONTENT_KEYS {
                if let Some(field) = data.get(*key) {
                    let text = flatten_content(field);
                    if !text.is_empty() {
                        return text;
                    }
                }
            }
        }

        // 3. Nested `payload` envelope (seen in some shim wrappers).
        if let Some(payload) = val.get("payload") {
            for key in CONTENT_KEYS {
                if let Some(field) = payload.get(*key) {
                    let text = flatten_content(field);
                    if !text.is_empty() {
                        return text;
                    }
                }
            }
        }

        String::new()
    }

    /// Look up a string-valued field under any of the provided keys, searching
    /// the top level and one level of nesting (`data`, `payload`, `metadata`).
    fn find_nested_str<'a>(val: &'a Value, keys: &[&str]) -> Option<&'a str> {
        for key in keys {
            if let Some(v) = val.get(*key).and_then(|v| v.as_str()) {
                return Some(v);
            }
        }
        for wrapper in ["data", "payload", "metadata"] {
            if let Some(inner) = val.get(wrapper) {
                for key in keys {
                    if let Some(v) = inner.get(*key).and_then(|v| v.as_str()) {
                        return Some(v);
                    }
                }
            }
        }
        None
    }

    /// Extract timestamp from an event object, checking both the top level and
    /// any `data`/`payload`/`metadata` envelope.
    fn extract_timestamp(val: &Value) -> Option<i64> {
        const TS_KEYS: &[&str] = &[
            "timestamp",
            "createdAt",
            "created_at",
            "time",
            "ts",
            "date",
            "startedAt",
            "started_at",
        ];

        for key in TS_KEYS {
            if let Some(ts) = val.get(*key).and_then(parse_timestamp) {
                return Some(ts);
            }
        }
        for wrapper in ["data", "payload", "metadata"] {
            if let Some(inner) = val.get(wrapper) {
                for key in TS_KEYS {
                    if let Some(ts) = inner.get(*key).and_then(parse_timestamp) {
                        return Some(ts);
                    }
                }
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
        let roots: Vec<PathBuf> = Self::source_roots(ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();

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

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
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
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
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
        let _ = CopilotCliConnector;
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

    /// Regression test for issue #187: Copilot CLI Chronicle events
    /// (since ~0.0.342) nest message payloads under a `data` object. Prior to
    /// the fix, `extract_content` only inspected top-level keys, so these
    /// events produced zero conversations.
    #[test]
    fn scan_parses_chronicle_nested_data_content() {
        let tmp = TempDir::new().unwrap();
        let session_dir = tmp.path().join(".copilot/session-state/chronicle-001");
        fs::create_dir_all(&session_dir).unwrap();

        // Exact shape reported in cass issue #187 for cc314.
        let events = r#"{"type":"session.start","data":{"sessionId":"chronicle-001","cwd":"/Users/cc314/projects/demo"},"timestamp":"2026-03-01T10:00:00.000Z"}
{"type":"user.message","data":{"content":"explain this repo"},"timestamp":"2026-03-01T10:00:01.000Z"}
{"type":"assistant.message","data":{"content":"This is a Rust project.","toolRequests":[]},"timestamp":"2026-03-01T10:00:02.000Z"}
{"type":"user.message","data":{"content":"what does lib.rs export?"},"timestamp":"2026-03-01T10:00:03.000Z"}
{"type":"assistant.message","data":{"content":"It re-exports connector factories.","toolRequests":[{"name":"Read","input":{"path":"lib.rs"}}]},"timestamp":"2026-03-01T10:00:04.000Z"}
"#;

        write_file(&session_dir, "events.jsonl", events);

        let connector = CopilotCliConnector::new();
        let root = tmp.path().join(".copilot/session-state");
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs.len(),
            1,
            "chronicle events should yield 1 conversation"
        );
        let conv = &convs[0];
        assert_eq!(conv.agent_slug, "copilot_cli");
        // session ID extracted from nested data OR the directory name.
        assert!(
            conv.external_id.as_deref() == Some("chronicle-001"),
            "expected session id 'chronicle-001', got {:?}",
            conv.external_id
        );
        assert_eq!(
            conv.workspace,
            Some(PathBuf::from("/Users/cc314/projects/demo")),
            "workspace should come from nested data.cwd"
        );
        assert_eq!(conv.messages.len(), 4, "two user + two assistant messages");
        assert_eq!(conv.messages[0].role, "user");
        assert!(conv.messages[0].content.contains("explain this repo"));
        assert_eq!(conv.messages[1].role, "assistant");
        assert!(conv.messages[1].content.contains("Rust project"));
        assert_eq!(conv.messages[2].role, "user");
        assert!(conv.messages[2].content.contains("lib.rs"));
        assert_eq!(conv.messages[3].role, "assistant");
        assert!(conv.messages[3].content.contains("connector factories"));
        // Title derived from first user message.
        assert!(
            conv.title
                .as_deref()
                .is_some_and(|t| t.contains("explain this repo")),
            "title should be the first user message prefix"
        );
        // Timestamps must parse from ISO8601 strings in data/top-level.
        assert!(conv.started_at.is_some());
        assert!(conv.ended_at.is_some());
        assert!(conv.started_at.unwrap() < conv.ended_at.unwrap());
    }

    /// Chronicle sessions where the directory UUID is the only source of the
    /// session id must still be indexed.
    #[test]
    fn scan_chronicle_falls_back_to_directory_uuid() {
        let tmp = TempDir::new().unwrap();
        let uuid = "4c5e9a9e-1234-4abc-9def-000000000001";
        let session_dir = tmp.path().join(format!(".copilot/session-state/{uuid}"));
        fs::create_dir_all(&session_dir).unwrap();

        // No sessionId field anywhere — only nested data.content messages.
        let events = r#"{"type":"user.message","data":{"content":"hi"},"timestamp":"2026-03-01T10:00:00.000Z"}
{"type":"assistant.message","data":{"content":"hello"},"timestamp":"2026-03-01T10:00:01.000Z"}
"#;
        write_file(&session_dir, "events.jsonl", events);

        let connector = CopilotCliConnector::new();
        let root = tmp.path().join(".copilot/session-state");
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some(uuid));
        assert_eq!(convs[0].messages.len(), 2);
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
