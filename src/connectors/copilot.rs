//! Connector for GitHub Copilot Chat session logs.
//!
//! ## Native VS Code chat-session storage (the primary history)
//!
//! VS Code's own chat store holds the bulk of Copilot Chat history and is
//! workspace-scoped (issue #16). It is handled by the
//! [`copilot_vscode`](super::copilot_vscode) module and covers, per product
//! root (`Code`, `Code - Insiders`, `VSCodium`) on Linux/macOS/Windows:
//! - `User/workspaceStorage/<id>/chatSessions/*.json|*.jsonl`
//! - `User/globalStorage/emptyWindowChatSessions/*.json|*.jsonl`
//! - `User/globalStorage/transferredChatSessions/*.json|*.jsonl`
//! - legacy `state.vscdb` (`interactive.sessions`) with the `copilot-vscdb`
//!   cargo feature
//!
//! ## Converted/extension globalStorage JSON
//!
//! Converted or extension-produced JSON may also live in globalStorage:
//! - Linux: ~/.config/Code/User/globalStorage/github.copilot-chat/
//! - macOS: ~/Library/Application Support/Code/User/globalStorage/github.copilot-chat/
//! - Windows: %APPDATA%/Code/User/globalStorage/github.copilot-chat/
//!
//! The conversations directory contains JSON files with chat sessions.
//! Each file typically represents a conversation panel session with an array
//! of conversation threads.
//!
//! Additionally, the `gh copilot` CLI may store history at:
//! - ~/.config/gh-copilot/
//!
//! ## Copilot CLI event logs
//!
//! GitHub Copilot CLI (the `gh copilot` or standalone `copilot` binary) stores
//! session history as JSONL event logs:
//! - ~/.copilot/session-state/{session-id}/events.jsonl  (v2, since 0.0.342)
//! - ~/.copilot/history-session-state/{session-id}.json  (v1, legacy)
//! - ~/.copilot/command-history-state.json
//!
//! Each line in `events.jsonl` is a JSON object with a `type` field identifying
//! the event kind. Conversation events use `user.message` and `assistant.message`
//! types with `content`, `role`, and `timestamp` fields.
//!
//! ## VS Code Copilot Chat JSON format
//!
//! The primary storage file is `conversations.json` (or individual `.json` files),
//! containing an array of conversation objects:
//!
//! ```json
//! [
//!   {
//!     "id": "uuid",
//!     "requester": "user",
//!     "workspaceFolder": "/path/to/project",
//!     "turns": [
//!       {
//!         "request": { "message": "...", "timestamp": 1700000000000 },
//!         "response": { "message": "...", "timestamp": 1700000001000 }
//!       }
//!     ]
//!   }
//! ]
//! ```

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;
use walkdir::WalkDir;

use super::copilot_vscode;
use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::read_capped;
use super::{
    Connector, file_modified_since, flatten_content, franken_detection_for_connector,
    parse_timestamp,
};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct CopilotConnector;

impl Default for CopilotConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl CopilotConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Known VS Code globalStorage paths for Copilot Chat on Linux.
    fn vscode_linux_paths() -> Vec<PathBuf> {
        let Some(home) = dirs::home_dir() else {
            return Vec::new();
        };
        vec![
            home.join(".config/Code/User/globalStorage/github.copilot-chat"),
            home.join(".config/Code - Insiders/User/globalStorage/github.copilot-chat"),
            home.join(".config/VSCodium/User/globalStorage/github.copilot-chat"),
        ]
    }

    /// Known VS Code globalStorage paths for Copilot Chat on macOS.
    fn vscode_macos_paths() -> Vec<PathBuf> {
        let Some(home) = dirs::home_dir() else {
            return Vec::new();
        };
        vec![
            home.join("Library/Application Support/Code/User/globalStorage/github.copilot-chat"),
            home.join("Library/Application Support/Code - Insiders/User/globalStorage/github.copilot-chat"),
            home.join("Library/Application Support/VSCodium/User/globalStorage/github.copilot-chat"),
        ]
    }

    /// Known VS Code globalStorage paths for Copilot Chat on Windows.
    ///
    /// Uses `%APPDATA%` (typically `C:\Users\<name>\AppData\Roaming`).
    fn vscode_windows_paths() -> Vec<PathBuf> {
        let Some(appdata) = dirs::config_dir() else {
            return Vec::new();
        };

        vec![
            appdata.join("Code/User/globalStorage/github.copilot-chat"),
            appdata.join("Code - Insiders/User/globalStorage/github.copilot-chat"),
            appdata.join("VSCodium/User/globalStorage/github.copilot-chat"),
        ]
    }

    /// All candidate paths for this platform.
    fn all_candidate_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        paths.extend(Self::vscode_linux_paths());
        paths.extend(Self::vscode_macos_paths());
        paths.extend(Self::vscode_windows_paths());
        paths.sort();
        paths.dedup();
        paths
    }

    /// Check if a path looks like Copilot Chat or Copilot CLI storage.
    fn looks_like_copilot_storage(path: &Path) -> bool {
        let segments: Vec<String> = path
            .components()
            .map(|component| component.as_os_str().to_string_lossy().to_lowercase())
            .collect();

        segments
            .iter()
            .any(|segment| segment == "github.copilot-chat" || segment == "copilot-chat")
    }

    fn append_explicit_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        let file_name = base.file_name().and_then(|n| n.to_str());
        let is_config = file_name.is_some_and(|n| n == ".config");
        let is_app_support = file_name.is_some_and(|n| n == "Application Support");
        let is_appdata_roaming = file_name.is_some_and(|n| n == "Roaming")
            && base
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == "AppData"));
        let is_code_variant =
            file_name.is_some_and(|n| n == "Code" || n == "Code - Insiders" || n == "VSCodium");
        let is_user = file_name.is_some_and(|n| n == "User");
        let is_global_storage = file_name.is_some_and(|n| n == "globalStorage");

        if base.exists() && Self::looks_like_copilot_storage(base) {
            roots.push(base.to_path_buf());
        }

        if file_name.is_some_and(|n| n == ".copilot") {
            let session_state = base.join("session-state");
            if session_state.exists() {
                roots.push(session_state);
            }
            let history_state = base.join("history-session-state");
            if history_state.exists() {
                roots.push(history_state);
            }
        }

        if is_global_storage {
            let copilot_chat = base.join("github.copilot-chat");
            if copilot_chat.exists() {
                roots.push(copilot_chat);
            }
        }

        if file_name.is_some_and(|n| n == "gh") {
            let gh_copilot = base.join("copilot");
            if gh_copilot.exists() {
                roots.push(gh_copilot);
            }
        }

        let mut candidates: Vec<PathBuf> = Vec::new();

        if is_config {
            candidates.push(base.join("Code/User/globalStorage/github.copilot-chat"));
            candidates.push(base.join("Code - Insiders/User/globalStorage/github.copilot-chat"));
            candidates.push(base.join("VSCodium/User/globalStorage/github.copilot-chat"));
            candidates.push(base.join("gh-copilot"));
            candidates.push(base.join("gh/copilot"));
        }

        if is_app_support {
            candidates.push(base.join("Code/User/globalStorage/github.copilot-chat"));
            candidates.push(base.join("Code - Insiders/User/globalStorage/github.copilot-chat"));
            candidates.push(base.join("VSCodium/User/globalStorage/github.copilot-chat"));
        }
        if is_appdata_roaming {
            candidates.push(base.join("Code/User/globalStorage/github.copilot-chat"));
            candidates.push(base.join("Code - Insiders/User/globalStorage/github.copilot-chat"));
            candidates.push(base.join("VSCodium/User/globalStorage/github.copilot-chat"));
        }

        if is_code_variant {
            candidates.push(base.join("User/globalStorage/github.copilot-chat"));
        }
        if is_user {
            candidates.push(base.join("globalStorage/github.copilot-chat"));
        }

        if !(is_config
            || is_app_support
            || is_appdata_roaming
            || is_code_variant
            || is_user
            || is_global_storage)
        {
            candidates.push(base.join(".config/Code/User/globalStorage/github.copilot-chat"));
            candidates
                .push(base.join(".config/Code - Insiders/User/globalStorage/github.copilot-chat"));
            candidates.push(base.join(".config/VSCodium/User/globalStorage/github.copilot-chat"));
            candidates.push(
                base.join(
                    "Library/Application Support/Code/User/globalStorage/github.copilot-chat",
                ),
            );
            candidates.push(base.join(
                "Library/Application Support/Code - Insiders/User/globalStorage/github.copilot-chat",
            ));
            candidates.push(base.join(
                "Library/Application Support/VSCodium/User/globalStorage/github.copilot-chat",
            ));
            candidates
                .push(base.join("AppData/Roaming/Code/User/globalStorage/github.copilot-chat"));
            candidates.push(
                base.join("AppData/Roaming/Code - Insiders/User/globalStorage/github.copilot-chat"),
            );
            candidates
                .push(base.join("AppData/Roaming/VSCodium/User/globalStorage/github.copilot-chat"));
            candidates.push(base.join(".config/gh-copilot"));
            candidates.push(base.join(".config/gh/copilot"));
            candidates.push(base.join(".copilot/session-state"));
            candidates.push(base.join(".copilot/history-session-state"));
        }

        for candidate in candidates {
            if candidate.exists() {
                roots.push(candidate);
            }
        }
    }

    /// Find JSON and JSONL files that may contain conversation data.
    fn find_conversation_files(root: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        if !root.exists() {
            return files;
        }

        // If root is a file, check it directly.
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

        // Walk the directory for JSON/JSONL files (limited depth to avoid deep traversal).
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

        // Keep connector traversal deterministic across filesystems/runs.
        files.sort();
        files
    }

    /// Bases handed to the native VS Code chat-session store scanner
    /// (issue #16). Explicit scan roots are expanded by the
    /// [`copilot_vscode`] module itself; in default-detection mode the
    /// platform `User` roots are probed unless `data_dir` explicitly targets
    /// either store family.
    fn native_scan_bases(ctx: &ScanContext) -> Vec<ScanRoot> {
        if !ctx.use_default_detection() {
            return ctx.scan_roots.clone();
        }
        if ctx.data_dir.exists() && copilot_vscode::looks_like_native_store(&ctx.data_dir) {
            return vec![ScanRoot::local(ctx.data_dir.clone())];
        }
        if ctx.data_dir.exists() && Self::looks_like_copilot_storage(&ctx.data_dir) {
            // data_dir pins the scan to the extension/CLI store only.
            return Vec::new();
        }
        copilot_vscode::default_user_roots()
            .into_iter()
            .filter(|path| path.exists())
            .map(ScanRoot::local)
            .collect()
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots: Vec<ScanRoot> = Vec::new();

        if ctx.use_default_detection() {
            if Self::looks_like_copilot_storage(&ctx.data_dir) && ctx.data_dir.exists() {
                roots.push(ScanRoot::local(ctx.data_dir.clone()));
            } else {
                roots.extend(
                    Self::all_candidate_paths()
                        .into_iter()
                        .filter(|path| path.exists())
                        .map(ScanRoot::local),
                );
            }
        } else {
            for scan_root in &ctx.scan_roots {
                let mut candidates = Vec::new();
                Self::append_explicit_roots(&mut candidates, &scan_root.path);
                roots.extend(candidates.into_iter().map(|path| scan_root.with_path(path)));
            }
        }

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        for root in Self::source_roots(ctx) {
            let files = Self::find_conversation_files(&root.path);
            for file in files {
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "copilot",
                        &root,
                        file,
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }
        }
        // Native VS Code chat-session stores (issue #16).
        out.extend(copilot_vscode::discover_native(
            &Self::native_scan_bases(ctx),
            ctx.since_ts,
        ));
        out
    }

    /// Parse a single JSON file that may contain one or more conversations.
    ///
    /// Handles multiple formats:
    /// 1. Array of conversation objects at top level
    /// 2. Single conversation object
    /// 3. Object with a "conversations" key containing an array
    fn parse_conversation_file(path: &Path) -> Result<Vec<NormalizedConversation>> {
        // Conversation exports can grow large; enforce the project's
        // 100MB scan cap.
        let content = match read_capped(path) {
            Ok(Some(content)) => content,
            Ok(None) => {
                tracing::warn!(
                    path = %path.display(),
                    "copilot: conversation file exceeds the scan size cap; skipping"
                );
                return Ok(Vec::new());
            }
            Err(e) => return Err(e.into()),
        };
        let val: Value = serde_json::from_str(&content)?;
        let mut conversations = Vec::new();

        // Strategy: try multiple known shapes of the JSON.
        let conv_array = if let Some(arr) = val.as_array() {
            // Top-level array of conversations
            arr.clone()
        } else if let Some(arr) = val.get("conversations").and_then(|v| v.as_array()) {
            // Object with "conversations" key
            arr.clone()
        } else if val.get("id").is_some() || val.get("turns").is_some() {
            // Single conversation object
            vec![val]
        } else {
            // Unknown format — skip
            tracing::debug!(
                path = %path.display(),
                "copilot: skipping file with unrecognized JSON structure"
            );
            return Ok(Vec::new());
        };

        for conv_val in &conv_array {
            if let Some(parsed) = Self::parse_single_conversation(conv_val, path) {
                conversations.push(parsed);
            }
        }

        Ok(conversations)
    }

    /// Parse a single conversation object from Copilot Chat JSON.
    #[allow(clippy::too_many_lines)]
    fn parse_single_conversation(
        conv: &Value,
        source_path: &Path,
    ) -> Option<NormalizedConversation> {
        let external_id = conv
            .get("id")
            .or_else(|| conv.get("conversationId"))
            .and_then(|v| v.as_str())
            .map(String::from);

        let title = conv
            .get("title")
            .or_else(|| conv.get("chatTitle"))
            .and_then(|v| v.as_str())
            .map(String::from);

        // Workspace/project path.
        let workspace = conv
            .get("workspaceFolder")
            .or_else(|| conv.get("workspace"))
            .or_else(|| conv.get("workspacePath"))
            .and_then(|v| v.as_str())
            .map(PathBuf::from);

        // Parse messages from "turns" array (VS Code Copilot Chat format).
        let mut messages = Vec::new();
        let mut started_at: Option<i64> = None;
        let mut ended_at: Option<i64> = None;

        if let Some(turns) = conv.get("turns").and_then(|v| v.as_array()) {
            for turn in turns {
                // Each turn typically has a "request" and "response".
                if let Some(request) = turn.get("request") {
                    let content = Self::extract_message_content(request);
                    if !content.trim().is_empty() {
                        let ts = Self::extract_turn_timestamp(request);
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

                        messages.push(NormalizedMessage {
                            idx: i64::try_from(messages.len()).unwrap_or(i64::MAX),
                            role: "user".to_string(),
                            author: Some("user".to_string()),
                            created_at: ts,
                            content,
                            extra: request.clone(),
                            invocations: Vec::new(),
                            snippets: Vec::new(),
                        });
                    }
                }

                if let Some(response) = turn.get("response") {
                    let content = Self::extract_message_content(response);
                    if !content.trim().is_empty() {
                        let ts = Self::extract_turn_timestamp(response);
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

                        messages.push(NormalizedMessage {
                            idx: i64::try_from(messages.len()).unwrap_or(i64::MAX),
                            role: "assistant".to_string(),
                            author: Some("copilot".to_string()),
                            created_at: ts,
                            content,
                            extra: response.clone(),
                            invocations: Vec::new(),
                            snippets: Vec::new(),
                        });
                    }
                }
            }
        }

        // Alternative format: "messages" array with role/content objects.
        if messages.is_empty()
            && let Some(msgs) = conv.get("messages").and_then(|v| v.as_array())
        {
            for msg in msgs {
                let role = msg
                    .get("role")
                    .and_then(|v| v.as_str())
                    .unwrap_or("assistant")
                    .to_string();

                let content = Self::extract_message_content(msg);
                if content.trim().is_empty() {
                    continue;
                }

                let ts = Self::extract_turn_timestamp(msg);
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

                messages.push(NormalizedMessage {
                    idx: i64::try_from(messages.len()).unwrap_or(i64::MAX),
                    role: role.clone(),
                    author: Some(if role == "user" {
                        "user".to_string()
                    } else {
                        "copilot".to_string()
                    }),
                    created_at: ts,
                    content,
                    extra: msg.clone(),
                    invocations: Vec::new(),
                    snippets: Vec::new(),
                });
            }
        }

        // Also check top-level timestamp if per-message timestamps missing.
        if started_at.is_none() {
            started_at = conv
                .get("createdAt")
                .or_else(|| conv.get("created_at"))
                .or_else(|| conv.get("timestamp"))
                .and_then(parse_timestamp);
        }
        if ended_at.is_none() {
            ended_at = conv
                .get("updatedAt")
                .or_else(|| conv.get("updated_at"))
                .and_then(parse_timestamp);
        }
        // If only one boundary is available, mirror it so timeline consumers
        // still get a consistent non-empty range.
        if started_at.is_none() {
            started_at = ended_at;
        }
        if ended_at.is_none() {
            ended_at = started_at;
        }

        if messages.is_empty() {
            return None;
        }

        // Derive title from first user message if not explicitly set.
        let title = title.or_else(|| {
            messages.iter().find(|m| m.role == "user").map(|m| {
                m.content
                    .lines()
                    .next()
                    .unwrap_or(&m.content)
                    .chars()
                    .take(120)
                    .collect::<String>()
            })
        });

        let metadata = serde_json::json!({
            "source": "copilot",
        });

        Some(NormalizedConversation {
            agent_slug: "copilot".to_string(),
            external_id,
            title,
            workspace,
            source_path: source_path.to_path_buf(),
            started_at,
            ended_at,
            metadata,
            messages,
        })
    }

    /// Extract message content from various possible field names/shapes.
    fn extract_message_content(val: &Value) -> String {
        // Try "message" field (Copilot Chat turns format)
        if let Some(msg) = val.get("message") {
            let text = flatten_content(msg);
            if !text.is_empty() {
                return text;
            }
        }

        // Try "content" field (standard chat format)
        if let Some(content) = val.get("content") {
            let text = flatten_content(content);
            if !text.is_empty() {
                return text;
            }
        }

        // Try "text" field
        if let Some(text) = val.get("text") {
            let text = flatten_content(text);
            if !text.is_empty() {
                return text;
            }
        }

        // Try "value" field
        if let Some(value) = val.get("value") {
            let text = flatten_content(value);
            if !text.is_empty() {
                return text;
            }
        }

        String::new()
    }

    /// Extract timestamp from a turn/message object.
    fn extract_turn_timestamp(val: &Value) -> Option<i64> {
        let candidates = ["timestamp", "createdAt", "created_at", "time", "ts", "date"];
        for key in candidates {
            if let Some(ts) = val.get(key).and_then(parse_timestamp) {
                return Some(ts);
            }
        }
        None
    }
}

impl Connector for CopilotConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("copilot").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let roots: Vec<PathBuf> = Self::source_roots(ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();

        let mut all_conversations = Vec::new();

        for root in roots {
            let files = Self::find_conversation_files(&root);
            tracing::debug!(
                root = %root.display(),
                file_count = files.len(),
                "copilot: scanning conversation files"
            );

            for file in files {
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }

                // CLI event logs are handled exclusively by the
                // copilot_cli connector (which also handles Chronicle
                // data envelopes that this parser cannot).
                let result = Self::parse_conversation_file(&file);

                match result {
                    Ok(convs) => {
                        tracing::debug!(
                            file = %file.display(),
                            conversations = convs.len(),
                            "copilot: parsed conversation file"
                        );
                        all_conversations.extend(convs);
                    }
                    Err(e) => {
                        tracing::debug!(
                            file = %file.display(),
                            error = %e,
                            "copilot: skipping unparseable file"
                        );
                    }
                }
            }
        }

        // Native VS Code chat-session stores (issue #16) are the primary
        // history surface and are advertised by discover_sources — they
        // must be SCANNED too. Previously scan_native had zero production
        // callers: every native conversation was invisible to scan() while
        // discovery flagged its files required_for_reconstruction.
        let native_conversations =
            copilot_vscode::scan_native(&Self::native_scan_bases(ctx), ctx.since_ts);

        // Cross-surface dedupe by external id: a session present both as a
        // native entry and as an extension-store export emits once (the
        // extension copy is scanned first, matching discovery order).
        let mut seen_surface_ids: HashSet<String> = all_conversations
            .iter()
            .filter_map(|c| c.external_id.clone())
            .collect();
        for conversation in native_conversations {
            match conversation.external_id.as_ref() {
                Some(id) if !seen_surface_ids.insert(id.clone()) => continue,
                _ => {}
            }
            all_conversations.push(conversation);
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
    use crate::connectors::scan::ScanRoot;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Helper to write a JSON file into a temp directory.
    fn write_json(dir: &Path, filename: &str, content: &str) -> PathBuf {
        let path = dir.join(filename);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn detect_returns_not_found_when_no_dirs_exist() {
        let connector = CopilotConnector::new();
        // On most test systems Copilot dirs won't exist.
        // This test just ensures detect() doesn't panic.
        let result = connector.detect();
        // Result depends on system — franken detection includes positive and
        // negative probe evidence. Just assert basic structural invariants.
        assert!(!result.evidence.is_empty());
        if result.detected {
            assert!(!result.root_paths.is_empty());
        }
    }

    #[test]
    fn scan_empty_dir_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("copilot-chat");
        fs::create_dir_all(&root).unwrap();

        let connector = CopilotConnector::new();
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn scan_with_explicit_config_root_finds_vscode_storage() {
        let tmp = TempDir::new().unwrap();
        let config_root = tmp.path().join(".config");
        let copilot_dir = config_root.join("Code/User/globalStorage/github.copilot-chat");
        fs::create_dir_all(&copilot_dir).unwrap();

        let json = r#"[
            {
                "id": "conv-config",
                "workspaceFolder": "/work/config",
                "turns": [
                    {
                        "request": {"message": "Hello", "timestamp": 1700000000000},
                        "response": {"message": "Hi", "timestamp": 1700000001000}
                    }
                ]
            }
        ]"#;

        write_json(&copilot_dir, "conversations.json", json);

        let connector = CopilotConnector::new();
        let ctx = ScanContext::with_roots(
            tmp.path().join("cass"),
            vec![ScanRoot::local(config_root)],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("conv-config"));
    }

    #[test]
    fn scan_parses_turns_format() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("copilot-chat");
        fs::create_dir_all(&root).unwrap();

        let json = r#"[
            {
                "id": "conv-001",
                "workspaceFolder": "/home/user/project",
                "turns": [
                    {
                        "request": {
                            "message": "How do I sort a vector in Rust?",
                            "timestamp": 1700000000000
                        },
                        "response": {
                            "message": "You can use `.sort()` or `.sort_by()` on a Vec.",
                            "timestamp": 1700000001000
                        }
                    },
                    {
                        "request": {
                            "message": "Can you show me an example?",
                            "timestamp": 1700000002000
                        },
                        "response": {
                            "message": "Sure! `let mut v = vec![3,1,2]; v.sort();`",
                            "timestamp": 1700000003000
                        }
                    }
                ]
            }
        ]"#;

        write_json(&root, "conversations.json", json);

        let connector = CopilotConnector::new();
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "copilot");
        assert_eq!(convs[0].external_id.as_deref(), Some("conv-001"));
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/project"))
        );
        assert_eq!(convs[0].messages.len(), 4);
        assert_eq!(convs[0].messages[0].role, "user");
        assert!(convs[0].messages[0].content.contains("sort a vector"));
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert!(convs[0].messages[1].content.contains(".sort()"));
        assert_eq!(convs[0].messages[2].role, "user");
        assert_eq!(convs[0].messages[3].role, "assistant");
        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
        assert!(convs[0].title.is_some());
        assert!(convs[0].title.as_ref().unwrap().contains("sort a vector"));
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn scan_parses_messages_format() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("copilot-chat");
        fs::create_dir_all(&root).unwrap();

        let json = r#"{
            "id": "conv-002",
            "title": "Explain lifetimes",
            "messages": [
                {
                    "role": "user",
                    "content": "Explain Rust lifetimes",
                    "timestamp": 1700000010000
                },
                {
                    "role": "assistant",
                    "content": "Lifetimes are a way of expressing the scope for which a reference is valid.",
                    "timestamp": 1700000011000
                }
            ]
        }"#;

        write_json(&root, "session-002.json", json);

        let connector = CopilotConnector::new();
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].title.as_deref(), Some("Explain lifetimes"));
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert_eq!(convs[0].messages[1].author.as_deref(), Some("copilot"));
    }

    #[test]
    fn scan_parses_conversations_wrapper() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("copilot-chat");
        fs::create_dir_all(&root).unwrap();

        let json = r#"{
            "conversations": [
                {
                    "id": "wrapped-001",
                    "messages": [
                        {"role": "user", "content": "Hello Copilot"},
                        {"role": "assistant", "content": "Hello! How can I help?"}
                    ]
                },
                {
                    "id": "wrapped-002",
                    "messages": [
                        {"role": "user", "content": "Write a function"},
                        {"role": "assistant", "content": "fn example() {}"}
                    ]
                }
            ]
        }"#;

        write_json(&root, "all-conversations.json", json);

        let connector = CopilotConnector::new();
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
        assert_eq!(convs[0].external_id.as_deref(), Some("wrapped-001"));
        assert_eq!(convs[1].external_id.as_deref(), Some("wrapped-002"));
    }

    #[test]
    fn scan_skips_empty_conversations() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("copilot-chat");
        fs::create_dir_all(&root).unwrap();

        let json = r#"[
            {
                "id": "empty-conv",
                "turns": []
            },
            {
                "id": "nonempty-conv",
                "turns": [
                    {
                        "request": {"message": "Hello"},
                        "response": {"message": "Hi there"}
                    }
                ]
            }
        ]"#;

        write_json(&root, "mixed.json", json);

        let connector = CopilotConnector::new();
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        // Only the non-empty conversation should be returned.
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("nonempty-conv"));
    }

    #[test]
    fn find_conversation_files_returns_sorted_order() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("copilot-chat");
        fs::create_dir_all(root.join("nested")).unwrap();

        write_json(&root, "zeta.json", "[]");
        write_json(&root, "alpha.json", "[]");
        write_json(&root.join("nested"), "middle.json", "[]");

        let files = CopilotConnector::find_conversation_files(&root);
        let mut sorted = files.clone();
        sorted.sort();
        assert_eq!(files, sorted);
    }

    #[test]
    fn scan_sets_ended_at_when_only_created_at_present() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("copilot-chat");
        fs::create_dir_all(&root).unwrap();

        // Messages have no per-message timestamps; only createdAt exists.
        let json = r#"{
            "id": "conv-created-only",
            "createdAt": 1700000022000,
            "messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "world"}
            ]
        }"#;
        write_json(&root, "created-only.json", json);

        let connector = CopilotConnector::new();
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].started_at, Some(1_700_000_022_000));
        assert_eq!(convs[0].ended_at, Some(1_700_000_022_000));
    }

    #[test]
    fn scan_respects_since_ts_filtering() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("copilot-chat");
        fs::create_dir_all(&root).unwrap();

        write_json(
            &root,
            "old.json",
            r#"[{"id":"old","turns":[{"request":{"message":"old msg"},"response":{"message":"old reply"}}]}]"#,
        );

        // Use a far-future timestamp to filter out everything.
        let connector = CopilotConnector::new();
        let far_future = chrono::Utc::now().timestamp_millis() + 86_400_000;
        let ctx = ScanContext::local_default(root, Some(far_future));
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn scan_with_scan_roots() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("fakehome");
        let copilot_dir = home.join(".config/Code/User/globalStorage/github.copilot-chat");
        fs::create_dir_all(&copilot_dir).unwrap();

        let json = r#"[{
            "id": "remote-001",
            "turns": [
                {"request": {"message": "test"}, "response": {"message": "reply"}}
            ]
        }]"#;

        write_json(&copilot_dir, "conversations.json", json);

        let connector = CopilotConnector::new();
        let scan_root = crate::connectors::ScanRoot::local(home);
        let ctx = ScanContext::with_roots(tmp.path().to_path_buf(), vec![scan_root], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("remote-001"));
    }

    #[test]
    fn scan_with_global_storage_scan_root() {
        let tmp = TempDir::new().unwrap();
        let global_storage = tmp.path().join("globalStorage");
        let copilot_dir = global_storage.join("github.copilot-chat");
        fs::create_dir_all(&copilot_dir).unwrap();

        let json = r#"[{
            "id": "global-001",
            "turns": [
                {"request": {"message": "hello"}, "response": {"message": "hi"}}
            ]
        }]"#;
        write_json(&copilot_dir, "conversations.json", json);

        let connector = CopilotConnector::new();
        let ctx =
            ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(global_storage)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("global-001"));
    }

    #[test]
    fn scan_with_windows_style_scan_root() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("fakehome");
        let copilot_dir = home.join("AppData/Roaming/Code/User/globalStorage/github.copilot-chat");
        fs::create_dir_all(&copilot_dir).unwrap();

        let json = r#"[{
            "id": "win-001",
            "messages": [
                {"role": "user", "content": "from windows root"},
                {"role": "assistant", "content": "ack"}
            ]
        }]"#;

        write_json(&copilot_dir, "conversations.json", json);

        let connector = CopilotConnector::new();
        let scan_root = crate::connectors::ScanRoot::local(home);
        let ctx = ScanContext::with_roots(tmp.path().to_path_buf(), vec![scan_root], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("win-001"));
    }

    #[test]
    fn scan_skips_invalid_json() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("copilot-chat");
        fs::create_dir_all(&root).unwrap();

        write_json(&root, "invalid.json", "not valid json {{{");

        let connector = CopilotConnector::new();
        let ctx = ScanContext::local_default(root, None);
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn looks_like_copilot_storage_works() {
        assert!(CopilotConnector::looks_like_copilot_storage(Path::new(
            "/home/user/.config/Code/User/globalStorage/github.copilot-chat"
        )));
        assert!(CopilotConnector::looks_like_copilot_storage(Path::new(
            "/tmp/copilot-chat/data"
        )));
        // gh-copilot / .copilot paths are handled by copilot_cli.
        assert!(!CopilotConnector::looks_like_copilot_storage(Path::new(
            "/home/user/.config/gh-copilot"
        )));
        assert!(!CopilotConnector::looks_like_copilot_storage(Path::new(
            "/home/user/.config/Code"
        )));
        assert!(!CopilotConnector::looks_like_copilot_storage(Path::new(
            "/home/user/projects/copilot-research"
        )));
    }

    #[test]
    fn default_impl() {
        let connector = CopilotConnector;
        let _ = connector;
    }

    #[test]
    fn all_candidate_paths_are_deduplicated() {
        let paths = CopilotConnector::all_candidate_paths();
        let mut deduped = paths.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(paths, deduped);
    }
}
