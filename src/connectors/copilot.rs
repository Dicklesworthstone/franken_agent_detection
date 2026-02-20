//! Connector for GitHub Copilot Chat session logs.
//!
//! GitHub Copilot Chat stores conversation history in VS Code's globalStorage:
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

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::ScanContext;
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

    /// gh copilot CLI config path.
    fn gh_copilot_paths() -> Vec<PathBuf> {
        let Some(home) = dirs::home_dir() else {
            return Vec::new();
        };
        vec![
            home.join(".config/gh-copilot"),
            home.join(".config/gh/copilot"),
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
        paths.extend(Self::gh_copilot_paths());
        paths.sort();
        paths.dedup();
        paths
    }

    /// Check if a path looks like Copilot Chat storage.
    fn looks_like_copilot_storage(path: &Path) -> bool {
        let segments: Vec<String> = path
            .components()
            .map(|component| component.as_os_str().to_string_lossy().to_lowercase())
            .collect();

        if segments.iter().any(|segment| {
            segment == "github.copilot-chat" || segment == "copilot-chat" || segment == "gh-copilot"
        }) {
            return true;
        }

        // Support nested CLI config path: ~/.config/gh/copilot
        segments
            .windows(2)
            .any(|pair| pair[0] == "gh" && pair[1] == "copilot")
    }

    /// Find JSON files that may contain conversation data.
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
                .is_some_and(|e| e == "json")
            {
                files.push(root.to_path_buf());
            }
            return files;
        }

        // Walk the directory for JSON files (limited depth to avoid deep traversal).
        for entry in WalkDir::new(root)
            .max_depth(4)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_file())
        {
            let name = entry.file_name().to_string_lossy();
            if name.ends_with(".json") {
                files.push(entry.path().to_path_buf());
            }
        }

        // Keep connector traversal deterministic across filesystems/runs.
        files.sort();
        files
    }

    /// Parse a single JSON file that may contain one or more conversations.
    ///
    /// Handles multiple formats:
    /// 1. Array of conversation objects at top level
    /// 2. Single conversation object
    /// 3. Object with a "conversations" key containing an array
    fn parse_conversation_file(&self, path: &Path) -> Result<Vec<NormalizedConversation>> {
        let content = fs::read_to_string(path)?;
        let val: Value = serde_json::from_str(&content)?;
        let mut conversations = Vec::new();

        // Strategy: try multiple known shapes of the JSON.
        let conv_array = if let Some(arr) = val.as_array() {
            // Top-level array of conversations
            arr.clone()
        } else if val
            .get("conversations")
            .and_then(|v| v.as_array())
            .is_some()
        {
            // Object with "conversations" key
            val["conversations"].as_array().unwrap().clone()
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
        let mut roots: Vec<PathBuf> = Vec::new();

        if ctx.use_default_detection() {
            // Check if data_dir itself looks like copilot storage (for testing).
            if Self::looks_like_copilot_storage(&ctx.data_dir) && ctx.data_dir.exists() {
                roots.push(ctx.data_dir.clone());
            } else {
                // Use default detection paths.
                for path in Self::all_candidate_paths() {
                    if path.exists() {
                        roots.push(path);
                    }
                }
            }
        } else {
            // Check scan_roots for copilot directories.
            for scan_root in &ctx.scan_roots {
                // Check common subdirectories within each scan root.
                let candidates = [
                    scan_root
                        .path
                        .join(".config/Code/User/globalStorage/github.copilot-chat"),
                    scan_root.path.join(
                        "Library/Application Support/Code/User/globalStorage/github.copilot-chat",
                    ),
                    scan_root
                        .path
                        .join("AppData/Roaming/Code/User/globalStorage/github.copilot-chat"),
                    scan_root.path.join(
                        "AppData/Roaming/Code - Insiders/User/globalStorage/github.copilot-chat",
                    ),
                    scan_root
                        .path
                        .join("AppData/Roaming/VSCodium/User/globalStorage/github.copilot-chat"),
                    scan_root.path.join(".config/gh-copilot"),
                    scan_root.path.join(".config/gh/copilot"),
                ];

                for candidate in &candidates {
                    if candidate.exists() {
                        roots.push(candidate.clone());
                    }
                }

                // Also check if the scan root itself is copilot storage.
                if Self::looks_like_copilot_storage(&scan_root.path) && scan_root.path.exists() {
                    roots.push(scan_root.path.clone());
                }
            }
        }

        if roots.is_empty() {
            return Ok(Vec::new());
        }

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

                match self.parse_conversation_file(&file) {
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

        Ok(all_conversations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(CopilotConnector::looks_like_copilot_storage(Path::new(
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
