use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use serde_json::Value;

use super::scan::ScanContext;
use super::{
    Connector, file_modified_since, flatten_content, franken_detection_for_connector,
    parse_timestamp,
};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct ClineConnector;
impl Default for ClineConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl ClineConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn candidate_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        let Some(base) = dirs::home_dir() else {
            return roots;
        };

        let code_roots = [
            base.join(".config/Code/User/globalStorage"),
            base.join("Library/Application Support/Code/User/globalStorage"),
            base.join("AppData/Roaming/Code/User/globalStorage"),
        ];
        let cursor_roots = [
            base.join(".config/Cursor/User/globalStorage"),
            base.join("Library/Application Support/Cursor/User/globalStorage"),
            base.join("AppData/Roaming/Cursor/User/globalStorage"),
        ];
        let extensions = ["saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline"];

        for root in code_roots.iter().chain(cursor_roots.iter()) {
            for ext in &extensions {
                roots.push(root.join(ext));
            }
        }

        roots
    }

    fn storage_roots() -> Vec<PathBuf> {
        Self::candidate_roots()
            .into_iter()
            .filter(|r| r.exists())
            .collect()
    }

    fn normalize_root_path(path: &std::path::Path) -> PathBuf {
        if path
            .file_name()
            .is_some_and(|n| n == "settings" || n == "settings.json")
        {
            path.parent().unwrap_or(path).to_path_buf()
        } else {
            path.to_path_buf()
        }
    }

    fn looks_like_storage(path: &std::path::Path) -> bool {
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains("claude-dev") || n.contains("roo-cline"))
        {
            return true;
        }

        if path.is_dir() {
            return fs::read_dir(path)
                .map(|mut d| {
                    d.any(|e| {
                        e.ok().is_some_and(|e| {
                            let p = e.path();
                            p.is_dir()
                                && (p.join("ui_messages.json").exists()
                                    || p.join("api_conversation_history.json").exists())
                        })
                    })
                })
                .unwrap_or(false);
        }

        false
    }
}

impl Connector for ClineConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("cline").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let override_root = Self::normalize_root_path(&ctx.data_dir);
        let roots = if ctx.use_default_detection() {
            if Self::looks_like_storage(&override_root) {
                vec![override_root]
            } else {
                Self::storage_roots()
            }
        } else if Self::looks_like_storage(&override_root) {
            vec![override_root]
        } else {
            return Ok(Vec::new());
        };

        if roots.is_empty() {
            return Ok(Vec::new());
        }

        let mut convs = Vec::new();
        for root in roots {
            if !root.exists() {
                continue;
            }

            let entries = match fs::read_dir(&root) {
                Ok(e) => e,
                Err(e) => {
                    tracing::debug!(path = %root.display(), error = %e, "cline: skipping unreadable directory");
                    continue;
                }
            };
            for entry in entries {
                let Ok(entry) = entry else { continue };
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let task_id = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(std::string::ToString::to_string);
                if task_id.as_deref() == Some("taskHistory.json") {
                    continue;
                }

                let meta_path = path.join("task_metadata.json");
                let ui_messages_path = path.join("ui_messages.json");
                let api_messages_path = path.join("api_conversation_history.json");

                // Prefer UI messages as they are user-facing. Fallback to API history.
                let source_file = if ui_messages_path.exists() {
                    Some(ui_messages_path)
                } else if api_messages_path.exists() {
                    Some(api_messages_path)
                } else {
                    None
                };

                let Some(file) = source_file else {
                    continue;
                };

                // Skip files not modified since last scan (incremental indexing)
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }

                let data = match fs::read_to_string(&file) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::debug!(path = %file.display(), error = %e, "cline: skipping unreadable file");
                        continue;
                    }
                };
                let val: Value = match serde_json::from_str(&data) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(path = %file.display(), error = %e, "cline skipping malformed JSON");
                        continue;
                    }
                };

                let mut messages = Vec::new();
                if let Some(arr) = val.as_array() {
                    for item in arr {
                        // Use parse_timestamp to handle both i64 milliseconds and ISO-8601 strings
                        let created = item
                            .get("timestamp")
                            .or_else(|| item.get("created_at"))
                            .or_else(|| item.get("ts"))
                            .and_then(parse_timestamp);

                        // NOTE: Do NOT filter individual messages by timestamp here!
                        // The file-level check in file_modified_since() is sufficient.
                        // Filtering messages would cause older messages to be lost when
                        // the file is re-indexed after new messages are added.

                        let role = item
                            .get("role")
                            .or_else(|| item.get("type"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("agent");

                        let content = item
                            .get("content")
                            .or_else(|| item.get("text"))
                            .or_else(|| item.get("message"))
                            .map(flatten_content)
                            .unwrap_or_default();

                        if content.trim().is_empty() {
                            continue;
                        }

                        messages.push(NormalizedMessage {
                            idx: i64::try_from(messages.len()).unwrap_or(i64::MAX), // preserve original order for stable sorting
                            role: role.to_string(),
                            author: None,
                            created_at: created,
                            content,
                            extra: item.clone(),
                            snippets: Vec::new(),
                        });
                    }
                }

                if messages.is_empty() {
                    continue;
                }

                // Sort by timestamp (missing timestamps go last), preserving original order
                messages.sort_by(|a, b| {
                    let a_ts = a.created_at.unwrap_or(i64::MAX);
                    let b_ts = b.created_at.unwrap_or(i64::MAX);
                    a_ts.cmp(&b_ts).then_with(|| a.idx.cmp(&b.idx))
                });

                // Re-index
                crate::types::reindex_messages(&mut messages);

                let mut title = None;
                let mut workspace = None;

                if meta_path.exists()
                    && let Ok(s) = fs::read_to_string(&meta_path)
                    && let Ok(v) = serde_json::from_str::<Value>(&s)
                {
                    title = v
                        .get("title")
                        .and_then(|t| t.as_str())
                        .map(std::string::ToString::to_string);
                    // Try to find workspace path
                    // Cline doesn't standardize this in metadata, but sometimes it's there or in state.
                    // We check common keys.
                    workspace = v
                        .get("rootPath")
                        .or_else(|| v.get("cwd"))
                        .or_else(|| v.get("workspace"))
                        .and_then(|s| s.as_str())
                        .map(PathBuf::from);
                }

                // Fallback title from first message
                if title.is_none() {
                    title = messages
                        .first()
                        .and_then(|m| m.content.lines().next())
                        .map(|s| s.chars().take(100).collect());
                }

                convs.push(NormalizedConversation {
                    agent_slug: "cline".to_string(),
                    external_id: task_id,
                    title,
                    workspace,
                    source_path: path.clone(),
                    started_at: messages.iter().filter_map(|m| m.created_at).min(),
                    ended_at: messages.iter().filter_map(|m| m.created_at).max(),
                    metadata: serde_json::json!({"source": "cline"}),
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
    use std::path::Path;
    use tempfile::TempDir;

    // =====================================================
    // Constructor Tests
    // =====================================================

    #[test]
    fn new_creates_connector() {
        let connector = ClineConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = ClineConnector;
        let _ = connector;
    }

    // =====================================================
    // Helper: Create Cline storage structure
    // =====================================================

    fn create_cline_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join("claude-dev");
        fs::create_dir_all(&storage).unwrap();
        storage
    }

    fn create_task_dir(storage: &Path, task_id: &str) -> PathBuf {
        let task_dir = storage.join(task_id);
        fs::create_dir_all(&task_dir).unwrap();
        task_dir
    }

    // =====================================================
    // scan() Tests with ui_messages.json
    // =====================================================

    #[test]
    fn scan_parses_ui_messages_simple() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-001");

        let messages = json!([
            {"role": "user", "content": "Hello Cline!", "timestamp": 1733000000},
            {"role": "assistant", "content": "Hello! How can I help?", "timestamp": 1733000001}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Cline!");
        assert_eq!(convs[0].messages[1].role, "assistant");
    }

    #[test]
    fn scan_prefers_ui_messages_over_api_history() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-prefer");

        // Both files exist
        let ui = json!([{"role": "user", "content": "From UI"}]);
        let api = json!([{"role": "user", "content": "From API"}]);
        fs::write(task_dir.join("ui_messages.json"), ui.to_string()).unwrap();
        fs::write(
            task_dir.join("api_conversation_history.json"),
            api.to_string(),
        )
        .unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].content, "From UI");
    }

    #[test]
    fn scan_falls_back_to_api_history() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-api");

        // Only API history exists
        let api = json!([{"role": "user", "content": "From API history"}]);
        fs::write(
            task_dir.join("api_conversation_history.json"),
            api.to_string(),
        )
        .unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].content, "From API history");
    }

    // =====================================================
    // scan() Tests with task_metadata.json
    // =====================================================

    #[test]
    fn scan_extracts_title_from_metadata() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-meta");

        let messages = json!([{"role": "user", "content": "Test"}]);
        let metadata = json!({"title": "My Cline Task"});
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();
        fs::write(task_dir.join("task_metadata.json"), metadata.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("My Cline Task".to_string()));
    }

    #[test]
    fn scan_extracts_workspace_from_root_path() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-ws");

        let messages = json!([{"role": "user", "content": "Test"}]);
        let metadata = json!({"rootPath": "/home/user/project"});
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();
        fs::write(task_dir.join("task_metadata.json"), metadata.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/project"))
        );
    }

    #[test]
    fn scan_extracts_workspace_from_cwd() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-cwd");

        let messages = json!([{"role": "user", "content": "Test"}]);
        let metadata = json!({"cwd": "/home/user/cwd-project"});
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();
        fs::write(task_dir.join("task_metadata.json"), metadata.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/cwd-project"))
        );
    }

    #[test]
    fn scan_extracts_workspace_from_workspace_key() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-ws-key");

        let messages = json!([{"role": "user", "content": "Test"}]);
        let metadata = json!({"workspace": "/home/user/ws"});
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();
        fs::write(task_dir.join("task_metadata.json"), metadata.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].workspace, Some(PathBuf::from("/home/user/ws")));
    }

    // =====================================================
    // Message Parsing Tests
    // =====================================================

    #[test]
    fn scan_parses_role_from_type_field() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-type");

        let messages = json!([{"type": "userMessage", "content": "Test"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].role, "userMessage");
    }

    #[test]
    fn scan_parses_content_from_text_field() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-text");

        let messages = json!([{"role": "user", "text": "Content from text field"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].content, "Content from text field");
    }

    #[test]
    fn scan_parses_content_from_message_field() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-msg");

        let messages = json!([{"role": "user", "message": "Content from message field"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].content, "Content from message field");
    }

    #[test]
    fn scan_parses_timestamp() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-ts");

        let messages = json!([{"role": "user", "content": "Test", "timestamp": 1733000000}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].created_at, Some(1733000000000));
    }

    #[test]
    fn scan_parses_created_at() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-created");

        let messages = json!([{"role": "user", "content": "Test", "created_at": 1733000001}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].created_at, Some(1733000001000));
    }

    #[test]
    fn scan_parses_ts() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-ts-field");

        let messages = json!([{"role": "user", "content": "Test", "ts": 1733000002}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].created_at, Some(1733000002000));
    }

    #[test]
    fn scan_skips_empty_content() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-empty");

        let messages = json!([
            {"role": "user", "content": "Valid"},
            {"role": "assistant", "content": ""},
            {"role": "assistant", "content": "   "}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages.len(), 1);
    }

    #[test]
    fn scan_sorts_messages_by_timestamp() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-sort");

        // Messages out of order
        let messages = json!([
            {"role": "assistant", "content": "Later", "timestamp": 1733000100},
            {"role": "user", "content": "Earlier", "timestamp": 1733000000}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].content, "Earlier");
        assert_eq!(convs[0].messages[1].content, "Later");
    }

    #[test]
    fn scan_assigns_sequential_indices() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-idx");

        let messages = json!([
            {"role": "user", "content": "First", "timestamp": 1},
            {"role": "assistant", "content": "Second", "timestamp": 2},
            {"role": "user", "content": "Third", "timestamp": 3}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].idx, 0);
        assert_eq!(convs[0].messages[1].idx, 1);
        assert_eq!(convs[0].messages[2].idx, 2);
    }

    #[test]
    fn scan_defaults_role_to_agent() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-no-role");

        let messages = json!([{"content": "No role field"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].role, "agent");
    }

    // =====================================================
    // Title Extraction Tests
    // =====================================================

    #[test]
    fn scan_extracts_title_from_first_message_if_no_metadata() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-no-meta");

        let messages = json!([
            {"role": "user", "content": "First line\nSecond line"},
            {"role": "assistant", "content": "Response"}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("First line".to_string()));
    }

    #[test]
    fn scan_truncates_long_titles() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-long-title");

        let long_content = "x".repeat(200);
        let messages = json!([{"role": "user", "content": long_content}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title.as_ref().unwrap().len(), 100);
    }

    // =====================================================
    // External ID and Agent Slug Tests
    // =====================================================

    #[test]
    fn scan_uses_task_dir_name_as_external_id() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "unique-task-id-123");

        let messages = json!([{"role": "user", "content": "Test"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].external_id, Some("unique-task-id-123".to_string()));
    }

    #[test]
    fn scan_sets_agent_slug_to_cline() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-slug");

        let messages = json!([{"role": "user", "content": "Test"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].agent_slug, "cline");
    }

    // =====================================================
    // Timestamp Tests
    // =====================================================

    #[test]
    fn scan_sets_started_at_from_first_message() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-start");

        let messages = json!([
            {"role": "user", "content": "First", "timestamp": 1733000000},
            {"role": "assistant", "content": "Last", "timestamp": 1733000100}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].started_at, Some(1733000000000));
        assert_eq!(convs[0].ended_at, Some(1733000100000));
    }

    // =====================================================
    // Edge Cases
    // =====================================================

    #[test]
    fn scan_handles_empty_storage() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_task_history_json() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);

        // This is a file, not a dir, but the code checks for dir name
        let task_history_dir = storage.join("taskHistory.json");
        fs::create_dir_all(&task_history_dir).unwrap();
        let messages = json!([{"role": "user", "content": "Test"}]);
        fs::write(
            task_history_dir.join("ui_messages.json"),
            messages.to_string(),
        )
        .unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should be skipped
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_dir_without_message_files() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-no-files");
        // Don't create any message files

        // Create metadata only
        let metadata = json!({"title": "No messages"});
        fs::write(task_dir.join("task_metadata.json"), metadata.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_invalid_json() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-invalid");

        fs::write(task_dir.join("ui_messages.json"), "not valid json").unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_empty_messages_array() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-empty-arr");

        let messages = json!([]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_handles_multiple_tasks() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);

        for i in 1..=3 {
            let task_dir = create_task_dir(&storage, &format!("task-{i}"));
            let messages = json!([{"role": "user", "content": format!("Task {i}")}]);
            fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();
        }

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 3);
    }

    #[test]
    fn scan_skips_non_directory_entries() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);

        // Create a file instead of directory
        fs::write(storage.join("not-a-dir.json"), "{}").unwrap();

        // Create a real task
        let task_dir = create_task_dir(&storage, "real-task");
        let messages = json!([{"role": "user", "content": "Test"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Only the real task should be processed
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn scan_sets_metadata_source() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-meta-src");

        let messages = json!([{"role": "user", "content": "Test"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["source"], "cline");
    }

    // =====================================================
    // Edge case tests — malformed input robustness (br-2w98)
    // =====================================================

    #[test]
    fn scan_truncated_json_skips_task() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-trunc");

        // Write truncated JSON
        fs::write(
            task_dir.join("ui_messages.json"),
            r#"[{"role": "user", "content": "Hello"#,
        )
        .unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0, "truncated JSON should be skipped");
    }

    #[test]
    fn scan_json_object_instead_of_array_skips_task() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-obj");

        // JSON object instead of array
        let content = json!({"role": "user", "content": "Not an array"});
        fs::write(task_dir.join("ui_messages.json"), content.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // val.as_array() returns None for objects, so task is skipped
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_type_mismatch_in_messages_skips_bad_entries() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-mismatch");

        let messages = json!([
            // String instead of object
            "not a message object",
            // Number
            42,
            // Null
            null,
            // Object with wrong field types (content is a number)
            {"role": "user", "content": 12345},
            // Valid entry
            {"role": "user", "content": "Valid message"}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid message");
    }

    #[test]
    fn scan_deeply_nested_json_does_not_stack_overflow() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-deep");

        // Build deeply nested JSON (200 levels)
        let mut nested = String::new();
        for _ in 0..200 {
            nested.push_str("{\"a\":");
        }
        nested.push('1');
        for _ in 0..200 {
            nested.push('}');
        }
        fs::write(task_dir.join("ui_messages.json"), &nested).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        // Should not panic or stack overflow
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn scan_large_message_body_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-large");

        let large_content = "x".repeat(1_000_000);
        let messages = json!([{"role": "user", "content": large_content}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content.len(), 1_000_000);
    }

    #[test]
    fn scan_null_bytes_in_content_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-null");

        let messages = json!([
            {"role": "user", "content": "before\u{0000}after"},
            {"role": "user", "content": "Clean message"}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(
            !convs[0].messages.is_empty(),
            "should extract at least the clean message"
        );
    }

    #[test]
    fn scan_malformed_metadata_does_not_crash() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-bad-meta");

        let messages = json!([{"role": "user", "content": "Test"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();
        // Write malformed metadata
        fs::write(task_dir.join("task_metadata.json"), "not valid json {{{").unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should still extract the conversation even with bad metadata
        assert_eq!(convs.len(), 1);
        // Title should fallback to first message content
        assert_eq!(convs[0].title, Some("Test".to_string()));
    }

    #[test]
    fn scan_mixed_valid_and_invalid_tasks() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);

        // Invalid task: bad JSON
        let bad_dir = create_task_dir(&storage, "task-bad");
        fs::write(bad_dir.join("ui_messages.json"), "invalid json").unwrap();

        // Valid task
        let good_dir = create_task_dir(&storage, "task-good");
        let messages = json!([{"role": "user", "content": "Valid task"}]);
        fs::write(good_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        // Another invalid: empty array
        let empty_dir = create_task_dir(&storage, "task-empty-arr");
        fs::write(empty_dir.join("ui_messages.json"), "[]").unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1, "should only extract the valid task");
        assert_eq!(convs[0].messages[0].content, "Valid task");
    }

    #[test]
    fn scan_preserves_extra_fields_in_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-extra");

        let messages = json!([{
            "role": "user",
            "content": "Test",
            "customField": "customValue",
            "nestedData": {"key": "value"}
        }]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].extra["customField"], "customValue");
        assert_eq!(convs[0].messages[0].extra["nestedData"]["key"], "value");
    }
}
