use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::read_capped;
use super::{
    Connector, extract_invocations_from_content_blocks, file_modified_since, flatten_content,
    franken_detection_for_connector, parse_timestamp, utils::dedupe_path_key,
};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct ClineConnector;
impl Default for ClineConnector {
    fn default() -> Self {
        Self::new()
    }
}

const CLINE_EXTENSIONS: [&str; 2] = ["saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline"];

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
            base.join(".config/Code - Insiders/User/globalStorage"),
            base.join(".config/VSCodium/User/globalStorage"),
            base.join("Library/Application Support/Code/User/globalStorage"),
            base.join("Library/Application Support/Code - Insiders/User/globalStorage"),
            base.join("Library/Application Support/VSCodium/User/globalStorage"),
            base.join("AppData/Roaming/Code/User/globalStorage"),
            base.join("AppData/Roaming/Code - Insiders/User/globalStorage"),
            base.join("AppData/Roaming/VSCodium/User/globalStorage"),
        ];
        let cursor_roots = [
            base.join(".config/Cursor/User/globalStorage"),
            base.join("Library/Application Support/Cursor/User/globalStorage"),
            base.join("AppData/Roaming/Cursor/User/globalStorage"),
        ];
        for root in code_roots.iter().chain(cursor_roots.iter()) {
            for ext in &CLINE_EXTENSIONS {
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

    fn append_explicit_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        let base = Self::normalize_root_path(base);
        if Self::looks_like_storage(&base) {
            // A provider store, tasks directory, task or exact transcript is
            // already a complete scope. Do not widen it to adjacent stores.
            roots.push(base);
            return;
        }
        let file_name = base.file_name().and_then(|n| n.to_str());
        let is_config = file_name.is_some_and(|n| n == ".config");
        let is_app_support = file_name.is_some_and(|n| n == "Application Support");
        let is_appdata_roaming = file_name.is_some_and(|n| n == "Roaming")
            && base
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == "AppData"));
        let is_code_variant = file_name
            .is_some_and(|n| matches!(n, "Code" | "Code - Insiders" | "VSCodium" | "Cursor"));
        let is_user = file_name.is_some_and(|n| n == "User");
        let is_global_storage = file_name.is_some_and(|n| n == "globalStorage");

        let mut storage_roots: Vec<PathBuf> = Vec::new();

        if is_global_storage {
            storage_roots.push(base.clone());
        }

        if is_config {
            storage_roots.push(base.join("Code/User/globalStorage"));
            storage_roots.push(base.join("Code - Insiders/User/globalStorage"));
            storage_roots.push(base.join("VSCodium/User/globalStorage"));
            storage_roots.push(base.join("Cursor/User/globalStorage"));
        }

        if is_app_support {
            storage_roots.push(base.join("Code/User/globalStorage"));
            storage_roots.push(base.join("Code - Insiders/User/globalStorage"));
            storage_roots.push(base.join("VSCodium/User/globalStorage"));
            storage_roots.push(base.join("Cursor/User/globalStorage"));
        }

        if is_appdata_roaming {
            storage_roots.push(base.join("Code/User/globalStorage"));
            storage_roots.push(base.join("Code - Insiders/User/globalStorage"));
            storage_roots.push(base.join("VSCodium/User/globalStorage"));
            storage_roots.push(base.join("Cursor/User/globalStorage"));
        }

        if is_code_variant {
            storage_roots.push(base.join("User/globalStorage"));
        }

        if is_user {
            storage_roots.push(base.join("globalStorage"));
        }

        if !(is_config
            || is_app_support
            || is_appdata_roaming
            || is_code_variant
            || is_user
            || is_global_storage)
        {
            storage_roots.push(base.join(".config/Code/User/globalStorage"));
            storage_roots.push(base.join(".config/Code - Insiders/User/globalStorage"));
            storage_roots.push(base.join(".config/VSCodium/User/globalStorage"));
            storage_roots.push(base.join(".config/Cursor/User/globalStorage"));
            storage_roots.push(base.join("Library/Application Support/Code/User/globalStorage"));
            storage_roots
                .push(base.join("Library/Application Support/Code - Insiders/User/globalStorage"));
            storage_roots
                .push(base.join("Library/Application Support/VSCodium/User/globalStorage"));
            storage_roots.push(base.join("Library/Application Support/Cursor/User/globalStorage"));
            storage_roots.push(base.join("AppData/Roaming/Code/User/globalStorage"));
            storage_roots.push(base.join("AppData/Roaming/Code - Insiders/User/globalStorage"));
            storage_roots.push(base.join("AppData/Roaming/VSCodium/User/globalStorage"));
            storage_roots.push(base.join("AppData/Roaming/Cursor/User/globalStorage"));
        }

        for root in storage_roots {
            for ext in &CLINE_EXTENSIONS {
                let candidate = root.join(ext);
                if candidate.exists() && Self::looks_like_storage(&candidate) {
                    roots.push(candidate);
                }
            }
        }
    }

    fn is_message_path(path: &Path) -> bool {
        path.file_name().is_some_and(|name| {
            name == "ui_messages.json" || name == "api_conversation_history.json"
        })
    }

    fn task_source(task_dir: &Path) -> Option<PathBuf> {
        if task_dir
            .file_name()
            .is_some_and(|name| name == "taskHistory.json")
        {
            return None;
        }
        // UI history is the user-facing transcript. Keep API history as the
        // fallback only when that file is absent, as in the original adapter.
        ["ui_messages.json", "api_conversation_history.json"]
            .into_iter()
            .map(|name| task_dir.join(name))
            .find(|path| path.is_file())
    }

    fn looks_like_storage(path: &Path) -> bool {
        if Self::is_message_path(path)
            || path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                n.contains("claude-dev") || n.contains("roo-cline") || n == "tasks"
            })
            || path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == "tasks"))
            || Self::task_source(path).is_some()
            || Self::contains_task_sources(&path.join("tasks"))
        {
            return true;
        }

        Self::contains_task_sources(path)
    }

    fn contains_task_sources(path: &Path) -> bool {
        fs::read_dir(path).is_ok_and(|mut entries| {
            entries.any(|entry| {
                entry.is_ok_and(|entry| {
                    let path = entry.path();
                    path.is_dir() && Self::task_source(&path).is_some()
                })
            })
        })
    }

    fn is_storage_container(path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                matches!(
                    name,
                    ".config"
                        | "Application Support"
                        | "Code"
                        | "Code - Insiders"
                        | "VSCodium"
                        | "Cursor"
                        | "User"
                        | "globalStorage"
                ) || (name == "Roaming"
                    && path
                        .parent()
                        .is_some_and(|parent| parent.file_name().is_some_and(|n| n == "AppData")))
            })
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let override_root = Self::normalize_root_path(&ctx.data_dir);
        let mut roots: Vec<ScanRoot> = if ctx.use_default_detection() {
            // A data_dir that names an extension dir scopes directly; a
            // data_dir that is a VS Code base (globalStorage, User,
            // Code variant, platform root) derives its ext dirs via the
            // same expansion explicit roots get, so a mirrored base is
            // not silently ignored in favor of the live machine.
            let mut derived = Vec::new();
            Self::append_explicit_roots(&mut derived, &override_root);
            if !derived.is_empty() {
                derived.into_iter().map(ScanRoot::local).collect()
            } else if Self::is_storage_container(&override_root) {
                // A missing or empty selected VS Code store must not read
                // unrelated live histories from the current machine.
                Vec::new()
            } else {
                Self::storage_roots()
                    .into_iter()
                    .map(ScanRoot::local)
                    .collect()
            }
        } else {
            let mut explicit = Vec::new();
            for root in &ctx.scan_roots {
                let mut paths = Vec::new();
                Self::append_explicit_roots(&mut paths, &root.path);
                explicit.extend(paths.into_iter().map(|path| root.with_path(path)));
            }
            explicit
        };

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    fn source_files(root: &Path) -> Vec<PathBuf> {
        if Self::is_message_path(root) {
            return root
                .is_file()
                .then(|| root.to_path_buf())
                .into_iter()
                .collect();
        }
        if let Some(source) = Self::task_source(root) {
            return vec![source];
        }
        if root
            .parent()
            .is_some_and(|parent| parent.file_name().is_some_and(|name| name == "tasks"))
        {
            // A selected native task is terminal even if its transcript is
            // absent. Never replace it with a nested task or artifact.
            return Vec::new();
        }

        let mut files = Vec::new();
        // Native Cline writes <globalStorage>/tasks/<id> (disk.ts,
        // ensureTaskDirectoryExists). Preserve direct <store>/<id> histories
        // too, without recursively reading arbitrary extension directories.
        for directory in [root.to_path_buf(), root.join("tasks")] {
            if !directory.is_dir() {
                continue;
            }
            let entries = match fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(err) => {
                    tracing::debug!(path = %directory.display(), error = %err, "cline: skipping unreadable task directory");
                    continue;
                }
            };
            for entry in entries.flatten() {
                let task_dir = entry.path();
                if task_dir.is_dir()
                    && let Some(source) = Self::task_source(&task_dir)
                {
                    files.push(source);
                }
            }
        }
        files.sort();
        files.dedup();
        files
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        let mut seen_task_dirs = HashSet::new();
        for root in Self::source_roots(ctx) {
            for file in Self::source_files(&root.path) {
                let Some(task_dir) = file.parent() else {
                    continue;
                };
                // An ancestor of the selected store may be a symlink too.
                // Keep the original path/provenance in the source record,
                // but compare actual task directories across overlapping roots.
                let task_key =
                    fs::canonicalize(task_dir).unwrap_or_else(|_| dedupe_path_key(task_dir));
                if !seen_task_dirs.insert(task_key) {
                    continue;
                }
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }

                out.push(
                    DiscoveredSourceFile::new(
                        "cline",
                        &root,
                        file.clone(),
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );

                let meta_path = task_dir.join("task_metadata.json");
                if meta_path.is_file() {
                    out.push(
                        DiscoveredSourceFile::new(
                            "cline",
                            &root,
                            meta_path,
                            DiscoveredSourceRole::MetadataSidecar,
                            false,
                        )
                        .with_fs_metadata(),
                    );
                }
            }
        }
        out
    }
}

impl Connector for ClineConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("cline").unwrap_or_else(DetectionResult::not_found)
    }

    #[allow(clippy::too_many_lines)]
    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        // Use exactly the discovery selection, including its UI/API preference,
        // incremental filter and cross-root task deduplication.
        for source in Self::discover_sources(ctx) {
            if source.role != DiscoveredSourceRole::PrimarySessionLog {
                continue;
            }
            let file = source.source_path;
            let Some(path) = file.parent() else {
                continue;
            };
            let task_id = path
                .file_name()
                .and_then(|s| s.to_str())
                .map(std::string::ToString::to_string);
            let meta_path = path.join("task_metadata.json");

            // Task logs embed base64 screenshots and routinely reach
            // tens of MB; enforce the project's 100MB scan cap.
            let data = match read_capped(&file) {
                Ok(Some(d)) => d.trim_start_matches('\u{feff}').to_string(),
                Ok(None) => {
                    tracing::debug!(path = %file.display(), "cline: file exceeds the scan size cap; skipping");
                    continue;
                }
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
                let mut legacy_usage = if file
                    .file_name()
                    .is_some_and(|name| name == "ui_messages.json")
                {
                    super::token_extraction::cline_legacy_usage_attachments(arr)
                } else {
                    std::collections::BTreeMap::new()
                };
                for (index, item) in arr.iter().enumerate() {
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

                    let role = normalized_role(item);

                    let content_val = item
                        .get("content")
                        .or_else(|| item.get("text"))
                        .or_else(|| item.get("message"));
                    let content = content_val.map(flatten_content).unwrap_or_default();

                    let attached_usage = legacy_usage.remove(&index);
                    let has_attached_usage = attached_usage
                        .as_ref()
                        .and_then(Value::as_object)
                        .is_some_and(|usage| !usage.is_empty());
                    if content.trim().is_empty() && !has_attached_usage {
                        continue;
                    }
                    let mut extra = item.clone();
                    if let Some(usage) = attached_usage {
                        // The original start/finish rows and their content stay
                        // intact; only selected counters are copied to cass.
                        if !extra.get("cass").is_some_and(Value::is_object) {
                            extra["cass"] = serde_json::json!({});
                        }
                        extra["cass"]["token_usage"] = usage;
                    }

                    messages.push(NormalizedMessage {
                        idx: i64::try_from(messages.len()).unwrap_or(i64::MAX), // preserve original order for stable sorting
                        role: role.to_string(),
                        author: None,
                        created_at: created,
                        content,
                        extra,
                        invocations: content_val
                            .map_or_else(Vec::new, extract_invocations_from_content_blocks),
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

            let (mut title, workspace) = if meta_path.exists()
                && let Ok(s) = fs::read_to_string(&meta_path)
                && let Ok(v) = serde_json::from_str::<Value>(&s)
            {
                let title = v
                    .get("title")
                    .and_then(|t| t.as_str())
                    .map(std::string::ToString::to_string);
                // Try to find workspace path
                // Cline doesn't standardize this in metadata, but sometimes it's there or in state.
                // We check common keys.
                let workspace = v
                    .get("rootPath")
                    .or_else(|| v.get("cwd"))
                    .or_else(|| v.get("workspace"))
                    .and_then(|s| s.as_str())
                    .map(PathBuf::from);
                (title, workspace)
            } else {
                (None, None)
            };

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
                source_path: file.clone(),
                started_at: messages.iter().filter_map(|m| m.created_at).min(),
                ended_at: messages.iter().filter_map(|m| m.created_at).max(),
                metadata: serde_json::json!({"source": "cline"}),
                messages,
            });
        }

        Ok(convs)
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

fn normalized_role(item: &Value) -> &str {
    if let Some(role) = item.get("role").and_then(Value::as_str) {
        return role;
    }
    // Native Cline UI records use ask/say for their display type, not their
    // speaker. Keep the subtype in raw extra while exposing useful roles.
    // See cline/cline's ExtensionMessage.ts and sdk/message-translator.ts.
    match item.get("type").and_then(Value::as_str) {
        Some("say") => match item.get("say").and_then(Value::as_str) {
            Some("task" | "user_feedback" | "user_feedback_diff") => "user",
            Some("command_output" | "mcp_server_response" | "browser_action_result") => "tool",
            _ => "assistant",
        },
        Some("ask") => "assistant",
        Some(legacy_type) => legacy_type,
        None => "agent",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
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
            {"role": "user", "content": "Hello Cline!", "timestamp": 1_733_000_000},
            {"role": "assistant", "content": "Hello! How can I help?", "timestamp": 1_733_000_001}
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
    fn scan_with_explicit_roots_uses_scan_roots() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-explicit");

        let messages = json!([
            {"role": "user", "content": "Explicit root", "timestamp": 1_733_000_000}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::with_roots(
            dir.path().join("not-cline"),
            vec![ScanRoot::local(storage.clone())],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Explicit root");
    }

    #[test]
    fn scan_with_global_storage_scan_root() {
        let dir = TempDir::new().unwrap();
        let global_storage = dir.path().join("globalStorage");
        let storage = global_storage.join("saoudrizwan.claude-dev");
        let task_dir = create_task_dir(&storage, "task-global");

        let messages = json!([{"role": "user", "content": "From globalStorage"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::with_roots(
            dir.path().join("not-cline"),
            vec![ScanRoot::local(global_storage)],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "From globalStorage");
    }

    #[test]
    fn scan_with_explicit_config_root_finds_storage() {
        let dir = TempDir::new().unwrap();
        let config_root = dir.path().join(".config");
        let storage = config_root.join("Code/User/globalStorage/saoudrizwan.claude-dev");
        let task_dir = create_task_dir(&storage, "task-config");

        let messages = json!([{"role": "user", "content": "From .config"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::with_roots(
            dir.path().join("not-cline"),
            vec![ScanRoot::local(config_root)],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "From .config");
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
    fn discover_source_files_includes_primary_and_metadata_sidecar() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-discovery");

        let messages = json!([{"role": "user", "content": "Test"}]);
        let metadata = json!({"title": "Discovered Cline Task"});
        let primary = task_dir.join("ui_messages.json");
        let sidecar = task_dir.join("task_metadata.json");
        fs::write(&primary, messages.to_string()).unwrap();
        fs::write(&sidecar, metadata.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let discovered = connector.discover_source_files(&ctx).unwrap();

        assert_eq!(discovered.len(), 2);
        assert!(discovered.iter().any(|source| {
            source.source_path == primary
                && source.role == DiscoveredSourceRole::PrimarySessionLog
                && source.required_for_reconstruction
        }));
        assert!(discovered.iter().any(|source| {
            source.source_path == sidecar
                && source.role == DiscoveredSourceRole::MetadataSidecar
                && !source.required_for_reconstruction
        }));
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
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

        let messages = json!([{"role": "user", "content": "Test", "timestamp": 1_733_000_000}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].created_at, Some(1_733_000_000_000));
    }

    #[test]
    fn scan_parses_created_at() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-created");

        let messages = json!([{"role": "user", "content": "Test", "created_at": 1_733_000_001}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].created_at, Some(1_733_000_001_000));
    }

    #[test]
    fn scan_parses_ts() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-ts-field");

        let messages = json!([{"role": "user", "content": "Test", "ts": 1_733_000_002}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].created_at, Some(1_733_000_002_000));
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
            {"role": "assistant", "content": "Later", "timestamp": 1_733_000_100},
            {"role": "user", "content": "Earlier", "timestamp": 1_733_000_000}
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
            {"role": "user", "content": "First", "timestamp": 1_733_000_000},
            {"role": "assistant", "content": "Last", "timestamp": 1_733_000_100}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].started_at, Some(1_733_000_000_000));
        assert_eq!(convs[0].ended_at, Some(1_733_000_100_000));
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
