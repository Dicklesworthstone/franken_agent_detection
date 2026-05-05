//! Connector for Qwen Code (Alibaba) session logs.
//!
//! Qwen Code stores sessions as JSON files at:
//! - `~/.qwen/tmp/<project-hash>/chats/session-<timestamp>-<id>.json`
//!
//! Each file is a complete JSON object containing:
//! - `sessionId`, `projectHash`, `startTime`, `lastUpdated`
//! - `messages` array with objects: `id`, `timestamp`, `type`, `content`, `tokens`
//!
//! Message types: `user`, `qwen` (assistant)

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::{
    Connector, file_modified_since, flatten_content, franken_detection_for_connector,
    parse_timestamp, utils::dedupe_path_key,
};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct QwenConnector;

impl Default for QwenConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl QwenConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Get the Qwen tmp root directory.
    fn tmp_root() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".qwen")
            .join("tmp")
    }

    fn looks_like_qwen_storage(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        path_str.contains(".qwen") && path_str.contains("tmp")
    }

    fn append_qwen_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        if Self::looks_like_qwen_storage(base) {
            roots.push(base.to_path_buf());
            return;
        }

        if base.file_name().is_some_and(|name| name == ".qwen") {
            let candidate = base.join("tmp");
            if candidate.exists() {
                roots.push(candidate);
            }
            return;
        }

        let candidate = base.join(".qwen/tmp");
        if candidate.exists() {
            roots.push(candidate);
        }
    }

    /// Find all session-*.json files under a root.
    fn session_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if !root.exists() {
            return out;
        }

        for entry in WalkDir::new(root).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }

            let name = entry.file_name().to_str().unwrap_or("");
            if name.starts_with("session-")
                && entry
                    .path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            {
                out.push(entry.path().to_path_buf());
            }
        }

        out.sort();
        out
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots: Vec<ScanRoot> = Vec::new();
        if ctx.use_default_detection() {
            if Self::looks_like_qwen_storage(&ctx.data_dir) && ctx.data_dir.exists() {
                roots.push(ScanRoot::local(ctx.data_dir.clone()));
            }
            let root = Self::tmp_root();
            if root.exists() {
                roots.push(ScanRoot::local(root));
            }
        } else {
            for scan_root in &ctx.scan_roots {
                let mut candidates = Vec::new();
                Self::append_qwen_roots(&mut candidates, &scan_root.path);
                roots.extend(candidates.into_iter().map(|path| scan_root.with_path(path)));
            }

            if ctx.data_dir.exists() {
                let mut candidates = Vec::new();
                Self::append_qwen_roots(&mut candidates, &ctx.data_dir);
                roots.extend(candidates.into_iter().map(ScanRoot::local));
            }
        }

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        let mut seen_files: HashSet<PathBuf> = HashSet::new();
        for root in Self::source_roots(ctx) {
            if !root.path.exists() {
                continue;
            }
            for session_path in Self::session_files(&root.path) {
                if !seen_files.insert(dedupe_path_key(&session_path)) {
                    continue;
                }
                if !file_modified_since(&session_path, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "qwen",
                        &root,
                        session_path.clone(),
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
                if let Some(project_dir) = session_path.parent().and_then(Path::parent) {
                    let config = project_dir.join("config.json");
                    if config.exists() {
                        out.push(
                            DiscoveredSourceFile::new(
                                "qwen",
                                &root,
                                config,
                                DiscoveredSourceRole::MetadataSidecar,
                                false,
                            )
                            .with_fs_metadata(),
                        );
                    }
                }
            }
        }
        out
    }
}

impl Connector for QwenConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("qwen").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut roots: Vec<PathBuf> = Self::source_roots(ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();

        if roots.is_empty() {
            return Ok(Vec::new());
        }

        roots.sort();
        roots.dedup();

        let mut convs = Vec::new();
        let mut seen_files: HashSet<PathBuf> = HashSet::new();

        for root in roots {
            if !root.exists() {
                continue;
            }

            for session_path in Self::session_files(&root) {
                if !seen_files.insert(dedupe_path_key(&session_path)) {
                    continue;
                }

                if !file_modified_since(&session_path, ctx.since_ts) {
                    continue;
                }

                match parse_qwen_session(&session_path) {
                    Ok(Some(conv)) => convs.push(conv),
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(
                            path = %session_path.display(),
                            error = %e,
                            "qwen parse error"
                        );
                    }
                }
            }
        }

        Ok(convs)
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

/// Parse a Qwen session JSON file into a `NormalizedConversation`.
fn parse_qwen_session(path: &Path) -> Result<Option<NormalizedConversation>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read qwen session {}", path.display()))?;

    let val: Value = serde_json::from_str(&content)
        .with_context(|| format!("parse qwen session JSON {}", path.display()))?;

    let session_id = val
        .get("sessionId")
        .and_then(|v| v.as_str())
        .map(String::from);
    let project_hash = val
        .get("projectHash")
        .and_then(|v| v.as_str())
        .map(String::from);

    let started_at = val.get("startTime").and_then(parse_timestamp);
    let ended_at = val.get("lastUpdated").and_then(parse_timestamp);

    let Some(raw_messages) = val.get("messages").and_then(|v| v.as_array()) else {
        return Ok(None);
    };

    let mut messages = Vec::new();

    for raw_msg in raw_messages {
        let msg_type = raw_msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Normalize role: "qwen" -> "assistant", "user" -> "user"
        let role = match msg_type {
            "user" => "user".to_string(),
            "qwen" | "assistant" => "assistant".to_string(),
            _other => {
                // Unknown types normalized to assistant for forward compatibility
                "assistant".to_string()
            }
        };

        // Extract content (string or array)
        let content_val = raw_msg.get("content");
        let content_str = content_val.map(flatten_content).unwrap_or_default();

        if content_str.trim().is_empty() {
            continue;
        }

        let created = raw_msg.get("timestamp").and_then(parse_timestamp);

        messages.push(NormalizedMessage {
            idx: 0,
            role,
            author: None,
            created_at: created,
            content: content_str,
            extra: raw_msg.clone(),
            invocations: Vec::new(),
            snippets: Vec::new(),
        });
    }

    crate::types::reindex_messages(&mut messages);

    if messages.is_empty() {
        return Ok(None);
    }

    // Try to infer workspace from the directory structure
    // Pattern: ~/.qwen/tmp/<project-hash>/chats/session-*.json
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

    let metadata = serde_json::json!({
        "source": "qwen",
        "sessionId": session_id.as_deref(),
        "projectHash": project_hash.as_deref(),
    });

    Ok(Some(NormalizedConversation {
        agent_slug: "qwen".into(),
        external_id: session_id,
        title,
        workspace,
        source_path: path.to_path_buf(),
        started_at,
        ended_at,
        metadata,
        messages,
    }))
}

/// Try to infer workspace from the session path or nearby files.
/// Path pattern: `~/.qwen/tmp/<project-hash>/chats/session-*.json`
fn infer_workspace(path: &Path) -> Option<PathBuf> {
    // Go up to the project-hash directory (parent of "chats")
    let chats_dir = path.parent()?;
    let project_dir = chats_dir.parent()?;

    // Check for a config/workspace file in the project directory
    let config_path = project_dir.join("config.json");
    if let Ok(content) = fs::read_to_string(&config_path) {
        if let Ok(val) = serde_json::from_str::<Value>(&content) {
            for key in &["workspace", "projectPath", "cwd", "path"] {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // =========================================================================
    // Constructor tests
    // =========================================================================

    #[test]
    fn new_creates_connector() {
        let connector = QwenConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = QwenConnector;
        let _ = connector;
    }

    // =========================================================================
    // Helper to create Qwen storage layout
    // =========================================================================

    fn create_qwen_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join(".qwen").join("tmp");
        fs::create_dir_all(&storage).unwrap();
        storage
    }

    fn write_session_file(storage: &Path, project_hash: &str, filename: &str, content: &str) {
        let chats_dir = storage.join(project_hash).join("chats");
        fs::create_dir_all(&chats_dir).unwrap();
        let file_path = chats_dir.join(filename);
        fs::write(&file_path, content).unwrap();
    }

    // =========================================================================
    // Detection tests
    // =========================================================================

    #[test]
    fn detect_not_found_without_tmp_dir() {
        let connector = QwenConnector::new();
        let result = connector.detect();
        let _ = result.detected;
    }

    // =========================================================================
    // JSON parsing tests
    // =========================================================================

    #[test]
    fn scan_parses_basic_session() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "50ba1660-9b88-4500-8f25-dab05f90d790",
            "projectHash": "abc123",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "user",
                    "content": "Hello Qwen"
                },
                {
                    "id": "msg-002",
                    "timestamp": "2025-11-08T23:19:13.706Z",
                    "type": "qwen",
                    "content": "Hello! How can I help?"
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "abc123",
            "session-1731107950138-50ba1660.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "qwen");
        assert_eq!(
            convs[0].external_id,
            Some("50ba1660-9b88-4500-8f25-dab05f90d790".to_string())
        );
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Qwen");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert!(convs[0].messages[1].content.contains("How can I help"));
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn scan_with_explicit_roots_scans_all_roots() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let storage_a = create_qwen_storage(&dir_a);
        let storage_b = create_qwen_storage(&dir_b);

        let session_a = r#"{
            "sessionId": "sess-a",
            "projectHash": "hash-a",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                { "id": "msg-a", "timestamp": "2025-11-08T23:19:10.138Z", "type": "user", "content": "Hi A" }
            ]
        }"#;
        let session_b = r#"{
            "sessionId": "sess-b",
            "projectHash": "hash-b",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                { "id": "msg-b", "timestamp": "2025-11-08T23:19:10.138Z", "type": "user", "content": "Hi B" }
            ]
        }"#;

        write_session_file(&storage_a, "hash-a", "session-a.json", session_a);
        write_session_file(&storage_b, "hash-b", "session-b.json", session_b);

        let connector = QwenConnector::new();
        let ctx = ScanContext::with_roots(
            PathBuf::new(),
            vec![
                ScanRoot::local(dir_a.path().to_path_buf()),
                ScanRoot::local(dir_b.path().to_path_buf()),
            ],
            None,
        );

        let mut convs = connector.scan(&ctx).unwrap();
        convs.sort_by(|a, b| a.external_id.cmp(&b.external_id));
        let ids: Vec<_> = convs
            .iter()
            .filter_map(|c| c.external_id.as_deref())
            .collect();
        assert_eq!(ids, vec!["sess-a", "sess-b"]);
    }

    #[test]
    fn scan_with_explicit_root_at_qwen_dir() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-001",
            "projectHash": "hash-001",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                { "id": "msg-001", "timestamp": "2025-11-08T23:19:10.138Z", "type": "user", "content": "Hello Qwen" }
            ]
        }"#;
        write_session_file(&storage, "hash-001", "session-001.json", session_json);

        let qwen_dir = dir.path().join(".qwen");

        let connector = QwenConnector::new();
        let ctx = ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(qwen_dir)], None);

        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id, Some("sess-001".to_string()));
    }

    #[test]
    fn scan_extracts_metadata() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-meta",
            "projectHash": "proj-hash-001",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "user",
                    "content": "Test"
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "proj-hash-001",
            "session-1731107950138-meta.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["sessionId"], "sess-meta");
        assert_eq!(convs[0].metadata["projectHash"], "proj-hash-001");
        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
    }

    #[test]
    fn scan_generates_title_from_first_user_message() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-title",
            "projectHash": "proj1",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "user",
                    "content": "Explain the architecture of this codebase"
                },
                {
                    "id": "msg-002",
                    "timestamp": "2025-11-08T23:19:13.706Z",
                    "type": "qwen",
                    "content": "Sure, let me walk through it."
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "proj1",
            "session-1731107950138-title.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].title,
            Some("Explain the architecture of this codebase".to_string())
        );
    }

    #[test]
    fn scan_reads_workspace_from_config() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        // Create session
        let session_json = r#"{
            "sessionId": "sess-ws",
            "projectHash": "proj-ws",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "user",
                    "content": "hello"
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "proj-ws",
            "session-1731107950138-ws.json",
            session_json,
        );

        // Create config.json in project directory
        let project_dir = storage.join("proj-ws");
        fs::write(
            project_dir.join("config.json"),
            r#"{"workspace": "/home/user/my-project"}"#,
        )
        .unwrap();

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/my-project"))
        );
    }

    #[test]
    fn scan_multiple_sessions() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        for i in 1..=3 {
            let session_json = format!(
                r#"{{
                "sessionId": "sess-{i}",
                "projectHash": "proj1",
                "startTime": "2025-11-0{i}T10:00:00.000Z",
                "lastUpdated": "2025-11-0{i}T10:01:00.000Z",
                "messages": [
                    {{
                        "id": "msg-{i}",
                        "timestamp": "2025-11-0{i}T10:00:00.000Z",
                        "type": "user",
                        "content": "Message {i}"
                    }}
                ]
            }}"#
            );
            write_session_file(
                &storage,
                "proj1",
                &format!("session-17311079{i}0000-{i}.json"),
                &session_json,
            );
        }

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 3);
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn edge_empty_messages_returns_none() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-empty",
            "projectHash": "proj1",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": []
        }"#;
        write_session_file(
            &storage,
            "proj1",
            "session-1731107950138-empty.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs.is_empty());
    }

    #[test]
    fn edge_missing_messages_field() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-no-messages",
            "projectHash": "proj1"
        }"#;
        write_session_file(
            &storage,
            "proj1",
            "session-1731107950138-nomsg.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs.is_empty());
    }

    #[test]
    fn edge_empty_content_messages_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-empty-content",
            "projectHash": "proj1",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "user",
                    "content": "Has content"
                },
                {
                    "id": "msg-002",
                    "timestamp": "2025-11-08T23:19:11.000Z",
                    "type": "qwen",
                    "content": ""
                },
                {
                    "id": "msg-003",
                    "timestamp": "2025-11-08T23:19:12.000Z",
                    "type": "qwen",
                    "content": "   "
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "proj1",
            "session-1731107950138-emptyc.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Has content");
    }

    #[test]
    fn edge_malformed_json_returns_error_gracefully() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let chats_dir = storage.join("proj1").join("chats");
        fs::create_dir_all(&chats_dir).unwrap();
        fs::write(
            chats_dir.join("session-1731107950138-bad.json"),
            "not valid json {{{",
        )
        .unwrap();

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        // Should not propagate error, just skip
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn edge_array_content_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-arr",
            "projectHash": "proj1",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "qwen",
                    "content": [{"type": "text", "text": "Part A"}, {"type": "text", "text": "Part B"}]
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "proj1",
            "session-1731107950138-arr.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("Part A"));
        assert!(convs[0].messages[0].content.contains("Part B"));
    }

    #[test]
    fn unknown_message_types_normalized_to_assistant() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-unknown-types",
            "projectHash": "proj1",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "system",
                    "content": "System prompt text"
                },
                {
                    "id": "msg-002",
                    "timestamp": "2025-11-08T23:19:11.000Z",
                    "type": "metadata",
                    "content": "Some metadata"
                },
                {
                    "id": "msg-003",
                    "timestamp": "2025-11-08T23:19:12.000Z",
                    "type": "user",
                    "content": "Normal user msg"
                },
                {
                    "id": "msg-004",
                    "timestamp": "2025-11-08T23:19:13.000Z",
                    "type": "qwen",
                    "content": "Normal qwen msg"
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "proj1",
            "session-1731107950138-unknown.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 4);
        // "system" and "metadata" should both be normalized to "assistant"
        assert_eq!(convs[0].messages[0].role, "assistant");
        assert_eq!(convs[0].messages[1].role, "assistant");
        // Standard types preserved
        assert_eq!(convs[0].messages[2].role, "user");
        assert_eq!(convs[0].messages[3].role, "assistant");
    }

    #[test]
    fn edge_non_session_json_files_ignored() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        // Write a non-session JSON file
        let chats_dir = storage.join("proj1").join("chats");
        fs::create_dir_all(&chats_dir).unwrap();
        fs::write(chats_dir.join("config.json"), r#"{"setting": "value"}"#).unwrap();

        // Write a valid session file
        let session_json = r#"{
            "sessionId": "sess-valid",
            "projectHash": "proj1",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "user",
                    "content": "Valid message"
                }
            ]
        }"#;
        fs::write(
            chats_dir.join("session-1731107950138-valid.json"),
            session_json,
        )
        .unwrap();

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
    }
}
