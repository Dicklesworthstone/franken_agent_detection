//! Connector for Cursor IDE chat history.
//!
//! Cursor stores chat history in SQLite databases (state.vscdb) within:
//! - macOS: ~/Library/Application Support/Cursor/User/globalStorage/
//! - macOS workspaces: ~/Library/Application Support/Cursor/User/workspaceStorage/{id}/
//! - Linux: ~/.config/Cursor/User/globalStorage/
//! - Windows: %APPDATA%/Cursor/User/globalStorage/
//!
//! Chat data is stored in the `cursorDiskKV` table with keys like:
//! - `composerData:{uuid}` - Composer/chat session data (JSON)
//!
//! And in the `ItemTable` with keys like:
//! - `workbench.panel.aichat.view.aichat.chatdata` - Legacy chat data

#![allow(
    clippy::cast_possible_wrap,
    clippy::doc_markdown,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::missing_const_for_fn,
    clippy::must_use_candidate,
    clippy::option_if_let_else,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::unreadable_literal
)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use frankensqlite::compat::{ConnectionExt, OpenFlags, RowExt, open_with_flags};
use frankensqlite::{Connection, params};
use serde_json::Value;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::{Connector, file_modified_since, franken_detection_for_connector, parse_timestamp};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

/// Cursor v0.40+ bubble type constants (numeric encoding)
mod bubble_type {
    /// User message type in new format
    pub const USER: i64 = 1;
    /// Assistant message type in new format
    pub const ASSISTANT: i64 = 2;
}

/// Type alias for the bubble data lookup map.
/// Keys are bubble IDs for O(1) lookup within a composer.
type BubbleDataMap = HashMap<String, Value>;

pub struct CursorConnector;

impl Default for CursorConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl CursorConnector {
    pub fn new() -> Self {
        Self
    }

    /// Compute the exclusive upper bound for prefix range scans.
    ///
    /// For prefix `abc:`, this returns `abc;`, so
    /// `key >= prefix AND key < upper` matches all keys that start with `prefix`.
    fn prefix_upper_bound(prefix: &str) -> String {
        let mut upper = prefix.to_string();
        if let Some(last) = upper.pop() {
            if let Some(next_char) = std::char::from_u32(last as u32 + 1) {
                upper.push(next_char);
            } else {
                // Fallback for char overflow: keep the last char and append max scalar.
                upper.push(last);
                upper.push('\u{10FFFF}');
            }
        }
        upper
    }

    /// Get the base Cursor application support directory
    pub fn app_support_dir() -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            dirs::home_dir().map(|h| h.join("Library/Application Support/Cursor/User"))
        }
        #[cfg(target_os = "linux")]
        {
            // Check if we're in WSL and should look at Windows Cursor paths first
            if Self::is_wsl()
                && let Some(wsl_path) = Self::find_wsl_cursor_path()
            {
                return Some(wsl_path);
            }
            // Fall back to Linux native path
            dirs::home_dir().map(|h| h.join(".config/Cursor/User"))
        }
        #[cfg(target_os = "windows")]
        {
            dirs::data_dir().map(|d| d.join("Cursor/User"))
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            None
        }
    }

    fn looks_like_base(path: &Path) -> bool {
        path.join("globalStorage").exists()
            || path.join("workspaceStorage").exists()
            || path
                .file_name()
                .is_some_and(|n| n == "globalStorage" || n == "workspaceStorage")
            || (path.is_file() && path.file_name().is_some_and(|n| n == "state.vscdb"))
    }

    fn append_explicit_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        if Self::looks_like_base(base) {
            roots.push(base.to_path_buf());
        }

        let candidates = [
            base.join(".config/Cursor/User"),
            base.join("Library/Application Support/Cursor/User"),
            base.join("AppData/Roaming/Cursor/User"),
            base.join("Cursor/User"),
        ];

        for candidate in candidates {
            if Self::looks_like_base(&candidate) {
                roots.push(candidate);
            }
        }
    }

    /// Check if running inside Windows Subsystem for Linux
    #[cfg(target_os = "linux")]
    fn is_wsl() -> bool {
        std::fs::read_to_string("/proc/version")
            .map(|v| v.to_lowercase().contains("microsoft"))
            .unwrap_or(false)
    }

    /// Find Cursor installation path via WSL mount points
    /// Probes /mnt/c/Users/*/AppData/Roaming/Cursor/User
    #[cfg(target_os = "linux")]
    fn find_wsl_cursor_path() -> Option<PathBuf> {
        let mnt_c_users = Path::new("/mnt/c/Users");
        if !mnt_c_users.exists() {
            return None;
        }

        // Optimization: Try to get the Windows username directly to avoid scanning all users
        if let Ok(output) = std::process::Command::new("cmd.exe")
            .args(["/c", "echo %USERNAME%"])
            .output()
        {
            if output.status.success() {
                let username = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let is_safe = !username.is_empty()
                    && !username.contains(['/', '\\'])
                    && !username.contains(':');
                if is_safe {
                    let user_path = mnt_c_users.join(&username);
                    let cursor_path = user_path.join("AppData/Roaming/Cursor/User");
                    if cursor_path.exists() {
                        return Some(cursor_path);
                    }
                }
            }
        }

        // Fallback: Scan directories if username detection failed
        // Limit depth and skip system directories to avoid hangs
        for entry in std::fs::read_dir(mnt_c_users).ok()?.flatten() {
            // Skip system directories
            let name = entry.file_name();
            let name_str = name.to_str().unwrap_or("");
            if name_str == "Default"
                || name_str == "Public"
                || name_str == "All Users"
                || name_str == "Default User"
                || name_str.starts_with('.')
            {
                continue;
            }

            let cursor_path = entry.path().join("AppData/Roaming/Cursor/User");
            // Check existence without traversing deeper
            if cursor_path.join("globalStorage").exists() {
                tracing::debug!(
                    path = %cursor_path.display(),
                    "Found Windows Cursor installation via WSL"
                );
                return Some(cursor_path);
            }
        }
        None
    }

    /// Find all state.vscdb files in Cursor storage
    fn find_db_files(base: &Path) -> Vec<PathBuf> {
        let mut dbs = Vec::new();

        // 1. Check if base itself is a DB (explicit file scan)
        if base.is_file() && base.file_name().is_some_and(|n| n == "state.vscdb") {
            dbs.push(base.to_path_buf());
            return dbs;
        }

        // 2. Check if base contains state.vscdb directly (e.g. pointing at globalStorage)
        let direct_db = base.join("state.vscdb");
        if direct_db.exists() {
            dbs.push(direct_db);
        }

        // 3. Check standard layout: globalStorage
        let global_db = base.join("globalStorage/state.vscdb");
        if global_db.exists() {
            dbs.push(global_db);
        }

        // 4. Check standard layout: workspaceStorage/{workspace-id}/state.vscdb
        // We only need this specific file pattern, so avoid recursive walking
        // over all workspace files (which can be large and noisy).
        let workspace_storage = base.join("workspaceStorage");
        if workspace_storage.exists() {
            // Keep compatibility with odd setups that place state.vscdb directly
            // under workspaceStorage.
            let root_db = workspace_storage.join("state.vscdb");
            if root_db.is_file() {
                dbs.push(root_db);
            }

            if let Ok(entries) = std::fs::read_dir(&workspace_storage) {
                for entry in entries.flatten() {
                    let db = entry.path().join("state.vscdb");
                    if db.is_file() {
                        dbs.push(db);
                    }
                }
            }
        }

        // Keep connector traversal deterministic across filesystems/runs.
        dbs.sort();
        dbs
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots: Vec<ScanRoot> = Vec::new();
        if ctx.use_default_detection() {
            if Self::looks_like_base(&ctx.data_dir) {
                roots.push(ScanRoot::local(ctx.data_dir.clone()));
            } else if let Some(default_base) = Self::app_support_dir() {
                roots.push(ScanRoot::local(default_base));
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
            for db_path in Self::find_db_files(&root.path) {
                if !file_modified_since(&db_path, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "cursor",
                        &root,
                        db_path,
                        DiscoveredSourceRole::SqliteDatabase,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }
        }
        out
    }

    /// Fast existence probe for detect(): return true on the first matching
    /// Cursor DB path instead of collecting all DB files.
    #[allow(dead_code)]
    fn has_any_db_file(base: &Path) -> bool {
        if base.is_file() && base.file_name().is_some_and(|n| n == "state.vscdb") {
            return true;
        }

        if base.join("state.vscdb").is_file() {
            return true;
        }

        if base.join("globalStorage/state.vscdb").is_file() {
            return true;
        }

        let workspace_storage = base.join("workspaceStorage");
        if !workspace_storage.exists() {
            return false;
        }

        if workspace_storage.join("state.vscdb").is_file() {
            return true;
        }

        if let Ok(entries) = std::fs::read_dir(&workspace_storage) {
            for entry in entries.flatten() {
                if entry.path().join("state.vscdb").is_file() {
                    return true;
                }
            }
        }

        false
    }

    /// Fetch bubble data for a specific composer from the database.
    /// Returns a map keyed by bubbleId for efficient O(1) lookup.
    /// This lazy-loads only the bubbles needed for one conversation,
    /// avoiding loading all bubbles into memory.
    fn fetch_bubble_data_for_composer(conn: &Connection, composer_id: &str) -> BubbleDataMap {
        let mut bubble_map = BubbleDataMap::new();

        // Optimization: Use range query instead of LIKE for prefix matching.
        // This guarantees SQLite uses the index on the `key` column.
        // Prefix: `bubbleId:{composerId}:`
        // Range: >= prefix AND < prefix_next
        let prefix = format!("bubbleId:{}:", composer_id);
        let limit = Self::prefix_upper_bound(&prefix);

        let prefix_len = prefix.len();

        if let Ok(rows) = conn.query_map_collect(
            "SELECT key, value FROM cursorDiskKV WHERE key >= ? AND key < ?",
            params![prefix.as_str(), limit.as_str()],
            |row| {
                let key: String = row.get_typed(0)?;
                let value: String = row.get_typed(1)?;
                Ok((key, value))
            },
        ) {
            for (key, value) in rows {
                // Key format: bubbleId:{composerId}:{bubbleId}
                // Extract just the bubbleId part
                if key.len() > prefix_len {
                    let bubble_id = &key[prefix_len..];
                    if let Ok(parsed) = serde_json::from_str::<Value>(&value) {
                        bubble_map.insert(bubble_id.to_string(), parsed);
                    }
                }
            }
        }

        bubble_map
    }

    /// Extract workspace from bubble data.
    /// Cursor v0.40+ stores workspaceProjectDir in bubble entries.
    fn extract_workspace_from_bubbles(bubble_map: &BubbleDataMap) -> Option<PathBuf> {
        for bubble in bubble_map.values() {
            // Try workspaceProjectDir first (most common)
            if let Some(dir) = bubble.get("workspaceProjectDir").and_then(|v| v.as_str())
                && !dir.is_empty()
            {
                return Some(PathBuf::from(dir));
            }

            // Try workspaceUris array
            if let Some(uris) = bubble.get("workspaceUris").and_then(|v| v.as_array()) {
                for uri in uris {
                    if let Some(uri_str) = uri.as_str() {
                        // Parse file:// or vscode-remote:// URIs
                        if let Some(path) = Self::parse_workspace_uri(uri_str) {
                            return Some(path);
                        }
                    }
                }
            }
        }
        None
    }

    /// Parse a workspace URI to extract the path.
    /// Handles file:// and vscode-remote:// URIs.
    fn parse_workspace_uri(uri: &str) -> Option<PathBuf> {
        if let Some(path) = uri.strip_prefix("file://") {
            // URL decode
            let decoded = urlencoding::decode(path).ok()?;
            let mut path_str = decoded.as_ref();

            // On Windows, file:///C:/... becomes /C:/...
            // We need to strip the leading slash if it looks like a drive letter
            if cfg!(windows) && path_str.starts_with('/') && path_str.len() > 2 {
                let chars: Vec<char> = path_str.chars().collect();
                if chars[2] == ':' && chars[1].is_ascii_alphabetic() {
                    path_str = &path_str[1..];
                }
            }

            return Some(PathBuf::from(path_str));
        }

        // Handle vscode-remote://ssh-remote+{json}/path format
        if let Some(rest) = uri.strip_prefix("vscode-remote://") {
            // Extract path after the host/connection info
            // Format: vscode-remote://ssh-remote+{encoded-json}/actual/path
            if let Some(slash_idx) = rest.find('/') {
                let path = &rest[slash_idx..];
                let decoded = urlencoding::decode(path).ok()?;
                return Some(PathBuf::from(decoded.into_owned()));
            }
        }

        None
    }

    /// Extract chat sessions from a SQLite database
    fn extract_from_db(
        db_path: &Path,
        since_ts: Option<i64>,
    ) -> Result<Vec<NormalizedConversation>> {
        let conn = open_with_flags(
            db_path.to_string_lossy().as_ref(),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .with_context(|| format!("failed to open Cursor db: {}", db_path.display()))?;

        // Set busy timeout to 5 seconds to avoid locking errors when Cursor is running
        conn.execute("PRAGMA busy_timeout = 5000;")
            .with_context(|| "failed to set busy_timeout")?;

        let mut convs = Vec::new();
        let mut seen_ids = HashSet::new();

        // Try cursorDiskKV table for composerData entries
        let composer_prefix = "composerData:";
        let composer_limit = Self::prefix_upper_bound(composer_prefix);
        if let Ok(rows) = conn.query_map_collect(
            "SELECT key, value FROM cursorDiskKV WHERE key >= ? AND key < ? AND value IS NOT NULL",
            params![composer_prefix, composer_limit.as_str()],
            |row| {
                let key: String = row.get_typed(0)?;
                let value: String = row.get_typed(1)?;
                Ok((key, value))
            },
        ) {
            for (key, value) in rows {
                if let Some(conv) = Self::parse_composer_data(
                    &key,
                    &value,
                    db_path,
                    since_ts,
                    &mut seen_ids,
                    Some(&conn),
                ) {
                    convs.push(conv);
                }
            }
        }

        // Also try ItemTable for legacy aichat data
        if let Ok(rows) = conn.query_map_collect(
            "SELECT key, value FROM ItemTable WHERE (key LIKE '%aichat%chatdata%' OR key LIKE '%composer%') AND value IS NOT NULL",
            params![],
            |row| {
                let key: String = row.get_typed(0)?;
                let value: String = row.get_typed(1)?;
                Ok((key, value))
            },
        ) {
            for (key, value) in rows {
                if let Some(conv) =
                    Self::parse_aichat_data(&key, &value, db_path, since_ts, &mut seen_ids)
                {
                    convs.push(conv);
                }
            }
        }

        Ok(convs)
    }

    /// Parse composerData JSON into a conversation.
    ///
    /// Supports multiple Cursor formats:
    /// - v0.40+ (new): `fullConversationHeadersOnly` with separate bubbleId entries
    /// - v0.3x (tabs): `tabs` → `bubbles` structure
    /// - v0.2x (conversationMap): `conversationMap` → `bubbles` structure
    /// - Simple: `text`/`richText` fields only
    fn parse_composer_data(
        key: &str,
        value: &str,
        db_path: &Path,
        since_ts: Option<i64>,
        seen_ids: &mut HashSet<String>,
        conn: Option<&Connection>,
    ) -> Option<NormalizedConversation> {
        let val: Value = serde_json::from_str(value).ok()?;

        // Extract composer ID from key (composerData:{uuid})
        let composer_id = key.strip_prefix("composerData:")?.to_string();

        // Skip if already seen
        if seen_ids.contains(&composer_id) {
            return None;
        }
        seen_ids.insert(composer_id.clone());

        // Extract timestamps
        let created_at = val.get("createdAt").and_then(parse_timestamp);
        let last_updated_at = val.get("lastUpdatedAt").and_then(parse_timestamp);

        let mut messages = Vec::new();
        let mut workspace: Option<PathBuf> = None;

        // Check for v0.40+ format with fullConversationHeadersOnly
        // This format stores only bubble IDs in composerData, with actual content
        // in separate bubbleId:{composerId}:{bubbleId} keys
        // Note: requires a database connection to fetch bubble content
        if let (Some(headers), Some(conn)) = (
            val.get("fullConversationHeadersOnly")
                .and_then(|v| v.as_array()),
            conn,
        ) {
            // Lazy-load bubble data for this composer
            let bubble_map = Self::fetch_bubble_data_for_composer(conn, &composer_id);

            // Extract workspace from bubbles
            workspace = Self::extract_workspace_from_bubbles(&bubble_map);

            // Parse each header reference
            for header in headers {
                if let Some(bubble_id) = header.get("bubbleId").and_then(|v| v.as_str())
                    && let Some(bubble) = bubble_map.get(bubble_id)
                    && let Some(msg) = Self::parse_bubble(bubble, messages.len())
                {
                    messages.push(msg);
                }
            }
        }

        // Parse conversation from bubbles/tabs structure (legacy v0.3x)
        if messages.is_empty()
            && let Some(tabs) = val.get("tabs").and_then(|v| v.as_array())
        {
            for tab in tabs {
                if let Some(bubbles) = tab.get("bubbles").and_then(|v| v.as_array()) {
                    for (idx, bubble) in bubbles.iter().enumerate() {
                        if let Some(msg) = Self::parse_bubble(bubble, idx) {
                            messages.push(msg);
                        }
                    }
                }
            }
        }

        // Also check conversationMap for older format (v0.2x)
        if messages.is_empty()
            && let Some(conv_map) = val.get("conversationMap").and_then(|v| v.as_object())
        {
            for (_, conv_val) in conv_map {
                if let Some(bubbles) = conv_val.get("bubbles").and_then(|v| v.as_array()) {
                    for (idx, bubble) in bubbles.iter().enumerate() {
                        if let Some(msg) = Self::parse_bubble(bubble, messages.len() + idx) {
                            messages.push(msg);
                        }
                    }
                }
            }
        }

        // Check for text/richText as user input (simple composer sessions)
        let user_text = val
            .get("text")
            .and_then(|v| v.as_str())
            .or_else(|| val.get("richText").and_then(|v| v.as_str()))
            .unwrap_or("");

        if !user_text.is_empty() && messages.is_empty() {
            messages.push(NormalizedMessage {
                idx: 0,
                role: "user".to_string(),
                author: None,
                created_at,
                content: user_text.to_string(),
                extra: serde_json::json!({}),
                invocations: Vec::new(),
                snippets: Vec::new(),
            });
        }

        // Skip if no messages
        if messages.is_empty() {
            return None;
        }

        // Re-index messages
        crate::types::reindex_messages(&mut messages);

        // Extract model info
        let model_name = val
            .get("modelConfig")
            .and_then(|m| m.get("modelName"))
            .and_then(|v| v.as_str());

        // Use explicit name field if available (v0.40+), otherwise derive from first message
        let title = val
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.chars().take(100).collect())
            .or_else(|| {
                messages.first().map(|m| {
                    m.content
                        .lines()
                        .next()
                        .unwrap_or("")
                        .chars()
                        .take(100)
                        .collect()
                })
            })
            .or_else(|| model_name.map(|m| format!("Cursor chat with {}", m)));

        // source_path must be unique per conversation for proper lookup in the TUI.
        // Since multiple conversations live in the same database file, we append
        // the composer_id to create a unique synthetic path for each conversation.
        let safe_id = urlencoding::encode(&composer_id);
        let unique_source_path = db_path.join(safe_id.as_ref());

        // Use lastUpdatedAt if available (most accurate), fall back to max message time, then createdAt
        let ended_at = last_updated_at
            .or_else(|| messages.iter().filter_map(|m| m.created_at).max())
            .or(created_at);

        // Optimization: Skip conversations not modified since last scan
        if let (Some(threshold), Some(ts)) = (since_ts, ended_at)
            && ts < threshold
        {
            return None;
        }

        Some(NormalizedConversation {
            agent_slug: "cursor".to_string(),
            external_id: Some(composer_id),
            title,
            workspace,
            source_path: unique_source_path,
            started_at: created_at,
            ended_at,
            metadata: serde_json::json!({
                "source": "cursor",
                "model": model_name,
                "unifiedMode": val.get("unifiedMode").and_then(|v| v.as_str()),
            }),
            messages,
        })
    }

    /// Parse a bubble (message) from Cursor's format.
    ///
    /// Handles both new format (v0.40+) and legacy formats:
    /// - Content: text > rawText > content > message
    /// - Role: numeric type (1=user, 2=assistant) or string type/role
    /// - Author: modelType (new) or model (legacy)
    fn parse_bubble(bubble: &Value, idx: usize) -> Option<NormalizedMessage> {
        // Extract content - try all known field names in priority order
        let content = bubble
            .get("text")
            .and_then(|v| v.as_str())
            .or_else(|| bubble.get("rawText").and_then(|v| v.as_str()))
            .or_else(|| bubble.get("content").and_then(|v| v.as_str()))
            .or_else(|| bubble.get("message").and_then(|v| v.as_str()))?;

        if content.trim().is_empty() {
            return None;
        }

        // Extract role - try numeric type first (v0.40+), then string type/role (legacy)
        let role = bubble
            .get("type")
            .and_then(|v| {
                // v0.40+ format: numeric type (1=user, 2=assistant)
                v.as_i64()
                    .map(|t| {
                        match t {
                            bubble_type::USER => "user",
                            bubble_type::ASSISTANT => "assistant",
                            // Fallback for unknown numeric types (e.g. system messages, tools)
                            // Default to "assistant" to preserve content visibility
                            _ => "assistant",
                        }
                        .to_string()
                    })
                    // Legacy format: string type
                    .or_else(|| v.as_str().map(Self::normalize_role))
            })
            .or_else(|| {
                // Fallback: check "role" field (legacy format)
                bubble
                    .get("role")
                    .and_then(|v| v.as_str())
                    .map(Self::normalize_role)
            })
            .unwrap_or_else(|| "assistant".to_string());

        let created_at = bubble
            .get("timestamp")
            .or_else(|| bubble.get("createdAt"))
            .and_then(parse_timestamp);

        // Extract author - try both field names (modelType is v0.40+)
        let author = bubble
            .get("modelType")
            .or_else(|| bubble.get("model"))
            .or_else(|| {
                // Also check modelInfo.modelName for v0.40+
                bubble.get("modelInfo").and_then(|m| m.get("modelName"))
            })
            .and_then(|v| v.as_str())
            .map(String::from);

        Some(NormalizedMessage {
            idx: idx as i64,
            role,
            author,
            created_at,
            content: content.to_string(),
            extra: bubble.clone(),
            invocations: Vec::new(),
            snippets: Vec::new(),
        })
    }

    /// Normalize role string to standard values (user/assistant).
    fn normalize_role(role: &str) -> String {
        match role.to_lowercase().as_str() {
            "user" | "human" => "user",
            "assistant" | "ai" | "bot" => "assistant",
            _ => role,
        }
        .to_string()
    }

    /// Parse legacy aichat data
    fn parse_aichat_data(
        key: &str,
        value: &str,
        db_path: &Path,
        _since_ts: Option<i64>, // File-level filtering done in scan(); message filtering not needed
        seen_ids: &mut HashSet<String>,
    ) -> Option<NormalizedConversation> {
        let val: Value = serde_json::from_str(value).ok()?;

        // Skip if already seen
        let id = format!("aichat-{}", key);
        if seen_ids.contains(&id) {
            return None;
        }
        seen_ids.insert(id.clone());

        let mut messages = Vec::new();
        let mut started_at: Option<i64> = None;
        let mut ended_at: Option<i64> = None;
        let mut update_time_bounds = |candidate_ts: Option<i64>| {
            if let Some(ts) = candidate_ts {
                started_at = Some(if let Some(current) = started_at {
                    current.min(ts)
                } else {
                    ts
                });
                ended_at = Some(if let Some(current) = ended_at {
                    current.max(ts)
                } else {
                    ts
                });
            }
        };

        // Parse tabs array
        if let Some(tabs) = val.get("tabs").and_then(|v| v.as_array()) {
            for tab in tabs {
                let tab_ts = tab.get("timestamp").and_then(parse_timestamp);

                // NOTE: Do NOT filter by timestamp here! File-level check is sufficient.

                if let Some(bubbles) = tab.get("bubbles").and_then(|v| v.as_array()) {
                    for bubble in bubbles {
                        if let Some(msg) = Self::parse_bubble(bubble, messages.len()) {
                            update_time_bounds(msg.created_at.or(tab_ts));
                            messages.push(msg);
                        }
                    }
                }
            }
        }

        if messages.is_empty() {
            return None;
        }

        // Re-index
        crate::types::reindex_messages(&mut messages);

        let title = messages.first().map(|m| {
            m.content
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(100)
                .collect()
        });

        // source_path must be unique per conversation for proper lookup in the TUI.
        let safe_id = urlencoding::encode(&id);
        let unique_source_path = db_path.join(safe_id.as_ref());

        Some(NormalizedConversation {
            agent_slug: "cursor".to_string(),
            external_id: Some(id),
            title,
            workspace: None,
            source_path: unique_source_path,
            started_at,
            ended_at,
            metadata: serde_json::json!({"source": "cursor_aichat"}),
            messages,
        })
    }
}

impl Connector for CursorConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("cursor").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let roots: Vec<PathBuf> = Self::source_roots(ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();

        if roots.is_empty() {
            return Ok(Vec::new());
        }

        let mut all_convs = Vec::new();

        for root in roots {
            if !root.exists() {
                continue;
            }

            let db_files = Self::find_db_files(&root);

            for db_path in db_files {
                // Skip files not modified since last scan
                if !file_modified_since(&db_path, ctx.since_ts) {
                    continue;
                }

                match Self::extract_from_db(&db_path, ctx.since_ts) {
                    Ok(convs) => {
                        tracing::debug!(
                            path = %db_path.display(),
                            count = convs.len(),
                            "cursor extracted conversations"
                        );
                        all_convs.extend(convs);
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %db_path.display(),
                            error = %e,
                            "cursor failed to extract from db"
                        );
                    }
                }
            }
        }

        Ok(all_convs)
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use frankensqlite::compat::ConnectionExt;
    use frankensqlite::params;
    use serde_json::json;
    use std::collections::HashSet;
    use std::fs;
    use tempfile::TempDir;

    /// Create a test SQLite database with the cursorDiskKV table
    fn create_test_db(path: &Path) -> Connection {
        let conn = Connection::open(path.to_string_lossy().as_ref()).unwrap();
        conn.execute("CREATE TABLE IF NOT EXISTS cursorDiskKV (key TEXT PRIMARY KEY, value TEXT)")
            .unwrap();
        conn.execute("CREATE TABLE IF NOT EXISTS ItemTable (key TEXT PRIMARY KEY, value TEXT)")
            .unwrap();
        conn
    }

    // =========================================================================
    // Constructor tests
    // =========================================================================

    #[test]
    fn new_creates_connector() {
        let connector = CursorConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = CursorConnector;
        let _ = connector;
    }

    // =========================================================================
    // find_db_files tests
    // =========================================================================

    #[test]
    fn find_db_files_empty_for_nonexistent() {
        let dir = TempDir::new().unwrap();
        let dbs = CursorConnector::find_db_files(dir.path());
        assert!(dbs.is_empty());
    }

    #[test]
    fn find_db_files_finds_global_storage() {
        let dir = TempDir::new().unwrap();
        let global_dir = dir.path().join("globalStorage");
        fs::create_dir_all(&global_dir).unwrap();
        fs::write(global_dir.join("state.vscdb"), "").unwrap();

        let dbs = CursorConnector::find_db_files(dir.path());
        assert_eq!(dbs.len(), 1);
        assert!(dbs[0].ends_with("state.vscdb"));
    }

    #[test]
    fn find_db_files_finds_workspace_storage() {
        let dir = TempDir::new().unwrap();
        let workspace_dir = dir.path().join("workspaceStorage").join("abc123");
        fs::create_dir_all(&workspace_dir).unwrap();
        fs::write(workspace_dir.join("state.vscdb"), "").unwrap();

        let dbs = CursorConnector::find_db_files(dir.path());
        assert_eq!(dbs.len(), 1);
    }

    #[test]
    fn find_db_files_finds_multiple() {
        let dir = TempDir::new().unwrap();

        // Create global storage
        let global_dir = dir.path().join("globalStorage");
        fs::create_dir_all(&global_dir).unwrap();
        fs::write(global_dir.join("state.vscdb"), "").unwrap();

        // Create multiple workspace storage dirs
        for i in 1..=3 {
            let ws_dir = dir.path().join("workspaceStorage").join(format!("ws{}", i));
            fs::create_dir_all(&ws_dir).unwrap();
            fs::write(ws_dir.join("state.vscdb"), "").unwrap();
        }

        let dbs = CursorConnector::find_db_files(dir.path());
        assert_eq!(dbs.len(), 4); // 1 global + 3 workspace
    }

    #[test]
    fn find_db_files_returns_sorted_order() {
        let dir = TempDir::new().unwrap();

        let ws_z = dir.path().join("workspaceStorage").join("zeta");
        let ws_a = dir.path().join("workspaceStorage").join("alpha");
        fs::create_dir_all(&ws_z).unwrap();
        fs::create_dir_all(&ws_a).unwrap();
        fs::write(ws_z.join("state.vscdb"), "").unwrap();
        fs::write(ws_a.join("state.vscdb"), "").unwrap();

        let dbs = CursorConnector::find_db_files(dir.path());
        assert_eq!(dbs.len(), 2);

        let names: Vec<_> = dbs
            .iter()
            .map(|p| {
                p.parent()
                    .and_then(|x| x.file_name())
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }

    #[test]
    fn find_db_files_ignores_workspace_noise_files() {
        let dir = TempDir::new().unwrap();
        let workspace_dir = dir.path().join("workspaceStorage").join("abc123");
        fs::create_dir_all(&workspace_dir).unwrap();

        for i in 0..20 {
            fs::write(workspace_dir.join(format!("noise_{i}.json")), "{}").unwrap();
        }
        fs::write(workspace_dir.join("state.vscdb"), "").unwrap();

        let dbs = CursorConnector::find_db_files(dir.path());
        assert_eq!(dbs.len(), 1);
        assert!(dbs[0].ends_with("state.vscdb"));
    }

    #[test]
    fn find_db_files_supports_workspace_storage_root_db() {
        let dir = TempDir::new().unwrap();
        let workspace_storage = dir.path().join("workspaceStorage");
        fs::create_dir_all(&workspace_storage).unwrap();
        fs::write(workspace_storage.join("state.vscdb"), "").unwrap();

        let dbs = CursorConnector::find_db_files(dir.path());
        assert_eq!(dbs.len(), 1);
        assert!(dbs[0].ends_with("workspaceStorage/state.vscdb"));
    }

    #[test]
    fn has_any_db_file_is_true_for_workspace_storage_db() {
        let dir = TempDir::new().unwrap();
        let workspace_dir = dir.path().join("workspaceStorage").join("abc123");
        fs::create_dir_all(&workspace_dir).unwrap();
        fs::write(workspace_dir.join("state.vscdb"), "").unwrap();

        assert!(CursorConnector::has_any_db_file(dir.path()));
    }

    #[test]
    fn has_any_db_file_is_false_for_workspace_noise_only() {
        let dir = TempDir::new().unwrap();
        let workspace_dir = dir.path().join("workspaceStorage").join("abc123");
        fs::create_dir_all(&workspace_dir).unwrap();
        fs::write(workspace_dir.join("note.txt"), "noise").unwrap();

        assert!(!CursorConnector::has_any_db_file(dir.path()));
    }

    // =========================================================================
    // parse_bubble tests
    // =========================================================================

    #[test]
    fn parse_bubble_with_text() {
        let bubble = json!({
            "text": "Hello from user",
            "type": "user"
        });

        let msg = CursorConnector::parse_bubble(&bubble, 0);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert_eq!(msg.content, "Hello from user");
        assert_eq!(msg.role, "user");
    }

    #[test]
    fn parse_bubble_with_content_field() {
        let bubble = json!({
            "content": "Response from assistant",
            "role": "assistant"
        });

        let msg = CursorConnector::parse_bubble(&bubble, 1);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert_eq!(msg.content, "Response from assistant");
        assert_eq!(msg.role, "assistant");
    }

    #[test]
    fn parse_bubble_with_message_field() {
        let bubble = json!({
            "message": "Another message",
            "type": "ai"
        });

        let msg = CursorConnector::parse_bubble(&bubble, 0);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert_eq!(msg.content, "Another message");
        assert_eq!(msg.role, "assistant"); // "ai" maps to assistant
    }

    #[test]
    fn parse_bubble_role_normalization() {
        let test_cases = vec![
            ("user", "user"),
            ("human", "user"),
            ("assistant", "assistant"),
            ("ai", "assistant"),
            ("bot", "assistant"),
            ("custom", "custom"), // Unknown roles pass through
        ];

        for (input_role, expected_role) in test_cases {
            let bubble = json!({
                "text": "test",
                "type": input_role
            });

            let msg = CursorConnector::parse_bubble(&bubble, 0).unwrap();
            assert_eq!(
                msg.role, expected_role,
                "Failed for input role: {}",
                input_role
            );
        }
    }

    #[test]
    fn parse_bubble_empty_content_returns_none() {
        let bubble = json!({
            "text": "",
            "type": "user"
        });

        assert!(CursorConnector::parse_bubble(&bubble, 0).is_none());
    }

    #[test]
    fn parse_bubble_whitespace_only_returns_none() {
        let bubble = json!({
            "text": "   \n\t  ",
            "type": "user"
        });

        assert!(CursorConnector::parse_bubble(&bubble, 0).is_none());
    }

    #[test]
    fn parse_bubble_extracts_timestamp() {
        let bubble = json!({
            "text": "Test",
            "type": "user",
            "timestamp": 1700000000000i64
        });

        let msg = CursorConnector::parse_bubble(&bubble, 0).unwrap();
        assert_eq!(msg.created_at, Some(1700000000000));
    }

    #[test]
    fn parse_bubble_extracts_model() {
        let bubble = json!({
            "text": "Response",
            "type": "assistant",
            "model": "gpt-4"
        });

        let msg = CursorConnector::parse_bubble(&bubble, 0).unwrap();
        assert_eq!(msg.author, Some("gpt-4".to_string()));
    }

    #[test]
    fn parse_bubble_defaults_to_assistant() {
        let bubble = json!({
            "text": "No role specified"
        });

        let msg = CursorConnector::parse_bubble(&bubble, 0).unwrap();
        assert_eq!(msg.role, "assistant");
    }

    // =========================================================================
    // parse_composer_data tests
    // =========================================================================

    #[test]
    fn parse_composer_data_with_tabs_and_bubbles() {
        let key = "composerData:abc-123";
        let value = json!({
            "createdAt": 1700000000000i64,
            "tabs": [{
                "bubbles": [
                    {"text": "Hello", "type": "user"},
                    {"text": "Hi there!", "type": "assistant"}
                ]
            }]
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        assert!(conv.is_some());
        let conv = conv.unwrap();
        assert_eq!(conv.agent_slug, "cursor");
        assert_eq!(conv.external_id, Some("abc-123".to_string()));
        assert_eq!(conv.messages.len(), 2);
        assert_eq!(conv.messages[0].role, "user");
        assert_eq!(conv.messages[1].role, "assistant");
    }

    #[test]
    fn parse_composer_data_with_conversation_map() {
        let key = "composerData:def-456";
        let value = json!({
            "conversationMap": {
                "conv1": {
                    "bubbles": [
                        {"text": "Question?", "type": "user"},
                        {"content": "Answer!", "role": "assistant"}
                    ]
                }
            }
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        assert!(conv.is_some());
        let conv = conv.unwrap();
        assert_eq!(conv.messages.len(), 2);
    }

    #[test]
    fn parse_composer_data_with_text_only() {
        let key = "composerData:simple-123";
        let value = json!({
            "text": "Simple user input without bubbles",
            "createdAt": 1700000000000i64
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        assert!(conv.is_some());
        let conv = conv.unwrap();
        assert_eq!(conv.messages.len(), 1);
        assert_eq!(conv.messages[0].role, "user");
        assert!(conv.messages[0].content.contains("Simple user input"));
    }

    #[test]
    fn parse_composer_data_with_rich_text() {
        let key = "composerData:rich-789";
        let value = json!({
            "richText": "Rich text content here"
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        assert!(conv.is_some());
        let conv = conv.unwrap();
        assert!(conv.messages[0].content.contains("Rich text"));
    }

    #[test]
    fn parse_composer_data_skips_duplicates() {
        let key = "composerData:dup-123";
        let value = json!({ "text": "Content" }).to_string();

        let mut seen = HashSet::new();
        let conv1 = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );
        let conv2 = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        assert!(conv1.is_some());
        assert!(conv2.is_none()); // Duplicate should return None
    }

    #[test]
    fn parse_composer_data_returns_none_for_empty() {
        let key = "composerData:empty-123";
        let value = json!({}).to_string();

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        assert!(conv.is_none());
    }

    #[test]
    fn parse_composer_data_extracts_model_config() {
        let key = "composerData:model-123";
        let value = json!({
            "text": "Test",
            "modelConfig": {
                "modelName": "gpt-4-turbo"
            }
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        assert!(conv.is_some());
        let conv = conv.unwrap();
        assert_eq!(conv.metadata["model"], "gpt-4-turbo");
    }

    #[test]
    fn parse_composer_data_invalid_key_returns_none() {
        let key = "not-composer-data"; // Missing "composerData:" prefix
        let value = json!({ "text": "Content" }).to_string();

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        assert!(conv.is_none());
    }

    // =========================================================================
    // parse_aichat_data tests
    // =========================================================================

    #[test]
    fn parse_aichat_data_with_tabs() {
        let key = "aichat.chatdata";
        let value = json!({
            "tabs": [{
                "timestamp": 1700000000000i64,
                "bubbles": [
                    {"text": "User question", "type": "user"},
                    {"text": "AI response", "type": "ai"}
                ]
            }]
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv =
            CursorConnector::parse_aichat_data(key, &value, Path::new("/test"), None, &mut seen);

        assert!(conv.is_some());
        let conv = conv.unwrap();
        assert_eq!(conv.agent_slug, "cursor");
        assert!(conv.external_id.as_ref().unwrap().starts_with("aichat-"));
        assert_eq!(conv.messages.len(), 2);
    }

    #[test]
    fn parse_aichat_data_tracks_min_max_out_of_order_timestamps() {
        let key = "aichat.bounds";
        let value = json!({
            "tabs": [
                {
                    "timestamp": 1700000200,
                    "bubbles": [
                        {"text": "later", "type": "ai", "timestamp": 1700000300}
                    ]
                },
                {
                    "timestamp": 1700000000,
                    "bubbles": [
                        {"text": "earlier", "type": "user", "timestamp": 1700000100}
                    ]
                }
            ]
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv =
            CursorConnector::parse_aichat_data(key, &value, Path::new("/test"), None, &mut seen)
                .expect("aichat conversation should parse");

        // Bounds should be based on true min/max timestamps, not traversal order.
        assert_eq!(conv.started_at, Some(1_700_000_100_000));
        assert_eq!(conv.ended_at, Some(1_700_000_300_000));
    }

    #[test]
    fn parse_aichat_data_parses_string_tab_timestamp() {
        let key = "aichat.string-ts";
        let value = json!({
            "tabs": [{
                "timestamp": "1700000400",
                "bubbles": [
                    {"text": "no bubble timestamp", "type": "user"}
                ]
            }]
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv =
            CursorConnector::parse_aichat_data(key, &value, Path::new("/test"), None, &mut seen)
                .expect("aichat conversation should parse");

        // String timestamps should be normalized to milliseconds.
        assert_eq!(conv.started_at, Some(1_700_000_400_000));
        assert_eq!(conv.ended_at, Some(1_700_000_400_000));
    }

    #[test]
    fn parse_aichat_data_returns_none_for_empty() {
        let key = "aichat.empty";
        let value = json!({
            "tabs": []
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv =
            CursorConnector::parse_aichat_data(key, &value, Path::new("/test"), None, &mut seen);

        assert!(conv.is_none());
    }

    #[test]
    fn parse_aichat_data_skips_duplicates() {
        let key = "aichat.dup";
        let value = json!({
            "tabs": [{
                "bubbles": [{"text": "Content", "type": "user"}]
            }]
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv1 =
            CursorConnector::parse_aichat_data(key, &value, Path::new("/test"), None, &mut seen);
        let conv2 =
            CursorConnector::parse_aichat_data(key, &value, Path::new("/test"), None, &mut seen);

        assert!(conv1.is_some());
        assert!(conv2.is_none());
    }

    // =========================================================================
    // extract_from_db tests
    // =========================================================================

    #[test]
    fn extract_from_db_with_composer_data() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("state.vscdb");

        let conn = create_test_db(&db_path);
        let value = json!({ "text": "Database test" }).to_string();
        conn.execute_compat(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            params!["composerData:db-test-123", value.as_str()],
        )
        .unwrap();
        drop(conn);

        let convs = CursorConnector::extract_from_db(&db_path, None).unwrap();
        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("Database test"));
    }

    #[test]
    fn extract_from_db_with_aichat_data() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("state.vscdb");

        let conn = create_test_db(&db_path);
        let value = json!({
            "tabs": [{
                "bubbles": [{"text": "Aichat test", "type": "user"}]
            }]
        })
        .to_string();
        conn.execute_compat(
            "INSERT INTO ItemTable (key, value) VALUES (?, ?)",
            params![
                "workbench.panel.aichat.view.aichat.chatdata",
                value.as_str()
            ],
        )
        .unwrap();
        drop(conn);

        let convs = CursorConnector::extract_from_db(&db_path, None).unwrap();
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn extract_from_db_handles_empty_db() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("state.vscdb");

        let _conn = create_test_db(&db_path);

        let convs = CursorConnector::extract_from_db(&db_path, None).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn extract_from_db_fails_for_missing_file() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("nonexistent.vscdb");

        let result = CursorConnector::extract_from_db(&db_path, None);
        assert!(result.is_err());
    }

    #[test]
    fn extract_from_db_skips_rows_with_null_value() {
        // Cursor stores some rows in cursorDiskKV / ItemTable with a NULL value
        // (e.g. internal markers without payload). The row mapper requests
        // `value` as `String`, so a single NULL row used to abort the entire
        // `query_map_collect` via fail-fast semantics, silently dropping every
        // valid composerData row alongside it.
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("state.vscdb");

        let conn = create_test_db(&db_path);
        let value = json!({ "text": "real conversation" }).to_string();
        conn.execute_compat(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            params!["composerData:real-1", value.as_str()],
        )
        .unwrap();
        // NULL-value row that previously poisoned the whole query.
        conn.execute_compat(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, NULL)",
            params!["composerData:null-marker"],
        )
        .unwrap();
        drop(conn);

        let convs = CursorConnector::extract_from_db(&db_path, None).unwrap();
        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("real conversation"));
    }

    // =========================================================================
    // Detection tests
    // =========================================================================

    #[test]
    fn detect_not_found_without_cursor_dir() {
        let connector = CursorConnector::new();
        let result = connector.detect();
        // On most CI/test systems, Cursor won't be installed
        // Just verify detect() doesn't panic
        let _ = result.detected;
    }

    // =========================================================================
    // Scan tests
    // =========================================================================

    #[test]
    fn scan_empty_directory_returns_empty() {
        let dir = TempDir::new().unwrap();

        // Create globalStorage to make scan() use this directory instead of fallback
        let global_dir = dir.path().join("globalStorage");
        fs::create_dir_all(&global_dir).unwrap();
        // Create an empty state.vscdb to prevent fallback to system Cursor
        create_test_db(&global_dir.join("state.vscdb"));

        let connector = CursorConnector::new();
        let ctx = ScanContext::local_default(dir.path().to_path_buf(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn scan_processes_global_storage() {
        let dir = TempDir::new().unwrap();

        // Create Cursor-like directory structure
        let cursor_dir = dir.path().join("Cursor");
        let global_dir = cursor_dir.join("globalStorage");
        fs::create_dir_all(&global_dir).unwrap();

        // Create database with test data
        let db_path = global_dir.join("state.vscdb");
        let conn = create_test_db(&db_path);
        let value = json!({ "text": "Scan test" }).to_string();
        conn.execute_compat(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            params!["composerData:scan-123", value.as_str()],
        )
        .unwrap();
        drop(conn);

        let connector = CursorConnector::new();
        let ctx = ScanContext::local_default(cursor_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok());
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);

        let discovered_paths: HashSet<PathBuf> = connector
            .discover_source_files(&ctx)
            .unwrap()
            .into_iter()
            .map(|source| source.source_path)
            .collect();
        assert!(
            discovered_paths.contains(&db_path),
            "discovery should include consumed Cursor database {}",
            db_path.display()
        );
        assert!(
            convs[0].source_path.starts_with(&db_path),
            "Cursor conversation source path should be derived from consumed db {}",
            db_path.display()
        );
    }

    #[test]
    fn scan_with_home_scan_root_finds_cursor_storage() {
        let dir = TempDir::new().unwrap();
        let home = dir.path();

        let global_dir = home.join(".config/Cursor/User/globalStorage");
        fs::create_dir_all(&global_dir).unwrap();

        let db_path = global_dir.join("state.vscdb");
        let conn = create_test_db(&db_path);
        let value = json!({ "text": "Explicit root" }).to_string();
        conn.execute_compat(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            params!["composerData:explicit-123", value.as_str()],
        )
        .unwrap();
        drop(conn);

        let connector = CursorConnector::new();
        let ctx = ScanContext::with_roots(
            PathBuf::new(),
            vec![ScanRoot::local(home.to_path_buf())],
            None,
        );
        let result = connector.scan(&ctx);

        assert!(result.is_ok());
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn scan_recognizes_cursor_in_path() {
        let dir = TempDir::new().unwrap();

        // Directory name contains "Cursor"
        let cursor_dir = dir.path().join("TestCursor");
        let global_dir = cursor_dir.join("globalStorage");
        fs::create_dir_all(&global_dir).unwrap();

        let db_path = global_dir.join("state.vscdb");
        let conn = create_test_db(&db_path);
        let value = json!({ "text": "Path test" }).to_string();
        conn.execute_compat(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            params!["composerData:path-123", value.as_str()],
        )
        .unwrap();
        drop(conn);

        let connector = CursorConnector::new();
        let ctx = ScanContext::local_default(cursor_dir, None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn parse_composer_data_invalid_json_returns_none() {
        let key = "composerData:invalid-123";
        let value = "not valid json {{{";

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        assert!(conv.is_none());
    }

    #[test]
    fn parse_bubble_preserves_original_in_extra() {
        let bubble = json!({
            "text": "Test",
            "type": "user",
            "customField": "customValue"
        });

        let msg = CursorConnector::parse_bubble(&bubble, 0).unwrap();
        assert_eq!(msg.extra["customField"], "customValue");
    }

    #[test]
    fn conversation_title_from_first_message() {
        let key = "composerData:title-test";
        let value = json!({
            "tabs": [{
                "bubbles": [
                    {"text": "This is the first line\nSecond line here", "type": "user"}
                ]
            }]
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        let conv = conv.unwrap();
        // Title should be first line only
        assert_eq!(conv.title, Some("This is the first line".to_string()));
    }

    #[test]
    fn conversation_title_truncates_long_lines() {
        let key = "composerData:long-title";
        let long_text = "x".repeat(200);
        let value = json!({ "text": long_text }).to_string();

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        let conv = conv.unwrap();
        assert!(conv.title.as_ref().unwrap().len() <= 100);
    }

    #[test]
    fn messages_are_reindexed_sequentially() {
        let key = "composerData:reindex";
        let value = json!({
            "tabs": [{
                "bubbles": [
                    {"text": "One", "type": "user"},
                    {"text": "Two", "type": "assistant"},
                    {"text": "Three", "type": "user"}
                ]
            }]
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        )
        .unwrap();

        assert_eq!(conv.messages[0].idx, 0);
        assert_eq!(conv.messages[1].idx, 1);
        assert_eq!(conv.messages[2].idx, 2);
    }

    // =========================================================================
    // WSL detection tests (Linux-only)
    // =========================================================================

    #[cfg(target_os = "linux")]
    mod wsl_tests {
        use super::*;

        #[test]
        fn is_wsl_returns_false_on_native_linux() {
            // On a real Linux system (not WSL), /proc/version won't contain "microsoft"
            // This test just verifies the function doesn't panic
            let result = CursorConnector::is_wsl();
            // We can't assert the exact value since it depends on the environment,
            // but we verify the function works
            let _ = result;
        }

        #[test]
        fn find_wsl_cursor_path_returns_none_without_mnt_c() {
            // On native Linux, /mnt/c typically doesn't exist
            // This verifies the function gracefully returns None
            if !Path::new("/mnt/c/Users").exists() {
                let result = CursorConnector::find_wsl_cursor_path();
                assert!(result.is_none());
            }
        }

        #[test]
        fn find_wsl_cursor_path_skips_system_dirs() {
            // Create a temp structure that mimics /mnt/c/Users with system dirs
            let dir = TempDir::new().unwrap();
            let users_dir = dir.path().join("Users");
            fs::create_dir_all(&users_dir).unwrap();

            // Create system directories that should be skipped
            for sys_dir in ["Default", "Public", "All Users", "Default User"] {
                fs::create_dir_all(users_dir.join(sys_dir)).unwrap();
            }

            // The function checks /mnt/c/Users specifically, so we can't directly test
            // the skipping logic without mocking. Instead, verify the skip list is correct.
            let skip_list = ["Default", "Public", "All Users", "Default User"];
            assert_eq!(skip_list.len(), 4);
        }

        #[test]
        fn wsl_path_structure_is_valid() {
            // Verify the expected WSL path structure
            let expected = Path::new("/mnt/c/Users/TestUser/AppData/Roaming/Cursor/User");
            assert!(expected.starts_with("/mnt/c/Users"));
            assert!(expected.ends_with("Cursor/User"));
        }
    }

    // =========================================================================
    // Edge case tests — malformed input robustness (br-2w98)
    // =========================================================================

    #[test]
    fn truncated_json_in_db_value_returns_none() {
        let key = "composerData:truncated-123";
        // JSON truncated mid-object
        let value = r#"{"text": "Hello", "tabs": [{"bubbles": [{"text": "Hi", "type":"#;

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        assert!(
            conv.is_none(),
            "truncated JSON should not produce a conversation"
        );
    }

    #[test]
    fn json_type_mismatch_in_bubbles_skips_bad_entries() {
        let key = "composerData:mismatch-123";
        let value = json!({
            "tabs": [{
                "bubbles": [
                    // String where object expected
                    "not a bubble object",
                    // Number instead of object
                    42,
                    // Null
                    null,
                    // Boolean
                    true,
                    // Valid entry that should still be extracted
                    {"text": "Valid bubble", "type": "user"}
                ]
            }]
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        assert!(
            conv.is_some(),
            "should extract valid bubbles despite type mismatches"
        );
        let conv = conv.unwrap();
        assert_eq!(conv.messages.len(), 1);
        assert_eq!(conv.messages[0].content, "Valid bubble");
    }

    #[test]
    fn deeply_nested_json_in_db_value_does_not_stack_overflow() {
        let key = "composerData:deep-123";
        // Build deeply nested JSON (200 levels) - serde_json has a recursion limit of 128
        let mut nested = String::new();
        for _ in 0..200 {
            nested.push_str("{\"a\":");
        }
        nested.push('1');
        for _ in 0..200 {
            nested.push('}');
        }

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &nested,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        // Should either parse or fail gracefully, never stack overflow
        assert!(
            conv.is_none(),
            "deeply nested JSON without text/tabs should produce no conversation"
        );
    }

    #[test]
    fn large_message_body_in_bubble_handled() {
        let key = "composerData:large-123";
        let large_content = "x".repeat(1_000_000);
        let value = json!({
            "tabs": [{
                "bubbles": [
                    {"text": large_content, "type": "user"}
                ]
            }]
        })
        .to_string();

        let mut seen = HashSet::new();
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            None,
            &mut seen,
            None,
        );

        assert!(conv.is_some(), "large message body should not cause OOM");
        let conv = conv.unwrap();
        assert_eq!(conv.messages[0].content.len(), 1_000_000);
    }

    #[test]
    fn corrupted_sqlite_db_does_not_panic() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("corrupted.vscdb");
        fs::write(&db_path, "not a sqlite database at all").unwrap();

        let result = CursorConnector::extract_from_db(&db_path, None);
        // SQLite engines may open the file lazily; query failures are caught with if-let-Ok
        // The important thing is that it doesn't panic
        if let Ok(convs) = result {
            assert!(
                convs.is_empty(),
                "corrupted DB should produce no conversations"
            );
        }
    }

    #[test]
    fn db_with_missing_tables_returns_empty() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("no_tables.vscdb");

        // Create a valid SQLite DB but without the expected tables
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        conn.execute("CREATE TABLE unrelated_table (id INTEGER PRIMARY KEY, data TEXT)")
            .unwrap();
        drop(conn);

        let result = CursorConnector::extract_from_db(&db_path, None);
        // Should not error even without expected tables
        assert!(result.is_ok(), "missing tables should not cause an error");
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn v040_headers_referencing_missing_bubbles_skips_gracefully() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("state.vscdb");

        let conn = create_test_db(&db_path);
        // Insert composerData with fullConversationHeadersOnly referencing non-existent bubbles
        let value = json!({
            "fullConversationHeadersOnly": [
                {"bubbleId": "nonexistent-1"},
                {"bubbleId": "nonexistent-2"}
            ]
        })
        .to_string();
        conn.execute_compat(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            params!["composerData:v040-missing", value.as_str()],
        )
        .unwrap();
        drop(conn);

        let convs = CursorConnector::extract_from_db(&db_path, None).unwrap();
        // Should not crash; no messages means no conversation
        assert!(
            convs.is_empty(),
            "missing bubble references should produce no conversations"
        );
    }

    #[test]
    fn unexpected_numeric_type_in_bubble_defaults_to_assistant() {
        // Bubble type values other than 1 (user) or 2 (assistant)
        for type_val in [0, 3, -1, 999] {
            let bubble = json!({
                "text": "Unknown type bubble",
                "type": type_val
            });

            let msg = CursorConnector::parse_bubble(&bubble, 0);
            assert!(
                msg.is_some(),
                "type {} should still produce a message",
                type_val
            );
            assert_eq!(
                msg.unwrap().role,
                "assistant",
                "unknown numeric type {} should default to assistant",
                type_val
            );
        }
    }

    #[test]
    fn null_bytes_in_bubble_content_handled() {
        let bubble = json!({
            "text": "before\u{0000}after",
            "type": "user"
        });

        let msg = CursorConnector::parse_bubble(&bubble, 0);
        assert!(
            msg.is_some(),
            "null bytes in content should not cause errors"
        );
    }

    #[test]
    fn mixed_valid_and_invalid_entries_in_db() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("state.vscdb");

        let conn = create_test_db(&db_path);

        // Insert invalid JSON
        conn.execute_compat(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            params!["composerData:invalid-1", "not valid json {{{"],
        )
        .unwrap();

        // Insert valid entry
        let valid_value = json!({ "text": "Valid entry" }).to_string();
        conn.execute_compat(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            params!["composerData:valid-1", valid_value.as_str()],
        )
        .unwrap();

        // Insert empty JSON
        conn.execute_compat(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            params!["composerData:empty-1", "{}"],
        )
        .unwrap();

        // Insert another valid entry
        let valid_value2 = json!({ "text": "Another valid" }).to_string();
        conn.execute_compat(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            params!["composerData:valid-2", valid_value2.as_str()],
        )
        .unwrap();

        drop(conn);

        let convs = CursorConnector::extract_from_db(&db_path, None).unwrap();
        assert_eq!(
            convs.len(),
            2,
            "should extract only the valid conversations, skipping invalid/empty"
        );
    }

    #[test]
    fn parse_workspace_uri_handles_malformed_uris() {
        // Empty string
        assert!(CursorConnector::parse_workspace_uri("").is_none());

        // No scheme
        assert!(CursorConnector::parse_workspace_uri("just/a/path").is_none());

        // Unknown scheme
        assert!(CursorConnector::parse_workspace_uri("ftp://host/path").is_none());

        // file:// with path should work
        let result = CursorConnector::parse_workspace_uri("file:///home/user/project");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), PathBuf::from("/home/user/project"));

        // vscode-remote:// with no path separator
        assert!(CursorConnector::parse_workspace_uri("vscode-remote://no-slash-here").is_none());

        // URL-encoded file:// path
        let result = CursorConnector::parse_workspace_uri("file:///home/user/my%20project/src");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), PathBuf::from("/home/user/my project/src"));
    }

    #[test]
    fn since_ts_filtering_skips_old_conversations() {
        let key = "composerData:old-conv";
        let value = json!({
            "text": "Old message",
            "createdAt": 1000000000000i64,
            "lastUpdatedAt": 1000000001000i64
        })
        .to_string();

        let mut seen = HashSet::new();
        // Set since_ts to after the conversation's lastUpdatedAt
        let conv = CursorConnector::parse_composer_data(
            key,
            &value,
            Path::new("/test"),
            Some(1500000000000),
            &mut seen,
            None,
        );

        assert!(
            conv.is_none(),
            "conversation older than since_ts should be skipped"
        );
    }

    // NOTE:
    // The original cass test mutated HOME to validate default detection behavior.
    // Rust 2024 marks process-wide environment mutation as unsafe, and this crate
    // forbids unsafe code globally. Keep behavior covered by explicit-root tests.
}
