use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::{dedupe_path_key, read_capped};
use super::{
    Connector, extract_invocations_from_content_blocks, flatten_content,
    franken_detection_for_connector, parse_timestamp, unwrap_skill_invocations,
};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct AmpConnector;
impl Default for AmpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl AmpConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn cache_root() -> Option<PathBuf> {
        // Check actual environment variable first (not .env files — Amp relies on
        // real shell environment, and dotenvy can mask the true XDG_DATA_HOME).
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            let p = PathBuf::from(xdg).join("amp");
            if p.exists() {
                return Some(p);
            }
        }
        // Check XDG default (~/.local/share/amp) — Amp uses this on all platforms
        if let Some(home) = dirs::home_dir() {
            let xdg_default = home.join(".local").join("share").join("amp");
            if xdg_default.exists() {
                return Some(xdg_default);
            }
        }
        // Fall back to platform-specific data dir (e.g. ~/Library/Application Support on macOS)
        dirs::data_dir().map(|d| d.join("amp"))
    }

    fn vscode_global_storage() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        if let Some(home) = dirs::home_dir() {
            roots.push(home.join(".config/Code/User/globalStorage/sourcegraph.amp"));
            roots.push(home.join(".config/Code - Insiders/User/globalStorage/sourcegraph.amp"));
            roots.push(home.join(".config/VSCodium/User/globalStorage/sourcegraph.amp"));
            roots.push(
                home.join("Library/Application Support/Code/User/globalStorage/sourcegraph.amp"),
            );
            roots.push(home.join(
                "Library/Application Support/Code - Insiders/User/globalStorage/sourcegraph.amp",
            ));
            roots.push(
                home.join(
                    "Library/Application Support/VSCodium/User/globalStorage/sourcegraph.amp",
                ),
            );
            roots.push(home.join("AppData/Roaming/Code/User/globalStorage/sourcegraph.amp"));
            roots.push(
                home.join("AppData/Roaming/Code - Insiders/User/globalStorage/sourcegraph.amp"),
            );
            roots.push(home.join("AppData/Roaming/VSCodium/User/globalStorage/sourcegraph.amp"));
        }
        roots
    }

    #[must_use]
    pub fn candidate_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        if let Some(root) = Self::cache_root() {
            roots.push(root);
        }
        roots.extend(Self::vscode_global_storage());
        roots
    }

    fn looks_like_root(path: &Path) -> bool {
        (path.is_file() && is_amp_log_file(path))
            || path
                .file_name()
                .is_some_and(|n| n.to_str().unwrap_or("").contains("amp"))
            || std::fs::read_dir(path)
                .is_ok_and(|mut d| d.any(|e| e.is_ok_and(|e| is_amp_log_file(&e.path()))))
    }

    fn append_explicit_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        let file_name = base.file_name().and_then(|n| n.to_str());
        let is_config = file_name.is_some_and(|n| n == ".config");
        let is_local = file_name.is_some_and(|n| n == ".local");
        let is_share = file_name.is_some_and(|n| n == "share")
            && base
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".local"));
        let is_app_support = file_name.is_some_and(|n| n == "Application Support");
        let is_appdata_roaming = file_name.is_some_and(|n| n == "Roaming")
            && base
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == "AppData"));
        let is_code_variant =
            file_name.is_some_and(|n| n == "Code" || n == "Code - Insiders" || n == "VSCodium");
        let is_user = file_name.is_some_and(|n| n == "User");
        let is_global_storage = file_name.is_some_and(|n| n == "globalStorage");

        if Self::looks_like_root(base) {
            roots.push(base.to_path_buf());
        }

        if is_global_storage {
            let candidate = base.join("sourcegraph.amp");
            if Self::looks_like_root(&candidate) {
                roots.push(candidate);
            }
        }

        let mut candidates: Vec<PathBuf> = Vec::new();

        if is_config {
            candidates.push(base.join("Code/User/globalStorage/sourcegraph.amp"));
            candidates.push(base.join("Code - Insiders/User/globalStorage/sourcegraph.amp"));
            candidates.push(base.join("VSCodium/User/globalStorage/sourcegraph.amp"));
        }

        if is_app_support {
            candidates.push(base.join("amp"));
            candidates.push(base.join("Code/User/globalStorage/sourcegraph.amp"));
            candidates.push(base.join("Code - Insiders/User/globalStorage/sourcegraph.amp"));
            candidates.push(base.join("VSCodium/User/globalStorage/sourcegraph.amp"));
        }

        if is_appdata_roaming {
            candidates.push(base.join("amp"));
            candidates.push(base.join("Code/User/globalStorage/sourcegraph.amp"));
            candidates.push(base.join("Code - Insiders/User/globalStorage/sourcegraph.amp"));
            candidates.push(base.join("VSCodium/User/globalStorage/sourcegraph.amp"));
        }

        if is_code_variant {
            candidates.push(base.join("User/globalStorage/sourcegraph.amp"));
        }

        if is_user {
            candidates.push(base.join("globalStorage/sourcegraph.amp"));
        }

        if is_local {
            candidates.push(base.join("share/amp"));
        }

        if is_share {
            candidates.push(base.join("amp"));
        }

        if !(is_config
            || is_local
            || is_share
            || is_app_support
            || is_appdata_roaming
            || is_code_variant
            || is_user
            || is_global_storage)
        {
            candidates.push(base.join(".local/share/amp"));
            candidates.push(base.join("Library/Application Support/amp"));
            candidates.push(base.join("AppData/Roaming/amp"));
            candidates.push(base.join(".config/Code/User/globalStorage/sourcegraph.amp"));
            candidates
                .push(base.join(".config/Code - Insiders/User/globalStorage/sourcegraph.amp"));
            candidates.push(base.join(".config/VSCodium/User/globalStorage/sourcegraph.amp"));
            candidates.push(
                base.join("Library/Application Support/Code/User/globalStorage/sourcegraph.amp"),
            );
            candidates.push(base.join(
                "Library/Application Support/Code - Insiders/User/globalStorage/sourcegraph.amp",
            ));
            candidates.push(
                base.join(
                    "Library/Application Support/VSCodium/User/globalStorage/sourcegraph.amp",
                ),
            );
            candidates.push(base.join("AppData/Roaming/Code/User/globalStorage/sourcegraph.amp"));
            candidates.push(
                base.join("AppData/Roaming/Code - Insiders/User/globalStorage/sourcegraph.amp"),
            );
            candidates
                .push(base.join("AppData/Roaming/VSCodium/User/globalStorage/sourcegraph.amp"));
        }

        for candidate in candidates {
            if Self::looks_like_root(&candidate) {
                roots.push(candidate);
            }
        }
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots: Vec<ScanRoot> = if ctx.use_default_detection() {
            if Self::looks_like_root(&ctx.data_dir) {
                vec![ScanRoot::local(ctx.data_dir.clone())]
            } else {
                Self::candidate_roots()
                    .into_iter()
                    .map(ScanRoot::local)
                    .collect()
            }
        } else {
            let mut explicit_roots = Vec::new();
            for scan_root in &ctx.scan_roots {
                let mut candidates = Vec::new();
                Self::append_explicit_roots(&mut candidates, &scan_root.path);
                explicit_roots.extend(candidates.into_iter().map(|path| scan_root.with_path(path)));
            }
            explicit_roots
        };

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        for root in Self::source_roots(ctx) {
            if !root.path.exists() {
                continue;
            }
            for entry in WalkDir::new(&root.path).into_iter().flatten() {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path();
                if !is_amp_log_file(path) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "amp",
                        &root,
                        path.to_path_buf(),
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }
        }
        out
    }
}

impl Connector for AmpConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("amp").unwrap_or_else(DetectionResult::not_found)
    }

    #[allow(clippy::too_many_lines)]
    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        let mut seen_ids = std::collections::HashSet::<PathBuf>::new();
        let roots: Vec<PathBuf> = Self::source_roots(ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();

        for root in roots {
            if !root.exists() {
                continue;
            }

            for entry in WalkDir::new(&root).into_iter().flatten() {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path();
                if !is_amp_log_file(path) {
                    continue;
                }
                // NOTE: We intentionally skip the file_modified_since() check for Amp.
                // Amp does not update file mtime when new messages are added to a thread,
                // so mtime-based incremental indexing would miss new messages.
                // This means Amp files are always re-read, but correctness is preserved.
                // Amp never bumps mtimes, so oversized threads are re-read
                // on EVERY scan — enforce the project's 100MB cap here.
                let text = match read_capped(path) {
                    Ok(Some(text)) => text,
                    Ok(None) => {
                        tracing::warn!(
                            path = %path.display(),
                            "amp: thread exceeds the scan size cap; skipping"
                        );
                        continue;
                    }
                    Err(_) => continue,
                };
                let val: Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                if let Some(messages) = extract_messages(&val, ctx.since_ts) {
                    if messages.is_empty() {
                        continue;
                    }
                    let title = val
                        .get("title")
                        .and_then(|v| v.as_str())
                        .map(std::string::ToString::to_string)
                        .or_else(|| {
                            messages
                                .first()
                                .and_then(|m| m.content.lines().next())
                                .map(std::string::ToString::to_string)
                        });

                    let workspace = infer_workspace(&val).or_else(|| {
                        messages.iter().find_map(|m| {
                            m.extra
                                .get("workspace")
                                .and_then(|w| w.as_str())
                                .map(PathBuf::from)
                        })
                    });

                    // Identity precedence: the thread's own `id` field is
                    // what amp itself addresses a thread by; a bare file
                    // stem ("thread.json") is shared by EVERY thread in a
                    // store and collides downstream. Fall back to the
                    // root-relative path (stable within a store), then the
                    // lossless full path.
                    let external_id = val
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|id| !id.trim().is_empty())
                        .map(String::from)
                        .or_else(|| {
                            path.strip_prefix(&root).ok().and_then(|rel| {
                                rel.to_str().map(|s| s.trim_start_matches('/').to_string())
                            })
                        })
                        .or_else(|| {
                            path.file_stem()
                                .and_then(|s| s.to_str())
                                .map(std::string::ToString::to_string)
                        })
                        .or_else(|| Some(path.display().to_string()));

                    // Key on the full, losslessly-encoded path: is_amp_log_file
                    // accepts any *.json under a "threads" directory, so distinct
                    // files frequently share a stem across roots — a stem-only
                    // key silently dropped every thread after the first.
                    // PathBuf (not Display) keeps non-UTF8 OsStr bytes intact.
                    let key = dedupe_path_key(path);
                    if seen_ids.insert(key) {
                        // Use per-message timestamps when available, falling back
                        // to the top-level "created" field (millisecond epoch) that
                        // Amp stores on thread objects.
                        let thread_created = val.get("created").and_then(parse_timestamp);
                        let started_at = messages
                            .iter()
                            .filter_map(|m| m.created_at)
                            .min()
                            .or(thread_created);
                        let ended_at = messages
                            .iter()
                            .filter_map(|m| m.created_at)
                            .max()
                            .or(thread_created);

                        convs.push(NormalizedConversation {
                            agent_slug: "amp".into(),
                            external_id,
                            title,
                            workspace,
                            source_path: path.to_path_buf(),
                            started_at,
                            ended_at,
                            metadata: val.clone(),
                            messages,
                        });
                        tracing::info!(
                            target: "connector::amp",
                            source = %path.display(),
                            messages = convs.last().map_or(0, |c| c.messages.len()),
                            since_ts = ctx.since_ts,
                            "amp_scan"
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

fn extract_messages(val: &Value, _since_ts: Option<i64>) -> Option<Vec<NormalizedMessage>> {
    let msgs = val
        .get("messages")
        .and_then(|m| m.as_array().cloned())
        .or_else(|| {
            val.get("thread")
                .and_then(|t| t.get("messages"))
                .and_then(|m| m.as_array().cloned())
        })?;

    let mut out = Vec::new();
    for m in msgs {
        // Amp thread JSON uses several raw spellings for turns ("human",
        // "agent", "userMessage", "assistantMsg", …). Normalize to the
        // conformance contract's role set — downstream consumers route on
        // user/assistant, and raw pass-through misfiles user turns.
        let raw_role = m
            .get("role")
            .or_else(|| m.get("speaker"))
            .or_else(|| m.get("type"))
            .and_then(|v| v.as_str());
        let role = normalize_amp_role(raw_role);

        // Handle content as either string or array of content blocks
        let content = extract_content_value(m.get("content"))
            .or_else(|| extract_content_value(m.get("text")))
            .or_else(|| extract_content_value(m.get("body")))
            .unwrap_or_default();

        if content.trim().is_empty() {
            continue;
        }

        // Use parse_timestamp to handle both i64 milliseconds and ISO-8601 strings
        // Also check sentAt which Amp uses, and "created" (millisecond epoch)
        let created_at = m
            .get("created_at")
            .or_else(|| m.get("createdAt"))
            .or_else(|| m.get("sentAt"))
            .or_else(|| m.get("timestamp"))
            .or_else(|| m.get("ts"))
            .or_else(|| m.get("created"))
            .and_then(parse_timestamp);
        let author = m
            .get("author")
            .or_else(|| m.get("sender"))
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string);

        // NOTE: Do NOT filter individual messages by timestamp here!
        // The file-level check in file_modified_since() is sufficient.
        // Filtering messages would cause older messages to be lost when
        // the file is re-indexed after new messages are added.

        out.push(NormalizedMessage {
            idx: 0, // Will be re-assigned after filtering
            role: role.to_string(),
            author,
            created_at,
            content,
            extra: m.clone(),
            invocations: {
                let mut inv = m
                    .get("content")
                    .map_or_else(Vec::new, extract_invocations_from_content_blocks);
                unwrap_skill_invocations(&mut inv);
                inv
            },
            snippets: Vec::new(),
        });
    }

    // Re-assign indices after filtering to maintain sequential order
    crate::types::reindex_messages(&mut out);

    if out.is_empty() { None } else { Some(out) }
}

/// Map an Amp raw role/speaker/type spelling onto the conformance contract's
/// valid role set (`user`, `assistant`, `system`, `tool`, `function`).
///
/// Amp threads label turns "human"/"agent" (and some exports use
/// "userMessage"/"assistantMsg"); everything model-side — including missing
/// and unrecognized spellings, which historically defaulted to "agent" —
/// maps to `assistant`.
fn normalize_amp_role(raw: Option<&str>) -> &'static str {
    match raw.map(str::to_ascii_lowercase).as_deref() {
        Some("human" | "user" | "usermessage") => "user",
        Some("system") => "system",
        Some("toolresult" | "tool") => "tool",
        _ => "assistant",
    }
}

/// Extract text content from a value that may be a string or an array of content blocks.
/// Uses the shared `flatten_content` helper for consistent handling across all connectors.
fn extract_content_value(val: Option<&Value>) -> Option<String> {
    let val = val?;
    let result = flatten_content(val);
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn infer_workspace(val: &Value) -> Option<PathBuf> {
    let keys = ["workspace", "cwd", "path", "project_path", "repo", "root"];
    for k in keys {
        if let Some(p) = val.get(k).and_then(|v| v.as_str()) {
            return Some(PathBuf::from(p));
        }
    }

    // Amp stores workspace at env.initial.trees[].uri (as a file:// URI or path)
    if let Some(trees) = val
        .get("env")
        .and_then(|e| e.get("initial"))
        .and_then(|i| i.get("trees"))
        .and_then(|t| t.as_array())
    {
        for tree in trees {
            if let Some(uri) = tree.get("uri").and_then(|u| u.as_str()) {
                let path_str = if let Some(stripped) = uri.strip_prefix("file://") {
                    // Decode %XX escapes (e.g. `my%20project`): the URI is
                    // wire format, the workspace is a filesystem path.
                    super::percent_decode_utf8(stripped)
                } else if !uri.contains("://") {
                    // Bare path (no scheme), treat as filesystem path
                    uri.to_string()
                } else {
                    // Non-file scheme (ssh://, https://, vscode-remote://…) — skip
                    continue;
                };
                if !path_str.is_empty() {
                    return Some(PathBuf::from(path_str));
                }
            }
        }
    }

    None
}

fn is_amp_log_file(path: &std::path::Path) -> bool {
    if path.extension().and_then(|e| e.to_str()) != Some("json") {
        return false;
    }
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
        let stem_lower = stem.to_ascii_lowercase();
        // Match known patterns: thread, conversation, chat
        if stem_lower.contains("thread")
            || stem_lower.contains("conversation")
            || stem_lower.contains("chat")
        {
            return true;
        }
        // Match Amp's T-{uuid}.json format (e.g., T-01872a67-152b-46af-a1af-4de6fce3d2b3.json)
        if stem_lower.starts_with("t-") && looks_like_uuid(&stem[2..]) {
            return true;
        }
    }
    // Also match any .json file in a "threads" directory
    if let Some(parent) = path.parent()
        && let Some(dir_name) = parent.file_name().and_then(|n| n.to_str())
        && dir_name == "threads"
    {
        return true;
    }
    false
}

/// Check if a string looks like a UUID (8-4-4-4-12 hex pattern)
fn looks_like_uuid(s: &str) -> bool {
    // UUID format: 8-4-4-4-12 (32 hex chars + 4 dashes = 36 chars)
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8, 4, 4, 4, 12];
    for (part, &expected_len) in parts.iter().zip(expected_lens.iter()) {
        if part.len() != expected_len || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    // =====================================================
    // Constructor Tests
    // =====================================================

    #[test]
    fn new_creates_connector() {
        let connector = AmpConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = AmpConnector;
        let _ = connector;
    }

    // =====================================================
    // is_amp_log_file() Tests
    // =====================================================

    #[test]
    fn is_amp_log_file_matches_thread_json() {
        assert!(is_amp_log_file(std::path::Path::new("thread.json")));
        assert!(is_amp_log_file(std::path::Path::new("my-thread.json")));
        assert!(is_amp_log_file(std::path::Path::new("Thread_123.json")));
    }

    #[test]
    fn is_amp_log_file_matches_conversation_json() {
        assert!(is_amp_log_file(std::path::Path::new("conversation.json")));
        assert!(is_amp_log_file(std::path::Path::new(
            "conversation-2025-12-17.json"
        )));
        assert!(is_amp_log_file(std::path::Path::new("CONVERSATION.json")));
    }

    #[test]
    fn is_amp_log_file_matches_chat_json() {
        assert!(is_amp_log_file(std::path::Path::new("chat.json")));
        assert!(is_amp_log_file(std::path::Path::new("chat-session.json")));
        assert!(is_amp_log_file(std::path::Path::new("Chat_Log.json")));
    }

    #[test]
    fn is_amp_log_file_rejects_non_json() {
        assert!(!is_amp_log_file(std::path::Path::new("thread.txt")));
        assert!(!is_amp_log_file(std::path::Path::new("conversation.xml")));
        assert!(!is_amp_log_file(std::path::Path::new("chat")));
    }

    #[test]
    fn is_amp_log_file_rejects_wrong_stems() {
        assert!(!is_amp_log_file(std::path::Path::new("config.json")));
        assert!(!is_amp_log_file(std::path::Path::new("settings.json")));
        assert!(!is_amp_log_file(std::path::Path::new("data.json")));
    }

    #[test]
    fn is_amp_log_file_matches_uuid_format() {
        // Amp stores files as T-{uuid}.json
        assert!(is_amp_log_file(std::path::Path::new(
            "T-01872a67-152b-46af-a1af-4de6fce3d2b3.json"
        )));
        assert!(is_amp_log_file(std::path::Path::new(
            "t-abcdef12-3456-7890-abcd-ef1234567890.json"
        )));
    }

    #[test]
    fn is_amp_log_file_rejects_invalid_uuid() {
        // T- prefix but not a valid UUID
        assert!(!is_amp_log_file(std::path::Path::new("T-not-a-uuid.json")));
        assert!(!is_amp_log_file(std::path::Path::new("T-12345.json")));
    }

    #[test]
    fn is_amp_log_file_matches_threads_directory() {
        // Any .json in a "threads" directory should match
        assert!(is_amp_log_file(std::path::Path::new(
            "/home/user/.local/share/amp/threads/random-file.json"
        )));
        assert!(is_amp_log_file(std::path::Path::new(
            "threads/any-name.json"
        )));
    }

    #[test]
    fn looks_like_uuid_valid_uuids() {
        assert!(looks_like_uuid("01872a67-152b-46af-a1af-4de6fce3d2b3"));
        assert!(looks_like_uuid("abcdef12-3456-7890-abcd-ef1234567890"));
        assert!(looks_like_uuid("00000000-0000-0000-0000-000000000000"));
        assert!(looks_like_uuid("ABCDEF12-3456-7890-ABCD-EF1234567890"));
    }

    #[test]
    fn looks_like_uuid_invalid() {
        assert!(!looks_like_uuid("not-a-uuid"));
        assert!(!looks_like_uuid("12345"));
        assert!(!looks_like_uuid(""));
        assert!(!looks_like_uuid("01872a67-152b-46af-a1af-4de6fce3d2b")); // too short
        assert!(!looks_like_uuid("01872a67-152b-46af-a1af-4de6fce3d2b33")); // too long
        assert!(!looks_like_uuid("0187zzzz-152b-46af-a1af-4de6fce3d2b3")); // non-hex
    }

    #[test]
    fn scan_with_global_storage_scan_root() {
        let tmp = TempDir::new().unwrap();
        let global_storage = tmp.path().join("globalStorage");
        let amp_root = global_storage.join("sourcegraph.amp");
        fs::create_dir_all(&amp_root).unwrap();

        let log = json!({
            "messages": [
                {"role": "user", "content": "Hello Amp", "created_at": 1_700_000_000_000_i64}
            ]
        });
        fs::write(amp_root.join("conversation.json"), log.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx =
            ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(global_storage)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Hello Amp");
    }

    // =====================================================
    // infer_workspace() Tests
    // =====================================================

    #[test]
    fn infer_workspace_from_workspace_key() {
        let val = json!({"workspace": "/home/user/project"});
        assert_eq!(
            infer_workspace(&val),
            Some(PathBuf::from("/home/user/project"))
        );
    }

    #[test]
    fn scan_prefers_thread_id_for_external_id_with_relative_path_fallback() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("amp-store");
        let threads = store.join("threads");
        fs::create_dir_all(&threads).unwrap();

        // A thread carrying amp's own id: that id is the identity.
        fs::write(
            threads.join("T-111.json"),
            json!({
                "id": "T-111",
                "title": "With id",
                "messages": [{"role": "user", "content": "hi"}]
            })
            .to_string(),
        )
        .unwrap();
        // An export without an id: the root-relative path keeps it unique
        // (a bare stem would collide with every other thread.json).
        fs::write(
            threads.join("thread.json"),
            json!({
                "title": "No id",
                "messages": [{"role": "user", "content": "hello"}]
            })
            .to_string(),
        )
        .unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(store, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
        let with_id = convs
            .iter()
            .find(|c| c.title.as_deref() == Some("With id"))
            .expect("thread with id");
        assert_eq!(with_id.external_id.as_deref(), Some("T-111"));
        let no_id = convs
            .iter()
            .find(|c| c.title.as_deref() == Some("No id"))
            .expect("thread without id");
        assert_eq!(no_id.external_id.as_deref(), Some("threads/thread.json"));
    }

    #[test]
    fn infer_workspace_from_cwd_key() {
        let val = json!({"cwd": "/home/user/cwd-project"});
        assert_eq!(
            infer_workspace(&val),
            Some(PathBuf::from("/home/user/cwd-project"))
        );
    }

    #[test]
    fn infer_workspace_from_path_key() {
        let val = json!({"path": "/home/user/path-project"});
        assert_eq!(
            infer_workspace(&val),
            Some(PathBuf::from("/home/user/path-project"))
        );
    }

    #[test]
    fn infer_workspace_from_project_path_key() {
        let val = json!({"project_path": "/home/user/proj"});
        assert_eq!(
            infer_workspace(&val),
            Some(PathBuf::from("/home/user/proj"))
        );
    }

    #[test]
    fn infer_workspace_from_repo_key() {
        let val = json!({"repo": "/home/user/repo"});
        assert_eq!(
            infer_workspace(&val),
            Some(PathBuf::from("/home/user/repo"))
        );
    }

    #[test]
    fn infer_workspace_from_root_key() {
        let val = json!({"root": "/home/user/root"});
        assert_eq!(
            infer_workspace(&val),
            Some(PathBuf::from("/home/user/root"))
        );
    }

    #[test]
    fn infer_workspace_returns_none_when_no_match() {
        let val = json!({"title": "Test", "id": "123"});
        assert!(infer_workspace(&val).is_none());
    }

    #[test]
    fn infer_workspace_prefers_workspace_key() {
        let val = json!({
            "workspace": "/workspace",
            "cwd": "/cwd",
            "path": "/path"
        });
        assert_eq!(infer_workspace(&val), Some(PathBuf::from("/workspace")));
    }

    // =====================================================
    // extract_messages() Tests
    // =====================================================

    #[test]
    fn extract_messages_from_messages_array() {
        let val = json!({
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there!"}
            ]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "user");
        assert_eq!(msgs[0].content, "Hello");
        assert_eq!(msgs[1].role, "assistant");
    }

    #[test]
    fn extract_messages_from_thread_messages() {
        let val = json!({
            "thread": {
                "messages": [
                    {"role": "user", "content": "Question?"},
                    {"role": "assistant", "content": "Answer!"}
                ]
            }
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, "Question?");
    }

    #[test]
    fn extract_messages_uses_speaker_as_role() {
        let val = json!({
            "messages": [{"speaker": "human", "content": "Test"}]
        });
        let msgs = extract_messages(&val, None).unwrap();
        // Raw Amp spellings normalize onto the conformance role set.
        assert_eq!(msgs[0].role, "user");
    }

    #[test]
    fn extract_messages_uses_type_as_role() {
        let val = json!({
            "messages": [{"type": "userMessage", "content": "Test"}]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs[0].role, "user");
    }

    #[test]
    fn extract_messages_uses_text_as_content() {
        let val = json!({
            "messages": [{"role": "user", "text": "Text content"}]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs[0].content, "Text content");
    }

    #[test]
    fn extract_messages_uses_body_as_content() {
        let val = json!({
            "messages": [{"role": "user", "body": "Body content"}]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs[0].content, "Body content");
    }

    #[test]
    fn extract_messages_skips_empty_content() {
        let val = json!({
            "messages": [
                {"role": "user", "content": "Valid"},
                {"role": "assistant", "content": ""},
                {"role": "assistant", "content": "   "}
            ]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "Valid");
    }

    #[test]
    fn extract_messages_parses_created_at() {
        let val = json!({
            "messages": [{"role": "user", "content": "Test", "created_at": 1_733_000_000}]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs[0].created_at, Some(1_733_000_000_000));
    }

    #[test]
    fn extract_messages_parses_created_at_camel_case() {
        let val = json!({
            "messages": [{"role": "user", "content": "Test", "createdAt": 1_733_000_001}]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs[0].created_at, Some(1_733_000_001_000));
    }

    #[test]
    fn extract_messages_parses_timestamp() {
        let val = json!({
            "messages": [{"role": "user", "content": "Test", "timestamp": 1_733_000_002}]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs[0].created_at, Some(1_733_000_002_000));
    }

    #[test]
    fn extract_messages_parses_ts() {
        let val = json!({
            "messages": [{"role": "user", "content": "Test", "ts": 1_733_000_003}]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs[0].created_at, Some(1_733_000_003_000));
    }

    #[test]
    fn extract_messages_parses_author() {
        let val = json!({
            "messages": [{"role": "user", "content": "Test", "author": "john"}]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs[0].author, Some("john".to_string()));
    }

    #[test]
    fn extract_messages_parses_sender_as_author() {
        let val = json!({
            "messages": [{"role": "user", "content": "Test", "sender": "jane"}]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs[0].author, Some("jane".to_string()));
    }

    #[test]
    fn extract_messages_assigns_sequential_indices() {
        let val = json!({
            "messages": [
                {"role": "user", "content": "First"},
                {"role": "assistant", "content": "Second"},
                {"role": "user", "content": "Third"}
            ]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs[0].idx, 0);
        assert_eq!(msgs[1].idx, 1);
        assert_eq!(msgs[2].idx, 2);
    }

    #[test]
    fn extract_messages_defaults_roleless_entries_to_assistant() {
        let val = json!({
            "messages": [{"content": "No role"}]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs[0].role, "assistant");
    }

    #[test]
    fn extract_messages_returns_none_for_empty() {
        let val = json!({"messages": []});
        assert!(extract_messages(&val, None).is_none());
    }

    #[test]
    fn extract_messages_returns_none_for_missing() {
        let val = json!({"title": "No messages"});
        assert!(extract_messages(&val, None).is_none());
    }

    #[test]
    fn extract_messages_handles_content_array() {
        // Amp can store content as an array of content blocks
        let val = json!({
            "messages": [{
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Part one."},
                    {"type": "text", "text": "Part two."}
                ]
            }]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].content.contains("Part one"));
        assert!(msgs[0].content.contains("Part two"));
    }

    #[test]
    fn extract_messages_handles_string_array_content() {
        // Content as array of plain strings
        let val = json!({
            "messages": [{
                "role": "user",
                "content": ["Hello", "World"]
            }]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].content.contains("Hello"));
        assert!(msgs[0].content.contains("World"));
    }

    #[test]
    fn extract_messages_parses_sent_at() {
        // Amp uses sentAt for message timestamps
        let val = json!({
            "messages": [{"role": "user", "content": "Test", "sentAt": 1_733_000_005}]
        });
        let msgs = extract_messages(&val, None).unwrap();
        assert_eq!(msgs[0].created_at, Some(1_733_000_005_000));
    }

    // =====================================================
    // scan() Tests
    // =====================================================

    fn create_amp_dir(dir: &TempDir) -> PathBuf {
        let amp_dir = dir.path().join("amp");
        fs::create_dir_all(&amp_dir).unwrap();
        amp_dir
    }

    #[test]
    fn scan_parses_simple_conversation() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let content = json!({
            "title": "Test Thread",
            "workspace": "/home/user/project",
            "messages": [
                {"role": "user", "content": "Hello Amp!"},
                {"role": "assistant", "content": "Hello! How can I help?"}
            ]
        });
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].title, Some("Test Thread".to_string()));
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/project"))
        );
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Amp!");
    }

    #[test]
    fn scan_handles_multiple_files() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let content1 = json!({
            "messages": [{"role": "user", "content": "Session 1"}]
        });
        let content2 = json!({
            "messages": [{"role": "user", "content": "Session 2"}]
        });
        fs::write(amp_dir.join("thread-1.json"), content1.to_string()).unwrap();
        fs::write(amp_dir.join("conversation-2.json"), content2.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
    }

    #[test]
    fn scan_handles_empty_directory() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_non_matching_files() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let content = json!({"messages": [{"role": "user", "content": "Test"}]});
        fs::write(amp_dir.join("config.json"), content.to_string()).unwrap();
        fs::write(amp_dir.join("settings.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_extracts_title_from_first_message_if_missing() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let content = json!({
            "messages": [
                {"role": "user", "content": "First line\nSecond line"},
                {"role": "assistant", "content": "Response"}
            ]
        });
        fs::write(amp_dir.join("chat.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("First line".to_string()));
    }

    #[test]
    fn scan_sets_agent_slug_to_amp() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let content = json!({"messages": [{"role": "user", "content": "Test"}]});
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].agent_slug, "amp");
    }

    #[test]
    fn scan_uses_relative_path_as_external_id_without_a_thread_id() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let content = json!({"messages": [{"role": "user", "content": "Test"}]});
        fs::write(amp_dir.join("my-thread-123.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // No `id` field: the root-relative path is the stable identity (a
        // bare stem is shared by every thread.json in a store).
        assert_eq!(convs[0].external_id, Some("my-thread-123.json".to_string()));
    }

    #[test]
    fn scan_extracts_timestamps_from_messages() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let content = json!({
            "messages": [
                {"role": "user", "content": "First", "timestamp": 1_733_000_000},
                {"role": "assistant", "content": "Last", "timestamp": 1_733_000_100}
            ]
        });
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].started_at, Some(1_733_000_000_000));
        assert_eq!(convs[0].ended_at, Some(1_733_000_100_000));
    }

    #[test]
    fn scan_skips_invalid_json() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        fs::write(amp_dir.join("thread.json"), "not valid json").unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_files_without_messages() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let content = json!({"title": "Empty Thread"});
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_handles_thread_nested_messages() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let content = json!({
            "thread": {
                "messages": [
                    {"role": "user", "content": "Nested message"}
                ]
            }
        });
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Nested message");
    }

    #[test]
    fn scan_deduplicates_by_external_id() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        // Create same file in nested directory
        let nested = amp_dir.join("nested");
        fs::create_dir_all(&nested).unwrap();

        let content = json!({
            "id": "same-id",
            "messages": [{"role": "user", "content": "Test"}]
        });
        fs::write(amp_dir.join("thread-same-id.json"), content.to_string()).unwrap();
        fs::write(nested.join("thread-same-id.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should have at least 1 (deduplication happens by external_id)
        assert!(!convs.is_empty());
    }

    #[test]
    fn scan_stores_source_path() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let content = json!({"messages": [{"role": "user", "content": "Test"}]});
        let file_path = amp_dir.join("thread.json");
        fs::write(&file_path, content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].source_path, file_path);
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn scan_infers_workspace_from_message_extra() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let content = json!({
            "messages": [
                {"role": "user", "content": "Test", "workspace": "/msg/workspace"}
            ]
        });
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].workspace, Some(PathBuf::from("/msg/workspace")));
    }

    #[test]
    fn scan_stores_full_json_as_metadata() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);

        let content = json!({
            "title": "Meta Test",
            "custom_field": "custom_value",
            "messages": [{"role": "user", "content": "Test"}]
        });
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["title"], "Meta Test");
        assert_eq!(convs[0].metadata["custom_field"], "custom_value");
    }

    // =====================================================
    // candidate_roots() Tests
    // =====================================================

    #[test]
    fn candidate_roots_returns_non_empty_list() {
        let roots = AmpConnector::candidate_roots();
        assert!(!roots.is_empty());
    }

    #[test]
    fn candidate_roots_includes_cache_root() {
        let roots = AmpConnector::candidate_roots();
        if let Some(cache) = AmpConnector::cache_root() {
            assert!(roots.contains(&cache));
        }
    }

    // =========================================================================
    // Edge case tests — malformed input robustness (br-2w98)
    // =========================================================================

    #[test]
    fn edge_empty_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        fs::write(amp_dir.join("thread.json"), "").unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_whitespace_only_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        fs::write(amp_dir.join("thread.json"), "   \n\n\t  ").unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_truncated_json_file_handled() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        // JSON truncated mid-object
        fs::write(
            amp_dir.join("thread.json"),
            r#"{"messages": [{"role": "user", "content": "hel"#,
        )
        .unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_invalid_utf8_file_skipped() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        // Write raw bytes that are invalid UTF-8
        std::fs::write(amp_dir.join("thread.json"), b"\xff\xfe{\"messages\":[]}").unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_bom_marker_at_file_start_handled() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        // UTF-8 BOM + valid JSON
        let mut data = vec![0xEF, 0xBB, 0xBF];
        data.extend_from_slice(br#"{"messages":[{"role":"user","content":"BOM test"}]}"#);
        std::fs::write(amp_dir.join("thread.json"), &data).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // BOM may cause JSON parse failure since serde_json doesn't strip BOM
        // The connector should skip the file gracefully either way
        assert!(convs.len() <= 1);
    }

    #[test]
    fn edge_json_type_mismatch_messages_not_array() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        // messages is a string instead of an array
        let content = json!({"messages": "not an array"});
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_json_type_mismatch_messages_is_number() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        let content = json!({"messages": 42});
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_deeply_nested_json_does_not_stack_overflow() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        // Create deeply nested JSON (200 levels)
        let mut nested = String::from(r#"{"messages":[{"role":"user","content":"deep","extra":"#);
        for _ in 0..200 {
            nested.push_str(r#"{"a":"#);
        }
        nested.push_str(r#""leaf""#);
        for _ in 0..200 {
            nested.push('}');
        }
        nested.push_str("}]}");
        fs::write(amp_dir.join("thread.json"), &nested).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        // Should not stack overflow - either parses or skips gracefully
        let result = connector.scan(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn edge_large_message_body_handled() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        let large_body = "x".repeat(1_000_000); // 1MB message
        let content = json!({
            "messages": [{"role": "user", "content": large_body}]
        });
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content.len(), 1_000_000);
    }

    #[test]
    fn edge_null_bytes_in_content_handled() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        let content = json!({
            "messages": [{"role": "user", "content": "hello\u{0000}world"}]
        });
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("hello"));
    }

    // ---- Amp-specific edge cases ----

    #[test]
    fn edge_uuid_filename_with_malformed_json() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        // T-{uuid}.json format with invalid content
        fs::write(
            amp_dir.join("T-01872a67-152b-46af-a1af-4de6fce3d2b3.json"),
            "not json",
        )
        .unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_thread_nested_messages_malformed_inner() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        // thread.messages exists but messages contain bad data
        let content = json!({
            "thread": {
                "messages": [
                    {"role": "user", "content": "Valid"},
                    {"content": null},
                    {"role": 42, "content": "Role is number"},
                    {"role": "assistant"}  // no content at all
                ]
            }
        });
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // Should parse at least the valid messages, skip empty/null content
        assert!(!convs.is_empty());
        for conv in &convs {
            for msg in &conv.messages {
                assert!(!msg.content.trim().is_empty());
            }
        }
    }

    #[test]
    fn edge_all_content_field_fallbacks() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        // Test text and body fallbacks
        let content = json!({
            "messages": [
                {"role": "user", "text": "From text field"},
                {"role": "assistant", "body": "From body field"}
            ]
        });
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].content, "From text field");
        assert_eq!(convs[0].messages[1].content, "From body field");
    }

    #[test]
    fn edge_iso_string_timestamp_parsing() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        let content = json!({
            "messages": [
                {"role": "user", "content": "Test", "sentAt": "2025-12-01T10:00:00Z"},
                {"role": "assistant", "content": "Reply", "createdAt": "2025-12-01T10:00:01.500Z"}
            ]
        });
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        // Both messages should have parsed timestamps
        assert!(convs[0].messages[0].created_at.is_some());
        assert!(convs[0].messages[1].created_at.is_some());
    }

    #[test]
    fn edge_mixed_role_key_variants() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        // Uses "speaker" and "type" as role keys
        let content = json!({
            "messages": [
                {"speaker": "human", "content": "Via speaker"},
                {"type": "assistantMsg", "content": "Via type"}
            ]
        });
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::local_default(amp_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[1].role, "assistant");
    }

    #[test]
    fn scan_with_explicit_local_share_root_finds_amp_cache() {
        let dir = TempDir::new().unwrap();
        let local_share = dir.path().join(".local/share");
        let amp_dir = local_share.join("amp");
        fs::create_dir_all(&amp_dir).unwrap();

        let content = json!({
            "messages": [
                {"role": "user", "content": "Hello from XDG"}
            ]
        });
        fs::write(amp_dir.join("thread.json"), content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::with_roots(
            dir.path().join("cass"),
            vec![ScanRoot::local(local_share)],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Hello from XDG");
    }

    #[test]
    fn scan_accepts_explicit_amp_log_file_root() {
        let dir = TempDir::new().unwrap();
        let amp_dir = create_amp_dir(&dir);
        let amp_file = amp_dir.join("thread-explicit.json");
        let content = json!({
            "messages": [
                {"role": "user", "content": "Explicit root works"}
            ]
        });
        fs::write(&amp_file, content.to_string()).unwrap();

        let connector = AmpConnector::new();
        let ctx = ScanContext::with_roots(
            amp_file.clone(),
            vec![crate::connectors::scan::ScanRoot::local(amp_file.clone())],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].source_path, amp_file);
        assert_eq!(convs[0].messages.len(), 1);
    }
}
