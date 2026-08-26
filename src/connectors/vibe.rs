//! Connector for Vibe (Mistral) session logs.
//!
//! Vibe stores JSONL sessions at:
//! - ~/.vibe/logs/session/*/messages.jsonl
//!
//! Each line is a message object:
//! {"role":"user|assistant|system","content":"...","timestamp":"..."}

use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;
use walkdir::WalkDir;

use std::collections::HashSet;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::dedupe_path_key;
use super::{
    Connector, file_modified_since, flatten_content, franken_detection_for_connector,
    parse_timestamp,
};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct VibeConnector;

impl Default for VibeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl VibeConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
    fn sessions_root() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".vibe")
            .join("logs")
            .join("session")
    }

    fn looks_like_vibe_storage(path: &Path) -> bool {
        // Structural parent-chain check: `<...>/.vibe/logs/session`.
        // A substring test mis-scoped default detection onto lookalikes
        // such as `/home/u/.vibe-backup/logs/session-archive`.
        let matches_layout = path.file_name().is_some_and(|n| n == "session")
            && path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == "logs"))
            && path
                .parent()
                .and_then(Path::parent)
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".vibe"));
        let is_logs_dir = path.file_name().is_some_and(|n| n == "logs")
            && path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".vibe"));
        let is_vibe_dir = path.file_name().is_some_and(|n| n == ".vibe")
            && path.join("logs").join("session").is_dir();
        matches_layout || is_logs_dir || is_vibe_dir
    }

    fn append_explicit_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        if base.exists() && Self::looks_like_vibe_storage(base) {
            roots.push(base.to_path_buf());
        }

        if base.file_name().is_some_and(|n| n == ".vibe") {
            let sessions = base.join("logs").join("session");
            if sessions.exists() {
                roots.push(sessions);
            }
        }

        if base.file_name().is_some_and(|n| n == "logs")
            && base
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".vibe"))
        {
            let sessions = base.join("session");
            if sessions.exists() {
                roots.push(sessions);
            }
        }
    }

    pub(crate) fn session_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if !root.exists() {
            return out;
        }

        for entry in WalkDir::new(root).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }

            if entry.file_name() == "messages.jsonl" {
                out.push(entry.path().to_path_buf());
            }
        }

        // Keep connector traversal deterministic across filesystems/runs.
        out.sort();
        out
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots: Vec<ScanRoot> = Vec::new();
        if ctx.use_default_detection() {
            if Self::looks_like_vibe_storage(&ctx.data_dir) && ctx.data_dir.exists() {
                roots.push(ScanRoot::local(ctx.data_dir.clone()));
            } else {
                let root = Self::sessions_root();
                if root.exists() {
                    roots.push(ScanRoot::local(root));
                }
            }
        } else {
            for root in &ctx.scan_roots {
                let candidate = root.path.join(".vibe/logs/session");
                if candidate.exists() {
                    roots.push(root.with_path(candidate));
                }

                let mut explicit = Vec::new();
                Self::append_explicit_roots(&mut explicit, &root.path);
                roots.extend(explicit.into_iter().map(|path| root.with_path(path)));
            }
        }
        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        // Same cross-root dedupe as scan(): overlapping or symlink-aliased
        // roots must not produce duplicate discovered sources.
        let mut seen_files: HashSet<PathBuf> = HashSet::new();
        for mut root in Self::source_roots(ctx) {
            if root.path.is_file() {
                let parent = root.path.parent().unwrap_or(&root.path).to_path_buf();
                root = root.with_path(parent);
            }
            for file in Self::session_files(&root.path) {
                if !seen_files.insert(dedupe_path_key(&file)) {
                    continue;
                }
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "vibe",
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

    fn extract_role(val: &Value) -> String {
        val.get("role")
            .and_then(|v| v.as_str())
            .or_else(|| val.get("speaker").and_then(|v| v.as_str()))
            .or_else(|| {
                val.get("message")
                    .and_then(|m| m.get("role"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("assistant")
            .to_string()
    }

    fn extract_content(val: &Value) -> String {
        if let Some(content) = val.get("content") {
            return flatten_content(content);
        }
        if let Some(content) = val.get("text") {
            return flatten_content(content);
        }
        if let Some(content) = val.get("message").and_then(|msg| msg.get("content")) {
            return flatten_content(content);
        }
        String::new()
    }

    fn extract_timestamp(val: &Value) -> Option<i64> {
        let candidates = ["timestamp", "created_at", "createdAt", "time", "ts"];

        for key in candidates {
            if let Some(ts) = val.get(key).and_then(parse_timestamp) {
                return Some(ts);
            }
        }

        if let Some(message) = val.get("message") {
            for key in candidates {
                if let Some(ts) = message.get(key).and_then(parse_timestamp) {
                    return Some(ts);
                }
            }
        }

        None
    }
}

impl Connector for VibeConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("vibe").unwrap_or_else(DetectionResult::not_found)
    }

    #[allow(clippy::too_many_lines)]
    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let roots: Vec<PathBuf> = Self::source_roots(ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();

        if roots.is_empty() {
            return Ok(Vec::new());
        }

        // Overlapping or symlink-aliased roots reach the same session file
        // twice; dedupe across ALL roots on the lossless path key.
        let mut seen_files: HashSet<PathBuf> = HashSet::new();

        let mut convs = Vec::new();

        for mut root in roots {
            if root.is_file() {
                root = root.parent().unwrap_or(&root).to_path_buf();
            }

            let files = Self::session_files(&root);
            for file in files {
                if !seen_files.insert(dedupe_path_key(&file)) {
                    continue;
                }
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }

                let external_id = file
                    .parent()
                    .and_then(|parent| parent.strip_prefix(&root).ok())
                    .and_then(|rel| rel.to_str().map(str::to_string))
                    .or_else(|| {
                        file.parent()
                            .and_then(|p| p.file_name())
                            .and_then(|s| s.to_str())
                            .map(str::to_string)
                    });

                let source_path = file;
                let file_handle = match fs::File::open(&source_path) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::debug!(
                            path = %source_path.display(),
                            error = %e,
                            "vibe: skipping unreadable session"
                        );
                        continue;
                    }
                };
                let reader = std::io::BufReader::new(file_handle);

                let mut messages = Vec::new();
                let mut started_at: Option<i64> = None;
                let mut ended_at: Option<i64> = None;

                for line_res in reader.lines() {
                    let Ok(line) = line_res else {
                        continue;
                    };
                    if line.trim().is_empty() {
                        continue;
                    }

                    let line = line.trim_start_matches('\u{feff}');
                    let val: Value = match serde_json::from_str(line) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let role = Self::extract_role(&val);
                    let content = Self::extract_content(&val);

                    if content.trim().is_empty() {
                        continue;
                    }

                    let created = Self::extract_timestamp(&val);
                    started_at = match (started_at, created) {
                        (Some(curr), Some(ts)) => Some(curr.min(ts)),
                        (None, Some(ts)) => Some(ts),
                        (other, None) => other,
                    };
                    ended_at = match (ended_at, created) {
                        (Some(curr), Some(ts)) => Some(curr.max(ts)),
                        (None, Some(ts)) => Some(ts),
                        (other, None) => other,
                    };

                    messages.push(NormalizedMessage {
                        idx: i64::try_from(messages.len()).unwrap_or(i64::MAX),
                        role,
                        author: None,
                        created_at: created,
                        content,
                        extra: val,
                        invocations: Vec::new(),
                        snippets: Vec::new(),
                    });
                }

                if messages.is_empty() {
                    continue;
                }

                let title = messages
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
                        messages
                            .first()
                            .and_then(|m| m.content.lines().next())
                            .map(|s| s.chars().take(100).collect())
                    });

                let metadata = serde_json::json!({
                    "source": "vibe",
                });

                convs.push(NormalizedConversation {
                    agent_slug: "vibe".to_string(),
                    external_id,
                    title,
                    workspace: None,
                    source_path,
                    started_at,
                    ended_at,
                    metadata,
                    messages,
                });
            }
        }

        Ok(convs)
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use tempfile::TempDir;

    fn write_session(root: &Path, session_id: &str, lines: &[&str]) -> PathBuf {
        let dir = root.join(session_id);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("messages.jsonl");
        let content = lines.join("\n");
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn scan_parses_basic_jsonl() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".vibe/logs/session");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "sess-123",
            &[
                r#"{"role":"user","content":"Hello there","timestamp":"2025-01-27T03:30:00.000Z"}"#,
                r#"{"role":"assistant","content":"Hi","timestamp":"2025-01-27T03:30:05.000Z"}"#,
            ],
        );

        let connector = VibeConnector::new();
        let ctx = ScanContext::local_default(sessions, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "vibe");
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].title, Some("Hello there".to_string()));
        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
        assert!(
            convs[0]
                .external_id
                .as_deref()
                .unwrap_or("")
                .contains("sess-123")
        );
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn scan_skips_invalid_and_empty_lines() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".vibe/logs/session");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "sess-456",
            &[
                "",
                "not-json",
                r#"{"role":"user","content":"Line 1","timestamp":"2025-01-27T03:30:00.000Z"}"#,
                r#"{"role":"assistant","content":"","timestamp":"2025-01-27T03:30:05.000Z"}"#,
            ],
        );

        let connector = VibeConnector::new();
        let ctx = ScanContext::local_default(sessions, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].role, "user");
    }

    #[test]
    fn scan_with_vibe_root_scan_root() {
        let tmp = TempDir::new().unwrap();
        let vibe_root = tmp.path().join(".vibe");
        let sessions = vibe_root.join("logs").join("session");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "sess-root",
            &[r#"{"role":"user","content":"Root scan","timestamp":1700000000000}"#],
        );

        let connector = VibeConnector::new();
        let ctx = ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(vibe_root)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Root scan");
    }

    #[test]
    fn session_files_returns_sorted_order() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".vibe/logs/session");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "z-last",
            &[r#"{"role":"user","content":"z","timestamp":"2025-01-27T03:30:00.000Z"}"#],
        );
        write_session(
            &sessions,
            "a-first",
            &[r#"{"role":"user","content":"a","timestamp":"2025-01-27T03:30:00.000Z"}"#],
        );
        write_session(
            &sessions,
            "m-middle",
            &[r#"{"role":"user","content":"m","timestamp":"2025-01-27T03:30:00.000Z"}"#],
        );

        let files = VibeConnector::session_files(&sessions);
        let mut sorted = files.clone();
        sorted.sort();
        assert_eq!(files, sorted);
    }
}
