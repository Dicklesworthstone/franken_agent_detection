//! Connector for Clawdbot session logs.
//!
//! Clawdbot stores JSONL sessions at:
//! - ~/.clawdbot/sessions/*.jsonl
//!
//! Each line is a message object:
//! {"role":"user|assistant|system","content":"...","timestamp":"2025-01-27T03:30:00.000Z", ...}

use std::fs;
use std::io::BufRead;
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

pub struct ClawdbotConnector;

impl Default for ClawdbotConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl ClawdbotConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn sessions_root() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".clawdbot")
            .join("sessions")
    }

    fn looks_like_clawdbot_storage(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        path_str.contains("clawdbot") && path_str.contains("sessions")
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
            if entry.path().extension().and_then(|s| s.to_str()) == Some("jsonl") {
                out.push(entry.path().to_path_buf());
            }
        }

        // Keep connector traversal deterministic across filesystems/runs.
        out.sort();
        out
    }

    fn append_explicit_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        if base.exists() && Self::looks_like_clawdbot_storage(base) {
            roots.push(base.to_path_buf());
        }

        if base.file_name().is_some_and(|n| n == ".clawdbot") {
            let sessions = base.join("sessions");
            if sessions.exists() {
                roots.push(sessions);
            }
        }
    }
}

impl Connector for ClawdbotConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("clawdbot").unwrap_or_else(DetectionResult::not_found)
    }

    #[allow(clippy::too_many_lines)]
    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut roots: Vec<PathBuf> = Vec::new();

        if ctx.use_default_detection() {
            if Self::looks_like_clawdbot_storage(&ctx.data_dir) && ctx.data_dir.exists() {
                roots.push(ctx.data_dir.clone());
            } else {
                let root = Self::sessions_root();
                if root.exists() {
                    roots.push(root);
                }
            }
        } else {
            for root in &ctx.scan_roots {
                let candidate = root.path.join(".clawdbot").join("sessions");
                if candidate.exists() {
                    roots.push(candidate);
                }
                Self::append_explicit_roots(&mut roots, &root.path);
            }
        }

        if roots.is_empty() {
            return Ok(Vec::new());
        }

        let mut convs = Vec::new();

        for mut root in roots {
            if root.is_file() {
                root = root.parent().unwrap_or(&root).to_path_buf();
            }

            let files = Self::session_files(&root);
            for file in files {
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }

                let source_path = file.clone();
                let external_id = source_path
                    .strip_prefix(&root)
                    .ok()
                    .and_then(|rel| {
                        rel.with_extension("")
                            .to_str()
                            .map(std::string::ToString::to_string)
                    })
                    .or_else(|| {
                        source_path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .map(std::string::ToString::to_string)
                    });

                let file_handle = match fs::File::open(&file) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::debug!(path = %file.display(), error = %e, "clawdbot: skipping unreadable session");
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

                    let val: Value = match serde_json::from_str(&line) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let role = val
                        .get("role")
                        .and_then(|v| v.as_str())
                        .unwrap_or("assistant");
                    let content = val.get("content").map(flatten_content).unwrap_or_default();

                    if content.trim().is_empty() {
                        continue;
                    }

                    let created = val.get("timestamp").and_then(parse_timestamp);
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
                        role: role.to_string(),
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
                    "source": "clawdbot",
                });

                convs.push(NormalizedConversation {
                    agent_slug: "clawdbot".to_string(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use tempfile::TempDir;

    fn write_session(root: &Path, name: &str, lines: &[&str]) -> PathBuf {
        let path = root.join(name);
        let content = lines.join("\n");
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn scan_parses_basic_jsonl() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".clawdbot/sessions");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "session.jsonl",
            &[
                r#"{"role":"user","content":"Hello there","timestamp":"2025-01-27T03:30:00.000Z"}"#,
                r#"{"role":"assistant","content":"Hi","timestamp":"2025-01-27T03:30:05.000Z"}"#,
            ],
        );

        let connector = ClawdbotConnector::new();
        let ctx = ScanContext::local_default(sessions.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "clawdbot");
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].title, Some("Hello there".to_string()));
        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
    }

    #[test]
    fn scan_skips_invalid_and_empty_lines() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".clawdbot/sessions");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "bad.jsonl",
            &[
                "",
                "not-json",
                r#"{"role":"user","content":"Line 1","timestamp":"2025-01-27T03:30:00.000Z"}"#,
                r#"{"role":"assistant","content":"","timestamp":"2025-01-27T03:30:05.000Z"}"#,
            ],
        );

        let connector = ClawdbotConnector::new();
        let ctx = ScanContext::local_default(sessions.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].role, "user");
    }

    #[test]
    fn scan_with_clawdbot_root_scan_root() {
        let tmp = TempDir::new().unwrap();
        let clawdbot_root = tmp.path().join(".clawdbot");
        let sessions = clawdbot_root.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "root.jsonl",
            &[r#"{"role":"user","content":"From root","timestamp":1700000000000}"#],
        );

        let connector = ClawdbotConnector::new();
        let ctx =
            ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(clawdbot_root)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "From root");
    }

    #[test]
    fn session_files_returns_sorted_order() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".clawdbot/sessions");
        fs::create_dir_all(sessions.join("nested")).unwrap();

        write_session(
            &sessions,
            "z-last.jsonl",
            &[r#"{"role":"user","content":"z"}"#],
        );
        write_session(
            &sessions,
            "a-first.jsonl",
            &[r#"{"role":"user","content":"a"}"#],
        );
        write_session(
            &sessions.join("nested"),
            "m-middle.jsonl",
            &[r#"{"role":"user","content":"m"}"#],
        );

        let files = ClawdbotConnector::session_files(&sessions);
        let mut sorted = files.clone();
        sorted.sort();
        assert_eq!(files, sorted);
    }
}
