//! Connector for Hermes (Nous Research) agent sessions.
//!
//! Hermes stores one JSON object per session at:
//! - `~/.hermes/sessions/session_*.json`
//!
//! Each file is a single conversation:
//! ```json
//! {
//!   "session_id": "20260517_113230_64b5be",
//!   "model": "gpt-5.5",
//!   "platform": "acp",
//!   "session_start": "2026-05-17T11:32:30.730753",
//!   "last_updated":  "2026-05-17T11:32:41.406858",
//!   "system_prompt": "...",
//!   "message_count": 41,
//!   "messages": [ { "role": "user", "content": "..." }, ... ]
//! }
//! ```
//!
//! Message shape (verified across real sessions): `content` is always a string;
//! roles are `user` / `assistant` / `tool`. Assistant messages may additionally
//! carry `reasoning` (a string or null), `tool_calls` (a list), `finish_reason`
//! (a string), and `codex_reasoning_items`. We fold `reasoning` into the
//! searchable content (it is prose worth finding) and preserve the structured
//! fields (`tool_calls`, `finish_reason`, `codex_reasoning_items`) in `extra` so
//! nothing is lost.
//!
//! The same directory also contains `request_dump_*.json` files — raw API request
//! dumps, not conversations — which we deliberately skip.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{Value, json};
use walkdir::WalkDir;

use super::scan::ScanContext;
use super::{Connector, file_modified_since, franken_detection_for_connector, parse_timestamp};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct HermesConnector;

impl Default for HermesConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl HermesConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Find Hermes session files under the provided roots.
    ///
    /// Matches `session_*.json` and skips `request_dump_*.json` (raw API dumps,
    /// not conversations). Depth is shallow — Hermes keeps sessions flat under
    /// `~/.hermes/sessions/` — but we allow a little nesting in case a root is
    /// passed higher up (e.g. `~/.hermes`).
    fn find_session_files(roots: &[&Path]) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for root in roots {
            if !root.exists() {
                continue;
            }
            for entry in WalkDir::new(root)
                .max_depth(4)
                .into_iter()
                .flatten()
                .filter(|e| e.file_type().is_file())
            {
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("session_") && n.ends_with(".json"))
                {
                    files.push(entry.path().to_path_buf());
                }
            }
        }
        // Deterministic traversal across filesystems/runs.
        files.sort();
        files
    }

    /// Parse a Hermes session timestamp to epoch millis, falling back to the
    /// file's mtime when absent/unparseable.
    ///
    /// Hermes writes naive ISO-8601 with sub-second precision and **no timezone**
    /// (e.g. `2026-05-17T11:32:30.730753`). The shared `parse_timestamp` only
    /// recognizes timezone-bearing forms (RFC3339 / trailing `Z`), so we try the
    /// naive form here first, then defer to the shared helper (which also handles
    /// epoch ints/floats), then to file mtime. Times are interpreted as UTC; the
    /// small offset is acceptable for indexing/sorting.
    fn timestamp_or_mtime(raw: Option<&str>, path: &Path) -> Option<i64> {
        if let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) {
            // Naive (no-Z) ISO-8601, with or without fractional seconds.
            for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
                if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
                    return Some(dt.and_utc().timestamp_millis());
                }
            }
            // Timezone-bearing / epoch forms via the shared helper.
            if let Some(ts) = parse_timestamp(&Value::String(s.to_string())) {
                return Some(ts);
            }
        }
        let meta = fs::metadata(path).ok()?;
        let mtime = meta.modified().ok()?;
        i64::try_from(
            mtime
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .ok()
    }

    #[allow(clippy::unused_self)]
    fn parse_session(&self, path: &Path) -> Result<NormalizedConversation> {
        let raw = fs::read_to_string(path)?;
        let root: Value = serde_json::from_str(&raw)?;

        let session_id = root
            .get("session_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let model = root.get("model").and_then(Value::as_str);
        let platform = root.get("platform").and_then(Value::as_str);

        let started_at =
            Self::timestamp_or_mtime(root.get("session_start").and_then(Value::as_str), path);
        let ended_at =
            Self::timestamp_or_mtime(root.get("last_updated").and_then(Value::as_str), path);

        let mut messages = Vec::new();
        if let Some(arr) = root.get("messages").and_then(Value::as_array) {
            for (i, m) in arr.iter().enumerate() {
                let role = m
                    .get("role")
                    .and_then(Value::as_str)
                    .unwrap_or("assistant")
                    .to_string();

                // `content` is always a string in practice; tolerate other shapes
                // by stringifying so a future format change never drops a message.
                let mut content = match m.get("content") {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(other) => other.to_string(),
                };

                // Fold assistant `reasoning` (a string) into searchable content.
                if let Some(reasoning) = m.get("reasoning").and_then(Value::as_str)
                    && !reasoning.trim().is_empty()
                {
                    if content.trim().is_empty() {
                        content = reasoning.to_string();
                    } else {
                        content = format!("{content}\n\n[reasoning]\n{reasoning}");
                    }
                }

                // Preserve structured fields without losing them to the text body.
                let mut extra = serde_json::Map::new();
                for key in ["tool_calls", "finish_reason", "codex_reasoning_items"] {
                    if let Some(v) = m.get(key)
                        && !v.is_null()
                    {
                        extra.insert(key.to_string(), v.clone());
                    }
                }

                messages.push(NormalizedMessage {
                    idx: i64::try_from(i).unwrap_or(i64::MAX),
                    role: role.clone(),
                    author: Some(role),
                    created_at: None, // Hermes timestamps are per-session, not per-message
                    content,
                    extra: Value::Object(extra),
                    snippets: Vec::new(),
                });
            }
        }

        let title = match (&session_id, model) {
            (Some(id), Some(m)) => Some(format!("Hermes {id} ({m})")),
            (Some(id), None) => Some(format!("Hermes {id}")),
            (None, Some(m)) => Some(format!("Hermes session ({m})")),
            (None, None) => Some("Hermes session".to_string()),
        };

        Ok(NormalizedConversation {
            agent_slug: "hermes".to_string(),
            external_id: session_id,
            title,
            // Hermes sessions are not workspace-scoped on disk; leave None.
            workspace: None,
            source_path: path.to_path_buf(),
            started_at,
            ended_at,
            metadata: json!({
                "model": model,
                "platform": platform,
                "message_count": root.get("message_count").and_then(Value::as_i64),
            }),
            messages,
        })
    }
}

impl Connector for HermesConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("hermes").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut roots: Vec<PathBuf> = Vec::new();
        let mut add_root = |root: PathBuf| {
            if !roots.contains(&root) {
                roots.push(root);
            }
        };

        if ctx.use_default_detection() {
            // Explicit override always wins.
            if let Ok(override_root) = dotenvy::var("CASS_HERMES_DATA_ROOT")
                && !override_root.trim().is_empty()
            {
                add_root(PathBuf::from(override_root.trim()));
            } else {
                // If data_dir already points at a hermes sessions dir, use it;
                // otherwise fall back to the canonical ~/.hermes/sessions.
                if ctx.data_dir.file_name().is_some_and(|n| n == "sessions")
                    && ctx
                        .data_dir
                        .parent()
                        .is_some_and(|p| p.file_name().is_some_and(|n| n == ".hermes"))
                {
                    add_root(ctx.data_dir.clone());
                }
                if let Some(home) = dirs::home_dir() {
                    let sessions = home.join(".hermes").join("sessions");
                    if sessions.exists() {
                        add_root(sessions);
                    }
                }
            }
        } else {
            for root in &ctx.scan_roots {
                add_root(root.path.clone());
            }
        }

        if roots.is_empty() {
            return Ok(Vec::new());
        }

        let root_refs: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
        let files = Self::find_session_files(&root_refs);

        let mut conversations = Vec::new();
        for path in files {
            if !file_modified_since(&path, ctx.since_ts) {
                continue;
            }
            match self.parse_session(&path) {
                Ok(conv) => conversations.push(conv),
                Err(e) => {
                    tracing::warn!("failed to parse hermes session {}: {}", path.display(), e);
                }
            }
        }
        Ok(conversations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_session(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    const SAMPLE: &str = r#"{
        "session_id": "20260517_113230_64b5be",
        "model": "gpt-5.5",
        "platform": "acp",
        "session_start": "2026-05-17T11:32:30.730753",
        "last_updated": "2026-05-17T11:32:41.406858",
        "system_prompt": "You are Hermes.",
        "message_count": 3,
        "messages": [
            {"role": "user", "content": "What inspirations does Stakeholders draw from?"},
            {"role": "assistant", "content": "It draws from X.", "reasoning": "thinking about X", "finish_reason": "stop"},
            {"role": "tool", "content": "tool output here"}
        ]
    }"#;

    // ---- constructor ----
    #[test]
    fn new_and_default_construct() {
        let _ = HermesConnector::new();
        let _ = HermesConnector;
    }

    // ---- find_session_files ----
    #[test]
    fn find_matches_session_files() {
        let dir = TempDir::new().unwrap();
        write_session(dir.path(), "session_20260517_113230_64b5be.json", SAMPLE);
        let files = HermesConnector::find_session_files(&[dir.path()]);
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn find_skips_request_dumps() {
        let dir = TempDir::new().unwrap();
        write_session(dir.path(), "session_a.json", SAMPLE);
        write_session(dir.path(), "request_dump_x.json", "{}");
        let files = HermesConnector::find_session_files(&[dir.path()]);
        assert_eq!(files.len(), 1);
        assert!(
            files[0]
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("session_")
        );
    }

    #[test]
    fn find_ignores_unrelated_files() {
        let dir = TempDir::new().unwrap();
        write_session(dir.path(), "config.yaml", "x");
        write_session(dir.path(), "notes.json", "{}");
        let files = HermesConnector::find_session_files(&[dir.path()]);
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn find_returns_sorted() {
        let dir = TempDir::new().unwrap();
        write_session(dir.path(), "session_b.json", SAMPLE);
        write_session(dir.path(), "session_a.json", SAMPLE);
        let files = HermesConnector::find_session_files(&[dir.path()]);
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["session_a.json", "session_b.json"]);
    }

    #[test]
    fn find_nonexistent_root_is_empty() {
        let files = HermesConnector::find_session_files(&[Path::new("/no/such/dir")]);
        assert!(files.is_empty());
    }

    // ---- parse_session ----
    #[test]
    fn parse_basic_fields() {
        let dir = TempDir::new().unwrap();
        let p = write_session(dir.path(), "session_x.json", SAMPLE);
        let conv = HermesConnector::new().parse_session(&p).unwrap();
        assert_eq!(conv.agent_slug, "hermes");
        assert_eq!(conv.external_id.as_deref(), Some("20260517_113230_64b5be"));
        assert!(conv.title.unwrap().contains("gpt-5.5"));
        assert_eq!(conv.messages.len(), 3);
        assert!(conv.started_at.is_some());
        assert!(conv.ended_at.is_some());
    }

    #[test]
    fn parse_preserves_roles() {
        let dir = TempDir::new().unwrap();
        let p = write_session(dir.path(), "session_x.json", SAMPLE);
        let conv = HermesConnector::new().parse_session(&p).unwrap();
        assert_eq!(conv.messages[0].role, "user");
        assert_eq!(conv.messages[1].role, "assistant");
        assert_eq!(conv.messages[2].role, "tool");
    }

    #[test]
    fn parse_folds_reasoning_into_content() {
        let dir = TempDir::new().unwrap();
        let p = write_session(dir.path(), "session_x.json", SAMPLE);
        let conv = HermesConnector::new().parse_session(&p).unwrap();
        let assistant = &conv.messages[1];
        assert!(assistant.content.contains("It draws from X."));
        assert!(assistant.content.contains("thinking about X"));
        assert!(assistant.content.contains("[reasoning]"));
    }

    #[test]
    fn parse_stashes_structured_fields_in_extra() {
        let dir = TempDir::new().unwrap();
        let p = write_session(dir.path(), "session_x.json", SAMPLE);
        let conv = HermesConnector::new().parse_session(&p).unwrap();
        let assistant = &conv.messages[1];
        assert_eq!(
            assistant.extra.get("finish_reason").and_then(Value::as_str),
            Some("stop")
        );
        // reasoning is folded into content, not duplicated in extra
        assert!(assistant.extra.get("reasoning").is_none());
    }

    #[test]
    fn parse_sequential_indices() {
        let dir = TempDir::new().unwrap();
        let p = write_session(dir.path(), "session_x.json", SAMPLE);
        let conv = HermesConnector::new().parse_session(&p).unwrap();
        assert_eq!(conv.messages[0].idx, 0);
        assert_eq!(conv.messages[1].idx, 1);
        assert_eq!(conv.messages[2].idx, 2);
    }

    #[test]
    fn parse_metadata_carries_model_and_platform() {
        let dir = TempDir::new().unwrap();
        let p = write_session(dir.path(), "session_x.json", SAMPLE);
        let conv = HermesConnector::new().parse_session(&p).unwrap();
        assert_eq!(
            conv.metadata.get("model").and_then(Value::as_str),
            Some("gpt-5.5")
        );
        assert_eq!(
            conv.metadata.get("platform").and_then(Value::as_str),
            Some("acp")
        );
    }

    #[test]
    fn parse_naive_iso_timestamp_is_not_mtime() {
        // Hermes writes naive (no-Z) ISO timestamps; ensure we parse the real
        // session time rather than silently falling back to the file mtime.
        let dir = TempDir::new().unwrap();
        let p = write_session(dir.path(), "session_ts.json", SAMPLE);
        let conv = HermesConnector::new().parse_session(&p).unwrap();
        // 2026-05-17T11:32:30.730753 UTC == 1779017550730 ms
        assert_eq!(conv.started_at, Some(1_779_017_550_730));
        // 2026-05-17T11:32:41.406858 UTC == 1779017561406 ms
        assert_eq!(conv.ended_at, Some(1_779_017_561_406));
    }

    #[test]
    fn parse_missing_timestamps_falls_back_to_mtime() {
        let dir = TempDir::new().unwrap();
        let body = r#"{"session_id":"s","model":"m","messages":[{"role":"user","content":"hi"}]}"#;
        let p = write_session(dir.path(), "session_notime.json", body);
        let conv = HermesConnector::new().parse_session(&p).unwrap();
        // mtime fallback => still populated
        assert!(conv.started_at.is_some());
        assert!(conv.ended_at.is_some());
    }

    #[test]
    fn parse_empty_messages() {
        let dir = TempDir::new().unwrap();
        let body = r#"{"session_id":"s","model":"m","messages":[]}"#;
        let p = write_session(dir.path(), "session_empty.json", body);
        let conv = HermesConnector::new().parse_session(&p).unwrap();
        assert_eq!(conv.messages.len(), 0);
    }

    #[test]
    fn parse_missing_session_id_still_titled() {
        let dir = TempDir::new().unwrap();
        let body = r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
        let p = write_session(dir.path(), "session_noid.json", body);
        let conv = HermesConnector::new().parse_session(&p).unwrap();
        assert!(conv.external_id.is_none());
        assert!(conv.title.unwrap().contains("Hermes"));
    }

    #[test]
    fn parse_null_reasoning_is_ignored() {
        let dir = TempDir::new().unwrap();
        let body = r#"{"session_id":"s","messages":[{"role":"assistant","content":"hello","reasoning":null}]}"#;
        let p = write_session(dir.path(), "session_nullr.json", body);
        let conv = HermesConnector::new().parse_session(&p).unwrap();
        assert_eq!(conv.messages[0].content, "hello");
        assert!(!conv.messages[0].content.contains("[reasoning]"));
    }

    #[test]
    fn parse_invalid_json_errors() {
        let dir = TempDir::new().unwrap();
        let p = write_session(dir.path(), "session_bad.json", "{not json");
        assert!(HermesConnector::new().parse_session(&p).is_err());
    }

    #[test]
    fn parse_invalid_utf8_errors() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("session_utf8.json");
        fs::write(&p, b"\xFF\xFE not utf8").unwrap();
        assert!(HermesConnector::new().parse_session(&p).is_err());
    }

    // ---- scan ----
    // Use explicit scan_roots (with_roots) so use_default_detection() is false and
    // the connector reads the provided temp dir instead of ~/.hermes/sessions.
    fn ctx_with_root(dir: &Path) -> ScanContext {
        ScanContext::with_roots(
            dir.to_path_buf(),
            vec![super::super::scan::ScanRoot::local(dir.to_path_buf())],
            None,
        )
    }

    #[test]
    fn scan_explicit_roots_finds_sessions() {
        let dir = TempDir::new().unwrap();
        write_session(dir.path(), "session_x.json", SAMPLE);
        write_session(dir.path(), "request_dump_y.json", "{}");

        let connector = HermesConnector::new();
        let convs = connector.scan(&ctx_with_root(dir.path())).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "hermes");
    }

    #[test]
    fn scan_empty_dir_is_empty() {
        let dir = TempDir::new().unwrap();
        let connector = HermesConnector::new();
        let convs = connector.scan(&ctx_with_root(dir.path())).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn scan_sets_source_path() {
        let dir = TempDir::new().unwrap();
        let p = write_session(dir.path(), "session_x.json", SAMPLE);
        let connector = HermesConnector::new();
        let convs = connector.scan(&ctx_with_root(dir.path())).unwrap();
        assert_eq!(convs[0].source_path, p);
    }
}
