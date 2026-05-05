//! Connector for Charm's Crush AI coding agent sessions.
//!
//! Crush stores session data in `SQLite` databases:
//!   - Global:      `~/.crush/crush.db`
//!   - Per-project: `.crush/crush.db` within project directories
//!
//! Schema:
//!   - `sessions` (`id`, `title`, `prompt_tokens`, `completion_tokens`, `cost`)
//!   - `messages` (`session_id` FK, `role`, `parts` JSON, `created_at` ms, `model`, `provider`)
//!
//! The `parts` column contains a JSON array of objects with `type` and `text` fields;
//! text content is extracted from entries where `type == "text"`.
//!
//! **NOTE:** This connector uses `frankensqlite`. See AGENTS.md RULE 2.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use frankensqlite::compat::{ConnectionExt, OpenFlags, ParamValue, RowExt, open_with_flags};
use serde::Deserialize;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::env_path_nonempty;
use super::{Connector, franken_detection_for_connector};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct CrushConnector;

impl Default for CrushConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl CrushConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Locate the global Crush database at `~/.crush/crush.db`.
    fn global_db_path() -> Option<PathBuf> {
        if let Some(p) = env_path_nonempty("CRUSH_SQLITE_DB") {
            if p.is_file() {
                return Some(p);
            }
        }

        let db = dirs::home_dir()?.join(".crush").join("crush.db");
        if db.is_file() { Some(db) } else { None }
    }

    /// Discover per-project `.crush/crush.db` files by scanning common project roots.
    fn discover_project_dbs() -> Vec<PathBuf> {
        let mut dbs = Vec::new();

        // Check cwd
        if let Ok(cwd) = std::env::current_dir() {
            let candidate = cwd.join(".crush").join("crush.db");
            if candidate.exists() {
                dbs.push(candidate);
            }
        }

        dbs
    }

    /// Extract sessions from a Crush `SQLite` database using frankensqlite.
    fn extract_from_sqlite(
        db_path: &Path,
        since_ts: Option<i64>,
    ) -> Result<Vec<NormalizedConversation>> {
        let conn = open_with_flags(
            db_path.to_string_lossy().as_ref(),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .with_context(|| format!("failed to open Crush db: {}", db_path.display()))?;

        conn.execute("PRAGMA busy_timeout = 5000;")
            .with_context(|| "failed to set busy_timeout")?;

        let (query, params) = Self::build_query(since_ts);
        let rows: Vec<CrushRow> = conn.query_map_collect(&query, &params, |row| {
            Ok(CrushRow {
                session_id: row.get_typed(0)?,
                title: row.get_typed(1)?,
                prompt_tokens: row.get_typed(2)?,
                completion_tokens: row.get_typed(3)?,
                cost: row.get_typed(4)?,
                role: row.get_typed(5)?,
                parts_json: row.get_typed(6)?,
                created_at: row.get_typed(7)?,
                model: row.get_typed(8)?,
                provider: row.get_typed(9)?,
            })
        })?;

        Ok(group_rows_into_conversations(&rows, db_path))
    }

    /// Build the SQL query, optionally filtered by `since_ts`.
    ///
    /// When `since_ts` is set, uses a subquery to find sessions with ANY message
    /// at or after the cutoff, then returns ALL messages for those sessions.
    /// This ensures complete conversations are always returned.
    fn build_query(since_ts: Option<i64>) -> (String, Vec<ParamValue>) {
        const BASE: &str = "SELECT s.id, s.title, s.prompt_tokens, s.completion_tokens, s.cost, \
                            m.role, m.parts, m.created_at, m.model, m.provider \
                            FROM sessions s JOIN messages m ON m.session_id = s.id";

        since_ts.map_or_else(
            || (format!("{BASE} ORDER BY s.id, m.created_at"), vec![]),
            |since| {
                (
                    format!(
                        "{BASE} WHERE s.id IN \
                         (SELECT DISTINCT session_id FROM messages WHERE created_at >= ?1) \
                         ORDER BY s.id, m.created_at"
                    ),
                    vec![ParamValue::from(since)],
                )
            },
        )
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut db_paths: Vec<ScanRoot> = Vec::new();

        if ctx.data_dir.extension().is_some_and(|ext| ext == "db") {
            db_paths.push(ScanRoot::local(ctx.data_dir.clone()));
        } else if ctx.use_default_detection() {
            if let Some(global) = Self::global_db_path() {
                db_paths.push(ScanRoot::local(global));
            }
            db_paths.extend(
                Self::discover_project_dbs()
                    .into_iter()
                    .map(ScanRoot::local),
            );
            let candidate = ctx.data_dir.join("crush.db");
            if candidate.exists() {
                db_paths.push(ScanRoot::local(candidate));
            }
        } else {
            let candidate = ctx.data_dir.join("crush.db");
            if candidate.exists() {
                db_paths.push(ScanRoot::local(candidate));
            }
            for scan_root in &ctx.scan_roots {
                if scan_root.path.extension().is_some_and(|ext| ext == "db") {
                    db_paths.push(scan_root.clone());
                }
                db_paths.push(scan_root.with_path(scan_root.path.join("crush.db")));
                db_paths.push(scan_root.with_path(scan_root.path.join(".crush/crush.db")));
            }
        }

        let mut seen = HashSet::new();
        db_paths.retain(|root| seen.insert(root.path.clone()));
        db_paths
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        Self::source_roots(ctx)
            .into_iter()
            .filter(|root| root.path.exists())
            .map(|root| {
                DiscoveredSourceFile::new(
                    "crush",
                    &root,
                    root.path.clone(),
                    DiscoveredSourceRole::SqliteDatabase,
                    true,
                )
                .with_fs_metadata()
            })
            .collect()
    }
}

impl Connector for CrushConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("crush").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();

        let db_paths: Vec<PathBuf> = Self::source_roots(ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();

        // Track seen session IDs to dedup across global + per-project databases.
        let mut seen_ids: HashSet<String> = HashSet::new();

        for db in &db_paths {
            if !db.exists() {
                continue;
            }
            match Self::extract_from_sqlite(db, ctx.since_ts) {
                Ok(db_convs) => {
                    tracing::debug!(
                        "crush sqlite: found {} sessions in {}",
                        db_convs.len(),
                        db.display()
                    );
                    for conv in db_convs {
                        let id = conv.external_id.clone().unwrap_or_default();
                        if seen_ids.insert(id) {
                            convs.push(conv);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("crush sqlite: failed to read {}: {e}", db.display());
                }
            }
        }

        Ok(convs)
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

// --- Internal helpers & types ---

struct CrushRow {
    session_id: String,
    title: Option<String>,
    prompt_tokens: Option<i64>,
    completion_tokens: Option<i64>,
    cost: Option<f64>,
    role: Option<String>,
    parts_json: Option<String>,
    created_at: Option<i64>,
    model: Option<String>,
    provider: Option<String>,
}

struct SessionMeta {
    id: String,
    title: Option<String>,
    prompt_tokens: Option<i64>,
    completion_tokens: Option<i64>,
    cost: Option<f64>,
}

#[derive(Deserialize)]
struct CrushPart {
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

/// Group rows into `NormalizedConversation` structs (rows are pre-sorted by `session_id`).
fn group_rows_into_conversations(rows: &[CrushRow], db_path: &Path) -> Vec<NormalizedConversation> {
    let mut convs: Vec<NormalizedConversation> = Vec::new();
    let mut current_session_id: Option<&str> = None;
    let mut current_messages: Vec<NormalizedMessage> = Vec::new();
    let mut current_meta: Option<SessionMeta> = None;

    for row in rows {
        let content = extract_text_from_parts(row.parts_json.as_deref());
        if content.trim().is_empty() {
            continue;
        }

        // Flush previous session when session_id changes.
        let flush = current_session_id.is_some_and(|id| id != row.session_id);
        if flush {
            if let Some(meta) = current_meta.take() {
                flush_session(&mut convs, &mut current_messages, &meta, db_path);
            }
        }

        let role = row.role.clone().unwrap_or_else(|| "assistant".to_string());
        let author = if role == "assistant" {
            row.model.clone()
        } else {
            Some("user".to_string())
        };

        current_messages.push(NormalizedMessage {
            idx: 0,
            role,
            author,
            created_at: row.created_at,
            content,
            extra: serde_json::json!({
                "model": row.model,
                "provider": row.provider,
            }),
            invocations: Vec::new(),
            snippets: Vec::new(),
        });

        if current_session_id != Some(&row.session_id) {
            current_meta = Some(SessionMeta {
                id: row.session_id.clone(),
                title: row.title.clone(),
                prompt_tokens: row.prompt_tokens,
                completion_tokens: row.completion_tokens,
                cost: row.cost,
            });
        }
        current_session_id = Some(&row.session_id);
    }

    // Flush final session.
    if let Some(meta) = current_meta.take() {
        flush_session(&mut convs, &mut current_messages, &meta, db_path);
    }

    convs
}

/// Extract text content from Crush's `parts` JSON column.
///
/// Format: `[{"type": "text", "text": "..."}, ...]`
fn extract_text_from_parts(parts_json: Option<&str>) -> String {
    let Some(json) = parts_json else {
        return String::new();
    };

    let parts: Vec<CrushPart> = match serde_json::from_str(json) {
        Ok(p) => p,
        Err(_) => {
            // Fall back: treat the whole string as plain text if it's not valid JSON.
            return json.to_string();
        }
    };

    parts
        .iter()
        .filter(|p| p.r#type.as_deref().unwrap_or("text") == "text")
        .filter_map(|p| p.text.as_deref())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Flush accumulated messages into a `NormalizedConversation` and push to `convs`.
fn flush_session(
    convs: &mut Vec<NormalizedConversation>,
    messages: &mut Vec<NormalizedMessage>,
    meta: &SessionMeta,
    db_path: &Path,
) {
    if messages.is_empty() {
        return;
    }

    let mut msgs = std::mem::take(messages);
    crate::types::reindex_messages(&mut msgs);

    let started_at = msgs.iter().filter_map(|m| m.created_at).min();
    let ended_at = msgs.iter().filter_map(|m| m.created_at).max();

    let title = meta.title.clone().or_else(|| {
        msgs.first()
            .and_then(|m| m.content.lines().next())
            .map(|s| s.chars().take(100).collect())
    });

    convs.push(NormalizedConversation {
        agent_slug: "crush".into(),
        external_id: Some(meta.id.clone()),
        title,
        workspace: None,
        source_path: db_path.to_path_buf(),
        started_at,
        ended_at,
        metadata: serde_json::json!({
            "session_id": meta.id,
            "prompt_tokens": meta.prompt_tokens,
            "completion_tokens": meta.completion_tokens,
            "cost": meta.cost,
            "source": "sqlite",
        }),
        messages: msgs,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use frankensqlite::compat::ConnectionExt;
    use frankensqlite::params;

    #[test]
    fn extract_text_from_parts_basic() {
        let json = r#"[{"type":"text","text":"Hello"},{"type":"text","text":"World"}]"#;
        assert_eq!(extract_text_from_parts(Some(json)), "Hello\nWorld");
    }

    #[test]
    fn extract_text_from_parts_skips_non_text() {
        let json = r#"[{"type":"tool_use","text":"ignored"},{"type":"text","text":"kept"}]"#;
        assert_eq!(extract_text_from_parts(Some(json)), "kept");
    }

    #[test]
    fn extract_text_from_parts_none() {
        assert_eq!(extract_text_from_parts(None), "");
    }

    #[test]
    fn extract_text_from_parts_invalid_json_fallback() {
        assert_eq!(
            extract_text_from_parts(Some("plain text content")),
            "plain text content"
        );
    }

    #[test]
    fn extract_text_from_parts_default_type() {
        // When type is omitted, default to "text"
        let json = r#"[{"text":"no type field"}]"#;
        assert_eq!(extract_text_from_parts(Some(json)), "no type field");
    }

    #[test]
    fn scan_discovers_consumed_sqlite_database() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("crush.db");
        let conn = frankensqlite::Connection::open(db_path.to_string_lossy().as_ref()).unwrap();

        conn.execute(
            "CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                title TEXT,
                prompt_tokens INTEGER,
                completion_tokens INTEGER,
                cost REAL
            )",
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE messages (
                session_id TEXT,
                role TEXT,
                parts TEXT,
                created_at INTEGER,
                model TEXT,
                provider TEXT
            )",
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO sessions (id, title, prompt_tokens, completion_tokens, cost)
             VALUES (?, ?, ?, ?, ?)",
            params!["sess-001", "Crush Test", 1_i64, 2_i64, 0.01_f64],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO messages (session_id, role, parts, created_at, model, provider)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                "sess-001",
                "user",
                r#"[{"type":"text","text":"Hello Crush"}]"#,
                1_733_000_000_000_i64,
                "crush-model",
                "crush"
            ],
        )
        .unwrap();
        drop(conn);

        let connector = CrushConnector::new();
        let ctx = ScanContext::local_default(db_path.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].source_path, db_path);
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }
}
