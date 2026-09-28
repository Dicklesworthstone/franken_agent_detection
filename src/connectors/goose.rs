//! Goose connector for SQLite and legacy JSONL session storage.
//!
//! **v1.20+ (SQLite):** Data is stored in `~/.local/share/goose/sessions/sessions.db`
//! with tables: `sessions` and `messages`.
//!
//! **Pre-v1.20 (JSONL):** Data at `~/.local/share/goose/sessions/` or legacy
//! `~/.goose/sessions/` using `*.jsonl` files — one per session.

#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::must_use_candidate,
    clippy::option_if_let_else,
    clippy::single_option_map,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use frankensqlite::compat::{OpenFlags, RowExt};
use frankensqlite::{Row, SqliteValue, params};

use super::sqlite_sync::{Connection, ConnectionExt, open_with_flags};
use serde::Deserialize;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::{dedupe_path_key, env_path_nonempty};
use super::{Connector, file_modified_since, franken_detection_for_connector};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
};

pub struct GooseConnector;

impl Default for GooseConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl GooseConnector {
    pub fn new() -> Self {
        Self
    }

    /// Find the Goose sessions directory.
    ///
    /// Returns the first existing sessions directory from:
    /// 1. `GOOSE_PATH_ROOT` env override: `$GOOSE_PATH_ROOT/data/sessions/`
    /// 2. XDG default: `~/.local/share/goose/sessions/`
    /// 3. Legacy: `~/.goose/sessions/`
    fn sessions_dir() -> Option<PathBuf> {
        // Check for env override first
        if let Ok(root) = dotenvy::var("GOOSE_PATH_ROOT") {
            let root = root.trim().to_string();
            if !root.is_empty() {
                let p = PathBuf::from(&root).join("data").join("sessions");
                if p.is_dir() {
                    return Some(p);
                }
            }
        }

        // XDG default: ~/.local/share/goose/sessions/
        if let Some(data) = dirs::data_local_dir() {
            let sessions = data.join("goose").join("sessions");
            if sessions.is_dir() {
                return Some(sessions);
            }
        }

        // Fallback: ~/.local/share/goose/sessions (explicit)
        if let Some(home) = dirs::home_dir() {
            let sessions = home
                .join(".local")
                .join("share")
                .join("goose")
                .join("sessions");
            if sessions.is_dir() {
                return Some(sessions);
            }
        }

        // Legacy: ~/.goose/sessions/
        if let Some(home) = dirs::home_dir() {
            let sessions = home.join(".goose").join("sessions");
            if sessions.is_dir() {
                return Some(sessions);
            }
        }

        None
    }

    /// Find the Goose SQLite database (v1.20+).
    /// Returns the path to `sessions.db` if it exists.
    fn sqlite_db_path() -> Option<PathBuf> {
        // Check for env override first
        if let Some(p) = env_path_nonempty("GOOSE_SQLITE_DB") {
            if p.is_file() {
                return Some(p);
            }
        }

        // Check for GOOSE_PATH_ROOT env
        if let Ok(root) = dotenvy::var("GOOSE_PATH_ROOT") {
            let root = root.trim().to_string();
            if !root.is_empty() {
                let db = PathBuf::from(&root)
                    .join("data")
                    .join("sessions")
                    .join("sessions.db");
                if db.is_file() {
                    return Some(db);
                }
            }
        }

        // XDG default: ~/.local/share/goose/sessions/sessions.db
        if let Some(data) = dirs::data_local_dir() {
            let db = data.join("goose").join("sessions").join("sessions.db");
            if db.is_file() {
                return Some(db);
            }
        }

        // Fallback: ~/.local/share/goose/sessions/sessions.db (explicit)
        if let Some(home) = dirs::home_dir() {
            let db = home
                .join(".local")
                .join("share")
                .join("goose")
                .join("sessions")
                .join("sessions.db");
            if db.is_file() {
                return Some(db);
            }
        }

        // Legacy: ~/.goose/sessions/sessions.db
        if let Some(home) = dirs::home_dir() {
            let db = home.join(".goose").join("sessions").join("sessions.db");
            if db.exists() {
                return Some(db);
            }
        }

        None
    }

    fn append_db_candidates(db_paths: &mut Vec<PathBuf>, base: &Path) {
        let file_name = base.file_name().and_then(|n| n.to_str());
        let is_local = file_name.is_some_and(|n| n == ".local");
        let is_share = file_name.is_some_and(|n| n == "share")
            && base
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".local"));
        let is_goose_root = file_name.is_some_and(|n| n == ".goose");

        if base.extension().is_some_and(|ext| ext == "db") {
            db_paths.push(base.to_path_buf());
        }

        db_paths.push(base.join("sessions.db"));
        db_paths.push(base.join("sessions").join("sessions.db"));

        if is_local {
            db_paths.push(base.join("share/goose/sessions/sessions.db"));
        }
        if is_share {
            db_paths.push(base.join("goose/sessions/sessions.db"));
        }
        if is_goose_root {
            db_paths.push(base.join("sessions/sessions.db"));
        }

        if !(is_local || is_share || is_goose_root) {
            db_paths.push(base.join(".local/share/goose/sessions/sessions.db"));
            db_paths.push(base.join(".goose/sessions/sessions.db"));
        }
    }

    fn append_session_roots(session_roots: &mut Vec<PathBuf>, base: &Path) {
        let file_name = base.file_name().and_then(|n| n.to_str());
        let is_local = file_name.is_some_and(|n| n == ".local");
        let is_share = file_name.is_some_and(|n| n == "share")
            && base
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".local"));
        let is_goose_root = file_name.is_some_and(|n| n == ".goose");

        if looks_like_goose_sessions(base) {
            session_roots.push(base.to_path_buf());
        }

        let mut candidates = Vec::new();
        candidates.push(base.join("sessions"));

        if is_local {
            candidates.push(base.join("share/goose/sessions"));
        }
        if is_share {
            candidates.push(base.join("goose/sessions"));
        }
        if is_goose_root {
            candidates.push(base.join("sessions"));
        }
        if !(is_local || is_share || is_goose_root) {
            candidates.push(base.join(".local/share/goose/sessions"));
            candidates.push(base.join(".goose/sessions"));
        }

        for candidate in candidates {
            if candidate.exists() && looks_like_goose_sessions(&candidate) {
                session_roots.push(candidate);
            }
        }
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut sources = Vec::new();
        Self::discover_sqlite_sources(ctx, &mut sources);
        Self::discover_jsonl_sources(ctx, &mut sources);
        sources
    }

    fn discover_sqlite_sources(ctx: &ScanContext, sources: &mut Vec<DiscoveredSourceFile>) {
        let mut candidates: Vec<(ScanRoot, PathBuf)> = Vec::new();
        if ctx.data_dir.extension().is_some_and(|ext| ext == "db") {
            let root = ScanRoot::local(ctx.data_dir.clone());
            candidates.push((root, ctx.data_dir.clone()));
        } else if ctx.use_default_detection() {
            // Mirrors scan(): a sessions.db under data_dir scopes discovery
            // to it; only otherwise probe the system store.
            // GOOSE_SQLITE_DB keeps precedence.
            let candidate = (!ctx.data_dir.as_os_str().is_empty())
                .then(|| ctx.data_dir.join("sessions.db"))
                .filter(|p| p.is_file());
            if let Some(db) = candidate.filter(|_| env_path_nonempty("GOOSE_SQLITE_DB").is_none()) {
                candidates.push((ScanRoot::local(db.clone()), db));
            } else if let Some(db) = Self::sqlite_db_path() {
                let root = ScanRoot::local(db.clone());
                candidates.push((root, db));
            }
        } else {
            if !ctx.data_dir.as_os_str().is_empty() {
                let root = ScanRoot::local(ctx.data_dir.clone());
                let db_path = root.path.join("sessions.db");
                candidates.push((root, db_path));
            }
            for scan_root in &ctx.scan_roots {
                let mut db_paths = Vec::new();
                Self::append_db_candidates(&mut db_paths, &scan_root.path);
                candidates.extend(
                    db_paths
                        .into_iter()
                        .map(|db_path| (scan_root.clone(), db_path)),
                );
            }
        }

        let mut seen = HashSet::new();
        sources.extend(
            candidates
                .into_iter()
                .filter(|(_, db_path)| db_path.is_file())
                .filter(|(_, db_path)| seen.insert(db_path.clone()))
                .map(|(root, db_path)| {
                    DiscoveredSourceFile::new(
                        "goose",
                        &root,
                        db_path,
                        DiscoveredSourceRole::SqliteDatabase,
                        true,
                    )
                    .with_fs_metadata()
                }),
        );
    }

    fn discover_jsonl_sources(ctx: &ScanContext, sources: &mut Vec<DiscoveredSourceFile>) {
        let mut session_roots: Vec<(ScanRoot, PathBuf)> = Vec::new();
        if ctx.use_default_detection() {
            if ctx.data_dir.exists() && looks_like_goose_sessions(&ctx.data_dir) {
                let root = ScanRoot::local(ctx.data_dir.clone());
                session_roots.push((root, ctx.data_dir.clone()));
            } else if let Some(dir) = Self::sessions_dir() {
                let root = ScanRoot::local(dir.clone());
                session_roots.push((root, dir));
            }
        } else {
            if ctx.data_dir.exists() {
                let root = ScanRoot::local(ctx.data_dir.clone());
                let mut roots = Vec::new();
                Self::append_session_roots(&mut roots, &ctx.data_dir);
                session_roots.extend(
                    roots
                        .into_iter()
                        .map(|session_root| (root.clone(), session_root)),
                );
            }
            for scan_root in &ctx.scan_roots {
                let mut roots = Vec::new();
                Self::append_session_roots(&mut roots, &scan_root.path);
                session_roots.extend(
                    roots
                        .into_iter()
                        .map(|session_root| (scan_root.clone(), session_root)),
                );
            }
        }

        session_roots.sort_by(|left, right| left.1.cmp(&right.1));
        session_roots.dedup_by(|left, right| left.1 == right.1);

        let mut seen_files: HashSet<PathBuf> = HashSet::new();
        for (root, sessions_dir) in session_roots {
            let jsonl_files: Vec<PathBuf> = WalkDir::new(&sessions_dir)
                .max_depth(2)
                .into_iter()
                .flatten()
                .filter(|e| e.file_type().is_file())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
                .map(|e| e.path().to_path_buf())
                .collect();

            for jsonl_file in jsonl_files {
                if !seen_files.insert(dedupe_path_key(&jsonl_file)) {
                    continue;
                }
                if !file_modified_since(&jsonl_file, ctx.since_ts) {
                    continue;
                }
                sources.push(
                    DiscoveredSourceFile::new(
                        "goose",
                        &root,
                        jsonl_file,
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }
        }
    }

    /// Extract sessions from Goose's SQLite database (v1.20+).
    ///
    /// Schema:
    ///   `sessions`: id, description, working_dir, created_at, updated_at,
    ///               provider_name, model_config_json, session_type
    ///   `messages`: session_id, role, content_json, created_timestamp,
    ///               tokens, metadata_json, message_id
    fn extract_from_sqlite(
        db_path: &Path,
        since_ts: Option<i64>,
    ) -> Result<Vec<NormalizedConversation>> {
        let conn = open_with_flags(
            db_path.to_string_lossy().as_ref(),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .with_context(|| format!("failed to open Goose db: {}", db_path.display()))?;

        conn.execute("PRAGMA busy_timeout = 5000;")
            .with_context(|| "failed to set busy_timeout")?;

        // Query all sessions
        let sessions: Vec<GooseSqliteSession> = conn
            .query_map_collect(
                "SELECT id, description, working_dir, created_at, updated_at, \
                        provider_name, model_config_json, session_type \
                 FROM sessions",
                params![],
                |row| {
                    Ok(GooseSqliteSession {
                        id: row.get_typed(0)?,
                        description: row.get_typed(1)?,
                        working_dir: row.get_typed(2)?,
                        created_at: optional_sqlite_value(row, 3),
                        updated_at: optional_sqlite_value(row, 4),
                        provider_name: row.get_typed(5)?,
                        model_config_json: row.get_typed(6)?,
                        session_type: row.get_typed(7)?,
                    })
                },
            )
            .with_context(|| "failed to query Goose sessions")?;

        let mut convs = Vec::new();
        let mut seen_ids = HashSet::new();

        for session in sessions {
            if !seen_ids.insert(session.id.clone()) {
                continue;
            }

            let session_created_ms = session
                .created_at
                .as_ref()
                .and_then(normalize_goose_ts_value);
            let session_updated_ms = session
                .updated_at
                .as_ref()
                .and_then(normalize_goose_ts_value);

            // Filter by since_ts
            if let Some(since) = since_ts {
                let latest = session_updated_ms.or(session_created_ms).unwrap_or(0);
                if latest < since {
                    continue;
                }
            }

            // Load messages for this session
            let messages = Self::load_messages_sqlite(&conn, &session.id)?;
            if messages.is_empty() {
                continue;
            }

            let msg_started_at = messages.iter().filter_map(|m| m.created_at).min();
            let msg_ended_at = messages.iter().filter_map(|m| m.created_at).max();

            let started_at = session_created_ms.or(msg_started_at);
            let ended_at = session_updated_ms.or(msg_ended_at).or(started_at);

            let workspace = session.working_dir.map(PathBuf::from);
            let title = session.description.or_else(|| {
                messages
                    .first()
                    .and_then(|m| m.content.lines().next())
                    .map(|s| s.chars().take(100).collect())
            });

            // Parse model info from model_config_json if available
            let model_name = session
                .model_config_json
                .as_deref()
                .and_then(|json_str| serde_json::from_str::<serde_json::Value>(json_str).ok())
                .and_then(|v| {
                    v.get("model")
                        .or_else(|| v.get("model_name"))
                        .and_then(|m| m.as_str())
                        .map(std::string::ToString::to_string)
                });

            convs.push(NormalizedConversation {
                agent_slug: "goose".into(),
                external_id: Some(session.id.clone()),
                title,
                workspace,
                source_path: db_path.join(urlencoding::encode(&session.id).as_ref()),
                started_at,
                ended_at,
                metadata: serde_json::json!({
                    "session_id": session.id,
                    "provider_name": session.provider_name,
                    "model_name": model_name,
                    "session_type": session.session_type,
                    "source": "sqlite",
                }),
                messages,
            });
        }

        Ok(convs)
    }

    /// Load messages for a session from SQLite.
    fn load_messages_sqlite(conn: &Connection, session_id: &str) -> Result<Vec<NormalizedMessage>> {
        let rows: Vec<GooseSqliteMessage> = conn.query_map_collect(
            "SELECT message_id, role, content_json, created_timestamp, tokens, metadata_json \
             FROM messages WHERE session_id = ? ORDER BY created_timestamp ASC",
            params![session_id],
            |row| {
                Ok(GooseSqliteMessage {
                    message_id: row.get_typed(0)?,
                    role: row.get_typed(1)?,
                    content_json: row.get_typed(2)?,
                    created_timestamp: optional_sqlite_value(row, 3),
                    tokens: row.get_typed(4)?,
                    metadata_json: row.get_typed(5)?,
                })
            },
        )?;

        let mut pending: Vec<(Option<i64>, String, NormalizedMessage)> = Vec::new();

        for row in rows {
            let msg_id = row.message_id.unwrap_or_default();
            if msg_id.is_empty() {
                continue;
            }

            let role = row.role.unwrap_or_else(|| "assistant".to_string());
            let created_at = row
                .created_timestamp
                .as_ref()
                .and_then(normalize_goose_ts_value);

            // Parse content_json to extract text and tool invocations
            let (content_text, invocations) =
                parse_goose_content_json(row.content_json.as_deref().unwrap_or("[]"));

            if content_text.trim().is_empty() && invocations.is_empty() {
                continue;
            }

            // Extract model info from metadata_json if available
            let author = if role == "assistant" {
                row.metadata_json
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
                    .and_then(|v| {
                        v.get("model")
                            .or_else(|| v.get("model_name"))
                            .and_then(|m| m.as_str())
                            .map(std::string::ToString::to_string)
                    })
            } else {
                Some("user".to_string())
            };

            let mut extra = serde_json::json!({
                "message_id": msg_id,
                "session_id": session_id,
            });
            if let Some(tokens) = row.tokens {
                extra["tokens"] = serde_json::json!(tokens);
            }

            pending.push((
                created_at,
                msg_id.clone(),
                NormalizedMessage {
                    idx: 0,
                    role,
                    author,
                    created_at,
                    content: content_text,
                    extra,
                    invocations,
                    snippets: Vec::new(),
                },
            ));
        }

        // Sort by timestamp, then by message id
        pending.sort_by(|a, b| {
            let a_ts = a.0.unwrap_or(i64::MAX);
            let b_ts = b.0.unwrap_or(i64::MAX);
            a_ts.cmp(&b_ts).then_with(|| a.1.cmp(&b.1))
        });
        let mut messages: Vec<NormalizedMessage> =
            pending.into_iter().map(|(_, _, msg)| msg).collect();
        crate::types::reindex_messages(&mut messages);

        Ok(messages)
    }
}

/// Session row from Goose SQLite.
struct GooseSqliteSession {
    id: String,
    description: Option<String>,
    working_dir: Option<String>,
    created_at: Option<SqliteValue>,
    updated_at: Option<SqliteValue>,
    provider_name: Option<String>,
    model_config_json: Option<String>,
    session_type: Option<String>,
}

/// Message row from Goose SQLite.
struct GooseSqliteMessage {
    message_id: Option<String>,
    role: Option<String>,
    content_json: Option<String>,
    created_timestamp: Option<SqliteValue>,
    tokens: Option<i64>,
    metadata_json: Option<String>,
}

/// JSONL line from legacy Goose session files.
#[derive(Debug, Deserialize)]
struct GooseJsonlLine {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    content: Option<serde_json::Value>,
    #[serde(default)]
    created_at: Option<serde_json::Value>,
    #[serde(default, alias = "message_id")]
    id: Option<String>,
    #[serde(default)]
    model: Option<String>,
}

impl Connector for GooseConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("goose").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();

        // --- Phase 1: Try SQLite database (v1.20+) ---
        let mut db_paths: Vec<PathBuf> = Vec::new();
        if ctx.data_dir.extension().is_some_and(|ext| ext == "db") {
            db_paths.push(ctx.data_dir.clone());
        } else if ctx.use_default_detection() {
            // Mirror the JSONL policy: a sessions.db under data_dir scopes
            // the sqlite scan to it; only otherwise probe the system store.
            // Probing both leaked the machine's real sessions into scoped
            // fixture/mirror scans. GOOSE_SQLITE_DB keeps precedence.
            let candidate = (!ctx.data_dir.as_os_str().is_empty())
                .then(|| ctx.data_dir.join("sessions.db"))
                .filter(|p| p.is_file());
            if let Some(db) = candidate.filter(|_| env_path_nonempty("GOOSE_SQLITE_DB").is_none()) {
                db_paths.push(db);
            } else if let Some(db) = Self::sqlite_db_path() {
                db_paths.push(db);
            }
        } else {
            if !ctx.data_dir.as_os_str().is_empty() {
                db_paths.push(ctx.data_dir.join("sessions.db"));
            }
            for scan_root in &ctx.scan_roots {
                Self::append_db_candidates(&mut db_paths, &scan_root.path);
            }
        }

        {
            let mut seen = HashSet::new();
            db_paths.retain(|p| seen.insert(p.clone()));
        }

        for db in db_paths {
            if !db.exists() {
                continue;
            }
            match Self::extract_from_sqlite(&db, ctx.since_ts) {
                Ok(sqlite_convs) => {
                    tracing::debug!(
                        "goose sqlite: found {} sessions in {}",
                        sqlite_convs.len(),
                        db.display()
                    );
                    convs.extend(sqlite_convs);
                }
                Err(e) => {
                    tracing::debug!("goose sqlite: failed to read {}: {e}", db.display());
                }
            }
        }

        // Collect seen IDs from SQLite results to avoid duplicates with JSONL
        let mut seen_ids: HashSet<String> =
            convs.iter().filter_map(|c| c.external_id.clone()).collect();

        // --- Phase 2: Fall back to JSONL file scanning (pre-v1.20) ---
        let mut session_roots: Vec<PathBuf> = Vec::new();
        if ctx.use_default_detection() {
            if ctx.data_dir.exists() && looks_like_goose_sessions(&ctx.data_dir) {
                session_roots.push(ctx.data_dir.clone());
            } else if let Some(dir) = Self::sessions_dir() {
                session_roots.push(dir);
            }
        } else {
            if ctx.data_dir.exists() {
                Self::append_session_roots(&mut session_roots, &ctx.data_dir);
            }
            for scan_root in &ctx.scan_roots {
                Self::append_session_roots(&mut session_roots, &scan_root.path);
            }
        }

        if session_roots.is_empty() {
            return Ok(convs);
        }

        session_roots.sort();
        session_roots.dedup();

        let mut seen_files: HashSet<PathBuf> = HashSet::new();

        for sessions_dir in session_roots {
            // Collect all .jsonl files
            let jsonl_files: Vec<PathBuf> = WalkDir::new(&sessions_dir)
                .max_depth(2)
                .into_iter()
                .flatten()
                .filter(|e| e.file_type().is_file())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
                .map(|e| e.path().to_path_buf())
                .collect();

            for jsonl_file in jsonl_files {
                if !seen_files.insert(dedupe_path_key(&jsonl_file)) {
                    continue;
                }
                if !file_modified_since(&jsonl_file, ctx.since_ts) {
                    continue;
                }

                // Use filename stem as session ID
                let session_id = jsonl_file
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                if !seen_ids.insert(session_id.clone()) {
                    continue;
                }

                match parse_goose_jsonl(&jsonl_file, &session_id) {
                    Ok(conv) => {
                        if !conv.messages.is_empty() {
                            convs.push(conv);
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "goose jsonl: failed to parse {}: {e}",
                            jsonl_file.display()
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

/// Check if a directory looks like a Goose sessions directory.
fn looks_like_goose_sessions(path: &Path) -> bool {
    // Check for sessions.db or any .jsonl files
    if path.join("sessions.db").exists() {
        return true;
    }

    // Check for at least one .jsonl file
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if entry.path().extension().is_some_and(|ext| ext == "jsonl") {
                return true;
            }
        }
    }

    false
}

fn optional_sqlite_value(row: &Row, index: usize) -> Option<SqliteValue> {
    row.get(index).and_then(|value| {
        if matches!(value, SqliteValue::Null) {
            None
        } else {
            Some(value.clone())
        }
    })
}

/// Normalize a raw SQLite value to epoch milliseconds.
///
/// Goose may store timestamps as:
///  - TEXT: ISO 8601 strings like `"2024-01-15T14:30:00Z"` or `"2024-01-15 14:30:00"`
///  - INTEGER: epoch seconds or epoch milliseconds
///  - REAL: fractional epoch seconds
fn normalize_goose_ts_value(val: &SqliteValue) -> Option<i64> {
    match val {
        SqliteValue::Integer(i) => normalize_goose_timestamp(Some(*i)),
        SqliteValue::Float(f) => {
            if f.is_nan() || f.is_infinite() {
                return None;
            }
            // Fractional epoch seconds (e.g. 1700000000.123)
            if (1_000_000_000.0..10_000_000_000.0).contains(f) {
                Some((*f * 1000.0) as i64)
            } else {
                normalize_goose_timestamp(Some(*f as i64))
            }
        }
        SqliteValue::Text(s) => {
            // Try common datetime formats
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
                Some(dt.and_utc().timestamp_millis())
            } else if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
            {
                Some(dt.and_utc().timestamp_millis())
            } else if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
                Some(dt.and_utc().timestamp_millis())
            } else if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
            {
                Some(dt.and_utc().timestamp_millis())
            } else if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                Some(dt.timestamp_millis())
            } else {
                // Last resort: try parsing as integer string
                s.trim()
                    .parse::<i64>()
                    .ok()
                    .and_then(|i| normalize_goose_timestamp(Some(i)))
            }
        }
        SqliteValue::Null | SqliteValue::Blob(_) => None,
    }
}

fn normalize_goose_timestamp(ts: Option<i64>) -> Option<i64> {
    ts.map(|raw| {
        // Plausible epoch seconds range -> convert to millis
        if (1_000_000_000..10_000_000_000).contains(&raw) {
            raw.saturating_mul(1000)
        } else {
            raw
        }
    })
}

/// Parse Goose's content_json array.
///
/// Goose stores message content as a JSON array with mixed element types:
/// - `{"type": "text", "text": "..."}` — plain text
/// - `{"type": "toolRequest", "toolCall": {"value": {"name": "...", "arguments": {...}}}}` — tool call
/// - `{"type": "toolResult", ...}` — tool result
///
/// Returns `(concatenated_text, tool_invocations)`.
fn parse_goose_content_json(json_str: &str) -> (String, Vec<NormalizedInvocation>) {
    let arr: Vec<serde_json::Value> = match serde_json::from_str(json_str) {
        Ok(serde_json::Value::Array(arr)) => arr,
        // Sometimes content_json is a bare string
        Ok(serde_json::Value::String(s)) => return (s, Vec::new()),
        _ => return (String::new(), Vec::new()),
    };

    let mut text_pieces: Vec<String> = Vec::new();
    let mut invocations: Vec<NormalizedInvocation> = Vec::new();

    for item in &arr {
        let item_type = item.get("type").and_then(|v| v.as_str());

        match item_type {
            Some("text") => {
                if let Some(text) = item.get("text").and_then(|v| v.as_str()) {
                    if !text.trim().is_empty() {
                        text_pieces.push(text.to_string());
                    }
                }
            }
            Some("toolRequest") => {
                // Extract tool call: {"toolCall": {"value": {"name": "...", "arguments": {...}}}}
                if let Some(tool_call) = item.get("toolCall") {
                    let value = tool_call.get("value").unwrap_or(tool_call);

                    let name = value
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let arguments = value.get("arguments").cloned();
                    let call_id = item
                        .get("id")
                        .or_else(|| tool_call.get("id"))
                        .and_then(|v| v.as_str())
                        .map(std::string::ToString::to_string);

                    invocations.push(NormalizedInvocation {
                        kind: "tool".to_string(),
                        name: name.to_string(),
                        raw_name: None,
                        call_id,
                        arguments,
                    });
                }
            }
            Some("toolResult") => {
                // Include tool result text in content for context
                if let Some(result) = item.get("result") {
                    // result may be a string or an array of content blocks
                    match result {
                        serde_json::Value::String(s) if !s.trim().is_empty() => {
                            text_pieces.push(format!("[Tool Result]\n{s}"));
                        }
                        serde_json::Value::Array(arr) => {
                            for block in arr {
                                if block.get("type").and_then(|v| v.as_str()) == Some("text") {
                                    if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                                        if !text.trim().is_empty() {
                                            text_pieces.push(format!("[Tool Result]\n{text}"));
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                // Unknown type — try to extract any text content
                if let Some(text) = item.get("text").and_then(|v| v.as_str()) {
                    if !text.trim().is_empty() {
                        text_pieces.push(text.to_string());
                    }
                }
            }
        }
    }

    (text_pieces.join("\n\n"), invocations)
}

/// Parse a legacy Goose JSONL session file.
fn parse_goose_jsonl(path: &Path, session_id: &str) -> Result<NormalizedConversation> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read Goose JSONL file {}", path.display()))?;

    let mut pending: Vec<(Option<i64>, String, NormalizedMessage)> = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let entry: GooseJsonlLine = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(
                    "goose jsonl: failed to parse line {} in {}: {e}",
                    line_idx + 1,
                    path.display()
                );
                continue;
            }
        };

        let msg_id = entry
            .id
            .unwrap_or_else(|| format!("{session_id}-{line_idx}"));

        let role = entry.role.unwrap_or_else(|| "assistant".to_string());

        // Parse content — may be a string or an array of content blocks
        let (content_text, invocations) = match &entry.content {
            Some(serde_json::Value::String(s)) => (s.clone(), Vec::new()),
            Some(serde_json::Value::Array(_)) => {
                let json_str = serde_json::to_string(&entry.content).unwrap_or_default();
                parse_goose_content_json(&json_str)
            }
            _ => (String::new(), Vec::new()),
        };

        if content_text.trim().is_empty() && invocations.is_empty() {
            continue;
        }

        // Parse created_at timestamp
        let created_at = match &entry.created_at {
            Some(serde_json::Value::Number(n)) => {
                if let Some(i) = n.as_i64() {
                    normalize_goose_timestamp(Some(i))
                } else if let Some(f) = n.as_f64() {
                    if f.is_nan() || f.is_infinite() {
                        None
                    } else if (1_000_000_000.0..10_000_000_000.0).contains(&f) {
                        Some((f * 1000.0) as i64)
                    } else {
                        normalize_goose_timestamp(Some(f as i64))
                    }
                } else {
                    None
                }
            }
            Some(serde_json::Value::String(s)) => {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                    Some(dt.timestamp_millis())
                } else if let Ok(ts) = s.parse::<i64>() {
                    normalize_goose_timestamp(Some(ts))
                } else {
                    None
                }
            }
            _ => None,
        };

        let author = if role == "assistant" {
            entry.model.clone()
        } else {
            Some("user".to_string())
        };

        pending.push((
            created_at,
            msg_id.clone(),
            NormalizedMessage {
                idx: 0,
                role,
                author,
                created_at,
                content: content_text,
                extra: serde_json::json!({
                    "message_id": msg_id,
                    "session_id": session_id,
                }),
                invocations,
                snippets: Vec::new(),
            },
        ));
    }

    // Sort by timestamp, then by message id
    pending.sort_by(|a, b| {
        let a_ts = a.0.unwrap_or(i64::MAX);
        let b_ts = b.0.unwrap_or(i64::MAX);
        a_ts.cmp(&b_ts).then_with(|| a.1.cmp(&b.1))
    });
    let mut messages: Vec<NormalizedMessage> = pending.into_iter().map(|(_, _, msg)| msg).collect();
    crate::types::reindex_messages(&mut messages);

    let started_at = messages.iter().filter_map(|m| m.created_at).min();
    let ended_at = messages.iter().filter_map(|m| m.created_at).max();

    let title = messages
        .first()
        .and_then(|m| m.content.lines().next())
        .map(|s| s.chars().take(100).collect());

    Ok(NormalizedConversation {
        agent_slug: "goose".into(),
        external_id: Some(session_id.to_string()),
        title,
        workspace: None,
        source_path: path.to_path_buf(),
        started_at,
        ended_at,
        metadata: serde_json::json!({
            "session_id": session_id,
            "source": "jsonl",
        }),
        messages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::{ScanContext, ScanRoot};
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn open_test_connection(path: &Path) -> Connection {
        Connection::open(path.to_string_lossy().as_ref()).unwrap()
    }

    // =====================================================
    // Constructor Tests
    // =====================================================

    #[test]
    fn new_creates_connector() {
        let connector = GooseConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = GooseConnector;
        let _ = connector;
    }

    // =====================================================
    // looks_like_goose_sessions() Tests
    // =====================================================

    #[test]
    fn looks_like_goose_sessions_with_db() {
        let dir = TempDir::new().unwrap();
        assert!(!looks_like_goose_sessions(dir.path()));

        fs::write(dir.path().join("sessions.db"), b"sqlite").unwrap();
        assert!(looks_like_goose_sessions(dir.path()));
    }

    #[test]
    fn looks_like_goose_sessions_with_jsonl() {
        let dir = TempDir::new().unwrap();
        assert!(!looks_like_goose_sessions(dir.path()));

        fs::write(dir.path().join("session1.jsonl"), b"{}").unwrap();
        assert!(looks_like_goose_sessions(dir.path()));
    }

    #[test]
    fn looks_like_goose_sessions_empty_dir() {
        let dir = TempDir::new().unwrap();
        assert!(!looks_like_goose_sessions(dir.path()));
    }

    #[test]
    fn scan_with_goose_root_scan_root() {
        let dir = TempDir::new().unwrap();
        let goose_root = dir.path().join(".goose");
        let sessions_dir = goose_root.join("sessions");
        fs::create_dir_all(&sessions_dir).unwrap();
        fs::write(
            sessions_dir.join("session1.jsonl"),
            r#"{"role":"user","content":"hi","created_at":1700000000}"#,
        )
        .unwrap();

        let connector = GooseConnector::new();
        let ctx = ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(goose_root)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("session1"));
    }

    #[test]
    fn scan_with_explicit_local_share_root_finds_sqlite_db() {
        let dir = TempDir::new().unwrap();
        let local_share = dir.path().join(".local/share");
        let sessions_dir = local_share.join("goose/sessions");
        fs::create_dir_all(&sessions_dir).unwrap();

        let db_path = sessions_dir.join("sessions.db");
        let conn = open_test_connection(&db_path);
        conn.execute_batch(
            "CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                description TEXT,
                working_dir TEXT,
                created_at INTEGER,
                updated_at INTEGER,
                provider_name TEXT,
                model_config_json TEXT,
                session_type TEXT
            );
            CREATE TABLE messages (
                session_id TEXT,
                role TEXT,
                content_json TEXT,
                created_timestamp INTEGER,
                tokens INTEGER,
                metadata_json TEXT,
                message_id TEXT PRIMARY KEY
            );",
        )
        .unwrap();

        conn.execute_compat(
            "INSERT INTO sessions (id, description, working_dir, created_at, updated_at, provider_name) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "sess-share",
                "Share session",
                "/home/user/share",
                1_700_000_000,
                1_700_000_100,
                "openai"
            ],
        )
        .unwrap();

        let content_json = json!([
            {"type": "text", "text": "Hello from share!"}
        ]);
        conn.execute_compat(
            "INSERT INTO messages (session_id, role, content_json, created_timestamp, tokens, metadata_json, message_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "sess-share",
                "assistant",
                content_json.to_string(),
                1_700_000_050,
                7,
                r#"{"model": "gpt-4o"}"#,
                "msg-share"
            ],
        )
        .unwrap();

        let connector = GooseConnector::new();
        let ctx = ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(local_share)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-share"));
    }

    // =====================================================
    // parse_goose_content_json() Tests
    // =====================================================

    #[test]
    fn parse_content_json_text_block() {
        let json = r#"[{"type": "text", "text": "Hello, world!"}]"#;
        let (text, invocations) = parse_goose_content_json(json);
        assert_eq!(text, "Hello, world!");
        assert!(invocations.is_empty());
    }

    #[test]
    fn parse_content_json_tool_request() {
        let json = json!([
            {"type": "text", "text": "Let me read that file."},
            {
                "type": "toolRequest",
                "id": "call_123",
                "toolCall": {
                    "value": {
                        "name": "read_file",
                        "arguments": {"path": "/tmp/test.txt"}
                    }
                }
            }
        ]);
        let json_str = serde_json::to_string(&json).unwrap();
        let (text, invocations) = parse_goose_content_json(&json_str);
        assert_eq!(text, "Let me read that file.");
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].name, "read_file");
        assert_eq!(invocations[0].kind, "tool");
        assert_eq!(invocations[0].call_id.as_deref(), Some("call_123"));
        assert_eq!(
            invocations[0].arguments,
            Some(json!({"path": "/tmp/test.txt"}))
        );
    }

    #[test]
    fn parse_content_json_multiple_tool_requests() {
        let json = json!([
            {"type": "toolRequest", "toolCall": {"value": {"name": "bash", "arguments": {"cmd": "ls"}}}},
            {"type": "text", "text": "Done."},
            {"type": "toolRequest", "toolCall": {"value": {"name": "write_file", "arguments": {"path": "a.txt"}}}}
        ]);
        let json_str = serde_json::to_string(&json).unwrap();
        let (text, invocations) = parse_goose_content_json(&json_str);
        assert_eq!(text, "Done.");
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[0].name, "bash");
        assert_eq!(invocations[1].name, "write_file");
    }

    #[test]
    fn parse_content_json_bare_string() {
        let (text, invocations) = parse_goose_content_json(r#""just a string""#);
        assert_eq!(text, "just a string");
        assert!(invocations.is_empty());
    }

    #[test]
    fn parse_content_json_empty() {
        let (text, invocations) = parse_goose_content_json("[]");
        assert_eq!(text, "");
        assert!(invocations.is_empty());
    }

    #[test]
    fn parse_content_json_invalid() {
        let (text, invocations) = parse_goose_content_json("not json");
        assert_eq!(text, "");
        assert!(invocations.is_empty());
    }

    #[test]
    fn parse_content_json_tool_result_string() {
        let json = json!([
            {"type": "toolResult", "result": "file contents here"}
        ]);
        let json_str = serde_json::to_string(&json).unwrap();
        let (text, _invocations) = parse_goose_content_json(&json_str);
        assert!(text.contains("file contents here"));
    }

    #[test]
    fn parse_content_json_tool_result_array() {
        let json = json!([
            {"type": "toolResult", "result": [{"type": "text", "text": "output line 1"}]}
        ]);
        let json_str = serde_json::to_string(&json).unwrap();
        let (text, _invocations) = parse_goose_content_json(&json_str);
        assert!(text.contains("output line 1"));
    }

    #[test]
    fn parse_content_json_toolcall_without_value_wrapper() {
        // Some versions may omit the `value` wrapper
        let json = json!([
            {
                "type": "toolRequest",
                "toolCall": {
                    "name": "shell",
                    "arguments": {"command": "pwd"}
                }
            }
        ]);
        let json_str = serde_json::to_string(&json).unwrap();
        let (_text, invocations) = parse_goose_content_json(&json_str);
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].name, "shell");
    }

    // =====================================================
    // Timestamp Normalization Tests
    // =====================================================

    #[test]
    fn normalize_epoch_seconds() {
        assert_eq!(
            normalize_goose_timestamp(Some(1_700_000_000)),
            Some(1_700_000_000_000)
        );
    }

    #[test]
    fn normalize_epoch_millis_passthrough() {
        assert_eq!(
            normalize_goose_timestamp(Some(1_700_000_000_000)),
            Some(1_700_000_000_000)
        );
    }

    #[test]
    fn normalize_sqlite_ts_integer() {
        let val = SqliteValue::Integer(1_700_000_000);
        assert_eq!(normalize_goose_ts_value(&val), Some(1_700_000_000_000));
    }

    #[test]
    fn normalize_sqlite_ts_text_iso() {
        let val = SqliteValue::Text("2024-01-15T14:30:00Z".into());
        assert!(normalize_goose_ts_value(&val).is_some());
    }

    #[test]
    fn normalize_sqlite_ts_text_space() {
        let val = SqliteValue::Text("2024-01-15 14:30:00".into());
        assert!(normalize_goose_ts_value(&val).is_some());
    }

    #[test]
    fn normalize_sqlite_ts_real() {
        let val = SqliteValue::Float(1_700_000_000.5);
        let result = normalize_goose_ts_value(&val);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 1_700_000_000_500);
    }

    #[test]
    fn normalize_sqlite_ts_null() {
        let val = SqliteValue::Null;
        assert_eq!(normalize_goose_ts_value(&val), None);
    }

    // =====================================================
    // JSONL Parsing Tests
    // =====================================================

    #[test]
    fn parse_jsonl_basic() {
        let dir = TempDir::new().unwrap();
        let jsonl_path = dir.path().join("test-session.jsonl");

        let lines = [
            json!({"role": "user", "content": "Hello", "id": "msg1", "created_at": 1700000000}).to_string(),
            json!({"role": "assistant", "content": "Hi there!", "id": "msg2", "created_at": 1700000001}).to_string(),
        ];
        fs::write(&jsonl_path, lines.join("\n")).unwrap();

        let conv = parse_goose_jsonl(&jsonl_path, "test-session").unwrap();
        assert_eq!(conv.agent_slug, "goose");
        assert_eq!(conv.external_id.as_deref(), Some("test-session"));
        assert_eq!(conv.messages.len(), 2);
        assert_eq!(conv.messages[0].role, "user");
        assert_eq!(conv.messages[0].content, "Hello");
        assert_eq!(conv.messages[1].role, "assistant");
        assert_eq!(conv.messages[1].content, "Hi there!");
    }

    #[test]
    fn parse_jsonl_with_content_blocks() {
        let dir = TempDir::new().unwrap();
        let jsonl_path = dir.path().join("test-session.jsonl");

        let line = json!({
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Let me help you."},
                {"type": "toolRequest", "toolCall": {"value": {"name": "bash", "arguments": {"cmd": "ls"}}}}
            ],
            "id": "msg1"
        });
        fs::write(&jsonl_path, line.to_string()).unwrap();

        let conv = parse_goose_jsonl(&jsonl_path, "test-session").unwrap();
        assert_eq!(conv.messages.len(), 1);
        assert!(conv.messages[0].content.contains("Let me help you."));
        assert_eq!(conv.messages[0].invocations.len(), 1);
        assert_eq!(conv.messages[0].invocations[0].name, "bash");
    }

    #[test]
    fn parse_jsonl_empty_lines_skipped() {
        let dir = TempDir::new().unwrap();
        let jsonl_path = dir.path().join("test-session.jsonl");

        let content = format!(
            "{}\n\n{}\n",
            json!({"role": "user", "content": "Hi", "id": "m1"}),
            json!({"role": "assistant", "content": "Hey", "id": "m2"})
        );
        fs::write(&jsonl_path, content).unwrap();

        let conv = parse_goose_jsonl(&jsonl_path, "test").unwrap();
        assert_eq!(conv.messages.len(), 2);
    }

    // =====================================================
    // SQLite Tests
    // =====================================================

    #[test]
    fn extract_sqlite_basic() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("sessions.db");

        let conn = open_test_connection(&db_path);
        conn.execute_batch(
            "CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                description TEXT,
                working_dir TEXT,
                created_at INTEGER,
                updated_at INTEGER,
                provider_name TEXT,
                model_config_json TEXT,
                session_type TEXT
            );
            CREATE TABLE messages (
                session_id TEXT,
                role TEXT,
                content_json TEXT,
                created_timestamp INTEGER,
                tokens INTEGER,
                metadata_json TEXT,
                message_id TEXT PRIMARY KEY
            );",
        )
        .unwrap();

        conn.execute_compat(
            "INSERT INTO sessions (id, description, working_dir, created_at, updated_at, provider_name) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "sess1",
                "Test session",
                "/home/user/project",
                1_700_000_000,
                1_700_000_100,
                "openai"
            ],
        )
        .unwrap();

        let content_json = json!([
            {"type": "text", "text": "Hello from Goose!"}
        ]);
        conn.execute_compat(
            "INSERT INTO messages (session_id, role, content_json, created_timestamp, tokens, metadata_json, message_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "sess1",
                "assistant",
                content_json.to_string(),
                1_700_000_050,
                42,
                r#"{"model": "gpt-4o"}"#,
                "msg1"
            ],
        )
        .unwrap();

        drop(conn);

        let convs = GooseConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "goose");
        assert_eq!(convs[0].external_id.as_deref(), Some("sess1"));
        assert_eq!(convs[0].title.as_deref(), Some("Test session"));
        assert_eq!(
            convs[0].workspace.as_deref(),
            Some(std::path::Path::new("/home/user/project"))
        );
        assert_eq!(convs[0].messages.len(), 1);
        assert!(convs[0].messages[0].content.contains("Hello from Goose!"));
        assert_eq!(convs[0].messages[0].author.as_deref(), Some("gpt-4o"));
        assert_eq!(
            convs[0].metadata.get("source").and_then(|v| v.as_str()),
            Some("sqlite")
        );
    }

    #[test]
    fn default_detection_scopes_sqlite_to_data_dir() {
        // A sessions.db under data_dir must scope the default-detection
        // sqlite scan to THIS store; the machine's real ~/.goose store must
        // not leak additional conversations into the result.
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("sessions.db");
        let conn = open_test_connection(&db_path);
        conn.execute_batch(
            "CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                description TEXT,
                working_dir TEXT,
                created_at INTEGER,
                updated_at INTEGER,
                provider_name TEXT,
                model_config_json TEXT,
                session_type TEXT
            );
            CREATE TABLE messages (
                session_id TEXT,
                role TEXT,
                content_json TEXT,
                created_timestamp INTEGER,
                tokens INTEGER,
                metadata_json TEXT,
                message_id TEXT PRIMARY KEY
            );",
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO sessions (id, description, working_dir, created_at, updated_at, provider_name) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "sess-scope",
                "Scoped session",
                "/data/projects/demo",
                1_700_000_000_i64,
                1_700_000_100_i64,
                "openai"
            ],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO messages (session_id, role, content_json, created_timestamp, tokens, metadata_json, message_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "sess-scope",
                "assistant",
                json!([{"type": "text", "text": "Hello from Goose!"}]).to_string(),
                1_700_000_050_i64,
                42_i64,
                r#"{"model": "gpt-4o"}"#,
                "msg-scope"
            ],
        )
        .unwrap();
        drop(conn);

        let convs = GooseConnector
            .scan(&ScanContext::local_default(dir.path().to_path_buf(), None))
            .unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-scope"));
        // Goose derives per-session source paths as <db>/<external_id>.
        assert_eq!(convs[0].source_path, db_path.join("sess-scope"));
    }

    #[test]
    fn extract_sqlite_with_tool_calls() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("sessions.db");

        let conn = open_test_connection(&db_path);
        conn.execute_batch(
            "CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                description TEXT,
                working_dir TEXT,
                created_at INTEGER,
                updated_at INTEGER,
                provider_name TEXT,
                model_config_json TEXT,
                session_type TEXT
            );
            CREATE TABLE messages (
                session_id TEXT,
                role TEXT,
                content_json TEXT,
                created_timestamp INTEGER,
                tokens INTEGER,
                metadata_json TEXT,
                message_id TEXT PRIMARY KEY
            );",
        )
        .unwrap();

        conn.execute_compat(
            "INSERT INTO sessions (id, description, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params!["sess1", "Tools test", 1_700_000_000, 1_700_000_100],
        )
        .unwrap();

        let content_json = json!([
            {"type": "text", "text": "Let me check that file."},
            {
                "type": "toolRequest",
                "id": "tc_1",
                "toolCall": {
                    "value": {
                        "name": "read_file",
                        "arguments": {"path": "/etc/hosts"}
                    }
                }
            }
        ]);
        conn.execute_compat(
            "INSERT INTO messages (session_id, role, content_json, created_timestamp, message_id) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "sess1",
                "assistant",
                content_json.to_string(),
                1_700_000_050,
                "msg1"
            ],
        )
        .unwrap();

        drop(conn);

        let convs = GooseConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert_eq!(convs.len(), 1);
        let msg = &convs[0].messages[0];
        assert_eq!(msg.invocations.len(), 1);
        assert_eq!(msg.invocations[0].name, "read_file");
        assert_eq!(msg.invocations[0].call_id.as_deref(), Some("tc_1"));
    }

    #[test]
    fn extract_sqlite_since_filter() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("sessions.db");

        let conn = open_test_connection(&db_path);
        conn.execute_batch(
            "CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                description TEXT,
                working_dir TEXT,
                created_at INTEGER,
                updated_at INTEGER,
                provider_name TEXT,
                model_config_json TEXT,
                session_type TEXT
            );
            CREATE TABLE messages (
                session_id TEXT,
                role TEXT,
                content_json TEXT,
                created_timestamp INTEGER,
                tokens INTEGER,
                metadata_json TEXT,
                message_id TEXT PRIMARY KEY
            );",
        )
        .unwrap();

        // Old session
        conn.execute_compat(
            "INSERT INTO sessions (id, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params!["old", "Old session", 1_600_000_000, 1_600_000_100],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO messages (session_id, role, content_json, created_timestamp, message_id) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "old",
                "user",
                r#"[{"type":"text","text":"old"}]"#,
                1_600_000_050,
                "old_msg"
            ],
        )
        .unwrap();

        // New session
        conn.execute_compat(
            "INSERT INTO sessions (id, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params!["new", "New session", 1_700_000_000, 1_700_000_100],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO messages (session_id, role, content_json, created_timestamp, message_id) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "new",
                "user",
                r#"[{"type":"text","text":"new"}]"#,
                1_700_000_050,
                "new_msg"
            ],
        )
        .unwrap();

        drop(conn);

        // Since timestamp that excludes the old session (converted to millis)
        let since = 1_650_000_000_000;
        let convs = GooseConnector::extract_from_sqlite(&db_path, Some(since)).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("new"));
    }

    #[test]
    fn extract_sqlite_empty_messages_skipped() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("sessions.db");

        let conn = open_test_connection(&db_path);
        conn.execute_batch(
            "CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                description TEXT,
                working_dir TEXT,
                created_at INTEGER,
                updated_at INTEGER,
                provider_name TEXT,
                model_config_json TEXT,
                session_type TEXT
            );
            CREATE TABLE messages (
                session_id TEXT,
                role TEXT,
                content_json TEXT,
                created_timestamp INTEGER,
                tokens INTEGER,
                metadata_json TEXT,
                message_id TEXT PRIMARY KEY
            );",
        )
        .unwrap();

        // Session with no messages
        conn.execute_compat(
            "INSERT INTO sessions (id, description, created_at) VALUES (?1, ?2, ?3)",
            params!["empty", "Empty session", 1_700_000_000],
        )
        .unwrap();

        drop(conn);

        let convs = GooseConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn discover_source_files_includes_sqlite_and_jsonl_sources() {
        let temp = TempDir::new().unwrap();
        let sessions_root = temp.path().join("goose").join("sessions");
        fs::create_dir_all(&sessions_root).unwrap();
        let db_path = sessions_root.join("sessions.db");
        let jsonl_path = sessions_root.join("legacy.jsonl");
        fs::write(&db_path, b"not a real sqlite db").unwrap();
        fs::write(
            &jsonl_path,
            br#"{"role":"user","content":[{"type":"text","text":"hello"}],"created_at":1700000000}"#,
        )
        .unwrap();

        let root = ScanRoot::local(sessions_root.clone());
        let ctx = ScanContext::with_roots(temp.path().to_path_buf(), vec![root], None);
        let sources = GooseConnector::new()
            .discover_source_files(&ctx)
            .expect("source discovery");

        assert!(sources.iter().any(|source| {
            source.source_path == db_path
                && source.provider_slug == "goose"
                && source.role == DiscoveredSourceRole::SqliteDatabase
                && source.required_for_reconstruction
        }));
        assert!(sources.iter().any(|source| {
            source.source_path == jsonl_path
                && source.provider_slug == "goose"
                && source.role == DiscoveredSourceRole::PrimarySessionLog
                && source.required_for_reconstruction
        }));
    }
}
