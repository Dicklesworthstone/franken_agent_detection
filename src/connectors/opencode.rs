//! `OpenCode` connector for JSON file-based and `SQLite` storage.
//!
//! **v1.2+ (SQLite):** Data is stored in `~/.local/share/opencode/opencode.db`
//! with tables: session, message, part. The `message.data` and `part.data` columns
//! contain JSON blobs.
//!
//! **Pre-v1.2 (JSON):** Data at `~/.local/share/opencode/storage/` using files:
//!   - session/{projectID}/{sessionID}.json  - Session metadata
//!   - message/{sessionID}/{messageID}.json  - Message metadata
//!   - part/{messageID}/{partID}.json        - Actual message content

#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::manual_string_new,
    clippy::map_unwrap_or,
    clippy::missing_const_for_fn,
    clippy::must_use_candidate,
    clippy::nonminimal_bool,
    clippy::option_if_let_else,
    clippy::single_option_map,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::unnecessary_wraps,
    clippy::unreadable_literal
)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use frankensqlite::compat::{OpenFlags, ParamValue, RowExt};
use frankensqlite::{Row, SqliteValue, params};

use super::sqlite_sync::{Connection, ConnectionExt, open_with_flags};

/// Max ids bound into a single `... IN (?, ?, …)` chunk. Kept well under
/// SQLite's default 999-parameter ceiling. (#372: incremental opencode scans
/// load only the changed sessions' messages/parts instead of the whole DB.)
const OPENCODE_SQL_IN_CHUNK: usize = 800;

/// Emit a scan liveness tick every N decoded rows during a large sqlite scan so
/// the host stall watchdog sees progress before the first conversation is
/// yielded (cass#373 Variant A). Frequent enough that a multi-minute full scan
/// never leaves a >120s silent gap; cheap enough to be noise otherwise.
const OPENCODE_SCAN_TICK_EVERY: usize = 2000;

/// Call `tick` (if present) once every `OPENCODE_SCAN_TICK_EVERY` rows.
#[inline]
fn opencode_scan_tick(tick: Option<&(dyn Fn() + Send + Sync)>, row_index: usize) {
    if row_index % OPENCODE_SCAN_TICK_EVERY == 0
        && let Some(tick) = tick
    {
        tick();
    }
}
use serde::Deserialize;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::{dedupe_path_key, env_path_nonempty};
use super::{Connector, file_modified_since, franken_detection_for_connector};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct OpenCodeConnector;

impl Default for OpenCodeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenCodeConnector {
    pub fn new() -> Self {
        Self
    }

    /// Get the OpenCode storage directory.
    /// OpenCode stores sessions in ~/.local/share/opencode/storage/
    fn storage_root() -> Option<PathBuf> {
        // Check for env override first (useful for testing)
        if let Some(p) = env_path_nonempty("OPENCODE_STORAGE_ROOT") {
            if p.is_dir() {
                return Some(p);
            }
        }

        // Primary location: XDG data directory (Linux/macOS)
        if let Some(data) = dirs::data_local_dir() {
            let storage_dir = data.join("opencode/storage");
            if storage_dir.is_dir() {
                return Some(storage_dir);
            }
        }

        // XDG config path — on macOS dirs::data_local_dir() returns
        // ~/Library/Application Support which misses XDG-style installs
        // that place data under ~/.config/opencode/ (#146).
        if let Some(config) = dirs::config_dir() {
            let storage_dir = config.join("opencode/storage");
            if storage_dir.is_dir() {
                return Some(storage_dir);
            }
        }

        // Fallback: ~/.local/share/opencode/storage
        if let Some(home) = dirs::home_dir() {
            let storage_dir = home.join(".local/share/opencode/storage");
            if storage_dir.is_dir() {
                return Some(storage_dir);
            }
            // Also check ~/.config/opencode/storage for XDG-style installs
            let xdg_storage = home.join(".config/opencode/storage");
            if xdg_storage.is_dir() {
                return Some(xdg_storage);
            }
        }

        None
    }

    /// Home/XDG DB discovery is only valid when every supplied scan root
    /// refers to this machine. A remote-mirror root must never pull the
    /// local canonical `opencode.db` into its scan — the caller attributes
    /// everything returned by that invocation to the remote source, so the
    /// local sessions would be double-indexed under the remote `source_id`
    /// (cass#357). Vacuously true when `scan_roots` is empty, preserving
    /// default detection and the issue #174 local-explicit-root behavior.
    fn allow_local_default_dbs(ctx: &ScanContext) -> bool {
        ctx.scan_roots.iter().all(|root| root.origin.is_local())
    }

    /// All known locations where OpenCode may store its SQLite database,
    /// in priority order. Exposed so that scan paths can fall back through
    /// them even when the caller provided an explicit (non-matching)
    /// `data_dir`.
    fn sqlite_db_candidates() -> Vec<PathBuf> {
        Self::sqlite_db_candidates_from(
            env_path_nonempty("OPENCODE_SQLITE_DB"),
            dirs::home_dir().as_deref(),
            dirs::data_local_dir().as_deref(),
            dirs::config_dir().as_deref(),
        )
    }

    /// Pure, env-free variant of [`Self::sqlite_db_candidates`] for tests.
    /// Every environment-dependent input is passed in explicitly so the
    /// resulting list is fully deterministic.
    fn sqlite_db_candidates_from(
        explicit_override: Option<PathBuf>,
        home: Option<&Path>,
        xdg_data: Option<&Path>,
        xdg_config: Option<&Path>,
    ) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();

        // 1. Explicit override for tests / custom installs.
        if let Some(path) = explicit_override {
            out.push(path);
        }

        // 2. XDG data dir via $HOME. OpenCode uses this on every platform,
        //    including macOS. This MUST be tried before
        //    dirs::data_local_dir() because on macOS the latter resolves
        //    to ~/Library/Application Support which OpenCode does not use.
        if let Some(home) = home {
            out.push(home.join(".local/share/opencode/opencode.db"));
            out.push(home.join(".config/opencode/opencode.db"));
        }

        // 3. Platform-native data/config dirs (for users who have moved
        //    OpenCode into non-XDG locations).
        if let Some(data) = xdg_data {
            out.push(data.join("opencode/opencode.db"));
        }
        if let Some(config) = xdg_config {
            out.push(config.join("opencode/opencode.db"));
        }

        // Deduplicate preserving order — multiple dirs helpers may resolve
        // to the same path on a given platform (e.g. macOS config_dir ==
        // data_local_dir).
        let mut seen = HashSet::new();
        out.retain(|p| seen.insert(p.clone()));
        out
    }

    fn is_local_share_root(path: &Path) -> bool {
        path.file_name().is_some_and(|name| name == "share")
            && path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|name| name == ".local"))
    }

    fn is_appdata_roaming(path: &Path) -> bool {
        path.file_name().is_some_and(|name| name == "Roaming")
            && path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|name| name == "AppData"))
    }

    fn append_explicit_db_candidates(out: &mut Vec<PathBuf>, base: &Path) {
        let file_name = base.file_name().and_then(|n| n.to_str());
        let is_config = file_name.is_some_and(|n| n == ".config");
        let is_local = file_name.is_some_and(|n| n == ".local");
        let is_share = Self::is_local_share_root(base);
        let is_app_support = file_name.is_some_and(|n| n == "Application Support");
        let is_roaming = Self::is_appdata_roaming(base);
        let is_opencode = file_name.is_some_and(|n| n == "opencode");

        if base.extension().is_some_and(|ext| ext == "db") {
            out.push(base.to_path_buf());
        } else {
            out.push(base.join("opencode.db"));
        }

        if is_opencode {
            out.push(base.join("opencode.db"));
        }

        // Treat base as an XDG-style root for opencode data.
        out.push(base.join("opencode/opencode.db"));

        if is_local {
            out.push(base.join("share/opencode/opencode.db"));
        }

        if !(is_config || is_local || is_share || is_app_support || is_roaming || is_opencode) {
            out.push(base.join(".local/share/opencode/opencode.db"));
            out.push(base.join(".config/opencode/opencode.db"));
            out.push(base.join("Library/Application Support/opencode/opencode.db"));
            out.push(base.join("AppData/Roaming/opencode/opencode.db"));
        }
    }

    fn append_explicit_storage_candidates(out: &mut Vec<PathBuf>, base: &Path) {
        let file_name = base.file_name().and_then(|n| n.to_str());
        let is_config = file_name.is_some_and(|n| n == ".config");
        let is_local = file_name.is_some_and(|n| n == ".local");
        let is_share = Self::is_local_share_root(base);
        let is_app_support = file_name.is_some_and(|n| n == "Application Support");
        let is_roaming = Self::is_appdata_roaming(base);
        let is_opencode = file_name.is_some_and(|n| n == "opencode");

        out.push(base.join("opencode/storage"));

        if is_opencode {
            out.push(base.join("storage"));
        }

        if is_local {
            out.push(base.join("share/opencode/storage"));
        }

        if !(is_config || is_local || is_share || is_app_support || is_roaming || is_opencode) {
            out.push(base.join(".local/share/opencode/storage"));
            out.push(base.join(".config/opencode/storage"));
            out.push(base.join("Library/Application Support/opencode/storage"));
            out.push(base.join("AppData/Roaming/opencode/storage"));
        }
    }

    fn sqlite_source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut db_candidates: Vec<ScanRoot> = Vec::new();
        if ctx.data_dir.extension().is_some_and(|ext| ext == "db") {
            db_candidates.push(ScanRoot::local(ctx.data_dir.clone()));
        } else if !ctx.data_dir.as_os_str().is_empty() {
            db_candidates.push(ScanRoot::local(ctx.data_dir.join("opencode.db")));
        }

        if !ctx.use_default_detection() {
            for scan_root in &ctx.scan_roots {
                let mut candidates = Vec::new();
                Self::append_explicit_db_candidates(&mut candidates, &scan_root.path);
                db_candidates.extend(candidates.into_iter().map(|path| scan_root.with_path(path)));
            }
        }

        if Self::allow_local_default_dbs(ctx) {
            db_candidates.extend(
                Self::sqlite_db_candidates()
                    .into_iter()
                    .map(ScanRoot::local),
            );
        }

        let mut seen = HashSet::new();
        db_candidates.retain(|root| seen.insert(root.path.clone()));
        db_candidates
    }

    fn storage_source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut storage_roots: Vec<ScanRoot> = Vec::new();
        if ctx.use_default_detection() {
            if ctx.data_dir.exists() && looks_like_opencode_storage(&ctx.data_dir) {
                storage_roots.push(ScanRoot::local(ctx.data_dir.clone()));
            } else if let Some(root) = Self::storage_root() {
                storage_roots.push(ScanRoot::local(root));
            }
        } else {
            if ctx.data_dir.exists() && looks_like_opencode_storage(&ctx.data_dir) {
                storage_roots.push(ScanRoot::local(ctx.data_dir.clone()));
            }
            for scan_root in &ctx.scan_roots {
                let mut candidates = vec![scan_root.path.clone()];
                Self::append_explicit_storage_candidates(&mut candidates, &scan_root.path);
                for candidate in candidates {
                    if candidate.exists() && looks_like_opencode_storage(&candidate) {
                        storage_roots.push(scan_root.with_path(candidate));
                    }
                }
            }
        }

        storage_roots.sort_by(|a, b| a.path.cmp(&b.path));
        storage_roots.dedup_by(|a, b| a.path == b.path);
        storage_roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        Self::discover_sqlite_sources(ctx, &mut out);
        Self::discover_legacy_storage_sources(ctx, &mut out);
        out
    }

    fn discover_sqlite_sources(ctx: &ScanContext, out: &mut Vec<DiscoveredSourceFile>) {
        let mut seen = HashSet::new();

        for root in Self::sqlite_source_roots(ctx) {
            if !root.path.is_file() {
                continue;
            }
            let canonical = std::fs::canonicalize(&root.path).unwrap_or_else(|_| root.path.clone());
            if !seen.insert(canonical) {
                continue;
            }
            out.push(
                DiscoveredSourceFile::new(
                    "opencode",
                    &root,
                    root.path.clone(),
                    DiscoveredSourceRole::SqliteDatabase,
                    true,
                )
                .with_fs_metadata(),
            );
        }
    }

    fn discover_legacy_storage_sources(ctx: &ScanContext, out: &mut Vec<DiscoveredSourceFile>) {
        let mut seen_session_files = HashSet::new();
        for root in Self::storage_source_roots(ctx) {
            let session_dir = root.path.join("session");
            let message_dir = root.path.join("message");
            let part_dir = root.path.join("part");
            if !session_dir.exists() {
                continue;
            }

            let session_files: Vec<PathBuf> = WalkDir::new(&session_dir)
                .into_iter()
                .flatten()
                .filter(|entry| entry.file_type().is_file())
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                .map(|entry| entry.path().to_path_buf())
                .collect();

            for session_file in session_files {
                if !seen_session_files.insert(dedupe_path_key(&session_file)) {
                    continue;
                }
                if !session_has_updates(&session_file, &message_dir, &part_dir, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "opencode",
                        &root,
                        session_file.clone(),
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );

                Self::discover_legacy_session_sidecars(
                    &root,
                    &session_file,
                    &message_dir,
                    &part_dir,
                    out,
                );
            }
        }
    }

    fn discover_legacy_session_sidecars(
        root: &ScanRoot,
        session_file: &Path,
        message_dir: &Path,
        part_dir: &Path,
        out: &mut Vec<DiscoveredSourceFile>,
    ) {
        let Some(session_id) = session_file.file_stem().and_then(|name| name.to_str()) else {
            return;
        };
        let session_msg_dir = message_dir.join(session_id);
        if !session_msg_dir.exists() {
            return;
        }

        for entry in WalkDir::new(&session_msg_dir).into_iter().flatten() {
            if !entry.file_type().is_file()
                || !entry.path().extension().is_some_and(|ext| ext == "json")
            {
                continue;
            }

            let message_file = entry.path().to_path_buf();
            out.push(
                DiscoveredSourceFile::new(
                    "opencode",
                    root,
                    message_file.clone(),
                    DiscoveredSourceRole::MetadataSidecar,
                    true,
                )
                .with_fs_metadata(),
            );
            Self::discover_legacy_message_parts(root, &message_file, part_dir, out);
        }
    }

    fn discover_legacy_message_parts(
        root: &ScanRoot,
        message_file: &Path,
        part_dir: &Path,
        out: &mut Vec<DiscoveredSourceFile>,
    ) {
        let Some(message_id) = message_file.file_stem().and_then(|name| name.to_str()) else {
            return;
        };
        let message_part_dir = part_dir.join(message_id);
        for part_entry in WalkDir::new(&message_part_dir).into_iter().flatten() {
            if !part_entry.file_type().is_file()
                || part_entry
                    .path()
                    .extension()
                    .is_none_or(|ext| ext != "json")
            {
                continue;
            }
            out.push(
                DiscoveredSourceFile::new(
                    "opencode",
                    root,
                    part_entry.path().to_path_buf(),
                    DiscoveredSourceRole::MetadataSidecar,
                    true,
                )
                .with_fs_metadata(),
            );
        }
    }

    /// Extract sessions from OpenCode's SQLite database (v1.2+).
    ///
    /// Schema: session(id, title, directory, project_id, time_created, time_updated),
    ///         message(id, session_id, data JSON), part(id, message_id, session_id, data JSON)
    fn extract_from_sqlite(
        db_path: &Path,
        since_ts: Option<i64>,
        progress_tick: Option<&(dyn Fn() + Send + Sync)>,
    ) -> Result<Vec<NormalizedConversation>> {
        let conn = open_with_flags(
            db_path.to_string_lossy().as_ref(),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .with_context(|| format!("failed to open OpenCode db: {}", db_path.display()))?;

        conn.execute("PRAGMA busy_timeout = 5000;")
            .with_context(|| "failed to set busy_timeout")?;

        // Query all sessions. Read timestamps as raw SQLite values — Drizzle ORM may
        // store them as ISO text (YYYY-MM-DD HH:MM:SS) or epoch integers depending on config.
        // We normalize in Rust rather than using strftime() which breaks on integer columns.
        let sessions: Vec<SqliteSession> = conn
            .query_map_collect(
                "SELECT id, title, directory, project_id, time_created, time_updated FROM session",
                params![],
                |row| {
                    Ok(SqliteSession {
                        id: row.get_typed(0)?,
                        title: row.get_typed(1)?,
                        directory: row.get_typed(2)?,
                        project_id: row.get_typed(3)?,
                        time_created_raw: optional_sqlite_value(row, 4),
                        time_updated_raw: optional_sqlite_value(row, 5),
                    })
                },
            )
            .with_context(|| "failed to query OpenCode sessions")?;

        // #372: on an incremental scan, restrict the (expensive) message/part
        // decode to the sessions that could possibly clear the cutoff, instead
        // of decoding the whole DB and filtering afterwards. The predicate is
        // exactly the one the post-decode filter below applies via `ended_at`
        // (which prefers `session.time_updated`): keep a session iff its update
        // time is unknown — in which case the per-message time filter still
        // decides — or at/after the cutoff. Sessions whose known update time is
        // before the cutoff are dropped here without loading their messages or
        // parts, and the post-decode filter remains as a correctness backstop.
        let keep_session_ids: Option<HashSet<String>> = since_ts.map(|since| {
            sessions
                .iter()
                .filter(|session| {
                    session
                        .time_updated_raw
                        .as_ref()
                        .and_then(normalize_sqlite_ts_value)
                        .is_none_or(|updated| updated >= since)
                })
                .map(|session| session.id.clone())
                .collect()
        });

        let mut messages_by_session =
            Self::load_sqlite_messages_by_session(&conn, keep_session_ids.as_ref(), progress_tick)?;
        let mut convs = Vec::new();
        let mut seen_ids = HashSet::new();

        for (session_index, session) in sessions.into_iter().enumerate() {
            opencode_scan_tick(progress_tick, session_index);
            if !seen_ids.insert(session.id.clone()) {
                continue;
            }

            let messages = messages_by_session.remove(&session.id).unwrap_or_default();
            if messages.is_empty() {
                continue;
            }

            let msg_started_at = messages.iter().filter_map(|m| m.created_at).min();
            let msg_ended_at = messages.iter().filter_map(|m| m.created_at).max();

            let session_created_ms = session
                .time_created_raw
                .as_ref()
                .and_then(normalize_sqlite_ts_value);
            let session_updated_ms = session
                .time_updated_raw
                .as_ref()
                .and_then(normalize_sqlite_ts_value);

            let started_at = session_created_ms.or(msg_started_at);
            let ended_at = session_updated_ms.or(msg_ended_at).or(started_at);

            // Filter by since_ts in Rust (can't reliably filter in SQL when
            // timestamp column format is unknown). Sessions whose timestamps
            // are ALL unparseable must stay: pruning them on latest=0 would
            // drop them from every incremental scan forever (the flat-file
            // path guards this blind spot with mtimes; SQLite rows have no
            // such fallback). Only KNOWN-old sessions are pruned.
            if let Some(since) = since_ts
                && let Some(latest) = ended_at.or(started_at)
                && latest < since
            {
                continue;
            }

            let workspace = session.directory.map(PathBuf::from);
            let title = session.title.or_else(|| {
                messages
                    .first()
                    .and_then(|m| m.content.lines().next())
                    .map(|s| s.chars().take(100).collect())
            });

            convs.push(NormalizedConversation {
                agent_slug: "opencode".into(),
                external_id: Some(session.id.clone()),
                title,
                workspace,
                source_path: db_path.join(urlencoding::encode(&session.id).as_ref()),
                started_at,
                ended_at,
                metadata: serde_json::json!({
                    "session_id": session.id,
                    "project_id": session.project_id,
                    "source": "sqlite",
                }),
                messages,
            });
        }

        Ok(convs)
    }

    fn load_sqlite_messages_by_session(
        conn: &Connection,
        keep_session_ids: Option<&HashSet<String>>,
        progress_tick: Option<&(dyn Fn() + Send + Sync)>,
    ) -> Result<HashMap<String, Vec<NormalizedMessage>>> {
        // Load the message rows first (no ORDER BY — they are re-sorted per
        // session below), restricted to the kept sessions on an incremental
        // scan so old sessions' messages are never read or decoded (#372).
        let rows: Vec<SqliteMessageRow> = match keep_session_ids {
            None => conn.query_map_collect(
                "SELECT session_id, id, data, time_created FROM message",
                params![],
                |row| {
                    Ok(SqliteMessageRow {
                        session_id: row.get_typed(0)?,
                        id: row.get_typed(1)?,
                        data_json: row.get_typed(2)?,
                        time_created_raw: optional_sqlite_value(row, 3),
                    })
                },
            )?,
            Some(ids) => {
                let id_list: Vec<&String> = ids.iter().collect();
                let mut rows: Vec<SqliteMessageRow> = Vec::new();
                for chunk in id_list.chunks(OPENCODE_SQL_IN_CHUNK) {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!(
                        "SELECT session_id, id, data, time_created FROM message WHERE session_id IN ({placeholders})"
                    );
                    let bind: Vec<ParamValue> = chunk
                        .iter()
                        .map(|id| ParamValue::from(id.as_str()))
                        .collect();
                    rows.extend(conn.query_map_collect(&sql, &bind, |row| {
                        Ok(SqliteMessageRow {
                            session_id: row.get_typed(0)?,
                            id: row.get_typed(1)?,
                            data_json: row.get_typed(2)?,
                            time_created_raw: optional_sqlite_value(row, 3),
                        })
                    })?);
                }
                rows
            }
        };

        // Decode only the parts belonging to the messages we actually loaded.
        let kept_message_ids: Option<HashSet<String>> =
            keep_session_ids.map(|_| rows.iter().map(|row| row.id.clone()).collect());
        let mut parts_by_message =
            Self::load_sqlite_parts_by_message(conn, kept_message_ids.as_ref(), progress_tick)?;

        let mut pending_by_session: HashMap<String, Vec<PendingSqliteMessage>> = HashMap::new();

        for (row_index, row) in rows.into_iter().enumerate() {
            opencode_scan_tick(progress_tick, row_index);
            let msg_data: SqliteMessageData = match serde_json::from_str(&row.data_json) {
                Ok(d) => d,
                Err(e) => {
                    tracing::debug!(
                        "opencode sqlite: failed to parse message data for {}: {e}",
                        row.id
                    );
                    continue;
                }
            };

            let parts = parts_by_message.remove(&row.id).unwrap_or_default();
            let content_text = if !parts.is_empty() {
                assemble_content_from_parts(&parts)
            } else {
                String::new()
            };

            if content_text.trim().is_empty() {
                continue;
            }

            let role = msg_data.role.unwrap_or_else(|| "assistant".to_string());
            let col_ts = row
                .time_created_raw
                .as_ref()
                .and_then(normalize_sqlite_ts_value);
            let created_at =
                normalize_opencode_timestamp(msg_data.time.as_ref().and_then(|t| t.created))
                    .or(col_ts);

            let author = if role == "assistant" {
                msg_data.model_id.clone()
            } else {
                Some("user".to_string())
            };

            let message_id = row.id;
            let session_id = row.session_id;
            pending_by_session
                .entry(session_id.clone())
                .or_default()
                .push(PendingSqliteMessage {
                    created_at,
                    message_id: message_id.clone(),
                    message: NormalizedMessage {
                        idx: 0,
                        role,
                        author,
                        created_at,
                        content: content_text,
                        extra: serde_json::json!({
                            "message_id": message_id,
                            "session_id": session_id,
                        }),
                        invocations: Vec::new(),
                        snippets: Vec::new(),
                    },
                });
        }

        let mut messages_by_session = HashMap::new();
        for (session_id, mut pending) in pending_by_session {
            pending.sort_by(|a, b| {
                let a_ts = a.created_at.unwrap_or(i64::MAX);
                let b_ts = b.created_at.unwrap_or(i64::MAX);
                a_ts.cmp(&b_ts)
                    .then_with(|| a.message_id.cmp(&b.message_id))
            });
            let mut messages: Vec<NormalizedMessage> =
                pending.into_iter().map(|pending| pending.message).collect();
            crate::types::reindex_messages(&mut messages);
            messages_by_session.insert(session_id, messages);
        }

        Ok(messages_by_session)
    }

    fn load_sqlite_parts_by_message(
        conn: &Connection,
        message_ids: Option<&HashSet<String>>,
        progress_tick: Option<&(dyn Fn() + Send + Sync)>,
    ) -> Result<HashMap<String, Vec<PartInfo>>> {
        // No ORDER BY — parts are re-sorted per message below. On an incremental
        // scan only the kept messages' parts are read/decoded (#372: the `part`
        // table is the largest, so this is the dominant saving).
        let rows: Vec<(String, String)> = match message_ids {
            None => {
                conn.query_map_collect("SELECT message_id, data FROM part", params![], |row| {
                    Ok((row.get_typed(0)?, row.get_typed(1)?))
                })?
            }
            Some(ids) => {
                let id_list: Vec<&String> = ids.iter().collect();
                let mut rows: Vec<(String, String)> = Vec::new();
                for chunk in id_list.chunks(OPENCODE_SQL_IN_CHUNK) {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!(
                        "SELECT message_id, data FROM part WHERE message_id IN ({placeholders})"
                    );
                    let bind: Vec<ParamValue> = chunk
                        .iter()
                        .map(|id| ParamValue::from(id.as_str()))
                        .collect();
                    rows.extend(conn.query_map_collect(&sql, &bind, |row| {
                        Ok((row.get_typed(0)?, row.get_typed(1)?))
                    })?);
                }
                rows
            }
        };

        let mut parts_by_message: HashMap<String, Vec<PartInfo>> = HashMap::new();
        for (row_index, (message_id, row)) in rows.into_iter().enumerate() {
            opencode_scan_tick(progress_tick, row_index);
            match serde_json::from_str::<SqlitePartData>(&row) {
                Ok(part_data) => {
                    parts_by_message
                        .entry(message_id)
                        .or_default()
                        .push(PartInfo {
                            id: part_data.id,
                            index: part_data.index,
                            message_id: None,
                            part_type: part_data.part_type,
                            text: part_data.text,
                            state: part_data.state,
                        });
                }
                Err(e) => {
                    tracing::debug!("opencode sqlite: failed to parse part data: {e}");
                }
            }
        }

        for parts in parts_by_message.values_mut() {
            sort_parts_for_message(parts);
        }

        Ok(parts_by_message)
    }
}

struct SqliteMessageRow {
    session_id: String,
    id: String,
    data_json: String,
    time_created_raw: Option<SqliteValue>,
}

struct PendingSqliteMessage {
    created_at: Option<i64>,
    message_id: String,
    message: NormalizedMessage,
}

/// Session row from SQLite.
/// Timestamps are read as raw SQLite values because Drizzle ORM
/// may store them as TEXT (ISO 8601) or INTEGER (epoch seconds/ms).
struct SqliteSession {
    id: String,
    title: Option<String>,
    directory: Option<String>,
    project_id: Option<String>,
    time_created_raw: Option<SqliteValue>,
    time_updated_raw: Option<SqliteValue>,
}

/// Deserialized message.data JSON from SQLite.
#[derive(Debug, Deserialize)]
struct SqliteMessageData {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    time: Option<MessageTime>,
    #[serde(rename = "modelID", default)]
    model_id: Option<String>,
}

/// Deserialized part.data JSON from SQLite.
#[derive(Debug, Deserialize)]
struct SqlitePartData {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, alias = "order", alias = "sequence")]
    index: Option<i64>,
    #[serde(rename = "type", default)]
    part_type: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    state: Option<ToolState>,
}

// ============================================================================
// JSON Structures for OpenCode Storage (pre-v1.2 flat files)
// ============================================================================

/// Session info from session/{projectID}/{sessionID}.json
#[derive(Debug, Deserialize)]
struct SessionInfo {
    id: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    directory: Option<String>,
    #[serde(rename = "projectID", default)]
    project_id: Option<String>,
    #[serde(default)]
    time: Option<SessionTime>,
}

#[derive(Debug, Deserialize)]
struct SessionTime {
    #[serde(default)]
    created: Option<i64>,
    #[serde(default)]
    updated: Option<i64>,
}

/// Message info from message/{sessionID}/{messageID}.json
#[derive(Debug, Deserialize)]
struct MessageInfo {
    id: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    time: Option<MessageTime>,
    #[serde(rename = "modelID", default)]
    model_id: Option<String>,
    #[serde(rename = "sessionID", default)]
    session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MessageTime {
    #[serde(default)]
    created: Option<i64>,
    #[serde(default)]
    #[allow(dead_code)]
    completed: Option<i64>,
}

/// Part info from part/{messageID}/{partID}.json
#[derive(Debug, Clone, Deserialize)]
struct PartInfo {
    #[serde(default)]
    #[allow(dead_code)]
    id: Option<String>,
    #[serde(default, alias = "order", alias = "sequence")]
    index: Option<i64>,
    #[serde(rename = "messageID", default)]
    #[allow(dead_code)]
    message_id: Option<String>,
    #[serde(rename = "type", default)]
    part_type: Option<String>,
    #[serde(default)]
    text: Option<String>,
    // Tool state for tool parts
    #[serde(default)]
    state: Option<ToolState>,
}

#[derive(Debug, Clone, Deserialize)]
struct ToolState {
    #[serde(default)]
    output: Option<String>,
}

impl Connector for OpenCodeConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("opencode").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        let mut scanned_dbs: HashSet<PathBuf> = HashSet::new();

        // --- Phase 1: Try SQLite database(s) (v1.2+) ---
        // Collect candidate database paths in priority order:
        //   1. If ctx.data_dir looks like a path to `opencode.db` itself
        //      (has a `.db` extension), use it as-is.
        //   2. Otherwise, if ctx.data_dir is non-empty, treat it as a
        //      directory and check for `<data_dir>/opencode.db`.
        //   3. Always add the built-in default search list. This ensures
        //      we find the canonical XDG location even when explicit scan
        //      roots or a stale detection path were passed in (see issue #174).
        //
        // Non-existence of any candidate is filtered at iteration time
        // (`if !db.exists() { continue; }` below), so we do not gate the
        // `extension == "db"` branch on `.exists()` — otherwise a
        // user-supplied .db path that doesn't exist yet would silently
        // fall through to the "join opencode.db" branch and produce a
        // nonsense `/path/to/file.db/opencode.db` candidate.
        let mut db_candidates: Vec<PathBuf> = Vec::new();
        if ctx.data_dir.extension().is_some_and(|ext| ext == "db") {
            db_candidates.push(ctx.data_dir.clone());
        } else if !ctx.data_dir.as_os_str().is_empty() {
            db_candidates.push(ctx.data_dir.join("opencode.db"));
        }

        if !ctx.use_default_detection() {
            for scan_root in &ctx.scan_roots {
                Self::append_explicit_db_candidates(&mut db_candidates, &scan_root.path);
            }
        }

        if Self::allow_local_default_dbs(ctx) {
            db_candidates.extend(Self::sqlite_db_candidates());
        }

        // Deduplicate while preserving priority order.
        {
            let mut seen = HashSet::new();
            db_candidates.retain(|p| seen.insert(p.clone()));
        }

        // Session ids seen across ALL db candidates: stale migrated copies
        // (e.g. ~/.config/opencode/opencode.db left behind after a move to
        // ~/.local/share) share session ids with the live store, and
        // emitting both double-indexes every conversation. First-wins by
        // candidate priority order (explicit/data_dir before defaults).
        let mut seen_db_session_ids: HashSet<String> = HashSet::new();

        for db in db_candidates {
            if !db.is_file() {
                continue;
            }
            // Canonicalize if possible so two routes to the same file are
            // still deduplicated (e.g. via symlink or `./`-prefixed path).
            let canonical = std::fs::canonicalize(&db).unwrap_or_else(|_| db.clone());
            if !scanned_dbs.insert(canonical) {
                continue;
            }
            match Self::extract_from_sqlite(&db, ctx.since_ts, ctx.progress_tick.as_deref()) {
                Ok(sqlite_convs) => {
                    let fresh_count = sqlite_convs.len();
                    convs.extend(sqlite_convs.into_iter().filter(|conv| {
                        conv.external_id
                            .as_ref()
                            .is_none_or(|id| seen_db_session_ids.insert(id.clone()))
                    }));
                    tracing::debug!(
                        "opencode sqlite: found {fresh_count} sessions in {}",
                        db.display()
                    );
                }
                Err(e) => {
                    tracing::debug!("opencode sqlite: failed to read {}: {e}", db.display());
                }
            }
        }

        // Collect seen IDs from SQLite results to avoid duplicates with JSON
        let mut seen_ids: HashSet<String> =
            convs.iter().filter_map(|c| c.external_id.clone()).collect();

        // --- Phase 2: Fall back to JSON file storage (pre-v1.2) ---
        let mut storage_roots: Vec<PathBuf> = Vec::new();
        if ctx.use_default_detection() {
            if ctx.data_dir.exists() && looks_like_opencode_storage(&ctx.data_dir) {
                storage_roots.push(ctx.data_dir.clone());
            } else if let Some(root) = Self::storage_root() {
                storage_roots.push(root);
            }
        } else {
            if ctx.data_dir.exists() && looks_like_opencode_storage(&ctx.data_dir) {
                storage_roots.push(ctx.data_dir.clone());
            }
            for scan_root in &ctx.scan_roots {
                let mut candidates = vec![scan_root.path.clone()];
                Self::append_explicit_storage_candidates(&mut candidates, &scan_root.path);
                for candidate in candidates {
                    if candidate.exists() && looks_like_opencode_storage(&candidate) {
                        storage_roots.push(candidate);
                    }
                }
            }
        }

        if storage_roots.is_empty() {
            return Ok(convs);
        }

        storage_roots.sort();
        storage_roots.dedup();

        let mut seen_session_files: HashSet<PathBuf> = HashSet::new();

        for storage_root in storage_roots {
            let session_dir = storage_root.join("session");
            let message_dir = storage_root.join("message");
            let part_dir = storage_root.join("part");

            if !session_dir.exists() {
                continue;
            }

            // Collect all session files
            let session_files: Vec<PathBuf> = WalkDir::new(&session_dir)
                .into_iter()
                .flatten()
                .filter(|e| e.file_type().is_file())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "json")
                        .unwrap_or(false)
                })
                .map(|e| e.path().to_path_buf())
                .collect();

            for session_file in session_files {
                if !seen_session_files.insert(dedupe_path_key(&session_file)) {
                    continue;
                }
                if !session_has_updates(&session_file, &message_dir, &part_dir, ctx.since_ts) {
                    continue;
                }

                // Parse session
                let session = match parse_session_file(&session_file) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(
                            "opencode: failed to parse session {}: {e}",
                            session_file.display()
                        );
                        continue;
                    }
                };

                // Deduplicate by session ID
                if !seen_ids.insert(session.id.clone()) {
                    continue;
                }

                // Load messages for this session
                let session_msg_dir = message_dir.join(&session.id);
                let messages = if session_msg_dir.exists() {
                    load_messages(&session_msg_dir, &part_dir)?
                } else {
                    Vec::new()
                };

                if messages.is_empty() {
                    continue;
                }

                // Build normalized conversation
                let msg_started_at = messages.iter().filter_map(|m| m.created_at).min();
                let msg_ended_at = messages.iter().filter_map(|m| m.created_at).max();

                let started_at = session
                    .time
                    .as_ref()
                    .and_then(|t| normalize_opencode_timestamp(t.created))
                    .or(msg_started_at);
                let ended_at = session
                    .time
                    .as_ref()
                    .and_then(|t| normalize_opencode_timestamp(t.updated))
                    .or(msg_ended_at)
                    .or(started_at);

                let workspace = session.directory.map(PathBuf::from);
                let title = session.title.or_else(|| {
                    messages
                        .first()
                        .and_then(|m| m.content.lines().next())
                        .map(|s| s.chars().take(100).collect())
                });

                convs.push(NormalizedConversation {
                    agent_slug: "opencode".into(),
                    external_id: Some(session.id.clone()),
                    title,
                    workspace,
                    source_path: session_file.clone(),
                    started_at,
                    ended_at,
                    metadata: serde_json::json!({
                        "session_id": session.id,
                        "project_id": session.project_id,
                    }),
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

/// Check if a directory looks like OpenCode storage
fn looks_like_opencode_storage(path: &std::path::Path) -> bool {
    // Check for characteristic subdirectories.
    // We require 'session' and 'message' to be present to confirm this is an OpenCode storage root.
    // relying on the path name containing "opencode" is too loose and causes shadowing
    // if the CASS data directory has "opencode" in its name.
    path.join("session").exists() && path.join("message").exists()
}

fn normalize_opencode_timestamp(ts: Option<i64>) -> Option<i64> {
    ts.map(|raw| {
        // OpenCode appears to store epoch timestamps in milliseconds (see fixtures),
        // but some sources may emit epoch seconds. We treat "plausible epoch seconds"
        // as seconds and otherwise assume milliseconds (including small synthetic test values).
        if (1_000_000_000..10_000_000_000).contains(&raw) {
            raw.saturating_mul(1000)
        } else {
            raw
        }
    })
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
/// Drizzle ORM can store timestamps as:
///  - TEXT: ISO 8601 strings like `"2024-01-15 14:30:00"` or `"2024-01-15T14:30:00"`
///  - INTEGER: epoch seconds (e.g. `1700000000`) or epoch milliseconds (e.g. `1700000000000`)
///
/// Returns `None` for NULL or unparseable values.
fn normalize_sqlite_ts_value(val: &SqliteValue) -> Option<i64> {
    match val {
        SqliteValue::Integer(i) => normalize_opencode_timestamp(Some(*i)),
        SqliteValue::Float(f) => normalize_opencode_timestamp(Some(*f as i64)),
        SqliteValue::Text(s) => {
            // Try common SQLite/Drizzle datetime formats (space separator)
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
                Some(dt.and_utc().timestamp_millis())
            } else if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
            {
                Some(dt.and_utc().timestamp_millis())
            // ISO 8601 with T separator
            } else if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
                Some(dt.and_utc().timestamp_millis())
            } else if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
            {
                Some(dt.and_utc().timestamp_millis())
            // RFC 3339 with timezone (e.g. "2024-01-15T14:30:00Z")
            } else if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                Some(dt.timestamp_millis())
            } else {
                // Last resort: try parsing as integer string
                s.trim()
                    .parse::<i64>()
                    .ok()
                    .and_then(|i| normalize_opencode_timestamp(Some(i)))
            }
        }
        SqliteValue::Null | SqliteValue::Blob(_) => None,
    }
}

fn session_has_updates(
    session_file: &Path,
    message_root: &Path,
    part_root: &Path,
    since_ts: Option<i64>,
) -> bool {
    if since_ts.is_none() {
        return true;
    }

    if file_modified_since(session_file, since_ts) {
        return true;
    }

    let session_id = session_file
        .file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_string);
    let Some(session_id) = session_id else {
        return true;
    };

    let session_msg_dir = message_root.join(&session_id);
    if !session_msg_dir.exists() {
        return false;
    }

    let mut message_ids = Vec::new();
    if let Ok(entries) = fs::read_dir(&session_msg_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if path.extension().map(|ext| ext == "json").unwrap_or(false) {
                if file_modified_since(&path, since_ts) {
                    return true;
                }
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    message_ids.push(stem.to_string());
                }
            }
        }
    }

    for message_id in message_ids {
        let part_dir = part_root.join(&message_id);
        if !part_dir.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(&part_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if file_modified_since(&path, since_ts) {
                    return true;
                }
            }
        }
    }

    false
}

/// Parse a session JSON file
fn parse_session_file(path: &Path) -> Result<SessionInfo> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read session file {}", path.display()))?;
    // Editors/tools sometimes leave a UTF-8 BOM on flat-file sessions;
    // serde_json rejects a leading U+FEFF and the whole session would be
    // silently skipped (gemini's replay strips it for the same reason).
    let content = content.trim_start_matches('\u{feff}');
    let session: SessionInfo = serde_json::from_str(content)
        .with_context(|| format!("parse session JSON {}", path.display()))?;
    Ok(session)
}

/// Load all messages for a session
fn load_messages(session_msg_dir: &Path, part_dir: &Path) -> Result<Vec<NormalizedMessage>> {
    let mut pending: Vec<(Option<i64>, String, NormalizedMessage)> = Vec::new();

    // Find all message files for this session
    let msg_files: Vec<PathBuf> = WalkDir::new(session_msg_dir)
        .max_depth(1)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    for msg_file in msg_files {
        let content = match fs::read_to_string(&msg_file) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let msg_info: MessageInfo = match serde_json::from_str(&content) {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Load parts for this specific message
        let mut parts = Vec::new();
        let msg_part_dir = part_dir.join(&msg_info.id);

        if msg_part_dir.exists() {
            for entry in WalkDir::new(&msg_part_dir)
                .max_depth(1)
                .into_iter()
                .flatten()
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false)
                    && let Ok(content) = fs::read_to_string(path)
                    && let Ok(part) = serde_json::from_str::<PartInfo>(&content)
                {
                    parts.push(part);
                }
            }
        }
        sort_parts_for_message(&mut parts);

        // Assemble message content from parts
        let content_text = assemble_content_from_parts(&parts);
        if content_text.trim().is_empty() {
            continue;
        }

        // Determine role
        let role = msg_info
            .role
            .clone()
            .unwrap_or_else(|| "assistant".to_string());

        // Determine timestamp
        let created_at =
            normalize_opencode_timestamp(msg_info.time.as_ref().and_then(|t| t.created));

        // Author from model_id for assistant messages
        let author = if role == "assistant" {
            msg_info.model_id.clone()
        } else {
            Some("user".to_string())
        };

        let message_id = msg_info.id.clone();
        pending.push((
            created_at,
            message_id.clone(),
            NormalizedMessage {
                idx: 0, // Will be assigned later
                role,
                author,
                created_at,
                content: content_text,
                extra: serde_json::json!({
                    "message_id": message_id,
                    "session_id": msg_info.session_id,
                }),
                invocations: Vec::new(),
                snippets: Vec::new(),
            },
        ));
    }

    // Sort by timestamp, then by message id to ensure deterministic ordering.
    pending.sort_by(|a, b| {
        let a_ts = a.0.unwrap_or(i64::MAX);
        let b_ts = b.0.unwrap_or(i64::MAX);
        a_ts.cmp(&b_ts).then_with(|| a.1.cmp(&b.1))
    });
    let mut messages: Vec<NormalizedMessage> = pending.into_iter().map(|(_, _, msg)| msg).collect();
    crate::types::reindex_messages(&mut messages);

    Ok(messages)
}

fn sort_parts_for_message(parts: &mut [PartInfo]) {
    parts.sort_by(|a, b| {
        let a_idx = a.index.unwrap_or(i64::MAX);
        let b_idx = b.index.unwrap_or(i64::MAX);
        a_idx
            .cmp(&b_idx)
            .then_with(|| {
                a.id.as_deref()
                    .unwrap_or("")
                    .cmp(b.id.as_deref().unwrap_or(""))
            })
            .then_with(|| {
                a.part_type
                    .as_deref()
                    .unwrap_or("")
                    .cmp(b.part_type.as_deref().unwrap_or(""))
            })
            .then_with(|| {
                a.text
                    .as_deref()
                    .unwrap_or("")
                    .cmp(b.text.as_deref().unwrap_or(""))
            })
    });
}

/// Assemble message content from parts
fn assemble_content_from_parts(parts: &[PartInfo]) -> String {
    let mut content_pieces: Vec<String> = Vec::new();

    for part in parts {
        match part.part_type.as_deref() {
            Some("text") => {
                if let Some(text) = &part.text
                    && !text.trim().is_empty()
                {
                    content_pieces.push(text.clone());
                }
            }
            Some("tool") => {
                // Include tool output if available
                if let Some(state) = &part.state
                    && let Some(output) = &state.output
                    && !output.trim().is_empty()
                {
                    content_pieces.push(format!("[Tool Output]\n{}", output));
                }
            }
            Some("reasoning") => {
                if let Some(text) = &part.text
                    && !text.trim().is_empty()
                {
                    content_pieces.push(format!("[Reasoning]\n{}", text));
                }
            }
            Some("patch") => {
                if let Some(text) = &part.text
                    && !text.trim().is_empty()
                {
                    content_pieces.push(format!("[Patch]\n{}", text));
                }
            }
            // Ignore step-start, step-finish, and other control parts
            _ => {}
        }
    }

    content_pieces.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn open_test_connection(path: &Path) -> Connection {
        Connection::open(path.to_string_lossy().as_ref()).unwrap()
    }

    // =====================================================
    // Constructor Tests
    // =====================================================

    #[test]
    fn new_creates_connector() {
        let connector = OpenCodeConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = OpenCodeConnector;
        let _ = connector;
    }

    // =====================================================
    // looks_like_opencode_storage() Tests
    // =====================================================

    #[test]
    fn looks_like_opencode_storage_requires_subdirs() {
        let dir = TempDir::new().unwrap();
        let opencode_path = dir.path().join("opencode").join("test");
        fs::create_dir_all(&opencode_path).unwrap();

        // Name alone should NOT be enough (prevents shadowing)
        assert!(!looks_like_opencode_storage(&opencode_path));

        // Adding subdirs makes it valid
        fs::create_dir_all(opencode_path.join("session")).unwrap();
        fs::create_dir_all(opencode_path.join("message")).unwrap();
        assert!(looks_like_opencode_storage(&opencode_path));
    }

    #[test]
    fn looks_like_opencode_storage_with_session_dir() {
        let dir = TempDir::new().unwrap();
        // Requires both session AND message subdirs
        fs::create_dir_all(dir.path().join("session")).unwrap();
        assert!(!looks_like_opencode_storage(dir.path()));
        fs::create_dir_all(dir.path().join("message")).unwrap();
        assert!(looks_like_opencode_storage(dir.path()));
    }

    #[test]
    fn looks_like_opencode_storage_with_message_dir() {
        let dir = TempDir::new().unwrap();
        // Requires both session AND message subdirs
        fs::create_dir_all(dir.path().join("message")).unwrap();
        assert!(!looks_like_opencode_storage(dir.path()));
        fs::create_dir_all(dir.path().join("session")).unwrap();
        assert!(looks_like_opencode_storage(dir.path()));
    }

    #[test]
    fn looks_like_opencode_storage_with_part_dir() {
        let dir = TempDir::new().unwrap();
        // part alone is not enough; need session + message
        fs::create_dir_all(dir.path().join("part")).unwrap();
        assert!(!looks_like_opencode_storage(dir.path()));
        fs::create_dir_all(dir.path().join("session")).unwrap();
        fs::create_dir_all(dir.path().join("message")).unwrap();
        assert!(looks_like_opencode_storage(dir.path()));
    }

    #[test]
    fn looks_like_opencode_storage_returns_false_for_random_dir() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("random")).unwrap();
        assert!(!looks_like_opencode_storage(dir.path()));
    }

    // =====================================================
    // session_has_updates() Tests
    // =====================================================

    #[test]
    fn session_has_updates_detects_message_file_change() {
        let dir = TempDir::new().unwrap();
        let storage = dir.path();
        let session_dir = storage.join("session/proj");
        let message_dir = storage.join("message/session-1");
        let part_dir = storage.join("part");
        fs::create_dir_all(&session_dir).unwrap();
        fs::create_dir_all(&message_dir).unwrap();
        fs::create_dir_all(&part_dir).unwrap();

        let session_file = session_dir.join("session-1.json");
        fs::write(&session_file, r#"{"id":"session-1"}"#).unwrap();

        let message_file = message_dir.join("msg-1.json");
        fs::write(&message_file, r#"{"id":"msg-1","role":"user"}"#).unwrap();

        let since_ts = file_mtime_ms(&message_file);

        let updated_message_file = message_dir.join("msg-2.json");
        fs::write(&updated_message_file, r#"{"id":"msg-2","role":"user"}"#).unwrap();

        assert!(session_has_updates(
            &session_file,
            &storage.join("message"),
            &storage.join("part"),
            Some(since_ts)
        ));
    }

    #[test]
    fn session_has_updates_detects_part_file_change() {
        let dir = TempDir::new().unwrap();
        let storage = dir.path();
        let session_dir = storage.join("session/proj");
        let message_dir = storage.join("message/session-1");
        let part_dir = storage.join("part");
        fs::create_dir_all(&session_dir).unwrap();
        fs::create_dir_all(&message_dir).unwrap();
        fs::create_dir_all(&part_dir).unwrap();

        let session_file = session_dir.join("session-1.json");
        fs::write(&session_file, r#"{"id":"session-1"}"#).unwrap();

        let message_file = message_dir.join("msg-1.json");
        fs::write(&message_file, r#"{"id":"msg-1","role":"assistant"}"#).unwrap();

        let since_ts = file_mtime_ms(&message_file);

        let part_dir_for_message = part_dir.join("msg-1");
        fs::create_dir_all(&part_dir_for_message).unwrap();
        fs::write(part_dir_for_message.join("part-1.json"), r#"{"text":"hi"}"#).unwrap();

        assert!(session_has_updates(
            &session_file,
            &storage.join("message"),
            &storage.join("part"),
            Some(since_ts)
        ));
    }

    fn file_mtime_ms(path: &Path) -> i64 {
        std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    // =====================================================
    // assemble_content_from_parts() Tests
    // =====================================================

    #[test]
    fn assemble_content_from_text_parts() {
        let parts = vec![
            PartInfo {
                id: Some("p1".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("Hello, world!".into()),
                state: None,
            },
            PartInfo {
                id: Some("p2".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("Second part".into()),
                state: None,
            },
        ];
        let content = assemble_content_from_parts(&parts);
        assert!(content.contains("Hello, world!"));
        assert!(content.contains("Second part"));
    }

    #[test]
    fn assemble_content_from_tool_parts() {
        let parts = vec![PartInfo {
            id: Some("p1".into()),
            index: None,
            message_id: Some("m1".into()),
            part_type: Some("tool".into()),
            text: None,
            state: Some(ToolState {
                output: Some("Tool executed successfully".into()),
            }),
        }];
        let content = assemble_content_from_parts(&parts);
        assert!(content.contains("[Tool Output]"));
        assert!(content.contains("Tool executed successfully"));
    }

    #[test]
    fn assemble_content_from_reasoning_parts() {
        let parts = vec![PartInfo {
            id: Some("p1".into()),
            index: None,
            message_id: Some("m1".into()),
            part_type: Some("reasoning".into()),
            text: Some("Let me think about this...".into()),
            state: None,
        }];
        let content = assemble_content_from_parts(&parts);
        assert!(content.contains("[Reasoning]"));
        assert!(content.contains("Let me think about this..."));
    }

    #[test]
    fn assemble_content_from_patch_parts() {
        let parts = vec![PartInfo {
            id: Some("p1".into()),
            index: None,
            message_id: Some("m1".into()),
            part_type: Some("patch".into()),
            text: Some("@@ -1,3 +1,4 @@".into()),
            state: None,
        }];
        let content = assemble_content_from_parts(&parts);
        assert!(content.contains("[Patch]"));
        assert!(content.contains("@@ -1,3 +1,4 @@"));
    }

    #[test]
    fn assemble_content_skips_empty_text() {
        let parts = vec![
            PartInfo {
                id: Some("p1".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("".into()),
                state: None,
            },
            PartInfo {
                id: Some("p2".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("   ".into()),
                state: None,
            },
            PartInfo {
                id: Some("p3".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("Actual content".into()),
                state: None,
            },
        ];
        let content = assemble_content_from_parts(&parts);
        assert_eq!(content, "Actual content");
    }

    #[test]
    fn assemble_content_skips_unknown_part_types() {
        let parts = vec![
            PartInfo {
                id: Some("p1".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("step-start".into()),
                text: Some("Starting...".into()),
                state: None,
            },
            PartInfo {
                id: Some("p2".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("step-finish".into()),
                text: Some("Done".into()),
                state: None,
            },
        ];
        let content = assemble_content_from_parts(&parts);
        assert!(content.is_empty());
    }

    #[test]
    fn assemble_content_mixed_parts() {
        let parts = vec![
            PartInfo {
                id: Some("p1".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("Here's my analysis:".into()),
                state: None,
            },
            PartInfo {
                id: Some("p2".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("reasoning".into()),
                text: Some("Thinking...".into()),
                state: None,
            },
            PartInfo {
                id: Some("p3".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("tool".into()),
                text: None,
                state: Some(ToolState {
                    output: Some("Result: 42".into()),
                }),
            },
        ];
        let content = assemble_content_from_parts(&parts);
        assert!(content.contains("Here's my analysis:"));
        assert!(content.contains("[Reasoning]"));
        assert!(content.contains("[Tool Output]"));
    }

    #[test]
    fn sort_parts_for_message_orders_by_index_then_id() {
        let mut parts = vec![
            PartInfo {
                id: Some("b".into()),
                index: Some(2),
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("second".into()),
                state: None,
            },
            PartInfo {
                id: Some("a".into()),
                index: Some(1),
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("first".into()),
                state: None,
            },
        ];

        sort_parts_for_message(&mut parts);
        assert_eq!(parts[0].text.as_deref(), Some("first"));
        assert_eq!(parts[1].text.as_deref(), Some("second"));
    }

    // =====================================================
    // Helper: Create OpenCode storage structure
    // =====================================================

    fn create_opencode_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join("opencode").join("storage");
        fs::create_dir_all(storage.join("session")).unwrap();
        fs::create_dir_all(storage.join("message")).unwrap();
        fs::create_dir_all(storage.join("part")).unwrap();
        storage
    }

    fn write_session(storage: &Path, project_id: &str, session: &serde_json::Value) {
        let session_id = session["id"].as_str().unwrap();
        let session_dir = storage.join("session").join(project_id);
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(
            session_dir.join(format!("{session_id}.json")),
            session.to_string(),
        )
        .unwrap();
    }

    fn write_message(storage: &Path, session_id: &str, message: &serde_json::Value) {
        let message_id = message["id"].as_str().unwrap();
        let message_dir = storage.join("message").join(session_id);
        fs::create_dir_all(&message_dir).unwrap();
        fs::write(
            message_dir.join(format!("{message_id}.json")),
            message.to_string(),
        )
        .unwrap();
    }

    fn write_part(storage: &Path, message_id: &str, part: &serde_json::Value) {
        let part_id = part["id"].as_str().unwrap();
        let part_dir = storage.join("part").join(message_id);
        fs::create_dir_all(&part_dir).unwrap();
        fs::write(part_dir.join(format!("{part_id}.json")), part.to_string()).unwrap();
    }

    // =====================================================
    // scan() Tests
    // =====================================================

    #[test]
    fn scan_parses_simple_conversation() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        // Create session
        let session = json!({
            "id": "sess-001",
            "title": "Test Session",
            "directory": "/home/user/project",
            "projectID": "proj-001",
            "time": {
                "created": 1733000000,
                "updated": 1733000100
            }
        });
        write_session(&storage, "proj-001", &session);

        // Create message
        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "sess-001",
            "time": {
                "created": 1733000000,
                "completed": 1733000001
            }
        });
        write_message(&storage, "sess-001", &message);

        // Create part
        let part = json!({
            "id": "part-001",
            "messageID": "msg-001",
            "type": "text",
            "text": "Hello, OpenCode!"
        });
        write_part(&storage, "msg-001", &part);

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].title, Some("Test Session".to_string()));
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/project"))
        );
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].role, "user");
        assert!(convs[0].messages[0].content.contains("Hello, OpenCode!"));
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn scan_with_opencode_root_scan_root() {
        use crate::connectors::scan::ScanRoot;

        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-001",
            "title": "Explicit Root",
            "directory": "/home/user/project",
            "projectID": "proj-001",
            "time": {
                "created": 1733000000,
                "updated": 1733000100
            }
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "sess-001",
            "time": {
                "created": 1733000000,
                "completed": 1733000001
            }
        });
        write_message(&storage, "sess-001", &message);

        let part = json!({
            "id": "part-001",
            "messageID": "msg-001",
            "type": "text",
            "text": "Hello explicit root!"
        });
        write_part(&storage, "msg-001", &part);

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::with_roots(
            PathBuf::new(),
            vec![ScanRoot::local(dir.path().join("opencode"))],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-001"));
    }

    #[test]
    fn scan_parses_multiple_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-002",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        // User message
        let user_msg = json!({
            "id": "msg-u1",
            "role": "user",
            "sessionID": "sess-002",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-002", &user_msg);
        write_part(
            &storage,
            "msg-u1",
            &json!({
                "id": "p1",
                "messageID": "msg-u1",
                "type": "text",
                "text": "What is 2+2?"
            }),
        );

        // Assistant message
        let assistant_msg = json!({
            "id": "msg-a1",
            "role": "assistant",
            "sessionID": "sess-002",
            "modelID": "gpt-4",
            "time": {"created": 1733000001}
        });
        write_message(&storage, "sess-002", &assistant_msg);
        write_part(
            &storage,
            "msg-a1",
            &json!({
                "id": "p2",
                "messageID": "msg-a1",
                "type": "text",
                "text": "2 + 2 = 4"
            }),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert_eq!(convs[0].messages[1].author, Some("gpt-4".to_string()));
    }

    #[test]
    fn scan_handles_empty_storage() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_sessions_without_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-empty",
            "title": "Empty Session",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);
        // Don't create any messages

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_extracts_title_from_first_message_if_no_session_title() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-no-title",
            "projectID": "proj-001"
            // No title field
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "sess-no-title",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-no-title", &message);
        write_part(
            &storage,
            "msg-001",
            &json!({
                "id": "p1",
                "messageID": "msg-001",
                "type": "text",
                "text": "This is the first line\nSecond line\nThird line"
            }),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("This is the first line".to_string()));
    }

    #[test]
    fn scan_sets_agent_slug_to_opencode() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-slug",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "sess-slug",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-slug", &message);
        write_part(
            &storage,
            "msg-001",
            &json!({"id": "p1", "messageID": "msg-001", "type": "text", "text": "Test"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].agent_slug, "opencode");
    }

    #[test]
    fn scan_sets_metadata_with_session_and_project_id() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-meta",
            "projectID": "proj-meta-001"
        });
        write_session(&storage, "proj-meta-001", &session);

        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "sess-meta",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-meta", &message);
        write_part(
            &storage,
            "msg-001",
            &json!({"id": "p1", "messageID": "msg-001", "type": "text", "text": "Test"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["session_id"], "sess-meta");
        assert_eq!(convs[0].metadata["project_id"], "proj-meta-001");
    }

    #[test]
    fn scan_sorts_messages_by_timestamp() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-sort",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        // Create messages out of order
        let msg_later = json!({
            "id": "msg-later",
            "role": "assistant",
            "sessionID": "sess-sort",
            "time": {"created": 1733000100}
        });
        let msg_earlier = json!({
            "id": "msg-earlier",
            "role": "user",
            "sessionID": "sess-sort",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-sort", &msg_later);
        write_message(&storage, "sess-sort", &msg_earlier);

        write_part(
            &storage,
            "msg-later",
            &json!({"id": "p1", "messageID": "msg-later", "type": "text", "text": "Later"}),
        );
        write_part(
            &storage,
            "msg-earlier",
            &json!({"id": "p2", "messageID": "msg-earlier", "type": "text", "text": "Earlier"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages.len(), 2);
        // Earlier message should be first due to sorting
        assert!(convs[0].messages[0].content.contains("Earlier"));
        assert!(convs[0].messages[1].content.contains("Later"));
    }

    #[test]
    fn scan_assigns_sequential_indices() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-idx",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        for i in 0..3 {
            let msg = json!({
                "id": format!("msg-{i}"),
                "role": "user",
                "sessionID": "sess-idx",
                "time": {"created": 1733000000 + i}
            });
            write_message(&storage, "sess-idx", &msg);
            write_part(
                &storage,
                &format!("msg-{i}"),
                &json!({
                    "id": format!("p{i}"),
                    "messageID": format!("msg-{i}"),
                    "type": "text",
                    "text": format!("Message {i}")
                }),
            );
        }

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].idx, 0);
        assert_eq!(convs[0].messages[1].idx, 1);
        assert_eq!(convs[0].messages[2].idx, 2);
    }

    #[test]
    fn scan_handles_messages_without_parts() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-no-parts",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-no-parts",
            "role": "user",
            "sessionID": "sess-no-parts",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-no-parts", &message);
        // Don't create any parts

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Session should be skipped because message has no content
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_deduplicates_sessions_by_id() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        // Create same session in two project directories
        let session = json!({
            "id": "sess-dupe",
            "title": "Duplicate Session",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);
        write_session(&storage, "proj-002", &session);

        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "sess-dupe",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-dupe", &message);
        write_part(
            &storage,
            "msg-001",
            &json!({"id": "p1", "messageID": "msg-001", "type": "text", "text": "Test"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should only have one conversation (deduplicated)
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn scan_uses_default_role_when_missing() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-no-role",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        // Message without role field
        let message = json!({
            "id": "msg-no-role",
            "sessionID": "sess-no-role",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-no-role", &message);
        write_part(
            &storage,
            "msg-no-role",
            &json!({"id": "p1", "messageID": "msg-no-role", "type": "text", "text": "Test"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Default role should be "assistant"
        assert_eq!(convs[0].messages[0].role, "assistant");
    }

    #[test]
    fn scan_handles_multiple_parts_per_message() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-multi-part",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-multi",
            "role": "assistant",
            "sessionID": "sess-multi-part",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-multi-part", &message);

        // Multiple parts for one message
        write_part(
            &storage,
            "msg-multi",
            &json!({"id": "p1", "messageID": "msg-multi", "type": "text", "text": "First part"}),
        );
        write_part(
            &storage,
            "msg-multi",
            &json!({"id": "p2", "messageID": "msg-multi", "type": "reasoning", "text": "Reasoning part"}),
        );
        write_part(
            &storage,
            "msg-multi",
            &json!({"id": "p3", "messageID": "msg-multi", "type": "text", "text": "Third part"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        let content = &convs[0].messages[0].content;
        assert!(content.contains("First part"));
        assert!(content.contains("[Reasoning]"));
        assert!(content.contains("Third part"));
    }

    #[test]
    fn scan_extracts_timestamps() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-ts",
            "projectID": "proj-001",
            "time": {
                "created": 1733000000,
                "updated": 1733000200
            }
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-ts",
            "role": "user",
            "sessionID": "sess-ts",
            "time": {"created": 1733000050}
        });
        write_message(&storage, "sess-ts", &message);
        write_part(
            &storage,
            "msg-ts",
            &json!({"id": "p1", "messageID": "msg-ts", "type": "text", "text": "Test"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].started_at, Some(1_733_000_000_000));
        assert_eq!(convs[0].ended_at, Some(1_733_000_200_000));
        assert_eq!(convs[0].messages[0].created_at, Some(1_733_000_050_000));
    }

    #[test]
    fn scan_uses_external_id_from_session_id() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "unique-session-id-123",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "unique-session-id-123",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "unique-session-id-123", &message);
        write_part(
            &storage,
            "msg-001",
            &json!({"id": "p1", "messageID": "msg-001", "type": "text", "text": "Test"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].external_id,
            Some("unique-session-id-123".to_string())
        );
    }

    #[test]
    fn scan_skips_invalid_session_json() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        // Create invalid session file
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(session_dir.join("invalid.json"), "not valid json").unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_invalid_message_json() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-invalid-msg",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        // Create invalid message file
        let msg_dir = storage.join("message").join("sess-invalid-msg");
        fs::create_dir_all(&msg_dir).unwrap();
        fs::write(msg_dir.join("bad.json"), "not valid json").unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should skip the session because no valid messages
        assert_eq!(convs.len(), 0);
    }

    // =====================================================
    // parse_session_file() Tests
    // =====================================================

    #[test]
    fn parse_session_file_parses_complete_session() {
        let dir = TempDir::new().unwrap();
        let session = json!({
            "id": "sess-parse",
            "title": "Parse Test",
            "directory": "/test/dir",
            "projectID": "proj-parse",
            "time": {
                "created": 1733000000,
                "updated": 1733000100
            }
        });
        let path = dir.path().join("session.json");
        fs::write(&path, session.to_string()).unwrap();

        let result = parse_session_file(&path).unwrap();
        assert_eq!(result.id, "sess-parse");
        assert_eq!(result.title, Some("Parse Test".to_string()));
        assert_eq!(result.directory, Some("/test/dir".to_string()));
        assert_eq!(result.project_id, Some("proj-parse".to_string()));
        assert!(result.time.is_some());
    }

    #[test]
    fn parse_session_file_handles_minimal_session() {
        let dir = TempDir::new().unwrap();
        let session = json!({"id": "minimal"});
        let path = dir.path().join("minimal.json");
        fs::write(&path, session.to_string()).unwrap();

        let result = parse_session_file(&path).unwrap();
        assert_eq!(result.id, "minimal");
        assert!(result.title.is_none());
        assert!(result.directory.is_none());
    }

    // =========================================================================
    // Edge case tests — malformed input robustness (br-2w98)
    // =========================================================================

    #[test]
    fn edge_empty_session_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(session_dir.join("sess-empty.json"), "").unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_whitespace_only_session_file_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(session_dir.join("sess-ws.json"), "   \n\t  ").unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_truncated_session_json_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(
            session_dir.join("sess-trunc.json"),
            r#"{"id": "sess-trunc", "title": "Trun"#,
        )
        .unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_invalid_utf8_session_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(
            session_dir.join("sess-bad-utf8.json"),
            b"\xff\xfe{\"id\":\"bad\"}",
        )
        .unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_bom_marker_at_session_file_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();

        let mut data = vec![0xEF, 0xBB, 0xBF];
        data.extend_from_slice(br#"{"id":"sess-bom","projectID":"proj-001"}"#);
        std::fs::write(session_dir.join("sess-bom.json"), &data).unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        // BOM may cause parse failure; connector should skip gracefully
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.len() <= 1);
    }

    #[test]
    fn edge_json_type_mismatch_in_session_file() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();
        // id should be a string, give it a number
        fs::write(session_dir.join("sess-bad.json"), r#"{"id": 12345}"#).unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // Should skip since id is not a string (serde will fail)
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_deeply_nested_part_json() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-deep", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-deep",
            "role": "user",
            "sessionID": "sess-deep",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-deep", &message);

        // Create a part with deeply nested extra data
        let mut nested = String::from(
            r#"{"id":"p-deep","messageID":"msg-deep","type":"text","text":"deep test","extra":"#,
        );
        for _ in 0..200 {
            nested.push_str(r#"{"a":"#);
        }
        nested.push_str(r#""leaf""#);
        for _ in 0..200 {
            nested.push('}');
        }
        nested.push('}');
        let part_dir = storage.join("part").join("msg-deep");
        fs::create_dir_all(&part_dir).unwrap();
        fs::write(part_dir.join("p-deep.json"), &nested).unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        // Should not stack overflow
        let result = connector.scan(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn edge_large_part_text_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-large", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-large",
            "role": "user",
            "sessionID": "sess-large",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-large", &message);

        let large_text = "x".repeat(1_000_000);
        write_part(
            &storage,
            "msg-large",
            &json!({"id": "p-large", "messageID": "msg-large", "type": "text", "text": large_text}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.len() >= 1_000_000);
    }

    #[test]
    fn edge_null_bytes_in_part_content() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-null", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-null",
            "role": "user",
            "sessionID": "sess-null",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-null", &message);

        write_part(
            &storage,
            "msg-null",
            &json!({"id": "p-null", "messageID": "msg-null", "type": "text", "text": "hello\u{0000}world"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("hello"));
    }

    #[test]
    fn edge_whitespace_only_part_text_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-ws-part", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-ws",
            "role": "assistant",
            "sessionID": "sess-ws-part",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-ws-part", &message);

        // Part with only whitespace text
        write_part(
            &storage,
            "msg-ws",
            &json!({"id": "p-ws", "messageID": "msg-ws", "type": "text", "text": "   \n\t  "}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // Message with only whitespace content should be skipped
        assert_eq!(convs.len(), 0);
    }

    // ---- OpenCode-specific edge cases ----

    #[test]
    fn edge_corrupted_message_file_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-corrupt", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        // Write a valid message and a corrupted one
        let valid_msg = json!({
            "id": "msg-valid",
            "role": "user",
            "sessionID": "sess-corrupt",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-corrupt", &valid_msg);
        write_part(
            &storage,
            "msg-valid",
            &json!({"id": "p1", "messageID": "msg-valid", "type": "text", "text": "Valid message"}),
        );

        // Corrupted message file
        let msg_dir = storage.join("message").join("sess-corrupt");
        fs::write(msg_dir.join("msg-corrupt.json"), "{{{{not json").unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // Valid message should still be parsed; corrupted one skipped
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert!(convs[0].messages[0].content.contains("Valid message"));
    }

    #[test]
    fn edge_missing_part_directory_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-nopart", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-nopartdir",
            "role": "user",
            "sessionID": "sess-nopart",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-nopart", &message);
        // Don't create part directory at all (not even the part/msg-nopartdir/ dir)

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // Message without parts should be skipped (empty content)
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_part_with_no_type_field_ignored() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-notype", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-notype",
            "role": "assistant",
            "sessionID": "sess-notype",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-notype", &message);

        // Part without "type" field (falls through to _ => {} in match)
        write_part(
            &storage,
            "msg-notype",
            &json!({"id": "p-notype", "messageID": "msg-notype", "text": "No type field"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // Part without type is ignored, message has no content, so session skipped
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_part_ordering_preserves_index_order() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-order", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-order",
            "role": "assistant",
            "sessionID": "sess-order",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-order", &message);

        // Parts with explicit indices out of order
        write_part(
            &storage,
            "msg-order",
            &json!({"id": "p-c", "messageID": "msg-order", "type": "text", "text": "Third", "index": 3}),
        );
        write_part(
            &storage,
            "msg-order",
            &json!({"id": "p-a", "messageID": "msg-order", "type": "text", "text": "First", "index": 1}),
        );
        write_part(
            &storage,
            "msg-order",
            &json!({"id": "p-b", "messageID": "msg-order", "type": "text", "text": "Second", "index": 2}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        let content = &convs[0].messages[0].content;
        // Verify order: First before Second before Third
        let first_pos = content.find("First").unwrap();
        let second_pos = content.find("Second").unwrap();
        let third_pos = content.find("Third").unwrap();
        assert!(first_pos < second_pos);
        assert!(second_pos < third_pos);
    }

    #[test]
    fn edge_session_ended_at_uses_latest_available_message_timestamp() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        // Session with no explicit time metadata
        let session = json!({"id": "sess-mixed-ts", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        // Message with timestamp
        let timed_message = json!({
            "id": "msg-timed",
            "role": "user",
            "sessionID": "sess-mixed-ts",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-mixed-ts", &timed_message);
        write_part(
            &storage,
            "msg-timed",
            &json!({"id": "p-timed", "messageID": "msg-timed", "type": "text", "text": "Timestamped"}),
        );

        // Later message without timestamp (sorts after timestamped messages)
        let untimed_message = json!({
            "id": "msg-untimed",
            "role": "assistant",
            "sessionID": "sess-mixed-ts"
        });
        write_message(&storage, "sess-mixed-ts", &untimed_message);
        write_part(
            &storage,
            "msg-untimed",
            &json!({"id": "p-untimed", "messageID": "msg-untimed", "type": "text", "text": "No timestamp"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].started_at, Some(1_733_000_000_000));
        assert_eq!(convs[0].ended_at, Some(1_733_000_000_000));
        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn edge_session_ended_at_falls_back_to_started_at_when_updated_missing() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        // Session has created time but no updated time
        let session = json!({
            "id": "sess-created-only",
            "projectID": "proj-001",
            "time": {"created": 1733000500}
        });
        write_session(&storage, "proj-001", &session);

        // Message has no timestamp
        let message = json!({
            "id": "msg-no-time",
            "role": "user",
            "sessionID": "sess-created-only"
        });
        write_message(&storage, "sess-created-only", &message);
        write_part(
            &storage,
            "msg-no-time",
            &json!({"id": "p-no-time", "messageID": "msg-no-time", "type": "text", "text": "Only session created time"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].started_at, Some(1_733_000_500_000));
        assert_eq!(convs[0].ended_at, Some(1_733_000_500_000));
    }

    #[test]
    fn edge_session_without_time_field() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        // Session with no time field at all
        let session = json!({"id": "sess-notime", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-notime",
            "role": "user",
            "sessionID": "sess-notime"
            // No time field
        });
        write_message(&storage, "sess-notime", &message);
        write_part(
            &storage,
            "msg-notime",
            &json!({"id": "p1", "messageID": "msg-notime", "type": "text", "text": "No timestamps"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        // Timestamps should be None
        assert!(convs[0].started_at.is_none());
        assert!(convs[0].ended_at.is_none());
    }

    // =====================================================
    // SQLite Extraction Tests (v1.2+)
    // =====================================================

    /// Create a test SQLite database with the OpenCode v1.2+ schema.
    fn create_test_sqlite_db(dir: &Path) -> PathBuf {
        let db_path = dir.join("opencode.db");
        let conn = open_test_connection(&db_path);

        conn.execute_batch(
            "CREATE TABLE session (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                title TEXT,
                directory TEXT,
                time_created TEXT DEFAULT CURRENT_TIMESTAMP,
                time_updated TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE message (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                data TEXT NOT NULL,
                time_created TEXT DEFAULT CURRENT_TIMESTAMP,
                time_updated TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE part (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                data TEXT NOT NULL,
                time_created TEXT DEFAULT CURRENT_TIMESTAMP,
                time_updated TEXT DEFAULT CURRENT_TIMESTAMP
            );",
        )
        .unwrap();

        db_path
    }

    #[test]
    fn sqlite_extract_simple_session() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        conn.execute_compat(
            "INSERT INTO session (id, project_id, title, directory) VALUES (?1, ?2, ?3, ?4)",
            params!["sess-1", "proj-1", "Test Session", "/home/user/project"],
        )
        .unwrap();

        conn.execute_compat(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-1",
                "sess-1",
                r#"{"role":"user","time":{"created":1700000000000}}"#,
            ],
        )
        .unwrap();

        conn.execute_compat(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-1",
                "msg-1",
                "sess-1",
                r#"{"type":"text","text":"Hello world"}"#,
            ],
        )
        .unwrap();

        conn.execute_compat(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-2",
                "sess-1",
                r#"{"role":"assistant","time":{"created":1700000001000},"modelID":"claude-3"}"#,
            ],
        )
        .unwrap();

        conn.execute_compat(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-2",
                "msg-2",
                "sess-1",
                r#"{"type":"text","text":"Hi there!"}"#,
            ],
        )
        .unwrap();

        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None, None).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-1"));
        assert_eq!(convs[0].title.as_deref(), Some("Test Session"));
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello world");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert_eq!(convs[0].messages[1].content, "Hi there!");
        assert_eq!(convs[0].messages[1].author.as_deref(), Some("claude-3"));
    }

    #[test]
    fn sqlite_extract_incremental_skips_old_sessions_without_dropping_new() {
        use std::collections::HashSet;
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        let insert = |sid: &str, updated_ms: Option<i64>, msg_created_ms: i64, text: &str| {
            match updated_ms {
                Some(u) => conn
                    .execute_compat(
                        "INSERT INTO session (id, title, time_updated) VALUES (?1, ?2, ?3)",
                        params![sid, sid, u],
                    )
                    .unwrap(),
                None => conn
                    .execute_compat(
                        "INSERT INTO session (id, title, time_updated) VALUES (?1, ?2, NULL)",
                        params![sid, sid],
                    )
                    .unwrap(),
            };
            conn.execute_compat(
                "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
                params![
                    format!("{sid}-m"),
                    sid,
                    format!(r#"{{"role":"user","time":{{"created":{msg_created_ms}}}}}"#)
                ],
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
                params![
                    format!("{sid}-p"),
                    format!("{sid}-m"),
                    sid,
                    format!(r#"{{"type":"text","text":"{text}"}}"#)
                ],
            )
            .unwrap();
        };

        let old_ms = 1_700_000_000_000_i64;
        let new_ms = 1_700_000_900_000_i64;
        let cutoff = 1_700_000_500_000_i64;

        insert("old", Some(old_ms), old_ms, "old content");
        insert("new", Some(new_ms), new_ms, "new content");
        // No session time -> the keep filter must fall through to the per-message
        // time filter (kept when recent, dropped when old).
        insert("null-recent", None, new_ms, "null recent content");
        insert("null-old", None, old_ms, "null old content");
        drop(conn);

        // Full scan sees every session.
        let full = OpenCodeConnector::extract_from_sqlite(&db_path, None, None).unwrap();
        let full_ids: HashSet<String> = full.iter().filter_map(|c| c.external_id.clone()).collect();
        assert_eq!(
            full_ids,
            ["old", "new", "null-recent", "null-old"]
                .iter()
                .copied()
                .map(str::to_string)
                .collect()
        );

        // Incremental at the cutoff: known-old sessions are skipped without
        // decoding their parts; the recent + unknown-time-recent survive.
        let inc = OpenCodeConnector::extract_from_sqlite(&db_path, Some(cutoff), None).unwrap();
        let inc_ids: HashSet<String> = inc.iter().filter_map(|c| c.external_id.clone()).collect();
        assert_eq!(
            inc_ids,
            ["new", "null-recent"]
                .iter()
                .copied()
                .map(str::to_string)
                .collect(),
            "incremental keeps updated>=cutoff and unknown-time+recent-msg, drops the rest"
        );

        // The kept session's content is byte-identical to the full-scan version:
        // the decode-skip must not corrupt or lose a kept session's messages.
        let new_full = full
            .iter()
            .find(|c| c.external_id.as_deref() == Some("new"))
            .unwrap();
        let new_inc = inc
            .iter()
            .find(|c| c.external_id.as_deref() == Some("new"))
            .unwrap();
        assert_eq!(new_inc.messages.len(), new_full.messages.len());
        assert_eq!(new_inc.messages[0].content, new_full.messages[0].content);
        assert_eq!(new_inc.messages[0].content, "new content");
    }

    #[test]
    fn sqlite_extract_calls_progress_tick_during_scan() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);
        conn.execute_compat(
            "INSERT INTO session (id, title) VALUES (?1, ?2)",
            params!["s", "s"],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params!["m", "s", r#"{"role":"user"}"#],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params!["p", "m", "s", r#"{"type":"text","text":"hi"}"#],
        )
        .unwrap();
        drop(conn);

        let ticks = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&ticks);
        let tick = move || {
            counter.fetch_add(1, Ordering::Relaxed);
        };
        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None, Some(&tick)).unwrap();
        assert_eq!(convs.len(), 1);
        assert!(
            ticks.load(Ordering::Relaxed) >= 1,
            "the scan progress tick must fire while decoding (cass#373 Variant A)"
        );
    }

    #[test]
    fn sqlite_extract_empty_db() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None, None).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn sqlite_extract_skips_empty_messages() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        conn.execute_compat(
            "INSERT INTO session (id, title) VALUES (?1, ?2)",
            params!["sess-empty", "Empty Session"],
        )
        .unwrap();

        // Session with no messages should be skipped
        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None, None).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn sqlite_extract_with_tool_parts() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        conn.execute_compat(
            "INSERT INTO session (id, title) VALUES (?1, ?2)",
            params!["sess-tools", "Tool Session"],
        )
        .unwrap();

        conn.execute_compat(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params!["msg-t1", "sess-tools", r#"{"role":"assistant"}"#],
        )
        .unwrap();

        // Text part
        conn.execute_compat(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "p1",
                "msg-t1",
                "sess-tools",
                r#"{"type":"text","text":"Let me check that."}"#,
            ],
        )
        .unwrap();

        // Tool part with output
        conn.execute_compat(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "p2",
                "msg-t1",
                "sess-tools",
                r#"{"type":"tool","state":{"output":"file.rs: 42 lines"}}"#,
            ],
        )
        .unwrap();

        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None, None).unwrap();
        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("Let me check that."));
        assert!(convs[0].messages[0].content.contains("[Tool Output]"));
        assert!(convs[0].messages[0].content.contains("file.rs: 42 lines"));
    }

    #[test]
    fn sqlite_extract_deduplicates_sessions() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        // Two sessions with different IDs
        for (sid, title) in &[("sess-a", "Session A"), ("sess-b", "Session B")] {
            conn.execute_compat(
                "INSERT INTO session (id, title) VALUES (?1, ?2)",
                params![*sid, *title],
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
                params![format!("msg-{sid}"), *sid, r#"{"role":"user"}"#],
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
                params![
                    format!("p-{sid}"),
                    format!("msg-{sid}"),
                    *sid,
                    r#"{"type":"text","text":"Hello"}"#,
                ],
            )
            .unwrap();
        }

        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None, None).unwrap();
        assert_eq!(convs.len(), 2);
    }

    #[test]
    fn sqlite_extract_groups_bulk_scanned_messages_by_session() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        for session_id in ["sess-a", "sess-b"] {
            conn.execute_compat(
                "INSERT INTO session (id, title) VALUES (?1, ?2)",
                params![session_id, format!("Session {session_id}")],
            )
            .unwrap();
        }

        for (message_id, session_id, role, created_at) in [
            ("msg-a-late", "sess-a", "assistant", 30_i64),
            ("msg-b-only", "sess-b", "user", 20_i64),
            ("msg-a-early", "sess-a", "user", 10_i64),
        ] {
            conn.execute_compat(
                "INSERT INTO message (id, session_id, data, time_created)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    message_id,
                    session_id,
                    format!(r#"{{"role":"{role}"}}"#),
                    created_at
                ],
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO part (id, message_id, session_id, data, time_created)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    format!("part-{message_id}"),
                    message_id,
                    session_id,
                    format!(r#"{{"type":"text","text":"content for {message_id}"}}"#),
                    created_at
                ],
            )
            .unwrap();
        }

        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None, None).unwrap();
        assert_eq!(convs.len(), 2);

        let sess_a = convs
            .iter()
            .find(|conv| conv.external_id.as_deref() == Some("sess-a"))
            .expect("sess-a conversation");
        assert_eq!(sess_a.messages.len(), 2);
        assert_eq!(sess_a.messages[0].idx, 0);
        assert_eq!(sess_a.messages[0].content, "content for msg-a-early");
        assert_eq!(sess_a.messages[1].idx, 1);
        assert_eq!(sess_a.messages[1].content, "content for msg-a-late");

        let sess_b = convs
            .iter()
            .find(|conv| conv.external_id.as_deref() == Some("sess-b"))
            .expect("sess-b conversation");
        assert_eq!(sess_b.messages.len(), 1);
        assert_eq!(sess_b.messages[0].idx, 0);
        assert_eq!(sess_b.messages[0].content, "content for msg-b-only");
    }

    /// Test that SQLite extraction handles integer timestamps (epoch seconds)
    /// which Drizzle ORM may use instead of TEXT ISO 8601 strings.
    #[test]
    fn sqlite_extract_handles_integer_timestamps() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("opencode.db");
        let conn = open_test_connection(&db_path);

        // Create schema with INTEGER timestamp columns (Drizzle ORM integer mode)
        conn.execute_batch(
            "CREATE TABLE session (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                title TEXT,
                directory TEXT,
                time_created INTEGER,
                time_updated INTEGER
            );
            CREATE TABLE message (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                data TEXT NOT NULL,
                time_created INTEGER,
                time_updated INTEGER
            );
            CREATE TABLE part (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                data TEXT NOT NULL,
                time_created INTEGER,
                time_updated INTEGER
            );",
        )
        .unwrap();

        // Insert session with epoch second timestamps
        conn.execute_compat(
            "INSERT INTO session (id, project_id, title, time_created, time_updated) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["sess-int", "proj-1", "Integer TS Session", 1700000000_i64, 1700000100_i64],
        ).unwrap();

        conn.execute_compat(
            "INSERT INTO message (id, session_id, data, time_created) VALUES (?1, ?2, ?3, ?4)",
            params!["msg-int", "sess-int", r#"{"role":"user"}"#, 1700000050_i64],
        )
        .unwrap();

        conn.execute_compat(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-int",
                "msg-int",
                "sess-int",
                r#"{"type":"text","text":"Integer timestamps!"}"#,
            ],
        )
        .unwrap();

        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None, None).unwrap();
        assert_eq!(convs.len(), 1);
        // Epoch seconds should be normalized to milliseconds
        assert_eq!(convs[0].started_at, Some(1_700_000_000_000));
        assert_eq!(convs[0].ended_at, Some(1_700_000_100_000));
        assert!(convs[0].messages[0].content.contains("Integer timestamps!"));
    }

    #[test]
    fn sqlite_extract_metadata_includes_source() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        conn.execute_compat(
            "INSERT INTO session (id, project_id, title) VALUES (?1, ?2, ?3)",
            params!["sess-meta", "proj-meta", "Meta Session"],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params!["msg-meta", "sess-meta", r#"{"role":"user"}"#],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "p-meta",
                "msg-meta",
                "sess-meta",
                r#"{"type":"text","text":"Test"}"#,
            ],
        )
        .unwrap();

        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None, None).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].metadata["source"], "sqlite");
        assert_eq!(convs[0].metadata["project_id"], "proj-meta");
    }

    // =====================================================
    // normalize_sqlite_ts_value() Tests
    // =====================================================

    #[test]
    fn normalize_sqlite_ts_value_integer_epoch_seconds() {
        let val = SqliteValue::Integer(1_700_000_000);
        assert_eq!(normalize_sqlite_ts_value(&val), Some(1_700_000_000_000));
    }

    #[test]
    fn normalize_sqlite_ts_value_integer_epoch_millis() {
        let val = SqliteValue::Integer(1_700_000_000_000);
        // Already in ms range, should pass through
        assert_eq!(normalize_sqlite_ts_value(&val), Some(1_700_000_000_000));
    }

    #[test]
    fn normalize_sqlite_ts_value_text_sqlite_format() {
        let val = SqliteValue::Text("2024-01-15 14:30:00".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        // Should parse to 2024-01-15T14:30:00 UTC epoch millis
        assert_eq!(result, 1_705_329_000_000);
    }

    #[test]
    fn normalize_sqlite_ts_value_text_iso8601_t_separator() {
        let val = SqliteValue::Text("2024-01-15T14:30:00".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        assert_eq!(result, 1_705_329_000_000);
    }

    #[test]
    fn normalize_sqlite_ts_value_text_fractional_seconds() {
        let val = SqliteValue::Text("2024-01-15 14:30:00.123".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        assert_eq!(result, 1_705_329_000_123);
    }

    #[test]
    fn normalize_sqlite_ts_value_text_t_fractional() {
        let val = SqliteValue::Text("2024-01-15T14:30:00.456".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        assert_eq!(result, 1_705_329_000_456);
    }

    #[test]
    fn normalize_sqlite_ts_value_text_rfc3339_z() {
        let val = SqliteValue::Text("2024-01-15T14:30:00Z".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        assert_eq!(result, 1_705_329_000_000);
    }

    #[test]
    fn normalize_sqlite_ts_value_text_rfc3339_offset() {
        let val = SqliteValue::Text("2024-01-15T14:30:00+00:00".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        assert_eq!(result, 1_705_329_000_000);
    }

    #[test]
    fn normalize_sqlite_ts_value_text_integer_string() {
        let val = SqliteValue::Text("1700000000".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        assert_eq!(result, 1_700_000_000_000);
    }

    #[test]
    fn normalize_sqlite_ts_value_null() {
        let val = SqliteValue::Null;
        assert_eq!(normalize_sqlite_ts_value(&val), None);
    }

    #[test]
    fn normalize_sqlite_ts_value_unparseable_text() {
        let val = SqliteValue::Text("not a date".into());
        assert_eq!(normalize_sqlite_ts_value(&val), None);
    }

    #[test]
    fn normalize_sqlite_ts_value_empty_text() {
        let val = SqliteValue::Text("".into());
        assert_eq!(normalize_sqlite_ts_value(&val), None);
    }

    #[test]
    fn normalize_sqlite_ts_value_real() {
        let val = SqliteValue::Float(1_700_000_000.5);
        assert_eq!(normalize_sqlite_ts_value(&val), Some(1_700_000_000_000));
    }

    // =====================================================
    // Regression: issue #174 — SQLite DB discovery
    // =====================================================

    /// Regression for issue #174: the candidate list must put XDG paths
    /// reachable from `$HOME` ahead of `dirs::data_local_dir()` so macOS
    /// users (where `data_local_dir()` resolves to `~/Library/Application
    /// Support`) still have their canonical `~/.local/share/opencode/
    /// opencode.db` found. The explicit override must always win.
    #[test]
    fn sqlite_db_candidates_from_orders_home_xdg_before_platform_dirs() {
        let home = PathBuf::from("/home/testuser");
        let xdg_data = PathBuf::from("/var/lib/xdg");
        let xdg_config = PathBuf::from("/etc/xdg");

        // No override → home-XDG paths must come first.
        let list = OpenCodeConnector::sqlite_db_candidates_from(
            None,
            Some(&home),
            Some(&xdg_data),
            Some(&xdg_config),
        );
        assert_eq!(list.len(), 4);
        assert_eq!(list[0], home.join(".local/share/opencode/opencode.db"));
        assert_eq!(list[1], home.join(".config/opencode/opencode.db"));
        assert_eq!(list[2], xdg_data.join("opencode/opencode.db"));
        assert_eq!(list[3], xdg_config.join("opencode/opencode.db"));

        // Explicit override always wins.
        let override_path = PathBuf::from("/custom/opencode.db");
        let list = OpenCodeConnector::sqlite_db_candidates_from(
            Some(override_path.clone()),
            Some(&home),
            Some(&xdg_data),
            Some(&xdg_config),
        );
        assert_eq!(list[0], override_path);
        assert_eq!(list.len(), 5);
    }

    /// Regression for issue #174: when two dirs helpers resolve to the
    /// same path (common on macOS where config_dir == data_local_dir),
    /// the candidate list must deduplicate while preserving priority.
    #[test]
    fn sqlite_db_candidates_from_deduplicates_overlapping_roots() {
        let home = PathBuf::from("/Users/testuser");
        // On macOS, both of these map to ~/Library/Application Support.
        let overlap = PathBuf::from("/Users/testuser/Library/Application Support");
        let list = OpenCodeConnector::sqlite_db_candidates_from(
            None,
            Some(&home),
            Some(&overlap),
            Some(&overlap),
        );
        // 2 home-XDG paths + 1 overlap path (deduplicated) = 3.
        assert_eq!(list.len(), 3, "list = {list:?}");
        assert_eq!(list[0], home.join(".local/share/opencode/opencode.db"));
        assert_eq!(list[1], home.join(".config/opencode/opencode.db"));
        assert_eq!(list[2], overlap.join("opencode/opencode.db"));
    }

    /// Regression for issue #174: when the caller passes an explicit
    /// directory that contains `opencode.db`, the scanner must discover
    /// it. This is the ctx.data_dir-as-parent path.
    #[test]
    fn scan_finds_sqlite_db_when_data_dir_is_db_parent() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);
        conn.execute_compat(
            "INSERT INTO session (id, project_id, title, directory) VALUES (?1, ?2, ?3, ?4)",
            params![
                "sess-parent",
                "proj-p",
                "Parent Session",
                "/home/user/parent",
            ],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-parent",
                "sess-parent",
                r#"{"role":"user","time":{"created":1700000000000}}"#,
            ],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-parent",
                "msg-parent",
                "sess-parent",
                r#"{"type":"text","text":"Parent content"}"#,
            ],
        )
        .unwrap();

        // Pass the parent directory (not the .db file itself).
        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(dir.path().to_path_buf(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-parent"));
    }

    /// Regression for issue #174: when the caller passes an explicit
    /// scan root (use_default_detection() == false) that does NOT
    /// contain opencode.db, the scanner must still find a DB via the
    /// ctx.data_dir-as-parent candidate if one is present.
    #[test]
    fn scan_finds_sqlite_db_via_data_dir_even_with_explicit_scan_roots() {
        use crate::connectors::scan::ScanRoot;

        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);
        conn.execute_compat(
            "INSERT INTO session (id, project_id, title, directory) VALUES (?1, ?2, ?3, ?4)",
            params![
                "sess-roots",
                "proj-roots",
                "Roots Session",
                "/home/user/roots",
            ],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-roots",
                "sess-roots",
                r#"{"role":"user","time":{"created":1700000000000}}"#,
            ],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-roots",
                "msg-roots",
                "sess-roots",
                r#"{"type":"text","text":"Roots content"}"#,
            ],
        )
        .unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::with_roots(
            dir.path().to_path_buf(),
            vec![ScanRoot::local(dir.path().to_path_buf())],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(
            convs.len(),
            1,
            "explicit scan_roots must still check ctx.data_dir for opencode.db"
        );
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-roots"));
    }

    #[test]
    fn scan_finds_sqlite_db_with_explicit_config_root() {
        use crate::connectors::scan::ScanRoot;

        let dir = TempDir::new().unwrap();
        let config_root = dir.path().join(".config");
        let opencode_dir = config_root.join("opencode");
        std::fs::create_dir_all(&opencode_dir).unwrap();

        let db_path = create_test_sqlite_db(&opencode_dir);
        let conn = open_test_connection(&db_path);
        conn.execute_compat(
            "INSERT INTO session (id, project_id, title, directory) VALUES (?1, ?2, ?3, ?4)",
            params![
                "sess-config",
                "proj-config",
                "Config Session",
                "/home/user/config",
            ],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-config",
                "sess-config",
                r#"{"role":"user","time":{"created":1700000000000}}"#,
            ],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-config",
                "msg-config",
                "sess-config",
                r#"{"type":"text","text":"Config content"}"#,
            ],
        )
        .unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::with_roots(
            dir.path().to_path_buf(),
            vec![ScanRoot::local(config_root)],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-config"));
    }

    /// Regression: when `ctx.data_dir` points directly at an
    /// `opencode.db` FILE (not the parent directory), the scanner must
    /// use it as-is — without trying to join `opencode.db` onto it
    /// again (which would produce a nonsense candidate like
    /// `/path/to/opencode.db/opencode.db`).
    #[test]
    fn scan_accepts_data_dir_as_direct_db_file() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);
        conn.execute_compat(
            "INSERT INTO session (id, project_id, title, directory) VALUES (?1, ?2, ?3, ?4)",
            params![
                "sess-direct",
                "proj-direct",
                "Direct Session",
                "/home/user/direct",
            ],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-direct",
                "sess-direct",
                r#"{"role":"user","time":{"created":1700000000000}}"#,
            ],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-direct",
                "msg-direct",
                "sess-direct",
                r#"{"type":"text","text":"Direct content"}"#,
            ],
        )
        .unwrap();

        let connector = OpenCodeConnector::new();
        // Pass the db file itself as data_dir.
        let ctx = ScanContext::local_default(db_path.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-direct"));
    }

    /// Regression: a nonexistent `.db` path passed as `ctx.data_dir`
    /// must not be silently treated as a directory (which would have
    /// produced a bogus `/path/to/missing.db/opencode.db` candidate in
    /// an earlier draft). The scanner simply finds nothing.
    #[test]
    fn scan_handles_nonexistent_db_path_in_data_dir() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing.db");
        // No file on disk at `missing`.

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::with_roots(
            missing,
            vec![crate::connectors::scan::ScanRoot::local(
                dir.path().to_path_buf(),
            )],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();
        assert!(
            convs.is_empty(),
            "nonexistent .db path should not produce sessions"
        );
    }

    /// Regression for cass#357: a remote-mirror scan root must never pull the
    /// local machine's canonical home/XDG `opencode.db` into its scan. The
    /// caller attributes everything returned by that invocation to the remote
    /// source, so a home fallback double-indexes local sessions under the
    /// remote `source_id`.
    #[test]
    fn remote_scan_root_does_not_include_local_default_dbs() {
        let dir = TempDir::new().unwrap();
        let mirror = dir.path().join("remotes/studio/mirror/opencode");
        fs::create_dir_all(&mirror).unwrap();
        let db_path = create_test_sqlite_db(&mirror);
        let conn = open_test_connection(&db_path);
        conn.execute_compat(
            "INSERT INTO session (id, project_id, title, directory) VALUES (?1, ?2, ?3, ?4)",
            params![
                "sess-remote",
                "proj-r",
                "Remote Session",
                "/home/remote/project"
            ],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-remote",
                "sess-remote",
                r#"{"role":"user","time":{"created":1700000000000}}"#,
            ],
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-remote",
                "msg-remote",
                "sess-remote",
                r#"{"type":"text","text":"Remote content"}"#,
            ],
        )
        .unwrap();

        let ctx = ScanContext::with_roots(
            PathBuf::new(),
            vec![ScanRoot::remote(
                mirror.clone(),
                crate::types::Origin::remote("studio"),
                None,
            )],
            None,
        );
        assert!(
            !OpenCodeConnector::allow_local_default_dbs(&ctx),
            "a remote scan root must disable the home/XDG DB fallback (cass#357)"
        );

        let connector = OpenCodeConnector::new();
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(
            convs
                .iter()
                .filter(|c| c.external_id.as_deref() == Some("sess-remote"))
                .count(),
            1,
            "the remote mirror's own DB must still be scanned"
        );
        for conv in &convs {
            assert!(
                conv.source_path.starts_with(&mirror),
                "remote-context scan leaked a session outside the mirror root (cass#357): {}",
                conv.source_path.display()
            );
        }
        // Discovery must stay in lockstep with scan (trait contract).
        let discovered = connector.discover_source_files(&ctx).unwrap();
        for file in &discovered {
            assert!(
                file.source_path.starts_with(&mirror),
                "remote-context discovery leaked a source outside the mirror root (cass#357): {}",
                file.source_path.display()
            );
        }
    }

    /// Companion to the cass#357 guard: local explicit roots (and empty
    /// roots, i.e. default detection) must keep the issue #174 home/XDG DB
    /// fallback, and any remote root in the mix disables it.
    #[test]
    fn local_scan_roots_keep_default_db_fallback() {
        let dir = TempDir::new().unwrap();
        let local_ctx = ScanContext::with_roots(
            PathBuf::new(),
            vec![ScanRoot::local(dir.path().to_path_buf())],
            None,
        );
        assert!(OpenCodeConnector::allow_local_default_dbs(&local_ctx));

        let default_ctx = ScanContext::local_default(PathBuf::new(), None);
        assert!(OpenCodeConnector::allow_local_default_dbs(&default_ctx));

        let mixed_ctx = ScanContext::with_roots(
            PathBuf::new(),
            vec![
                ScanRoot::local(dir.path().to_path_buf()),
                ScanRoot::remote(
                    dir.path().join("mirror"),
                    crate::types::Origin::remote("laptop"),
                    None,
                ),
            ],
            None,
        );
        assert!(
            !OpenCodeConnector::allow_local_default_dbs(&mixed_ctx),
            "any remote root disables the local-default fallback"
        );
    }
}
