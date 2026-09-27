//! Connector for `OpenClaw` session logs.
//!
//! `OpenClaw` has two storage generations:
//!
//! **Legacy (pre-v2026.8.1)** stores JSONL sessions at:
//! - ~/.openclaw/agents/<agent-name>/sessions/*.jsonl
//!
//! Each line has a `type` discriminator: "session", "message", "`model_change`",
//! "`thinking_level_change`", "custom". Messages are wrapped:
//! {"type":"message","id":"...","message":{"role":"user","content":[...],...}}
//!
//! **`OpenClaw` 2.0 (v2026.8.1+)** migrates active transcripts into a per-agent
//! SQLite store at:
//! - ~/.openclaw/agents/<agent-name>/agent/openclaw-agent.sqlite
//!
//! The `transcript_events(session_id, seq, event_json, created_at)` table holds
//! one legacy-shaped transcript entry per row (the same "session"/"message"
//! objects that used to be JSONL lines), so both variants share one event
//! parser. Newer stores add `event_zstd` and `event_utf8_bytes`: a large
//! event is then stored with `event_json` NULL, its UTF-8 JSON compressed into
//! a Zstandard frame in `event_zstd`, and the decoded byte length recorded in
//! `event_utf8_bytes`. Such rows are decoded (bounded, length- and
//! UTF-8-checked) before the shared parser runs, and a row that cannot be
//! decoded is skipped on its own rather than failing the whole store.
//!
//! The SQLite path is behind the `openclaw-sqlite` feature, admits a
//! database by sniffing the schema (never by version strings), opens it
//! read-only so a live `OpenClaw` Gateway is undisturbed, and skips legacy
//! JSONL files whose session id already came out of the SQLite store (the
//! migration leaves archived `*.jsonl.deleted.<ts>.zst` artifacts behind, and
//! partially migrated trees may briefly hold both).

use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::{Connector, file_modified_since, flatten_content, parse_timestamp};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct OpenClawConnector;

impl Default for OpenClawConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenClawConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn openclaw_home() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(".openclaw"))
    }

    fn agents_root() -> Option<PathBuf> {
        Self::openclaw_home().map(|home| home.join("agents"))
    }

    fn find_agent_session_dirs() -> Vec<PathBuf> {
        Self::agents_root().map_or_else(Vec::new, |agents_root| {
            Self::find_agent_session_dirs_at(&agents_root)
        })
    }

    fn find_agent_session_dirs_at(agents_root: &Path) -> Vec<PathBuf> {
        tracing::debug!(
            agents_root = %agents_root.display(),
            "openclaw: scanning agents root for sessions directories"
        );

        if !agents_root.exists() || !agents_root.is_dir() {
            return Vec::new();
        }

        let mut session_dirs: Vec<PathBuf> = Vec::new();
        let walker = WalkDir::new(agents_root)
            .follow_links(false)
            .min_depth(1)
            .max_depth(2);

        for entry_res in walker {
            let entry = match entry_res {
                Ok(entry) => entry,
                Err(err) => {
                    tracing::debug!(
                        agents_root = %agents_root.display(),
                        error = %err,
                        "openclaw: cannot read directory entry, continuing"
                    );
                    continue;
                }
            };

            if !entry.file_type().is_dir() || entry.depth() != 1 {
                continue;
            }

            let agent_name = entry.file_name().to_string_lossy().to_string();
            let sessions_dir = entry.path().join("sessions");
            let has_sessions = sessions_dir.is_dir();
            tracing::debug!(
                agent = %agent_name,
                has_sessions,
                "openclaw: found agent directory"
            );

            if has_sessions {
                session_dirs.push(sessions_dir);
            } else {
                tracing::debug!(
                    agent = %agent_name,
                    "openclaw: skipping agent directory without sessions/ subdirectory"
                );
            }
        }

        session_dirs.sort();
        session_dirs.dedup();

        let mut agent_names: Vec<String> = session_dirs
            .iter()
            .filter_map(|dir| {
                dir.parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .map(String::from)
            })
            .collect();
        agent_names.sort();

        tracing::debug!(
            count = session_dirs.len(),
            agents = ?agent_names,
            "openclaw: discovered agent session directories"
        );

        session_dirs
    }

    /// Name of the `OpenClaw` 2.0 per-agent SQLite transcript store.
    const AGENT_DB_FILE_NAME: &'static str = "openclaw-agent.sqlite";

    /// Per-agent SQLite store for one `agents/<name>` directory, if present.
    fn agent_db_for_agent_dir(agent_dir: &Path) -> Option<PathBuf> {
        let db = agent_dir.join("agent").join(Self::AGENT_DB_FILE_NAME);
        if db.is_file() { Some(db) } else { None }
    }

    /// Discover `OpenClaw` 2.0 per-agent SQLite stores under an agents root:
    /// `agents/<agent>/agent/openclaw-agent.sqlite`.
    fn find_agent_db_paths_at(agents_root: &Path) -> Vec<PathBuf> {
        if !agents_root.is_dir() {
            return Vec::new();
        }

        let mut dbs: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = fs::read_dir(agents_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                // Mirror the JSONL walker: only real directories, no symlinks.
                if !entry.file_type().is_ok_and(|ft| ft.is_dir()) {
                    continue;
                }
                if let Some(db) = Self::agent_db_for_agent_dir(&path) {
                    dbs.push(db);
                }
            }
        }

        dbs.sort();
        dbs.dedup();
        dbs
    }

    fn detect_from_agents_root(agents_root: &Path) -> DetectionResult {
        let mut roots = Self::find_agent_session_dirs_at(agents_root);
        let db_paths = Self::find_agent_db_paths_at(agents_root);
        let mut evidence = vec![
            format!("found {}", agents_root.display()),
            format!("discovered {} agent session dirs", roots.len()),
            format!("discovered {} agent sqlite stores", db_paths.len()),
        ];

        let mut names: Vec<String> = roots
            .iter()
            .filter_map(|path| {
                path.parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .map(String::from)
            })
            .chain(db_paths.iter().filter_map(|db| {
                db.parent()
                    .and_then(Path::parent)
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .map(String::from)
            }))
            .collect();
        names.sort();
        names.dedup();
        if !names.is_empty() {
            evidence.push(format!("agents: {}", names.join(", ")));
        }

        roots.extend(db_paths);

        DetectionResult {
            detected: true,
            evidence,
            root_paths: roots,
        }
    }

    fn looks_like_openclaw_storage(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        path_str.contains("openclaw") && path_str.contains("sessions")
    }

    fn session_root_from_candidate(path: &Path) -> Option<PathBuf> {
        let dir = if path.is_file() {
            path.parent().unwrap_or(path)
        } else {
            path
        };

        if dir.file_name().and_then(|n| n.to_str()) == Some("sessions") && dir.is_dir() {
            return Some(dir.to_path_buf());
        }

        let sessions = dir.join("sessions");
        if sessions.is_dir() {
            Some(sessions)
        } else {
            None
        }
    }

    fn roots_from_scan_path(path: &Path) -> Vec<PathBuf> {
        let mut roots = Vec::new();

        if let Some(explicit) = Self::session_root_from_candidate(path)
            && Self::looks_like_openclaw_storage(&explicit)
        {
            roots.push(explicit);
        }

        let embedded_agents = path.join(".openclaw").join("agents");
        if embedded_agents.exists() {
            roots.extend(Self::find_agent_session_dirs_at(&embedded_agents));
        }

        if path.file_name().and_then(|n| n.to_str()) == Some(".openclaw") {
            roots.extend(Self::find_agent_session_dirs_at(&path.join("agents")));
        }

        if path.file_name().and_then(|n| n.to_str()) == Some("agents") {
            roots.extend(Self::find_agent_session_dirs_at(path));
        }

        roots.sort();
        roots.dedup();
        roots
    }

    fn agent_directory_from_sessions_root(path: &Path) -> String {
        path.parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("openclaw")
            .to_string()
    }

    fn agent_slug_for_directory(agent_dir: &str) -> String {
        if agent_dir == "openclaw" {
            "openclaw".to_string()
        } else {
            format!("openclaw/{agent_dir}")
        }
    }

    fn session_files(root: &Path) -> Vec<PathBuf> {
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

        // Keep scan order deterministic across filesystems and runs.
        out.sort();
        out
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots: Vec<ScanRoot> = Vec::new();
        if ctx.use_default_detection() {
            if let Some(explicit) = Self::session_root_from_candidate(&ctx.data_dir)
                && Self::looks_like_openclaw_storage(&explicit)
                && explicit.exists()
            {
                roots.push(ScanRoot::local(explicit));
            } else {
                roots.extend(
                    Self::find_agent_session_dirs()
                        .into_iter()
                        .map(ScanRoot::local),
                );
            }
        } else {
            for root in &ctx.scan_roots {
                roots.extend(
                    Self::roots_from_scan_path(&root.path)
                        .into_iter()
                        .map(|path| root.with_path(path)),
                );
            }
        }

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();

        #[cfg(feature = "openclaw-sqlite")]
        for root in Self::sqlite_source_roots(ctx) {
            if root.path.is_file() && file_modified_since(&root.path, ctx.since_ts) {
                out.push(
                    DiscoveredSourceFile::new(
                        "openclaw",
                        &root,
                        root.path.clone(),
                        DiscoveredSourceRole::SqliteDatabase,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }
        }

        for mut root in Self::source_roots(ctx) {
            if root.path.is_file() {
                let parent = root.path.parent().unwrap_or(&root.path).to_path_buf();
                root = root.with_path(parent);
            }
            for file in Self::session_files(&root.path) {
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "openclaw",
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

    /// Agent directory name for a per-agent SQLite store path
    /// (`.../agents/<agent>/agent/openclaw-agent.sqlite`).
    #[cfg(feature = "openclaw-sqlite")]
    fn agent_directory_from_db_path(db: &Path) -> String {
        let parent = db.parent();
        if parent.and_then(|p| p.file_name()).and_then(|n| n.to_str()) == Some("agent") {
            parent
                .and_then(Path::parent)
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .map_or_else(|| "openclaw".to_string(), String::from)
        } else {
            "openclaw".to_string()
        }
    }

    /// SQLite store candidates reachable from one scan path.
    #[cfg(feature = "openclaw-sqlite")]
    fn sqlite_roots_from_scan_path(path: &Path) -> Vec<PathBuf> {
        let mut roots = Vec::new();

        if path.is_file() {
            if path.file_name().and_then(|n| n.to_str()) == Some(Self::AGENT_DB_FILE_NAME) {
                roots.push(path.to_path_buf());
            }
        } else {
            // `path` may be an agent directory (agents/<name>) …
            if let Some(db) = Self::agent_db_for_agent_dir(path) {
                roots.push(db);
            }
            // … or its agent/ subdirectory.
            let inner = path.join(Self::AGENT_DB_FILE_NAME);
            if inner.is_file() {
                roots.push(inner);
            }
        }

        let embedded_agents = path.join(".openclaw").join("agents");
        if embedded_agents.exists() {
            roots.extend(Self::find_agent_db_paths_at(&embedded_agents));
        }
        if path.file_name().and_then(|n| n.to_str()) == Some(".openclaw") {
            roots.extend(Self::find_agent_db_paths_at(&path.join("agents")));
        }
        if path.file_name().and_then(|n| n.to_str()) == Some("agents") {
            roots.extend(Self::find_agent_db_paths_at(path));
        }

        roots.sort();
        roots.dedup();
        roots
    }

    /// SQLite store roots for this scan context (mirrors [`Self::source_roots`]).
    #[cfg(feature = "openclaw-sqlite")]
    fn sqlite_source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots: Vec<ScanRoot> = Vec::new();
        if ctx.use_default_detection() {
            let scoped_to_jsonl = Self::session_root_from_candidate(&ctx.data_dir)
                .is_some_and(|p| Self::looks_like_openclaw_storage(&p) && p.exists());
            let from_data = Self::sqlite_roots_from_scan_path(&ctx.data_dir);
            if scoped_to_jsonl || !from_data.is_empty() {
                // data_dir names one specific OpenClaw store: stay scoped to
                // it and never mix in the machine's real ~/.openclaw stores.
                roots.extend(from_data.into_iter().map(ScanRoot::local));
            } else if let Some(agents_root) = Self::agents_root() {
                roots.extend(
                    Self::find_agent_db_paths_at(&agents_root)
                        .into_iter()
                        .map(ScanRoot::local),
                );
            }
        } else {
            for root in &ctx.scan_roots {
                roots.extend(
                    Self::sqlite_roots_from_scan_path(&root.path)
                        .into_iter()
                        .map(|path| root.with_path(path)),
                );
            }
        }

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    /// Scan every discovered SQLite store, appending conversations to `convs`
    /// and returning the `(agent_directory, session_id)` pairs it produced so
    /// the legacy JSONL pass can skip already-covered sessions.
    #[cfg(feature = "openclaw-sqlite")]
    fn scan_sqlite_stores(
        ctx: &ScanContext,
        convs: &mut Vec<NormalizedConversation>,
    ) -> std::collections::HashSet<(String, String)> {
        let mut seen = std::collections::HashSet::new();
        for root in Self::sqlite_source_roots(ctx) {
            let db = &root.path;
            if !db.is_file() || !file_modified_since(db, ctx.since_ts) {
                continue;
            }
            let agent_directory = Self::agent_directory_from_db_path(db);
            match sqlite_store::extract_from_sqlite(db, &agent_directory, ctx.since_ts) {
                Ok(db_convs) => {
                    tracing::debug!(
                        agent = %agent_directory,
                        sessions = db_convs.len(),
                        path = %db.display(),
                        "openclaw: scanned sqlite transcript store"
                    );
                    for conv in db_convs {
                        if let Some(sid) = conv.metadata.get("session_id").and_then(|v| v.as_str())
                        {
                            seen.insert((agent_directory.clone(), sid.to_string()));
                        }
                        convs.push(conv);
                    }
                }
                Err(err) => {
                    tracing::debug!(
                        path = %db.display(),
                        error = %err,
                        "openclaw: skipping unreadable/unrecognized sqlite store"
                    );
                }
            }
        }
        seen
    }

    /// Flatten `OpenClaw` content blocks into a single string.
    /// Content is an array of blocks: text, toolCall, thinking.
    fn flatten_openclaw_content(content: &Value) -> String {
        match content {
            Value::String(s) => s.clone(),
            Value::Array(arr) => {
                let parts: Vec<String> = arr
                    .iter()
                    .filter_map(|block| {
                        let block_type = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        match block_type {
                            "text" => block.get("text").and_then(|t| t.as_str()).map(String::from),
                            "toolCall" => {
                                let name = block
                                    .get("name")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("tool_call");
                                Some(format!("[tool: {name}]"))
                            }
                            "thinking" => {
                                block.get("text").and_then(|t| t.as_str()).map(String::from)
                            }
                            _ => block.get("text").and_then(|t| t.as_str()).map(String::from),
                        }
                    })
                    .collect();
                parts.join("\n")
            }
            _ => flatten_content(content),
        }
    }
}

/// Accumulates one session's transcript events into normalized messages.
///
/// Both storage variants feed this: legacy JSONL feeds one parsed line per
/// call, and the `OpenClaw` 2.0 SQLite store feeds one `event_json` row per
/// call (the rows carry the same "session"/"message" objects the JSONL lines
/// used to).
#[derive(Default)]
struct SessionEventAccumulator {
    messages: Vec<NormalizedMessage>,
    started_at: Option<i64>,
    ended_at: Option<i64>,
    session_cwd: Option<String>,
}

impl SessionEventAccumulator {
    /// Apply one transcript event. `fallback_created_at` supplies a storage
    /// timestamp (e.g. the SQLite `created_at` column, already in epoch ms)
    /// used when the event itself carries none.
    fn apply_event(&mut self, val: Value, fallback_created_at: Option<i64>) {
        let line_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match line_type {
            "session" => {
                // Extract session metadata
                self.session_cwd = val.get("cwd").and_then(|v| v.as_str()).map(String::from);
                if let Some(ts) = val
                    .get("timestamp")
                    .and_then(parse_timestamp)
                    .or(fallback_created_at)
                {
                    self.started_at = Some(self.started_at.map_or(ts, |curr| curr.min(ts)));
                }
            }
            "message" => {
                // Messages are wrapped: {type:"message", message:{role, content, ...}}
                let Some(msg) = val.get("message") else {
                    return;
                };

                let role = msg
                    .get("role")
                    .and_then(|v| v.as_str())
                    .unwrap_or("assistant");

                let content = msg
                    .get("content")
                    .map(OpenClawConnector::flatten_openclaw_content)
                    .unwrap_or_default();

                if content.trim().is_empty() {
                    return;
                }

                // Timestamps can be on the wrapper or inner message
                let created = val
                    .get("timestamp")
                    .and_then(parse_timestamp)
                    .or_else(|| msg.get("timestamp").and_then(parse_timestamp))
                    .or(fallback_created_at);

                self.started_at = match (self.started_at, created) {
                    (Some(curr), Some(ts)) => Some(curr.min(ts)),
                    (None, Some(ts)) => Some(ts),
                    (other, None) => other,
                };
                self.ended_at = match (self.ended_at, created) {
                    (Some(curr), Some(ts)) => Some(curr.max(ts)),
                    (None, Some(ts)) => Some(ts),
                    (other, None) => other,
                };

                let invocations = msg
                    .get("content")
                    .and_then(|c| c.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter(|block| {
                                block.get("type").and_then(|t| t.as_str()) == Some("toolCall")
                            })
                            .map(|block| {
                                let name = block
                                    .get("name")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                crate::types::NormalizedInvocation {
                                    kind: "tool".to_string(),
                                    name,
                                    raw_name: None,
                                    call_id: block
                                        .get("id")
                                        .and_then(|v| v.as_str())
                                        .map(String::from),
                                    arguments: block
                                        .get("arguments")
                                        .or_else(|| block.get("input"))
                                        .cloned(),
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                let idx = i64::try_from(self.messages.len()).unwrap_or(i64::MAX);
                let author = msg.get("model").and_then(|v| v.as_str()).map(String::from);
                self.messages.push(NormalizedMessage {
                    idx,
                    role: role.to_string(),
                    author,
                    created_at: created,
                    content,
                    extra: val,
                    invocations,
                    snippets: Vec::new(),
                });
            }
            // Skip model_change, thinking_level_change, custom, etc.
            _ => {}
        }
    }

    /// Session title: first line of the first user message, else of the first
    /// message.
    fn title(&self) -> Option<String> {
        self.messages
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
                self.messages
                    .first()
                    .and_then(|m| m.content.lines().next())
                    .map(|s| s.chars().take(100).collect())
            })
    }
}

#[cfg(feature = "openclaw-sqlite")]
mod sqlite_store {
    //! Schema-sniffing reader for the `OpenClaw` 2.0 per-agent SQLite store.

    use std::path::Path;

    use anyhow::{Context, Result, bail};
    use frankensqlite::compat::{OpenFlags, ParamValue, RowExt};
    use frankensqlite::{Row, SqliteValue};
    use serde_json::Value;

    use super::super::parse_timestamp;
    use super::super::sqlite_sync::{Connection, ConnectionExt, open_with_flags};
    use super::{OpenClawConnector, SessionEventAccumulator};
    use crate::types::NormalizedConversation;

    /// Columns this reader actually consumes; their presence admits the
    /// database regardless of what other columns/tables a future `OpenClaw`
    /// adds. Version strings are deliberately not consulted.
    const REQUIRED_EVENT_COLS: &[&str] = &["session_id", "seq", "event_json", "created_at"];

    /// Columns of the compressed payload encoding. Both must be present for
    /// compressed rows to be decodable; older stores have neither.
    const COMPRESSED_EVENT_COLS: &[&str] = &["event_zstd", "event_utf8_bytes"];

    /// `OpenClaw`'s own ceiling for both the stored frame and the decoded
    /// event (`MAX_COMPRESSED_EVENT_BYTES`). Anything larger is not a frame
    /// the writer could have produced, so it is rejected before allocating.
    pub(super) const MAX_COMPRESSED_EVENT_BYTES: usize = 4 * 1024 * 1024;

    /// What [`admit`] learned about a store's schema.
    struct AdmittedStore {
        conn: Connection,
        /// `event_zstd` and `event_utf8_bytes` both exist.
        has_compressed_payloads: bool,
    }

    fn admit(db_path: &Path) -> Result<AdmittedStore> {
        let conn = open_with_flags(
            db_path.to_string_lossy().as_ref(),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .with_context(|| format!("failed to open read-only: {}", db_path.display()))?;

        // A live OpenClaw Gateway may hold a writer on this database.
        conn.execute("PRAGMA busy_timeout = 5000;")
            .with_context(|| "failed to set busy_timeout")?;
        // Belt-and-braces on top of the read-only open flag.
        for pragma in ["PRAGMA query_only = ON;", "PRAGMA trusted_schema = OFF;"] {
            if let Err(err) = conn.execute(pragma) {
                tracing::debug!("openclaw sqlite: best-effort {pragma} failed: {err}");
            }
        }

        // Schema sniff: the transcript table must be a real table (not a
        // view hiding arbitrary SQL) and expose the consumed columns.
        let kinds: Vec<String> = conn
            .query_map_collect(
                "SELECT type FROM sqlite_master WHERE name = 'transcript_events'",
                &[],
                |row| row.get_typed::<String>(0),
            )
            .with_context(|| "failed to read sqlite schema")?;
        match kinds.first() {
            Some(ty) if ty == "table" => {}
            Some(ty) => {
                bail!("not an OpenClaw agent store: transcript_events is a {ty}, not a table")
            }
            None => bail!("not an OpenClaw agent store: missing table transcript_events"),
        }

        let cols: Vec<String> = conn
            .query_map_collect("PRAGMA table_info(transcript_events)", &[], |row| {
                row.get_typed::<String>(1)
            })
            .with_context(|| "failed to read transcript_events columns")?;
        for required in REQUIRED_EVENT_COLS {
            if !cols.iter().any(|c| c == required) {
                bail!("not an OpenClaw agent store: transcript_events lacks column {required}");
            }
        }
        let has_compressed_payloads = COMPRESSED_EVENT_COLS
            .iter()
            .all(|wanted| cols.iter().any(|c| c == wanted));

        Ok(AdmittedStore {
            conn,
            has_compressed_payloads,
        })
    }

    fn non_null(row: &Row, index: usize) -> Option<&SqliteValue> {
        row.get(index)
            .filter(|value| !matches!(value, SqliteValue::Null))
    }

    /// Why one transcript row could not be turned into event JSON text.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum PayloadError {
        /// Neither `event_json` nor a compressed frame is present.
        Missing,
        /// `event_json` holds a number, or a blob that is not UTF-8.
        IdentityNotText,
        /// The compressed frame or its recorded length is absent, of the
        /// wrong type, or outside `OpenClaw`'s bounds.
        InvalidBounds,
        /// The frame is corrupt or decodes to more than the recorded length.
        Decompress,
        /// The frame decoded to a different number of bytes than recorded.
        LengthMismatch { recorded: usize, decoded: usize },
        /// The decoded bytes are not UTF-8.
        NotUtf8,
    }

    /// Resolve one row's event JSON text the way `OpenClaw` reads it:
    /// `coalesce(event_json, decode(event_zstd, event_utf8_bytes))`.
    ///
    /// The decoder mirrors the writer's checks: the frame must be a non-empty
    /// blob of at most 4 MiB, the recorded length an integer in
    /// `1..=4 MiB`, the frame must decode to exactly that many bytes (the
    /// output buffer is capped at the recorded length, so a frame that would
    /// expand further fails instead of allocating), and the result must be
    /// UTF-8.
    pub(super) fn event_json_text(
        event_json: Option<&SqliteValue>,
        event_zstd: Option<&SqliteValue>,
        event_utf8_bytes: Option<&SqliteValue>,
    ) -> std::result::Result<String, PayloadError> {
        match event_json {
            Some(SqliteValue::Text(text)) => return Ok(text.to_string()),
            // SQLite's column affinity is advisory; a writer binding bytes
            // leaves a blob in a TEXT column. Accept it only as UTF-8.
            Some(SqliteValue::Blob(bytes)) => {
                return String::from_utf8(bytes.to_vec())
                    .map_err(|_| PayloadError::IdentityNotText);
            }
            Some(_) => return Err(PayloadError::IdentityNotText),
            None => {}
        }

        let frame = match event_zstd {
            None => return Err(PayloadError::Missing),
            Some(SqliteValue::Blob(frame))
                if !frame.is_empty() && frame.len() <= MAX_COMPRESSED_EVENT_BYTES =>
            {
                frame
            }
            Some(_) => return Err(PayloadError::InvalidBounds),
        };
        let recorded = match event_utf8_bytes {
            Some(SqliteValue::Integer(n)) => usize::try_from(*n)
                .ok()
                .filter(|n| (1..=MAX_COMPRESSED_EVENT_BYTES).contains(n))
                .ok_or(PayloadError::InvalidBounds)?,
            _ => return Err(PayloadError::InvalidBounds),
        };

        let decoded =
            zstd::bulk::decompress(frame, recorded).map_err(|_| PayloadError::Decompress)?;
        if decoded.len() != recorded {
            return Err(PayloadError::LengthMismatch {
                recorded,
                decoded: decoded.len(),
            });
        }
        String::from_utf8(decoded).map_err(|_| PayloadError::NotUtf8)
    }

    /// Replay one session's rows, in `seq` order, into an accumulator.
    /// Returns it with the highest `seq` seen (decodable or not).
    fn read_session_events(
        conn: &Connection,
        events_sql: &str,
        session_id: &str,
        db_path: &Path,
    ) -> Result<(SessionEventAccumulator, Option<i64>)> {
        // Rows are decoded one at a time in Rust so that a single unreadable
        // payload costs that event only, never the query (and with it every
        // session in the store).
        let rows: Vec<(i64, Option<i64>, std::result::Result<String, PayloadError>)> = conn
            .query_map_collect(events_sql, &[ParamValue::from(session_id)], |row| {
                Ok((
                    row.get_typed::<i64>(0)?,
                    row.get_typed::<Option<i64>>(2).ok().flatten(),
                    event_json_text(non_null(row, 1), non_null(row, 3), non_null(row, 4)),
                ))
            })?;

        let mut acc = SessionEventAccumulator::default();
        let mut last_seq: Option<i64> = None;
        let mut undecodable = 0_usize;
        for (seq, created_at, event_json) in rows {
            last_seq = Some(seq);
            let event_json = match event_json {
                Ok(text) => text,
                Err(err) => {
                    undecodable += 1;
                    tracing::debug!(
                        "openclaw sqlite: skipping undecodable event {session_id}#{seq} in {}: \
                         {err:?}",
                        db_path.display()
                    );
                    continue;
                }
            };
            let Ok(val) = serde_json::from_str::<Value>(&event_json) else {
                continue;
            };
            acc.apply_event(
                val,
                created_at.and_then(|ms| parse_timestamp(&Value::from(ms))),
            );
        }
        if undecodable > 0 {
            tracing::warn!(
                "openclaw sqlite: skipped {undecodable} undecodable transcript event(s) in \
                 session {session_id} of {}",
                db_path.display()
            );
        }
        Ok((acc, last_seq))
    }

    /// Extract normalized conversations from one per-agent SQLite store.
    pub(super) fn extract_from_sqlite(
        db_path: &Path,
        agent_directory: &str,
        since_ts: Option<i64>,
    ) -> Result<Vec<NormalizedConversation>> {
        let AdmittedStore {
            conn,
            has_compressed_payloads,
        } = admit(db_path)?;
        // Legacy stores lack the compressed columns; select NULLs in their
        // place so both shapes share one row decoder.
        let events_sql = if has_compressed_payloads {
            "SELECT seq, event_json, created_at, event_zstd, event_utf8_bytes \
             FROM transcript_events WHERE session_id = ?1 ORDER BY seq ASC"
        } else {
            "SELECT seq, event_json, created_at, NULL, NULL \
             FROM transcript_events WHERE session_id = ?1 ORDER BY seq ASC"
        };
        conn.read_transaction(|conn| -> Result<Vec<NormalizedConversation>> {
            // Session-level freshness: include a session when ANY event is at
            // or after the cutoff, then return ALL of its events so the
            // conversation stays complete. `created_at` units are normalized
            // in Rust (parse_timestamp banding), not assumed in SQL.
            let sessions: Vec<(String, i64)> = conn.query_map_collect(
                "SELECT session_id, MAX(created_at) FROM transcript_events \
                 GROUP BY session_id ORDER BY session_id",
                &[],
                |row| Ok((row.get_typed::<String>(0)?, row.get_typed::<i64>(1)?)),
            )?;

            let mut convs = Vec::new();
            for (session_id, last_raw) in sessions {
                let last_at = parse_timestamp(&Value::from(last_raw));
                if let (Some(since), Some(last)) = (since_ts, last_at) {
                    if last < since.saturating_sub(1_000) {
                        continue;
                    }
                }

                let (acc, last_seq) = read_session_events(conn, events_sql, &session_id, db_path)?;

                if acc.messages.is_empty() {
                    continue;
                }

                let external_id = if agent_directory == "openclaw" {
                    session_id.clone()
                } else {
                    format!("{agent_directory}/{session_id}")
                };
                let title = acc.title();
                let workspace = acc.session_cwd.as_ref().map(std::path::PathBuf::from);
                let metadata = serde_json::json!({
                    "source": "openclaw",
                    "storage": "sqlite",
                    "session_id": session_id,
                    "cwd": acc.session_cwd,
                    "agent_directory": agent_directory,
                    // Incremental checkpoint for downstream freshness probes:
                    // (session_id, last_event_seq, last_event_at) advance
                    // monotonically as the Gateway appends transcript rows.
                    "last_event_seq": last_seq,
                    "last_event_at": last_at,
                });

                convs.push(NormalizedConversation {
                    agent_slug: OpenClawConnector::agent_slug_for_directory(agent_directory),
                    external_id: Some(external_id),
                    title,
                    workspace,
                    source_path: db_path.to_path_buf(),
                    started_at: acc.started_at,
                    ended_at: acc.ended_at,
                    metadata,
                    messages: acc.messages,
                });
            }
            Ok(convs)
        })
    }
}

impl Connector for OpenClawConnector {
    fn detect(&self) -> DetectionResult {
        // Use OpenClaw-specific multi-agent detection instead of the generic
        // franken probe, which only checks for directory existence and doesn't
        // walk the agents/<name>/sessions/ layout.
        match Self::agents_root() {
            Some(agents_root) if agents_root.exists() => {
                Self::detect_from_agents_root(&agents_root)
            }
            _ => DetectionResult::not_found(),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();

        // OpenClaw 2.0 SQLite stores first: sessions they cover must not be
        // double-indexed from leftover/partially-migrated JSONL files.
        #[cfg(feature = "openclaw-sqlite")]
        let sqlite_sessions = Self::scan_sqlite_stores(ctx, &mut convs);
        #[cfg(not(feature = "openclaw-sqlite"))]
        let sqlite_sessions: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();

        let roots: Vec<PathBuf> = Self::source_roots(ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();

        if roots.is_empty() {
            return Ok(convs);
        }

        let mut scanned_agents = 0usize;

        for mut root in roots {
            if root.is_file() {
                root = root.parent().unwrap_or(&root).to_path_buf();
            }

            let agent_directory = Self::agent_directory_from_sessions_root(&root);
            let agent_slug = Self::agent_slug_for_directory(&agent_directory);
            let files = Self::session_files(&root);
            let mut agent_file_count = 0usize;
            let mut agent_session_count = 0usize;
            let mut agent_error_count = 0usize;
            tracing::debug!(
                agent = %agent_directory,
                file_count = files.len(),
                "openclaw: scanning agent directory"
            );
            for file in files {
                agent_file_count += 1;
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }

                if !sqlite_sessions.is_empty() {
                    let stem = file
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or_default();
                    if sqlite_sessions.contains(&(agent_directory.clone(), stem.to_string())) {
                        tracing::debug!(
                            agent = %agent_directory,
                            path = %file.display(),
                            "openclaw: skipping JSONL session already covered by sqlite store"
                        );
                        continue;
                    }
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

                let external_id = if agent_directory == "openclaw" {
                    external_id
                } else {
                    external_id.map(|id| format!("{agent_directory}/{id}"))
                };

                let file_handle = match fs::File::open(&file) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::debug!(path = %file.display(), error = %e, "openclaw: skipping unreadable session");
                        agent_error_count += 1;
                        continue;
                    }
                };
                let reader = std::io::BufReader::new(file_handle);

                let mut acc = SessionEventAccumulator::default();
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
                    acc.apply_event(val, None);
                }

                if acc.messages.is_empty() {
                    continue;
                }

                let title = acc.title();
                let workspace = acc.session_cwd.as_ref().map(PathBuf::from);

                let metadata = serde_json::json!({
                    "source": "openclaw",
                    "cwd": acc.session_cwd,
                    "agent_directory": agent_directory.clone(),
                });

                convs.push(NormalizedConversation {
                    agent_slug: agent_slug.clone(),
                    external_id,
                    title,
                    workspace,
                    source_path,
                    started_at: acc.started_at,
                    ended_at: acc.ended_at,
                    metadata,
                    messages: acc.messages,
                });
                agent_session_count += 1;
            }

            scanned_agents += 1;
            tracing::debug!(
                agent = %agent_directory,
                files = agent_file_count,
                sessions = agent_session_count,
                errors = agent_error_count,
                "openclaw: completed agent scan"
            );
        }

        tracing::debug!(
            agents = scanned_agents,
            sessions = convs.len(),
            "openclaw: completed multi-agent scan"
        );

        Ok(convs)
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_session(root: &Path, name: &str, lines: &[&str]) -> PathBuf {
        let path = root.join(name);
        let content = lines.join("\n");
        fs::write(&path, content).unwrap();
        path
    }

    fn write_minimal_openclaw_session(
        sessions_root: &Path,
        file_name: &str,
        cwd: &str,
        user_text: &str,
    ) -> PathBuf {
        write_session(
            sessions_root,
            file_name,
            &[
                &format!(
                    r#"{{"type":"session","id":"s1","timestamp":"2026-02-01T16:00:00.000Z","cwd":"{cwd}"}}"#
                ),
                &format!(
                    r#"{{"type":"message","id":"m1","timestamp":"2026-02-01T16:00:01.000Z","message":{{"role":"user","content":[{{"type":"text","text":"{user_text}"}}]}}}}"#
                ),
            ],
        )
    }

    fn ctx_with_root(root: &Path) -> ScanContext {
        ScanContext::with_roots(
            root.to_path_buf(),
            vec![super::super::ScanRoot::local(root.to_path_buf())],
            None,
        )
    }

    #[test]
    fn scan_parses_openclaw_wrapped_messages() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".openclaw/agents/openclaw/sessions");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "session.jsonl",
            &[
                r#"{"type":"session","id":"abc","timestamp":"2026-02-01T16:00:00.000Z","cwd":"/home/user/project","version":"0.1.0"}"#,
                r#"{"type":"message","id":"m1","parentId":"abc","timestamp":"2026-02-01T16:00:00.828Z","message":{"role":"user","content":[{"type":"text","text":"Hello OpenClaw"}],"timestamp":1769961600827}}"#,
                r#"{"type":"message","id":"m2","parentId":"m1","timestamp":"2026-02-01T16:00:06.672Z","message":{"role":"assistant","content":[{"type":"text","text":"Hi there!"},{"type":"toolCall","id":"tc1","name":"exec","arguments":{}}],"api":"anthropic-messages","provider":"anthropic","model":"claude-opus-4-5"}}"#,
            ],
        );

        let connector = OpenClawConnector::new();
        let ctx = ScanContext::local_default(sessions.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "openclaw");
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].title, Some("Hello OpenClaw".to_string()));
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert!(convs[0].messages[1].content.contains("Hi there!"));
        assert!(convs[0].messages[1].content.contains("[tool: exec]"));
        assert_eq!(
            convs[0].messages[1].author,
            Some("claude-opus-4-5".to_string())
        );
        assert!(convs[0].workspace.is_some());
        assert!(convs[0].started_at.is_some());
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn scan_skips_non_message_types() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".openclaw/agents/openclaw/sessions");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "session2.jsonl",
            &[
                r#"{"type":"session","id":"s1","timestamp":"2026-02-01T16:00:00.000Z","cwd":"/"}"#,
                r#"{"type":"model_change","model":"gpt-5"}"#,
                r#"{"type":"thinking_level_change","level":"high"}"#,
                r#"{"type":"message","id":"m1","timestamp":"2026-02-01T16:00:01.000Z","message":{"role":"user","content":"Only message"}}"#,
                r#"{"type":"custom","data":"something"}"#,
            ],
        );

        let connector = OpenClawConnector::new();
        let ctx = ScanContext::local_default(sessions.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Only message");
    }

    #[test]
    fn scan_handles_empty_and_invalid_lines() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".openclaw/agents/openclaw/sessions");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "bad.jsonl",
            &[
                "",
                "not-json",
                r#"{"type":"message","id":"m1","timestamp":"2026-02-01T16:00:00.000Z","message":{"role":"user","content":"Valid"}}"#,
                r#"{"type":"message","id":"m2","message":{"role":"assistant","content":""}}"#,
            ],
        );

        let connector = OpenClawConnector::new();
        let ctx = ScanContext::local_default(sessions.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        // Only the valid non-empty message should appear
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid");
    }

    #[test]
    fn agents_root_path_construction() {
        if let Some(home) = dirs::home_dir() {
            assert_eq!(
                OpenClawConnector::agents_root().unwrap(),
                home.join(".openclaw").join("agents")
            );
        }
    }

    #[test]
    fn find_dirs_empty_root() {
        let tmp = TempDir::new().unwrap();
        let agents_root = tmp.path().join("agents");
        fs::create_dir_all(&agents_root).unwrap();
        tracing::debug!("Scanning agents root: {}", agents_root.display());
        let dirs = OpenClawConnector::find_agent_session_dirs_at(&agents_root);
        assert!(dirs.is_empty());
    }

    #[test]
    fn find_dirs_no_sessions_subdir() {
        let tmp = TempDir::new().unwrap();
        let agents_root = tmp.path().join("agents");
        fs::create_dir_all(agents_root.join("alice")).unwrap();
        let dirs = OpenClawConnector::find_agent_session_dirs_at(&agents_root);
        assert!(dirs.is_empty());
    }

    #[test]
    fn find_dirs_one_agent() {
        let tmp = TempDir::new().unwrap();
        let agents_root = tmp.path().join("agents");
        let alice = agents_root.join("alice").join("sessions");
        fs::create_dir_all(&alice).unwrap();

        let dirs = OpenClawConnector::find_agent_session_dirs_at(&agents_root);
        assert_eq!(dirs, vec![alice]);
    }

    #[test]
    fn find_dirs_multiple_agents_sorted() {
        let tmp = TempDir::new().unwrap();
        let agents_root = tmp.path().join("agents");
        fs::create_dir_all(agents_root.join("charlie").join("sessions")).unwrap();
        fs::create_dir_all(agents_root.join("alice").join("sessions")).unwrap();
        fs::create_dir_all(agents_root.join("bob").join("sessions")).unwrap();

        let dirs = OpenClawConnector::find_agent_session_dirs_at(&agents_root);
        let discovered: Vec<String> = dirs
            .iter()
            .filter_map(|p| {
                p.parent()
                    .and_then(|pp| pp.file_name())
                    .and_then(|n| n.to_str())
                    .map(String::from)
            })
            .collect();
        assert_eq!(
            discovered,
            vec![
                "alice".to_string(),
                "bob".to_string(),
                "charlie".to_string()
            ]
        );
    }

    #[test]
    fn find_dirs_max_depth_ignores_deep_nesting() {
        let tmp = TempDir::new().unwrap();
        let agents_root = tmp.path().join("agents");
        fs::create_dir_all(agents_root.join("alice").join("sessions")).unwrap();
        fs::create_dir_all(
            agents_root
                .join("nested")
                .join("too")
                .join("deep")
                .join("sessions"),
        )
        .unwrap();

        let dirs = OpenClawConnector::find_agent_session_dirs_at(&agents_root);
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].to_string_lossy().contains(&format!(
            "{}alice{}",
            std::path::MAIN_SEPARATOR,
            std::path::MAIN_SEPARATOR
        )));
    }

    #[test]
    fn session_files_are_sorted_for_deterministic_scan_order() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        write_session(
            &sessions,
            "z-last.jsonl",
            &[r#"{"type":"message","message":{"role":"user","content":"z"}}"#],
        );
        write_session(
            &sessions,
            "a-first.jsonl",
            &[r#"{"type":"message","message":{"role":"user","content":"a"}}"#],
        );

        let files = OpenClawConnector::session_files(&sessions);
        let file_names: Vec<String> = files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
            .collect();

        assert_eq!(
            file_names,
            vec!["a-first.jsonl".to_string(), "z-last.jsonl".to_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn find_dirs_symlink_skipped() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let agents_root = tmp.path().join("agents");
        let real_agent = tmp.path().join("real_alice");
        fs::create_dir_all(real_agent.join("sessions")).unwrap();
        fs::create_dir_all(&agents_root).unwrap();
        symlink(&real_agent, agents_root.join("alice_link")).unwrap();

        let dirs = OpenClawConnector::find_agent_session_dirs_at(&agents_root);
        assert!(dirs.is_empty());
    }

    #[test]
    fn detect_reports_agent_names() {
        let tmp = TempDir::new().unwrap();
        let agents_root = tmp.path().join("agents");
        fs::create_dir_all(agents_root.join("alice").join("sessions")).unwrap();
        fs::create_dir_all(agents_root.join("bob").join("sessions")).unwrap();

        let detection = OpenClawConnector::detect_from_agents_root(&agents_root);
        assert!(detection.detected);
        assert_eq!(detection.root_paths.len(), 2);
        let joined = detection.evidence.join(" | ");
        assert!(joined.contains("discovered 2 agent session dirs"));
        assert!(joined.contains("alice"));
        assert!(joined.contains("bob"));
    }

    #[test]
    fn detect_zero_agents() {
        let tmp = TempDir::new().unwrap();
        let agents_root = tmp.path().join("agents");
        fs::create_dir_all(&agents_root).unwrap();

        let detection = OpenClawConnector::detect_from_agents_root(&agents_root);
        assert!(detection.detected);
        assert!(detection.root_paths.is_empty());
        assert!(
            detection
                .evidence
                .iter()
                .any(|line| line.contains("discovered 0 agent session dirs"))
        );
    }

    #[test]
    fn scan_multiple_agents() {
        let tmp = TempDir::new().unwrap();
        let alice_sessions = tmp.path().join(".openclaw/agents/alice/sessions");
        let bob_sessions = tmp.path().join(".openclaw/agents/bob/sessions");
        fs::create_dir_all(&alice_sessions).unwrap();
        fs::create_dir_all(&bob_sessions).unwrap();
        write_minimal_openclaw_session(&alice_sessions, "alice.jsonl", "/tmp/alice", "hello alice");
        write_minimal_openclaw_session(&bob_sessions, "bob.jsonl", "/tmp/bob", "hello bob");

        let connector = OpenClawConnector::new();
        let ctx = ctx_with_root(tmp.path());
        let mut convs = connector.scan(&ctx).unwrap();
        convs.sort_by(|a, b| a.agent_slug.cmp(&b.agent_slug));

        assert_eq!(convs.len(), 2);
        assert_eq!(convs[0].agent_slug, "openclaw/alice");
        assert_eq!(convs[1].agent_slug, "openclaw/bob");
    }

    #[test]
    fn scan_agent_identity_preserved() {
        let tmp = TempDir::new().unwrap();
        let alice_sessions = tmp.path().join(".openclaw/agents/alice/sessions");
        fs::create_dir_all(&alice_sessions).unwrap();
        write_minimal_openclaw_session(&alice_sessions, "s1.jsonl", "/tmp/alice", "from alice");

        let connector = OpenClawConnector::new();
        let ctx = ctx_with_root(tmp.path());
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "openclaw/alice");
        assert_eq!(convs[0].external_id.as_deref(), Some("alice/s1"));
    }

    #[test]
    fn scan_agent_metadata_present() {
        let tmp = TempDir::new().unwrap();
        let alice_sessions = tmp.path().join(".openclaw/agents/alice/sessions");
        fs::create_dir_all(&alice_sessions).unwrap();
        write_minimal_openclaw_session(
            &alice_sessions,
            "meta.jsonl",
            "/tmp/alice",
            "metadata check",
        );

        let connector = OpenClawConnector::new();
        let ctx = ctx_with_root(tmp.path());
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0]
                .metadata
                .get("agent_directory")
                .and_then(|v| v.as_str()),
            Some("alice")
        );
    }

    #[test]
    fn scan_mixed_valid_invalid_across_agents() {
        let tmp = TempDir::new().unwrap();
        let alice_sessions = tmp.path().join(".openclaw/agents/alice/sessions");
        let bob_sessions = tmp.path().join(".openclaw/agents/bob/sessions");
        fs::create_dir_all(&alice_sessions).unwrap();
        fs::create_dir_all(&bob_sessions).unwrap();
        write_session(
            &alice_sessions,
            "bad.jsonl",
            &["not-json", "still-not-json"],
        );
        write_minimal_openclaw_session(&bob_sessions, "good.jsonl", "/tmp/bob", "valid from bob");

        let connector = OpenClawConnector::new();
        let ctx = ctx_with_root(tmp.path());
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "openclaw/bob");
    }

    #[test]
    fn scan_single_agent_unchanged_slug() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".openclaw/agents/openclaw/sessions");
        fs::create_dir_all(&sessions).unwrap();
        write_minimal_openclaw_session(&sessions, "single.jsonl", "/tmp/openclaw", "legacy mode");

        let connector = OpenClawConnector::new();
        let ctx = ScanContext::local_default(sessions.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "openclaw");
        assert_eq!(convs[0].external_id.as_deref(), Some("single"));
        assert_eq!(
            convs[0]
                .metadata
                .get("agent_directory")
                .and_then(|v| v.as_str()),
            Some("openclaw")
        );
    }

    #[test]
    fn scan_with_explicit_agent_root_path() {
        let tmp = TempDir::new().unwrap();
        let agent_root = tmp.path().join(".openclaw/agents/alice");
        let sessions = agent_root.join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        write_minimal_openclaw_session(&sessions, "root.jsonl", "/tmp/alice", "explicit root");

        let connector = OpenClawConnector::new();
        let ctx = ScanContext::with_roots(
            tmp.path().to_path_buf(),
            vec![super::super::ScanRoot::local(agent_root)],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "openclaw/alice");
    }

    #[test]
    fn detect_reports_sqlite_only_agents() {
        // Detection is pure filesystem probing: an OpenClaw 2.0 agent with
        // only a per-agent SQLite store (no sessions/ dir) must be visible
        // even without the openclaw-sqlite feature.
        let tmp = TempDir::new().unwrap();
        let agents_root = tmp.path().join("agents");
        let db_dir = agents_root.join("alice").join("agent");
        fs::create_dir_all(&db_dir).unwrap();
        let db = db_dir.join("openclaw-agent.sqlite");
        fs::write(&db, b"stub").unwrap();

        let detection = OpenClawConnector::detect_from_agents_root(&agents_root);
        assert!(detection.detected);
        assert!(detection.root_paths.contains(&db));
        let joined = detection.evidence.join(" | ");
        assert!(joined.contains("discovered 0 agent session dirs"));
        assert!(joined.contains("discovered 1 agent sqlite stores"));
        assert!(joined.contains("alice"));
    }

    #[cfg(feature = "openclaw-sqlite")]
    mod sqlite_variant {
        use super::*;
        use crate::connectors::sqlite_sync::{Connection, ConnectionExt};
        use frankensqlite::params;

        fn create_agent_db(agent_dir: &Path) -> PathBuf {
            let db_dir = agent_dir.join("agent");
            fs::create_dir_all(&db_dir).unwrap();
            let db_path = db_dir.join("openclaw-agent.sqlite");
            let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
            conn.execute(
                "CREATE TABLE transcript_events (
                    session_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    event_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (session_id, seq)
                )",
            )
            .unwrap();
            drop(conn);
            db_path
        }

        fn insert_event(
            db_path: &Path,
            session_id: &str,
            seq: i64,
            event_json: &str,
            created_at: i64,
        ) {
            let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
            conn.execute_compat(
                "INSERT INTO transcript_events (session_id, seq, event_json, created_at) \
                 VALUES (?, ?, ?, ?)",
                params![session_id, seq, event_json, created_at],
            )
            .unwrap();
        }

        fn seed_session(db_path: &Path, session_id: &str) {
            insert_event(
                db_path,
                session_id,
                1,
                &format!(r#"{{"type":"session","id":"{session_id}","cwd":"/tmp/alice"}}"#),
                1_700_000_000_000,
            );
            insert_event(
                db_path,
                session_id,
                2,
                r#"{"type":"message","id":"m1","message":{"role":"user","content":[{"type":"text","text":"Hello from sqlite"}]}}"#,
                1_700_000_001_000,
            );
            insert_event(
                db_path,
                session_id,
                3,
                r#"{"type":"message","id":"m2","message":{"role":"assistant","content":[{"type":"text","text":"Hi!"},{"type":"toolCall","id":"tc1","name":"exec","arguments":{}}],"model":"claude-opus-4-5"}}"#,
                1_700_000_002_000,
            );
        }

        #[test]
        fn scan_discovers_openclaw2_sqlite_transcripts_without_jsonl() {
            let tmp = TempDir::new().unwrap();
            let agent_dir = tmp.path().join(".openclaw/agents/alice");
            let db = create_agent_db(&agent_dir);
            seed_session(&db, "sess-1");

            let connector = OpenClawConnector::new();
            let ctx = ctx_with_root(tmp.path());
            let convs = connector.scan(&ctx).unwrap();

            assert_eq!(convs.len(), 1);
            let conv = &convs[0];
            assert_eq!(conv.agent_slug, "openclaw/alice");
            assert_eq!(conv.external_id.as_deref(), Some("alice/sess-1"));
            assert_eq!(conv.source_path, db);
            assert_eq!(conv.messages.len(), 2);
            assert_eq!(conv.messages[0].role, "user");
            assert_eq!(conv.title, Some("Hello from sqlite".to_string()));
            assert!(conv.messages[1].content.contains("Hi!"));
            assert!(conv.messages[1].content.contains("[tool: exec]"));
            assert_eq!(conv.messages[1].author, Some("claude-opus-4-5".to_string()));
            // The events carry no timestamps of their own, so the SQLite
            // created_at column must back-fill message/session times.
            assert_eq!(conv.messages[0].created_at, Some(1_700_000_001_000));
            assert_eq!(conv.started_at, Some(1_700_000_000_000));
            assert_eq!(conv.ended_at, Some(1_700_000_002_000));
            assert_eq!(conv.workspace.as_deref(), Some(Path::new("/tmp/alice")));
            assert_eq!(
                conv.metadata.get("storage").and_then(|v| v.as_str()),
                Some("sqlite")
            );
            assert_eq!(
                conv.metadata
                    .get("last_event_seq")
                    .and_then(serde_json::Value::as_i64),
                Some(3)
            );
            crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
        }

        #[test]
        fn sqlite_sessions_not_double_indexed_from_leftover_jsonl() {
            let tmp = TempDir::new().unwrap();
            let agent_dir = tmp.path().join(".openclaw/agents/alice");
            let sessions = agent_dir.join("sessions");
            fs::create_dir_all(&sessions).unwrap();
            // sess-1 exists in BOTH stores (partially migrated tree); sess-2
            // only as legacy JSONL.
            write_minimal_openclaw_session(&sessions, "sess-1.jsonl", "/tmp/alice", "legacy copy");
            write_minimal_openclaw_session(&sessions, "sess-2.jsonl", "/tmp/alice", "jsonl only");
            let db = create_agent_db(&agent_dir);
            seed_session(&db, "sess-1");

            let connector = OpenClawConnector::new();
            let ctx = ctx_with_root(tmp.path());
            let mut convs = connector.scan(&ctx).unwrap();
            convs.sort_by(|a, b| a.external_id.cmp(&b.external_id));

            assert_eq!(convs.len(), 2);
            assert_eq!(convs[0].external_id.as_deref(), Some("alice/sess-1"));
            // The overlapping session comes from the SQLite store, not JSONL.
            assert_eq!(
                convs[0].metadata.get("storage").and_then(|v| v.as_str()),
                Some("sqlite")
            );
            assert_eq!(convs[0].title, Some("Hello from sqlite".to_string()));
            assert_eq!(convs[1].external_id.as_deref(), Some("alice/sess-2"));
            assert_eq!(convs[1].title, Some("jsonl only".to_string()));
        }

        #[test]
        fn incremental_scan_surfaces_new_sqlite_event_without_jsonl() {
            // The issue's minimal confirmation: a new transcript event in the
            // SQLite store becomes discoverable on an incremental scan even
            // when no active-session JSONL exists at all.
            let tmp = TempDir::new().unwrap();
            let agent_dir = tmp.path().join(".openclaw/agents/alice");
            let db = create_agent_db(&agent_dir);
            seed_session(&db, "sess-1");

            let since = Some(1_750_000_000_000);
            let connector = OpenClawConnector::new();
            let ctx = ScanContext::with_roots(
                tmp.path().to_path_buf(),
                vec![crate::connectors::ScanRoot::local(tmp.path().to_path_buf())],
                since,
            );
            assert!(connector.scan(&ctx).unwrap().is_empty());

            insert_event(
                &db,
                "sess-1",
                4,
                r#"{"type":"message","id":"m3","message":{"role":"user","content":[{"type":"text","text":"post-cutoff follow-up"}]}}"#,
                1_760_000_000_000,
            );

            let convs = connector.scan(&ctx).unwrap();
            assert_eq!(convs.len(), 1);
            // The whole session is returned, not just the fresh event.
            assert_eq!(convs[0].messages.len(), 3);
            assert_eq!(convs[0].ended_at, Some(1_760_000_000_000));
        }

        /// Current `OpenClaw` schema: `event_json` is nullable and large
        /// events live in `event_zstd` with their decoded UTF-8 length.
        fn create_compressed_agent_db(agent_dir: &Path) -> PathBuf {
            let db_dir = agent_dir.join("agent");
            fs::create_dir_all(&db_dir).unwrap();
            let db_path = db_dir.join("openclaw-agent.sqlite");
            let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
            conn.execute(
                "CREATE TABLE transcript_events (
                    session_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    event_json TEXT,
                    created_at INTEGER NOT NULL,
                    event_zstd BLOB,
                    event_utf8_bytes INTEGER,
                    navigation_json TEXT,
                    PRIMARY KEY (session_id, seq)
                )",
            )
            .unwrap();
            drop(conn);
            db_path
        }

        fn insert_compressed_event(
            db_path: &Path,
            session_id: &str,
            seq: i64,
            frame: &[u8],
            utf8_bytes: i64,
            created_at: i64,
        ) {
            let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
            conn.execute_compat(
                "INSERT INTO transcript_events \
                 (session_id, seq, event_json, created_at, event_zstd, event_utf8_bytes) \
                 VALUES (?, ?, NULL, ?, ?, ?)",
                params![session_id, seq, created_at, frame.to_vec(), utf8_bytes],
            )
            .unwrap();
        }

        fn compress(json: &str) -> (Vec<u8>, i64) {
            let frame = zstd::bulk::compress(json.as_bytes(), 1).unwrap();
            (frame, i64::try_from(json.len()).unwrap())
        }

        /// The frame from the GH #25 reproduction, produced by an encoder
        /// other than the `zstd` crate: the 106-byte event whose user text is
        /// `compressedfixturemessage`.
        const ISSUE_25_FRAME: &[u8] = &[
            0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x6a, 0x7d, 0x02, 0x00, 0x62, 0x44, 0x0f, 0x16, 0xa0,
            0xb5, 0x39, 0x04, 0x9f, 0x23, 0x89, 0xc0, 0xd2, 0xee, 0x1d, 0xcd, 0x12, 0x65, 0xf3,
            0xff, 0xf2, 0x59, 0xe3, 0xff, 0x1b, 0x02, 0xad, 0x09, 0xcd, 0xa8, 0xbe, 0x8e, 0x82,
            0x70, 0xa6, 0x31, 0x19, 0x54, 0x7a, 0xa4, 0x5f, 0x7e, 0x70, 0xfd, 0xf1, 0x0f, 0x2a,
            0x25, 0x45, 0xa7, 0x02, 0x20, 0x2c, 0x3b, 0x52, 0x1b, 0x43, 0xa6, 0x4d, 0xaf, 0x4e,
            0x81, 0x97, 0x05, 0x05, 0x00, 0x9d, 0x40, 0x82, 0xca, 0x80, 0xb3, 0x2a, 0xf0, 0x33,
            0x40, 0x2d, 0x8a, 0x1d,
        ];

        fn user_event(text: &str) -> String {
            format!(
                r#"{{"type":"message","message":{{"role":"user","content":[{{"type":"text","text":"{text}"}}]}}}}"#
            )
        }

        #[test]
        fn compressed_event_does_not_hide_the_rest_of_the_store() {
            // GH #25: one `event_json = NULL` row used to abort the query
            // with a type mismatch and drop every session in the database.
            let tmp = TempDir::new().unwrap();
            let agent_dir = tmp.path().join(".openclaw/agents/main");
            let db = create_compressed_agent_db(&agent_dir);
            insert_event(
                &db,
                "fixture",
                1,
                &user_event("plainfixturemessage"),
                1_700_000_000_000,
            );
            insert_compressed_event(&db, "fixture", 2, ISSUE_25_FRAME, 106, 1_700_000_001_000);
            let (frame, len) = compress(&user_event("cratecompressedmessage"));
            insert_compressed_event(&db, "fixture", 3, &frame, len, 1_700_000_002_000);
            // A second session must survive too.
            insert_event(
                &db,
                "other",
                1,
                &user_event("othersession"),
                1_700_000_003_000,
            );

            let before = fs::read(&db).unwrap();
            let connector = OpenClawConnector::new();
            let ctx = ctx_with_root(tmp.path());
            let mut convs = connector.scan(&ctx).unwrap();
            convs.sort_by(|a, b| a.external_id.cmp(&b.external_id));
            assert_eq!(
                fs::read(&db).unwrap(),
                before,
                "the source store must stay untouched"
            );

            assert_eq!(convs.len(), 2);
            let texts: Vec<&str> = convs[0]
                .messages
                .iter()
                .map(|m| m.content.as_str())
                .collect();
            assert_eq!(convs[0].external_id.as_deref(), Some("main/fixture"));
            assert_eq!(
                texts,
                [
                    "plainfixturemessage",
                    "compressedfixturemessage",
                    "cratecompressedmessage"
                ]
            );
            assert_eq!(convs[0].messages[1].created_at, Some(1_700_000_001_000));
            assert_eq!(
                convs[0]
                    .metadata
                    .get("last_event_seq")
                    .and_then(serde_json::Value::as_i64),
                Some(3)
            );
            assert_eq!(convs[1].messages[0].content, "othersession");
        }

        #[test]
        fn undecodable_compressed_rows_are_skipped_individually() {
            let tmp = TempDir::new().unwrap();
            let agent_dir = tmp.path().join(".openclaw/agents/main");
            let db = create_compressed_agent_db(&agent_dir);
            let (good, good_len) = compress(&user_event("survivor"));
            let (other, other_len) = compress(&user_event("x"));
            insert_event(&db, "s", 1, &user_event("first"), 1_700_000_000_000);
            // Recorded length too short: the capped buffer cannot hold the frame.
            insert_compressed_event(&db, "s", 2, &other, other_len - 1, 1_700_000_000_001);
            // Recorded length too long: decodes to fewer bytes than recorded.
            insert_compressed_event(&db, "s", 3, &other, other_len + 1, 1_700_000_000_002);
            // Not a Zstandard frame at all.
            insert_compressed_event(&db, "s", 4, b"not zstd", 8, 1_700_000_000_003);
            // Recorded length beyond OpenClaw's 4 MiB ceiling.
            insert_compressed_event(&db, "s", 5, &other, 5 * 1024 * 1024, 1_700_000_000_004);
            // Well-formed frame whose payload is not UTF-8.
            let bad_utf8 = zstd::bulk::compress(&[0xff, 0xfe, 0xfd], 1).unwrap();
            insert_compressed_event(&db, "s", 6, &bad_utf8, 3, 1_700_000_000_005);
            {
                let conn = Connection::open(db.to_string_lossy().as_ref()).unwrap();
                // No payload in any column.
                conn.execute(
                    "INSERT INTO transcript_events (session_id, seq, event_json, created_at) \
                     VALUES ('s', 7, NULL, 1700000000006)",
                )
                .unwrap();
                // Frame present but its recorded length missing.
                conn.execute_compat(
                    "INSERT INTO transcript_events \
                     (session_id, seq, event_json, created_at, event_zstd, event_utf8_bytes) \
                     VALUES ('s', 8, NULL, 1700000000007, ?, NULL)",
                    params![good.clone()],
                )
                .unwrap();
            }
            insert_compressed_event(&db, "s", 9, &good, good_len, 1_700_000_000_008);

            let convs = OpenClawConnector::new()
                .scan(&ctx_with_root(tmp.path()))
                .unwrap();
            assert_eq!(convs.len(), 1);
            let texts: Vec<&str> = convs[0]
                .messages
                .iter()
                .map(|m| m.content.as_str())
                .collect();
            assert_eq!(texts, ["first", "survivor"]);
            assert_eq!(
                convs[0]
                    .metadata
                    .get("last_event_seq")
                    .and_then(serde_json::Value::as_i64),
                Some(9)
            );
        }

        #[test]
        fn payload_decoder_enforces_openclaw_bounds() {
            use super::super::sqlite_store::{
                MAX_COMPRESSED_EVENT_BYTES, PayloadError, event_json_text,
            };
            use frankensqlite::SqliteValue;

            #[allow(clippy::needless_pass_by_value)] // keeps the call sites terse
            fn dec(
                json: Option<SqliteValue>,
                zstd: Option<SqliteValue>,
                bytes: Option<SqliteValue>,
            ) -> Result<String, PayloadError> {
                event_json_text(json.as_ref(), zstd.as_ref(), bytes.as_ref())
            }

            let blob = |b: &[u8]| Some(SqliteValue::Blob(b.to_vec().into()));
            let int = |n: i64| Some(SqliteValue::Integer(n));
            let json = user_event("bounded");
            let (frame, len) = compress(&json);

            // Identity text wins even when a frame is also present.
            assert_eq!(
                dec(Some(SqliteValue::Text("{}".into())), blob(&frame), int(len)),
                Ok("{}".to_string())
            );
            assert_eq!(dec(None, blob(&frame), int(len)), Ok(json.clone()));
            assert_eq!(dec(None, None, None), Err(PayloadError::Missing));
            assert_eq!(
                dec(Some(SqliteValue::Integer(1)), None, None),
                Err(PayloadError::IdentityNotText)
            );
            assert_eq!(
                dec(None, blob(&[]), int(len)),
                Err(PayloadError::InvalidBounds)
            );
            assert_eq!(
                dec(None, blob(&frame), int(0)),
                Err(PayloadError::InvalidBounds)
            );
            assert_eq!(
                dec(None, blob(&frame), int(-1)),
                Err(PayloadError::InvalidBounds)
            );
            assert_eq!(
                dec(None, Some(SqliteValue::Text("x".into())), int(len)),
                Err(PayloadError::InvalidBounds)
            );
            let oversized_frame = vec![0_u8; MAX_COMPRESSED_EVENT_BYTES + 1];
            assert_eq!(
                dec(None, blob(&oversized_frame), int(len)),
                Err(PayloadError::InvalidBounds)
            );
            // A frame that expands past the recorded length fails inside the
            // capped buffer instead of allocating its real size.
            let bomb = zstd::bulk::compress(&vec![b'a'; MAX_COMPRESSED_EVENT_BYTES], 1).unwrap();
            assert_eq!(
                dec(None, blob(&bomb), int(16)),
                Err(PayloadError::Decompress)
            );
            assert_eq!(
                dec(None, blob(&frame), int(len + 5)),
                Err(PayloadError::LengthMismatch {
                    recorded: usize::try_from(len + 5).unwrap(),
                    decoded: usize::try_from(len).unwrap(),
                })
            );
        }

        #[test]
        fn unrecognized_sqlite_schema_is_skipped_not_fatal() {
            let tmp = TempDir::new().unwrap();
            let db_dir = tmp.path().join(".openclaw/agents/alice/agent");
            fs::create_dir_all(&db_dir).unwrap();
            let db_path = db_dir.join("openclaw-agent.sqlite");
            let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
            conn.execute("CREATE TABLE something_else (id TEXT PRIMARY KEY)")
                .unwrap();
            drop(conn);

            let connector = OpenClawConnector::new();
            let ctx = ctx_with_root(tmp.path());
            let convs = connector.scan(&ctx).unwrap();
            assert!(convs.is_empty());
        }
    }
}
