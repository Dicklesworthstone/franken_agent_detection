//! Connector for Shelley (boldsoftware/shelley) conversation databases.
//!
//! Shelley stores MANY conversations in ONE WAL-mode `SQLite` database. The
//! database location is configurable (`shelley -db <path>`); the CLI default
//! is `shelley.db` relative to the server process's working directory.
//!
//! Schema (authoritative history: Shelley's `db/schema` migrations):
//!   - `migrations(migration_number, migration_name, executed_at)`
//!   - `conversations(conversation_id, slug, user_initiated, created_at,
//!     updated_at, [cwd, archived, parent_conversation_id, model,
//!     conversation_options, current_generation, tags, is_draft, draft,
//!     queued_messages, agent_working])`
//!   - `messages(message_id, conversation_id, sequence_id, type, llm_data,
//!     user_data, usage_data, created_at, [display_data,
//!     excluded_from_context, generation, llm_api_url, model_name,
//!     forked_from_message_id, user_email, other_usage_data])`
//!
//! `llm_data` is the canonical message payload (Go `llm.Message` serialized
//! with exported field names). `Role` and content `Type` are persisted as
//! integers from one shared Go `iota` block: `Role` 0=user 1=assistant;
//! `Type` 2=text 3=thinking 4=redacted-thinking 5=tool-use 6=tool-result
//! 7=server-tool-use 8=web-search-result-set 9=web-search-result.
//!
//! Safety contract (cass gh#415):
//!   - open read-only, best-effort `PRAGMA query_only`/`trusted_schema=OFF`,
//!     bounded busy timeout, and never write, checkpoint, or migrate;
//!   - never admit a database by filename alone: admission requires the
//!     Shelley schema signature (and migration records for auto-discovered
//!     candidates);
//!   - the same database also holds API keys and other sensitive
//!     configuration, so consumers must NOT raw-mirror the file (cass-side
//!     policy);
//!   - never index drafts, queued messages, generated system prompts,
//!     participant emails, image/base64 payloads, signatures, or encrypted
//!     continuation data.
//!
//! **NOTE:** This connector uses `frankensqlite`. See AGENTS.md RULE 2.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use frankensqlite::compat::{OpenFlags, ParamValue, RowExt};
use serde::Deserialize;
use serde_json::{Value, json};

use super::sqlite_sync::{Connection, ConnectionExt, open_with_flags};
use super::utils::env_path_nonempty;
use super::{Connector, franken_detection_for_connector};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
};

use super::scan::{
    DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot, SourceCompletion,
    SourceScanHooks,
};

/// Pre-deserialization cap for a raw JSON column value.
const MAX_RAW_FIELD_BYTES: usize = 8 * 1024 * 1024;
/// Cap for searchable content per message.
const MAX_CONTENT_BYTES: usize = 1024 * 1024;
/// Cap for tool invocation arguments.
const MAX_ARGS_BYTES: usize = 128 * 1024;
/// Cap for a message `extra` JSON blob.
const MAX_EXTRA_BYTES: usize = 256 * 1024;
/// Cap for an individual URL.
const MAX_URL_BYTES: usize = 8 * 1024;
/// Recursive content rendering depth limit.
const MAX_RENDER_DEPTH: usize = 32;
/// Messages fetched per keyset batch.
const MESSAGE_BATCH_ROWS: usize = 512;
/// Title bound when derived from the first user message.
const MAX_TITLE_CHARS: usize = 120;
/// Incremental-scan overlap window (ms) applied to `since_ts`.
const SINCE_OVERLAP_MS: i64 = 2_000;

/// Environment override naming one explicit Shelley database.
pub const SHELLEY_DB_ENV: &str = "CASS_SHELLEY_DB";

pub struct ShelleyConnector;

impl Default for ShelleyConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Candidate expansion
// ---------------------------------------------------------------------------

/// How a candidate database path was configured, which controls admission
/// strictness and error behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateKind {
    /// Explicit file/env configuration: signature admission, hard errors.
    Explicit,
    /// Automatically derived (`shelley.db` under a root/preset/default):
    /// migration-record admission, silent non-match.
    Auto,
}

#[derive(Debug, Clone)]
struct Candidate {
    root: ScanRoot,
    kind: CandidateKind,
}

fn dedupe_candidates(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut seen: HashSet<PathBuf> = HashSet::new();
    candidates.retain(|candidate| {
        let canonical = std::fs::canonicalize(&candidate.root.path)
            .unwrap_or_else(|_| candidate.root.path.clone());
        seen.insert(canonical)
    });
    candidates
}

/// Default local candidate paths, in priority order (pure; injectable for
/// tests): optional cass preset `~/.config/shelley/shelley.db`, Shelley's CLI
/// default `./shelley.db`, then `~/shelley.db`.
fn default_local_candidates(home: Option<&Path>, cwd: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = home {
        out.push(home.join(".config").join("shelley").join("shelley.db"));
    }
    if let Some(cwd) = cwd {
        out.push(cwd.join("shelley.db"));
    }
    if let Some(home) = home {
        out.push(home.join("shelley.db"));
    }
    out
}

impl ShelleyConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Expand scan-context roots into candidate database paths.
    ///
    /// Priority (cass gh#415): explicit file roots (any filename), explicit
    /// directory roots (`<root>/shelley.db`, `<root>/.config/shelley/shelley.db`),
    /// `CASS_SHELLEY_DB`, the cass preset, then `./shelley.db` and
    /// `~/shelley.db`. When any supplied root is remote, local defaults are
    /// NOT added.
    fn candidate_roots(ctx: &ScanContext) -> Vec<Candidate> {
        let mut out: Vec<Candidate> = Vec::new();

        if ctx.data_dir.extension().is_some_and(|ext| ext == "db") {
            // cass fixture/scoped convention: a *.db data_dir IS the database.
            out.push(Candidate {
                root: ScanRoot::local(ctx.data_dir.clone()),
                kind: CandidateKind::Explicit,
            });
            return dedupe_candidates(out);
        }

        if ctx.use_default_detection() {
            if let Some(env_db) = env_path_nonempty(SHELLEY_DB_ENV) {
                out.push(Candidate {
                    root: ScanRoot::local(env_db),
                    kind: CandidateKind::Explicit,
                });
                return dedupe_candidates(out);
            }
            let scoped = ctx.data_dir.join("shelley.db");
            if !ctx.data_dir.as_os_str().is_empty() && scoped.is_file() {
                // A shelley.db under data_dir scopes the scan to it (mirrors
                // the crush data_dir convention).
                out.push(Candidate {
                    root: ScanRoot::local(scoped),
                    kind: CandidateKind::Auto,
                });
                return dedupe_candidates(out);
            }
            for path in default_local_candidates(
                dirs::home_dir().as_deref(),
                std::env::current_dir().ok().as_deref(),
            ) {
                out.push(Candidate {
                    root: ScanRoot::local(path),
                    kind: CandidateKind::Auto,
                });
            }
            return dedupe_candidates(out);
        }

        // Explicit scan roots. Remote roots suppress local defaults entirely.
        let scoped = ctx.data_dir.join("shelley.db");
        if scoped.is_file() {
            out.push(Candidate {
                root: ScanRoot::local(scoped),
                kind: CandidateKind::Auto,
            });
        }
        for scan_root in &ctx.scan_roots {
            if scan_root.path.is_file() {
                out.push(Candidate {
                    root: scan_root.clone(),
                    kind: CandidateKind::Explicit,
                });
                continue;
            }
            out.push(Candidate {
                root: scan_root.with_path(scan_root.path.join("shelley.db")),
                kind: CandidateKind::Auto,
            });
            out.push(Candidate {
                root: scan_root.with_path(
                    scan_root
                        .path
                        .join(".config")
                        .join("shelley")
                        .join("shelley.db"),
                ),
                kind: CandidateKind::Auto,
            });
        }
        dedupe_candidates(out)
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        for candidate in Self::candidate_roots(ctx) {
            let db = candidate.root.path.clone();
            if !db.is_file() {
                continue;
            }
            // Only surface databases that pass Shelley admission: discovery
            // must never claim a foreign SQLite file for this provider.
            if admit_database(&db, candidate.kind).is_err() {
                continue;
            }
            out.push(
                DiscoveredSourceFile::new(
                    "shelley",
                    &candidate.root,
                    db.clone(),
                    DiscoveredSourceRole::SqliteDatabase,
                    true,
                )
                .with_fs_metadata(),
            );
            let wal = sidecar_path(&db, "-wal");
            if wal.is_file() {
                out.push(
                    DiscoveredSourceFile::new(
                        "shelley",
                        &candidate.root,
                        wal,
                        DiscoveredSourceRole::MetadataSidecar,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }
            let shm = sidecar_path(&db, "-shm");
            if shm.is_file() {
                out.push(
                    DiscoveredSourceFile::new(
                        "shelley",
                        &candidate.root,
                        shm,
                        DiscoveredSourceRole::MetadataSidecar,
                        false,
                    )
                    .with_fs_metadata(),
                );
            }
        }
        out
    }

    fn scan_candidates(
        ctx: &ScanContext,
        hooks: &mut SourceScanHooks<'_>,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        let mut seen_external: HashSet<String> = HashSet::new();
        for candidate in Self::candidate_roots(ctx) {
            let db = candidate.root.path.clone();
            if !db.is_file() {
                if candidate.kind == CandidateKind::Explicit {
                    bail!(
                        "shelley: configured database does not exist: {}",
                        db.display()
                    );
                }
                continue;
            }
            if candidate.root.origin.is_remote() {
                // A synced copy of a live SQLite database + WAL is not a
                // consistent snapshot; refuse rather than index stale or torn
                // contents (cass gh#415 first-implementation rule).
                match admit_database(&db, CandidateKind::Explicit) {
                    Ok(_) => bail!(
                        "shelley: remote Shelley databases are not supported yet: {} \
                         (a live SQLite database and its WAL cannot be synced as one \
                         consistent bundle; index it on the remote host instead)",
                        db.display()
                    ),
                    Err(_) => continue,
                }
            }
            // Pre-parse source identity, constructed exactly like
            // discover_sources() with size/mtime observed BEFORE the database
            // is opened (FAD#22). The predicate runs before admission so an
            // unchanged database is skipped without even being opened.
            let discovered = DiscoveredSourceFile::new(
                "shelley",
                &candidate.root,
                db.clone(),
                DiscoveredSourceRole::SqliteDatabase,
                true,
            )
            .with_fs_metadata();
            let wal = sidecar_path(&db, "-wal");
            let wal_discovered = wal.is_file().then(|| {
                DiscoveredSourceFile::new(
                    "shelley",
                    &candidate.root,
                    wal,
                    DiscoveredSourceRole::MetadataSidecar,
                    true,
                )
                .with_fs_metadata()
            });
            if !hooks.should_scan(&discovered) {
                tracing::debug!(
                    "shelley: host ledger skipped unchanged database {}",
                    db.display()
                );
                continue;
            }
            match scan_one_database(&db, candidate.kind, ctx.since_ts) {
                Ok(convs) => {
                    let mut emitted = 0usize;
                    for conv in convs {
                        let key = conv.external_id.clone().unwrap_or_default();
                        if seen_external.insert(key) {
                            on_conversation(conv)?;
                            emitted += 1;
                        }
                    }
                    // Source complete only after EVERY conversation from this
                    // database was delivered, and only when neither the
                    // database nor its WAL changed while we were reading.
                    let changed = discovered.fs_metadata_changed()
                        || wal_discovered
                            .as_ref()
                            .is_some_and(DiscoveredSourceFile::fs_metadata_changed);
                    if changed {
                        tracing::debug!(
                            "shelley: {} changed during scan; completion withheld",
                            db.display()
                        );
                    } else if emitted > 0 {
                        hooks.complete(&SourceCompletion {
                            source: discovered,
                            required_sidecars: wal_discovered.into_iter().collect(),
                            conversations_emitted: emitted,
                        })?;
                    }
                }
                Err(err) => {
                    if candidate.kind == CandidateKind::Explicit {
                        return Err(err.context(format!(
                            "shelley: failed to read configured database {}",
                            db.display()
                        )));
                    }
                    tracing::debug!(
                        "shelley: skipping candidate {}: {err:#}",
                        db.display()
                    );
                }
            }
        }
        Ok(())
    }
}

impl Connector for ShelleyConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("shelley").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        Self::scan_candidates(ctx, &mut SourceScanHooks::default(), &mut |conv| {
            convs.push(conv);
            Ok(())
        })?;
        Ok(convs)
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        Self::scan_candidates(ctx, &mut SourceScanHooks::default(), on_conversation)
    }

    fn supports_source_boundaries(&self) -> bool {
        true
    }

    fn scan_with_source_boundaries(
        &self,
        ctx: &ScanContext,
        hooks: &mut SourceScanHooks<'_>,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        Self::scan_candidates(ctx, hooks, on_conversation)
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

fn sidecar_path(db: &Path, suffix: &str) -> PathBuf {
    let mut name = db.file_name().map_or_else(String::new, |f| {
        f.to_string_lossy().into_owned()
    });
    name.push_str(suffix);
    db.with_file_name(name)
}

// ---------------------------------------------------------------------------
// Admission (schema-aware detection)
// ---------------------------------------------------------------------------

struct SchemaPlan {
    conv_cols: HashSet<String>,
    msg_cols: HashSet<String>,
}

const REQUIRED_CONV_COLS: &[&str] = &[
    "conversation_id",
    "slug",
    "user_initiated",
    "created_at",
    "updated_at",
];
const REQUIRED_MSG_COLS: &[&str] = &[
    "message_id",
    "conversation_id",
    "sequence_id",
    "type",
    "llm_data",
    "user_data",
    "usage_data",
    "created_at",
];

fn table_columns(conn: &Connection, table: &str) -> Result<HashSet<String>> {
    let rows: Vec<String> = conn
        .query_map_collect(&format!("PRAGMA table_info({table})"), &[], |row| {
            row.get_typed::<String>(1)
        })
        .with_context(|| format!("failed to read column list for table {table}"))?;
    Ok(rows.into_iter().collect())
}

/// Open `path` read-only and validate the Shelley schema signature.
///
/// `kind` controls strictness: automatically discovered candidates must also
/// carry the base migration records (`001`..`003`); explicitly configured
/// candidates are admitted on the exact required table/column signature so
/// sanitized fixtures and repaired databases remain usable.
fn admit_database(path: &Path, kind: CandidateKind) -> Result<(Connection, SchemaPlan)> {
    let conn = open_with_flags(
        path.to_string_lossy().as_ref(),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .with_context(|| format!("failed to open read-only: {}", path.display()))?;

    // Bounded busy timeout: Shelley may hold a writer on this database.
    conn.execute("PRAGMA busy_timeout = 2000;")
        .with_context(|| "failed to set busy_timeout")?;
    // Belt-and-braces on top of the read-only open flag. These pragmas are
    // best-effort: the engine already refuses writes on this handle.
    for pragma in ["PRAGMA query_only = ON;", "PRAGMA trusted_schema = OFF;"] {
        if let Err(err) = conn.execute(pragma) {
            tracing::debug!("shelley: best-effort {pragma} failed: {err}");
        }
    }

    // Required objects must be tables (not views) — a view could hide
    // arbitrary SQL behind the expected names.
    let tables: Vec<(String, String)> = conn
        .query_map_collect(
            "SELECT name, type FROM sqlite_master \
             WHERE name IN ('migrations','conversations','messages')",
            &[],
            |row| Ok((row.get_typed::<String>(0)?, row.get_typed::<String>(1)?)),
        )
        .with_context(|| "failed to read sqlite schema")?;
    let mut found: HashMap<String, String> = HashMap::new();
    for (name, ty) in tables {
        found.insert(name, ty);
    }
    for required in ["migrations", "conversations", "messages"] {
        match found.get(required) {
            Some(ty) if ty == "table" => {}
            Some(ty) => bail!("not a Shelley database: {required} is a {ty}, not a table"),
            None => bail!("not a Shelley database: missing table {required}"),
        }
    }

    let conv_cols = table_columns(&conn, "conversations")?;
    let msg_cols = table_columns(&conn, "messages")?;
    let migration_cols = table_columns(&conn, "migrations")?;
    for col in REQUIRED_CONV_COLS {
        if !conv_cols.contains(*col) {
            bail!("not a Shelley database: conversations lacks column {col}");
        }
    }
    for col in REQUIRED_MSG_COLS {
        if !msg_cols.contains(*col) {
            bail!("not a Shelley database: messages lacks column {col}");
        }
    }
    if !migration_cols.contains("migration_name") {
        bail!("not a Shelley database: migrations lacks column migration_name");
    }

    if kind == CandidateKind::Auto {
        let base_migrations: i64 = conn.query_row_map(
            "SELECT COUNT(*) FROM migrations WHERE migration_name IN \
             ('001-conversations.sql','002-messages.sql','003-add-message-sequence.sql')",
            &[],
            |row| row.get_typed::<i64>(0),
        )?;
        if base_migrations < 3 {
            bail!(
                "not an automatically admissible Shelley database: base migration \
                 records 001..003 are missing"
            );
        }
    }

    Ok((conn, SchemaPlan {
        conv_cols,
        msg_cols,
    }))
}

/// Probe one candidate path for detection purposes (schema-aware; never
/// path-existence-only). Returns `Ok` only for an admissible database.
pub(crate) fn probe_candidate(path: &Path, explicit: bool) -> Result<()> {
    let kind = if explicit {
        CandidateKind::Explicit
    } else {
        CandidateKind::Auto
    };
    admit_database(path, kind).map(|_| ())
}

/// Detection candidates for the registry's schema-aware Shelley entry:
/// `(path, explicit)` pairs, in priority order.
pub(crate) fn detection_candidates() -> Vec<(PathBuf, bool)> {
    let mut out: Vec<(PathBuf, bool)> = Vec::new();
    if let Some(env_db) = env_path_nonempty(SHELLEY_DB_ENV) {
        out.push((env_db, true));
    }
    for path in default_local_candidates(
        dirs::home_dir().as_deref(),
        std::env::current_dir().ok().as_deref(),
    ) {
        out.push((path, false));
    }
    let mut seen = HashSet::new();
    out.retain(|(path, _)| seen.insert(path.clone()));
    out
}

// ---------------------------------------------------------------------------
// Database scan
// ---------------------------------------------------------------------------

struct ConvRow {
    conversation_id: String,
    slug: Option<String>,
    user_initiated: bool,
    created_at: Option<i64>,
    updated_at: Option<i64>,
    cwd: Option<String>,
    archived: bool,
    parent_conversation_id: Option<String>,
    model: Option<String>,
    conversation_options: Option<String>,
    current_generation: Option<i64>,
    tags: Option<String>,
}

fn opt_flag(row: &frankensqlite::Row, idx: Option<usize>) -> Result<bool, frankensqlite::FrankenError> {
    idx.map_or(Ok(false), |i| {
        Ok(row.get_typed::<Option<i64>>(i)?.unwrap_or(0) != 0)
    })
}

fn opt_text(
    row: &frankensqlite::Row,
    idx: Option<usize>,
) -> Result<Option<String>, frankensqlite::FrankenError> {
    idx.map_or(Ok(None), |i| row.get_typed::<Option<String>>(i))
}

fn opt_int(
    row: &frankensqlite::Row,
    idx: Option<usize>,
) -> Result<Option<i64>, frankensqlite::FrankenError> {
    idx.map_or(Ok(None), |i| row.get_typed::<Option<i64>>(i))
}

/// Read a Shelley DATETIME column leniently: TEXT timestamps from Go drivers
/// in several layouts, or numeric epoch seconds/milliseconds.
fn read_ts(row: &frankensqlite::Row, idx: usize) -> Option<i64> {
    if let Ok(Some(text)) = row.get_typed::<Option<String>>(idx) {
        if let Some(ms) = parse_shelley_timestamp(&text) {
            return Some(ms);
        }
    }
    if let Ok(Some(n)) = row.get_typed::<Option<i64>>(idx) {
        return Some(normalize_epoch_ms(n));
    }
    None
}

const fn normalize_epoch_ms(n: i64) -> i64 {
    // Values below ~1973 in ms are interpreted as epoch seconds.
    if n.abs() < 100_000_000_000 { n.saturating_mul(1000) } else { n }
}

fn parse_shelley_timestamp(raw: &str) -> Option<i64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp_millis());
    }
    for fmt in ["%Y-%m-%d %H:%M:%S%.f %z", "%Y-%m-%d %H:%M:%S%.f%:z"] {
        if let Ok(dt) = chrono::DateTime::parse_from_str(s, fmt) {
            return Some(dt.timestamp_millis());
        }
    }
    for fmt in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Some(naive.and_utc().timestamp_millis());
        }
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(normalize_epoch_ms(n));
    }
    None
}

struct ColumnPlan {
    select: String,
    index: HashMap<&'static str, usize>,
}

fn build_column_plan(present: &HashSet<String>, required: &[&'static str], optional: &[&'static str]) -> ColumnPlan {
    let mut cols: Vec<&'static str> = Vec::new();
    cols.extend_from_slice(required);
    for col in optional {
        if present.contains(*col) {
            cols.push(*col);
        }
    }
    let mut index = HashMap::new();
    for (i, col) in cols.iter().enumerate() {
        index.insert(*col, i);
    }
    ColumnPlan {
        select: cols.join(", "),
        index,
    }
}

impl ColumnPlan {
    fn idx(&self, col: &str) -> Option<usize> {
        self.index.get(col).copied()
    }

    fn req(&self, col: &str) -> usize {
        self.index[col]
    }
}

fn load_conversations(conn: &Connection, plan: &SchemaPlan) -> Result<Vec<ConvRow>> {
    let cols = build_column_plan(
        &plan.conv_cols,
        REQUIRED_CONV_COLS,
        &[
            "cwd",
            "archived",
            "parent_conversation_id",
            "model",
            "conversation_options",
            "current_generation",
            "tags",
        ],
    );
    let sql = format!(
        "SELECT {} FROM conversations ORDER BY conversation_id",
        cols.select
    );
    conn.query_map_collect(&sql, &[], |row| {
        Ok(ConvRow {
            conversation_id: row.get_typed::<String>(cols.req("conversation_id"))?,
            slug: row.get_typed::<Option<String>>(cols.req("slug"))?,
            user_initiated: row
                .get_typed::<Option<i64>>(cols.req("user_initiated"))?
                .unwrap_or(1)
                != 0,
            created_at: read_ts(row, cols.req("created_at")),
            updated_at: read_ts(row, cols.req("updated_at")),
            cwd: opt_text(row, cols.idx("cwd"))?,
            archived: opt_flag(row, cols.idx("archived"))?,
            parent_conversation_id: opt_text(row, cols.idx("parent_conversation_id"))?,
            model: opt_text(row, cols.idx("model"))?,
            conversation_options: opt_text(row, cols.idx("conversation_options"))?,
            current_generation: opt_int(row, cols.idx("current_generation"))?,
            tags: opt_text(row, cols.idx("tags"))?,
        })
    })
    .with_context(|| "failed to read conversations")
}

struct MsgRow {
    message_id: String,
    sequence_id: i64,
    mtype: String,
    llm_data: Option<String>,
    user_data: Option<String>,
    usage_data: Option<String>,
    created_at: Option<i64>,
    display_data: Option<String>,
    excluded_from_context: bool,
    generation: i64,
    llm_api_url: Option<String>,
    model_name: Option<String>,
    forked_from_message_id: Option<String>,
    other_usage_data: Option<String>,
}

const OPTIONAL_MSG_COLS: &[&str] = &[
    "display_data",
    "excluded_from_context",
    "generation",
    "llm_api_url",
    "model_name",
    "forked_from_message_id",
    "other_usage_data",
];

/// Fetch all messages of one conversation ordered by `(sequence_id,
/// message_id)` via bounded keyset batches, invoking `on_row` per row.
fn for_each_message(
    conn: &Connection,
    plan: &SchemaPlan,
    conversation_id: &str,
    on_row: &mut dyn FnMut(MsgRow),
) -> Result<()> {
    // user_email is deliberately never selected (privacy).
    let cols = build_column_plan(&plan.msg_cols, REQUIRED_MSG_COLS, OPTIONAL_MSG_COLS);
    let sql = format!(
        "SELECT {} FROM messages WHERE conversation_id = ? \
         AND (sequence_id > ? OR (sequence_id = ? AND message_id > ?)) \
         ORDER BY sequence_id, message_id LIMIT {MESSAGE_BATCH_ROWS}",
        cols.select
    );
    let mut last_seq: i64 = i64::MIN;
    let mut last_id = String::new();
    loop {
        let params = [
            ParamValue::from(conversation_id.to_string()),
            ParamValue::from(last_seq),
            ParamValue::from(last_seq),
            ParamValue::from(last_id.clone()),
        ];
        let batch: Vec<MsgRow> = conn
            .query_map_collect(&sql, &params, |row| {
                Ok(MsgRow {
                    message_id: row.get_typed::<String>(cols.req("message_id"))?,
                    sequence_id: row.get_typed::<i64>(cols.req("sequence_id"))?,
                    mtype: row.get_typed::<String>(cols.req("type"))?,
                    llm_data: row.get_typed::<Option<String>>(cols.req("llm_data"))?,
                    user_data: row.get_typed::<Option<String>>(cols.req("user_data"))?,
                    usage_data: row.get_typed::<Option<String>>(cols.req("usage_data"))?,
                    created_at: read_ts(row, cols.req("created_at")),
                    display_data: opt_text(row, cols.idx("display_data"))?,
                    excluded_from_context: opt_flag(row, cols.idx("excluded_from_context"))?,
                    generation: opt_int(row, cols.idx("generation"))?.unwrap_or(0),
                    llm_api_url: opt_text(row, cols.idx("llm_api_url"))?,
                    model_name: opt_text(row, cols.idx("model_name"))?,
                    forked_from_message_id: opt_text(row, cols.idx("forked_from_message_id"))?,
                    other_usage_data: opt_text(row, cols.idx("other_usage_data"))?,
                })
            })
            .with_context(|| format!("failed to read messages for {conversation_id}"))?;
        let batch_len = batch.len();
        for row in batch {
            last_seq = row.sequence_id;
            last_id.clone_from(&row.message_id);
            on_row(row);
        }
        if batch_len < MESSAGE_BATCH_ROWS {
            return Ok(());
        }
    }
}

/// Per-conversation message activity summary used for incremental scans and
/// `ended_at` derivation.
fn message_activity(conn: &Connection) -> Result<HashMap<String, (i64, Option<i64>)>> {
    let rows: Vec<(String, i64, Option<String>)> = conn
        .query_map_collect(
            "SELECT conversation_id, COUNT(*), MAX(created_at) FROM messages \
             GROUP BY conversation_id",
            &[],
            |row| {
                Ok((
                    row.get_typed::<String>(0)?,
                    row.get_typed::<i64>(1)?,
                    row.get_typed::<Option<String>>(2)?,
                ))
            },
        )
        .with_context(|| "failed to summarize message activity")?;
    Ok(rows
        .into_iter()
        .map(|(id, count, max_ts)| {
            (
                id,
                (count, max_ts.as_deref().and_then(parse_shelley_timestamp)),
            )
        })
        .collect())
}

#[allow(clippy::too_many_lines)]
fn scan_one_database(
    db_path: &Path,
    kind: CandidateKind,
    since_ts: Option<i64>,
) -> Result<Vec<NormalizedConversation>> {
    let (conn, plan) = admit_database(db_path, kind)?;
    let canonical = std::fs::canonicalize(db_path).unwrap_or_else(|_| db_path.to_path_buf());
    let namespace = database_namespace(&canonical);

    conn.read_transaction(|conn| {
        let conversations = load_conversations(conn, &plan)?;
        let activity = message_activity(conn)?;
        let mut out = Vec::new();
        for conv in conversations {
            let (message_count, last_msg_ts) = activity
                .get(&conv.conversation_id)
                .copied()
                .unwrap_or((0, None));
            if message_count == 0 {
                // Draft-only or genuinely empty conversation: nothing to index,
                // and metadata-only records must never create new rows.
                continue;
            }
            let full = since_ts.is_none_or(|since| {
                let cutoff = since.saturating_sub(SINCE_OVERLAP_MS);
                last_msg_ts.is_none_or(|ts| ts >= cutoff)
                    || conv.created_at.is_some_and(|ts| ts >= cutoff)
            });
            let projected = if full {
                project_conversation(conn, &plan, &conv, &canonical, &namespace, last_msg_ts)?
            } else {
                Some(metadata_only_conversation(
                    &conv,
                    &canonical,
                    &namespace,
                    message_count,
                    last_msg_ts,
                ))
            };
            if let Some(projected) = projected {
                out.push(projected);
            }
        }
        Ok(out)
    })
}

/// First 16 hex characters of `blake3(canonical_db_path)`: the per-database
/// namespace that keeps conversation IDs from independent databases distinct.
fn database_namespace(canonical: &Path) -> String {
    let digest = blake3::hash(canonical.to_string_lossy().as_bytes());
    digest.to_hex().as_str()[..16].to_string()
}

fn shelley_external_id(namespace: &str, conversation_id: &str) -> String {
    format!("shelley:{namespace}:{conversation_id}")
}

fn conversation_metadata(
    conv: &ConvRow,
    namespace: &str,
    message_count: i64,
    omitted_system: usize,
    omitted_carried: usize,
    duplicate_sequence_ids: &[i64],
    metadata_only: bool,
) -> Value {
    let tags: Value = conv
        .tags
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    let options = conv
        .conversation_options
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .map_or_else(
            || json!(null),
            |opts| {
                // Allowlist only known non-secret option keys; hook URLs and
                // anything unrecognized stay out.
                let mut safe = serde_json::Map::new();
                for key in ["thinking_level", "disable_all_tools", "disable_notifications"] {
                    if let Some(v) = opts.get(key) {
                        safe.insert(key.to_string(), v.clone());
                    }
                }
                Value::Object(safe)
            },
        );
    let mut shelley = serde_json::Map::new();
    shelley.insert("conversation_id".into(), json!(conv.conversation_id));
    shelley.insert("database_namespace".into(), json!(namespace));
    shelley.insert("user_initiated".into(), json!(conv.user_initiated));
    shelley.insert(
        "parent_conversation_id".into(),
        json!(conv.parent_conversation_id),
    );
    shelley.insert("archived".into(), json!(conv.archived));
    shelley.insert("current_generation".into(), json!(conv.current_generation));
    shelley.insert("configured_model".into(), json!(conv.model));
    shelley.insert("tags".into(), tags);
    shelley.insert("options".into(), options);
    shelley.insert("message_count".into(), json!(message_count));
    shelley.insert(
        "omitted_system_prompt_count".into(),
        json!(omitted_system),
    );
    shelley.insert(
        "omitted_carried_message_count".into(),
        json!(omitted_carried),
    );
    if !duplicate_sequence_ids.is_empty() {
        shelley.insert(
            "corrupt_duplicate_sequence_ids".into(),
            json!(duplicate_sequence_ids),
        );
    }
    if metadata_only {
        shelley.insert("metadata_only".into(), json!(true));
    }
    json!({ "source": "shelley", "shelley": Value::Object(shelley) })
}

fn conversation_shell(
    conv: &ConvRow,
    canonical: &Path,
    namespace: &str,
    title: Option<String>,
    ended_at: Option<i64>,
    metadata: Value,
    messages: Vec<NormalizedMessage>,
) -> NormalizedConversation {
    NormalizedConversation {
        agent_slug: "shelley".into(),
        external_id: Some(shelley_external_id(namespace, &conv.conversation_id)),
        title,
        workspace: conv.cwd.as_deref().map(PathBuf::from),
        source_path: canonical.to_path_buf(),
        started_at: conv.created_at,
        ended_at: ended_at.or(conv.updated_at),
        metadata,
        messages,
    }
}

fn metadata_only_conversation(
    conv: &ConvRow,
    canonical: &Path,
    namespace: &str,
    message_count: i64,
    last_msg_ts: Option<i64>,
) -> NormalizedConversation {
    let metadata = conversation_metadata(conv, namespace, message_count, 0, 0, &[], true);
    conversation_shell(
        conv,
        canonical,
        namespace,
        conv.slug.clone(),
        last_msg_ts,
        metadata,
        Vec::new(),
    )
}

#[allow(clippy::too_many_lines)]
fn project_conversation(
    db: &Connection,
    plan: &SchemaPlan,
    conv: &ConvRow,
    canonical: &Path,
    namespace: &str,
    last_msg_ts: Option<i64>,
) -> Result<Option<NormalizedConversation>> {
    let mut projected: Vec<ProjectedMessage> = Vec::new();
    let mut omitted_system = 0usize;
    let mut tool_names: HashMap<String, String> = HashMap::new();
    let mut seen_seq: HashSet<i64> = HashSet::new();
    let mut duplicate_seq: Vec<i64> = Vec::new();

    for_each_message(db, plan, &conv.conversation_id, &mut |row| {
        if !seen_seq.insert(row.sequence_id) {
            duplicate_seq.push(row.sequence_id);
        }
        match project_message(&row, &mut tool_names) {
            Projection::Message(msg) => projected.push(*msg),
            Projection::SystemPromptOmitted => omitted_system += 1,
            Projection::Skipped => {}
        }
    })?;

    if !duplicate_seq.is_empty() {
        tracing::warn!(
            "shelley: conversation {} in {} has duplicate sequence_id values {:?} \
             (source corruption; rows retained)",
            conv.conversation_id,
            canonical.display(),
            duplicate_seq
        );
    }

    let omitted_carried = suppress_carried_duplicates(&mut projected);

    let messages: Vec<NormalizedMessage> = projected
        .into_iter()
        .map(ProjectedMessage::into_normalized)
        .collect();
    if messages.is_empty() {
        return Ok(None);
    }

    let title = conv
        .slug
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            messages
                .iter()
                .filter(|m| m.role == "user")
                .find_map(|m| {
                    let line = m.content.lines().find(|l| !l.trim().is_empty())?;
                    Some(line.trim().chars().take(MAX_TITLE_CHARS).collect::<String>())
                })
        });

    let ended_at = messages
        .iter()
        .filter_map(|m| m.created_at)
        .max()
        .or(last_msg_ts);
    let metadata = conversation_metadata(
        conv,
        namespace,
        i64::try_from(messages.len()).unwrap_or(i64::MAX),
        omitted_system,
        omitted_carried,
        &duplicate_seq,
        false,
    );
    Ok(Some(conversation_shell(
        conv,
        canonical,
        namespace,
        title,
        ended_at,
        metadata,
        messages,
    )))
}

// ---------------------------------------------------------------------------
// Message projection
// ---------------------------------------------------------------------------

/// Persisted Go `llm.Message` (exported field names; ints from a shared iota).
#[derive(Deserialize, Default)]
struct LlmMessage {
    #[serde(rename = "Role", default)]
    role: i64,
    #[serde(rename = "Content", default)]
    content: Vec<LlmContent>,
    #[serde(rename = "ErrorType", default)]
    error_type: Option<String>,
    #[serde(rename = "ErrorRetryable", default)]
    error_retryable: bool,
    #[serde(rename = "RefusalCategory", default)]
    refusal_category: Option<String>,
    #[serde(rename = "RefusalExplanation", default)]
    refusal_explanation: Option<String>,
    #[serde(rename = "EndOfTurn", default)]
    end_of_turn: bool,
}

#[derive(Deserialize, Default)]
struct LlmContent {
    #[serde(rename = "ID", default)]
    id: Option<String>,
    #[serde(rename = "Type", default)]
    ctype: i64,
    #[serde(rename = "Text", default)]
    text: Option<String>,
    #[serde(rename = "Thinking", default)]
    thinking: Option<String>,
    #[serde(rename = "MediaType", default)]
    media_type: Option<String>,
    #[serde(rename = "Data", default)]
    data: Option<String>,
    #[serde(rename = "ToolName", default)]
    tool_name: Option<String>,
    #[serde(rename = "ToolInput", default)]
    tool_input: Option<Value>,
    #[serde(rename = "ToolUseID", default)]
    tool_use_id: Option<String>,
    #[serde(rename = "ToolError", default)]
    tool_error: bool,
    #[serde(rename = "ToolResult", default)]
    tool_result: Vec<Self>,
    #[serde(rename = "Title", default)]
    title: Option<String>,
    #[serde(rename = "URL", default)]
    url: Option<String>,
    #[serde(rename = "PageAge", default)]
    page_age: Option<String>,
}

const CONTENT_TYPE_TEXT: i64 = 2;
const CONTENT_TYPE_THINKING: i64 = 3;
const CONTENT_TYPE_REDACTED_THINKING: i64 = 4;
const CONTENT_TYPE_TOOL_USE: i64 = 5;
const CONTENT_TYPE_TOOL_RESULT: i64 = 6;
const CONTENT_TYPE_SERVER_TOOL_USE: i64 = 7;
const CONTENT_TYPE_WEB_SEARCH_SET: i64 = 8;
const CONTENT_TYPE_WEB_SEARCH_RESULT: i64 = 9;

struct ProjectedMessage {
    sequence_id: i64,
    role: String,
    author: Option<String>,
    created_at: Option<i64>,
    content: String,
    extra: serde_json::Map<String, Value>,
    invocations: Vec<NormalizedInvocation>,
    generation: i64,
    carried: bool,
    match_key: [u8; 32],
}

impl ProjectedMessage {
    fn into_normalized(self) -> NormalizedMessage {
        NormalizedMessage {
            idx: self.sequence_id,
            role: self.role,
            author: self.author,
            created_at: self.created_at,
            content: self.content,
            extra: Value::Object(self.extra),
            invocations: self.invocations,
            snippets: Vec::new(),
        }
    }
}

enum Projection {
    Message(Box<ProjectedMessage>),
    SystemPromptOmitted,
    Skipped,
}

impl Projection {
    fn message(msg: ProjectedMessage) -> Self {
        Self::Message(Box::new(msg))
    }
}

/// Parse an optional raw JSON column with the pre-deserialization size cap.
fn parse_bounded_json(raw: Option<&str>, what: &str, message_id: &str) -> Option<Value> {
    let raw = raw?;
    if raw.len() > MAX_RAW_FIELD_BYTES {
        tracing::debug!(
            "shelley: {what} for message {message_id} exceeds {MAX_RAW_FIELD_BYTES} bytes; omitted"
        );
        return None;
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(value) => Some(value),
        Err(err) => {
            tracing::debug!("shelley: malformed {what} for message {message_id}: {err}");
            None
        }
    }
}

fn user_data_str<'a>(user_data: Option<&'a Value>, key: &str) -> Option<&'a str> {
    user_data?.get(key)?.as_str()
}

fn user_data_truthy(user_data: Option<&Value>, key: &str) -> bool {
    user_data.and_then(|d| d.get(key)).is_some_and(|v| {
        v.as_bool()
            .unwrap_or_else(|| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("true")))
    })
}

#[allow(clippy::too_many_lines)]
fn project_message(row: &MsgRow, tool_names: &mut HashMap<String, String>) -> Projection {
    if row.mtype == "slug" {
        // Slug-generation bookkeeping rows carry no searchable content.
        return Projection::Skipped;
    }

    let user_data = parse_bounded_json(row.user_data.as_deref(), "user_data", &row.message_id);
    let ud = user_data.as_ref();

    let llm: Option<LlmMessage> = row
        .llm_data
        .as_deref()
        .filter(|raw| raw.len() <= MAX_RAW_FIELD_BYTES)
        .and_then(|raw| match serde_json::from_str::<LlmMessage>(raw) {
            Ok(msg) => Some(msg),
            Err(err) => {
                tracing::debug!(
                    "shelley: malformed llm_data for message {}: {err}",
                    row.message_id
                );
                None
            }
        });

    // Render LLM content blocks (also resolves the tool-use ID -> name map).
    // "Only tool results" is judged on the TOP-LEVEL blocks (never the
    // recursively rendered children): Shelley stores tool results as
    // user-role LLM messages, and such rows normalize to role=tool.
    let mut rendered = RenderedContent::default();
    let mut only_tool_results = false;
    if let Some(llm) = llm.as_ref() {
        only_tool_results = !llm.content.is_empty()
            && llm.content.iter().all(|block| {
                matches!(
                    block.ctype,
                    CONTENT_TYPE_TOOL_RESULT | CONTENT_TYPE_WEB_SEARCH_SET
                )
            });
        render_blocks(&llm.content, 0, tool_names, row, &mut rendered);
    }

    let distilled = user_data_truthy(ud, "distilled");
    let distill_status = user_data_str(ud, "distill_status").map(str::to_string);
    let carried = user_data_truthy(ud, "compaction_carried");
    let ud_text = user_data_str(ud, "text").map(str::to_string);

    // Role + content per row type (cass gh#415 role-mapping table).
    let (role, mut content, author): (String, String, Option<String>) = match row.mtype.as_str() {
        "user" => {
            let role = if only_tool_results && !rendered.parts.is_empty() {
                "tool"
            } else {
                "user"
            };
            (role.to_string(), rendered.parts.join("\n"), Some("user".to_string()))
        }
        "agent" => (
            "assistant".to_string(),
            rendered.parts.join("\n"),
            row.model_name.clone(),
        ),
        "tool" => ("tool".to_string(), rendered.parts.join("\n"), None),
        "error" => ("system".to_string(), rendered.parts.join("\n"), None),
        "warning" | "gitinfo" | "modelchange" => {
            let label = row.mtype.as_str();
            let text = ud_text.as_deref().unwrap_or_default();
            ("system".to_string(), format!("[{label}] {text}"), None)
        }
        "system" => {
            let recognized = distilled
                || distill_status.is_some()
                || ud_text.is_some()
                || user_data_truthy(ud, "cwd_change");
            if !recognized {
                // Generated system prompt + tool schema: skip entirely.
                return Projection::SystemPromptOmitted;
            }
            let text = ud_text
                .as_deref()
                .map_or_else(|| rendered.parts.join("\n"), str::to_string);
            ("system".to_string(), text, None)
        }
        other => {
            // Unknown row type: derive the role from a valid LLM role when
            // present, otherwise preserve the original type as a system event.
            llm.as_ref().map_or_else(
                || {
                    (
                        "system".to_string(),
                        format!("[{other}] {}", ud_text.clone().unwrap_or_default()),
                        None,
                    )
                },
                |msg| {
                    let role = if msg.role == 1 { "assistant" } else { "user" };
                    (role.to_string(), rendered.parts.join("\n"), None)
                },
            )
        }
    };

    // Distillation summaries are real searchable content.
    if distilled {
        if let Some(summary) = user_data_str(ud, "distillation_content") {
            content = summary.to_string();
        }
    } else if let Some(status) = distill_status.as_deref() {
        if content.trim().is_empty() {
            content = format!("[Distillation status: {status}]");
        }
    }
    if user_data_truthy(ud, "cwd_change") {
        let from = user_data_str(ud, "from").unwrap_or_default();
        let to = user_data_str(ud, "to").unwrap_or_default();
        if content.trim().is_empty() {
            content = format!("[cwd change] {from} -> {to}");
        }
    }

    let content = bound_text(&content, MAX_CONTENT_BYTES);
    let match_key = carried_match_key(&row.mtype, &role, &content);

    // --- extra ---
    let mut extra = serde_json::Map::new();
    extra.insert("message_id".into(), json!(row.message_id));
    extra.insert("sequence_id".into(), json!(row.sequence_id));
    extra.insert("shelley_type".into(), json!(row.mtype));
    extra.insert("generation".into(), json!(row.generation));
    if row.excluded_from_context {
        extra.insert("excluded_from_context".into(), json!(true));
    }
    if let Some(model) = row.model_name.as_deref() {
        extra.insert("model_name".into(), json!(model));
    }
    if let Some(llm) = llm.as_ref() {
        if llm.end_of_turn {
            extra.insert("end_of_turn".into(), json!(true));
        }
        if let Some(error_type) = llm.error_type.as_deref().filter(|e| !e.is_empty()) {
            extra.insert("error_type".into(), json!(error_type));
            extra.insert("error_retryable".into(), json!(llm.error_retryable));
            if let Some(cat) = llm.refusal_category.as_deref().filter(|c| !c.is_empty()) {
                extra.insert("refusal_category".into(), json!(cat));
            }
            if let Some(expl) = llm
                .refusal_explanation
                .as_deref()
                .filter(|e| !e.is_empty())
            {
                extra.insert(
                    "refusal_explanation".into(),
                    json!(bound_text(expl, 4096)),
                );
            }
        }
    }
    if let Some(url) = row.llm_api_url.as_deref().and_then(sanitize_url) {
        extra.insert("llm_api_url".into(), json!(url));
    }
    if distilled {
        extra.insert("distilled".into(), json!(true));
    }
    if let Some(status) = distill_status {
        extra.insert("distill_status".into(), json!(status));
    }
    if rendered.tool_call_count > 0 {
        extra.insert(
            "cass".into(),
            json!({ "tool_call_count": rendered.tool_call_count }),
        );
    }

    let fork_copied = row.forked_from_message_id.is_some();
    if fork_copied {
        // Copied rows must not double-count usage: mark them for the token
        // extractor's explicit suppressed state and omit the usage block.
        extra.insert("fork_copied".into(), json!(true));
        extra.insert(
            "forked_from_message_id".into(),
            json!(row.forked_from_message_id),
        );
    } else {
        if let Some(usage) =
            parse_bounded_json(row.usage_data.as_deref(), "usage_data", &row.message_id)
        {
            if let Some(bounded) = bounded_usage(&usage) {
                extra.insert("usage".into(), bounded);
            }
        }
        if let Some(other) = parse_bounded_json(
            row.other_usage_data.as_deref(),
            "other_usage_data",
            &row.message_id,
        ) {
            if let Some(bounded) = bounded_other_usage(&other) {
                extra.insert("other_usage".into(), bounded);
            }
        }
    }

    enforce_extra_budget(&mut extra);

    if content.trim().is_empty() && rendered.invocations.is_empty() {
        return Projection::Skipped;
    }

    Projection::message(ProjectedMessage {
        sequence_id: row.sequence_id,
        role,
        author,
        created_at: row.created_at,
        content,
        extra,
        invocations: rendered.invocations,
        generation: row.generation,
        carried,
        match_key,
    })
}

fn carried_match_key(mtype: &str, role: &str, content: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(mtype.as_bytes());
    hasher.update(&[0]);
    hasher.update(role.as_bytes());
    hasher.update(&[0]);
    hasher.update(content.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Suppress compaction-carried duplicates: a carried row that matches the
/// nearest unconsumed prior-generation row (by type/role/content, never by
/// timestamp) is dropped and counted; an unmatched carried row is retained
/// and flagged. Returns the omitted count.
fn suppress_carried_duplicates(projected: &mut Vec<ProjectedMessage>) -> usize {
    let mut consumed: Vec<bool> = vec![false; projected.len()];
    let mut suppress: Vec<bool> = vec![false; projected.len()];
    let mut omitted = 0usize;
    for i in 0..projected.len() {
        if !projected[i].carried {
            continue;
        }
        let mut matched = false;
        for j in (0..i).rev() {
            if consumed[j] || suppress[j] {
                continue;
            }
            if projected[j].generation < projected[i].generation
                && projected[j].match_key == projected[i].match_key
            {
                consumed[j] = true;
                matched = true;
                break;
            }
        }
        if matched {
            suppress[i] = true;
            omitted += 1;
        } else {
            projected[i]
                .extra
                .insert("unmatched_carried".into(), json!(true));
        }
    }
    let mut keep = suppress.iter().map(|s| !s);
    projected.retain(|_| keep.next().unwrap_or(true));
    omitted
}

// ---------------------------------------------------------------------------
// Content-block rendering
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RenderedContent {
    parts: Vec<String>,
    invocations: Vec<NormalizedInvocation>,
    tool_call_count: u32,
}

#[allow(clippy::too_many_lines)]
fn render_blocks(
    blocks: &[LlmContent],
    depth: usize,
    tool_names: &mut HashMap<String, String>,
    row: &MsgRow,
    out: &mut RenderedContent,
) {
    if depth >= MAX_RENDER_DEPTH {
        out.parts.push("[content omitted: depth limit]".to_string());
        return;
    }
    for block in blocks {
        let is_image = block
            .media_type
            .as_deref()
            .is_some_and(|m| !m.is_empty())
            && block.data.as_deref().is_some_and(|d| !d.is_empty());

        if is_image {
            // Never emit base64 bytes; a placeholder with MIME + size + digest.
            let data = block.data.as_deref().unwrap_or_default();
            let approx_bytes = data.len() / 4 * 3;
            let digest = blake3::hash(data.as_bytes());
            out.parts.push(format!(
                "[image: {} ~{} bytes blake3:{}]",
                block.media_type.as_deref().unwrap_or("unknown"),
                approx_bytes,
                &digest.to_hex().as_str()[..16]
            ));
            continue;
        }

        match block.ctype {
            CONTENT_TYPE_TEXT => {
                if let Some(text) = block.text.as_deref().filter(|t| !t.is_empty()) {
                    out.parts.push(text.to_string());
                }
            }
            CONTENT_TYPE_THINKING => {
                if let Some(thinking) = block.thinking.as_deref().filter(|t| !t.is_empty()) {
                    out.parts.push(format!("[Thinking]\n{thinking}"));
                }
            }
            CONTENT_TYPE_REDACTED_THINKING => {
                // Never emit Data or Signature.
                out.parts.push("[Redacted thinking]".to_string());
            }
            CONTENT_TYPE_TOOL_USE | CONTENT_TYPE_SERVER_TOOL_USE => {
                let name = block
                    .tool_name
                    .clone()
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| "tool".to_string());
                if let Some(id) = block.id.as_deref().filter(|i| !i.is_empty()) {
                    tool_names.insert(id.to_string(), name.clone());
                }
                let args_text = block
                    .tool_input
                    .as_ref()
                    .map(|input| {
                        bound_text(
                            &serde_json::to_string(input).unwrap_or_default(),
                            MAX_ARGS_BYTES,
                        )
                    })
                    .unwrap_or_default();
                let label = if block.ctype == CONTENT_TYPE_SERVER_TOOL_USE {
                    "Server tool call"
                } else {
                    "Tool call"
                };
                out.parts.push(format!("[{label}: {name}]\n{args_text}"));
                out.tool_call_count = out.tool_call_count.saturating_add(1);
                out.invocations.push(NormalizedInvocation {
                    kind: "tool".to_string(),
                    name,
                    raw_name: None,
                    call_id: block.id.clone().filter(|i| !i.is_empty()),
                    arguments: block
                        .tool_input
                        .clone()
                        .map(|input| bounded_json_value(&input, MAX_ARGS_BYTES)),
                });
            }
            CONTENT_TYPE_TOOL_RESULT => {
                let name = block
                    .tool_use_id
                    .as_deref()
                    .and_then(|id| tool_names.get(id).cloned())
                    .or_else(|| display_tool_name(row))
                    .unwrap_or_else(|| "tool".to_string());
                let error_suffix = if block.tool_error { " (error)" } else { "" };
                out.parts.push(format!("[Tool result: {name}]{error_suffix}"));
                render_blocks(&block.tool_result, depth + 1, tool_names, row, out);
            }
            CONTENT_TYPE_WEB_SEARCH_SET => {
                out.parts.push("[Web search results]".to_string());
                render_blocks(&block.tool_result, depth + 1, tool_names, row, out);
            }
            CONTENT_TYPE_WEB_SEARCH_RESULT => {
                let title = block
                    .title
                    .as_deref()
                    .map(|t| bound_text(t, 512))
                    .unwrap_or_default();
                let url = block
                    .url
                    .as_deref()
                    .and_then(sanitize_url)
                    .unwrap_or_default();
                let age = block.page_age.as_deref().unwrap_or_default();
                let mut line = format!("[Web result] {title}");
                if !url.is_empty() {
                    line.push_str(" — ");
                    line.push_str(&url);
                }
                if !age.is_empty() {
                    line.push_str(" (");
                    line.push_str(age);
                    line.push(')');
                }
                out.parts.push(line);
                if let Some(text) = block.text.as_deref().filter(|t| !t.is_empty()) {
                    out.parts.push(bound_text(text, 16 * 1024));
                }
            }
            other => {
                // Unknown/forward-compatible type: keep safe visible text.
                if let Some(text) = block.text.as_deref().filter(|t| !t.is_empty()) {
                    out.parts.push(text.to_string());
                } else if let Some(thinking) =
                    block.thinking.as_deref().filter(|t| !t.is_empty())
                {
                    out.parts.push(format!("[Thinking]\n{thinking}"));
                } else {
                    out.parts.push(format!("[unsupported content type {other}]"));
                }
            }
        }
    }
}

/// Safe tool-name fallback from `display_data`: only shallow, well-known
/// string keys; never arbitrary recursive display content.
fn display_tool_name(row: &MsgRow) -> Option<String> {
    let raw = row.display_data.as_deref()?;
    if raw.len() > MAX_RAW_FIELD_BYTES {
        return None;
    }
    let value: Value = serde_json::from_str(raw).ok()?;
    for key in ["toolName", "tool_name", "name"] {
        if let Some(name) = value.get(key).and_then(Value::as_str) {
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Bounding, sanitization, usage
// ---------------------------------------------------------------------------

/// UTF-8-safe deterministic truncation: bounded head + tail plus an omitted
/// byte count and content digest. The original oversized value is never
/// retained elsewhere.
fn bound_text(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let digest = blake3::hash(s.as_bytes());
    let head_budget = max * 3 / 5;
    let tail_budget = max / 5;
    let head_end = floor_char_boundary(s, head_budget);
    let tail_start = ceil_char_boundary(s, s.len().saturating_sub(tail_budget));
    let omitted = tail_start.saturating_sub(head_end);
    format!(
        "{}\n[... omitted {omitted} bytes, blake3:{} ...]\n{}",
        &s[..head_end],
        &digest.to_hex().as_str()[..16],
        &s[tail_start..]
    )
}

fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    idx = idx.min(s.len());
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn ceil_char_boundary(s: &str, mut idx: usize) -> usize {
    idx = idx.min(s.len());
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

/// Bound a JSON value by serialized size, replacing oversized values with an
/// omission descriptor.
fn bounded_json_value(value: &Value, max: usize) -> Value {
    let serialized = serde_json::to_string(value).unwrap_or_default();
    if serialized.len() <= max {
        value.clone()
    } else {
        let digest = blake3::hash(serialized.as_bytes());
        json!({
            "omitted": true,
            "bytes": serialized.len(),
            "blake3": &digest.to_hex().as_str()[..16],
        })
    }
}

/// Sanitize a URL to `http`/`https`, removing userinfo, query, and fragment,
/// bounded to [`MAX_URL_BYTES`].
fn sanitize_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_URL_BYTES * 4 {
        return None;
    }
    let mut parsed = url::Url::parse(trimmed).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    parsed.set_query(None);
    parsed.set_fragment(None);
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    let out = parsed.to_string();
    if out.len() > MAX_URL_BYTES {
        return Some(bound_text(&out, MAX_URL_BYTES));
    }
    Some(out)
}

/// Project Shelley's direct `llm.Usage` JSON into a bounded allowlisted block.
fn bounded_usage(usage: &Value) -> Option<Value> {
    let obj = usage.as_object()?;
    let mut out = serde_json::Map::new();
    for key in [
        "input_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
        "output_tokens",
        "cost_usd",
    ] {
        if let Some(v) = obj.get(key) {
            if v.is_number() {
                out.insert(key.to_string(), v.clone());
            }
        }
    }
    if let Some(model) = obj.get("model").and_then(Value::as_str) {
        if !model.is_empty() {
            out.insert("model".to_string(), json!(bound_text(model, 256)));
        }
    }
    if let Some(url) = obj.get("url").and_then(Value::as_str).and_then(sanitize_url) {
        out.insert("url".to_string(), json!(url));
    }
    if out.is_empty() {
        None
    } else {
        Some(Value::Object(out))
    }
}

/// Preserve heterogeneous indirect usage (`other_usage_data`: purposed calls,
/// potentially multiple models) as bounded structured metadata WITHOUT
/// collapsing it into one fake usage record.
fn bounded_other_usage(other: &Value) -> Option<Value> {
    let arr = other.as_array()?;
    let mut out = Vec::new();
    for entry in arr.iter().take(64) {
        let obj = entry.as_object()?;
        let mut safe = serde_json::Map::new();
        if let Some(purpose) = obj.get("purpose").and_then(Value::as_str) {
            safe.insert("purpose".to_string(), json!(bound_text(purpose, 128)));
        }
        for key in [
            "input_tokens",
            "cache_creation_input_tokens",
            "cache_read_input_tokens",
            "output_tokens",
            "cost_usd",
        ] {
            if let Some(v) = obj.get(key) {
                if v.is_number() {
                    safe.insert(key.to_string(), v.clone());
                }
            }
        }
        if let Some(model) = obj.get("model").and_then(Value::as_str) {
            if !model.is_empty() {
                safe.insert("model".to_string(), json!(bound_text(model, 256)));
            }
        }
        if let Some(url) = obj.get("url").and_then(Value::as_str).and_then(sanitize_url) {
            safe.insert("url".to_string(), json!(url));
        }
        out.push(Value::Object(safe));
    }
    if out.is_empty() {
        None
    } else {
        Some(Value::Array(out))
    }
}

/// Enforce the message-extra size budget, dropping the largest optional
/// members first.
fn enforce_extra_budget(extra: &mut serde_json::Map<String, Value>) {
    for victim in ["other_usage", "usage", "refusal_explanation"] {
        let size = serde_json::to_string(&Value::Object(extra.clone())).map_or(0, |s| s.len());
        if size <= MAX_EXTRA_BYTES {
            return;
        }
        if extra.remove(victim).is_some() {
            extra.insert(format!("{victim}_omitted"), json!(true));
        }
    }
}

#[cfg(test)]
#[allow(clippy::similar_names)] // conn/conv/convs fixture bindings are idiomatic here
mod tests {
    use super::*;
    use frankensqlite::params;

    fn fixture_schema(conn: &Connection, with_migrations: bool) {
        conn.execute_batch(
            "CREATE TABLE migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                migration_number INTEGER NOT NULL,
                migration_name TEXT NOT NULL UNIQUE,
                executed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE conversations (
                conversation_id TEXT PRIMARY KEY,
                slug TEXT,
                user_initiated BOOLEAN NOT NULL DEFAULT TRUE,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                cwd TEXT,
                archived BOOLEAN NOT NULL DEFAULT FALSE,
                parent_conversation_id TEXT,
                model TEXT,
                conversation_options TEXT NOT NULL DEFAULT '{}',
                current_generation INTEGER NOT NULL DEFAULT 0,
                tags TEXT NOT NULL DEFAULT '[]',
                is_draft BOOLEAN NOT NULL DEFAULT FALSE,
                draft TEXT NOT NULL DEFAULT '',
                queued_messages TEXT NOT NULL DEFAULT '[]'
            );
            CREATE TABLE messages (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sequence_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                llm_data TEXT,
                user_data TEXT,
                usage_data TEXT,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                display_data TEXT,
                excluded_from_context BOOLEAN NOT NULL DEFAULT FALSE,
                generation INTEGER NOT NULL DEFAULT 0,
                llm_api_url TEXT,
                model_name TEXT,
                forked_from_message_id TEXT,
                user_email TEXT,
                other_usage_data TEXT
            );",
        )
        .unwrap();
        if with_migrations {
            for (n, name) in [
                (1_i64, "001-conversations.sql"),
                (2, "002-messages.sql"),
                (3, "003-add-message-sequence.sql"),
            ] {
                conn.execute_compat(
                    "INSERT INTO migrations (migration_number, migration_name) VALUES (?, ?)",
                    params![n, name],
                )
                .unwrap();
            }
        }
    }

    fn insert_conv(conn: &Connection, id: &str, slug: Option<&str>) {
        conn.execute_compat(
            "INSERT INTO conversations (conversation_id, slug, user_initiated, created_at, updated_at, cwd)
             VALUES (?, ?, 1, '2026-08-01 10:00:00', '2026-08-01 11:00:00', '/work/proj')",
            params![id, slug],
        )
        .unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_msg(
        conn: &Connection,
        conv: &str,
        seq: i64,
        mtype: &str,
        llm: Option<&str>,
        user: Option<&str>,
        usage: Option<&str>,
        model_name: Option<&str>,
    ) {
        let message_id = format!("m{conv}-{seq}");
        conn.execute_compat(
            "INSERT INTO messages (message_id, conversation_id, sequence_id, type, llm_data,
             user_data, usage_data, created_at, model_name)
             VALUES (?, ?, ?, ?, ?, ?, ?, '2026-08-01 10:30:00', ?)",
            params![message_id, conv, seq, mtype, llm, user, usage, model_name],
        )
        .unwrap();
    }

    fn llm_text(role: i64, text: &str) -> String {
        serde_json::to_string(&json!({
            "Role": role,
            "Content": [{"Type": CONTENT_TYPE_TEXT, "Text": text}],
        }))
        .unwrap()
    }

    fn build_fixture(dir: &Path, name: &str, with_migrations: bool) -> PathBuf {
        let db_path = dir.join(name);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        fixture_schema(&conn, with_migrations);
        drop(conn);
        db_path
    }

    fn scan_path(db_path: &Path) -> Vec<NormalizedConversation> {
        let connector = ShelleyConnector::new();
        let ctx = ScanContext::local_default(db_path.to_path_buf(), None);
        connector.scan(&ctx).unwrap()
    }

    #[test]
    fn scan_projects_roles_order_and_identity() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "anything.db", false);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "c1", Some("fix-the-tests"));
        insert_msg(&conn, "c1", 1, "user", Some(&llm_text(0, "please fix it")), None, None, None);
        insert_msg(
            &conn,
            "c1",
            2,
            "agent",
            Some(&llm_text(1, "on it")),
            None,
            Some(r#"{"input_tokens":100,"output_tokens":25,"cache_read_input_tokens":7,"cost_usd":0.01,"model":"claude-opus-5"}"#),
            Some("claude-opus-5"),
        );
        // Tool-result-only user row must normalize to role=tool.
        let tool_result = serde_json::to_string(&json!({
            "Role": 0,
            "Content": [{
                "Type": CONTENT_TYPE_TOOL_RESULT,
                "ToolUseID": "tu-1",
                "ToolResult": [{"Type": CONTENT_TYPE_TEXT, "Text": "42 passed"}],
            }],
        }))
        .unwrap();
        insert_msg(&conn, "c1", 3, "user", Some(&tool_result), None, None, None);
        drop(conn);

        // Explicit *.db data_dir admits by signature (no migration rows).
        let convs = scan_path(&db_path);
        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        assert_eq!(conv.agent_slug, "shelley");
        assert_eq!(conv.title.as_deref(), Some("fix-the-tests"));
        assert_eq!(conv.workspace.as_deref(), Some(Path::new("/work/proj")));
        let external = conv.external_id.as_deref().unwrap();
        assert!(external.starts_with("shelley:"));
        assert!(external.ends_with(":c1"));
        // 16-hex namespace between the colons.
        let namespace = external.split(':').nth(1).unwrap();
        assert_eq!(namespace.len(), 16);
        assert!(namespace.chars().all(|c| c.is_ascii_hexdigit()));

        assert_eq!(conv.messages.len(), 3);
        assert_eq!(conv.messages[0].role, "user");
        assert_eq!(conv.messages[1].role, "assistant");
        assert_eq!(conv.messages[1].author.as_deref(), Some("claude-opus-5"));
        assert_eq!(conv.messages[2].role, "tool");
        // idx is the raw sequence_id, never reindexed.
        assert_eq!(conv.messages[0].idx, 1);
        assert_eq!(conv.messages[2].idx, 3);
        assert!(conv.messages[2].content.contains("42 passed"));
        let usage = conv.messages[1].extra.get("usage").unwrap();
        assert_eq!(usage.get("input_tokens").and_then(Value::as_i64), Some(100));
        assert_eq!(usage.get("cost_usd").and_then(Value::as_f64), Some(0.01));

        let meta = &conv.metadata;
        assert_eq!(
            meta.pointer("/shelley/database_namespace")
                .and_then(Value::as_str)
                .map(str::len),
            Some(16)
        );
        assert_eq!(
            meta.pointer("/shelley/conversation_id").and_then(Value::as_str),
            Some("c1")
        );
        crate::connectors::assert_discovery_covers_scan_sources(
            &ShelleyConnector::new(),
            &ScanContext::local_default(db_path.clone(), None),
        );
    }

    #[test]
    fn random_sqlite_is_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("shelley.db");
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        conn.execute("CREATE TABLE stuff (id INTEGER PRIMARY KEY, blob TEXT)")
            .unwrap();
        drop(conn);

        // Explicit configuration of a non-Shelley database is an actionable error.
        let connector = ShelleyConnector::new();
        let ctx = ScanContext::local_default(db_path.clone(), None);
        let err = connector.scan(&ctx).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("shelley"), "error should name the connector: {msg}");
        assert!(
            msg.contains(&db_path.display().to_string()),
            "error should carry the path: {msg}"
        );

        // Auto-derived candidate (directory scan root): ordinary non-match.
        let root = ScanRoot::local(tmp.path().to_path_buf());
        let ctx = ScanContext::with_roots(tmp.path().join("data"), vec![root], None);
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn auto_candidate_requires_migration_records() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Correct signature but NO migration rows.
        let db_path = build_fixture(tmp.path(), "shelley.db", false);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "c1", None);
        insert_msg(&conn, "c1", 1, "user", Some(&llm_text(0, "hello")), None, None, None);
        drop(conn);

        let connector = ShelleyConnector::new();
        // Via directory root => auto admission => rejected quietly.
        let root = ScanRoot::local(tmp.path().to_path_buf());
        let ctx = ScanContext::with_roots(tmp.path().join("data"), vec![root], None);
        assert!(connector.scan(&ctx).unwrap().is_empty());

        // Same database as an explicit file root => signature admission => scanned.
        let root = ScanRoot::local(db_path.clone());
        let ctx = ScanContext::with_roots(tmp.path().join("data"), vec![root], None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn migration_records_admit_auto_candidates() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "shelley.db", true);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "c1", None);
        insert_msg(&conn, "c1", 1, "user", Some(&llm_text(0, "hi there")), None, None, None);
        drop(conn);

        let connector = ShelleyConnector::new();
        let root = ScanRoot::local(tmp.path().to_path_buf());
        let ctx = ScanContext::with_roots(tmp.path().join("data"), vec![root], None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        // Title falls back to first user text when slug is NULL.
        assert_eq!(convs[0].title.as_deref(), Some("hi there"));
    }

    #[test]
    fn thinking_tools_and_cross_row_name_resolution() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "s.db", false);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "c1", Some("t"));
        let agent = serde_json::to_string(&json!({
            "Role": 1,
            "Content": [
                {"Type": CONTENT_TYPE_THINKING, "Thinking": "let me think"},
                {"Type": CONTENT_TYPE_REDACTED_THINKING, "Data": "SECRETBYTES", "Signature": "sig"},
                {"Type": CONTENT_TYPE_TOOL_USE, "ID": "tu-9", "ToolName": "bash",
                 "ToolInput": {"cmd": "ls"}},
            ],
        }))
        .unwrap();
        insert_msg(&conn, "c1", 1, "agent", Some(&agent), None, None, None);
        let result = serde_json::to_string(&json!({
            "Role": 0,
            "Content": [{
                "Type": CONTENT_TYPE_TOOL_RESULT,
                "ToolUseID": "tu-9",
                "ToolError": true,
                "ToolResult": [{"Type": CONTENT_TYPE_TEXT, "Text": "no such dir"}],
            }],
        }))
        .unwrap();
        insert_msg(&conn, "c1", 2, "user", Some(&result), None, None, None);
        drop(conn);

        let convs = scan_path(&db_path);
        let msgs = &convs[0].messages;
        assert!(msgs[0].content.contains("[Thinking]\nlet me think"));
        assert!(msgs[0].content.contains("[Redacted thinking]"));
        assert!(!msgs[0].content.contains("SECRETBYTES"));
        assert!(msgs[0].content.contains("[Tool call: bash]"));
        assert!(msgs[0].content.contains("\"cmd\":\"ls\""));
        assert_eq!(msgs[0].invocations.len(), 1);
        assert_eq!(msgs[0].invocations[0].name, "bash");
        assert_eq!(msgs[0].invocations[0].call_id.as_deref(), Some("tu-9"));
        assert_eq!(
            msgs[0]
                .extra
                .pointer("/cass/tool_call_count")
                .and_then(Value::as_u64),
            Some(1)
        );
        // Cross-row resolution: the later tool result knows the tool's name.
        assert!(msgs[1].content.contains("[Tool result: bash] (error)"));
        assert!(msgs[1].content.contains("no such dir"));
    }

    #[test]
    fn system_prompt_slug_and_draft_are_omitted() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "s.db", false);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "c1", Some("t"));
        // Bare system prompt row: no recognized event metadata.
        insert_msg(&conn, "c1", 1, "system", Some(&llm_text(0, "You are Shelley. Tools: ...")), None, None, None);
        insert_msg(&conn, "c1", 2, "user", Some(&llm_text(0, "hi")), None, None, None);
        insert_msg(&conn, "c1", 3, "slug", Some(&llm_text(1, "a-generated-slug")), None, None, None);
        insert_msg(
            &conn,
            "c1",
            4,
            "gitinfo",
            None,
            Some(r#"{"text":"branch main at abc123"}"#),
            None,
            None,
        );
        // Draft-only conversation must be skipped outright.
        conn.execute_compat(
            "INSERT INTO conversations (conversation_id, is_draft, draft) VALUES (?, 1, 'secret draft text')",
            params!["c-draft"],
        )
        .unwrap();
        drop(conn);

        let convs = scan_path(&db_path);
        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        assert_eq!(conv.messages.len(), 2);
        assert!(conv.messages.iter().all(|m| !m.content.contains("You are Shelley")));
        assert!(conv.messages.iter().all(|m| !m.content.contains("a-generated-slug")));
        assert!(conv.messages[1].content.contains("[gitinfo] branch main at abc123"));
        assert_eq!(conv.messages[1].role, "system");
        assert_eq!(
            conv.metadata
                .pointer("/shelley/omitted_system_prompt_count")
                .and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn fork_copies_suppress_usage() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "s.db", false);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "cf", Some("fork"));
        conn.execute_compat(
            "INSERT INTO messages (message_id, conversation_id, sequence_id, type, llm_data,
             usage_data, created_at, model_name, forked_from_message_id)
             VALUES ('mf-1', 'cf', 1, 'agent', ?, ?, '2026-08-01 10:30:00', 'claude-opus-5', 'orig-77')",
            params![
                llm_text(1, "copied answer"),
                r#"{"input_tokens":500,"output_tokens":80}"#
            ],
        )
        .unwrap();
        drop(conn);

        let convs = scan_path(&db_path);
        let msg = &convs[0].messages[0];
        assert_eq!(msg.extra.get("fork_copied").and_then(Value::as_bool), Some(true));
        assert!(msg.extra.get("usage").is_none());

        // The token extractor must return the explicit suppressed state:
        // neither API usage nor a content-length estimate.
        let usage = super::super::token_extraction::extract_tokens_for_agent(
            "shelley",
            &msg.extra,
            &msg.content,
            &msg.role,
        );
        assert!(matches!(
            usage.data_source,
            super::super::token_extraction::TokenDataSource::Suppressed
        ));
        assert!(!usage.has_token_data());
    }

    #[test]
    fn token_extraction_reads_direct_usage() {
        let extra = json!({
            "model_name": "claude-opus-5",
            "usage": {
                "input_tokens": 120,
                "output_tokens": 30,
                "cache_read_input_tokens": 11,
                "cache_creation_input_tokens": 7,
                "model": "claude-opus-5"
            },
            "cass": {"tool_call_count": 2}
        });
        let usage = super::super::token_extraction::extract_tokens_for_agent(
            "shelley", &extra, "content", "assistant",
        );
        assert_eq!(usage.input_tokens, Some(120));
        assert_eq!(usage.output_tokens, Some(30));
        assert_eq!(usage.cache_read_tokens, Some(11));
        assert_eq!(usage.cache_creation_tokens, Some(7));
        assert_eq!(usage.model_name.as_deref(), Some("claude-opus-5"));
        assert_eq!(usage.provider.as_deref(), Some("anthropic"));
        assert_eq!(usage.tool_call_count, 2);
        assert!(matches!(
            usage.data_source,
            super::super::token_extraction::TokenDataSource::Api
        ));
    }

    #[test]
    fn carried_compaction_rows_are_suppressed_and_distillation_kept() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "s.db", false);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "cc", Some("compaction"));
        // Generation 0 original.
        insert_msg(&conn, "cc", 1, "user", Some(&llm_text(0, "original question")), None, None, None);
        // Distillation summary (generation 1).
        conn.execute_compat(
            "INSERT INTO messages (message_id, conversation_id, sequence_id, type, llm_data,
             user_data, created_at, generation)
             VALUES ('mc-2', 'cc', 2, 'system', NULL, ?, '2026-08-01 10:31:00', 1)",
            params![
                r#"{"distilled":"true","distillation_content":"Summary: fixed the bug"}"#
            ],
        )
        .unwrap();
        // Carried copy of the original (generation 1, fresh timestamp).
        conn.execute_compat(
            "INSERT INTO messages (message_id, conversation_id, sequence_id, type, llm_data,
             user_data, created_at, generation)
             VALUES ('mc-3', 'cc', 3, 'user', ?, ?, '2026-08-01 10:32:00', 1)",
            params![
                llm_text(0, "original question"),
                r#"{"compaction_carried":"true"}"#
            ],
        )
        .unwrap();
        // Carried row with NO earlier match: retained + flagged.
        conn.execute_compat(
            "INSERT INTO messages (message_id, conversation_id, sequence_id, type, llm_data,
             user_data, created_at, generation)
             VALUES ('mc-4', 'cc', 4, 'user', ?, ?, '2026-08-01 10:33:00', 1)",
            params![
                llm_text(0, "never seen before"),
                r#"{"compaction_carried":"true"}"#
            ],
        )
        .unwrap();
        drop(conn);

        let convs = scan_path(&db_path);
        let conv = &convs[0];
        let contents: Vec<&str> = conv.messages.iter().map(|m| m.content.as_str()).collect();
        assert_eq!(
            contents
                .iter()
                .filter(|c| c.contains("original question"))
                .count(),
            1,
            "carried duplicate must be suppressed: {contents:?}"
        );
        assert!(contents.iter().any(|c| c.contains("Summary: fixed the bug")));
        let unmatched = conv
            .messages
            .iter()
            .find(|m| m.content.contains("never seen before"))
            .unwrap();
        assert_eq!(
            unmatched.extra.get("unmatched_carried").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            conv.metadata
                .pointer("/shelley/omitted_carried_message_count")
                .and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn duplicate_sequence_ids_are_reported_as_corruption() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "s.db", false);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "cd", Some("dup"));
        insert_msg(&conn, "cd", 1, "user", Some(&llm_text(0, "one")), None, None, None);
        conn.execute_compat(
            "INSERT INTO messages (message_id, conversation_id, sequence_id, type, llm_data, created_at)
             VALUES ('dup-b', 'cd', 1, 'user', ?, '2026-08-01 10:30:01')",
            params![llm_text(0, "two")],
        )
        .unwrap();
        drop(conn);

        let convs = scan_path(&db_path);
        let conv = &convs[0];
        // Both rows retained (data preservation), corruption surfaced.
        assert_eq!(conv.messages.len(), 2);
        assert_eq!(
            conv.metadata
                .pointer("/shelley/corrupt_duplicate_sequence_ids/0")
                .and_then(Value::as_i64),
            Some(1)
        );
    }

    #[test]
    fn incremental_scan_emits_metadata_only_records() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "s.db", false);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "c-old", Some("old-conv"));
        insert_msg(&conn, "c-old", 1, "user", Some(&llm_text(0, "ancient history")), None, None, None);
        insert_conv(&conn, "c-new", Some("new-conv"));
        conn.execute_compat(
            "INSERT INTO messages (message_id, conversation_id, sequence_id, type, llm_data, created_at)
             VALUES ('mn-1', 'c-new', 1, 'user', ?, '2026-08-20 10:00:00')",
            params![llm_text(0, "fresh message")],
        )
        .unwrap();
        drop(conn);

        // since_ts after the old conversation, before the new message.
        let since = parse_shelley_timestamp("2026-08-10 00:00:00").unwrap();
        let connector = ShelleyConnector::new();
        let ctx = ScanContext::local_default(db_path.clone(), Some(since));
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 2);
        let old = convs
            .iter()
            .find(|c| c.external_id.as_deref().unwrap().ends_with(":c-old"))
            .unwrap();
        assert!(old.messages.is_empty());
        assert_eq!(
            old.metadata
                .pointer("/shelley/metadata_only")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(old.title.as_deref(), Some("old-conv"));
        let new = convs
            .iter()
            .find(|c| c.external_id.as_deref().unwrap().ends_with(":c-new"))
            .unwrap();
        assert_eq!(new.messages.len(), 1);
        assert!(new.messages[0].content.contains("fresh message"));
    }

    #[test]
    fn remote_shelley_database_is_rejected_with_actionable_error() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "shelley.db", true);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "c1", None);
        insert_msg(&conn, "c1", 1, "user", Some(&llm_text(0, "hi")), None, None, None);
        drop(conn);

        let connector = ShelleyConnector::new();
        let remote_root = ScanRoot::remote(
            db_path.clone(),
            crate::types::Origin::remote("workstation"),
            None,
        );
        let ctx = ScanContext::with_roots(tmp.path().join("data"), vec![remote_root], None);
        let err = connector.scan(&ctx).unwrap_err();
        assert!(format!("{err:#}").contains("remote Shelley databases are not supported"));

        // A remote root WITHOUT a Shelley database is an ordinary non-match.
        let other = tempfile::TempDir::new().unwrap();
        let remote_root = ScanRoot::remote(
            other.path().to_path_buf(),
            crate::types::Origin::remote("workstation"),
            None,
        );
        let ctx = ScanContext::with_roots(tmp.path().join("data2"), vec![remote_root], None);
        assert!(connector.scan(&ctx).unwrap().is_empty());
    }

    #[test]
    fn wal_only_row_is_visible_and_reader_does_not_mutate() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "wal.db", false);
        let writer = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        let mode: String = writer
            .query_row_map("PRAGMA journal_mode=wal;", &[], |row| {
                row.get_typed::<String>(0)
            })
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        insert_conv(&writer, "cw", Some("wal-conv"));
        insert_msg(&writer, "cw", 1, "user", Some(&llm_text(0, "committed via wal")), None, None, None);

        let wal_path = sidecar_path(&db_path, "-wal");
        assert!(
            wal_path.is_file(),
            "WAL sidecar should exist while the writer holds the database"
        );
        let db_before = std::fs::read(&db_path).unwrap();
        let wal_before = std::fs::read(&wal_path).ok();

        // Read while the writer connection is still open.
        let convs = scan_path(&db_path);
        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("committed via wal"));

        // Discovery must surface the database AND the live WAL sidecar.
        let sources = ShelleyConnector::new()
            .discover_source_files(&ScanContext::local_default(db_path.clone(), None))
            .unwrap();
        assert_eq!(sources[0].role, DiscoveredSourceRole::SqliteDatabase);
        let wal_source = sources
            .iter()
            .find(|s| s.source_path == wal_path)
            .expect("discovery should list the WAL sidecar");
        assert_eq!(wal_source.role, DiscoveredSourceRole::MetadataSidecar);
        assert!(wal_source.required_for_reconstruction);

        let db_after = std::fs::read(&db_path).unwrap();
        let wal_after = std::fs::read(&wal_path).ok();
        assert_eq!(db_before, db_after, "reader must not mutate the main database");
        assert_eq!(
            wal_before.as_ref().map(Vec::len),
            wal_after.as_ref().map(Vec::len),
            "reader must not change WAL size"
        );
        assert_eq!(wal_before, wal_after, "reader must not mutate the WAL");
        drop(writer);
    }

    #[test]
    fn discovery_lists_database_and_engine_sidecars() {
        // The engine's own WAL journaling may leave real -wal/-shm sidecars
        // behind after the fixture writer closes; discovery must list the
        // database first and each PRESENT sidecar with its role. (Fabricated
        // stub sidecars are not usable here: a fake WAL correctly fails the
        // read-only open during schema admission.)
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "d.db", false);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "c1", None);
        insert_msg(&conn, "c1", 1, "user", Some(&llm_text(0, "x")), None, None, None);
        drop(conn);

        let wal_path = sidecar_path(&db_path, "-wal");
        let shm_path = sidecar_path(&db_path, "-shm");
        let connector = ShelleyConnector::new();
        let ctx = ScanContext::local_default(db_path.clone(), None);
        let sources = connector.discover_source_files(&ctx).unwrap();

        let expected =
            1 + usize::from(wal_path.is_file()) + usize::from(shm_path.is_file());
        assert_eq!(sources.len(), expected);
        assert_eq!(sources[0].role, DiscoveredSourceRole::SqliteDatabase);
        assert!(sources[0].required_for_reconstruction);
        assert_eq!(sources[0].source_path, db_path);
        if wal_path.is_file() {
            let wal = sources
                .iter()
                .find(|s| s.source_path == wal_path)
                .expect("present WAL sidecar must be discovered");
            assert_eq!(wal.role, DiscoveredSourceRole::MetadataSidecar);
            assert!(wal.required_for_reconstruction);
        }
        if shm_path.is_file() {
            let shm = sources
                .iter()
                .find(|s| s.source_path == shm_path)
                .expect("present SHM sidecar must be discovered");
            assert_eq!(shm.role, DiscoveredSourceRole::MetadataSidecar);
            assert!(!shm.required_for_reconstruction);
        }
    }

    #[test]
    fn timestamp_parser_accepts_go_layouts() {
        assert_eq!(
            parse_shelley_timestamp("2026-08-01 10:00:00"),
            parse_shelley_timestamp("2026-08-01T10:00:00Z")
        );
        assert!(parse_shelley_timestamp("2026-08-01 10:00:00.123456789+02:00").is_some());
        assert!(parse_shelley_timestamp("2026-08-01T10:00:00.5-07:00").is_some());
        assert_eq!(parse_shelley_timestamp("1733000000"), Some(1_733_000_000_000));
        assert_eq!(parse_shelley_timestamp("1733000000000"), Some(1_733_000_000_000));
        assert_eq!(parse_shelley_timestamp(""), None);
        assert_eq!(parse_shelley_timestamp("not a date"), None);
    }

    #[test]
    fn url_sanitization_strips_secrets_and_rejects_non_http() {
        assert_eq!(
            sanitize_url("https://user:pass@api.example.com/v1/messages?key=sk-123#frag").as_deref(),
            Some("https://api.example.com/v1/messages")
        );
        assert!(sanitize_url("javascript:alert(1)").is_none());
        assert!(sanitize_url("file:///etc/passwd").is_none());
        assert!(sanitize_url("").is_none());
    }

    #[test]
    fn bound_text_truncates_with_digest_and_utf8_safety() {
        let long = "é".repeat(4000);
        let bounded = bound_text(&long, 1000);
        assert!(bounded.len() < 2000);
        assert!(bounded.contains("omitted"));
        assert!(bounded.contains("blake3:"));
        // Round-trips as valid UTF-8 by construction (would have panicked on
        // a bad boundary slice above).
        assert_eq!(bound_text("short", 1000), "short");
    }

    #[test]
    fn error_rows_preserve_retry_and_refusal_metadata() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "s.db", false);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "ce", Some("err"));
        let err_msg = serde_json::to_string(&json!({
            "Role": 1,
            "Content": [{"Type": CONTENT_TYPE_TEXT, "Text": "The request failed."}],
            "ErrorType": "llm_request",
            "ErrorRetryable": true,
        }))
        .unwrap();
        insert_msg(&conn, "ce", 1, "error", Some(&err_msg), None, None, None);
        drop(conn);

        let convs = scan_path(&db_path);
        let msg = &convs[0].messages[0];
        assert_eq!(msg.role, "system");
        assert!(msg.content.contains("The request failed."));
        assert_eq!(msg.extra.get("error_type").and_then(Value::as_str), Some("llm_request"));
        assert_eq!(msg.extra.get("error_retryable").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn queued_and_draft_text_never_reach_content() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = build_fixture(tmp.path(), "s.db", false);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        conn.execute_compat(
            "INSERT INTO conversations (conversation_id, slug, draft, queued_messages)
             VALUES ('cq', 'queued', 'DRAFTSECRET', '[\"QUEUEDSECRET\"]')",
            params![],
        )
        .unwrap();
        insert_msg(&conn, "cq", 1, "user", Some(&llm_text(0, "real content")), None, None, None);
        drop(conn);

        let convs = scan_path(&db_path);
        let serialized = serde_json::to_string(&convs[0].metadata).unwrap()
            + &convs[0]
                .messages
                .iter()
                .map(|m| m.content.clone())
                .collect::<String>();
        assert!(!serialized.contains("DRAFTSECRET"));
        assert!(!serialized.contains("QUEUEDSECRET"));
    }

    /// Fixture with TWO conversations in one database — the multi-conversation
    /// single-source case that makes naive per-conversation completion unsafe.
    fn two_conversation_fixture(dir: &Path) -> PathBuf {
        let db_path = build_fixture(dir, "multi.db", false);
        let conn = Connection::open(db_path.to_string_lossy().as_ref()).unwrap();
        insert_conv(&conn, "c1", Some("first"));
        insert_msg(&conn, "c1", 1, "user", Some(&llm_text(0, "alpha")), None, None, None);
        insert_conv(&conn, "c2", Some("second"));
        insert_msg(&conn, "c2", 1, "user", Some(&llm_text(0, "beta")), None, None, None);
        drop(conn);
        db_path
    }

    #[test]
    fn source_boundaries_complete_only_after_all_conversations() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = two_conversation_fixture(tmp.path());
        let connector = ShelleyConnector::new();
        assert!(connector.supports_source_boundaries());
        let ctx = ScanContext::local_default(db_path.clone(), None);

        let mut completions: Vec<SourceCompletion> = Vec::new();
        // `emitted` is read by the completion hook and advanced by the
        // conversation callback, which coexist — share it via Cell.
        let emitted = std::cell::Cell::new(0usize);
        let seen_before_completion = std::cell::Cell::new(0usize);
        {
            let mut on_complete = |completion: &SourceCompletion| {
                completions.push(completion.clone());
                seen_before_completion.set(emitted.get());
                Ok(())
            };
            let mut hooks = SourceScanHooks {
                should_scan_source: None,
                on_source_complete: Some(&mut on_complete),
            };
            connector
                .scan_with_source_boundaries(&ctx, &mut hooks, &mut |_conv| {
                    emitted.set(emitted.get() + 1);
                    Ok(())
                })
                .unwrap();
        }
        let emitted = emitted.get();
        let seen_before_completion = seen_before_completion.get();
        assert_eq!(emitted, 2);
        assert_eq!(completions.len(), 1, "one database => one completion");
        assert_eq!(
            seen_before_completion, 2,
            "completion must fire only after BOTH conversations were delivered"
        );
        let completion = &completions[0];
        assert_eq!(completion.conversations_emitted, 2);
        assert_eq!(completion.source.provider_slug, "shelley");
        assert_eq!(completion.source.role, DiscoveredSourceRole::SqliteDatabase);

        // Identity must match discover_source_files() exactly.
        let discovered = connector.discover_source_files(&ctx).unwrap();
        let primary = &discovered[0];
        assert_eq!(completion.source.source_path, primary.source_path);
        assert_eq!(completion.source.provider_slug, primary.provider_slug);
        assert_eq!(completion.source.origin, primary.origin);
        assert_eq!(completion.source.size_bytes, primary.size_bytes);
        assert_eq!(completion.source.modified_at_ms, primary.modified_at_ms);
        // Required sidecars carry the WAL when one exists on disk.
        let wal_on_disk = sidecar_path(&db_path, "-wal").is_file();
        assert_eq!(
            completion.required_sidecars.is_empty(),
            !wal_on_disk,
            "required sidecars must mirror the on-disk WAL presence"
        );
    }

    #[test]
    fn cancellation_between_conversations_withholds_completion() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = two_conversation_fixture(tmp.path());
        let connector = ShelleyConnector::new();
        let ctx = ScanContext::local_default(db_path.clone(), None);

        let mut completions = 0usize;
        let mut emitted = 0usize;
        {
            let mut on_complete = |_c: &SourceCompletion| {
                completions += 1;
                Ok(())
            };
            let mut hooks = SourceScanHooks {
                should_scan_source: None,
                on_source_complete: Some(&mut on_complete),
            };
            let result = connector.scan_with_source_boundaries(&ctx, &mut hooks, &mut |_conv| {
                emitted += 1;
                if emitted == 1 {
                    anyhow::bail!("host cancelled mid-source");
                }
                Ok(())
            });
            assert!(result.is_err(), "cancellation must propagate");
        }
        assert_eq!(emitted, 1);
        assert_eq!(
            completions, 0,
            "a cancelled source must never emit a completion event"
        );
    }

    #[test]
    fn skip_predicate_suppresses_parse_and_completion() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = two_conversation_fixture(tmp.path());
        let connector = ShelleyConnector::new();
        let ctx = ScanContext::local_default(db_path.clone(), None);

        let mut asked: Vec<PathBuf> = Vec::new();
        let mut completions = 0usize;
        let mut emitted = 0usize;
        {
            let mut should_scan = |source: &DiscoveredSourceFile| {
                asked.push(source.source_path.clone());
                false
            };
            let mut on_complete = |_c: &SourceCompletion| {
                completions += 1;
                Ok(())
            };
            let mut hooks = SourceScanHooks {
                should_scan_source: Some(&mut should_scan),
                on_source_complete: Some(&mut on_complete),
            };
            connector
                .scan_with_source_boundaries(&ctx, &mut hooks, &mut |_conv| {
                    emitted += 1;
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(asked.len(), 1, "predicate consulted once per candidate");
        assert!(
            asked[0].ends_with("multi.db"),
            "predicate sees the pre-parse source identity"
        );
        assert_eq!(emitted, 0, "skipped source emits no conversations");
        assert_eq!(completions, 0, "skipped source emits no completion");
    }

    #[test]
    fn resume_after_skip_produces_same_conversations_as_clean_scan() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = two_conversation_fixture(tmp.path());
        let connector = ShelleyConnector::new();
        let ctx = ScanContext::local_default(db_path.clone(), None);

        // Clean scan: record the completion fingerprint and conversations.
        let mut ledger: Option<SourceCompletion> = None;
        let mut clean_ids: Vec<String> = Vec::new();
        {
            let mut on_complete = |completion: &SourceCompletion| {
                ledger = Some(completion.clone());
                Ok(())
            };
            let mut hooks = SourceScanHooks {
                should_scan_source: None,
                on_source_complete: Some(&mut on_complete),
            };
            connector
                .scan_with_source_boundaries(&ctx, &mut hooks, &mut |conv| {
                    clean_ids.push(conv.external_id.clone().unwrap_or_default());
                    Ok(())
                })
                .unwrap();
        }
        let ledger = ledger.expect("clean scan must complete the source");
        assert_eq!(clean_ids.len(), 2);

        // Resume: the ledger fingerprint still matches => everything skipped.
        let mut resumed = 0usize;
        {
            let mut should_scan = |source: &DiscoveredSourceFile| {
                !(source.source_path == ledger.source.source_path
                    && source.size_bytes == ledger.source.size_bytes
                    && source.modified_at_ms == ledger.source.modified_at_ms)
            };
            let mut hooks = SourceScanHooks {
                should_scan_source: Some(&mut should_scan),
                on_source_complete: None,
            };
            connector
                .scan_with_source_boundaries(&ctx, &mut hooks, &mut |_conv| {
                    resumed += 1;
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(resumed, 0, "unchanged source must be fully skipped on resume");
    }
}
