//! Connector for Pi's experimental durable harness
//! (`@earendil-works/pi-durable`; `franken_agent_detection#28`).
//!
//! The durable harness is NOT the ordinary pi message-file format handled by
//! [`crate::connectors::pi_wire`]: one store holds MANY conversations (the
//! root conversation, forks, and task-owned child conversations), and every
//! change is an atomic commit. Two backends persist that state:
//!
//! - **SQLite** (`openNodeSqliteStorage`): one WAL-mode database. The
//!   coding agent's experimental durable host writes it at
//!   `<agent-dir>/experimental/durable-sessions/<cwd-hash>/<ms>-<uuid>/session.sqlite`.
//!   Tables `conversations` / `entries` hold the JSON records; the
//!   `durable_schema` singleton carries the schema version (1 supported).
//! - **JSONL** (`openNodeJsonlStorage`): one directory with `main.jsonl`
//!   (`{format: 1, type: "commit", seq, writes}` markers, one per commit) plus
//!   `doc-<id>.jsonl` / `task-<id>.jsonl` sidecars. Conversation and entry
//!   records live inline in the main markers; sidecar records count only when
//!   a main marker confirms their `(seq, ordinal)`. There is no default
//!   location: JSONL stores are found under explicit scan roots only.
//!
//! What is read, and what is not:
//!
//! - Only committed state. SQLite stores are opened read-only inside one read
//!   transaction (a coherent snapshot including the live WAL; nothing is
//!   recovered or checkpointed). JSONL readers ignore a torn final line, stop
//!   at the first corrupt complete marker, and ignore unconfirmed sidecar
//!   records. No source byte is ever written.
//! - Transcript entries (`pi.user`, `pi.assistant`, `pi.tool-result`,
//!   `pi.compaction`, `pi.reset` handoffs, and extension entries that carry
//!   model messages). `pi.system` prompt/tool declarations are never indexed.
//! - Per-conversation identity and fork/ownership links from the conversation
//!   records, and the conversation's working directory and model choice from
//!   its `pi.agent` document (a complete base on every change, so no delta
//!   replay is needed). Task checkpoints, inboxes, live state and any other
//!   application documents are never read.
//!
//! Each conversation becomes one [`NormalizedConversation`] carrying only its
//! OWN entries: a fork's inherited history is linked through
//! `metadata.parent` instead of being indexed twice. Every message records
//! whether it is part of the conversation's active model context (newest
//! `head` — a reset or compaction — and per-target `edits` applied, as the
//! harness derives context).
//!
//! The format is explicitly experimental upstream; unsupported versions are
//! skipped and reported through [`PiDurableConnector::store_diagnostics`]
//! rather than guessed at.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use serde_json::{Map, Value, json};
use walkdir::WalkDir;

use super::scan::{
    DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot, SourceCompletion,
    SourceScanHooks,
};
use super::utils::{dedupe_path_key, excluded_scan_paths_from_env, path_is_excluded, read_capped};
use super::{Connector, file_modified_since, franken_detection_for_connector};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
};

/// JSONL storage `format` this connector reads.
pub const SUPPORTED_JSONL_FORMAT: i64 = 1;
/// SQLite `durable_schema.version` this connector reads.
pub const SUPPORTED_SQLITE_SCHEMA: i64 = 1;

const SESSION_DB: &str = "session.sqlite";
const MAIN_FILE: &str = "main.jsonl";
const AGENT_DOCUMENT: &str = "pi.agent";
/// Explicit roots are walked this deep looking for stores.
const EXPLICIT_WALK_DEPTH: usize = 4;
/// Fork ancestry deeper than this is treated as corrupt.
const MAX_FORK_DEPTH: usize = 256;

/// Storage backend of one durable store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableBackend {
    Sqlite,
    Jsonl,
}

impl DurableBackend {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Jsonl => "jsonl",
        }
    }
}

/// Machine-readable report about a store this connector could not read in
/// full (unsupported version, missing SQLite support, incomplete source).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableStoreDiagnostic {
    /// `main.jsonl` / `session.sqlite` path of the store.
    pub path: PathBuf,
    pub backend: DurableBackend,
    /// Stable machine key, e.g. `unsupported_version`, `sqlite_support_not_compiled`,
    /// `torn_final_marker`, `corrupt_marker`, `unreadable`.
    pub code: &'static str,
    pub detail: String,
}

/// One store found on disk.
#[derive(Debug, Clone)]
struct StoreCandidate {
    root: ScanRoot,
    /// `session.sqlite` file or `main.jsonl` file.
    path: PathBuf,
    backend: DurableBackend,
}

/// Committed records of one store, independent of the backend.
#[derive(Default)]
struct DurableStore {
    format_version: i64,
    conversations: BTreeMap<i64, Value>,
    /// `EntryRecord`s ordered by (Session-global, ordered) entry id.
    entries: Vec<Value>,
    /// Latest `pi.agent` value per conversation id.
    agents: HashMap<i64, Value>,
    /// Non-fatal fidelity notes surfaced in conversation metadata.
    notes: Vec<Value>,
}

pub struct PiDurableConnector;

impl Default for PiDurableConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl PiDurableConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Default durable-session roots: `<agent-dir>/experimental/durable-sessions`
    /// where the agent dir is `PI_CODING_AGENT_DIR` (non-empty) or `~/.pi/agent`.
    fn default_store_roots() -> Vec<PathBuf> {
        let agent_dir = dotenvy::var("PI_CODING_AGENT_DIR")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(|v| crate::expand_leading_tilde(&v, dirs::home_dir().as_deref()))
            .or_else(|| dirs::home_dir().map(|home| home.join(".pi").join("agent")));
        agent_dir
            .map(|dir| vec![durable_root_of(&dir)])
            .unwrap_or_default()
    }

    /// Every store reachable from the scan context, deduplicated, honoring
    /// `CASS_EXCLUDE_PATHS`.
    fn candidates(ctx: &ScanContext) -> Vec<StoreCandidate> {
        let mut out = Vec::new();
        if ctx.use_default_detection() {
            let roots = if is_durable_root(&ctx.data_dir) {
                vec![ctx.data_dir.clone()]
            } else if ctx
                .data_dir
                .join("experimental")
                .join("durable-sessions")
                .is_dir()
            {
                vec![durable_root_of(&ctx.data_dir)]
            } else {
                Self::default_store_roots()
            };
            for root in roots {
                collect_default_layout(&ScanRoot::local(root), &mut out);
            }
        } else {
            for scan_root in &ctx.scan_roots {
                collect_explicit(scan_root, &mut out);
            }
        }

        let excluded = excluded_scan_paths_from_env();
        let mut seen = HashSet::new();
        out.retain(|candidate| {
            !path_is_excluded(&candidate.path, &excluded)
                && seen.insert(dedupe_path_key(&candidate.path))
        });
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    /// Stores that were found but cannot be read in full, with the reason.
    ///
    /// Lets a host (e.g. `cass diag --json`) report the compatibility boundary
    /// explicitly instead of implying full coverage: unsupported format or
    /// schema versions, SQLite stores in builds without the `pi-durable`
    /// feature, remote SQLite stores, and incomplete JSONL commit logs.
    #[must_use]
    pub fn store_diagnostics(&self, ctx: &ScanContext) -> Vec<DurableStoreDiagnostic> {
        let mut out = Vec::new();
        for candidate in Self::candidates(ctx) {
            match read_store(&candidate) {
                Ok(store) => {
                    for note in &store.notes {
                        out.push(DurableStoreDiagnostic {
                            path: candidate.path.clone(),
                            backend: candidate.backend,
                            code: note_code(note),
                            detail: note
                                .get("detail")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                        });
                    }
                }
                Err(err) => out.push(diagnostic_from_error(&candidate, &err)),
            }
        }
        out
    }
}

/// `<agent-dir>/experimental/durable-sessions`.
fn durable_root_of(agent_dir: &Path) -> PathBuf {
    agent_dir.join("experimental").join("durable-sessions")
}

fn is_durable_root(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == "durable-sessions")
}

/// `<24 lowercase hex>`: the host's per-cwd directory.
fn is_cwd_hash_dir(name: &str) -> bool {
    name.len() == 24 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `<13 digits>-<uuid>`: one durable session directory.
fn is_session_dir(name: &str) -> bool {
    let Some((millis, uuid)) = name.split_once('-') else {
        return false;
    };
    millis.len() == 13
        && millis.bytes().all(|b| b.is_ascii_digit())
        && uuid.len() == 36
        && uuid
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'-'))
}

/// Walk the host's exact `durable-sessions/<cwd-hash>/<session>/session.sqlite`
/// layout. Nothing else under the root is claimed.
fn collect_default_layout(root: &ScanRoot, out: &mut Vec<StoreCandidate>) {
    let Ok(hash_dirs) = std::fs::read_dir(&root.path) else {
        return;
    };
    for hash_dir in hash_dirs.flatten() {
        let hash_path = hash_dir.path();
        if !hash_path.is_dir() || !hash_dir.file_name().to_str().is_some_and(is_cwd_hash_dir) {
            continue;
        }
        let Ok(sessions) = std::fs::read_dir(&hash_path) else {
            continue;
        };
        for session in sessions.flatten() {
            if !session.file_name().to_str().is_some_and(is_session_dir) {
                continue;
            }
            let db = session.path().join(SESSION_DB);
            if db.is_file() {
                out.push(StoreCandidate {
                    root: root.clone(),
                    path: db,
                    backend: DurableBackend::Sqlite,
                });
            }
        }
    }
}

/// Whether `main.jsonl` starts with a durable commit marker (any format
/// version, so newer stores are reported rather than silently ignored).
fn looks_like_jsonl_store(main: &Path) -> bool {
    use std::io::{BufRead, BufReader, Read};
    let Ok(file) = std::fs::File::open(main) else {
        return false;
    };
    // Markers can be large; cap the sniff so a stray huge file is not slurped.
    let mut first = String::new();
    if BufReader::new(file.take(1 << 20))
        .read_line(&mut first)
        .is_err()
    {
        return false;
    }
    serde_json::from_str::<Value>(first.trim()).is_ok_and(|v| {
        v.get("type").and_then(Value::as_str) == Some("commit")
            && v.get("format").is_some_and(Value::is_i64)
            && v.get("writes").is_some_and(Value::is_array)
    })
}

/// Expand one explicit scan root: a store file, a store directory, an agent
/// dir, a durable-sessions root, or any directory containing stores.
fn collect_explicit(scan_root: &ScanRoot, out: &mut Vec<StoreCandidate>) {
    let path = &scan_root.path;
    if path.is_file() {
        if path.file_name().is_some_and(|n| n == MAIN_FILE) {
            if looks_like_jsonl_store(path) {
                out.push(StoreCandidate {
                    root: scan_root.clone(),
                    path: path.clone(),
                    backend: DurableBackend::Jsonl,
                });
            }
        } else {
            // An explicitly named database file is admitted by its schema at
            // read time, whatever its name.
            out.push(StoreCandidate {
                root: scan_root.clone(),
                path: path.clone(),
                backend: DurableBackend::Sqlite,
            });
        }
        return;
    }
    if !path.is_dir() {
        return;
    }
    let agent_layout = durable_root_of(path);
    if agent_layout.is_dir() {
        collect_default_layout(&scan_root.with_path(agent_layout), out);
    }
    for entry in WalkDir::new(path)
        .max_depth(EXPLICIT_WALK_DEPTH)
        .into_iter()
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name();
        if name == SESSION_DB {
            out.push(StoreCandidate {
                root: scan_root.clone(),
                path: entry.path().to_path_buf(),
                backend: DurableBackend::Sqlite,
            });
        } else if name == MAIN_FILE && looks_like_jsonl_store(entry.path()) {
            out.push(StoreCandidate {
                root: scan_root.clone(),
                path: entry.path().to_path_buf(),
                backend: DurableBackend::Jsonl,
            });
        }
    }
}

fn sidecar_path(db: &Path, suffix: &str) -> PathBuf {
    let mut raw = db.as_os_str().to_owned();
    raw.push(suffix);
    PathBuf::from(raw)
}

fn note(code: &str, detail: impl Into<String>) -> Value {
    json!({"code": code, "detail": detail.into()})
}

fn note_code(note: &Value) -> &'static str {
    match note.get("code").and_then(Value::as_str) {
        Some("torn_final_marker") => "torn_final_marker",
        Some("corrupt_marker") => "corrupt_marker",
        Some("unconfirmed_document_record") => "unconfirmed_document_record",
        _ => "note",
    }
}

/// Typed failure reasons, so diagnostics keep a stable code.
#[derive(Debug)]
enum StoreError {
    UnsupportedVersion(String),
    #[cfg_attr(feature = "pi-durable", allow(dead_code))]
    SqliteSupportNotCompiled,
    RemoteSqlite,
    #[cfg_attr(not(feature = "pi-durable"), allow(dead_code))]
    NotADurableStore(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(detail) | Self::NotADurableStore(detail) => {
                f.write_str(detail)
            }
            Self::SqliteSupportNotCompiled => f.write_str(
                "pi-durable SQLite stores need the `pi-durable` cargo feature in this build",
            ),
            Self::RemoteSqlite => f.write_str(
                "remote pi-durable SQLite stores are not read: a live database and its WAL \
                 cannot be synced as one consistent snapshot; index it on its own host",
            ),
        }
    }
}

impl std::error::Error for StoreError {}

fn diagnostic_from_error(
    candidate: &StoreCandidate,
    err: &anyhow::Error,
) -> DurableStoreDiagnostic {
    let code = match err.downcast_ref::<StoreError>() {
        Some(StoreError::UnsupportedVersion(_)) => "unsupported_version",
        Some(StoreError::SqliteSupportNotCompiled) => "sqlite_support_not_compiled",
        Some(StoreError::RemoteSqlite) => "remote_sqlite_unsupported",
        Some(StoreError::NotADurableStore(_)) => "not_a_durable_store",
        None => "unreadable",
    };
    DurableStoreDiagnostic {
        path: candidate.path.clone(),
        backend: candidate.backend,
        code,
        detail: format!("{err:#}"),
    }
}

fn read_store(candidate: &StoreCandidate) -> Result<DurableStore> {
    match candidate.backend {
        DurableBackend::Jsonl => read_jsonl_store(&candidate.path),
        DurableBackend::Sqlite => {
            if candidate.root.origin.is_remote() {
                return Err(StoreError::RemoteSqlite.into());
            }
            read_sqlite_store(&candidate.path)
        }
    }
}

// ---------------------------------------------------------------------------
// JSONL backend
// ---------------------------------------------------------------------------

/// A `pi.agent` document incarnation announced by the main log.
struct AgentDocument {
    conversation_id: i64,
    /// Confirmed `(seq, ordinal)` points of its sidecar records.
    points: HashSet<(i64, i64)>,
    retired: bool,
}

fn as_i64(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64)
}

/// Read the committed state of a JSONL store from its `main.jsonl`.
#[allow(clippy::too_many_lines)]
fn read_jsonl_store(main: &Path) -> Result<DurableStore> {
    let content = read_capped(main)?
        .ok_or_else(|| anyhow!("{} is over the scan size cap", main.display()))?;
    let mut store = DurableStore {
        format_version: SUPPORTED_JSONL_FORMAT,
        ..DurableStore::default()
    };
    let mut documents: BTreeMap<i64, AgentDocument> = BTreeMap::new();

    // Only newline-terminated lines are complete; the final segment (if any)
    // is a torn, unacknowledged append.
    let mut segments: Vec<&str> = content.split('\n').collect();
    let torn_tail = segments.pop().unwrap_or_default();
    if !torn_tail.trim().is_empty() {
        store.notes.push(note(
            "torn_final_marker",
            "main.jsonl ends with an incomplete marker; that commit is ignored",
        ));
    }

    for (index, line) in segments.iter().enumerate() {
        let line = line.trim_start_matches('\u{feff}').trim();
        if line.is_empty() {
            continue;
        }
        let Ok(marker) = serde_json::from_str::<Value>(line) else {
            store.notes.push(note(
                "corrupt_marker",
                format!(
                    "main.jsonl line {} is malformed; it and later commits are ignored",
                    index + 1
                ),
            ));
            break;
        };
        let format = as_i64(marker.get("format"));
        if format != Some(SUPPORTED_JSONL_FORMAT) {
            return Err(StoreError::UnsupportedVersion(format!(
                "main.jsonl line {} has format {:?}; only format {SUPPORTED_JSONL_FORMAT} is supported",
                index + 1,
                marker.get("format")
            ))
            .into());
        }
        let (Some(seq), Some(writes)) = (
            as_i64(marker.get("seq")),
            marker.get("writes").and_then(Value::as_array),
        ) else {
            store.notes.push(note(
                "corrupt_marker",
                format!(
                    "main.jsonl line {} is not a commit marker; it and later commits are ignored",
                    index + 1
                ),
            ));
            break;
        };
        if marker.get("type").and_then(Value::as_str) != Some("commit") {
            store.notes.push(note(
                "corrupt_marker",
                format!(
                    "main.jsonl line {} is not a commit marker; it and later commits are ignored",
                    index + 1
                ),
            ));
            break;
        }

        for write in writes {
            match write.get("type").and_then(Value::as_str) {
                Some("conversation") => {
                    if let Some(value) = write.get("value") {
                        if let Some(id) = as_i64(value.get("id")) {
                            store.conversations.insert(id, value.clone());
                        }
                    }
                }
                Some("entry") => {
                    if let Some(value) = write.get("value") {
                        if as_i64(value.get("id")).is_some() {
                            store.entries.push(value.clone());
                        }
                    }
                }
                Some("document.create") => {
                    let Some(record) = write.get("record") else {
                        continue;
                    };
                    if record.get("kind").and_then(Value::as_str) != Some(AGENT_DOCUMENT)
                        || record.pointer("/scope/kind").and_then(Value::as_str)
                            != Some("conversation")
                    {
                        continue;
                    }
                    let (Some(id), Some(conversation_id), Some(ordinal)) = (
                        as_i64(record.get("id")),
                        as_i64(record.pointer("/scope/conversationId")),
                        as_i64(write.get("ordinal")),
                    ) else {
                        continue;
                    };
                    documents.insert(
                        id,
                        AgentDocument {
                            conversation_id,
                            points: HashSet::from([(seq, ordinal)]),
                            retired: false,
                        },
                    );
                }
                Some("document.change") => {
                    if let (Some(id), Some(ordinal)) =
                        (as_i64(write.get("id")), as_i64(write.get("ordinal")))
                    {
                        if let Some(doc) = documents.get_mut(&id) {
                            doc.points.insert((seq, ordinal));
                        }
                    }
                }
                Some("document.retire") => {
                    if let Some(doc) = as_i64(write.get("id")).and_then(|id| documents.get_mut(&id))
                    {
                        doc.retired = true;
                    }
                }
                // Tasks, task sidecars and submissions are never read.
                _ => {}
            }
        }
    }

    store
        .entries
        .sort_by_key(|entry| as_i64(entry.get("id")).unwrap_or(i64::MAX));

    let dir = main.parent().unwrap_or_else(|| Path::new("."));
    // Ascending ids: a later incarnation for the same conversation wins.
    for (id, doc) in &documents {
        if doc.retired {
            continue;
        }
        if let Some(value) = latest_confirmed_base(&dir.join(format!("doc-{id}.jsonl")), *id, doc) {
            store.agents.insert(doc.conversation_id, value);
        }
    }
    Ok(store)
}

/// Newest confirmed complete base in one `pi.agent` sidecar.
fn latest_confirmed_base(sidecar: &Path, id: i64, doc: &AgentDocument) -> Option<Value> {
    let content = read_capped(sidecar).ok().flatten()?;
    let mut best: Option<(i64, Value)> = None;
    let mut segments: Vec<&str> = content.split('\n').collect();
    segments.pop(); // torn or empty tail: never confirmed
    for line in segments {
        let Ok(record) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        let (Some(seq), Some(ordinal)) = (as_i64(record.get("seq")), as_i64(record.get("ordinal")))
        else {
            continue;
        };
        if record.get("type").and_then(Value::as_str) != Some("record")
            || record.pointer("/payload/type").and_then(Value::as_str) != Some("document")
            || as_i64(record.pointer("/payload/id")) != Some(id)
            || !doc.points.contains(&(seq, ordinal))
        {
            continue;
        }
        if record
            .pointer("/payload/content/kind")
            .and_then(Value::as_str)
            != Some("base")
        {
            continue;
        }
        let Some(value) = record
            .pointer("/payload/content/value")
            .filter(|v| v.is_object())
        else {
            continue;
        };
        if best.as_ref().is_none_or(|(best_seq, _)| seq >= *best_seq) {
            best = Some((seq, value.clone()));
        }
    }
    best.map(|(_, value)| value)
}

// ---------------------------------------------------------------------------
// SQLite backend
// ---------------------------------------------------------------------------

#[cfg(not(feature = "pi-durable"))]
fn read_sqlite_store(path: &Path) -> Result<DurableStore> {
    let _ = path;
    Err(StoreError::SqliteSupportNotCompiled.into())
}

#[cfg(feature = "pi-durable")]
#[allow(clippy::too_many_lines)]
fn read_sqlite_store(path: &Path) -> Result<DurableStore> {
    use super::sqlite_sync::{ConnectionExt, open_with_flags};
    use anyhow::Context as _;
    use frankensqlite::compat::{OpenFlags, ParamValue, RowExt};

    let conn = open_with_flags(
        path.to_string_lossy().as_ref(),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .with_context(|| format!("failed to open read-only: {}", path.display()))?;
    // The harness may hold the writer; wait briefly instead of failing.
    conn.execute("PRAGMA busy_timeout = 2000;")
        .with_context(|| "failed to set busy_timeout")?;
    for pragma in ["PRAGMA query_only = ON;", "PRAGMA trusted_schema = OFF;"] {
        if let Err(err) = conn.execute(pragma) {
            tracing::debug!("pi_durable: best-effort {pragma} failed: {err}");
        }
    }

    // Admission: every object must be a real table (a view could hide
    // arbitrary SQL behind an expected name).
    let objects: Vec<(String, String)> = conn
        .query_map_collect(
            "SELECT name, type FROM sqlite_master WHERE name IN \
             ('durable_schema','conversations','entries','documents','document_revisions')",
            &[],
            |row| Ok((row.get_typed::<String>(0)?, row.get_typed::<String>(1)?)),
        )
        .with_context(|| "failed to read sqlite schema")?;
    let found: HashMap<String, String> = objects.into_iter().collect();
    for required in [
        "durable_schema",
        "conversations",
        "entries",
        "documents",
        "document_revisions",
    ] {
        match found.get(required).map(String::as_str) {
            Some("table") => {}
            Some(other) => {
                return Err(StoreError::NotADurableStore(format!(
                    "{}: {required} is a {other}, not a table",
                    path.display()
                ))
                .into());
            }
            None => {
                return Err(StoreError::NotADurableStore(format!(
                    "{}: missing table {required}",
                    path.display()
                ))
                .into());
            }
        }
    }

    conn.read_transaction(|conn| -> Result<DurableStore> {
        let version: i64 = conn
            .query_row_map(
                "SELECT version FROM durable_schema WHERE singleton = 1",
                &[],
                |row| row.get_typed::<i64>(0),
            )
            .with_context(|| "failed to read durable_schema")?;
        if version != SUPPORTED_SQLITE_SCHEMA {
            return Err(StoreError::UnsupportedVersion(format!(
                "{}: durable schema version {version}; only {SUPPORTED_SQLITE_SCHEMA} is supported",
                path.display()
            ))
            .into());
        }
        let mut store = DurableStore {
            format_version: version,
            ..DurableStore::default()
        };

        let parse = |raw: &str| serde_json::from_str::<Value>(raw).ok();
        let conversations: Vec<(i64, String)> = conn.query_map_collect(
            "SELECT id, record FROM conversations ORDER BY id",
            &[],
            |row| Ok((row.get_typed::<i64>(0)?, row.get_typed::<String>(1)?)),
        )?;
        for (id, raw) in conversations {
            if let Some(value) = parse(&raw) {
                store.conversations.insert(id, value);
            }
        }
        let entries: Vec<String> =
            conn.query_map_collect("SELECT record FROM entries ORDER BY id", &[], |row| {
                row.get_typed::<String>(0)
            })?;
        store.entries = entries.iter().filter_map(|raw| parse(raw)).collect();

        let documents: Vec<(i64, String)> = conn.query_map_collect(
            "SELECT id, record FROM documents WHERE retired_at IS NULL ORDER BY id",
            &[],
            |row| Ok((row.get_typed::<i64>(0)?, row.get_typed::<String>(1)?)),
        )?;
        for (id, raw) in documents {
            let Some(record) = parse(&raw) else {
                continue;
            };
            if record.get("kind").and_then(Value::as_str) != Some(AGENT_DOCUMENT)
                || record.pointer("/scope/kind").and_then(Value::as_str) != Some("conversation")
            {
                continue;
            }
            let Some(conversation_id) = as_i64(record.pointer("/scope/conversationId")) else {
                continue;
            };
            // `pi.agent` stores a complete base on every change.
            let bases: Vec<String> = conn.query_map_collect(
                "SELECT content FROM document_revisions \
                 WHERE document_id = ?1 AND kind = 'base' ORDER BY seq DESC LIMIT 1",
                &[ParamValue::from(id)],
                |row| row.get_typed::<String>(0),
            )?;
            if let Some(value) = bases
                .first()
                .and_then(|raw| parse(raw))
                .filter(Value::is_object)
            {
                store.agents.insert(conversation_id, value);
            }
        }
        Ok(store)
    })
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// Identity of the store a conversation came from.
struct StoreIdentity {
    backend: DurableBackend,
    /// Stable id: the session directory name for the host layout, else a
    /// hash of the canonical store path.
    store_id: String,
    source_path: PathBuf,
}

/// FNV-1a 64: a stable, dependency-free path fingerprint.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn store_identity(candidate: &StoreCandidate) -> StoreIdentity {
    let session_dir = candidate
        .path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .filter(|name| candidate.backend == DurableBackend::Sqlite && is_session_dir(name));
    let store_id = session_dir.map_or_else(
        || {
            let canonical =
                std::fs::canonicalize(&candidate.path).unwrap_or_else(|_| candidate.path.clone());
            format!("{:016x}", fnv1a64(canonical.to_string_lossy().as_bytes()))
        },
        str::to_string,
    );
    StoreIdentity {
        backend: candidate.backend,
        store_id,
        source_path: candidate.path.clone(),
    }
}

fn external_id(identity: &StoreIdentity, conversation_id: i64) -> String {
    format!("pi_durable:{}:{conversation_id}", identity.store_id)
}

/// Entries visible to one conversation: its own entries plus each ancestor's
/// entries up to that fork's `parent.at` cap. Ordered by entry id.
fn visible_entries<'a>(
    store: &'a DurableStore,
    by_conversation: &HashMap<i64, Vec<&'a Value>>,
    conversation_id: i64,
) -> Vec<&'a Value> {
    let mut out: Vec<&Value> = Vec::new();
    let mut cursor = Some((conversation_id, i64::MAX));
    let mut seen = HashSet::new();
    while let Some((id, cap)) = cursor {
        if !seen.insert(id) || seen.len() > MAX_FORK_DEPTH {
            break;
        }
        if let Some(entries) = by_conversation.get(&id) {
            out.extend(
                entries
                    .iter()
                    .copied()
                    .filter(|e| as_i64(e.get("id")).is_some_and(|eid| eid <= cap)),
            );
        }
        // A nested fork sees an ancestor only up to the EARLIEST cap on the
        // way: C forked from B at an entry B inherited from A must not see
        // A's entries after that point.
        cursor = store.conversations.get(&id).and_then(|record| {
            Some((
                as_i64(record.pointer("/parent/conversationId"))?,
                as_i64(record.pointer("/parent/at"))?.min(cap),
            ))
        });
    }
    out.sort_by_key(|e| as_i64(e.get("id")).unwrap_or(i64::MAX));
    out
}

/// Active-context membership per visible entry id, plus edit effects,
/// following the harness's context derivation: the newest visible entry with
/// a `head` selects the range start; within the range the newest edit per
/// target wins; the head entry leads and older head entries drop out.
struct ContextView {
    in_context: HashSet<i64>,
    edits: HashMap<i64, &'static str>,
    head_entry: Option<i64>,
}

fn derive_context(visible: &[&Value]) -> ContextView {
    let head_entry = visible
        .iter()
        .rev()
        .find(|e| as_i64(e.get("head")).is_some())
        .copied();
    let from = head_entry
        .and_then(|e| as_i64(e.get("head")))
        .unwrap_or(i64::MIN);
    let head_id = head_entry.and_then(|e| as_i64(e.get("id")));

    let in_range = |entry: &Value| as_i64(entry.get("id")).is_some_and(|id| id >= from);
    let mut in_context: HashSet<i64> = visible
        .iter()
        .filter(|e| in_range(e))
        .filter(|e| head_id.is_none() || e.get("head").is_none_or(Value::is_null))
        .filter_map(|e| as_i64(e.get("id")))
        .collect();
    if let Some(head_id) = head_id {
        in_context.insert(head_id);
    }

    let mut latest: HashMap<i64, &'static str> = HashMap::new();
    for entry in visible.iter().filter(|e| in_range(e)) {
        for edit in entry
            .get("edits")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(target) = as_i64(edit.get("target")) else {
                continue;
            };
            let action = match edit.get("action").and_then(Value::as_str) {
                Some("omit") => "omitted",
                Some("replace") => "replaced",
                _ => continue,
            };
            latest.insert(target, action);
        }
    }
    let mut edits = HashMap::new();
    for (target, action) in latest {
        if !in_context.contains(&target) {
            continue;
        }
        if action == "omitted" {
            in_context.remove(&target);
        }
        edits.insert(target, action);
    }
    ContextView {
        in_context,
        edits,
        head_entry: head_id,
    }
}

/// Flatten a pi-ai message content value to searchable text.
fn message_text(message: &Value) -> String {
    message
        .get("content")
        .map(super::pi_wire::flatten_message_content)
        .unwrap_or_default()
}

fn tool_invocations(message: &Value) -> Vec<NormalizedInvocation> {
    message
        .get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("toolCall"))
                .map(|b| NormalizedInvocation {
                    kind: "tool".to_string(),
                    name: b
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string(),
                    raw_name: None,
                    call_id: b.get("id").and_then(Value::as_str).map(String::from),
                    arguments: b.get("arguments").cloned(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Working directory recorded for a conversation: its `pi.agent` `cwd`, else
/// a `cwd` system-prompt section on its visible history that is an absolute
/// path (optionally rendered as `Working directory: <path>`).
fn conversation_workspace(
    agent: Option<&Value>,
    visible: &[&Value],
) -> Option<(PathBuf, &'static str)> {
    if let Some(cwd) = agent
        .and_then(|a| a.get("cwd"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|cwd| !cwd.is_empty())
    {
        return Some((PathBuf::from(cwd), "pi.agent"));
    }
    visible
        .iter()
        .rev()
        .filter(|e| e.get("kind").and_then(Value::as_str) == Some("pi.system"))
        .filter_map(|e| e.pointer("/model/0/sections/cwd").and_then(Value::as_str))
        .map(|raw| {
            raw.trim()
                .trim_start_matches("Working directory:")
                .trim()
                .to_string()
        })
        .find(|raw| !raw.contains('\n') && Path::new(raw).is_absolute())
        .map(|cwd| (PathBuf::from(cwd), "system_section"))
}

/// Bounded, non-private projection of a `pi.agent` document.
fn agent_summary(agent: &Value) -> Value {
    let mut out = Map::new();
    for (key, out_key) in [
        ("model", "model"),
        ("thinkingLevel", "thinking_level"),
        ("extensions", "extensions"),
    ] {
        if let Some(value) = agent.get(key).filter(|v| !v.is_null()) {
            out.insert(out_key.to_string(), value.clone());
        }
    }
    Value::Object(out)
}

#[allow(clippy::too_many_lines)]
fn normalize_store(store: &DurableStore, identity: &StoreIdentity) -> Vec<NormalizedConversation> {
    let mut by_conversation: HashMap<i64, Vec<&Value>> = HashMap::new();
    for entry in &store.entries {
        if let Some(conversation_id) = as_i64(entry.get("conversationId")) {
            by_conversation
                .entry(conversation_id)
                .or_default()
                .push(entry);
        }
    }

    // Conversations with entries but no record (should not happen in a
    // committed store) are still indexed, without fork/owner links.
    let mut conversation_ids: Vec<i64> = store.conversations.keys().copied().collect();
    for id in by_conversation.keys() {
        if !store.conversations.contains_key(id) {
            conversation_ids.push(*id);
        }
    }
    conversation_ids.sort_unstable();
    conversation_ids.dedup();

    let mut out = Vec::new();
    for conversation_id in conversation_ids {
        let own = by_conversation
            .get(&conversation_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if own.is_empty() {
            continue;
        }
        let visible = visible_entries(store, &by_conversation, conversation_id);
        let view = derive_context(&visible);

        let mut messages: Vec<NormalizedMessage> = Vec::new();
        let mut system_entry_count = 0_usize;
        let mut reset_count = 0_usize;
        let mut compaction_count = 0_usize;
        let mut bookkeeping_entry_count = 0_usize;
        let mut started_at: Option<i64> = None;
        let mut ended_at: Option<i64> = None;

        for entry in own {
            let Some(entry_id) = as_i64(entry.get("id")) else {
                continue;
            };
            let kind = entry.get("kind").and_then(Value::as_str).unwrap_or("");
            match kind {
                "pi.system" => {
                    system_entry_count += 1;
                    continue;
                }
                "pi.reset" => reset_count += 1,
                "pi.compaction" => compaction_count += 1,
                _ => {}
            }
            let Some(model) = entry.get("model").and_then(Value::as_array) else {
                bookkeeping_entry_count += 1;
                continue;
            };
            for (model_index, message) in model.iter().enumerate() {
                let raw_role = message.get("role").and_then(Value::as_str).unwrap_or("");
                if raw_role == "system" {
                    continue;
                }
                let text = message_text(message);
                let (role, source_role, content) = match (kind, raw_role) {
                    ("pi.compaction", _) => (
                        "system".to_string(),
                        "compaction".to_string(),
                        format!("[compaction] {text}"),
                    ),
                    ("pi.reset", _) => ("user".to_string(), "handoff".to_string(), text),
                    (_, "toolResult") => ("tool".to_string(), raw_role.to_string(), text),
                    (_, "") => ("unknown".to_string(), String::new(), text),
                    _ => (raw_role.to_string(), raw_role.to_string(), text),
                };
                let invocations = if role == "assistant" {
                    tool_invocations(message)
                } else {
                    Vec::new()
                };
                if content.trim().is_empty() && invocations.is_empty() {
                    continue;
                }
                let created_at = message.get("timestamp").and_then(super::parse_timestamp);
                if let Some(ts) = created_at {
                    started_at = Some(started_at.map_or(ts, |c| c.min(ts)));
                    ended_at = Some(ended_at.map_or(ts, |c| c.max(ts)));
                }
                let author = match role.as_str() {
                    "assistant" => message
                        .get("model")
                        .and_then(Value::as_str)
                        .map(String::from),
                    "tool" => message
                        .get("toolName")
                        .and_then(Value::as_str)
                        .map(String::from),
                    _ => None,
                };
                let stop_reason = message.get("stopReason").and_then(Value::as_str);
                // Failed/aborted/deferred answers never reach a later request.
                let excluded_answer = role == "assistant"
                    && matches!(stop_reason, Some("aborted" | "error" | "deferred"));
                let in_active_context = view.in_context.contains(&entry_id) && !excluded_answer;

                let mut cass = Map::new();
                cass.insert("entry_kind".into(), Value::from(kind));
                cass.insert("source_role".into(), Value::from(source_role));
                cass.insert("entry_id".into(), Value::from(entry_id));
                cass.insert("conversation_id".into(), Value::from(conversation_id));
                if model.len() > 1 {
                    cass.insert("model_index".into(), Value::from(model_index));
                }
                if let Some(task) = as_i64(entry.get("byTaskId")) {
                    cass.insert("by_task_id".into(), Value::from(task));
                }
                cass.insert("in_active_context".into(), Value::Bool(in_active_context));
                if let Some(edit) = view.edits.get(&entry_id) {
                    cass.insert("context_edit".into(), Value::from(*edit));
                }
                if let Some(head) = as_i64(entry.get("head")) {
                    cass.insert("head".into(), Value::from(head));
                }
                if let Some(reason) = entry.pointer("/data/reason") {
                    cass.insert("reason".into(), reason.clone());
                }
                if role == "assistant" {
                    if let Some(model_name) = &author {
                        cass.insert("model".into(), Value::from(model_name.as_str()));
                    }
                    if let Some(provider) = message.get("provider").and_then(Value::as_str) {
                        cass.insert("provider".into(), Value::from(provider));
                    }
                }
                if let Some(stop_reason) = stop_reason {
                    cass.insert("stop_reason".into(), Value::from(stop_reason));
                }

                messages.push(NormalizedMessage {
                    idx: i64::try_from(messages.len()).unwrap_or(i64::MAX),
                    role,
                    author,
                    created_at,
                    content,
                    extra: json!({
                        "kind": kind,
                        "entry_id": entry_id,
                        "message": message,
                        "cass": cass,
                    }),
                    snippets: Vec::new(),
                    invocations,
                });
            }
        }
        if messages.is_empty() {
            continue;
        }

        let record = store.conversations.get(&conversation_id);
        let agent = store.agents.get(&conversation_id);
        let workspace = conversation_workspace(agent, &visible);
        let title = messages
            .iter()
            .find(|m| {
                m.role == "user"
                    && m.extra.pointer("/cass/source_role").and_then(Value::as_str) == Some("user")
            })
            .or_else(|| messages.iter().find(|m| m.role == "user"))
            .or_else(|| messages.first())
            .map(|m| {
                m.content
                    .lines()
                    .next()
                    .unwrap_or(&m.content)
                    .chars()
                    .take(100)
                    .collect::<String>()
            });

        let mut metadata = Map::new();
        metadata.insert("source".into(), json!("pi_durable"));
        metadata.insert(
            "store".into(),
            json!({
                "backend": identity.backend.as_str(),
                "format_version": store.format_version,
                "store_id": identity.store_id,
            }),
        );
        metadata.insert("conversation_id".into(), json!(conversation_id));
        if let Some(parent) = record.and_then(|r| r.get("parent")) {
            let parent_id = as_i64(parent.get("conversationId"));
            metadata.insert(
                "parent".into(),
                json!({
                    "conversation_id": parent_id,
                    "at_entry_id": as_i64(parent.get("at")),
                    "external_id": parent_id.map(|id| external_id(identity, id)),
                    "inherited_entries": "linked, not duplicated",
                }),
            );
        }
        if let Some(owner) = record.and_then(|r| r.get("owner")) {
            let owner_id = as_i64(owner.get("conversationId"));
            metadata.insert(
                "owner".into(),
                json!({
                    "conversation_id": owner_id,
                    "task_id": as_i64(owner.get("taskId")),
                    "external_id": owner_id.map(|id| external_id(identity, id)),
                }),
            );
        }
        if let Some(agent) = agent {
            metadata.insert("agent".into(), agent_summary(agent));
        }
        if let Some((_, source)) = &workspace {
            metadata.insert("workspace_source".into(), json!(source));
        }
        metadata.insert(
            "context".into(),
            json!({
                "derivation": "head_and_edit_aware",
                "head_entry_id": view.head_entry,
                "reset_count": reset_count,
                "compaction_count": compaction_count,
            }),
        );
        if system_entry_count > 0 {
            metadata.insert("system_entry_count".into(), json!(system_entry_count));
        }
        if bookkeeping_entry_count > 0 {
            metadata.insert(
                "bookkeeping_entry_count".into(),
                json!(bookkeeping_entry_count),
            );
        }
        if !store.notes.is_empty() {
            metadata.insert("store_notes".into(), Value::Array(store.notes.clone()));
        }

        out.push(NormalizedConversation {
            agent_slug: "pi_durable".to_string(),
            external_id: Some(external_id(identity, conversation_id)),
            title,
            workspace: workspace.map(|(path, _)| path),
            source_path: identity.source_path.clone(),
            started_at,
            ended_at,
            metadata: Value::Object(metadata),
            messages,
        });
    }
    out
}

fn store_modified_since(candidate: &StoreCandidate, since_ts: Option<i64>) -> bool {
    // A missing WAL (checkpointed on close) is not a change, but
    // `file_modified_since` treats a missing path as modified.
    let wal = sidecar_path(&candidate.path, "-wal");
    file_modified_since(&candidate.path, since_ts)
        || (candidate.backend == DurableBackend::Sqlite
            && wal.is_file()
            && file_modified_since(&wal, since_ts))
}

fn scan_candidate(candidate: &StoreCandidate) -> Result<Vec<NormalizedConversation>> {
    let store = read_store(candidate)?;
    if store.conversations.is_empty() && store.entries.is_empty() {
        return Ok(Vec::new());
    }
    Ok(normalize_store(&store, &store_identity(candidate)))
}

impl Connector for PiDurableConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("pi_durable").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut out = Vec::new();
        self.scan_with_callback(ctx, &mut |conversation| {
            out.push(conversation);
            Ok(())
        })?;
        Ok(out)
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        self.scan_with_source_boundaries(ctx, &mut SourceScanHooks::default(), on_conversation)
    }

    fn supports_source_boundaries(&self) -> bool {
        true
    }

    /// One store is one source (FAD#22): `main.jsonl` (every committed
    /// change, `pi.agent` documents included, appends a marker to it) or
    /// `session.sqlite` with its WAL as a required sidecar. Completion fires
    /// only after every conversation of the store was delivered and neither
    /// file changed while it was read.
    fn scan_with_source_boundaries(
        &self,
        ctx: &ScanContext,
        hooks: &mut SourceScanHooks<'_>,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        for candidate in Self::candidates(ctx) {
            if !store_modified_since(&candidate, ctx.since_ts) {
                continue;
            }
            let (source, sidecars) = candidate_sources(&candidate);
            if !hooks.should_scan(&source) {
                continue;
            }
            match scan_candidate(&candidate) {
                Ok(conversations) => {
                    let emitted = conversations.len();
                    for conversation in conversations {
                        on_conversation(conversation)?;
                    }
                    let changed = source.fs_metadata_changed()
                        || sidecars
                            .iter()
                            .any(DiscoveredSourceFile::fs_metadata_changed);
                    if emitted > 0 && !changed {
                        hooks.complete(&SourceCompletion {
                            source,
                            required_sidecars: sidecars,
                            conversations_emitted: emitted,
                        })?;
                    }
                }
                Err(err) => {
                    let diagnostic = diagnostic_from_error(&candidate, &err);
                    match diagnostic.code {
                        // Explicitly named files that are simply not durable
                        // stores are expected under broad roots.
                        "not_a_durable_store" => tracing::debug!(
                            path = %candidate.path.display(),
                            "pi_durable: skipping non-durable SQLite file: {}",
                            diagnostic.detail
                        ),
                        code => tracing::warn!(
                            path = %candidate.path.display(),
                            backend = candidate.backend.as_str(),
                            code,
                            "pi_durable: skipping store: {}",
                            diagnostic.detail
                        ),
                    }
                }
            }
        }
        Ok(())
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        let mut out = Vec::new();
        for candidate in Self::candidates(ctx) {
            if !store_modified_since(&candidate, ctx.since_ts) {
                continue;
            }
            let (source, required) = candidate_sources(&candidate);
            out.push(source);
            out.extend(required);
            if candidate.backend == DurableBackend::Sqlite {
                let shm = sidecar_path(&candidate.path, "-shm");
                if shm.is_file() {
                    out.push(
                        DiscoveredSourceFile::new(
                            "pi_durable",
                            &candidate.root,
                            shm,
                            DiscoveredSourceRole::MetadataSidecar,
                            false,
                        )
                        .with_fs_metadata(),
                    );
                }
            }
        }
        Ok(out)
    }
}

/// Pre-parse identity of a store: its primary source and the sidecars whose
/// fingerprints also authorize a resume skip (a SQLite WAL).
fn candidate_sources(
    candidate: &StoreCandidate,
) -> (DiscoveredSourceFile, Vec<DiscoveredSourceFile>) {
    let role = match candidate.backend {
        DurableBackend::Jsonl => DiscoveredSourceRole::PrimarySessionLog,
        DurableBackend::Sqlite => DiscoveredSourceRole::SqliteDatabase,
    };
    let source = DiscoveredSourceFile::new(
        "pi_durable",
        &candidate.root,
        candidate.path.clone(),
        role,
        true,
    )
    .with_fs_metadata();
    let mut sidecars = Vec::new();
    if candidate.backend == DurableBackend::Sqlite {
        let wal = sidecar_path(&candidate.path, "-wal");
        if wal.is_file() {
            sidecars.push(
                DiscoveredSourceFile::new(
                    "pi_durable",
                    &candidate.root,
                    wal,
                    DiscoveredSourceRole::MetadataSidecar,
                    true,
                )
                .with_fs_metadata(),
            );
        }
    }
    (source, sidecars)
}

#[cfg(test)]
#[allow(
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::format_push_string
)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    /// One logical store write, materialized per backend.
    enum W {
        Conversation(Value),
        Entry(Value),
        /// `pi.agent` incarnation: (document id, conversation id, value).
        AgentCreate(i64, i64, Value),
        /// New complete base for an existing `pi.agent` document.
        AgentChange(i64, Value),
    }

    fn msg_entry(id: i64, conversation: i64, kind: &str, message: Value) -> W {
        W::Entry(
            json!({"id": id, "conversationId": conversation, "kind": kind, "model": [message]}),
        )
    }

    fn user(text: &str, ts: i64) -> Value {
        json!({"role": "user", "content": text, "timestamp": ts})
    }

    fn assistant(text: &str, stop: &str, ts: i64) -> Value {
        json!({"role": "assistant", "content": [{"type": "text", "text": text}],
               "api": "anthropic-messages", "provider": "anthropic", "model": "claude-x",
               "usage": {"input": 3, "output": 2, "cacheRead": 0, "cacheWrite": 0, "totalTokens": 5},
               "stopReason": stop, "timestamp": ts})
    }

    /// The committed history shared by the JSONL and SQLite fixtures: a root
    /// conversation with a tool round, compaction and context edit; a fork;
    /// and a task-owned child conversation with a reset handoff.
    fn commits() -> Vec<Vec<W>> {
        let t = 1_767_600_000_000_i64;
        vec![
            vec![
                W::Conversation(json!({"id": 1})),
                W::AgentCreate(
                    2,
                    1,
                    json!({"cwd": "/work/repo", "model": {"provider": "anthropic", "modelId": "claude-x"}, "thinkingLevel": "high", "instructions": "SECRET_INSTRUCTIONS_MARKER"}),
                ),
            ],
            vec![msg_entry(10, 1, "pi.user", user("DURABLE_FIRST_PROMPT", t))],
            vec![
                msg_entry(
                    11,
                    1,
                    "pi.system",
                    json!({"role": "system", "content": "", "sections": {"preamble": "SYSTEM_SECTION_MARKER", "cwd": "/work/repo"}, "toolsAdded": [{"name": "bash", "description": "TOOL_DECL_MARKER"}], "timestamp": t + 1}),
                ),
                W::Entry(
                    json!({"id": 12, "conversationId": 1, "kind": "pi.assistant", "byTaskId": 7, "model": [{
                    "role": "assistant",
                    "content": [{"type": "text", "text": "DURABLE_ANSWER_ONE"}, {"type": "toolCall", "id": "call_1", "name": "bash", "arguments": {"command": "ls"}}],
                    "provider": "anthropic", "model": "claude-x",
                    "usage": {"input": 100, "output": 20, "cacheRead": 5, "cacheWrite": 1, "totalTokens": 126},
                    "stopReason": "toolUse", "timestamp": t + 2}]}),
                ),
            ],
            vec![W::Entry(
                json!({"id": 13, "conversationId": 1, "kind": "pi.tool-result", "byTaskId": 8, "data": {"diagnostics": []}, "model": [{
                "role": "toolResult", "toolCallId": "call_1", "toolName": "bash",
                "content": [{"type": "text", "text": "TOOL_OUTPUT_MARKER"}], "isError": false, "timestamp": t + 3}]}),
            )],
            vec![msg_entry(
                14,
                1,
                "pi.assistant",
                assistant("DURABLE_ANSWER_TWO", "stop", t + 4),
            )],
            vec![msg_entry(15, 1, "pi.user", user("SECOND_PROMPT", t + 5))],
            vec![msg_entry(
                16,
                1,
                "pi.assistant",
                assistant("ABORTED_ANSWER", "aborted", t + 6),
            )],
            vec![W::Entry(
                json!({"id": 17, "conversationId": 1, "kind": "pi.compaction", "head": 15, "data": {"reason": "threshold"},
                "model": [user("COMPACTION_SUMMARY_MARKER", t + 7)]}),
            )],
            vec![
                msg_entry(18, 1, "pi.user", user("AFTER_COMPACTION", t + 8)),
                W::Entry(
                    json!({"id": 19, "conversationId": 1, "kind": "app.context-edit", "edits": [{"target": 15, "action": "omit"}]}),
                ),
            ],
            vec![
                msg_entry(
                    20,
                    1,
                    "pi.assistant",
                    assistant("FINAL_ANSWER", "stop", t + 9),
                ),
                W::AgentChange(
                    2,
                    json!({"cwd": "/work/repo", "model": {"provider": "anthropic", "modelId": "claude-y"}}),
                ),
            ],
            vec![
                W::Conversation(json!({"id": 3, "parent": {"conversationId": 1, "at": 14}})),
                W::AgentCreate(4, 3, json!({"cwd": "/work/fork"})),
            ],
            vec![
                msg_entry(21, 3, "pi.user", user("FORK_PROMPT", t + 10)),
                msg_entry(
                    22,
                    3,
                    "pi.assistant",
                    assistant("FORK_ANSWER", "stop", t + 11),
                ),
            ],
            vec![W::Conversation(
                json!({"id": 5, "owner": {"conversationId": 1, "taskId": 7}}),
            )],
            vec![
                msg_entry(
                    23,
                    5,
                    "pi.system",
                    json!({"role": "system", "content": "", "sections": {"cwd": "Working directory: /work/child"}, "timestamp": t + 12}),
                ),
                msg_entry(24, 5, "pi.user", user("CHILD_TASK_PROMPT", t + 13)),
            ],
            vec![
                W::Entry(
                    json!({"id": 25, "conversationId": 5, "kind": "pi.reset", "head": 25, "model": [user("HANDOFF_NOTE", t + 14)]}),
                ),
                msg_entry(
                    26,
                    5,
                    "pi.assistant",
                    assistant("CHILD_ANSWER", "stop", t + 15),
                ),
            ],
        ]
    }

    fn agent_record(doc: i64, conversation: i64) -> Value {
        json!({"id": doc, "kind": "pi.agent", "scope": {"kind": "conversation", "conversationId": conversation},
               "history": "rewindable", "fork": "asOf"})
    }

    fn base(value: &Value) -> Value {
        json!({"version": 1, "kind": "base", "value": value})
    }

    /// Materialize the commits as a JSONL store, plus an unconfirmed sidecar
    /// record and a torn final marker that a reader must ignore.
    fn write_jsonl_store(dir: &Path) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let mut main = String::new();
        let mut sidecars: BTreeMap<i64, String> = BTreeMap::new();
        for (index, commit) in commits().into_iter().enumerate() {
            let seq = i64::try_from(index).unwrap() + 1;
            let mut writes = Vec::new();
            let mut ordinal = 0_i64;
            for write in commit {
                match write {
                    W::Conversation(value) => {
                        writes.push(json!({"type": "conversation", "value": value}));
                    }
                    W::Entry(value) => writes.push(json!({"type": "entry", "value": value})),
                    W::AgentCreate(doc, conversation, value) => {
                        writes.push(json!({"type": "document.create", "record": agent_record(doc, conversation), "ordinal": ordinal}));
                        let line = json!({"format": 1, "type": "record", "seq": seq, "ordinal": ordinal,
                                          "payload": {"type": "document", "id": doc, "content": base(&value)}});
                        sidecars
                            .entry(doc)
                            .or_default()
                            .push_str(&format!("{line}\n"));
                        ordinal += 1;
                    }
                    W::AgentChange(doc, value) => {
                        writes.push(
                            json!({"type": "document.change", "id": doc, "ordinal": ordinal}),
                        );
                        let line = json!({"format": 1, "type": "record", "seq": seq, "ordinal": ordinal,
                                          "payload": {"type": "document", "id": doc, "content": base(&value)}});
                        sidecars
                            .entry(doc)
                            .or_default()
                            .push_str(&format!("{line}\n"));
                        ordinal += 1;
                    }
                }
            }
            main.push_str(&format!(
                "{}\n",
                json!({"format": 1, "type": "commit", "seq": seq, "writes": writes})
            ));
        }
        // A sidecar append whose main marker never landed.
        let unconfirmed = json!({"format": 1, "type": "record", "seq": 99, "ordinal": 0,
                                 "payload": {"type": "document", "id": 2, "content": base(&json!({"cwd": "/UNCONFIRMED"}))}});
        sidecars
            .entry(2)
            .or_default()
            .push_str(&format!("{unconfirmed}\n"));
        // A torn, unacknowledged final marker.
        main.push_str(r#"{"format":1,"type":"commit","seq":100,"writes":[{"type":"entry","value":{"id":99,"conversationId":1,"kind":"pi.user","model":[{"role":"user","content":"TORN_TAIL_MARKER"}]}}"#);
        for (doc, content) in sidecars {
            fs::write(dir.join(format!("doc-{doc}.jsonl")), content).unwrap();
        }
        // A live task sidecar holding a private checkpoint: never read.
        fs::write(
            dir.join("task-7.jsonl"),
            format!("{}\n", json!({"format": 1, "type": "record", "seq": 3, "ordinal": 0, "payload": {"type": "task", "value": {"id": 7, "state": {"status": "running", "checkpoint": "TASK_CHECKPOINT_MARKER"}}}})),
        )
        .unwrap();
        let main_path = dir.join(MAIN_FILE);
        fs::write(&main_path, main).unwrap();
        main_path
    }

    fn explicit_ctx(path: &Path) -> ScanContext {
        ScanContext::with_roots(
            PathBuf::from("/nonexistent-cass-state"),
            vec![ScanRoot::local(path.to_path_buf())],
            None,
        )
    }

    fn scan(path: &Path) -> Vec<NormalizedConversation> {
        let mut convs = PiDurableConnector::new().scan(&explicit_ctx(path)).unwrap();
        convs.sort_by_key(|c| c.metadata["conversation_id"].as_i64());
        convs
    }

    fn by_id(convs: &[NormalizedConversation], id: i64) -> &NormalizedConversation {
        convs
            .iter()
            .find(|c| c.metadata["conversation_id"] == id)
            .unwrap_or_else(|| panic!("conversation {id} missing"))
    }

    fn with_text<'a>(conv: &'a NormalizedConversation, needle: &str) -> &'a NormalizedMessage {
        conv.messages
            .iter()
            .find(|m| m.content.contains(needle))
            .unwrap_or_else(|| panic!("no message contains {needle}"))
    }

    fn in_context(msg: &NormalizedMessage) -> bool {
        msg.extra["cass"]["in_active_context"].as_bool().unwrap()
    }

    /// Assertions every backend must satisfy for the shared commit history.
    fn assert_fixture_semantics(convs: &[NormalizedConversation]) {
        assert_eq!(convs.len(), 3, "root, fork and task-owned child");
        let serialized = serde_json::to_string(convs).unwrap();
        for private in [
            "SYSTEM_SECTION_MARKER",
            "TOOL_DECL_MARKER",
            "SECRET_INSTRUCTIONS_MARKER",
            "TASK_CHECKPOINT_MARKER",
            "TORN_TAIL_MARKER",
            "/UNCONFIRMED",
        ] {
            assert!(!serialized.contains(private), "{private} leaked");
        }

        let root = by_id(convs, 1);
        assert_eq!(root.agent_slug, "pi_durable");
        assert_eq!(root.workspace.as_deref(), Some(Path::new("/work/repo")));
        assert_eq!(root.metadata["workspace_source"], "pi.agent");
        assert_eq!(root.metadata["agent"]["model"]["modelId"], "claude-y");
        assert_eq!(root.title.as_deref(), Some("DURABLE_FIRST_PROMPT"));
        let roles: Vec<&str> = root.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(
            roles,
            vec![
                "user",
                "assistant",
                "tool",
                "assistant",
                "user",
                "assistant",
                "system",
                "user",
                "assistant"
            ]
        );
        let answer = with_text(root, "DURABLE_ANSWER_ONE");
        assert_eq!(answer.author.as_deref(), Some("claude-x"));
        assert_eq!(answer.invocations.len(), 1);
        assert_eq!(answer.invocations[0].call_id.as_deref(), Some("call_1"));
        assert_eq!(answer.extra["cass"]["by_task_id"], 7);
        assert_eq!(
            with_text(root, "TOOL_OUTPUT_MARKER").author.as_deref(),
            Some("bash")
        );
        let compaction = with_text(root, "COMPACTION_SUMMARY_MARKER");
        assert_eq!(compaction.role, "system");
        assert_eq!(compaction.content, "[compaction] COMPACTION_SUMMARY_MARKER");
        assert_eq!(compaction.extra["cass"]["entry_kind"], "pi.compaction");
        assert_eq!(compaction.extra["cass"]["head"], 15);
        assert_eq!(compaction.extra["cass"]["reason"], "threshold");

        // Context: the compaction heads entry 15; entry 19 omits 15; the
        // aborted answer never reaches a request.
        for summarized in [
            "DURABLE_FIRST_PROMPT",
            "DURABLE_ANSWER_ONE",
            "TOOL_OUTPUT_MARKER",
            "DURABLE_ANSWER_TWO",
        ] {
            assert!(!in_context(with_text(root, summarized)), "{summarized}");
        }
        let omitted = with_text(root, "SECOND_PROMPT");
        assert!(!in_context(omitted));
        assert_eq!(omitted.extra["cass"]["context_edit"], "omitted");
        assert!(!in_context(with_text(root, "ABORTED_ANSWER")));
        assert_eq!(
            with_text(root, "ABORTED_ANSWER").extra["cass"]["stop_reason"],
            "aborted"
        );
        for live in [
            "COMPACTION_SUMMARY_MARKER",
            "AFTER_COMPACTION",
            "FINAL_ANSWER",
        ] {
            assert!(in_context(with_text(root, live)), "{live}");
        }
        assert_eq!(root.metadata["context"]["head_entry_id"], 17);
        assert_eq!(root.metadata["system_entry_count"], 1);
        assert_eq!(root.metadata["bookkeeping_entry_count"], 1);

        // The fork indexes only its own entries and links its parent.
        let fork = by_id(convs, 3);
        let fork_text: Vec<&str> = fork.messages.iter().map(|m| m.content.as_str()).collect();
        assert_eq!(fork_text, vec!["FORK_PROMPT", "FORK_ANSWER"]);
        assert_eq!(fork.workspace.as_deref(), Some(Path::new("/work/fork")));
        assert_eq!(fork.metadata["parent"]["conversation_id"], 1);
        assert_eq!(fork.metadata["parent"]["at_entry_id"], 14);
        assert_eq!(
            fork.metadata["parent"]["external_id"],
            root.external_id.clone().unwrap()
        );
        assert!(fork.messages.iter().all(in_context));

        // The task-owned child: owner link, reset handoff, cwd from the
        // rendered system section.
        let child = by_id(convs, 5);
        assert_eq!(child.metadata["owner"]["conversation_id"], 1);
        assert_eq!(child.metadata["owner"]["task_id"], 7);
        assert_eq!(child.workspace.as_deref(), Some(Path::new("/work/child")));
        assert_eq!(child.metadata["workspace_source"], "system_section");
        let handoff = with_text(child, "HANDOFF_NOTE");
        assert_eq!(handoff.role, "user");
        assert_eq!(handoff.extra["cass"]["source_role"], "handoff");
        assert!(in_context(handoff));
        assert!(!in_context(with_text(child, "CHILD_TASK_PROMPT")));
        assert!(in_context(with_text(child, "CHILD_ANSWER")));
        assert_eq!(child.title.as_deref(), Some("CHILD_TASK_PROMPT"));

        let mut ids: Vec<&str> = convs
            .iter()
            .filter_map(|c| c.external_id.as_deref())
            .collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 3, "external ids are distinct per conversation");
    }

    fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        WalkDir::new(dir)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_file())
            .map(|e| (e.path().to_path_buf(), fs::read(e.path()).unwrap()))
            .collect()
    }

    #[test]
    fn jsonl_store_reads_committed_conversations_only() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("app-store");
        write_jsonl_store(&store);
        let before = snapshot(tmp.path());

        let convs = scan(tmp.path());
        assert_fixture_semantics(&convs);
        let root = by_id(&convs, 1);
        assert_eq!(root.metadata["store"]["backend"], "jsonl");
        assert_eq!(root.source_path, store.join(MAIN_FILE));
        assert_eq!(root.metadata["store_notes"][0]["code"], "torn_final_marker");

        assert_eq!(
            snapshot(tmp.path()),
            before,
            "indexing changed source bytes"
        );
    }

    #[test]
    fn jsonl_discovery_and_diagnostics() {
        let tmp = TempDir::new().unwrap();
        let main = write_jsonl_store(&tmp.path().join("app-store"));
        let connector = PiDurableConnector::new();
        let ctx = explicit_ctx(tmp.path());
        let sources = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source_path, main);
        assert_eq!(sources[0].role, DiscoveredSourceRole::PrimarySessionLog);
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);

        let diagnostics = connector.store_diagnostics(&ctx);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "torn_final_marker");
    }

    #[test]
    fn unsupported_jsonl_format_is_reported_not_guessed() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("future");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(MAIN_FILE),
            format!("{}\n", json!({"format": 2, "type": "commit", "seq": 1, "writes": [{"type": "entry", "value": {"id": 1, "conversationId": 1, "kind": "pi.user", "model": [{"role": "user", "content": "future"}]}}]})),
        )
        .unwrap();
        let connector = PiDurableConnector::new();
        let ctx = explicit_ctx(tmp.path());
        assert!(connector.scan(&ctx).unwrap().is_empty());
        let diagnostics = connector.store_diagnostics(&ctx);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "unsupported_version");
    }

    #[test]
    fn arbitrary_jsonl_and_corrupt_markers_are_not_claimed() {
        let tmp = TempDir::new().unwrap();
        // A main.jsonl that is not a durable commit log is never claimed.
        let other = tmp.path().join("other");
        fs::create_dir_all(&other).unwrap();
        fs::write(
            other.join(MAIN_FILE),
            "{\"type\":\"message\",\"content\":\"x\"}\n",
        )
        .unwrap();
        assert!(PiDurableConnector::candidates(&explicit_ctx(tmp.path())).is_empty());

        // A corrupt interior marker stops replay; earlier commits survive.
        let dir = tmp.path().join("store");
        fs::create_dir_all(&dir).unwrap();
        let first = json!({"format": 1, "type": "commit", "seq": 1, "writes": [
            {"type": "conversation", "value": {"id": 1}},
            {"type": "entry", "value": {"id": 2, "conversationId": 1, "kind": "pi.user", "model": [{"role": "user", "content": "before corruption"}]}}]});
        let after = json!({"format": 1, "type": "commit", "seq": 3, "writes": [
            {"type": "entry", "value": {"id": 4, "conversationId": 1, "kind": "pi.user", "model": [{"role": "user", "content": "after corruption"}]}}]});
        fs::write(
            dir.join(MAIN_FILE),
            format!("{first}\n{{not json\n{after}\n"),
        )
        .unwrap();
        let convs = PiDurableConnector::new().scan(&explicit_ctx(&dir)).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "before corruption");
        assert_eq!(
            convs[0].metadata["store_notes"][0]["code"],
            "corrupt_marker"
        );
    }

    #[test]
    fn pi_durable_token_usage_is_exact() {
        use crate::connectors::token_extraction::{TokenDataSource, extract_tokens_for_agent};
        let tmp = TempDir::new().unwrap();
        write_jsonl_store(&tmp.path().join("s"));
        let convs = scan(tmp.path());
        let answer = with_text(by_id(&convs, 1), "DURABLE_ANSWER_ONE");
        let usage =
            extract_tokens_for_agent("pi_durable", &answer.extra, &answer.content, &answer.role);
        assert_eq!(usage.data_source, TokenDataSource::Api);
        assert_eq!(usage.input_tokens, Some(100));
        assert_eq!(usage.output_tokens, Some(20));
        assert_eq!(usage.cache_read_tokens, Some(5));
        assert_eq!(usage.model_name.as_deref(), Some("claude-x"));
        assert_eq!(usage.tool_call_count, 1);
    }

    #[test]
    fn session_dir_names_and_hash_dirs_match_the_host_layout() {
        assert!(is_session_dir(
            "1767600000000-0123abcd-4567-89ef-0123-456789abcdef"
        ));
        assert!(!is_session_dir(
            "176760000000-0123abcd-4567-89ef-0123-456789abcdef"
        ));
        assert!(!is_session_dir("session"));
        assert!(is_cwd_hash_dir("0123456789abcdef01234567"));
        assert!(!is_cwd_hash_dir("0123456789ABCDEF01234567"));
        assert!(!is_cwd_hash_dir("0123456789abcdef"));
    }

    #[test]
    fn a_store_is_one_resumable_source() {
        use crate::connectors::SourceScanHooks;
        let tmp = TempDir::new().unwrap();
        let main = write_jsonl_store(&tmp.path().join("s"));
        let connector = PiDurableConnector::new();
        assert!(connector.supports_source_boundaries());
        let ctx = explicit_ctx(tmp.path());

        let mut completions = Vec::new();
        let mut on_complete = |completion: &SourceCompletion| {
            completions.push((
                completion.source.source_path.clone(),
                completion.conversations_emitted,
            ));
            Ok(())
        };
        let mut hooks = SourceScanHooks {
            should_scan_source: None,
            on_source_complete: Some(&mut on_complete),
        };
        let mut delivered = 0;
        connector
            .scan_with_source_boundaries(&ctx, &mut hooks, &mut |_| {
                delivered += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(delivered, 3);
        assert_eq!(completions, vec![(main, 3)]);

        // A skipped store yields nothing.
        let mut never = |_: &DiscoveredSourceFile| false;
        let mut hooks = SourceScanHooks {
            should_scan_source: Some(&mut never),
            on_source_complete: None,
        };
        connector
            .scan_with_source_boundaries(&ctx, &mut hooks, &mut |_| {
                panic!("skipped store must not emit")
            })
            .unwrap();
    }

    #[test]
    fn nested_forks_see_ancestors_only_up_to_the_earliest_cap() {
        // A: 10 user, 11 answer, 12 user, 13 reset(head 13), 14 answer.
        // B forks A at 14 (sees the reset). C forks B at 12, an entry B
        // inherited from A: C must not see A's reset at 13.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("s");
        fs::create_dir_all(&dir).unwrap();
        let user_entry = |id: i64, conv: i64, text: &str| json!({"type": "entry", "value": {"id": id, "conversationId": conv, "kind": "pi.user", "model": [{"role": "user", "content": text}]}});
        let commits = [
            vec![json!({"type": "conversation", "value": {"id": 1}})],
            vec![
                user_entry(10, 1, "a10"),
                user_entry(11, 1, "a11"),
                user_entry(12, 1, "a12"),
                json!({"type": "entry", "value": {"id": 13, "conversationId": 1, "kind": "pi.reset", "head": 13}}),
                user_entry(14, 1, "a14"),
            ],
            vec![
                json!({"type": "conversation", "value": {"id": 2, "parent": {"conversationId": 1, "at": 14}}}),
            ],
            vec![user_entry(20, 2, "b20")],
            vec![
                json!({"type": "conversation", "value": {"id": 3, "parent": {"conversationId": 2, "at": 12}}}),
            ],
            vec![user_entry(30, 3, "c30")],
        ];
        let mut main = String::new();
        for (i, writes) in commits.iter().enumerate() {
            main.push_str(
                &json!({"format": 1, "type": "commit", "seq": i + 1, "writes": writes}).to_string(),
            );
            main.push('\n');
        }
        fs::write(dir.join(MAIN_FILE), main).unwrap();

        let convs = scan(&dir);
        assert_eq!(by_id(&convs, 2).metadata["context"]["head_entry_id"], 13);
        assert!(by_id(&convs, 3).metadata["context"]["head_entry_id"].is_null());
    }

    #[cfg(feature = "pi-durable")]
    mod sqlite {
        use super::*;
        use crate::connectors::sqlite_sync::{Connection, ConnectionExt};
        use frankensqlite::compat::ParamValue;

        /// The upstream schema (`storage/sqlite/migrations.ts`, version 1).
        const SCHEMA: &[&str] = &[
            "CREATE TABLE durable_schema (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version INTEGER NOT NULL CHECK (version >= 0)) STRICT",
            "CREATE TABLE durable_metadata (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), next_id TEXT NOT NULL, next_seq INTEGER NOT NULL) STRICT",
            "CREATE TABLE record_ids (id INTEGER PRIMARY KEY, record_type TEXT NOT NULL) STRICT",
            "CREATE TABLE conversations (id INTEGER PRIMARY KEY, owner_conversation_id INTEGER, owner_task_id INTEGER, record TEXT NOT NULL CHECK (json_valid(record))) STRICT",
            "CREATE TABLE entries (id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL, head INTEGER, commit_seq INTEGER NOT NULL, record TEXT NOT NULL CHECK (json_valid(record))) STRICT",
            "CREATE INDEX entries_by_conversation ON entries (conversation_id, id DESC)",
            "CREATE TABLE tasks (id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, abort_requested INTEGER NOT NULL, background INTEGER NOT NULL, record TEXT NOT NULL) STRICT",
            "CREATE TABLE submissions (id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL, request_id TEXT, status TEXT NOT NULL, record TEXT NOT NULL) STRICT",
            "CREATE TABLE documents (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, family INTEGER NOT NULL, key_value TEXT NOT NULL, scope_kind TEXT NOT NULL, owner_id INTEGER NOT NULL, created_at INTEGER NOT NULL, retired_at INTEGER, record TEXT NOT NULL CHECK (json_valid(record))) STRICT",
            "CREATE TABLE document_revisions (document_id INTEGER NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('base', 'delta')), version INTEGER NOT NULL, content TEXT NOT NULL CHECK (json_valid(content)), PRIMARY KEY (document_id, seq)) STRICT",
        ];

        fn s(value: &str) -> ParamValue {
            ParamValue::from(value)
        }

        fn write_sqlite_store(path: &Path, version: i64) {
            drop(open_sqlite_store(path, version, false));
        }

        /// Build the store; with `wal`, the returned writer keeps the
        /// database in WAL mode so committed rows live in the `-wal` file.
        fn open_sqlite_store(path: &Path, version: i64, wal: bool) -> Connection {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let conn = Connection::open(path.to_str().unwrap()).unwrap();
            if wal {
                let mode: String = conn
                    .query_row_map("PRAGMA journal_mode=wal;", &[], |row| {
                        frankensqlite::compat::RowExt::get_typed::<String>(row, 0)
                    })
                    .unwrap();
                assert_eq!(mode.to_ascii_lowercase(), "wal");
            }
            for statement in SCHEMA {
                conn.execute(statement).unwrap();
            }
            conn.execute_compat(
                "INSERT INTO durable_schema (singleton, version) VALUES (1, ?1)",
                &[ParamValue::from(version)],
            )
            .unwrap();
            // A live task row with a private checkpoint: never read.
            conn.execute_compat(
                "INSERT INTO tasks VALUES (7, 1, 'pi.generation', 'running', 0, 0, ?1)",
                &[s(&json!({"id": 7, "state": {"status": "running", "checkpoint": "TASK_CHECKPOINT_MARKER"}}).to_string())],
            )
            .unwrap();
            for (index, commit) in commits().into_iter().enumerate() {
                let seq = i64::try_from(index).unwrap() + 1;
                for write in commit {
                    match write {
                        W::Conversation(value) => {
                            conn.execute_compat(
                                "INSERT INTO conversations (id, owner_conversation_id, owner_task_id, record) VALUES (?1, NULL, NULL, ?2)",
                                &[ParamValue::from(value["id"].as_i64().unwrap()), s(&value.to_string())],
                            )
                            .unwrap();
                        }
                        W::Entry(value) => {
                            conn.execute_compat(
                                "INSERT INTO entries (id, conversation_id, head, commit_seq, record) VALUES (?1, ?2, NULL, ?3, ?4)",
                                &[
                                    ParamValue::from(value["id"].as_i64().unwrap()),
                                    ParamValue::from(value["conversationId"].as_i64().unwrap()),
                                    ParamValue::from(seq),
                                    s(&value.to_string()),
                                ],
                            )
                            .unwrap();
                        }
                        W::AgentCreate(doc, conversation, value) => {
                            let mut record = agent_record(doc, conversation);
                            record["createdAt"] = json!(seq);
                            conn.execute_compat(
                                "INSERT INTO documents (id, kind, family, key_value, scope_kind, owner_id, created_at, retired_at, record) \
                                 VALUES (?1, '\"pi.agent\"', 0, '', 'conversation', ?2, ?3, NULL, ?4)",
                                &[ParamValue::from(doc), ParamValue::from(conversation), ParamValue::from(seq), s(&record.to_string())],
                            )
                            .unwrap();
                            conn.execute_compat(
                                "INSERT INTO document_revisions (document_id, seq, kind, version, content) VALUES (?1, ?2, 'base', 1, ?3)",
                                &[ParamValue::from(doc), ParamValue::from(seq), s(&value.to_string())],
                            )
                            .unwrap();
                        }
                        W::AgentChange(doc, value) => {
                            conn.execute_compat(
                                "INSERT INTO document_revisions (document_id, seq, kind, version, content) VALUES (?1, ?2, 'base', 1, ?3)",
                                &[ParamValue::from(doc), ParamValue::from(seq), s(&value.to_string())],
                            )
                            .unwrap();
                        }
                    }
                }
            }
            conn
        }

        fn host_layout_db(home: &Path) -> PathBuf {
            home.join(".pi/agent/experimental/durable-sessions")
                .join("0123456789abcdef01234567")
                .join("1767600000000-0123abcd-4567-89ef-0123-456789abcdef")
                .join(SESSION_DB)
        }

        #[test]
        fn sqlite_store_matches_jsonl_semantics_without_mutation() {
            let tmp = TempDir::new().unwrap();
            let db = host_layout_db(tmp.path());
            write_sqlite_store(&db, SUPPORTED_SQLITE_SCHEMA);
            let before = snapshot(tmp.path());

            // An agent dir as the explicit root expands the host layout.
            let convs = scan(&tmp.path().join(".pi/agent"));
            assert_fixture_semantics(&convs);
            let root = by_id(&convs, 1);
            assert_eq!(root.metadata["store"]["backend"], "sqlite");
            assert_eq!(
                root.external_id.as_deref(),
                Some("pi_durable:1767600000000-0123abcd-4567-89ef-0123-456789abcdef:1")
            );
            assert_eq!(root.source_path, db);
            assert_eq!(
                snapshot(tmp.path()),
                before,
                "indexing changed source bytes"
            );

            // Same committed history through JSONL: equivalent transcript
            // content and provenance.
            let jsonl_tmp = TempDir::new().unwrap();
            write_jsonl_store(&jsonl_tmp.path().join("s"));
            let jsonl = scan(jsonl_tmp.path());
            let project = |convs: &[NormalizedConversation]| -> Vec<Value> {
                convs
                    .iter()
                    .map(|c| {
                        json!({
                            "conversation": c.metadata["conversation_id"],
                            "workspace": c.workspace,
                            "parent": c.metadata["parent"]["conversation_id"],
                            "owner": c.metadata["owner"]["conversation_id"],
                            "messages": c.messages.iter().map(|m| json!([m.role, m.content, m.author, m.created_at, m.extra["cass"]])).collect::<Vec<_>>(),
                        })
                    })
                    .collect()
            };
            assert_eq!(project(&convs), project(&jsonl));
        }

        #[test]
        fn default_detection_reads_the_durable_root_and_discovers_sidecars() {
            let tmp = TempDir::new().unwrap();
            let db = host_layout_db(tmp.path());
            // The harness holds its writer open: committed rows are still in
            // the WAL when the indexer reads.
            let writer = open_sqlite_store(&db, SUPPORTED_SQLITE_SCHEMA, true);
            let wal = sidecar_path(&db, "-wal");
            assert!(wal.is_file(), "the live writer should keep a WAL sidecar");
            let wal_before = fs::read(&wal).unwrap();
            let durable_root = tmp.path().join(".pi/agent/experimental/durable-sessions");
            let ctx = ScanContext::local_default(durable_root, None);
            let connector = PiDurableConnector::new();
            assert_eq!(connector.scan(&ctx).unwrap().len(), 3);
            let sources = connector.discover_source_files(&ctx).unwrap();
            assert_eq!(sources[0].role, DiscoveredSourceRole::SqliteDatabase);
            assert_eq!(sources[1].role, DiscoveredSourceRole::MetadataSidecar);
            assert!(sources[1].required_for_reconstruction);
            assert_eq!(
                fs::read(&wal).unwrap(),
                wal_before,
                "reader mutated the WAL"
            );
            drop(writer);
        }

        #[test]
        fn unsupported_schema_and_foreign_databases_are_skipped_with_diagnostics() {
            let tmp = TempDir::new().unwrap();
            write_sqlite_store(&tmp.path().join("future").join(SESSION_DB), 2);
            let foreign = tmp.path().join("foreign").join(SESSION_DB);
            fs::create_dir_all(foreign.parent().unwrap()).unwrap();
            Connection::open(foreign.to_str().unwrap())
                .unwrap()
                .execute("CREATE TABLE notes (body TEXT)")
                .unwrap();

            let connector = PiDurableConnector::new();
            let ctx = explicit_ctx(tmp.path());
            assert!(connector.scan(&ctx).unwrap().is_empty());
            let mut codes: Vec<&str> = connector
                .store_diagnostics(&ctx)
                .iter()
                .map(|d| d.code)
                .collect();
            codes.sort_unstable();
            assert_eq!(codes, vec!["not_a_durable_store", "unsupported_version"]);
        }

        #[test]
        fn incremental_scans_skip_closed_stores_without_a_wal() {
            let tmp = TempDir::new().unwrap();
            let db = host_layout_db(tmp.path());
            write_sqlite_store(&db, SUPPORTED_SQLITE_SCHEMA);
            // Simulate a store whose WAL was checkpointed away on close; the
            // filter must decide from the database alone, without opening it.
            for suffix in ["-wal", "-shm"] {
                let _ = fs::remove_file(sidecar_path(&db, suffix));
            }
            let future = chrono::Utc::now().timestamp_millis() + 3_600_000;
            let ctx = ScanContext::with_roots(
                PathBuf::from("/nonexistent"),
                vec![ScanRoot::local(tmp.path().join(".pi/agent"))],
                Some(future),
            );
            let connector = PiDurableConnector::new();
            assert!(connector.scan(&ctx).unwrap().is_empty());
            assert!(connector.discover_source_files(&ctx).unwrap().is_empty());
        }

        #[test]
        fn remote_sqlite_stores_are_refused() {
            let tmp = TempDir::new().unwrap();
            let db = host_layout_db(tmp.path());
            write_sqlite_store(&db, SUPPORTED_SQLITE_SCHEMA);
            let ctx = ScanContext::with_roots(
                PathBuf::from("/nonexistent"),
                vec![ScanRoot::remote(
                    db.clone(),
                    crate::types::Origin::remote_with_host("host-a", "host-a.example"),
                    None,
                )],
                None,
            );
            let connector = PiDurableConnector::new();
            assert!(connector.scan(&ctx).unwrap().is_empty());
            assert_eq!(
                connector.store_diagnostics(&ctx)[0].code,
                "remote_sqlite_unsupported"
            );
        }
    }

    #[cfg(not(feature = "pi-durable"))]
    #[test]
    fn sqlite_stores_report_missing_feature() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join(SESSION_DB);
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let connector = PiDurableConnector::new();
        let ctx = explicit_ctx(&db);
        assert!(connector.scan(&ctx).unwrap().is_empty());
        assert_eq!(
            connector.store_diagnostics(&ctx)[0].code,
            "sqlite_support_not_compiled"
        );
    }
}
