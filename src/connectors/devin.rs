//! Devin CLI connector (Cognition).
//!
//! The Devin CLI keeps every local session in ONE shared SQLite store,
//! `~/.local/share/devin/cli/sessions.db` (cass #449):
//!
//! - `sessions` — `id`, `title`, `working_directory`, `model`, `agent_mode`,
//!   `created_at` / `last_activity_at` (epoch **seconds**), `main_chain_id`
//!   (nullable), `hidden` (retired sessions that `devin list` omits).
//! - `message_nodes` — a *forest*, not a list: `session_id`, `node_id`,
//!   `parent_node_id`, `chat_message` (JSON), `created_at`. Branches are
//!   retries and edits; the live conversation is the parent chain that ends
//!   at `sessions.main_chain_id`. Replaying every row would interleave
//!   abandoned turns with the real ones (surveys of real stores put ~87% of
//!   the table off-chain), so the scan projects the main chain only.
//!
//! `chat_message` shapes, by `role`:
//! - `system` — `{message_id, role, content, metadata}` (not indexed);
//! - `user` — same, plus optional `images` (inline base64) and
//!   `metadata.is_user_input`;
//! - `assistant` — plus `tool_calls[] {id, index, kind, name, arguments}`
//!   where `arguments` is a JSON **object**, and `thinking {signature, thinking}`;
//! - `tool` — plus `tool_call_id` and optional `images`.
//!
//! `content` is a plain string in every observed node; the OpenAI-style parts
//! array is accepted too. Image payloads never reach the indexed text — an
//! `[image]` marker stands in for each one.
//!
//! Read-only: the store is opened `SQLITE_OPEN_READ_ONLY` with a busy timeout
//! because the live CLI may hold it open. Devin's cloud sessions are not on
//! disk and are out of scope here.

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

use std::path::PathBuf;

use super::{Connector, franken_detection_for_connector};
use crate::types::{DetectionResult, NormalizedConversation};

#[cfg(feature = "devin")]
use std::collections::{HashMap, HashSet};
#[cfg(feature = "devin")]
use std::path::Path;

#[cfg(feature = "devin")]
use anyhow::{Context, Result};
#[cfg(feature = "devin")]
use frankensqlite::compat::{OpenFlags, RowExt};
#[cfg(feature = "devin")]
use frankensqlite::params;

#[cfg(feature = "devin")]
use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
#[cfg(feature = "devin")]
use super::sqlite_sync::{Connection, ConnectionExt, open_with_flags};
#[cfg(feature = "devin")]
use super::utils::env_path_nonempty;
#[cfg(feature = "devin")]
use crate::types::{NormalizedInvocation, NormalizedMessage};

/// Override for the Devin data location. Accepts the `sessions.db` file, the
/// `cli` directory holding it, or the `devin` data root above that.
pub const DEVIN_DATA_ROOT_ENV: &str = "CASS_DEVIN_DATA_ROOT";

/// Upper bound on one `parent_node_id` walk. Nothing in the schema forbids a
/// cycle, and a real conversation is two orders of magnitude shorter.
#[cfg(feature = "devin")]
const MAX_CHAIN_DEPTH: usize = 50_000;

/// Serialized `tool_calls[].arguments` larger than this are replaced by a
/// size marker so one giant payload cannot dominate a message.
#[cfg(feature = "devin")]
const MAX_TOOL_ARGUMENTS_BYTES: usize = 32 * 1024;

pub struct DevinConnector;

impl Default for DevinConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl DevinConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Resolve `sessions.db` from an override value that may name the file,
    /// its `cli` directory, or the `devin` data root.
    #[must_use]
    pub fn database_path_from_root(root: &std::path::Path) -> PathBuf {
        if root.extension().is_some_and(|ext| ext == "db") {
            return root.to_path_buf();
        }
        let direct = root.join("sessions.db");
        if direct.is_file() {
            return direct;
        }
        let nested = root.join("cli").join("sessions.db");
        if nested.is_file() {
            return nested;
        }
        direct
    }

    /// Default store: `~/.local/share/devin/cli/sessions.db` on every
    /// platform (the CLI does not use the macOS `Application Support` dir).
    fn default_database_path() -> Option<PathBuf> {
        dirs::home_dir().map(|home| {
            home.join(".local")
                .join("share")
                .join("devin")
                .join("cli")
                .join("sessions.db")
        })
    }
}

#[cfg(feature = "devin")]
impl DevinConnector {
    /// Database candidates for a scan, in precedence order:
    /// a `.db` data_dir; default detection (a store under data_dir scopes the
    /// scan, then the env override, then the default location); or, with
    /// explicit roots, every root that resolves to a store.
    fn database_candidates(ctx: &ScanContext) -> Vec<(ScanRoot, PathBuf)> {
        let mut candidates: Vec<(ScanRoot, PathBuf)> = Vec::new();
        if ctx.data_dir.extension().is_some_and(|ext| ext == "db") {
            candidates.push((ScanRoot::local(ctx.data_dir.clone()), ctx.data_dir.clone()));
        } else if ctx.use_default_detection() {
            let scoped = (!ctx.data_dir.as_os_str().is_empty())
                .then(|| Self::database_path_from_root(&ctx.data_dir))
                .filter(|db| db.is_file());
            if let Some(db) = scoped {
                candidates.push((ScanRoot::local(db.clone()), db));
            } else if let Some(root) = env_path_nonempty(DEVIN_DATA_ROOT_ENV) {
                let db = Self::database_path_from_root(&root);
                candidates.push((ScanRoot::local(db.clone()), db));
            } else if let Some(db) = Self::default_database_path() {
                candidates.push((ScanRoot::local(db.clone()), db));
            }
        } else {
            for scan_root in &ctx.scan_roots {
                let db = Self::database_path_from_root(&scan_root.path);
                candidates.push((scan_root.clone(), db));
            }
        }
        let mut seen = HashSet::new();
        candidates.retain(|(_, db)| db.is_file() && seen.insert(db.clone()));
        candidates
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        Self::database_candidates(ctx)
            .into_iter()
            .map(|(root, db)| {
                DiscoveredSourceFile::new(
                    "devin",
                    &root,
                    db,
                    DiscoveredSourceRole::SqliteDatabase,
                    true,
                )
                .with_fs_metadata()
            })
            .collect()
    }

    /// Read every visible session's main chain from one store.
    ///
    /// `since_ts` (epoch ms) skips sessions whose `last_activity_at` is
    /// older. Sessions without a live chain or without indexable messages
    /// are skipped.
    pub fn extract_from_sqlite(
        db_path: &Path,
        since_ts: Option<i64>,
    ) -> Result<Vec<NormalizedConversation>> {
        let conn = open_with_flags(
            db_path.to_string_lossy().as_ref(),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .with_context(|| format!("failed to open Devin db: {}", db_path.display()))?;
        conn.execute("PRAGMA busy_timeout = 5000;")
            .context("failed to set busy_timeout on Devin db")?;

        let sessions = Self::load_sessions(&conn)?;
        let mut conversations = Vec::with_capacity(sessions.len());
        let mut seen_ids = HashSet::new();
        for session in sessions {
            if session.id.is_empty() || !seen_ids.insert(session.id.clone()) {
                continue;
            }
            let started_at = epoch_seconds_to_ms(session.created_at);
            let ended_at = epoch_seconds_to_ms(session.last_activity_at);
            if let Some(since) = since_ts
                && ended_at.or(started_at).unwrap_or(0) < since
            {
                continue;
            }
            let Some(main_chain_id) = session.main_chain_id else {
                continue;
            };
            let chain = Self::load_main_chain(&conn, &session.id, main_chain_id)?;
            let mut messages = Vec::new();
            for node in &chain.nodes {
                if let Some(message) = message_from_chat_message(
                    &node.chat_message,
                    epoch_seconds_to_ms(node.created_at),
                    session.model.as_deref(),
                ) {
                    messages.push(message);
                }
            }
            if messages.is_empty() {
                continue;
            }
            for (idx, message) in messages.iter_mut().enumerate() {
                message.idx = i64::try_from(idx).unwrap_or(i64::MAX);
            }

            let title = session
                .title
                .as_deref()
                .map(str::trim)
                .filter(|title| !title.is_empty())
                .map(str::to_owned)
                .or_else(|| {
                    messages
                        .iter()
                        .find(|message| message.role == "user")
                        .and_then(|message| message.content.lines().next())
                        .map(|line| line.chars().take(100).collect())
                });
            let workspace = session
                .working_directory
                .as_deref()
                .map(str::trim)
                .filter(|dir| !dir.is_empty())
                .map(PathBuf::from);
            let message_started_at = messages.iter().filter_map(|m| m.created_at).min();
            let message_ended_at = messages.iter().filter_map(|m| m.created_at).max();

            conversations.push(NormalizedConversation {
                agent_slug: "devin".into(),
                external_id: Some(session.id.clone()),
                title,
                workspace,
                source_path: db_path.join(urlencoding::encode(&session.id).as_ref()),
                started_at: started_at.or(message_started_at),
                ended_at: ended_at.or(message_ended_at),
                metadata: serde_json::json!({
                    "session_id": session.id,
                    "model": session.model,
                    "agent_mode": session.agent_mode,
                    "main_chain_id": main_chain_id,
                    "main_chain_nodes": chain.nodes.len(),
                    "off_chain_nodes": chain.off_chain_nodes,
                    "source": "sqlite",
                }),
                messages,
            });
        }
        Ok(conversations)
    }

    fn load_sessions(conn: &Connection) -> Result<Vec<DevinSession>> {
        const COLUMNS: &str = "id, title, working_directory, model, agent_mode, \
                               created_at, last_activity_at, main_chain_id";
        let map_row = |row: &frankensqlite::Row| {
            Ok(DevinSession {
                id: row.get_typed::<Option<String>>(0)?.unwrap_or_default(),
                title: row.get_typed(1)?,
                working_directory: row.get_typed(2)?,
                model: row.get_typed(3)?,
                agent_mode: row.get_typed(4)?,
                created_at: row.get_typed(5)?,
                last_activity_at: row.get_typed(6)?,
                main_chain_id: row.get_typed(7)?,
            })
        };
        // `hidden` marks sessions the CLI retired; they stay in the table but
        // never appear in `devin list`. Older stores may predate the column,
        // so fall back to an unfiltered read rather than failing the scan.
        match conn.query_map_collect(
            &format!("SELECT {COLUMNS} FROM sessions WHERE COALESCE(hidden, 0) = 0"),
            params![],
            map_row,
        ) {
            Ok(rows) => Ok(rows),
            Err(filtered_err) => conn
                .query_map_collect(
                    &format!("SELECT {COLUMNS} FROM sessions"),
                    params![],
                    map_row,
                )
                .with_context(|| {
                    format!("failed to query Devin sessions (hidden filter failed: {filtered_err})")
                }),
        }
    }

    /// Walk `parent_node_id` from the chain tip to its root and return the
    /// chain in reading (root-to-tip) order, plus how many rows of the
    /// session's forest were left out.
    fn load_main_chain(conn: &Connection, session_id: &str, tip: i64) -> Result<DevinChain> {
        let edges: Vec<(i64, Option<i64>)> = conn
            .query_map_collect(
                "SELECT node_id, parent_node_id FROM message_nodes WHERE session_id = ?1",
                params![session_id],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )
            .with_context(|| format!("failed to query Devin message_nodes for {session_id}"))?;
        let parents: HashMap<i64, Option<i64>> = edges.iter().copied().collect();
        let order = walk_main_chain(&parents, tip);
        let mut nodes = Vec::with_capacity(order.len());
        for node_id in &order {
            let node = conn
                .query_row_map(
                    "SELECT chat_message, created_at FROM message_nodes \
                     WHERE session_id = ?1 AND node_id = ?2",
                    params![session_id, *node_id],
                    |row| {
                        Ok(DevinNode {
                            chat_message: row.get_typed::<Option<String>>(0)?.unwrap_or_default(),
                            created_at: row.get_typed(1)?,
                        })
                    },
                )
                .with_context(|| {
                    format!("failed to load Devin message node {node_id} of {session_id}")
                })?;
            nodes.push(node);
        }
        Ok(DevinChain {
            off_chain_nodes: edges.len().saturating_sub(order.len()),
            nodes,
        })
    }
}

#[cfg(feature = "devin")]
struct DevinSession {
    id: String,
    title: Option<String>,
    working_directory: Option<String>,
    model: Option<String>,
    agent_mode: Option<String>,
    created_at: Option<i64>,
    last_activity_at: Option<i64>,
    main_chain_id: Option<i64>,
}

#[cfg(feature = "devin")]
struct DevinNode {
    chat_message: String,
    created_at: Option<i64>,
}

#[cfg(feature = "devin")]
struct DevinChain {
    nodes: Vec<DevinNode>,
    off_chain_nodes: usize,
}

/// Root-to-tip node ids of the chain ending at `tip`. Stops at a missing
/// parent, a node not in the session, a repeated node (cycle), or the depth
/// bound — never spins.
#[cfg(feature = "devin")]
fn walk_main_chain(parents: &HashMap<i64, Option<i64>>, tip: i64) -> Vec<i64> {
    let mut order = Vec::new();
    let mut visited = HashSet::new();
    let mut cursor = Some(tip);
    while let Some(node_id) = cursor {
        if order.len() >= MAX_CHAIN_DEPTH || !visited.insert(node_id) {
            break;
        }
        let Some(parent) = parents.get(&node_id) else {
            break;
        };
        order.push(node_id);
        cursor = *parent;
    }
    order.reverse();
    order
}

#[cfg(feature = "devin")]
fn epoch_seconds_to_ms(seconds: Option<i64>) -> Option<i64> {
    seconds
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| seconds.checked_mul(1000))
}

/// `content` as text: a plain string, or an OpenAI-style parts array whose
/// `text` parts are joined and whose image parts become `[image]` markers.
#[cfg(feature = "devin")]
fn text_content(content: Option<&serde_json::Value>) -> Option<String> {
    match content? {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Array(parts) => {
            let chunks: Vec<&str> = parts
                .iter()
                .filter_map(|part| match part.get("type").and_then(|t| t.as_str()) {
                    Some("text") => part.get("text").and_then(|t| t.as_str()),
                    Some("image" | "image_url") => Some("[image]"),
                    _ => None,
                })
                .collect();
            (!chunks.is_empty()).then(|| chunks.join("\n"))
        }
        _ => None,
    }
}

/// `[image]` markers for the inline base64 `images` array, so a screenshot
/// payload never reaches the indexed text.
#[cfg(feature = "devin")]
fn image_markers(object: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    let count = object.get("images").and_then(|v| v.as_array())?.len();
    (count > 0).then(|| vec!["[image]"; count].join("\n"))
}

#[cfg(feature = "devin")]
fn join_nonempty(parts: &[Option<String>]) -> String {
    parts
        .iter()
        .flatten()
        .filter(|part| !part.trim().is_empty())
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n")
}

/// One `message_nodes.chat_message` payload → at most one normalized message.
/// `system` nodes, contentless assistant nodes, and unparseable payloads
/// yield `None`. Visible for tests.
#[cfg(feature = "devin")]
pub(crate) fn message_from_chat_message(
    chat_message: &str,
    created_at: Option<i64>,
    model: Option<&str>,
) -> Option<NormalizedMessage> {
    let value: serde_json::Value = serde_json::from_str(chat_message).ok()?;
    let object = value.as_object()?;
    let role = object.get("role").and_then(|r| r.as_str()).unwrap_or("");
    let content = text_content(object.get("content"));
    let message_id = object
        .get("message_id")
        .and_then(|id| id.as_str())
        .map(str::to_owned);
    let mut extra = serde_json::Map::new();
    if let Some(message_id) = &message_id {
        extra.insert(
            "message_id".into(),
            serde_json::Value::String(message_id.clone()),
        );
    }

    let message = match role {
        "user" => {
            let text = join_nonempty(&[image_markers(object), content]);
            if text.is_empty() {
                return None;
            }
            if let Some(is_user_input) = object
                .get("metadata")
                .and_then(|m| m.get("is_user_input"))
                .and_then(serde_json::Value::as_bool)
            {
                extra.insert(
                    "is_user_input".into(),
                    serde_json::Value::Bool(is_user_input),
                );
            }
            NormalizedMessage {
                idx: 0,
                role: "user".into(),
                author: None,
                created_at,
                content: text,
                extra: serde_json::Value::Object(extra),
                snippets: Vec::new(),
                invocations: Vec::new(),
            }
        }
        "assistant" => {
            let mut invocations = Vec::new();
            let mut call_lines = Vec::new();
            for call in object
                .get("tool_calls")
                .and_then(|calls| calls.as_array())
                .into_iter()
                .flatten()
            {
                let name = call
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown")
                    .to_owned();
                let arguments = call.get("arguments").cloned().map(bound_tool_arguments);
                call_lines.push(format!("[tool_call: {name}]"));
                invocations.push(NormalizedInvocation {
                    kind: "tool".into(),
                    name,
                    raw_name: None,
                    call_id: call.get("id").and_then(|id| id.as_str()).map(str::to_owned),
                    arguments,
                });
            }
            let thinking = object
                .get("thinking")
                .and_then(|t| t.get("thinking"))
                .and_then(|t| t.as_str())
                .map(str::trim)
                .filter(|t| !t.is_empty());
            if let Some(thinking) = thinking {
                extra.insert(
                    "thinking".into(),
                    serde_json::Value::String(thinking.to_owned()),
                );
            }
            let text = join_nonempty(&[
                content,
                (!call_lines.is_empty()).then(|| call_lines.join("\n")),
            ]);
            if text.is_empty() {
                return None;
            }
            NormalizedMessage {
                idx: 0,
                role: "assistant".into(),
                author: model.map(str::to_owned),
                created_at,
                content: text,
                extra: serde_json::Value::Object(extra),
                snippets: Vec::new(),
                invocations,
            }
        }
        "tool" => {
            let text = join_nonempty(&[image_markers(object), content]);
            if text.is_empty() {
                return None;
            }
            if let Some(call_id) = object.get("tool_call_id").and_then(|id| id.as_str()) {
                extra.insert(
                    "tool_call_id".into(),
                    serde_json::Value::String(call_id.to_owned()),
                );
            }
            NormalizedMessage {
                idx: 0,
                role: "tool".into(),
                author: None,
                created_at,
                content: text,
                extra: serde_json::Value::Object(extra),
                snippets: Vec::new(),
                invocations: Vec::new(),
            }
        }
        _ => return None,
    };
    Some(message)
}

/// `tool_calls[].arguments` is a JSON object; keep it as-is unless its
/// serialized size is unreasonable, in which case a marker replaces it.
#[cfg(feature = "devin")]
fn bound_tool_arguments(arguments: serde_json::Value) -> serde_json::Value {
    let size = arguments.to_string().len();
    if size > MAX_TOOL_ARGUMENTS_BYTES {
        serde_json::Value::String(format!("[OMITTED large JSON payload bytes={size}]"))
    } else {
        arguments
    }
}

impl Connector for DevinConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("devin").unwrap_or_else(DetectionResult::not_found)
    }

    #[cfg(feature = "devin")]
    fn scan(&self, ctx: &super::scan::ScanContext) -> anyhow::Result<Vec<NormalizedConversation>> {
        let mut conversations = Vec::new();
        for (_, db) in Self::database_candidates(ctx) {
            match Self::extract_from_sqlite(&db, ctx.since_ts) {
                Ok(found) => {
                    tracing::debug!(
                        "devin sqlite: found {} sessions in {}",
                        found.len(),
                        db.display()
                    );
                    conversations.extend(found);
                }
                Err(err) => {
                    tracing::debug!("devin sqlite: failed to read {}: {err:#}", db.display());
                }
            }
        }
        Ok(conversations)
    }

    /// Without the `devin` feature the connector is detection-only.
    #[cfg(not(feature = "devin"))]
    fn scan(&self, _ctx: &super::scan::ScanContext) -> anyhow::Result<Vec<NormalizedConversation>> {
        Ok(Vec::new())
    }

    #[cfg(feature = "devin")]
    fn discover_source_files(
        &self,
        ctx: &super::scan::ScanContext,
    ) -> anyhow::Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

#[cfg(all(test, feature = "devin"))]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn open_test_connection(path: &Path) -> Connection {
        Connection::open(path.to_string_lossy().as_ref()).unwrap()
    }

    /// Schema as observed in CLI 3000.x stores (columns the connector reads
    /// plus a few it ignores).
    fn create_schema(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                title TEXT,
                working_directory TEXT,
                backend_type TEXT,
                model TEXT,
                agent_mode TEXT,
                created_at INTEGER,
                last_activity_at INTEGER,
                main_chain_id INTEGER,
                hidden INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE message_nodes (
                node_id INTEGER PRIMARY KEY,
                session_id TEXT NOT NULL,
                parent_node_id INTEGER,
                chat_message TEXT,
                created_at INTEGER
            );",
        )
        .unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_session(
        conn: &Connection,
        id: &str,
        title: &str,
        cwd: &str,
        created: i64,
        last: i64,
        main_chain_id: Option<i64>,
        hidden: i64,
    ) {
        conn.execute_compat(
            "INSERT INTO sessions (id, title, working_directory, backend_type, model, agent_mode, \
             created_at, last_activity_at, main_chain_id, hidden) \
             VALUES (?1, ?2, ?3, 'Windsurf', 'swe-1-7', 'bypass', ?4, ?5, ?6, ?7)",
            params![id, title, cwd, created, last, main_chain_id, hidden],
        )
        .unwrap();
    }

    fn insert_node(
        conn: &Connection,
        node_id: i64,
        session_id: &str,
        parent: Option<i64>,
        chat_message: &serde_json::Value,
        created: i64,
    ) {
        conn.execute_compat(
            "INSERT INTO message_nodes (node_id, session_id, parent_node_id, chat_message, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![node_id, session_id, parent, chat_message.to_string(), created],
        )
        .unwrap();
    }

    /// The reference fixture shape: system → user → assistant(tool_call) →
    /// tool → assistant, with an abandoned branch hanging off the user turn.
    fn seed_reference_store(db_path: &Path) {
        let conn = open_test_connection(db_path);
        create_schema(&conn);
        insert_session(
            &conn,
            "bald-ketch",
            "Fix the broken checks",
            "/tmp/as-agent-lab/devin/project",
            1_786_004_275,
            1_786_004_400,
            Some(5),
            0,
        );
        insert_node(
            &conn,
            1,
            "bald-ketch",
            None,
            &json!({"message_id": "m1", "role": "system", "content": "You are Devin.", "metadata": {}}),
            1_786_004_275,
        );
        insert_node(
            &conn,
            2,
            "bald-ketch",
            Some(1),
            &json!({"message_id": "m2", "role": "user", "content": "Fix the broken checks.",
                    "metadata": {"is_user_input": true}}),
            1_786_004_280,
        );
        insert_node(
            &conn,
            3,
            "bald-ketch",
            Some(2),
            &json!({"message_id": "m3", "role": "assistant", "content": "Reading the file.",
                    "thinking": {"signature": "sig", "thinking": "I should read it first."},
                    "tool_calls": [{"id": "call_1", "index": 0, "kind": "function",
                                    "name": "read_file", "arguments": {"path": "hello.py"}}],
                    "metadata": {"num_tokens": null}}),
            1_786_004_290,
        );
        insert_node(
            &conn,
            4,
            "bald-ketch",
            Some(3),
            &json!({"message_id": "m4", "role": "tool", "content": "print(\"hello\")",
                    "tool_call_id": "call_1", "metadata": {}}),
            1_786_004_300,
        );
        insert_node(
            &conn,
            5,
            "bald-ketch",
            Some(4),
            &json!({"message_id": "m5", "role": "assistant", "content": "The check passes now.",
                    "metadata": {}}),
            1_786_004_400,
        );
        // Abandoned branch (an edited/retried turn): must never be indexed.
        insert_node(
            &conn,
            6,
            "bald-ketch",
            Some(2),
            &json!({"message_id": "m6", "role": "assistant", "content": "ABANDONED BRANCH TEXT"}),
            1_786_004_285,
        );
        // A hidden (retired) session with a valid chain: excluded like `devin list`.
        insert_session(
            &conn,
            "hidden-one",
            "Old",
            "/tmp/old",
            1_700_000_000,
            1_700_000_100,
            Some(7),
            1,
        );
        insert_node(
            &conn,
            7,
            "hidden-one",
            None,
            &json!({"message_id": "h1", "role": "user", "content": "hidden prompt"}),
            1_700_000_000,
        );
        // A session with no live chain: nothing to index.
        insert_session(
            &conn,
            "no-chain",
            "Empty",
            "/tmp/e",
            1_700_000_000,
            1_700_000_100,
            None,
            0,
        );
        drop(conn);
    }

    #[test]
    fn extract_projects_the_main_chain_only() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("sessions.db");
        seed_reference_store(&db_path);

        let convs = DevinConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert_eq!(convs.len(), 1, "hidden and chainless sessions are skipped");
        let conv = &convs[0];
        assert_eq!(conv.agent_slug, "devin");
        assert_eq!(conv.external_id.as_deref(), Some("bald-ketch"));
        assert_eq!(conv.title.as_deref(), Some("Fix the broken checks"));
        assert_eq!(
            conv.workspace.as_deref(),
            Some(Path::new("/tmp/as-agent-lab/devin/project"))
        );
        assert_eq!(conv.started_at, Some(1_786_004_275_000));
        assert_eq!(conv.ended_at, Some(1_786_004_400_000));
        assert_eq!(conv.source_path, db_path.join("bald-ketch"));
        assert_eq!(conv.metadata["model"], "swe-1-7");
        assert_eq!(conv.metadata["agent_mode"], "bypass");
        assert_eq!(conv.metadata["main_chain_nodes"], 5);
        assert_eq!(conv.metadata["off_chain_nodes"], 1);

        // system node dropped; four indexable turns in reading order.
        let roles: Vec<&str> = conv.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, ["user", "assistant", "tool", "assistant"]);
        let idxs: Vec<i64> = conv.messages.iter().map(|m| m.idx).collect();
        assert_eq!(idxs, [0, 1, 2, 3]);
        assert!(
            conv.messages
                .iter()
                .all(|m| !m.content.contains("ABANDONED")),
            "off-chain branch leaked into the transcript"
        );

        let user = &conv.messages[0];
        assert_eq!(user.content, "Fix the broken checks.");
        assert_eq!(user.created_at, Some(1_786_004_280_000));
        assert_eq!(user.extra["is_user_input"], true);
        assert_eq!(user.extra["message_id"], "m2");

        let assistant = &conv.messages[1];
        assert_eq!(assistant.author.as_deref(), Some("swe-1-7"));
        assert_eq!(
            assistant.content,
            "Reading the file.\n[tool_call: read_file]"
        );
        assert_eq!(assistant.extra["thinking"], "I should read it first.");
        assert_eq!(assistant.invocations.len(), 1);
        assert_eq!(assistant.invocations[0].kind, "tool");
        assert_eq!(assistant.invocations[0].name, "read_file");
        assert_eq!(assistant.invocations[0].call_id.as_deref(), Some("call_1"));
        assert_eq!(
            assistant.invocations[0].arguments,
            Some(json!({"path": "hello.py"}))
        );

        let tool = &conv.messages[2];
        assert_eq!(tool.content, "print(\"hello\")");
        assert_eq!(tool.extra["tool_call_id"], "call_1");
        assert_eq!(conv.messages[3].content, "The check passes now.");
    }

    #[test]
    fn extract_honors_since_ts_on_last_activity() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("sessions.db");
        seed_reference_store(&db_path);
        assert_eq!(
            DevinConnector::extract_from_sqlite(&db_path, Some(1_786_004_400_001))
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            DevinConnector::extract_from_sqlite(&db_path, Some(1_786_004_400_000))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn extract_tolerates_a_store_without_the_hidden_column() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("sessions.db");
        let conn = open_test_connection(&db_path);
        conn.execute_batch(
            "CREATE TABLE sessions (id TEXT, title TEXT, working_directory TEXT, model TEXT, \
             agent_mode TEXT, created_at INTEGER, last_activity_at INTEGER, main_chain_id INTEGER);
             CREATE TABLE message_nodes (node_id INTEGER, session_id TEXT, parent_node_id INTEGER, \
             chat_message TEXT, created_at INTEGER);",
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO sessions VALUES ('s', NULL, '', NULL, NULL, 10, 20, 1)",
            params![],
        )
        .unwrap();
        insert_node(
            &conn,
            1,
            "s",
            None,
            &json!({"role": "user", "content": "first line\nsecond line"}),
            10,
        );
        drop(conn);
        let convs = DevinConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].title.as_deref(),
            Some("first line"),
            "title falls back to the first user line"
        );
        assert!(
            convs[0].workspace.is_none(),
            "blank working_directory is no workspace"
        );
        assert_eq!(convs[0].messages[0].author, None);
    }

    #[test]
    fn walk_main_chain_stops_on_cycles_and_missing_parents() {
        let parents: HashMap<i64, Option<i64>> = HashMap::from([
            (1, None),
            (2, Some(1)),
            (3, Some(2)),
            (9, Some(9)),
            (10, Some(11)),
        ]);
        assert_eq!(walk_main_chain(&parents, 3), vec![1, 2, 3]);
        assert_eq!(
            walk_main_chain(&parents, 9),
            vec![9],
            "self-cycle terminates"
        );
        assert_eq!(
            walk_main_chain(&parents, 10),
            vec![10],
            "missing parent ends the chain"
        );
        assert!(
            walk_main_chain(&parents, 42).is_empty(),
            "unknown tip is no chain"
        );
        let cycle: HashMap<i64, Option<i64>> = HashMap::from([(1, Some(2)), (2, Some(1))]);
        assert_eq!(walk_main_chain(&cycle, 1), vec![2, 1]);
    }

    #[test]
    fn chat_message_parsing_covers_images_parts_and_empties() {
        let user_with_images = json!({"role": "user", "content": "look",
            "images": [{"width": 1, "height": 1, "base64_data": "AAAA"}, {"base64_data": "BBBB"}]});
        let message = message_from_chat_message(&user_with_images.to_string(), None, None).unwrap();
        assert_eq!(message.content, "[image]\n[image]\nlook");
        assert!(
            !message.content.contains("AAAA"),
            "base64 payload must not be indexed"
        );

        let parts = json!({"role": "assistant", "content": [
            {"type": "text", "text": "part one"},
            {"type": "image_url", "image_url": {"url": "data:..."}},
            {"type": "text", "text": "part two"}]});
        let message =
            message_from_chat_message(&parts.to_string(), Some(5_000), Some("m")).unwrap();
        assert_eq!(message.content, "part one\n[image]\npart two");
        assert_eq!(message.created_at, Some(5_000));

        let tool_with_image = json!({"role": "tool", "tool_call_id": "c", "content": "",
            "images": [{"base64_data": "CCCC"}]});
        let message = message_from_chat_message(&tool_with_image.to_string(), None, None).unwrap();
        assert_eq!(message.content, "[image]");

        assert!(
            message_from_chat_message(r#"{"role":"system","content":"x"}"#, None, None).is_none()
        );
        assert!(
            message_from_chat_message(r#"{"role":"assistant","content":""}"#, None, None).is_none()
        );
        assert!(message_from_chat_message(r#"{"role":"user"}"#, None, None).is_none());
        assert!(message_from_chat_message("not json", None, None).is_none());
        assert!(message_from_chat_message("[1,2]", None, None).is_none());

        let tool_call_only = json!({"role": "assistant", "content": null,
            "tool_calls": [{"id": "x", "name": "bash", "arguments": {"cmd": "ls"}}]});
        let message = message_from_chat_message(&tool_call_only.to_string(), None, None).unwrap();
        assert_eq!(message.content, "[tool_call: bash]");
        assert_eq!(message.invocations[0].arguments, Some(json!({"cmd": "ls"})));

        let huge = "x".repeat(MAX_TOOL_ARGUMENTS_BYTES + 1);
        let big_call = json!({"role": "assistant", "tool_calls": [{"name": "w", "arguments": {"blob": huge}}]});
        let message = message_from_chat_message(&big_call.to_string(), None, None).unwrap();
        let marker = message.invocations[0]
            .arguments
            .as_ref()
            .unwrap()
            .as_str()
            .unwrap();
        assert!(
            marker.starts_with("[OMITTED large JSON payload bytes="),
            "{marker}"
        );
    }

    #[test]
    fn scan_and_discovery_resolve_the_store_from_a_scan_root() {
        let dir = TempDir::new().unwrap();
        let devin_root = dir.path().join("devin");
        let cli_dir = devin_root.join("cli");
        std::fs::create_dir_all(&cli_dir).unwrap();
        let db_path = cli_dir.join("sessions.db");
        seed_reference_store(&db_path);
        let connector = DevinConnector::new();

        // Explicit roots: the devin data root, the cli dir, and the db file
        // all resolve to the same store, deduplicated.
        let ctx = ScanContext::with_roots(
            dir.path().join("cass-data"),
            vec![
                ScanRoot::local(devin_root.clone()),
                ScanRoot::local(cli_dir.clone()),
                ScanRoot::local(db_path.clone()),
                ScanRoot::local(dir.path().join("nothing-here")),
            ],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        let sources = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source_path, db_path);
        assert_eq!(sources[0].role, DiscoveredSourceRole::SqliteDatabase);
        assert_eq!(sources[0].scan_root, devin_root);

        // Default detection with a store under data_dir scopes the scan to it.
        let scoped = ScanContext::local_default(devin_root.clone(), None);
        assert_eq!(connector.scan(&scoped).unwrap().len(), 1);
        let scoped_db = ScanContext::local_default(db_path.clone(), None);
        assert_eq!(connector.scan(&scoped_db).unwrap().len(), 1);

        // No store anywhere under the roots: empty, not an error.
        let empty = ScanContext::with_roots(
            dir.path().join("cass-data"),
            vec![ScanRoot::local(dir.path().join("nothing-here"))],
            None,
        );
        assert!(connector.scan(&empty).unwrap().is_empty());
        assert!(connector.discover_source_files(&empty).unwrap().is_empty());
    }

    #[test]
    fn database_path_from_root_accepts_file_cli_dir_and_data_root() {
        let dir = TempDir::new().unwrap();
        let cli = dir.path().join("cli");
        std::fs::create_dir_all(&cli).unwrap();
        std::fs::write(cli.join("sessions.db"), b"").unwrap();
        assert_eq!(
            DevinConnector::database_path_from_root(dir.path()),
            cli.join("sessions.db")
        );
        assert_eq!(
            DevinConnector::database_path_from_root(&cli),
            cli.join("sessions.db")
        );
        let file = dir.path().join("other.db");
        assert_eq!(DevinConnector::database_path_from_root(&file), file);
        let missing = dir.path().join("missing");
        assert_eq!(
            DevinConnector::database_path_from_root(&missing),
            missing.join("sessions.db")
        );
    }
}
