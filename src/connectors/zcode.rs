//! Read-only ZCode CLI/Desktop history (`~/.zcode/cli/db/db.sqlite`).
//!
//! The schema and JSON shapes were verified with ZCode CLI 0.17.1/Desktop
//! 3.18.2 in cass #573. Shared OpenCode table names are not a format signature:
//! admission also requires ZCode's identity, session-entry and turn-usage tables.
//! Runtime prompt snapshots, settings, rollout logs and desktop credentials are
//! never queried. Hosts must exclude this mixed-content database from raw mirroring.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use frankensqlite::compat::{OpenFlags, RowExt};
use frankensqlite::params;
use serde::Serialize;
use serde_json::{Value, json};

use super::Connector;
use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::sqlite_sync::{Connection, ConnectionExt, open_with_flags};
use super::utils::{
    dedupe_path_key, env_var_nonempty, excluded_scan_paths_from_env, path_is_excluded,
};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
};

const CONFIG_LIMIT: u64 = 1024 * 1024;

#[derive(Default)]
pub struct ZCodeConnector;

impl ZCodeConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Resolve the native database override without requiring the file to exist.
    /// Explicit overrides are authoritative even when missing: they must never
    /// silently fall back to another profile's history.
    #[must_use]
    pub fn configured_db_path() -> Option<PathBuf> {
        configured_path(
            dirs::home_dir().as_deref(),
            env_var_nonempty("ZCODE_SESSION_DB_PATH").as_deref(),
            env_var_nonempty("ZCODE_SESSION_DB").as_deref(),
            env_var_nonempty("ZCODE_STORAGE_DIR").as_deref(),
        )
    }

    /// Expand only known shallow store shapes, never a recursive home scan.
    /// The returned candidates need not exist, which also lets hosts watch a
    /// store's parent before its first database is created.
    #[must_use]
    pub fn db_paths_for_root(root: &Path) -> Vec<PathBuf> {
        if root.as_os_str().is_empty() || forbidden_path(root) {
            return Vec::new();
        }
        if root.is_file()
            || root
                .extension()
                .is_some_and(|ext| ext == "sqlite" || ext == "sqlite3" || ext == "db")
        {
            return vec![root.to_path_buf()];
        }
        vec![
            root.join("db.sqlite"),
            root.join("db/db.sqlite"),
            root.join("cli/db/db.sqlite"),
            root.join(".zcode/cli/db/db.sqlite"),
        ]
    }

    fn sources(ctx: &ScanContext) -> Result<Vec<(ScanRoot, PathBuf)>> {
        let exclusions = excluded_scan_paths_from_env()?;
        let mut candidates = Vec::new();
        if ctx.use_default_detection() {
            if forbidden_path(&ctx.data_dir) {
                return Ok(Vec::new());
            }
            let explicit_file = ctx.data_dir.is_file()
                || ctx
                    .data_dir
                    .extension()
                    .is_some_and(|ext| ext == "sqlite" || ext == "sqlite3" || ext == "db");
            let scoped = Self::db_paths_for_root(&ctx.data_dir)
                .into_iter()
                .filter(|path| path.is_file())
                .collect::<Vec<_>>();
            if explicit_file || !scoped.is_empty() {
                let root = ScanRoot::local(ctx.data_dir.clone());
                candidates.extend(scoped.into_iter().map(|path| (root.clone(), path)));
            } else if let Some(path) = Self::configured_db_path() {
                candidates.push((ScanRoot::local(path.clone()), path));
            }
        } else {
            // data_dir belongs to the host, not to an explicit source. Do not
            // add it or the local default store to a remote/fixture scan.
            for root in &ctx.scan_roots {
                if let Some(store) = root.mirrored_store(&[".zcode", "cli", "db"]) {
                    candidates.extend(
                        Self::db_paths_for_root(&store)
                            .into_iter()
                            .map(|path| (root.clone(), path)),
                    );
                }
                candidates.extend(
                    Self::db_paths_for_root(&root.path)
                        .into_iter()
                        .map(|path| (root.clone(), path)),
                );
            }
        }
        let mut seen = HashSet::new();
        candidates.retain(|(root, path)| {
            !path_is_excluded(&root.path, &exclusions)
                && !path_is_excluded(path, &exclusions)
                && !forbidden_path(path)
                && seen.insert(dedupe_path_key(path))
                && is_zcode_database(path)
        });
        Ok(candidates)
    }
}

fn configured_path(
    home: Option<&Path>,
    db_path: Option<&str>,
    db_alias: Option<&str>,
    storage: Option<&str>,
) -> Option<PathBuf> {
    let expand = |raw: &str| crate::expand_leading_tilde(raw, home);
    if let Some(raw) = trimmed(db_path).or_else(|| trimmed(db_alias)) {
        return Some(expand(raw));
    }
    let storage = trimmed(storage)
        .map(expand)
        .or_else(|| home.map(|home| home.join(".zcode")))?;
    // This one configuration file is needed only for storage.sessionDbPath.
    // Bounded reads avoid loading arbitrary oversized configuration payloads.
    let config = File::open(storage.join("cli/config.json"))
        .ok()
        .and_then(|file| {
            let mut bytes = Vec::new();
            file.take(CONFIG_LIMIT + 1).read_to_end(&mut bytes).ok()?;
            (bytes.len() as u64 <= CONFIG_LIMIT).then_some(bytes)
        })
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    if let Some(raw) = config
        .as_ref()
        .and_then(|value| value.pointer("/storage/sessionDbPath"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        return Some(expand(raw));
    }
    Some(storage.join("cli/db/db.sqlite"))
}

fn trimmed(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|raw| !raw.is_empty())
}

fn forbidden_path(path: &Path) -> bool {
    let components = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>();
    components.iter().any(|part| {
        matches!(
            *part,
            "rollout"
                | "certs"
                | "credentials.json"
                | "provider_config.json"
                | "tasks-index.sqlite"
        )
    }) || components.windows(2).any(|pair| pair == ["v2", "logs"])
}

fn open_database(path: &Path) -> Result<Connection> {
    ensure!(
        !forbidden_path(path),
        "not a ZCode transcript database path"
    );
    let mut header = [0_u8; 16];
    File::open(path)?.read_exact(&mut header)?;
    ensure!(&header == b"SQLite format 3\0", "not a SQLite database");
    let connection = open_with_flags(
        path.to_string_lossy().as_ref(),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .with_context(|| format!("failed to open ZCode database {}", path.display()))?;
    validate_schema(&connection)?;
    Ok(connection)
}

/// Schema-aware admission; no path or filename alone identifies ZCode.
#[must_use]
pub fn is_zcode_database(path: &Path) -> bool {
    path.is_file() && open_database(path).is_ok()
}

/// Recognize the mixed-content container even when its transcript schema is
/// newer than this reader supports. Hosts use this before raw copying a source
/// claimed by another connector. Errors mean safety could not be established
/// and must not be interpreted as permission to copy the file.
pub fn is_zcode_container(path: &Path) -> Result<bool> {
    if forbidden_path(path)
        && path.components().any(|component| {
            component
                .as_os_str()
                .to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(".zcode"))
        })
    {
        // Do not even read a header from ZCode's credential/log locations.
        // Other providers may use the same generic directory names; without
        // the .zcode component those names alone do not establish ownership.
        return Ok(true);
    }
    let mut header = Vec::with_capacity(16);
    File::open(path)?.take(16).read_to_end(&mut header)?;
    if header != b"SQLite format 3\0" {
        return Ok(false);
    }
    let connection = open_with_flags(
        path.to_string_lossy().as_ref(),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let columns = connection.query_map_collect(
        "PRAGMA table_info(\"zcode_database_identity\")",
        params![],
        |_row| Ok(()),
    )?;
    Ok(!columns.is_empty())
}

fn validate_schema(connection: &Connection) -> Result<()> {
    // These literals are the entire SQL identifier surface. Neither filenames
    // nor persisted content can become an interpolated table/column name.
    const TABLES: &[(&str, &[&str])] = &[
        (
            "session",
            &[
                "id",
                "project_id",
                "parent_id",
                "directory",
                "path",
                "title",
                "version",
                "time_created",
                "time_updated",
                "time_archived",
                "time_deleted",
            ],
        ),
        (
            "message",
            &[
                "id",
                "session_id",
                "time_created",
                "time_updated",
                "data",
                "sequence",
            ],
        ),
        (
            "part",
            &[
                "id",
                "message_id",
                "session_id",
                "time_created",
                "time_updated",
                "data",
                "sequence",
            ],
        ),
        (
            "session_entry",
            &[
                "id",
                "session_id",
                "type",
                "time_created",
                "time_updated",
                "data",
            ],
        ),
        (
            "turn_usage",
            &[
                "session_id",
                "turn_id",
                "user_message_id",
                "status",
                "started_at",
                "completed_at",
                "input_tokens",
                "output_tokens",
                "reasoning_tokens",
                "cache_creation_input_tokens",
                "cache_read_input_tokens",
                "computed_total_tokens",
                "tool_call_count",
            ],
        ),
        ("zcode_database_identity", &[]),
    ];
    for (table, required) in TABLES {
        let columns = connection.query_map_collect(
            &format!("PRAGMA table_info(\"{table}\")"),
            params![],
            |row| row.get_typed::<String>(1),
        )?;
        ensure!(
            !columns.is_empty()
                && required
                    .iter()
                    .all(|name| columns.iter().any(|column| column.as_str() == *name)),
            "unsupported ZCode schema: table {table} or required columns missing"
        );
    }
    Ok(())
}

impl Connector for ZCodeConnector {
    fn detect(&self) -> DetectionResult {
        let roots = Self::configured_db_path()
            .filter(|path| is_zcode_database(path))
            .into_iter()
            .collect::<Vec<_>>();
        DetectionResult {
            detected: !roots.is_empty(),
            evidence: roots
                .iter()
                .map(|path| format!("ZCode schema: {}", path.display()))
                .collect(),
            root_paths: roots,
        }
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut conversations = Vec::new();
        self.scan_with_callback(ctx, &mut |conversation| {
            conversations.push(conversation);
            Ok(())
        })?;
        Ok(conversations)
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        let skip_subagents = env_var_nonempty("CASS_SKIP_SUBAGENTS").is_some_and(|value| {
            matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
        });
        for (root, path) in Self::sources(ctx)? {
            let connection = open_database(&path)?;
            connection.read_transaction(|connection| {
                let sessions = load_sessions(connection)?;
                for session in sessions {
                    if let Some(tick) = &ctx.progress_tick {
                        tick();
                    }
                    if skip_subagents && session.parent_id.is_some() {
                        continue;
                    }
                    if let Some(mut conversation) =
                        load_conversation(connection, &path, session, ctx)?
                    {
                        conversation.metadata["origin"] = serde_json::to_value(&root.origin)?;
                        if let Some(workspace) = &conversation.workspace {
                            conversation.workspace = Some(PathBuf::from(
                                root.rewrite_workspace(&workspace.to_string_lossy(), Some("zcode")),
                            ));
                        }
                        on_conversation(conversation)?;
                    }
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }
        Ok(())
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        let exclusions = excluded_scan_paths_from_env()?;
        let mut files = Vec::new();
        for (root, path) in Self::sources(ctx)? {
            files.push(
                DiscoveredSourceFile::new(
                    "zcode",
                    &root,
                    path.clone(),
                    DiscoveredSourceRole::SqliteDatabase,
                    true,
                )
                .with_fs_metadata(),
            );
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                let sidecar = PathBuf::from(sidecar);
                if sidecar.is_file() && !path_is_excluded(&sidecar, &exclusions) {
                    files.push(
                        DiscoveredSourceFile::new(
                            "zcode",
                            &root,
                            sidecar,
                            DiscoveredSourceRole::MetadataSidecar,
                            true,
                        )
                        .with_fs_metadata(),
                    );
                }
            }
        }
        Ok(files)
    }
}

struct Session {
    id: String,
    project_id: String,
    parent_id: Option<String>,
    directory: String,
    path: Option<String>,
    title: String,
    version: String,
    created: i64,
    updated: i64,
    archived: Option<i64>,
}

fn load_sessions(connection: &Connection) -> Result<Vec<Session>> {
    connection
        .query_map_collect(
            "SELECT id, project_id, parent_id, directory, path, title, version, time_created, \
                time_updated, time_archived FROM session \
         WHERE time_deleted IS NULL ORDER BY time_created, id",
            params![],
            |row| {
                Ok(Session {
                    id: row.get_typed(0)?,
                    project_id: row.get_typed(1)?,
                    parent_id: row.get_typed(2)?,
                    directory: row.get_typed(3)?,
                    path: row.get_typed(4)?,
                    title: row.get_typed(5)?,
                    version: row.get_typed(6)?,
                    created: row.get_typed(7)?,
                    updated: row.get_typed(8)?,
                    archived: row.get_typed(9)?,
                })
            },
        )
        .context("could not read ZCode sessions")
}

struct JsonRow {
    id: String,
    created: i64,
    updated: i64,
    sequence: Option<i64>,
    data: String,
}

#[derive(Serialize)]
struct TurnUsage {
    turn_id: String,
    user_message_id: Option<String>,
    status: String,
    started_at: i64,
    completed_at: Option<i64>,
    input_tokens: i64,
    output_tokens: i64,
    reasoning_tokens: i64,
    cache_creation_input_tokens: i64,
    cache_read_input_tokens: i64,
    computed_total_tokens: i64,
    tool_call_count: i64,
}

fn load_turn_usage(connection: &Connection, session_id: &str) -> Result<Vec<TurnUsage>> {
    connection.query_map_collect(
        "SELECT turn_id, user_message_id, status, started_at, completed_at, input_tokens, \
                output_tokens, reasoning_tokens, cache_creation_input_tokens, cache_read_input_tokens, \
                computed_total_tokens, tool_call_count FROM turn_usage \
         WHERE session_id = ? ORDER BY started_at, turn_id",
        params![session_id],
        |row| Ok(TurnUsage {
            turn_id: row.get_typed(0)?, user_message_id: row.get_typed(1)?, status: row.get_typed(2)?,
            started_at: row.get_typed(3)?, completed_at: row.get_typed(4)?, input_tokens: row.get_typed(5)?,
            output_tokens: row.get_typed(6)?, reasoning_tokens: row.get_typed(7)?,
            cache_creation_input_tokens: row.get_typed(8)?, cache_read_input_tokens: row.get_typed(9)?,
            computed_total_tokens: row.get_typed(10)?, tool_call_count: row.get_typed(11)?,
        }),
    ).context("could not read ZCode turn usage")
}

fn hidden(value: &Value) -> bool {
    value.get("synthetic").and_then(Value::as_bool) == Some(true)
        || value.get("ignored").and_then(Value::as_bool) == Some(true)
        || value.get("visibility").and_then(Value::as_str) == Some("model-only")
        || value
            .pointer("/metadata/visibility")
            .and_then(Value::as_str)
            == Some("model-only")
        || value
            .pointer("/semantics/uiVisibility")
            .and_then(Value::as_str)
            == Some("hidden")
        || value
            .pointer("/semantics/transcriptVisibility")
            .and_then(Value::as_str)
            == Some("hidden")
}

fn nonempty_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn load_conversation(
    connection: &Connection,
    db_path: &Path,
    session: Session,
    ctx: &ScanContext,
) -> Result<Option<NormalizedConversation>> {
    let rows = connection.query_map_collect(
        "SELECT id, time_created, time_updated, sequence, data FROM message \
         WHERE session_id = ? ORDER BY COALESCE(sequence, 0), time_created, id",
        params![session.id.clone()],
        |row| {
            Ok(JsonRow {
                id: row.get_typed(0)?,
                created: row.get_typed(1)?,
                updated: row.get_typed(2)?,
                sequence: row.get_typed(3)?,
                data: row.get_typed(4)?,
            })
        },
    )?;
    let turns = load_turn_usage(connection, &session.id)?;
    let turns_by_user = turns
        .iter()
        .filter_map(|turn| {
            turn.user_message_id
                .as_deref()
                .map(|id| (id, turn.turn_id.as_str()))
        })
        .collect::<HashMap<_, _>>();
    let mut parts_by_message: HashMap<String, Vec<JsonRow>> = HashMap::new();
    let part_rows = connection.query_map_collect(
        "SELECT message_id, id, time_created, time_updated, sequence, data FROM part \
         WHERE session_id = ? ORDER BY COALESCE(sequence, 0), time_created, id",
        params![session.id.clone()],
        |row| {
            Ok((
                row.get_typed::<String>(0)?,
                JsonRow {
                    id: row.get_typed(1)?,
                    created: row.get_typed(2)?,
                    updated: row.get_typed(3)?,
                    sequence: row.get_typed(4)?,
                    data: row.get_typed(5)?,
                },
            ))
        },
    )?;
    for (message_id, row) in part_rows {
        parts_by_message.entry(message_id).or_default().push(row);
    }
    let mut messages = Vec::new();
    let mut latest = session.updated.max(session.created);
    let mut current_user = None;
    let mut assistant_workspace = None;
    for (row_index, row) in rows.into_iter().enumerate() {
        if row_index % 256 == 0
            && let Some(tick) = &ctx.progress_tick
        {
            tick();
        }
        latest = latest.max(row.updated).max(row.created);
        let Ok(data) = serde_json::from_str::<Value>(&row.data) else {
            continue;
        };
        let Some(role @ ("user" | "assistant" | "tool")) = data.get("role").and_then(Value::as_str)
        else {
            continue;
        };
        if hidden(&data)
            || (role == "user"
                && data.pointer("/semantics/origin").and_then(Value::as_str)
                    == Some("agent_runtime"))
        {
            continue;
        }
        if role == "user" {
            current_user = Some(row.id.clone());
        }
        let parts = parts_by_message.remove(&row.id).unwrap_or_default();
        let mut content = Vec::new();
        let mut part_metadata = Vec::new();
        let mut invocations = Vec::new();
        for (part_index, part) in parts.into_iter().enumerate() {
            if part_index % 256 == 0
                && let Some(tick) = &ctx.progress_tick
            {
                tick();
            }
            latest = latest.max(part.updated).max(part.created);
            let Ok(value) = serde_json::from_str::<Value>(&part.data) else {
                continue;
            };
            if hidden(&value) {
                continue;
            }
            if let Some(mut metadata) = render_part(&value, &mut content, &mut invocations) {
                metadata["id"] = part.id.into();
                metadata["sequence"] = part.sequence.into();
                part_metadata.push(metadata);
            }
        }
        let content = content.join("\n\n");
        // Keep visible usage-only assistant records: their direct counters
        // must not vanish merely because the reply contained no text.
        if content.trim().is_empty()
            && invocations.is_empty()
            && !(role == "assistant" && data.get("tokens").is_some_and(Value::is_object))
        {
            continue;
        }
        let model = data
            .get("modelId")
            .or_else(|| data.pointer("/modelSelection/modelId"));
        let provider = data
            .get("providerId")
            .or_else(|| data.pointer("/modelSelection/providerId"));
        let turn_id = data
            .pointer("/anchor/turnId")
            .and_then(Value::as_str)
            .or_else(|| {
                data.get("parentID")
                    .and_then(Value::as_str)
                    .and_then(|id| turns_by_user.get(id).copied())
            })
            .or_else(|| {
                current_user
                    .as_deref()
                    .and_then(|id| turns_by_user.get(id).copied())
            });
        if role == "assistant" && assistant_workspace.is_none() {
            assistant_workspace = nonempty_string(data.pointer("/path/cwd")).map(PathBuf::from);
        }
        let extra = json!({
            "id": row.id, "message_id": row.id, "sequence": row.sequence,
            "modelId": model, "providerId": provider, "tokens": data.get("tokens"),
            "parentID": data.get("parentID"), "finish": data.get("finish"),
            "parts": part_metadata,
            "cass": {"turn_id": turn_id, "tool_call_count": invocations.len()},
        });
        messages.push(NormalizedMessage {
            idx: i64::try_from(messages.len()).unwrap_or(i64::MAX),
            role: role.to_owned(),
            author: if role == "assistant" {
                nonempty_string(model).map(str::to_owned)
            } else {
                None
            },
            created_at: Some(
                data.pointer("/time/created")
                    .and_then(Value::as_i64)
                    .unwrap_or(row.created),
            ),
            content,
            extra,
            snippets: Vec::new(),
            invocations,
        });
    }
    for turn in &turns {
        latest = latest.max(turn.completed_at.unwrap_or(turn.started_at));
    }
    if messages.is_empty() || ctx.since_ts.is_some_and(|since| latest < since) {
        return Ok(None);
    }
    attach_turn_fallbacks(&mut messages, &turns);
    let workspace = (!session.directory.trim().is_empty())
        .then(|| PathBuf::from(&session.directory))
        .or_else(|| {
            session
                .path
                .as_deref()
                .filter(|path| !path.trim().is_empty())
                .map(PathBuf::from)
        })
        .or(assistant_workspace);
    let title = (!session.title.trim().is_empty())
        .then_some(session.title)
        .or_else(|| {
            messages
                .iter()
                .find(|message| message.role == "user")
                .and_then(|message| message.content.lines().next())
                .map(|line| line.chars().take(100).collect())
        });
    Ok(Some(NormalizedConversation {
        agent_slug: "zcode".into(),
        external_id: Some(session.id.clone()),
        title,
        workspace,
        source_path: db_path.join(urlencoding::encode(&session.id).as_ref()),
        started_at: Some(session.created),
        ended_at: Some(latest),
        metadata: json!({
            "session_id": session.id, "project_id": session.project_id, "parent_id": session.parent_id,
            "version": session.version, "time_archived": session.archived,
            "source": "sqlite", "zcode_schema": "cli-0.17.1", "turn_usage": turns,
        }),
        messages,
    }))
}

fn render_part(
    part: &Value,
    content: &mut Vec<String>,
    invocations: &mut Vec<NormalizedInvocation>,
) -> Option<Value> {
    let kind = part.get("type")?.as_str()?;
    match kind {
        "text" | "reasoning" => {
            let text = nonempty_string(part.get("text"))?;
            content.push(if kind == "reasoning" {
                format!("[Reasoning]\n{text}")
            } else {
                text.to_owned()
            });
            Some(json!({"type": kind, "text": text}))
        }
        "tool" => {
            let name = nonempty_string(part.get("tool"))?;
            let state = part.get("state")?;
            let status = state.get("status").and_then(Value::as_str)?;
            if !matches!(status, "pending" | "running" | "completed" | "error") {
                return None;
            }
            let input = state.get("input").cloned().map(strip_data_uris);
            invocations.push(NormalizedInvocation {
                kind: "tool".into(),
                name: name.into(),
                raw_name: None,
                call_id: nonempty_string(part.get("callID")).map(str::to_owned),
                arguments: input.clone(),
            });
            content.push(format!("[Tool: {name}]"));
            if let Some(input) = &input {
                content.push(input.to_string());
            }
            let output = state.get("output").cloned().map(strip_data_uris);
            let error = state.get("error").cloned().map(strip_data_uris);
            for (label, value) in [("Tool Output", &output), ("Tool Error", &error)] {
                if let Some(value) = value {
                    let text = value
                        .as_str()
                        .map_or_else(|| value.to_string(), str::to_owned);
                    if !text.trim().is_empty() {
                        content.push(format!("[{label}]\n{text}"));
                    }
                }
            }
            Some(json!({
                "type": kind, "callID": part.get("callID"), "tool": name,
                "state": {"status": status, "input": input, "output": output, "error": error},
            }))
        }
        "file" => {
            let filename = nonempty_string(part.get("filename"));
            let mime = nonempty_string(part.get("mime"));
            let url = nonempty_string(part.get("url")).filter(|url| !is_data_uri(url));
            content.push(format!(
                "[File: {}]",
                filename.or(mime).unwrap_or("attachment")
            ));
            Some(json!({"type": kind, "filename": filename, "mime": mime, "url": url}))
        }
        // step-finish counters duplicate message/turn usage. Snapshot, patch,
        // compaction, timeline and agent bookkeeping are not visible messages.
        _ => None,
    }
}

fn is_data_uri(value: &str) -> bool {
    value
        .trim_start()
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("data:"))
}

fn strip_data_uris(mut value: Value) -> Value {
    match &mut value {
        Value::String(text) if is_data_uri(text) => {
            *text = "[attachment omitted]".into();
        }
        Value::Array(values) => {
            for value in values {
                *value = strip_data_uris(value.take());
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                *value = strip_data_uris(value.take());
            }
        }
        _ => {}
    }
    value
}

fn has_message_tokens(extra: &Value) -> bool {
    [
        "/tokens/input",
        "/tokens/output",
        "/tokens/cache/read",
        "/tokens/cache/write",
    ]
    .iter()
    .any(|path| {
        extra
            .pointer(path)
            .and_then(Value::as_i64)
            .is_some_and(|count| count >= 0)
    })
}

fn attach_turn_fallbacks(messages: &mut [NormalizedMessage], turns: &[TurnUsage]) {
    for turn in turns {
        let indices = messages
            .iter()
            .enumerate()
            .filter_map(|(index, message)| {
                (message.role == "assistant"
                    && message
                        .extra
                        .pointer("/cass/turn_id")
                        .and_then(Value::as_str)
                        == Some(turn.turn_id.as_str()))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        let has_direct = indices
            .iter()
            .any(|index| has_message_tokens(&messages[*index].extra));
        // Preserve the aggregate as metadata for every turn. It is a fallback
        // only when that turn has no direct per-message counters; never add a
        // repeated turn total to its constituent message totals or infer a
        // residual from incomplete/inconsistent provider data.
        for index in &indices {
            if !has_message_tokens(&messages[*index].extra) {
                messages[*index].extra["cass"]["usage_covered_by_turn"] = true.into();
            }
        }
        if !has_direct && let Some(index) = indices.last() {
            messages[*index].extra["cass"]["token_usage"] = json!({
                "input": turn.input_tokens, "output": turn.output_tokens, "reasoning": turn.reasoning_tokens,
                "total": turn.computed_total_tokens,
                "cache": {"read": turn.cache_read_input_tokens, "write": turn.cache_creation_input_tokens},
            });
        }
    }
}
