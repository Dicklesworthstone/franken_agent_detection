//! Native VS Code chat-session storage for the Copilot connector.
//!
//! GitHub Copilot Chat's conversation history in VS Code proper is primarily
//! **workspace-scoped** and lives in VS Code's own chat-session store, not in
//! the extension's `globalStorage/github.copilot-chat` directory (issue #16;
//! verified against the VS Code sources referenced below). Under a VS Code
//! `User` root (`~/.config/Code/User`, `~/Library/Application Support/Code/User`,
//! `%APPDATA%/Code/User`, plus `Code - Insiders` / `VSCodium` variants):
//!
//! ```text
//! User/
//!   workspaceStorage/<workspace-id>/
//!     workspace.json                     ← {"folder": "file:///…"} (workspace resolution)
//!     chatSessions/<session-id>.json     ← flat serialized session (Mar 2025 – 1.108)
//!     chatSessions/<session-id>.jsonl    ← append-log session (1.109+)
//!     state.vscdb                        ← legacy SQLite (pre Mar 2025)
//!   globalStorage/
//!     emptyWindowChatSessions/<id>.json|.jsonl   ← sessions from empty windows
//!     transferredChatSessions/<id>.json|.jsonl   ← sessions mid-transfer between windows
//!     state.vscdb                        ← legacy SQLite, application scope
//! ```
//!
//! ## The three storage generations
//!
//! 1. **Legacy SQLite** (before March 2025): `state.vscdb`, table `ItemTable`,
//!    key `interactive.sessions`, value = JSON array of serialized sessions
//!    (`chatServiceImpl.ts`, `serializedChatKey`). Application-scoped sessions
//!    (empty windows) live in the *global* `state.vscdb`. Only available with
//!    the `copilot-vscdb` cargo feature (SQLite engine dependency).
//! 2. **Flat session JSON** (microsoft/vscode@a4ee2666, March 2025 – 1.108):
//!    `chatSessions/<session-id>.json` holds one serialized session.
//! 3. **Append-log JSONL** (microsoft/vscode@5438d07d, 1.109+):
//!    `chatSessions/<session-id>.jsonl` where each line is an object-mutation
//!    entry (`objectMutationLog.ts`):
//!    - `{"kind":0,"v":…}` — full snapshot (initial state / compaction)
//!    - `{"kind":1,"k":[…],"v":…}` — set value at key path
//!    - `{"kind":2,"k":[…],"v":[…]?,"i":n?}` — array push; `i` truncates first
//!    - `{"kind":3,"k":[…]}` — delete at key path
//!    A truncated final line is a normal artifact of an interrupted append and
//!    is tolerated; malformed interior lines are skipped-and-logged.
//!
//! ## Provider filtering
//!
//! The native store is shared by every chat provider, so a session is admitted
//! only when its serialized metadata identifies GitHub Copilot (a request
//! `agent.extensionId.value` starting with `github.copilot`, or the session
//! `responderUsername`/agent name `"GitHub Copilot"`). Sessions without
//! Copilot evidence are skipped rather than misattributed.
//!
//! `chat.ChatSessionStore.index` (a storage key, occasionally materialized as
//! a file) carries only session *metadata* and is never treated as a
//! transcript source.
//!
//! ## Deduplication
//!
//! The same session id can exist in multiple generations (migration) or in
//! multiple product trees (restored backup). Sources are parsed in generation
//! order — append-log, then flat JSON, then SQLite — and the first successful
//! parse of a session id wins.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanRoot};
use super::utils::dedupe_path_key;
use super::{file_modified_since, parse_timestamp};
use crate::types::{NormalizedConversation, NormalizedInvocation, NormalizedMessage,
    reindex_messages};

/// VS Code product directories that host a `User` tree.
const PRODUCT_DIRS: &[&str] = &["Code", "Code - Insiders", "VSCodium"];

/// Store labels carried into conversation metadata.
const STORE_WORKSPACE: &str = "vscode-workspace";
const STORE_EMPTY_WINDOW: &str = "vscode-empty-window";
const STORE_TRANSFERRED: &str = "vscode-transferred";
const STORE_STATE_DB: &str = "vscode-state-db";

/// Native storage generation, ordered by parse priority (newest first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum NativeFormat {
    /// `<session-id>.jsonl` append log (VS Code 1.109+).
    AppendLog,
    /// `<session-id>.json` flat serialized session (March 2025 – 1.108).
    FlatJson,
    /// `state.vscdb` `ItemTable` key `interactive.sessions` (pre March 2025).
    StateDb,
}

/// One native chat-session source file, plus enough context to resolve the
/// owning workspace.
#[derive(Debug, Clone)]
pub(crate) struct NativeSource {
    pub format: NativeFormat,
    pub path: PathBuf,
    /// Which store family the file came from (metadata label).
    pub store: &'static str,
    /// `workspaceStorage/<id>` directory, when workspace-scoped; used to read
    /// the sibling `workspace.json` for workspace resolution.
    pub workspace_dir: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Root discovery
// ---------------------------------------------------------------------------

/// Default VS Code `User` roots probed when no explicit scan roots are given.
pub(crate) fn default_user_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = dirs::home_dir() {
        for product in PRODUCT_DIRS {
            roots.push(home.join(".config").join(product).join("User"));
            roots.push(
                home.join("Library/Application Support")
                    .join(product)
                    .join("User"),
            );
            roots.push(home.join("AppData/Roaming").join(product).join("User"));
        }
    }
    if let Some(config) = dirs::config_dir() {
        for product in PRODUCT_DIRS {
            roots.push(config.join(product).join("User"));
        }
    }
    roots.sort();
    roots.dedup();
    roots
}

/// Whether a path clearly points into VS Code's native chat storage (used to
/// honor a `data_dir` that targets the native store directly).
pub(crate) fn looks_like_native_store(path: &Path) -> bool {
    let named = |name: &str| {
        path.components().any(|component| {
            let segment = component.as_os_str().to_string_lossy();
            segment == name
        })
    };
    named("workspaceStorage")
        || named("chatSessions")
        || named("emptyWindowChatSessions")
        || named("transferredChatSessions")
        || path.join("workspaceStorage").is_dir()
        || path.join("globalStorage").is_dir()
}

fn dir_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

fn is_session_file(path: &Path) -> Option<NativeFormat> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => Some(NativeFormat::FlatJson),
        Some("jsonl") => Some(NativeFormat::AppendLog),
        _ => None,
    }
}

/// Session-container directory names mapped to their store label.
fn store_for_container(name: &str) -> Option<&'static str> {
    match name {
        "chatSessions" => Some(STORE_WORKSPACE),
        "emptyWindowChatSessions" => Some(STORE_EMPTY_WINDOW),
        "transferredChatSessions" => Some(STORE_TRANSFERRED),
        _ => None,
    }
}

/// The `workspaceStorage/<id>` directory owning a `chatSessions` container,
/// when the layout matches.
fn workspace_dir_of_container(container: &Path) -> Option<PathBuf> {
    let storage_dir = container.parent()?;
    let storage_root = storage_dir.parent()?;
    if dir_name(storage_root)? == "workspaceStorage" {
        Some(storage_dir.to_path_buf())
    } else {
        None
    }
}

fn sorted_entries(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .collect();
    out.sort();
    out
}

fn collect_session_container(
    out: &mut Vec<NativeSource>,
    container: &Path,
    store: &'static str,
    workspace_dir: Option<&Path>,
) {
    for path in sorted_entries(container) {
        if !path.is_file() {
            continue;
        }
        let Some(format) = is_session_file(&path) else {
            // .DS_Store, lock files, materialized index blobs, …
            continue;
        };
        out.push(NativeSource {
            format,
            path,
            store,
            workspace_dir: workspace_dir.map(Path::to_path_buf),
        });
    }
}

fn push_state_db(
    out: &mut Vec<NativeSource>,
    db: PathBuf,
    workspace_dir: Option<&Path>,
) {
    if cfg!(feature = "copilot-vscdb") && db.is_file() {
        out.push(NativeSource {
            format: NativeFormat::StateDb,
            path: db,
            store: STORE_STATE_DB,
            workspace_dir: workspace_dir.map(Path::to_path_buf),
        });
    }
}

fn collect_workspace_storage(out: &mut Vec<NativeSource>, storage_root: &Path) {
    for storage_dir in sorted_entries(storage_root) {
        if !storage_dir.is_dir() {
            continue;
        }
        let container = storage_dir.join("chatSessions");
        if container.is_dir() {
            collect_session_container(out, &container, STORE_WORKSPACE, Some(&storage_dir));
        }
        push_state_db(out, storage_dir.join("state.vscdb"), Some(&storage_dir));
    }
}

fn collect_global_storage(out: &mut Vec<NativeSource>, global_root: &Path) {
    let empty = global_root.join("emptyWindowChatSessions");
    if empty.is_dir() {
        collect_session_container(out, &empty, STORE_EMPTY_WINDOW, None);
    }
    let transferred = global_root.join("transferredChatSessions");
    if transferred.is_dir() {
        collect_session_container(out, &transferred, STORE_TRANSFERRED, None);
    }
    // Application-scoped legacy sessions (empty windows) live in the global
    // state database.
    push_state_db(out, global_root.join("state.vscdb"), None);
}

fn collect_user_root(out: &mut Vec<NativeSource>, user_root: &Path) {
    let workspace_storage = user_root.join("workspaceStorage");
    if workspace_storage.is_dir() {
        collect_workspace_storage(out, &workspace_storage);
    }
    let global_storage = user_root.join("globalStorage");
    if global_storage.is_dir() {
        collect_global_storage(out, &global_storage);
    }
}

fn push_source_for_file(out: &mut Vec<NativeSource>, file: &Path) {
    if dir_name(file) == Some("state.vscdb") {
        let workspace_dir = file.parent().and_then(|storage_dir| {
            storage_dir.parent().and_then(|root| {
                (dir_name(root) == Some("workspaceStorage"))
                    .then(|| storage_dir.to_path_buf())
            })
        });
        push_state_db(out, file.to_path_buf(), workspace_dir.as_deref());
        return;
    }
    let Some(format) = is_session_file(file) else {
        return;
    };
    let container = file.parent();
    let store = container
        .and_then(dir_name)
        .and_then(store_for_container)
        .unwrap_or(STORE_WORKSPACE);
    let workspace_dir = container.and_then(workspace_dir_of_container);
    out.push(NativeSource {
        format,
        path: file.to_path_buf(),
        store,
        workspace_dir,
    });
}

/// Expand one scan base into concrete native session sources.
///
/// Accepts a session file, a session container, a `workspaceStorage` /
/// `globalStorage` / `User` / product directory, a platform config directory
/// (`.config`, `Application Support`, `AppData/Roaming`), or a home-like root.
pub(crate) fn native_sources_under(base: &Path) -> Vec<NativeSource> {
    let mut out = Vec::new();
    if base.is_file() {
        push_source_for_file(&mut out, base);
        return out;
    }
    if !base.is_dir() {
        return out;
    }

    match dir_name(base) {
        Some(name) if store_for_container(name).is_some() => {
            let store = store_for_container(name).unwrap_or(STORE_WORKSPACE);
            let workspace_dir = workspace_dir_of_container(base);
            collect_session_container(&mut out, base, store, workspace_dir.as_deref());
        }
        Some("workspaceStorage") => collect_workspace_storage(&mut out, base),
        Some("globalStorage") => collect_global_storage(&mut out, base),
        Some("User") => collect_user_root(&mut out, base),
        Some(name) if PRODUCT_DIRS.contains(&name) => {
            collect_user_root(&mut out, &base.join("User"));
        }
        Some(".config" | "Application Support" | "Roaming") => {
            for product in PRODUCT_DIRS {
                collect_user_root(&mut out, &base.join(product).join("User"));
            }
        }
        _ => {
            // Home-like base: probe every platform layout plus direct
            // product children (covers %APPDATA%-shaped bases).
            for product in PRODUCT_DIRS {
                collect_user_root(&mut out, &base.join(".config").join(product).join("User"));
                collect_user_root(
                    &mut out,
                    &base
                        .join("Library/Application Support")
                        .join(product)
                        .join("User"),
                );
                collect_user_root(
                    &mut out,
                    &base.join("AppData/Roaming").join(product).join("User"),
                );
                collect_user_root(&mut out, &base.join(product).join("User"));
            }
            if base.join("workspaceStorage").is_dir() || base.join("globalStorage").is_dir() {
                collect_user_root(&mut out, base);
            }
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Append-log replay (objectMutationLog.ts)
// ---------------------------------------------------------------------------

/// Walk `state` to the parent of the final path element, returning the parent
/// and the final key. Fails (None) on any structural mismatch.
fn walk_to_parent<'a, 'p>(
    state: &'a mut Value,
    path: &'p [Value],
) -> Option<(&'a mut Value, &'p Value)> {
    let (last, rest) = path.split_last()?;
    let mut current = state;
    for key in rest {
        current = step_into(current, key)?;
    }
    Some((current, last))
}

fn step_into<'a>(current: &'a mut Value, key: &Value) -> Option<&'a mut Value> {
    if let Some(name) = key.as_str() {
        return current.as_object_mut()?.get_mut(name);
    }
    let idx = usize::try_from(key.as_i64()?).ok()?;
    current.as_array_mut()?.get_mut(idx)
}

/// `{"kind":1,…}`: set `value` at `path` (creating a missing object key).
fn apply_set(state: &mut Value, path: &[Value], value: Value) -> bool {
    let Some((parent, last)) = walk_to_parent(state, path) else {
        return false;
    };
    if let Some(name) = last.as_str() {
        let Some(map) = parent.as_object_mut() else {
            return false;
        };
        map.insert(name.to_string(), value);
        return true;
    }
    let Some(idx) = last.as_i64().and_then(|i| usize::try_from(i).ok()) else {
        return false;
    };
    let Some(arr) = parent.as_array_mut() else {
        return false;
    };
    if idx < arr.len() {
        arr[idx] = value;
        true
    } else if idx == arr.len() {
        arr.push(value);
        true
    } else {
        false
    }
}

/// `{"kind":3,…}`: delete the value at `path` (object key removal; array
/// slots become null, mirroring VS Code's `current[k] = undefined`).
fn apply_delete(state: &mut Value, path: &[Value]) -> bool {
    let Some((parent, last)) = walk_to_parent(state, path) else {
        return false;
    };
    if let Some(name) = last.as_str() {
        let Some(map) = parent.as_object_mut() else {
            return false;
        };
        map.remove(name);
        return true;
    }
    let Some(idx) = last.as_i64().and_then(|i| usize::try_from(i).ok()) else {
        return false;
    };
    let Some(arr) = parent.as_array_mut() else {
        return false;
    };
    if idx < arr.len() {
        arr[idx] = Value::Null;
        true
    } else {
        false
    }
}

/// `{"kind":2,…}`: truncate the array at `path` to `truncate_to` (when given)
/// and append `values`. A missing target array is created, matching VS Code's
/// `current[arrayKey] || []`.
fn apply_push(
    state: &mut Value,
    path: &[Value],
    values: Option<&[Value]>,
    truncate_to: Option<usize>,
) -> bool {
    let Some((parent, last)) = walk_to_parent(state, path) else {
        return false;
    };
    let slot = if let Some(name) = last.as_str() {
        let Some(map) = parent.as_object_mut() else {
            return false;
        };
        map.entry(name.to_string())
            .or_insert_with(|| Value::Array(Vec::new()))
    } else {
        let Some(idx) = last.as_i64().and_then(|i| usize::try_from(i).ok()) else {
            return false;
        };
        let Some(arr) = parent.as_array_mut() else {
            return false;
        };
        match arr.get_mut(idx) {
            Some(existing) => existing,
            None => return false,
        }
    };
    if slot.is_null() {
        *slot = Value::Array(Vec::new());
    }
    let Some(arr) = slot.as_array_mut() else {
        return false;
    };
    if let Some(len) = truncate_to {
        arr.truncate(len);
    }
    if let Some(values) = values {
        arr.extend(values.iter().cloned());
    }
    true
}

/// Replay an append-log transcript into the final session object.
///
/// Returns `None` when no snapshot entry ever establishes a state. A
/// malformed *final* line is tolerated silently as a truncated append (the
/// normal crash/power-loss artifact for this format); malformed or
/// inapplicable interior entries are skipped-and-logged.
pub(crate) fn replay_append_log(content: &str, path: &Path) -> Option<Value> {
    let lines: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let mut state: Option<Value> = None;

    for (pos, line) in lines.iter().enumerate() {
        let is_last = pos + 1 == lines.len();
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            if is_last {
                tracing::debug!(
                    transcript = %path.display(),
                    "copilot: tolerating truncated final append-log line"
                );
            } else {
                tracing::warn!(
                    transcript = %path.display(),
                    line = pos + 1,
                    "copilot: skipping malformed append-log line"
                );
            }
            continue;
        };
        let Some(kind) = entry.get("kind").and_then(Value::as_u64) else {
            tracing::warn!(
                transcript = %path.display(),
                line = pos + 1,
                "copilot: skipping append-log entry without a kind"
            );
            continue;
        };
        if kind == 0 {
            // Snapshot: full state (initial entry or post-compaction rewrite).
            match entry.get("v") {
                Some(v) => state = Some(v.clone()),
                None => {
                    tracing::warn!(
                        transcript = %path.display(),
                        line = pos + 1,
                        "copilot: skipping snapshot entry without a value"
                    );
                }
            }
            continue;
        }
        let Some(current) = state.as_mut() else {
            tracing::warn!(
                transcript = %path.display(),
                line = pos + 1,
                "copilot: skipping mutation entry before any snapshot"
            );
            continue;
        };
        let path_ok = entry.get("k").and_then(Value::as_array);
        let applied = match (kind, path_ok) {
            (1, Some(k)) => apply_set(current, k, entry.get("v").cloned().unwrap_or(Value::Null)),
            (2, Some(k)) => {
                let values = entry.get("v").and_then(Value::as_array).map(Vec::as_slice);
                let truncate_to = entry
                    .get("i")
                    .and_then(Value::as_u64)
                    .and_then(|i| usize::try_from(i).ok());
                apply_push(current, k, values, truncate_to)
            }
            (3, Some(k)) => apply_delete(current, k),
            _ => false,
        };
        if !applied {
            tracing::warn!(
                transcript = %path.display(),
                line = pos + 1,
                kind,
                "copilot: skipping inapplicable append-log mutation"
            );
        }
    }

    state
}

// ---------------------------------------------------------------------------
// Provider filtering
// ---------------------------------------------------------------------------

fn agent_is_copilot(agent: &Value) -> bool {
    if let Some(ext) = agent
        .pointer("/extensionId/value")
        .and_then(Value::as_str)
    {
        if ext.to_ascii_lowercase().starts_with("github.copilot") {
            return true;
        }
    }
    agent
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(|name| name.eq_ignore_ascii_case("github copilot"))
}

/// Admit only sessions whose serialized metadata identifies GitHub Copilot.
/// The native store is shared by all chat providers (issue #16).
pub(crate) fn session_is_copilot(session: &Value) -> bool {
    if session
        .get("responderUsername")
        .and_then(Value::as_str)
        .is_some_and(|name| name.eq_ignore_ascii_case("github copilot"))
    {
        return true;
    }
    session
        .get("requests")
        .and_then(Value::as_array)
        .is_some_and(|requests| {
            requests
                .iter()
                .any(|request| request.get("agent").is_some_and(agent_is_copilot))
        })
}

// ---------------------------------------------------------------------------
// Workspace resolution
// ---------------------------------------------------------------------------

/// Minimal percent-decoding for `file://` URIs (no external dependency).
fn percent_decode(input: &str) -> String {
    fn hex_val(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos] == b'%' && pos + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[pos + 1]), hex_val(bytes[pos + 2])) {
                out.push((hi << 4) | lo);
                pos += 3;
                continue;
            }
        }
        out.push(bytes[pos]);
        pos += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse a `file://` workspace URI into a local path.
fn parse_file_uri(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    let decoded = percent_decode(rest);
    let mut path = decoded.as_str();
    // Windows: `file:///C:/…` decodes to `/C:/…`.
    if cfg!(windows) && path.len() > 2 {
        let chars: Vec<char> = path.chars().take(3).collect();
        if chars[0] == '/' && chars[1].is_ascii_alphabetic() && chars[2] == ':' {
            path = &path[1..];
        }
    }
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// Resolve the workspace folder for a `workspaceStorage/<id>` directory from
/// its `workspace.json` sidecar.
pub(crate) fn workspace_for_storage_dir(storage_dir: &Path) -> Option<PathBuf> {
    let raw = fs::read_to_string(storage_dir.join("workspace.json")).ok()?;
    let val: Value = serde_json::from_str(&raw).ok()?;
    let uri = val
        .get("folder")
        .or_else(|| val.get("workspace"))
        .or_else(|| val.get("configuration"))
        .and_then(Value::as_str)?;
    parse_file_uri(uri)
}

// ---------------------------------------------------------------------------
// Session -> NormalizedConversation
// ---------------------------------------------------------------------------

/// Extract the user-visible text of a serialized request `message`
/// (`string` in old data, `IParsedChatRequest` with `text`/`parts` since).
fn request_text(message: &Value) -> String {
    if let Some(text) = message.as_str() {
        return text.to_string();
    }
    if let Some(text) = message.get("text").and_then(Value::as_str) {
        return text.to_string();
    }
    let Some(parts) = message.get("parts").and_then(Value::as_array) else {
        return String::new();
    };
    parts
        .iter()
        .filter_map(|part| part.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("")
}

/// Extract assistant text and tool invocations from a serialized `response`
/// part array. Markdown parts serialize *without* a `kind`
/// (`toExport` unwraps `markdownContent` to the bare `IMarkdownString`);
/// every other part keeps its `kind` and only the recognized ones are used.
fn response_content(response: &Value) -> (String, Vec<NormalizedInvocation>) {
    let Some(parts) = response.as_array() else {
        return (String::new(), Vec::new());
    };
    let mut texts: Vec<String> = Vec::new();
    let mut invocations: Vec<NormalizedInvocation> = Vec::new();
    for part in parts {
        match part.get("kind").and_then(Value::as_str) {
            None => {
                // Bare IMarkdownString (or treeData, which has no `value`).
                if let Some(text) = part.get("value").and_then(Value::as_str) {
                    if !text.trim().is_empty() {
                        texts.push(text.to_string());
                    }
                }
            }
            Some("markdownContent") => {
                if let Some(text) = part.get("value").and_then(Value::as_str) {
                    if !text.trim().is_empty() {
                        texts.push(text.to_string());
                    }
                }
            }
            Some("markdownVuln") => {
                if let Some(text) = part.pointer("/content/value").and_then(Value::as_str) {
                    if !text.trim().is_empty() {
                        texts.push(text.to_string());
                    }
                }
            }
            Some("toolInvocationSerialized") => {
                let name = part
                    .get("toolId")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty());
                if let Some(name) = name {
                    invocations.push(NormalizedInvocation {
                        kind: "tool".to_string(),
                        name: name.to_string(),
                        raw_name: None,
                        call_id: part
                            .get("toolCallId")
                            .and_then(Value::as_str)
                            .map(String::from),
                        arguments: part
                            .pointer("/toolSpecificData/rawInput")
                            .cloned()
                            .filter(|v| !v.is_null()),
                    });
                }
            }
            // thinking, inlineReference, textEditGroup, codeblockUri, … are
            // presentation/telemetry for our purposes.
            _ => {}
        }
    }
    (texts.join("\n"), invocations)
}

/// Convert one serialized native session into a normalized conversation.
///
/// Returns `None` for sessions that are not Copilot's (shared store) or that
/// carry no conversation content.
pub(crate) fn session_to_conversation(
    session: &Value,
    source_path: &Path,
    store: &'static str,
    workspace: Option<PathBuf>,
) -> Option<NormalizedConversation> {
    if !session.is_object() {
        tracing::debug!(
            source = %source_path.display(),
            "copilot: skipping non-object native chat session"
        );
        return None;
    }
    if !session_is_copilot(session) {
        tracing::debug!(
            source = %source_path.display(),
            "copilot: skipping native chat session from another provider"
        );
        return None;
    }

    let external_id = session
        .get("sessionId")
        .and_then(Value::as_str)
        .map(String::from)
        .or_else(|| {
            source_path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(String::from)
        });

    let explicit_title = session
        .get("customTitle")
        .or_else(|| session.get("computedTitle"))
        .and_then(Value::as_str)
        .filter(|title| !title.trim().is_empty())
        .map(String::from);

    let creation = session.get("creationDate").and_then(parse_timestamp);
    let mut started_at = creation;
    let mut ended_at = session.get("lastMessageDate").and_then(parse_timestamp);

    let requester = session
        .get("requesterUsername")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty());

    let mut messages: Vec<NormalizedMessage> = Vec::new();
    for request in session
        .get("requests")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        // Requests marked hidden were removed on send; they never rendered.
        if request.get("isHidden").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let ts = request.get("timestamp").and_then(parse_timestamp);
        if let Some(t) = ts {
            started_at = Some(started_at.map_or(t, |s| s.min(t)));
            ended_at = Some(ended_at.map_or(t, |e| e.max(t)));
        }

        let user_text = request_text(request.get("message").unwrap_or(&Value::Null));
        if !user_text.trim().is_empty() {
            let mut extra = Map::new();
            if let Some(id) = request.get("requestId").and_then(Value::as_str) {
                extra.insert("request_id".to_string(), Value::String(id.to_string()));
            }
            messages.push(NormalizedMessage {
                idx: 0,
                role: "user".to_string(),
                author: requester.map(String::from).or_else(|| Some("user".to_string())),
                created_at: ts,
                content: user_text,
                extra: Value::Object(extra),
                invocations: Vec::new(),
                snippets: Vec::new(),
            });
        }

        let (assistant_text, invocations) =
            response_content(request.get("response").unwrap_or(&Value::Null));
        if !assistant_text.trim().is_empty() || !invocations.is_empty() {
            let mut extra = Map::new();
            if let Some(id) = request.get("requestId").and_then(Value::as_str) {
                extra.insert("request_id".to_string(), Value::String(id.to_string()));
            }
            if let Some(model) = request.get("modelId").and_then(Value::as_str) {
                extra.insert("model_id".to_string(), Value::String(model.to_string()));
            }
            messages.push(NormalizedMessage {
                idx: 0,
                role: "assistant".to_string(),
                author: Some("copilot".to_string()),
                created_at: None,
                content: assistant_text,
                extra: Value::Object(extra),
                invocations,
                snippets: Vec::new(),
            });
        }
    }

    if messages.is_empty() {
        return None;
    }
    reindex_messages(&mut messages);

    if started_at.is_none() {
        started_at = ended_at;
    }
    if ended_at.is_none() {
        ended_at = started_at;
    }

    let title = explicit_title.or_else(|| {
        messages.iter().find(|m| m.role == "user").map(|m| {
            m.content
                .lines()
                .next()
                .unwrap_or(&m.content)
                .chars()
                .take(120)
                .collect::<String>()
        })
    });

    let mut metadata = Map::new();
    metadata.insert("source".to_string(), Value::String("copilot".to_string()));
    metadata.insert("store".to_string(), Value::String(store.to_string()));
    if let Some(name) = requester {
        metadata.insert(
            "requester_username".to_string(),
            Value::String(name.to_string()),
        );
    }
    if let Some(name) = session.get("responderUsername").and_then(Value::as_str) {
        metadata.insert(
            "responder_username".to_string(),
            Value::String(name.to_string()),
        );
    }
    if let Some(location) = session.get("initialLocation").and_then(Value::as_str) {
        metadata.insert(
            "initial_location".to_string(),
            Value::String(location.to_string()),
        );
    }

    Some(NormalizedConversation {
        agent_slug: "copilot".to_string(),
        external_id,
        title,
        workspace,
        source_path: source_path.to_path_buf(),
        started_at,
        ended_at,
        metadata: Value::Object(metadata),
        messages,
    })
}

// ---------------------------------------------------------------------------
// Legacy SQLite generation (feature "copilot-vscdb")
// ---------------------------------------------------------------------------

/// Read the serialized sessions stored under the legacy `interactive.sessions`
/// key of a `state.vscdb`. Accepts both the persisted array shape and the
/// in-memory map shape defensively.
#[cfg(feature = "copilot-vscdb")]
fn sessions_from_state_db(db_path: &Path) -> Vec<Value> {
    use frankensqlite::compat::{OpenFlags, RowExt};
    use frankensqlite::params;

    use super::sqlite_sync::{ConnectionExt, open_with_flags};

    let conn = match open_with_flags(
        db_path.to_string_lossy().as_ref(),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(conn) => conn,
        Err(err) => {
            tracing::debug!(
                db = %db_path.display(),
                error = %err,
                "copilot: skipping unreadable state.vscdb"
            );
            return Vec::new();
        }
    };
    // Avoid lock errors when VS Code is running.
    let _ = conn.execute("PRAGMA busy_timeout = 5000;");

    let rows = conn.query_map_collect(
        "SELECT value FROM ItemTable WHERE key = 'interactive.sessions' AND value IS NOT NULL",
        params![],
        |row| {
            let value: String = row.get_typed(0)?;
            Ok(value)
        },
    );
    let Ok(rows) = rows else {
        return Vec::new();
    };

    let mut sessions = Vec::new();
    for raw in rows {
        let Ok(val) = serde_json::from_str::<Value>(&raw) else {
            tracing::warn!(
                db = %db_path.display(),
                "copilot: skipping malformed interactive.sessions payload"
            );
            continue;
        };
        match val {
            Value::Array(items) => sessions.extend(items),
            Value::Object(map) => sessions.extend(map.into_values()),
            _ => {
                tracing::warn!(
                    db = %db_path.display(),
                    "copilot: skipping interactive.sessions payload with unexpected shape"
                );
            }
        }
    }
    sessions
}

#[cfg(not(feature = "copilot-vscdb"))]
fn sessions_from_state_db(_db_path: &Path) -> Vec<Value> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Scan / discovery entry points
// ---------------------------------------------------------------------------

/// Collect `(root, source)` pairs from all bases, ordered for deterministic
/// generation-priority deduplication.
fn collect_sources(bases: &[ScanRoot]) -> Vec<(ScanRoot, NativeSource)> {
    let mut out: Vec<(ScanRoot, NativeSource)> = Vec::new();
    for base in bases {
        for source in native_sources_under(&base.path) {
            out.push((base.clone(), source));
        }
    }
    // Newest generation first so migration copies dedupe toward it.
    out.sort_by(|(_, a), (_, b)| a.format.cmp(&b.format).then_with(|| a.path.cmp(&b.path)));
    out
}

fn parse_source(source: &NativeSource, seen_sessions: &mut HashSet<String>) -> Vec<NormalizedConversation> {
    let workspace = source
        .workspace_dir
        .as_deref()
        .and_then(workspace_for_storage_dir);

    let sessions: Vec<Value> = match source.format {
        NativeFormat::FlatJson => {
            let Ok(raw) = fs::read_to_string(&source.path) else {
                return Vec::new();
            };
            match serde_json::from_str::<Value>(&raw) {
                Ok(session) => vec![session],
                Err(err) => {
                    tracing::warn!(
                        source = %source.path.display(),
                        error = %err,
                        "copilot: skipping malformed native chat session file"
                    );
                    return Vec::new();
                }
            }
        }
        NativeFormat::AppendLog => {
            let Ok(raw) = fs::read_to_string(&source.path) else {
                return Vec::new();
            };
            match replay_append_log(&raw, &source.path) {
                Some(session) => vec![session],
                None => return Vec::new(),
            }
        }
        NativeFormat::StateDb => sessions_from_state_db(&source.path),
    };

    let mut out = Vec::new();
    for session in &sessions {
        let Some(conversation) =
            session_to_conversation(session, &source.path, source.store, workspace.clone())
        else {
            continue;
        };
        // Deduplicate by session id across generations, migration copies, and
        // restored backups. A state-db row without a sessionId has no stable
        // identity (its "external id" would be the shared file stem), so it is
        // emitted without participating in dedupe.
        let dedupe_key = match source.format {
            NativeFormat::StateDb => session
                .get("sessionId")
                .and_then(Value::as_str)
                .map(String::from),
            NativeFormat::FlatJson | NativeFormat::AppendLog => conversation.external_id.clone(),
        };
        if let Some(key) = dedupe_key {
            if !seen_sessions.insert(key) {
                continue;
            }
        }
        out.push(conversation);
    }
    out
}

/// Scan every native source reachable from `bases`, deduplicating session ids
/// across storage generations and duplicated trees.
pub(crate) fn scan_native(bases: &[ScanRoot], since_ts: Option<i64>) -> Vec<NormalizedConversation> {
    let mut seen_files: HashSet<PathBuf> = HashSet::new();
    let mut seen_sessions: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for (_root, source) in collect_sources(bases) {
        if !seen_files.insert(dedupe_path_key(&source.path)) {
            continue;
        }
        if !file_modified_since(&source.path, since_ts) {
            continue;
        }
        out.extend(parse_source(&source, &mut seen_sessions));
    }
    out
}

/// Discover the native source files `scan_native` would consume, plus the
/// `workspace.json` sidecars consulted for workspace resolution.
pub(crate) fn discover_native(
    bases: &[ScanRoot],
    since_ts: Option<i64>,
) -> Vec<DiscoveredSourceFile> {
    let mut seen_files: HashSet<PathBuf> = HashSet::new();
    let mut seen_sidecars: HashSet<PathBuf> = HashSet::new();
    let mut out = Vec::new();
    for (root, source) in collect_sources(bases) {
        if !seen_files.insert(dedupe_path_key(&source.path)) {
            continue;
        }
        if !file_modified_since(&source.path, since_ts) {
            continue;
        }
        let role = match source.format {
            NativeFormat::StateDb => DiscoveredSourceRole::SqliteDatabase,
            NativeFormat::FlatJson | NativeFormat::AppendLog => {
                DiscoveredSourceRole::PrimarySessionLog
            }
        };
        out.push(
            DiscoveredSourceFile::new("copilot", &root, source.path.clone(), role, true)
                .with_fs_metadata(),
        );
        if let Some(workspace_dir) = &source.workspace_dir {
            let sidecar = workspace_dir.join("workspace.json");
            if sidecar.is_file() && seen_sidecars.insert(dedupe_path_key(&sidecar)) {
                out.push(
                    DiscoveredSourceFile::new(
                        "copilot",
                        &root,
                        sidecar,
                        DiscoveredSourceRole::MetadataSidecar,
                        false,
                    )
                    .with_fs_metadata(),
                );
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Fixtures below are constructed from the serialized shapes in VS Code's own
// sources (chatModel.ts `toJSON`/`toExport`, objectMutationLog.ts, and the
// pre-2025 chatServiceImpl.ts `interactive.sessions` persistence) — they are
// NOT copied from any external implementation.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    const WS_SESSION_ID: &str = "0a63f42a-0000-4000-8000-000000000001";
    const EMPTY_SESSION_ID: &str = "0a63f42a-0000-4000-8000-000000000002";
    const LOG_SESSION_ID: &str = "0a63f42a-0000-4000-8000-000000000003";

    fn copilot_agent() -> Value {
        json!({
            "id": "github.copilot.default",
            "name": "GitHub Copilot",
            "extensionId": {"value": "GitHub.copilot-chat", "_lower": "github.copilot-chat"},
            "extensionPublisherId": "GitHub",
            "locations": ["panel"],
            "metadata": {}
        })
    }

    fn copilot_request(id: &str, prompt: &str, answer: &str, ts: i64) -> Value {
        json!({
            "requestId": id,
            "message": {
                "text": prompt,
                "parts": [{"kind": "text", "text": prompt, "range": {"start": 0, "endExclusive": prompt.len()}}]
            },
            "variableData": {"variables": []},
            "response": [{"value": answer, "isTrusted": false}],
            "agent": copilot_agent(),
            "timestamp": ts,
            "modelId": "gpt-5-codex",
            "result": {"timings": {"totalElapsed": 1234}}
        })
    }

    fn copilot_session(session_id: &str, prompt: &str, answer: &str) -> Value {
        json!({
            "version": 3,
            "sessionId": session_id,
            "creationDate": 1_755_000_000_000_i64,
            "customTitle": null,
            "initialLocation": "panel",
            "requesterUsername": "octocat",
            "responderUsername": "GitHub Copilot",
            "requests": [copilot_request("request_1", prompt, answer, 1_755_000_060_000)]
        })
    }

    fn other_provider_session(session_id: &str) -> Value {
        json!({
            "version": 3,
            "sessionId": session_id,
            "creationDate": 1_755_000_000_000_i64,
            "initialLocation": "panel",
            "requesterUsername": "octocat",
            "responderUsername": "Continue",
            "requests": [{
                "requestId": "request_1",
                "message": {"text": "hi", "parts": []},
                "variableData": {"variables": []},
                "response": [{"value": "hello from another provider"}],
                "agent": {
                    "id": "continue.continue",
                    "name": "Continue",
                    "extensionId": {"value": "Continue.continue", "_lower": "continue.continue"}
                },
                "timestamp": 1_755_000_060_000_i64
            }]
        })
    }

    fn write_file(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, contents).expect("write fixture");
    }

    /// Build a realistic `User` tree:
    /// - workspaceStorage/<hash>/chatSessions/<id>.json (+ workspace.json)
    /// - workspaceStorage/<hash>/chatSessions/<id>.jsonl (append log)
    /// - globalStorage/emptyWindowChatSessions/<id>.json
    /// - a non-Copilot session that must be filtered out
    fn build_user_tree(user_root: &Path) -> PathBuf {
        let storage_dir = user_root.join("workspaceStorage/1f0e2d3c4b5a6978");
        write_file(
            &storage_dir.join("workspace.json"),
            r#"{"folder": "file:///home/octocat/proj%20x"}"#,
        );
        write_file(
            &storage_dir.join("chatSessions").join(format!("{WS_SESSION_ID}.json")),
            &copilot_session(WS_SESSION_ID, "Explain this borrow error", "Clone before the loop.")
                .to_string(),
        );
        // Harness noise that must never be parsed as a session.
        write_file(&storage_dir.join("chatSessions/.DS_Store"), "junk");

        // Append log: snapshot, then a pushed second request, then a set that
        // rewrites the second answer, then a truncated final line.
        let log_path = storage_dir
            .join("chatSessions")
            .join(format!("{LOG_SESSION_ID}.jsonl"));
        let snapshot = copilot_session(LOG_SESSION_ID, "Add a unit test", "Draft test added.");
        let pushed = copilot_request(
            "request_2",
            "Now make it pass",
            "placeholder",
            1_755_000_120_000,
        );
        let lines = [
            json!({"kind": 0, "v": snapshot}).to_string(),
            json!({"kind": 1, "k": ["customTitle"], "v": "Unit test session"}).to_string(),
            json!({"kind": 2, "k": ["requests"], "v": [pushed]}).to_string(),
            json!({"kind": 1, "k": ["requests", 1, "response", 0, "value"], "v": "Assertion fixed."})
                .to_string(),
            json!({"kind": 3, "k": ["inputState"]}).to_string(),
            // Truncated final append (crash artifact) — must be tolerated.
            "{\"kind\":2,\"k\":[\"requests\"],\"v\":[{\"requestId\":\"request_3\"".to_string(),
        ];
        write_file(&log_path, &lines.join("\n"));

        write_file(
            &user_root
                .join("globalStorage/emptyWindowChatSessions")
                .join(format!("{EMPTY_SESSION_ID}.json")),
            &copilot_session(EMPTY_SESSION_ID, "Quick question", "Quick answer.").to_string(),
        );
        write_file(
            &user_root
                .join("globalStorage/emptyWindowChatSessions")
                .join("other-provider.json"),
            &other_provider_session("other-provider-1").to_string(),
        );
        storage_dir
    }

    fn roots(path: &Path) -> Vec<ScanRoot> {
        vec![ScanRoot::local(path.to_path_buf())]
    }

    #[test]
    fn flat_json_workspace_session_parses_with_workspace() {
        let temp = TempDir::new().expect("tempdir");
        let user_root = temp.path().join("Code/User");
        build_user_tree(&user_root);

        let convs = scan_native(&roots(&user_root), None);
        let ws = convs
            .iter()
            .find(|c| c.external_id.as_deref() == Some(WS_SESSION_ID))
            .expect("workspace session");
        assert_eq!(ws.agent_slug, "copilot");
        // workspace.json file URI resolved, percent-decoding included.
        assert_eq!(ws.workspace, Some(PathBuf::from("/home/octocat/proj x")));
        assert_eq!(ws.metadata["store"], json!("vscode-workspace"));
        assert_eq!(ws.metadata["requester_username"], json!("octocat"));
        assert_eq!(ws.started_at, Some(1_755_000_000_000));
        assert_eq!(ws.ended_at, Some(1_755_000_060_000));

        let roles: Vec<&str> = ws.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, vec!["user", "assistant"]);
        assert_eq!(ws.messages[0].content, "Explain this borrow error");
        assert_eq!(ws.messages[1].content, "Clone before the loop.");
        assert_eq!(ws.messages[1].extra["model_id"], json!("gpt-5-codex"));
        assert_eq!(ws.title.as_deref(), Some("Explain this borrow error"));
    }

    #[test]
    fn append_log_replays_push_set_delete_and_tolerates_truncation() {
        let temp = TempDir::new().expect("tempdir");
        let user_root = temp.path().join("Code/User");
        build_user_tree(&user_root);

        let convs = scan_native(&roots(&user_root), None);
        let log = convs
            .iter()
            .find(|c| c.external_id.as_deref() == Some(LOG_SESSION_ID))
            .expect("append-log session");
        // kind:1 set of customTitle applied.
        assert_eq!(log.title.as_deref(), Some("Unit test session"));
        // kind:2 push added the second request, kind:1 rewrote its answer.
        let contents: Vec<&str> = log.messages.iter().map(|m| m.content.as_str()).collect();
        assert_eq!(
            contents,
            vec![
                "Add a unit test",
                "Draft test added.",
                "Now make it pass",
                "Assertion fixed."
            ]
        );
        // Truncated final line was tolerated (session still parsed).
        assert_eq!(log.workspace, Some(PathBuf::from("/home/octocat/proj x")));
    }

    #[test]
    fn empty_window_sessions_are_scanned_and_other_providers_filtered() {
        let temp = TempDir::new().expect("tempdir");
        let user_root = temp.path().join("Code/User");
        build_user_tree(&user_root);

        let convs = scan_native(&roots(&user_root), None);
        let empty = convs
            .iter()
            .find(|c| c.external_id.as_deref() == Some(EMPTY_SESSION_ID))
            .expect("empty-window session");
        assert_eq!(empty.metadata["store"], json!("vscode-empty-window"));
        assert_eq!(empty.workspace, None);

        // The non-Copilot session in the same shared store must NOT appear.
        assert!(
            convs
                .iter()
                .all(|c| c.external_id.as_deref() != Some("other-provider-1")),
            "non-Copilot session must be filtered out of the shared store"
        );
        assert_eq!(convs.len(), 3);
    }

    #[test]
    fn transferred_sessions_are_scanned() {
        let temp = TempDir::new().expect("tempdir");
        let user_root = temp.path().join("Code/User");
        write_file(
            &user_root
                .join("globalStorage/transferredChatSessions")
                .join("transfer-1.json"),
            &copilot_session("transfer-1", "Moved chat", "Still here.").to_string(),
        );
        let convs = scan_native(&roots(&user_root), None);
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].metadata["store"], json!("vscode-transferred"));
    }

    #[test]
    fn duplicate_session_id_across_generations_prefers_append_log() {
        let temp = TempDir::new().expect("tempdir");
        let user_root = temp.path().join("Code/User");
        let container = user_root.join("workspaceStorage/aa11/chatSessions");
        // Same session id as both migrated flat JSON and current append log.
        write_file(
            &container.join("dup-1.json"),
            &copilot_session("dup-1", "old copy", "old answer").to_string(),
        );
        write_file(
            &container.join("dup-1.jsonl"),
            &json!({"kind": 0, "v": copilot_session("dup-1", "new copy", "new answer")})
                .to_string(),
        );
        let convs = scan_native(&roots(&user_root), None);
        assert_eq!(convs.len(), 1, "one conversation per session id");
        assert_eq!(convs[0].messages[0].content, "new copy");
        assert!(
            convs[0]
                .source_path
                .extension()
                .is_some_and(|ext| ext == "jsonl"),
            "append-log generation must win the dedupe"
        );
    }

    #[test]
    fn scan_root_may_point_at_container_or_single_file() {
        let temp = TempDir::new().expect("tempdir");
        let user_root = temp.path().join("Code/User");
        let storage_dir = build_user_tree(&user_root);

        // Directly at a chatSessions container.
        let container = storage_dir.join("chatSessions");
        let convs = scan_native(&roots(&container), None);
        assert_eq!(convs.len(), 2);
        assert!(
            convs
                .iter()
                .all(|c| c.workspace == Some(PathBuf::from("/home/octocat/proj x"))),
            "container scans must still resolve the workspace"
        );

        // Directly at one session file.
        let file = container.join(format!("{WS_SESSION_ID}.json"));
        let convs = scan_native(&roots(&file), None);
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some(WS_SESSION_ID));
    }

    #[test]
    fn config_and_home_shaped_bases_expand_to_user_roots() {
        let temp = TempDir::new().expect("tempdir");
        let home = temp.path().join("home");
        let user_root = home.join(".config/Code - Insiders/User");
        write_file(
            &user_root
                .join("workspaceStorage/bb22/chatSessions")
                .join("cfg-1.json"),
            &copilot_session("cfg-1", "From insiders", "Answered.").to_string(),
        );

        // Home-shaped base.
        assert_eq!(scan_native(&roots(&home), None).len(), 1);
        // .config-shaped base.
        assert_eq!(scan_native(&roots(&home.join(".config")), None).len(), 1);
        // Product-shaped base.
        assert_eq!(
            scan_native(&roots(&home.join(".config/Code - Insiders")), None).len(),
            1
        );
    }

    #[test]
    fn nonexistent_and_empty_bases_yield_nothing() {
        let temp = TempDir::new().expect("tempdir");
        assert!(scan_native(&roots(&temp.path().join("missing")), None).is_empty());
        let empty = temp.path().join("empty");
        fs::create_dir_all(&empty).expect("mkdir");
        assert!(scan_native(&roots(&empty), None).is_empty());
    }

    #[test]
    fn since_ts_filters_stale_files() {
        let temp = TempDir::new().expect("tempdir");
        let user_root = temp.path().join("Code/User");
        build_user_tree(&user_root);
        let far_future = chrono::Utc::now().timestamp_millis() + 86_400_000;
        assert!(scan_native(&roots(&user_root), Some(far_future)).is_empty());
    }

    #[test]
    fn discovery_lists_scanned_files_and_workspace_sidecars() {
        let temp = TempDir::new().expect("tempdir");
        let user_root = temp.path().join("Code/User");
        build_user_tree(&user_root);

        let bases = roots(&user_root);
        let discovered = discover_native(&bases, None);
        let discovered_paths: HashSet<&Path> =
            discovered.iter().map(|s| s.source_path.as_path()).collect();
        for conv in scan_native(&bases, None) {
            assert!(
                discovered_paths.contains(conv.source_path.as_path()),
                "discovery must include scanned source {}",
                conv.source_path.display()
            );
        }
        assert!(
            discovered.iter().any(|s| {
                s.role == DiscoveredSourceRole::MetadataSidecar
                    && s.source_path.ends_with("workspace.json")
            }),
            "workspace.json sidecar should be discovered"
        );
        assert!(
            discovered
                .iter()
                .filter(|s| s.role == DiscoveredSourceRole::PrimarySessionLog)
                .all(|s| s.required_for_reconstruction && s.provider_slug == "copilot")
        );
    }

    #[test]
    fn malformed_interior_log_lines_are_skipped_not_fatal() {
        let path = PathBuf::from("/test/session.jsonl");
        let content = [
            json!({"kind": 0, "v": {"sessionId": "s", "responderUsername": "GitHub Copilot",
                "requests": [{"message": "hello", "response": [{"value": "hi"}],
                              "timestamp": 1_755_000_000_000_i64}]}})
            .to_string(),
            "garbage not json".to_string(),
            json!({"kind": 1, "k": ["customTitle"], "v": "kept"}).to_string(),
        ]
        .join("\n");
        let session = replay_append_log(&content, &path).expect("state survives");
        assert_eq!(session["customTitle"], json!("kept"));
    }

    #[test]
    fn append_log_without_snapshot_yields_none() {
        let path = PathBuf::from("/test/session.jsonl");
        let content = json!({"kind": 1, "k": ["customTitle"], "v": "x"}).to_string();
        assert!(replay_append_log(&content, &path).is_none());
    }

    #[test]
    fn append_log_push_truncates_from_index() {
        let path = PathBuf::from("/test/session.jsonl");
        let content = [
            json!({"kind": 0, "v": {"items": [1, 2, 3, 4]}}).to_string(),
            // Undo the last two entries, push one replacement.
            json!({"kind": 2, "k": ["items"], "v": [9], "i": 2}).to_string(),
        ]
        .join("\n");
        let state = replay_append_log(&content, &path).expect("state");
        assert_eq!(state["items"], json!([1, 2, 9]));
    }

    #[test]
    fn session_is_copilot_requires_copilot_evidence() {
        assert!(session_is_copilot(&copilot_session("a", "q", "a")));
        assert!(!session_is_copilot(&other_provider_session("b")));
        // extensionId evidence alone suffices even without responderUsername.
        let by_agent = json!({
            "sessionId": "c",
            "requests": [{"agent": {"extensionId": {"value": "GitHub.copilot-chat"}}}]
        });
        assert!(session_is_copilot(&by_agent));
        // No evidence at all — never attribute.
        assert!(!session_is_copilot(&json!({"sessionId": "d", "requests": []})));
    }

    #[test]
    fn legacy_string_message_and_old_shapes_parse() {
        // Pre-parsed-request era: message is a plain string, response parts
        // are bare markdown strings, version key absent.
        let session = json!({
            "sessionId": "legacy-1",
            "creationDate": 1_700_000_000_000_i64,
            "requesterUsername": "octocat",
            "responderUsername": "GitHub Copilot",
            "requests": [{
                "message": "How do I sort a vec?",
                "response": [{"value": "Use .sort()."}]
            }]
        });
        let conv = session_to_conversation(
            &session,
            Path::new("/db/state.vscdb"),
            STORE_STATE_DB,
            None,
        )
        .expect("legacy session parses");
        assert_eq!(conv.messages.len(), 2);
        assert_eq!(conv.messages[0].content, "How do I sort a vec?");
        assert_eq!(conv.messages[1].content, "Use .sort().");
        assert_eq!(conv.started_at, Some(1_700_000_000_000));
    }

    #[test]
    fn tool_invocations_and_non_text_parts_are_handled() {
        let session = json!({
            "sessionId": "tools-1",
            "responderUsername": "GitHub Copilot",
            "requests": [{
                "message": "run the tests",
                "timestamp": 1_755_000_000_000_i64,
                "response": [
                    {"kind": "inlineReference", "inlineReference": {"uri": "file:///x"}},
                    {"kind": "toolInvocationSerialized", "toolId": "run_tests",
                     "toolCallId": "call-9", "isComplete": true,
                     "invocationMessage": "Running tests",
                     "toolSpecificData": {"kind": "input", "rawInput": {"filter": "unit"}}},
                    {"value": "All 12 tests pass."},
                    {"kind": "thinking", "value": "internal reasoning"}
                ]
            }]
        });
        let conv = session_to_conversation(
            &session,
            Path::new("/x/tools-1.json"),
            STORE_WORKSPACE,
            None,
        )
        .expect("session parses");
        let assistant = &conv.messages[1];
        assert_eq!(assistant.content, "All 12 tests pass.");
        assert_eq!(assistant.invocations.len(), 1);
        assert_eq!(assistant.invocations[0].name, "run_tests");
        assert_eq!(assistant.invocations[0].call_id.as_deref(), Some("call-9"));
        assert_eq!(
            assistant.invocations[0].arguments,
            Some(json!({"filter": "unit"}))
        );
    }

    #[test]
    fn hidden_requests_and_empty_sessions_are_skipped() {
        let mut session = copilot_session("hidden-1", "visible", "answer");
        session["requests"][0]["isHidden"] = json!(true);
        assert!(
            session_to_conversation(
                &session,
                Path::new("/x/hidden-1.json"),
                STORE_WORKSPACE,
                None
            )
            .is_none(),
            "session with only hidden requests has no content"
        );
    }

    #[test]
    fn parse_file_uri_handles_plain_and_encoded_paths() {
        assert_eq!(
            parse_file_uri("file:///home/user/project"),
            Some(PathBuf::from("/home/user/project"))
        );
        assert_eq!(
            parse_file_uri("file:///home/user/my%20project"),
            Some(PathBuf::from("/home/user/my project"))
        );
        assert_eq!(parse_file_uri("vscode-remote://ssh/x"), None);
    }

    // --- Legacy SQLite generation (feature "copilot-vscdb") ---

    #[cfg(feature = "copilot-vscdb")]
    mod state_db {
        use super::*;
        use crate::connectors::sqlite_sync::{Connection, ConnectionExt};
        use frankensqlite::params;

        fn write_state_db(db_path: &Path, sessions: &Value) {
            fs::create_dir_all(db_path.parent().expect("parent")).expect("mkdir");
            let conn = Connection::open(db_path.to_string_lossy().as_ref()).expect("open db");
            conn.execute("CREATE TABLE IF NOT EXISTS ItemTable (key TEXT PRIMARY KEY, value TEXT)")
                .expect("create table");
            conn.execute_compat(
                "INSERT INTO ItemTable (key, value) VALUES (?, ?)",
                params!["interactive.sessions", sessions.to_string()],
            )
            .expect("insert sessions");
            // Index metadata key that must never be treated as a transcript.
            conn.execute_compat(
                "INSERT INTO ItemTable (key, value) VALUES (?, ?)",
                params!["chat.ChatSessionStore.index", "{\"version\":1,\"entries\":{}}"],
            )
            .expect("insert index");
        }

        #[test]
        fn legacy_workspace_state_db_sessions_parse() {
            let temp = TempDir::new().expect("tempdir");
            let user_root = temp.path().join("Code/User");
            let storage_dir = user_root.join("workspaceStorage/cc33");
            write_file(
                &storage_dir.join("workspace.json"),
                r#"{"folder": "file:///work/legacy"}"#,
            );
            write_state_db(
                &storage_dir.join("state.vscdb"),
                &json!([
                    copilot_session("sql-1", "Legacy question", "Legacy answer."),
                    other_provider_session("sql-other"),
                ]),
            );

            let convs = scan_native(&roots(&user_root), None);
            assert_eq!(convs.len(), 1, "only the Copilot session is admitted");
            assert_eq!(convs[0].external_id.as_deref(), Some("sql-1"));
            assert_eq!(convs[0].workspace, Some(PathBuf::from("/work/legacy")));
            assert_eq!(convs[0].metadata["store"], json!("vscode-state-db"));
        }

        #[test]
        fn global_state_db_carries_empty_window_scope_sessions() {
            let temp = TempDir::new().expect("tempdir");
            let user_root = temp.path().join("Code/User");
            write_state_db(
                &user_root.join("globalStorage/state.vscdb"),
                &json!([copilot_session("sql-global-1", "No folder open", "Sure.")]),
            );
            let convs = scan_native(&roots(&user_root), None);
            assert_eq!(convs.len(), 1);
            assert_eq!(convs[0].workspace, None);
        }

        #[test]
        fn newer_generation_wins_over_state_db_copy() {
            let temp = TempDir::new().expect("tempdir");
            let user_root = temp.path().join("Code/User");
            let storage_dir = user_root.join("workspaceStorage/dd44");
            write_state_db(
                &storage_dir.join("state.vscdb"),
                &json!([copilot_session("mig-1", "old sqlite copy", "old")]),
            );
            write_file(
                &storage_dir.join("chatSessions/mig-1.json"),
                &copilot_session("mig-1", "migrated copy", "new").to_string(),
            );
            let convs = scan_native(&roots(&user_root), None);
            assert_eq!(convs.len(), 1);
            assert_eq!(convs[0].messages[0].content, "migrated copy");
        }

        #[test]
        fn map_shaped_interactive_sessions_payload_is_accepted() {
            let temp = TempDir::new().expect("tempdir");
            let user_root = temp.path().join("Code/User");
            write_state_db(
                &user_root.join("workspaceStorage/ee55/state.vscdb"),
                &json!({"map-1": copilot_session("map-1", "Map shaped", "Yes.")}),
            );
            let convs = scan_native(&roots(&user_root), None);
            assert_eq!(convs.len(), 1);
            assert_eq!(convs[0].external_id.as_deref(), Some("map-1"));
        }
    }
}
