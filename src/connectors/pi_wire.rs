//! Shared session-store primitives for the pi-mono agent family.
//!
//! Oh My Pi (`omp`, <https://omp.sh>) is a pi-mono derivative that kept the
//! JSONL session-store layout: sessions live under
//! `<agent-home>/sessions/<safe-path>/<timestamp>_<uuid>.jsonl` and each file
//! is an append-only log of typed entries (`session` header, `message`,
//! `model_change`, `thinking_level_change`; omp additionally writes `title`
//! entries). Because the two distributions share this wire format, the
//! traversal and parsing primitives live here once and are consumed by both
//! the [`crate::connectors::pi_agent`] and [`crate::connectors::omp`]
//! connectors — only root discovery differs between them.
//!
//! Entry kinds beyond plain turns are preserved with identifiable provenance
//! (`extra.cass.entry_kind` / `source_role`): `compaction` and
//! `branch_summary` summaries (role `system`, prefixed `[compaction]` /
//! `[branch summary]`), extension `custom_message`s and in-message `custom`
//! roles, and `bashExecution` shell runs. System messages and compaction
//! system checkpoints (prompt sections, tool declarations) are never indexed.
//! Every branch in the file is kept (archive semantics) and annotated with
//! `on_active_branch` / `in_active_context`; see [`parse_session_file`].
//!
//! omp-specific extensions handled tolerantly:
//! - `title` entries (`{"type":"title","title":...}`) supply the
//!   conversation title when present; otherwise the `session` header title,
//!   then the first user message, is used.
//! - `model_change` entries carry a bare `model` field (pi-mono writes
//!   `provider` + `modelId`); either spelling updates the tracked model.

use super::utils::{dedupe_path_key, excluded_scan_paths_from_env, path_is_excluded, read_capped};
use crate::types::{NormalizedConversation, NormalizedMessage};
use anyhow::Result;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// The sessions directory under a pi-family agent home, or the home itself
/// when no `sessions/` child exists (older layouts scanned the home directly).
#[must_use]
pub fn sessions_dir(home: &Path) -> PathBuf {
    let sessions = home.join("sessions");
    if sessions.exists() {
        sessions
    } else {
        home.to_path_buf()
    }
}

/// Resolve a home path through symlinks so per-file dedupe keys stay stable
/// regardless of whether a caller reached the store via a symlinked ancestor.
fn dedupe_home(home: &Path) -> PathBuf {
    std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf())
}

/// Find all session JSONL files under the given pi-family root, in
/// deterministic (sorted) order.
///
/// Pi-agent session files are named `<timestamp>_<uuid>.jsonl`. Oh My Pi
/// additionally writes sub-agent transcripts as `<AgentName>.jsonl` inside a
/// sibling directory named after the session
/// (`…/<timestamp>_<uuid>/<AgentName>.jsonl`); each is a complete session
/// document with its own `session` header, so it parses like any main
/// transcript. A `.jsonl` is accepted when it is named like a session, or it
/// lives inside a session directory — recognized by its `_` marker AND the
/// main transcript `<dir>.jsonl` sitting beside it. The sibling requirement
/// matters: workspace-slug directories preserve underscores from the original
/// cwd (path encoding only rewrites `/`, `\`, `:`), so "parent contains `_`"
/// alone would sweep stray `.jsonl` exports under any project whose path
/// contains an underscore.
#[must_use]
pub fn session_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let sessions = sessions_dir(root);
    if !sessions.exists() {
        return out;
    }
    for entry in WalkDir::new(sessions).into_iter().flatten() {
        if entry.file_type().is_file() {
            let name = entry.file_name().to_str().unwrap_or("");
            let is_jsonl = Path::new(name)
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"));
            if !is_jsonl {
                continue;
            }
            let parent_is_session_dir = entry.path().parent().is_some_and(|parent| {
                let has_session_marker = parent
                    .file_name()
                    .and_then(|dir| dir.to_str())
                    .is_some_and(|dir| dir.contains('_'));
                has_session_marker && {
                    let mut main_transcript = parent.as_os_str().to_owned();
                    main_transcript.push(".jsonl");
                    Path::new(&main_transcript).is_file()
                }
            });
            if name.contains('_') || parent_is_session_dir {
                out.push(entry.path().to_path_buf());
            }
        }
    }
    // Keep connector traversal deterministic across filesystems/runs.
    out.sort();
    out
}

/// Flatten a pi-family message content value to a searchable string.
///
/// Handles the message.content shapes seen across the family:
/// - A bare string (simple user messages)
/// - An array of content blocks:
///   - `TextContent`: `{type: "text", text: "..."}`
///   - `ThinkingContent`: `{type: "thinking", thinking: "..."}`
///   - `ToolCall`: `{type: "toolCall", name: "...", arguments: {...}}`
///   - `ImageContent`: `{type: "image", ...}` (skipped for text extraction)
#[must_use]
pub fn flatten_message_content(content: &Value) -> String {
    // Direct string content (simple user messages)
    if let Some(s) = content.as_str() {
        return s.to_string();
    }

    // Array of content blocks
    if let Some(arr) = content.as_array() {
        let parts: Vec<String> = arr
            .iter()
            .filter_map(|item| {
                let item_type = item.get("type").and_then(|v| v.as_str());

                match item_type {
                    Some("text") => item.get("text").and_then(|v| v.as_str()).map(String::from),
                    Some("thinking") => {
                        // Include thinking content - valuable for search
                        item.get("thinking")
                            .and_then(|v| v.as_str())
                            .map(|t| format!("[Thinking] {t}"))
                    }
                    Some("toolCall") => {
                        // Include tool calls for searchability
                        let name = item
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let args = item
                            .get("arguments")
                            .map(|a| {
                                // Extract key argument values for context
                                a.as_object().map_or_else(String::new, |obj| {
                                    obj.iter()
                                        .filter_map(|(k, v)| v.as_str().map(|s| format!("{k}={s}")))
                                        .take(3) // Limit to avoid huge strings
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                })
                            })
                            .unwrap_or_default();
                        if args.is_empty() {
                            Some(format!("[Tool: {name}]"))
                        } else {
                            Some(format!("[Tool: {name}] {args}"))
                        }
                    }
                    _ => None, // Skip image and unknown content
                }
            })
            .collect();
        return parts.join("\n");
    }

    String::new()
}

/// Roles a pi-family `message` entry can carry that map to a fixed
/// normalized role. Anything else keeps its raw role (pi's `AgentMessage`
/// union is open: extensions may add roles via declaration merging).
const fn normalized_role(role: &str) -> Option<&'static str> {
    match role.as_bytes() {
        // Besides plain user turns: direct shell commands (`bashExecution`:
        // `!cmd` in the TUI, the RPC `bash` command) and extension-injected
        // context (`custom`; `hookMessage` before v3). Pi converts both to
        // user-role text before the next model request, which is also how
        // the Prime connector normalizes them.
        b"user" | b"bashExecution" | b"custom" | b"hookMessage" => Some("user"),
        b"assistant" => Some("assistant"),
        b"toolResult" => Some("tool"),
        // Context messages synthesized from summary entries.
        b"branchSummary" | b"compactionSummary" => Some("system"),
        _ => None,
    }
}

/// One tree entry of a pi-family session file (everything except the
/// `session` header, which is metadata only and not part of the tree).
struct WireEntry {
    value: Value,
    /// 1-based physical line in the source file: a stable source locator.
    line: usize,
    /// Position among all parsed records including the header; v1 compaction
    /// entries address their first kept entry by this index.
    file_index: usize,
    /// The entry's own id, when the file carries one (v2+).
    id: Option<String>,
    /// Resolved parent entry. v1 entries without ids are linked in file
    /// order, exactly as pi's v1→v2 migration links them.
    parent: Option<usize>,
}

impl WireEntry {
    fn entry_type(&self) -> &str {
        self.value.get("type").and_then(Value::as_str).unwrap_or("")
    }

    fn message_role(&self) -> Option<&str> {
        self.value
            .get("message")
            .and_then(|m| m.get("role"))
            .and_then(Value::as_str)
    }

    fn is_system_message(&self) -> bool {
        self.entry_type() == "message" && self.message_role() == Some("system")
    }
}

/// Integrity of the reconstructed `id`/`parentId` tree.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TreeIntegrity {
    /// v2+ tree with every parent present.
    Ok,
    /// v1 linear log (no entry ids); file order is the only branch.
    Linear,
    /// At least one `parentId` names an entry absent from the file. Branches
    /// cannot be told apart, so the file falls back to file order.
    MissingParent,
    /// The `parentId` links loop; the file falls back to file order.
    Cycle,
}

impl TreeIntegrity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Linear => "linear",
            Self::MissingParent => "missing_parent",
            Self::Cycle => "cycle",
        }
    }
}

/// Branch- and context-aware view over the entries of one session file.
///
/// Pi stores every branch of a conversation in one append-only file. This
/// crate indexes the whole archive (abandoned branches included, so archive
/// search never silently loses them), and annotates each emitted message with
/// whether it lies on the ACTIVE branch (pi's current leaf, which on load is
/// the last entry in the file, walked to its root) and whether it is part of
/// the ACTIVE MODEL CONTEXT (that branch after the latest compaction and the
/// latest `context_edit` for each target are applied — mirroring pi's
/// `buildContextEntries` / `buildSessionProjection`).
struct WireTree {
    on_active_branch: Vec<bool>,
    in_active_context: Vec<bool>,
    /// The newest compaction on the active branch: the only one whose
    /// summary is part of the model context.
    context_compaction: Option<usize>,
    /// `context_edit` effects on in-context targets: `"omitted"` or
    /// `"replaced"`.
    context_edits: HashMap<usize, &'static str>,
    /// Effective `(provider, model)` selection after each entry, inherited
    /// along its OWN ancestor chain only.
    model_state: Vec<(Option<String>, Option<String>)>,
    branch_leaf_count: usize,
    active_branch_len: usize,
    integrity: TreeIntegrity,
}

impl WireTree {
    #[allow(clippy::too_many_lines)]
    fn build(
        entries: &mut [WireEntry],
        header_provider: Option<&String>,
        header_model: Option<&String>,
    ) -> Self {
        let n = entries.len();
        // v1 logs carry no ids: every entry is a tree node, linked in file
        // order (pi's v1→v2 migration). In v2+ files, id-less lines (e.g.
        // omp's standalone `title` records) are metadata, not tree nodes.
        let has_ids = entries.iter().any(|e| e.id.is_some());
        let is_node = |e: &WireEntry| !has_ids || e.id.is_some();
        let mut integrity = if has_ids {
            TreeIntegrity::Ok
        } else {
            TreeIntegrity::Linear
        };

        // Resolve parents. Last write wins for duplicated ids, matching pi's
        // `Map.set` index.
        let mut by_id: HashMap<String, usize> = HashMap::new();
        for (idx, entry) in entries.iter().enumerate() {
            if let Some(id) = &entry.id {
                by_id.insert(id.clone(), idx);
            }
        }
        if has_ids {
            for (idx, entry) in entries.iter_mut().enumerate() {
                if entry.id.is_none() {
                    continue;
                }
                let parent_id = entry.value.get("parentId").and_then(Value::as_str);
                entry.parent = parent_id.and_then(|parent_id| match by_id.get(parent_id) {
                    Some(&parent_idx) if parent_idx != idx => Some(parent_idx),
                    _ => {
                        integrity = TreeIntegrity::MissingParent;
                        None
                    }
                });
            }
            if integrity == TreeIntegrity::Ok && has_parent_cycle(entries) {
                integrity = TreeIntegrity::Cycle;
            }
        }
        if integrity != TreeIntegrity::Ok {
            // Linear log, or a broken tree whose branches cannot be told
            // apart: file order is the only defensible branch (the same
            // fallback the Prime connector uses). A broken tree is reported
            // through `tree.integrity` instead of emitting an apparently
            // complete orphan suffix.
            let mut previous = None;
            for (idx, entry) in entries.iter_mut().enumerate() {
                if is_node(entry) {
                    entry.parent = previous;
                    previous = Some(idx);
                } else {
                    entry.parent = None;
                }
            }
        }

        // Active branch: pi's leaf on load is the last tree entry in the
        // file, walked to its root.
        let mut on_active_branch = vec![false; n];
        let mut path = Vec::new();
        let mut cursor = entries.iter().rposition(is_node);
        while let Some(idx) = cursor {
            if on_active_branch[idx] {
                break;
            }
            on_active_branch[idx] = true;
            path.push(idx);
            cursor = entries[idx].parent;
        }
        path.reverse();

        let mut has_child = vec![false; n];
        for entry in entries.iter() {
            if let Some(parent) = entry.parent {
                has_child[parent] = true;
            }
        }
        let branch_leaf_count = entries
            .iter()
            .zip(&has_child)
            .filter(|(entry, has_child)| is_node(entry) && !**has_child)
            .count();

        // Active context: the latest compaction on the path replaces the
        // entries before its first kept entry (system messages in the kept
        // range fold into the compaction checkpoint).
        let mut in_active_context = vec![false; n];
        let context_compaction = path
            .iter()
            .rposition(|&idx| entries[idx].entry_type() == "compaction");
        match context_compaction {
            None => {
                for &idx in &path {
                    in_active_context[idx] = true;
                }
            }
            Some(pos) => {
                let compaction = &entries[path[pos]];
                let first_kept_id = compaction
                    .value
                    .get("firstKeptEntryId")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                // v1 compactions address the first kept record by its index
                // among all file records (header included).
                let first_kept_index = compaction
                    .value
                    .get("firstKeptEntryIndex")
                    .and_then(Value::as_u64)
                    .and_then(|i| usize::try_from(i).ok());
                in_active_context[path[pos]] = true;
                let mut found = false;
                for &idx in &path[..pos] {
                    let entry = &entries[idx];
                    if (first_kept_id.is_some() && entry.id == first_kept_id)
                        || (first_kept_id.is_none() && Some(entry.file_index) == first_kept_index)
                    {
                        found = true;
                    }
                    if found && !entry.is_system_message() {
                        in_active_context[idx] = true;
                    }
                }
                for &idx in &path[pos + 1..] {
                    in_active_context[idx] = true;
                }
            }
        }
        let context_compaction = context_compaction.map(|pos| path[pos]);

        // Context edits among the context entries; the latest edit per
        // target wins. Edits change model context only, never raw history.
        let mut latest_edit: HashMap<usize, bool> = HashMap::new();
        for &idx in &path {
            let entry = &entries[idx];
            if !in_active_context[idx] || entry.entry_type() != "context_edit" {
                continue;
            }
            let Some(target) = entry
                .value
                .get("targetId")
                .and_then(Value::as_str)
                .and_then(|t| by_id.get(t).copied())
            else {
                continue;
            };
            let omitted = entry.value.get("replacement").is_none_or(Value::is_null);
            latest_edit.insert(target, omitted);
        }
        let mut context_edits = HashMap::new();
        for (target, omitted) in latest_edit {
            if !in_active_context[target] {
                continue;
            }
            if omitted {
                in_active_context[target] = false;
                context_edits.insert(target, "omitted");
            } else {
                context_edits.insert(target, "replaced");
            }
        }

        let model_state = resolve_model_states(entries, header_provider, header_model);

        Self {
            on_active_branch,
            in_active_context,
            context_compaction,
            context_edits,
            model_state,
            branch_leaf_count,
            active_branch_len: path.len(),
            integrity,
        }
    }
}

/// Whether following `parent` links from any entry loops.
fn has_parent_cycle(entries: &[WireEntry]) -> bool {
    // 0 = unvisited, 1 = on the current walk, 2 = known to reach a root.
    let mut state = vec![0_u8; entries.len()];
    for start in 0..entries.len() {
        let mut walk = Vec::new();
        let mut cursor = Some(start);
        while let Some(idx) = cursor {
            match state[idx] {
                1 => return true,
                2 => break,
                _ => {}
            }
            state[idx] = 1;
            walk.push(idx);
            cursor = entries[idx].parent;
        }
        for idx in walk {
            state[idx] = 2;
        }
    }
    false
}

/// Effective `(provider, model)` selection after each entry.
///
/// Each entry inherits the selection of its PARENT, never of whatever entry
/// happens to precede it in the file: a sibling branch's `model_change` must
/// not leak into another branch's attribution. `model_change` updates each
/// field it carries (pi-mono writes `provider` + `modelId`; omp writes a bare
/// `model`) and leaves the other one inherited.
fn resolve_model_states(
    entries: &[WireEntry],
    header_provider: Option<&String>,
    header_model: Option<&String>,
) -> Vec<(Option<String>, Option<String>)> {
    let root_state = (header_provider.cloned(), header_model.cloned());
    let mut states: Vec<Option<(Option<String>, Option<String>)>> = vec![None; entries.len()];
    for start in 0..entries.len() {
        if states[start].is_some() {
            continue;
        }
        // Collect the unresolved ancestor chain, stopping at a resolved
        // ancestor, a root, or a cycle.
        let mut chain = Vec::new();
        let mut on_chain = HashSet::new();
        let mut cursor = Some(start);
        let mut base = root_state.clone();
        while let Some(idx) = cursor {
            if let Some(state) = &states[idx] {
                base = state.clone();
                break;
            }
            if !on_chain.insert(idx) {
                break;
            }
            chain.push(idx);
            cursor = entries[idx].parent;
        }
        for &idx in chain.iter().rev() {
            let value = &entries[idx].value;
            if entries[idx].entry_type() == "model_change" {
                if let Some(provider) = value.get("provider").and_then(Value::as_str) {
                    base.0 = Some(provider.to_string());
                }
                if let Some(model) = value
                    .get("modelId")
                    .and_then(Value::as_str)
                    .or_else(|| value.get("model").and_then(Value::as_str))
                {
                    base.1 = Some(model.to_string());
                }
            }
            states[idx] = Some(base.clone());
        }
    }
    states
        .into_iter()
        .map(|state| state.unwrap_or_else(|| root_state.clone()))
        .collect()
}

/// Extract structured tool invocations from an assistant content array.
fn tool_invocations(content: Option<&Value>) -> Vec<crate::types::NormalizedInvocation> {
    content
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter(|item| item.get("type").and_then(Value::as_str) == Some("toolCall"))
                .map(|item| crate::types::NormalizedInvocation {
                    kind: "tool".to_string(),
                    name: item
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string(),
                    raw_name: None,
                    call_id: item.get("id").and_then(Value::as_str).map(String::from),
                    arguments: item.get("arguments").cloned(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// What one tree entry contributes as a normalized message, before
/// provenance is attached.
struct EmittedEntry {
    role: String,
    /// The pi role (or entry kind) it was derived from.
    source_role: String,
    content: String,
    author: Option<String>,
    invocations: Vec<crate::types::NormalizedInvocation>,
    created_at: Option<i64>,
    /// Raw entry to keep as `extra` (prompt/tool checkpoints stripped).
    raw: Value,
    /// Kind-specific provenance merged into `extra.cass`.
    provenance: serde_json::Map<String, Value>,
}

/// Map one tree entry to its normalized message, if it carries searchable
/// text. `model_state` is the entry's branch-local `(provider, model)`.
#[allow(clippy::too_many_lines)]
fn emit_entry(
    entry: &WireEntry,
    model_state: &(Option<String>, Option<String>),
) -> Option<EmittedEntry> {
    let value = &entry.value;
    let entry_ts = value.get("timestamp").and_then(super::parse_timestamp);
    let mut provenance = serde_json::Map::new();
    match entry.entry_type() {
        "message" => {
            let msg = value.get("message")?;
            let raw_role = msg.get("role").and_then(Value::as_str).unwrap_or("unknown");
            if raw_role == "system" {
                // Prompt sections and tool declarations, not conversation.
                return None;
            }
            let created_at =
                entry_ts.or_else(|| msg.get("timestamp").and_then(super::parse_timestamp));
            let role = normalized_role(raw_role).unwrap_or(raw_role).to_string();
            let content = match raw_role {
                "bashExecution" => {
                    let command = msg.get("command").and_then(Value::as_str).unwrap_or("");
                    let output = msg.get("output").and_then(Value::as_str).unwrap_or("");
                    for key in ["exitCode", "cancelled", "truncated", "excludeFromContext"] {
                        if let Some(v) = msg.get(key) {
                            provenance.insert(key.to_string(), v.clone());
                        }
                    }
                    if command.trim().is_empty() && output.trim().is_empty() {
                        String::new()
                    } else {
                        format!("$ {command}\n{output}")
                    }
                }
                "branchSummary" | "compactionSummary" => {
                    let summary = msg.get("summary").and_then(Value::as_str).unwrap_or("");
                    let label = if raw_role == "branchSummary" {
                        "branch summary"
                    } else {
                        "compaction"
                    };
                    if summary.trim().is_empty() {
                        String::new()
                    } else {
                        format!("[{label}] {summary}")
                    }
                }
                "custom" | "hookMessage" => {
                    for (key, out) in [("customType", "custom_type"), ("display", "display")] {
                        if let Some(v) = msg.get(key) {
                            provenance.insert(out.to_string(), v.clone());
                        }
                    }
                    msg.get("content")
                        .map(flatten_message_content)
                        .unwrap_or_default()
                }
                _ => msg
                    .get("content")
                    .map(flatten_message_content)
                    .unwrap_or_default(),
            };
            if content.trim().is_empty() {
                return None;
            }
            // Assistant attribution: the message's own model first, then the
            // selection inherited along this entry's own branch.
            let author = (role == "assistant").then(|| {
                msg.get("model")
                    .and_then(Value::as_str)
                    .map(String::from)
                    .or_else(|| model_state.1.clone())
            });
            let invocations = if role == "assistant" {
                tool_invocations(msg.get("content"))
            } else {
                Vec::new()
            };
            Some(EmittedEntry {
                role,
                source_role: raw_role.to_string(),
                content,
                author: author.flatten(),
                invocations,
                created_at,
                raw: value.clone(),
                provenance,
            })
        }
        "custom_message" => {
            let content = value
                .get("content")
                .map(flatten_message_content)
                .unwrap_or_default();
            if content.trim().is_empty() {
                return None;
            }
            for (key, out) in [("customType", "custom_type"), ("display", "display")] {
                if let Some(v) = value.get(key) {
                    provenance.insert(out.to_string(), v.clone());
                }
            }
            Some(EmittedEntry {
                role: "user".to_string(),
                source_role: "custom".to_string(),
                content,
                author: None,
                invocations: Vec::new(),
                created_at: entry_ts,
                raw: value.clone(),
                provenance,
            })
        }
        "compaction" => {
            let summary = value.get("summary").and_then(Value::as_str).unwrap_or("");
            if summary.trim().is_empty() {
                return None;
            }
            for (key, out) in [
                ("firstKeptEntryId", "first_kept_entry_id"),
                ("tokensBefore", "tokens_before"),
                ("fromHook", "from_hook"),
            ] {
                if let Some(v) = value.get(key) {
                    provenance.insert(out.to_string(), v.clone());
                }
            }
            // The checkpoint replays the full system prompt and tool
            // declarations at the compaction boundary: context-boundary
            // metadata, never conversation text. Keep only the fact that it
            // exists so the raw extra cannot smuggle it into an index.
            let mut raw = value.clone();
            if let Some(obj) = raw.as_object_mut() {
                if obj.remove("systemMessage").is_some() {
                    provenance.insert("system_checkpoint".to_string(), Value::Bool(true));
                }
            }
            Some(EmittedEntry {
                role: "system".to_string(),
                source_role: "compaction".to_string(),
                content: format!("[compaction] {summary}"),
                author: None,
                invocations: Vec::new(),
                created_at: entry_ts,
                raw,
                provenance,
            })
        }
        "branch_summary" => {
            let summary = value.get("summary").and_then(Value::as_str).unwrap_or("");
            if summary.trim().is_empty() {
                return None;
            }
            for (key, out) in [("fromId", "from_id"), ("fromHook", "from_hook")] {
                if let Some(v) = value.get(key) {
                    provenance.insert(out.to_string(), v.clone());
                }
            }
            Some(EmittedEntry {
                role: "system".to_string(),
                source_role: "branch_summary".to_string(),
                content: format!("[branch summary] {summary}"),
                author: None,
                invocations: Vec::new(),
                created_at: entry_ts,
                raw: value.clone(),
                provenance,
            })
        }
        _ => None,
    }
}

/// Parse one pi-family session JSONL file into a normalized conversation.
///
/// Returns `None` for unreadable files (logged at debug with `agent_slug`
/// context) and for files that yield zero usable messages — mirroring the
/// skip semantics of the original per-connector scan loops.
///
/// `sessions_dir` is used to derive the conversation's external id as a path
/// relative to the sessions directory (falling back to the file stem).
///
/// # Archive semantics
///
/// Every branch stored in the file is emitted, in file order, so abandoned
/// branches stay searchable. Each message's `extra.cass` records where it
/// came from and how it relates to the live conversation:
///
/// - `entry_kind` (`message`, `compaction`, `branch_summary`,
///   `custom_message`) and `source_role` (the pi role, e.g. `bashExecution`,
///   `custom`, `toolResult`), so summaries and injected context are never
///   mistaken for original turns;
/// - `entry_id` / `parent_id` / `source_line`: the tree link and a source
///   locator;
/// - `on_active_branch`: on the path from pi's current leaf to its root;
/// - `in_active_context`: part of the model context pi would rebuild (latest
///   compaction and `context_edit`s applied); `context_edit` says whether an
///   edit `omitted` or `replaced` the message for the model;
/// - `model` / `provider`: the selection inherited along the entry's own
///   branch.
///
/// System messages (prompt sections and tool declarations) and compaction
/// system checkpoints are never indexed as conversation text.
#[allow(clippy::too_many_lines)]
pub fn parse_session_file(
    path: &Path,
    sessions_dir: &Path,
    agent_slug: &str,
) -> Option<NormalizedConversation> {
    let source_path = path.to_path_buf();

    // Use the parent directory name + filename as external_id
    // e.g., "--Users-foo-project--/2024-01-15T10-30-00_uuid.jsonl"
    let external_id = source_path
        .strip_prefix(sessions_dir)
        .ok()
        .and_then(|rel| rel.to_str().map(String::from))
        .or_else(|| {
            source_path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(String::from)
        });

    // Session transcripts are append-only logs that grow without bound;
    // enforce the project's 100MB scan cap (chatgpt policy) instead of
    // reading an arbitrarily large file into memory.
    let content = match read_capped(&source_path) {
        Ok(Some(content)) => content,
        Ok(None) => {
            tracing::debug!(
                path = %source_path.display(),
                "{agent_slug}: skipping session over the scan size cap"
            );
            return None;
        }
        Err(e) => {
            tracing::debug!(path = %source_path.display(), error = %e, "{agent_slug}: skipping unreadable session");
            return None;
        }
    };

    let mut entries: Vec<WireEntry> = Vec::new();
    let mut file_index = 0_usize;
    let mut session_id: Option<String> = None;
    let mut session_cwd: Option<PathBuf> = None;
    let mut session_version: Option<Value> = None;
    let mut parent_session: Option<String> = None;
    let mut header_ts: Option<i64> = None;
    let mut provider: Option<String> = None;
    let mut model_id: Option<String> = None;
    let mut header_title: Option<String> = None;
    let mut title_entry: Option<String> = None;
    let mut session_name: Option<String> = None;
    let mut labels: HashMap<String, String> = HashMap::new();

    for (line_idx, line) in content.lines().enumerate() {
        let line = line.trim_start_matches('\u{feff}');
        if line.trim().is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let this_index = file_index;
        file_index += 1;

        match val.get("type").and_then(Value::as_str).unwrap_or("") {
            "session" => {
                // Session header: metadata only, not part of the tree.
                session_id = val.get("id").and_then(Value::as_str).map(String::from);
                session_cwd = val.get("cwd").and_then(Value::as_str).map(PathBuf::from);
                provider = val
                    .get("provider")
                    .and_then(Value::as_str)
                    .map(String::from);
                model_id = val.get("modelId").and_then(Value::as_str).map(String::from);
                header_title = val
                    .get("title")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .filter(|t| !t.is_empty());
                session_version = val.get("version").cloned();
                // Fork/clone ancestry. Keep the parent's file name (pi file
                // names embed the session UUID) rather than its absolute path.
                parent_session = val
                    .get("parentSession")
                    .and_then(Value::as_str)
                    .filter(|p| !p.is_empty())
                    .map(|parent| {
                        Path::new(parent)
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or(parent)
                            .to_string()
                    });
                if let Some(ts_val) = val.get("timestamp") {
                    header_ts = super::parse_timestamp(ts_val);
                }
                continue;
            }
            "title" => {
                // omp writes standalone title lines; prefer the most recent
                // non-empty one over the session-header title.
                if let Some(title) = val
                    .get("title")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .filter(|t| !t.is_empty())
                {
                    title_entry = Some(title);
                }
            }
            "session_info" => {
                // User-defined display name (`/name`, `--name`); the latest
                // entry wins, as in pi's session selector.
                session_name = val
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                    .map(str::to_string);
            }
            "label" => {
                if let Some(target) = val.get("targetId").and_then(Value::as_str) {
                    match val
                        .get("label")
                        .and_then(Value::as_str)
                        .filter(|l| !l.is_empty())
                    {
                        Some(label) => {
                            labels.insert(target.to_string(), label.to_string());
                        }
                        None => {
                            labels.remove(target);
                        }
                    }
                }
            }
            _ => {}
        }

        entries.push(WireEntry {
            id: val.get("id").and_then(Value::as_str).map(String::from),
            value: val,
            line: line_idx + 1,
            file_index: this_index,
            parent: None,
        });
    }

    let tree = WireTree::build(&mut entries, provider.as_ref(), model_id.as_ref());

    let mut messages = Vec::new();
    let mut started_at = header_ts;
    let mut ended_at: Option<i64> = None;
    let mut system_message_count = 0_usize;
    let mut compaction_count = 0_usize;
    let mut off_branch_message_count = 0_usize;

    for (idx, entry) in entries.iter().enumerate() {
        match entry.entry_type() {
            "compaction" => compaction_count += 1,
            "message" if entry.is_system_message() => system_message_count += 1,
            _ => {}
        }
        let Some(emitted) = emit_entry(entry, &tree.model_state[idx]) else {
            continue;
        };

        if let Some(ts) = emitted.created_at {
            started_at = Some(started_at.map_or(ts, |curr| curr.min(ts)));
            ended_at = Some(ended_at.map_or(ts, |curr| curr.max(ts)));
        }

        let on_active_branch = tree.on_active_branch[idx];
        if !on_active_branch {
            off_branch_message_count += 1;
        }
        // An older compaction retained inside the newest kept range is raw
        // history only; just the newest one contributes its summary.
        let in_active_context = tree.in_active_context[idx]
            && (entry.entry_type() != "compaction" || tree.context_compaction == Some(idx));

        let mut cass = serde_json::Map::new();
        cass.insert("entry_kind".into(), Value::from(entry.entry_type()));
        cass.insert("source_role".into(), Value::from(emitted.source_role));
        if let Some(id) = &entry.id {
            cass.insert("entry_id".into(), Value::from(id.as_str()));
        }
        if let Some(parent_id) = entry.value.get("parentId").and_then(Value::as_str) {
            cass.insert("parent_id".into(), Value::from(parent_id));
        }
        cass.insert("source_line".into(), Value::from(entry.line));
        cass.insert("on_active_branch".into(), Value::Bool(on_active_branch));
        cass.insert("in_active_context".into(), Value::Bool(in_active_context));
        if let Some(edit) = tree.context_edits.get(&idx) {
            cass.insert("context_edit".into(), Value::from(*edit));
        }
        if let Some(label) = entry.id.as_ref().and_then(|id| labels.get(id)) {
            cass.insert("label".into(), Value::from(label.as_str()));
        }
        if emitted.role == "assistant" {
            if let Some(model) = &emitted.author {
                cass.insert("model".into(), Value::from(model.as_str()));
            }
            let provider = entry
                .value
                .pointer("/message/provider")
                .and_then(Value::as_str)
                .map(String::from)
                .or_else(|| tree.model_state[idx].0.clone());
            if let Some(provider) = provider {
                cass.insert("provider".into(), Value::from(provider));
            }
        }
        cass.extend(emitted.provenance);

        let mut extra = emitted.raw;
        if let Some(obj) = extra.as_object_mut() {
            obj.insert("cass".to_string(), Value::Object(cass));
        }

        messages.push(NormalizedMessage {
            idx: i64::try_from(messages.len()).unwrap_or(i64::MAX),
            role: emitted.role,
            author: emitted.author,
            created_at: emitted.created_at,
            content: emitted.content,
            extra,
            invocations: emitted.invocations,
            snippets: Vec::new(),
        });
    }

    if messages.is_empty() {
        return None;
    }

    // Title precedence: the user-defined session name, then an explicit omp
    // `title` entry, then the session-header title, then the first ORIGINAL
    // user message (never injected context or a shell command), then any
    // message at all.
    let is_original_user = |m: &&NormalizedMessage| {
        m.role == "user"
            && m.extra.pointer("/cass/source_role").and_then(Value::as_str) == Some("user")
    };
    let title = session_name
        .or(title_entry)
        .or(header_title)
        .or_else(|| {
            messages
                .iter()
                .find(is_original_user)
                .or_else(|| messages.iter().find(|m| m.role == "user"))
                .map(|m| first_line_truncated(&m.content))
        })
        .or_else(|| messages.first().map(|m| first_line_truncated(&m.content)));

    // The conversation-level selection is the ACTIVE branch's, i.e. the
    // state at pi's current leaf.
    let (active_provider, active_model) = tree
        .model_state
        .last()
        .cloned()
        .unwrap_or((provider, model_id));

    let mut metadata = serde_json::json!({
        "source": agent_slug,
        "session_id": session_id,
        "provider": active_provider,
        "model_id": active_model,
        "tree": {
            "integrity": tree.integrity.as_str(),
            "total_entry_count": entries.len(),
            "active_branch_entry_count": tree.active_branch_len,
            "branch_leaf_count": tree.branch_leaf_count,
            "off_branch_message_count": off_branch_message_count,
            "active_leaf_id": entries.last().and_then(|e| e.id.clone()),
            "active_context": "compaction_and_context_edit_aware",
        },
    });
    if let Some(meta) = metadata.as_object_mut() {
        if let Some(version) = session_version {
            meta.insert("session_version".into(), version);
        }
        if let Some(parent) = parent_session {
            meta.insert("parent_session".into(), Value::from(parent));
        }
        if compaction_count > 0 {
            meta.insert("compaction_count".into(), Value::from(compaction_count));
        }
        if system_message_count > 0 {
            meta.insert(
                "system_message_count".into(),
                Value::from(system_message_count),
            );
        }
    }

    Some(NormalizedConversation {
        agent_slug: agent_slug.to_string(),
        external_id,
        title,
        workspace: session_cwd,
        source_path,
        started_at,
        ended_at,
        metadata,
        messages,
    })
}

fn first_line_truncated(content: &str) -> String {
    content
        .lines()
        .next()
        .unwrap_or(content)
        .chars()
        .take(100)
        .collect()
}

/// Discover deduplicated session files across `roots`, filtered by
/// `since_ts`, wrapped as primary session-log sources attributed to
/// `agent_slug`.
///
/// Takes full [`super::ScanRoot`]s rather than bare paths so each discovered
/// source keeps its scan-root provenance (`origin`, `platform`) — remote
/// roots must not be downgraded to local during discovery.
#[must_use]
pub fn discover_sources(
    roots: &[super::ScanRoot],
    ctx: &super::ScanContext,
    agent_slug: &'static str,
) -> Vec<super::DiscoveredSourceFile> {
    use super::{DiscoveredSourceFile, DiscoveredSourceRole};
    use crate::connectors::file_modified_since;

    let excluded_paths = excluded_scan_paths_from_env();
    let mut out = Vec::new();
    let mut seen_session_paths: HashSet<PathBuf> = HashSet::new();
    for root in roots {
        for file in session_files(&root.path) {
            // Match before deduplication and per-source metadata or pre-mirroring.
            if path_is_excluded(&file, &excluded_paths) {
                continue;
            }
            if !seen_session_paths.insert(dedupe_path_key(&file)) {
                continue;
            }
            if !file_modified_since(&file, ctx.since_ts) {
                continue;
            }
            out.push(
                DiscoveredSourceFile::new(
                    agent_slug,
                    root,
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

/// Scan every deduplicated, time-filtered session file across `homes` into
/// normalized conversations attributed to `agent_slug`.
///
/// Files that fail to parse or yield no messages are skipped silently
/// (debug-logged), matching the established connector behavior.
pub fn scan_homes(
    homes: &[PathBuf],
    ctx: &super::ScanContext,
    agent_slug: &'static str,
) -> Result<Vec<NormalizedConversation>> {
    let tagged: Vec<(PathBuf, Option<String>)> =
        homes.iter().map(|home| (home.clone(), None)).collect();
    scan_homes_tagged(&tagged, ctx, agent_slug)
}

/// Like [`scan_homes`], but each home carries optional profile provenance.
///
/// Provenance covers Oh My Pi named profiles: when a home is tagged, every
/// conversation parsed from it gets `metadata.profile = "<name>"` so
/// downstream consumers can reconstruct `omp --profile <name> --resume <id>`
/// instead of losing the profile after normalization
/// (`franken_agent_detection#17`).
///
/// Dedup is first-wins across the whole list: a session file reachable
/// through two homes (symlinks, overlapping roots) keeps the provenance of
/// the first home that reached it, so callers should order roots
/// most-specific first.
pub fn scan_homes_tagged(
    homes: &[(PathBuf, Option<String>)],
    ctx: &super::ScanContext,
    agent_slug: &'static str,
) -> Result<Vec<NormalizedConversation>> {
    use crate::connectors::file_modified_since;

    let excluded_paths = excluded_scan_paths_from_env();
    let mut convs = Vec::new();
    // Symlink-aliased homes (e.g. `~/.omp/agent` -> `~/Library/...`) reach
    // the same session files twice. Canonicalizing every FILE would be far
    // too expensive for hot scans, so resolve each home ONCE and skip a
    // home whose canonical path was already processed; emitted paths keep
    // the raw (first-seen) form.
    let mut seen_homes: HashSet<PathBuf> = HashSet::new();
    let mut seen_session_paths: HashSet<PathBuf> = HashSet::new();

    for (home, profile) in homes {
        let canonical_home = dedupe_home(home);
        if !seen_homes.insert(dedupe_path_key(&canonical_home)) {
            continue;
        }

        let files = session_files(home);
        if files.is_empty() {
            continue;
        }
        let sessions = sessions_dir(home);

        for file in files {
            // Use the same policy as discovery before the source is opened.
            if path_is_excluded(&file, &excluded_paths) {
                continue;
            }
            // Guard against equivalent-but-differently-spelled file paths.
            let dedupe_key = dedupe_path_key(&file);
            if !seen_session_paths.insert(dedupe_key) {
                continue;
            }
            // Skip files not modified since last scan
            if !file_modified_since(&file, ctx.since_ts) {
                continue;
            }

            if let Some(mut conversation) = parse_session_file(&file, &sessions, agent_slug) {
                if let Some(profile) = profile {
                    if let Some(meta) = conversation.metadata.as_object_mut() {
                        meta.insert(
                            "profile".to_string(),
                            serde_json::Value::String(profile.clone()),
                        );
                    }
                }
                convs.push(conversation);
            }
        }
    }

    Ok(convs)
}
