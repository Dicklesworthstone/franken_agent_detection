//! Connector for Prime Agent (<https://github.com/PrimeIntellect-ai/prime-agent>).
//!
//! Prime Agent stores sessions as flat JSONL files under
//! `~/.prime/agent/sessions/<session-id>.jsonl`. Each file starts with a
//! `type: "session"` header (metadata only) followed by tree-linked entries
//! (`id`/`parentId`) that enable in-place branching without new files:
//!
//! - version 1: linear entry sequence (no tree ids; file order is the branch);
//! - version 2: tree structure via `id`/`parentId`;
//! - version 3: renamed the `hookMessage` role to `custom`.
//!
//! Prime shares low-level JSONL habits with the pi-mono family but is NOT a
//! Pi alias: it probes different roots (`~/.prime/agent/sessions`), does not
//! use timestamp-plus-UUID basenames, and has its own entry vocabulary
//! (compaction, branch summaries, bash executions, custom extension
//! messages, RLM child-usage attribution). This connector therefore keeps a
//! separate slug, roots, tree semantics, record policy, and metadata.
//!
//! MVP scope (gh#388 in `coding_agent_session_search`): the ACTIVE branch
//! (leaf-to-root walk) becomes the canonical conversation; abandoned sibling
//! branches are not indexed as separate conversations, but
//! `total_entry_count` / `active_branch_entry_count` /
//! `omitted_branch_entry_count` make the omission explicit.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{Value, json};
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::dedupe_path_key;
use super::{Connector, franken_detection_for_connector, parse_timestamp};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
    reindex_messages,
};

/// Highest session-format version this connector understands.
const SUPPORTED_MAX_VERSION: i64 = 3;

/// Byte ceiling for any single bounded metadata/argument payload copied into
/// normalized storage. High-volume or unbounded provider fields must never be
/// duplicated into SQLite; CASS's raw mirror retains the source file.
const BOUNDED_FIELD_MAX_BYTES: usize = 2048;

/// `custom_message` extension types Prime itself excludes from useful
/// conversation context (session command plumbing and compaction outcomes).
const EXCLUDED_CUSTOM_MESSAGE_TYPES: &[&str] = &[
    "session-command",
    "session-command-result",
    "session_command",
    "session_command_result",
    "compaction-outcome",
    "compaction_outcome",
];

pub struct PrimeAgentConnector;

impl Default for PrimeAgentConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl PrimeAgentConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Candidate session directories in priority order, resolved from the
    /// live environment.
    fn default_session_dirs() -> Vec<PathBuf> {
        Self::session_dirs_from_overrides(
            dotenvy::var("PRIME_AGENT_SESSION_DIR").ok().as_deref(),
            dotenvy::var("PRIME_AGENT_CODING_AGENT_SESSION_DIR")
                .ok()
                .as_deref(),
            dotenvy::var("PRIME_AGENT_CODING_AGENT_DIR").ok().as_deref(),
            dirs::home_dir().as_deref(),
        )
    }

    /// Pure candidate derivation shared by [`Self::default_session_dirs`],
    /// split out so the env-driven precedence can be unit-tested without
    /// mutating process environment (`std::env::set_var` is `unsafe` and
    /// forbidden at the crate level).
    ///
    /// Precedence mirrors Prime's own config resolution:
    /// - `PRIME_AGENT_SESSION_DIR` names the sessions directory directly and
    ///   wins outright;
    /// - legacy `PRIME_AGENT_CODING_AGENT_SESSION_DIR` is honored next, the
    ///   same way;
    /// - `PRIME_AGENT_CODING_AGENT_DIR` pins the agent home (sessions live
    ///   under `<dir>/sessions`) and suppresses the built-in default;
    /// - otherwise `~/.prime/agent/sessions`.
    ///
    /// Empty values (`FOO=""`) are treated as unset so scans never fall
    /// through to the process working directory.
    fn session_dirs_from_overrides(
        session_dir: Option<&str>,
        legacy_session_dir: Option<&str>,
        agent_dir: Option<&str>,
        home: Option<&Path>,
    ) -> Vec<PathBuf> {
        if let Some(dir) = session_dir.filter(|s| !s.trim().is_empty()) {
            return vec![PathBuf::from(dir.trim())];
        }
        if let Some(dir) = legacy_session_dir.filter(|s| !s.trim().is_empty()) {
            return vec![PathBuf::from(dir.trim())];
        }
        if let Some(dir) = agent_dir.filter(|s| !s.trim().is_empty()) {
            return vec![PathBuf::from(dir.trim()).join("sessions")];
        }
        home.map(|home| home.join(".prime").join("agent").join("sessions"))
            .into_iter()
            .collect()
    }

    /// Structural check for a Prime session store handed over as an explicit
    /// path: `<...>/.prime/agent/sessions`, its `.prime/agent` parent form, or
    /// a `.prime` root that contains the store.
    fn looks_like_prime_storage(path: &Path) -> bool {
        let is_sessions = path.file_name().is_some_and(|n| n == "sessions")
            && path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == "agent"))
            && path
                .parent()
                .and_then(Path::parent)
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".prime"));
        let is_agent = path.file_name().is_some_and(|n| n == "agent")
            && path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".prime"))
            && path.join("sessions").is_dir();
        let is_prime = path.file_name().is_some_and(|n| n == ".prime")
            && path.join("agent").join("sessions").is_dir();
        is_sessions || is_agent || is_prime
    }

    /// Expand one explicit base path into every Prime store form it contains.
    fn append_explicit_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        if Self::looks_like_prime_storage(base) {
            if base.file_name().is_some_and(|n| n == "sessions") {
                roots.push(base.to_path_buf());
            } else if base.file_name().is_some_and(|n| n == "agent") {
                roots.push(base.join("sessions"));
            } else {
                roots.push(base.join("agent").join("sessions"));
            }
        }
        let nested = base.join(".prime").join("agent").join("sessions");
        if nested.is_dir() {
            roots.push(nested);
        }
    }

    /// All candidate `.jsonl` session files under a sessions directory, in
    /// deterministic (sorted) order. Current releases keep a flat directory;
    /// older per-project subdirectories (auto-migrated by Prime) are still
    /// walked so an unmigrated store is not silently empty.
    pub(crate) fn session_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if !root.exists() {
            return out;
        }
        for entry in WalkDir::new(root).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let is_jsonl = entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"));
            if is_jsonl {
                out.push(entry.path().to_path_buf());
            }
        }
        out.sort();
        out
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots: Vec<ScanRoot> = Vec::new();
        if ctx.use_default_detection() {
            if Self::looks_like_prime_storage(&ctx.data_dir) && ctx.data_dir.exists() {
                let mut expanded = Vec::new();
                Self::append_explicit_roots(&mut expanded, &ctx.data_dir);
                roots.extend(expanded.into_iter().map(ScanRoot::local));
            } else {
                roots.extend(
                    Self::default_session_dirs()
                        .into_iter()
                        .filter(|dir| dir.exists())
                        .map(ScanRoot::local),
                );
            }
        } else {
            for scan_root in &ctx.scan_roots {
                let mut expanded = Vec::new();
                Self::append_explicit_roots(&mut expanded, &scan_root.path);
                roots.extend(expanded.into_iter().map(|path| scan_root.with_path(path)));
            }
        }
        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        let mut seen_files: HashSet<PathBuf> = HashSet::new();
        for root in Self::source_roots(ctx) {
            for file in Self::session_files(&root.path) {
                if !seen_files.insert(dedupe_path_key(&file)) {
                    continue;
                }
                if !super::file_modified_since(&file, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "prime_agent",
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
}

/// One parsed non-header entry retained for tree projection.
struct PrimeEntry {
    /// 8-char hex tree id; `None` for v1 entries without tree linking.
    id: Option<String>,
    parent_id: Option<String>,
    value: Value,
}

/// Serialize a JSON value with a hard byte bound; oversized payloads are
/// replaced by a placeholder so unbounded provider fields never reach
/// normalized storage.
fn bounded_json(value: &Value) -> Value {
    let serialized = value.to_string();
    if serialized.len() <= BOUNDED_FIELD_MAX_BYTES {
        value.clone()
    } else {
        json!(format!(
            "[omitted: {} bytes exceeds {}-byte bound]",
            serialized.len(),
            BOUNDED_FIELD_MAX_BYTES
        ))
    }
}

/// Strip `user:password@` credential userinfo from URL-shaped strings.
fn strip_url_credentials(raw: &str) -> String {
    match raw.split_once("://") {
        Some((scheme, rest)) if rest.contains('@') => {
            let host = rest.split_once('@').map_or(rest, |(_, host)| host);
            format!("{scheme}://{host}")
        }
        _ => raw.to_string(),
    }
}

/// Recursively sanitize a metadata value: strip URL credentials from strings
/// and bound the total size.
fn sanitize_metadata_value(value: &Value) -> Value {
    fn sanitize(value: &Value) -> Value {
        match value {
            Value::String(s) => Value::String(strip_url_credentials(s)),
            Value::Array(items) => Value::Array(items.iter().map(sanitize).collect()),
            Value::Object(map) => {
                Value::Object(map.iter().map(|(k, v)| (k.clone(), sanitize(v))).collect())
            }
            other => other.clone(),
        }
    }
    bounded_json(&sanitize(value))
}

/// Flatten Prime content (`string | (text|image|thinking|toolCall)[]`) into
/// searchable text. Image payloads become a bounded MIME placeholder; base64
/// data never reaches normalized content.
fn flatten_prime_content(content: &Value) -> String {
    if let Some(text) = content.as_str() {
        return text.to_string();
    }
    let Some(blocks) = content.as_array() else {
        return String::new();
    };
    let mut parts: Vec<String> = Vec::new();
    for block in blocks {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(text) = block.get("text").and_then(Value::as_str) {
                    if !text.trim().is_empty() {
                        parts.push(text.to_string());
                    }
                }
            }
            Some("thinking") => {
                if let Some(text) = block.get("thinking").and_then(Value::as_str) {
                    if !text.trim().is_empty() {
                        parts.push(text.to_string());
                    }
                }
            }
            Some("image") => {
                let mime = block
                    .get("mimeType")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                parts.push(format!("[image: {mime}]"));
            }
            // toolCall blocks are surfaced as structured invocations, not
            // flattened prose.
            _ => {}
        }
    }
    parts.join("\n")
}

/// Extract Prime `toolCall` content blocks as structured invocations with
/// bounded arguments.
fn prime_invocations(content: &Value) -> Vec<NormalizedInvocation> {
    let Some(blocks) = content.as_array() else {
        return Vec::new();
    };
    let mut invocations = Vec::new();
    for block in blocks {
        if block.get("type").and_then(Value::as_str) != Some("toolCall") {
            continue;
        }
        let Some(name) = block.get("name").and_then(Value::as_str) else {
            continue;
        };
        invocations.push(NormalizedInvocation {
            kind: "tool".to_string(),
            name: name.to_string(),
            raw_name: None,
            call_id: block
                .get("id")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            arguments: block.get("arguments").map(bounded_json),
        });
    }
    invocations
}

/// The active branch as file-order indices, walked leaf-to-root and reversed.
///
/// Returns `None` when the tree is broken (missing parent or cycle); the
/// caller falls back to file order and records the integrity downgrade —
/// a broken tree must not silently emit an apparently complete orphan suffix.
fn active_branch_indices(entries: &[PrimeEntry]) -> Option<Vec<usize>> {
    let mut by_id: HashMap<&str, usize> = HashMap::new();
    for (idx, entry) in entries.iter().enumerate() {
        if let Some(id) = entry.id.as_deref() {
            // Last write wins: Prime ids are unique, but a duplicated id in a
            // hand-edited file should not panic the walk.
            by_id.insert(id, idx);
        }
    }
    if by_id.is_empty() {
        // Version 1: linear sequence without tree ids.
        return Some((0..entries.len()).collect());
    }

    let leaf_idx = entries.iter().rposition(|entry| entry.id.is_some())?;
    let mut branch = Vec::new();
    let mut visited: HashSet<usize> = HashSet::new();
    let mut cursor = Some(leaf_idx);
    while let Some(idx) = cursor {
        if !visited.insert(idx) {
            tracing::warn!(
                connector = "prime_agent",
                entry_index = idx,
                reason = "cycle in id/parentId chain",
                "prime_agent: session tree is cyclic; falling back to file order"
            );
            return None;
        }
        branch.push(idx);
        let parent = entries[idx].parent_id.as_deref();
        cursor = match parent {
            None => None,
            Some(parent_id) => {
                if let Some(&parent_idx) = by_id.get(parent_id) {
                    Some(parent_idx)
                } else {
                    tracing::warn!(
                        connector = "prime_agent",
                        parent_id,
                        reason = "parentId not present in file",
                        "prime_agent: session tree has a missing parent; falling back to file order"
                    );
                    return None;
                }
            }
        };
    }
    branch.reverse();
    Some(branch)
}

/// Parse one Prime session file into a normalized conversation.
///
/// Returns `Ok(None)` for files this connector must skip: a non-Prime first
/// record, an unsupported future version (structured diagnostic), or a
/// header-only shell with no searchable content.
#[allow(clippy::too_many_lines)]
fn parse_session_file(path: &Path) -> Result<Option<NormalizedConversation>> {
    let file = fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);

    let mut header: Option<Value> = None;
    let mut entries: Vec<PrimeEntry> = Vec::new();
    let mut malformed_interior = 0_usize;
    let mut pending_malformed: Option<usize> = None;
    let mut line_number = 0_usize;

    for line_result in reader.lines() {
        let Ok(line) = line_result else {
            break;
        };
        line_number += 1;
        let trimmed = line.trim_start_matches('\u{feff}').trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
            // Only a malformed FINAL line is forgiven (live write in
            // progress). Interior damage is counted after we know another
            // valid line followed it.
            if let Some(previous) = pending_malformed.take() {
                malformed_interior += 1;
                tracing::warn!(
                    connector = "prime_agent",
                    path = %path.display(),
                    line = previous,
                    "prime_agent: malformed interior JSONL record skipped"
                );
            }
            pending_malformed = Some(line_number);
            continue;
        };
        if let Some(previous) = pending_malformed.take() {
            malformed_interior += 1;
            tracing::warn!(
                connector = "prime_agent",
                path = %path.display(),
                line = previous,
                "prime_agent: malformed interior JSONL record skipped"
            );
        }

        if header.is_none() {
            if value.get("type").and_then(Value::as_str) != Some("session") {
                tracing::debug!(
                    connector = "prime_agent",
                    path = %path.display(),
                    reason = "first record is not a Prime session header",
                    "prime_agent: skipping non-Prime JSONL file"
                );
                return Ok(None);
            }
            let version = value.get("version").and_then(Value::as_i64).unwrap_or(1);
            if version > SUPPORTED_MAX_VERSION {
                tracing::warn!(
                    connector = "prime_agent",
                    path = %path.display(),
                    observed_version = version,
                    supported_max = SUPPORTED_MAX_VERSION,
                    reason = "session format version is newer than this connector supports",
                    "prime_agent: skipping unsupported future session version"
                );
                return Ok(None);
            }
            header = Some(value);
            continue;
        }

        entries.push(PrimeEntry {
            id: value
                .get("id")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            parent_id: value
                .get("parentId")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            value,
        });
    }

    let Some(header) = header else {
        return Ok(None);
    };

    let total_entry_count = entries.len();
    let (branch, tree_integrity) = active_branch_indices(&entries).map_or_else(
        || ((0..entries.len()).collect(), "broken_fallback_file_order"),
        |branch| (branch, "ok"),
    );
    let active_branch_entry_count = branch.len();
    let omitted_branch_entry_count = total_entry_count.saturating_sub(active_branch_entry_count);

    // Branch-sensitive metadata trackers.
    let mut messages: Vec<NormalizedMessage> = Vec::new();
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    let mut current_provider: Option<String> = None;
    let mut current_model: Option<String> = None;
    let mut git_state: Option<Value> = None;
    let mut agent_status: Option<Value> = None;
    let mut session_state: Option<String> = None;

    let mut observe_timestamp = |ts: Option<i64>| {
        if let Some(ts) = ts {
            started_at = Some(started_at.map_or(ts, |current: i64| current.min(ts)));
            ended_at = Some(ended_at.map_or(ts, |current: i64| current.max(ts)));
        }
    };

    for &idx in &branch {
        let entry = &entries[idx].value;
        let entry_ts = entry.get("timestamp").and_then(parse_timestamp);
        let entry_type = entry.get("type").and_then(Value::as_str).unwrap_or("");
        match entry_type {
            "message" => {
                let Some(message) = entry.get("message") else {
                    continue;
                };
                let role = message.get("role").and_then(Value::as_str).unwrap_or("");
                let created = message
                    .get("timestamp")
                    .and_then(parse_timestamp)
                    .or(entry_ts);
                observe_timestamp(created);
                match role {
                    "user" => {
                        let content =
                            flatten_prime_content(message.get("content").unwrap_or(&Value::Null));
                        if content.trim().is_empty() {
                            continue;
                        }
                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: "user".to_string(),
                            author: None,
                            created_at: created,
                            content,
                            extra: json!({"prime_entry_type": "message"}),
                            snippets: Vec::new(),
                            invocations: Vec::new(),
                        });
                    }
                    "assistant" => {
                        let content_value = message.get("content").unwrap_or(&Value::Null);
                        let content = flatten_prime_content(content_value);
                        let invocations = prime_invocations(content_value);
                        if content.trim().is_empty() && invocations.is_empty() {
                            continue;
                        }
                        if let Some(model) = message.get("model").and_then(Value::as_str) {
                            current_model = Some(model.to_string());
                        }
                        if let Some(provider) = message.get("provider").and_then(Value::as_str) {
                            current_provider = Some(provider.to_string());
                        }
                        let mut extra = serde_json::Map::new();
                        extra.insert("prime_entry_type".into(), json!("message"));
                        for key in ["provider", "model", "api", "stopReason", "errorMessage"] {
                            if let Some(value) = message.get(key) {
                                extra.insert(key.to_string(), bounded_json(value));
                            }
                        }
                        if let Some(usage) = message.get("usage") {
                            extra.insert("usage".into(), bounded_json(usage));
                        }
                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: "assistant".to_string(),
                            author: current_model.clone(),
                            created_at: created,
                            content,
                            extra: Value::Object(extra),
                            snippets: Vec::new(),
                            invocations,
                        });
                    }
                    "toolResult" => {
                        let content =
                            flatten_prime_content(message.get("content").unwrap_or(&Value::Null));
                        let mut extra = serde_json::Map::new();
                        extra.insert("prime_entry_type".into(), json!("message"));
                        for key in ["toolCallId", "toolName", "isError"] {
                            if let Some(value) = message.get(key) {
                                extra.insert(key.to_string(), bounded_json(value));
                            }
                        }
                        if content.trim().is_empty() {
                            continue;
                        }
                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: "tool".to_string(),
                            author: message
                                .get("toolName")
                                .and_then(Value::as_str)
                                .map(ToString::to_string),
                            created_at: created,
                            content,
                            extra: Value::Object(extra),
                            snippets: Vec::new(),
                            invocations: Vec::new(),
                        });
                    }
                    "bashExecution" => {
                        if message
                            .get("excludeFromContext")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                        {
                            continue;
                        }
                        let command = message.get("command").and_then(Value::as_str).unwrap_or("");
                        let output = message.get("output").and_then(Value::as_str).unwrap_or("");
                        let content = format!("$ {command}\n{output}");
                        if content.trim().len() <= 1 {
                            continue;
                        }
                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: "user".to_string(),
                            author: None,
                            created_at: created,
                            content,
                            extra: json!({
                                "prime_entry_type": "message",
                                "source_role": "bashExecution",
                                "exitCode": message.get("exitCode").cloned().unwrap_or(Value::Null),
                                "cancelled": message.get("cancelled").cloned().unwrap_or(Value::Null),
                                "truncated": message.get("truncated").cloned().unwrap_or(Value::Null),
                            }),
                            snippets: Vec::new(),
                            invocations: Vec::new(),
                        });
                    }
                    "custom" | "hookMessage" => {
                        // In-message custom roles (v3 `custom`, v2
                        // `hookMessage`) participate in context unless Prime
                        // excludes their type.
                        let custom_type = message
                            .get("customType")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if EXCLUDED_CUSTOM_MESSAGE_TYPES.contains(&custom_type) {
                            continue;
                        }
                        let content =
                            flatten_prime_content(message.get("content").unwrap_or(&Value::Null));
                        if content.trim().is_empty() {
                            continue;
                        }
                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: "user".to_string(),
                            author: None,
                            created_at: created,
                            content,
                            extra: json!({
                                "prime_entry_type": "message",
                                "source_role": "custom",
                                "customType": custom_type,
                                "display": message.get("display").cloned().unwrap_or(Value::Null),
                            }),
                            snippets: Vec::new(),
                            invocations: Vec::new(),
                        });
                    }
                    "branchSummary" | "compactionSummary" => {
                        let summary = message.get("summary").and_then(Value::as_str).unwrap_or("");
                        if summary.trim().is_empty() {
                            continue;
                        }
                        let label = if role == "branchSummary" {
                            "branch summary"
                        } else {
                            "compaction summary"
                        };
                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: "system".to_string(),
                            author: None,
                            created_at: created,
                            content: format!("[{label}] {summary}"),
                            extra: json!({"prime_entry_type": "message", "source_role": role}),
                            snippets: Vec::new(),
                            invocations: Vec::new(),
                        });
                    }
                    _ => {}
                }
            }
            "custom_message" => {
                let custom_type = entry
                    .get("customType")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if EXCLUDED_CUSTOM_MESSAGE_TYPES.contains(&custom_type) {
                    continue;
                }
                let content = flatten_prime_content(entry.get("content").unwrap_or(&Value::Null));
                if content.trim().is_empty() {
                    continue;
                }
                observe_timestamp(entry_ts);
                messages.push(NormalizedMessage {
                    idx: 0,
                    role: "user".to_string(),
                    author: None,
                    created_at: entry_ts,
                    content,
                    extra: json!({
                        "prime_entry_type": "custom_message",
                        "source_role": "custom",
                        "customType": custom_type,
                        "display": entry.get("display").cloned().unwrap_or(Value::Null),
                    }),
                    snippets: Vec::new(),
                    invocations: Vec::new(),
                });
            }
            "compaction" => {
                let summary = entry.get("summary").and_then(Value::as_str).unwrap_or("");
                if summary.trim().is_empty() {
                    continue;
                }
                observe_timestamp(entry_ts);
                messages.push(NormalizedMessage {
                    idx: 0,
                    role: "system".to_string(),
                    author: None,
                    created_at: entry_ts,
                    content: format!("[compaction] {summary}"),
                    extra: json!({
                        "prime_entry_type": "compaction",
                        "tokensBefore": entry.get("tokensBefore").cloned().unwrap_or(Value::Null),
                    }),
                    snippets: Vec::new(),
                    invocations: Vec::new(),
                });
            }
            "branch_summary" => {
                let summary = entry.get("summary").and_then(Value::as_str).unwrap_or("");
                if summary.trim().is_empty() {
                    continue;
                }
                observe_timestamp(entry_ts);
                messages.push(NormalizedMessage {
                    idx: 0,
                    role: "system".to_string(),
                    author: None,
                    created_at: entry_ts,
                    content: format!("[branch summary] {summary}"),
                    extra: json!({
                        "prime_entry_type": "branch_summary",
                        "fromId": entry.get("fromId").cloned().unwrap_or(Value::Null),
                    }),
                    snippets: Vec::new(),
                    invocations: Vec::new(),
                });
            }
            "model_change" => {
                if let Some(model) = entry.get("modelId").and_then(Value::as_str) {
                    current_model = Some(model.to_string());
                }
                if let Some(provider) = entry.get("provider").and_then(Value::as_str) {
                    current_provider = Some(provider.to_string());
                }
            }
            "git_state" => {
                git_state = Some(sanitize_metadata_value(entry));
            }
            "agent_status" => {
                agent_status = Some(sanitize_metadata_value(entry));
            }
            "session_state" => {
                if let Some(state) = entry.get("state").and_then(Value::as_str) {
                    session_state = Some(state.to_string());
                }
            }
            // Bookkeeping that never becomes searchable turns:
            // thinking_level_change, service_tier_change, label, custom
            // (extension state), child_usage_attributed (already folded into
            // the parent assistant usage by Prime on reload — summing it
            // again would double count), session_info (title, handled below
            // in file order).
            _ => {}
        }
    }

    if messages.is_empty() {
        return Ok(None);
    }
    reindex_messages(&mut messages);

    // Session name follows Prime's reverse-file-order behavior (the LATEST
    // session_info entry in the file wins, branch-independent).
    let session_name = entries
        .iter()
        .rev()
        .find(|entry| entry.value.get("type").and_then(Value::as_str) == Some("session_info"))
        .and_then(|entry| entry.value.get("name").and_then(Value::as_str))
        .filter(|name| !name.trim().is_empty())
        .map(ToString::to_string);
    let title = session_name.or_else(|| {
        messages.iter().find(|m| m.role == "user").map(|m| {
            m.content
                .lines()
                .next()
                .unwrap_or(&m.content)
                .chars()
                .take(100)
                .collect::<String>()
        })
    });

    let external_id = header
        .get("id")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(ToString::to_string)
        });
    let workspace = header.get("cwd").and_then(Value::as_str).map(PathBuf::from);
    // Fork/clone ancestry: prefer the parent session's basename over its
    // absolute path so provenance survives without leaking directory layout.
    let parent_session = header
        .get("parentSession")
        .and_then(Value::as_str)
        .map(|parent| {
            Path::new(parent)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(parent)
                .to_string()
        });

    let mut metadata = serde_json::Map::new();
    metadata.insert("source".into(), json!("prime_agent"));
    metadata.insert(
        "session_version".into(),
        header.get("version").cloned().unwrap_or_else(|| json!(1)),
    );
    metadata.insert("total_entry_count".into(), json!(total_entry_count));
    metadata.insert(
        "active_branch_entry_count".into(),
        json!(active_branch_entry_count),
    );
    metadata.insert(
        "omitted_branch_entry_count".into(),
        json!(omitted_branch_entry_count),
    );
    metadata.insert("tree_integrity".into(), json!(tree_integrity));
    if malformed_interior > 0 {
        metadata.insert(
            "malformed_interior_records".into(),
            json!(malformed_interior),
        );
    }
    if let Some(parent) = parent_session {
        metadata.insert("parent_session".into(), json!(parent));
    }
    if let Some(depth) = header.get("rlmDepth") {
        metadata.insert("rlm_depth".into(), depth.clone());
    }
    if let Some(model) = current_model {
        metadata.insert("model".into(), json!(model));
    }
    if let Some(provider) = current_provider {
        metadata.insert("provider".into(), json!(provider));
    }
    if let Some(state) = session_state {
        metadata.insert("session_state".into(), json!(state));
    }
    if let Some(git) = git_state {
        metadata.insert("git_state".into(), git);
    }
    if let Some(status) = agent_status {
        metadata.insert("agent_status".into(), status);
    }

    Ok(Some(NormalizedConversation {
        agent_slug: "prime_agent".to_string(),
        external_id,
        title,
        workspace,
        source_path: path.to_path_buf(),
        started_at,
        ended_at,
        metadata: Value::Object(metadata),
        messages,
    }))
}

impl Connector for PrimeAgentConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("prime_agent").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        let mut seen_files: HashSet<PathBuf> = HashSet::new();
        for root in Self::source_roots(ctx) {
            for file in Self::session_files(&root.path) {
                if !seen_files.insert(dedupe_path_key(&file)) {
                    continue;
                }
                if !super::file_modified_since(&file, ctx.since_ts) {
                    continue;
                }
                match parse_session_file(&file) {
                    Ok(Some(conversation)) => convs.push(conversation),
                    Ok(None) => {}
                    Err(error) => {
                        tracing::debug!(
                            connector = "prime_agent",
                            path = %file.display(),
                            error = %error,
                            "prime_agent: skipping unreadable session file"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use tempfile::TempDir;

    fn sessions_dir(tmp: &TempDir) -> PathBuf {
        let dir = tmp.path().join(".prime/agent/sessions");
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_session(dir: &Path, name: &str, lines: &[&str]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, lines.join("\n")).unwrap();
        path
    }

    const HEADER: &str = r#"{"type":"session","version":3,"id":"0192aa11-0000-7000-8000-000000000001","timestamp":"2026-01-05T10:00:00.000Z","cwd":"/work/project"}"#;

    fn msg(id: &str, parent: Option<&str>, message: &str) -> String {
        let parent = parent.map_or_else(|| "null".to_string(), |p| format!("\"{p}\""));
        format!(
            r#"{{"type":"message","id":"{id}","parentId":{parent},"timestamp":"2026-01-05T10:00:01.000Z","message":{message}}}"#
        )
    }

    #[test]
    fn scan_projects_active_branch_and_counts_omitted_siblings() {
        let tmp = TempDir::new().unwrap();
        let dir = sessions_dir(&tmp);
        write_session(
            &dir,
            "s1.jsonl",
            &[
                HEADER,
                &msg(
                    "aaaa0001",
                    None,
                    r#"{"role":"user","content":"first question","timestamp":1767607201000}"#,
                ),
                &msg(
                    "aaaa0002",
                    Some("aaaa0001"),
                    r#"{"role":"assistant","content":[{"type":"text","text":"abandoned answer"}],"provider":"openai","model":"gpt-4o","usage":{"input":10,"output":5,"cacheRead":0,"cacheWrite":0,"totalTokens":15},"stopReason":"stop","timestamp":1767607202000}"#,
                ),
                // Branch: a second child of aaaa0001 becomes the active leaf
                // chain; aaaa0002 is the abandoned sibling.
                &msg(
                    "aaaa0003",
                    Some("aaaa0001"),
                    r#"{"role":"assistant","content":[{"type":"text","text":"kept answer"},{"type":"thinking","thinking":"quiet plan"}],"provider":"anthropic","model":"claude-sonnet-4-5","usage":{"input":12,"output":7,"cacheRead":1,"cacheWrite":2,"totalTokens":22},"stopReason":"stop","timestamp":1767607203000}"#,
                ),
            ],
        );

        let connector = PrimeAgentConnector::new();
        let ctx = ScanContext::local_default(dir, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        assert_eq!(conv.agent_slug, "prime_agent");
        assert_eq!(
            conv.external_id.as_deref(),
            Some("0192aa11-0000-7000-8000-000000000001")
        );
        assert_eq!(conv.workspace.as_deref(), Some(Path::new("/work/project")));
        // Active branch = user + kept assistant; the abandoned sibling is
        // omitted but counted.
        assert_eq!(conv.messages.len(), 2);
        assert!(conv.messages[1].content.contains("kept answer"));
        assert!(conv.messages[1].content.contains("quiet plan"));
        assert!(
            !conv
                .messages
                .iter()
                .any(|m| m.content.contains("abandoned"))
        );
        assert_eq!(conv.metadata["total_entry_count"], 3);
        assert_eq!(conv.metadata["active_branch_entry_count"], 2);
        assert_eq!(conv.metadata["omitted_branch_entry_count"], 1);
        assert_eq!(conv.metadata["tree_integrity"], "ok");
        assert_eq!(conv.metadata["model"], "claude-sonnet-4-5");
        assert_eq!(conv.messages[1].extra["usage"]["totalTokens"], 22);
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn header_validation_rejects_future_versions_and_foreign_files() {
        let tmp = TempDir::new().unwrap();
        let dir = sessions_dir(&tmp);
        write_session(
            &dir,
            "future.jsonl",
            &[
                r#"{"type":"session","version":4,"id":"u1","timestamp":"2026-01-05T10:00:00.000Z","cwd":"/w"}"#,
                &msg("aaaa0001", None, r#"{"role":"user","content":"hi"}"#),
            ],
        );
        write_session(
            &dir,
            "foreign.jsonl",
            &[r#"{"role":"user","content":"a pi-style record, no header"}"#],
        );

        let connector = PrimeAgentConnector::new();
        let ctx = ScanContext::local_default(dir, None);
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn message_policy_covers_tools_bash_custom_and_images() {
        let tmp = TempDir::new().unwrap();
        let dir = sessions_dir(&tmp);
        write_session(
            &dir,
            "policy.jsonl",
            &[
                HEADER,
                &msg(
                    "aaaa0001",
                    None,
                    r#"{"role":"user","content":[{"type":"text","text":"look at this"},{"type":"image","data":"aGVsbG8=","mimeType":"image/png"}],"timestamp":1767607201000}"#,
                ),
                &msg(
                    "aaaa0002",
                    Some("aaaa0001"),
                    r#"{"role":"assistant","content":[{"type":"toolCall","id":"call_1","name":"bash","arguments":{"command":"ls"}}],"provider":"openai","model":"gpt-4o","stopReason":"toolUse","timestamp":1767607202000}"#,
                ),
                &msg(
                    "aaaa0003",
                    Some("aaaa0002"),
                    r#"{"role":"toolResult","toolCallId":"call_1","toolName":"bash","content":[{"type":"text","text":"README.md"}],"isError":false,"timestamp":1767607203000}"#,
                ),
                &msg(
                    "aaaa0004",
                    Some("aaaa0003"),
                    r#"{"role":"bashExecution","command":"echo hidden","output":"hidden","excludeFromContext":true,"timestamp":1767607204000}"#,
                ),
                &msg(
                    "aaaa0005",
                    Some("aaaa0004"),
                    r#"{"role":"bashExecution","command":"echo visible","output":"visible-output","exitCode":0,"cancelled":false,"truncated":false,"timestamp":1767607205000}"#,
                ),
                r#"{"type":"custom_message","id":"aaaa0006","parentId":"aaaa0005","timestamp":"2026-01-05T10:00:06.000Z","customType":"my-ext","content":"injected context","display":true}"#,
                r#"{"type":"custom_message","id":"aaaa0007","parentId":"aaaa0006","timestamp":"2026-01-05T10:00:07.000Z","customType":"session-command","content":"/resume plumbing","display":false}"#,
                r#"{"type":"custom","id":"aaaa0008","parentId":"aaaa0007","timestamp":"2026-01-05T10:00:08.000Z","customType":"my-ext","data":{"count":42}}"#,
                r#"{"type":"compaction","id":"aaaa0009","parentId":"aaaa0008","timestamp":"2026-01-05T10:00:09.000Z","summary":"earlier work summarized","firstKeptEntryId":"aaaa0003","tokensBefore":50000}"#,
            ],
        );

        let connector = PrimeAgentConnector::new();
        let ctx = ScanContext::local_default(dir, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        let contents: Vec<&str> = conv.messages.iter().map(|m| m.content.as_str()).collect();

        // Image became a bounded placeholder; no base64 anywhere.
        assert!(contents[0].contains("[image: image/png]"));
        assert!(!conv.messages[0].extra.to_string().contains("aGVsbG8="));
        // Assistant toolCall became a structured invocation.
        let invocation = &conv.messages[1].invocations[0];
        assert_eq!(invocation.name, "bash");
        assert_eq!(invocation.call_id.as_deref(), Some("call_1"));
        // toolResult projected to role "tool" with join metadata.
        assert_eq!(conv.messages[2].role, "tool");
        assert_eq!(conv.messages[2].extra["toolCallId"], "call_1");
        // excludeFromContext bash execution skipped; visible one kept.
        assert!(!contents.iter().any(|c| c.contains("hidden")));
        assert!(contents.iter().any(|c| c.contains("visible-output")));
        // Extension message kept, session-command plumbing excluded, custom
        // extension STATE never becomes a message.
        assert!(contents.iter().any(|c| c.contains("injected context")));
        assert!(!contents.iter().any(|c| c.contains("/resume plumbing")));
        assert!(!conv.messages.iter().any(|m| m.content.contains("42")));
        // Compaction summary is a labeled system turn.
        let compaction = conv
            .messages
            .iter()
            .find(|m| m.content.contains("earlier work summarized"))
            .unwrap();
        assert_eq!(compaction.role, "system");
    }

    #[test]
    fn env_override_precedence_is_pure_and_empty_safe() {
        let home = Path::new("/home/u");
        assert_eq!(
            PrimeAgentConnector::session_dirs_from_overrides(
                Some("/direct/sessions"),
                Some("/legacy"),
                Some("/agent-home"),
                Some(home)
            ),
            vec![PathBuf::from("/direct/sessions")]
        );
        assert_eq!(
            PrimeAgentConnector::session_dirs_from_overrides(
                None,
                Some("/legacy/sessions"),
                Some("/agent-home"),
                Some(home)
            ),
            vec![PathBuf::from("/legacy/sessions")]
        );
        assert_eq!(
            PrimeAgentConnector::session_dirs_from_overrides(
                Some(""),
                None,
                Some("/agent-home"),
                Some(home)
            ),
            vec![PathBuf::from("/agent-home/sessions")]
        );
        assert_eq!(
            PrimeAgentConnector::session_dirs_from_overrides(None, None, Some(""), Some(home)),
            vec![PathBuf::from("/home/u/.prime/agent/sessions")]
        );
    }

    #[test]
    fn malformed_final_line_is_forgiven_interior_damage_is_counted() {
        let tmp = TempDir::new().unwrap();
        let dir = sessions_dir(&tmp);
        write_session(
            &dir,
            "damaged.jsonl",
            &[
                HEADER,
                &msg(
                    "aaaa0001",
                    None,
                    r#"{"role":"user","content":"kept early"}"#,
                ),
                r#"{"type":"message","id":"aaaa0002","broken"#,
                &msg(
                    "aaaa0003",
                    Some("aaaa0001"),
                    r#"{"role":"assistant","content":[{"type":"text","text":"kept late"}],"timestamp":1767607203000}"#,
                ),
                r#"{"type":"message","truncated-live-write"#,
            ],
        );

        let connector = PrimeAgentConnector::new();
        let ctx = ScanContext::local_default(dir, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        assert_eq!(conv.messages.len(), 2);
        assert!(conv.messages[0].content.contains("kept early"));
        assert!(conv.messages[1].content.contains("kept late"));
        assert_eq!(conv.metadata["malformed_interior_records"], 1);
    }

    #[test]
    fn broken_tree_falls_back_to_file_order_with_integrity_flag() {
        let tmp = TempDir::new().unwrap();
        let dir = sessions_dir(&tmp);
        write_session(
            &dir,
            "orphan.jsonl",
            &[
                HEADER,
                &msg("aaaa0001", None, r#"{"role":"user","content":"first"}"#),
                // Missing parent: bbbb9999 never appears.
                &msg(
                    "aaaa0002",
                    Some("bbbb9999"),
                    r#"{"role":"assistant","content":[{"type":"text","text":"suffix"}]}"#,
                ),
            ],
        );

        let connector = PrimeAgentConnector::new();
        let ctx = ScanContext::local_default(dir, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        assert_eq!(
            conv.metadata["tree_integrity"],
            "broken_fallback_file_order"
        );
        assert_eq!(conv.messages.len(), 2);
    }

    #[test]
    fn session_info_name_wins_over_first_user_line() {
        let tmp = TempDir::new().unwrap();
        let dir = sessions_dir(&tmp);
        write_session(
            &dir,
            "named.jsonl",
            &[
                HEADER,
                &msg(
                    "aaaa0001",
                    None,
                    r#"{"role":"user","content":"raw first line"}"#,
                ),
                r#"{"type":"session_info","id":"aaaa0002","parentId":"aaaa0001","timestamp":"2026-01-05T10:00:05.000Z","name":"Refactor auth module"}"#,
            ],
        );

        let connector = PrimeAgentConnector::new();
        let ctx = ScanContext::local_default(dir, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs[0].title.as_deref(), Some("Refactor auth module"));
    }

    #[test]
    fn header_only_shell_produces_no_conversation() {
        let tmp = TempDir::new().unwrap();
        let dir = sessions_dir(&tmp);
        write_session(&dir, "shell.jsonl", &[HEADER]);

        let connector = PrimeAgentConnector::new();
        let ctx = ScanContext::local_default(dir, None);
        assert!(connector.scan(&ctx).unwrap().is_empty());
    }

    #[test]
    fn explicit_scan_roots_expand_prime_layouts() {
        let tmp = TempDir::new().unwrap();
        let dir = sessions_dir(&tmp);
        write_session(
            &dir,
            "s1.jsonl",
            &[
                HEADER,
                &msg("aaaa0001", None, r#"{"role":"user","content":"via root"}"#),
            ],
        );

        let connector = PrimeAgentConnector::new();
        // The copied-home form: root points at the home containing `.prime/`.
        let ctx = ScanContext::with_roots(
            PathBuf::new(),
            vec![ScanRoot::local(tmp.path().to_path_buf())],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("via root"));
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn credential_bearing_git_urls_are_stripped_from_metadata() {
        let tmp = TempDir::new().unwrap();
        let dir = sessions_dir(&tmp);
        write_session(
            &dir,
            "git.jsonl",
            &[
                HEADER,
                &msg("aaaa0001", None, r#"{"role":"user","content":"work"}"#),
                r#"{"type":"git_state","id":"aaaa0002","parentId":"aaaa0001","timestamp":"2026-01-05T10:00:05.000Z","branch":"main","remote":"https://user:hunter2token@github.com/org/repo.git"}"#,
            ],
        );

        let connector = PrimeAgentConnector::new();
        let ctx = ScanContext::local_default(dir, None);
        let convs = connector.scan(&ctx).unwrap();
        let git = convs[0].metadata["git_state"].to_string();
        assert!(!git.contains("hunter2token"));
        assert!(git.contains("github.com/org/repo.git"));
    }
}
