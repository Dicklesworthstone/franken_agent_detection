//! Antigravity (`agy`) connector.
//!
//! [Antigravity](https://antigravity.google) ships the `agy` CLI, Google's
//! successor to the Gemini CLI (`gmi`). It stores history under
//! `~/.gemini/antigravity-cli/` (a directory it shares with — but keeps separate
//! from — the legacy Gemini CLI, whose data lives under `~/.gemini/tmp/`):
//!
//! - `conversations/<uuid>.db` — one stock-SQLite database per conversation. The
//!   payload columns are an undocumented protobuf trajectory/steps model; this is
//!   the durable source of truth but expensive to read.
//! - `brain/<uuid>/.system_generated/logs/transcript.jsonl` — a **clean JSONL
//!   transcript** of the same conversation. This is the connector's primary read
//!   path: a simple, stable line-per-step JSON shape, no protobuf required. (A
//!   fuller `transcript_full.jsonl` sits beside it.)
//!
//! The `<uuid>` keying `conversations/<uuid>.db` and `brain/<uuid>/` is the same
//! id used by `agy --conversation <uuid>`.
//!
//! ## transcript.jsonl record shape
//!
//! Each line is one JSON object: `{ step_index, source, type, status,
//! created_at, content?, thinking?, tool_calls? }`.
//!
//! - `step_index` (i64) — timeline order. Indices may have gaps; we sort by it.
//! - `source` — `USER_EXPLICIT` | `MODEL` | `SYSTEM`.
//! - `type` — the step kind. Known kinds and their normalized mapping:
//!   - `USER_INPUT` (`USER_EXPLICIT`) → `role: "user"`. The real prompt is wrapped
//!     in `<USER_REQUEST>…</USER_REQUEST>`; `<ADDITIONAL_METADATA>` (local time)
//!     and `<USER_SETTINGS_CHANGE>` (records the model) are appended. We extract
//!     the request body and keep the wrappers in `extra`.
//!   - `PLANNER_RESPONSE` (`MODEL`) → `role: "assistant"`. `content` is the visible
//!     reply; `thinking` is the model's reasoning, preserved in `extra.thinking`.
//!   - any other `MODEL` kind (`VIEW_FILE`, `EDIT_FILE`, `RUN_COMMAND`, …) → a
//!     `role: "tool"` step. `content` is the tool result; `tool_calls` (when
//!     present) are the structured calls. We synthesize a [`NormalizedInvocation`]
//!     named after the step so the tool is searchable even when `tool_calls` is
//!     absent. The raw `type` is preserved in `extra.agy_type`.
//!   - `EPHEMERAL_MESSAGE` / `SYSTEM_MESSAGE` (`SYSTEM`) → `role: "system"`
//!     (preserved faithfully; tagged in `extra` so consumers can down-rank the
//!     repetitive ephemeral reminders).
//!   - `CONVERSATION_HISTORY` (`SYSTEM`) — a null-content marker; no message.
//! - `created_at` — RFC3339 UTC (`2026-06-11T20:14:42Z`), read by [`parse_timestamp`].
//!
//! Unknown future `type`s are never dropped or crashed on: they are emitted as a
//! best-effort message keyed off `source`, with the raw `type` kept in
//! `extra.agy_type`. (See the agy version-compatibility guard work.)

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Map, Value};
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::{dedupe_path_key, env_path_nonempty};
use super::{Connector, file_modified_since, franken_detection_for_connector, parse_timestamp};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
    reindex_messages,
};

/// Normalized agent slug emitted for every Antigravity conversation.
const AGENT_SLUG: &str = "antigravity";

/// Connector for the Antigravity (`agy`) coding agent.
pub struct AntigravityConnector;

impl Default for AntigravityConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl AntigravityConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Base directory holding `conversations/` and `brain/`.
    ///
    /// Defaults to `~/.gemini/antigravity-cli`; overridable for tests / remote
    /// mirrors via `CASS_ANTIGRAVITY_DATA_ROOT`.
    fn base_root() -> PathBuf {
        if let Some(explicit) = env_path_nonempty("CASS_ANTIGRAVITY_DATA_ROOT") {
            return explicit;
        }
        dirs::home_dir()
            .unwrap_or_default()
            .join(".gemini")
            .join("antigravity-cli")
    }

    /// Transcript path for a `brain/<uuid>` conversation directory.
    fn transcript_path(conversation_dir: &Path) -> PathBuf {
        conversation_dir
            .join(".system_generated")
            .join("logs")
            .join("transcript.jsonl")
    }

    /// The fuller transcript variant, when agy wrote one.
    fn transcript_full_path(conversation_dir: &Path) -> PathBuf {
        conversation_dir
            .join(".system_generated")
            .join("logs")
            .join("transcript_full.jsonl")
    }

    /// A conversation directory is recognized by the presence of its
    /// `transcript.jsonl` (the primary read path).
    fn is_conversation_dir(path: &Path) -> bool {
        Self::transcript_path(path).is_file()
    }

    /// The `<uuid>` for a conversation directory (its directory name).
    fn conversation_uuid(conversation_dir: &Path) -> Option<String> {
        conversation_dir
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|s| !s.trim().is_empty())
            .map(String::from)
    }

    /// The sibling `conversations/<uuid>.db` for a `brain/<uuid>` directory, when
    /// the standard layout is intact (`<base>/brain/<uuid>` ↔
    /// `<base>/conversations/<uuid>.db`).
    fn sibling_db_path(conversation_dir: &Path) -> Option<PathBuf> {
        let uuid = Self::conversation_uuid(conversation_dir)?;
        // conversation_dir = <base>/brain/<uuid>; climb to <base>.
        let base = conversation_dir.parent()?.parent()?;
        let db = base.join("conversations").join(format!("{uuid}.db"));
        db.is_file().then_some(db)
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots = if ctx.use_default_detection() {
            vec![ScanRoot::local(Self::base_root())]
        } else {
            ctx.scan_roots.clone()
        };

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    /// Resolve every `brain/<uuid>` conversation directory reachable from a scan
    /// target. The target may be the conversation directory itself, the `brain/`
    /// directory, or the `antigravity-cli` base directory.
    fn conversation_dirs(scan_target: &Path) -> Vec<PathBuf> {
        if Self::is_conversation_dir(scan_target) {
            return vec![scan_target.to_path_buf()];
        }

        let mut out = Vec::new();
        // The transcript sits at <conv>/.system_generated/logs/transcript.jsonl,
        // so the conversation dir is three levels above the file. From the base
        // dir that file is at depth 5 (base/brain/<uuid>/.system_generated/logs).
        for entry in WalkDir::new(scan_target)
            .min_depth(1)
            .max_depth(6)
            .into_iter()
            .flatten()
        {
            if !entry.file_type().is_file() || entry.file_name() != "transcript.jsonl" {
                continue;
            }
            let path = entry.path();
            // Require the .system_generated/logs/ ancestry so we don't pick up an
            // unrelated transcript.jsonl somewhere else.
            let conv_dir = path
                .parent() // logs/
                .filter(|logs| logs.file_name().is_some_and(|n| n == "logs"))
                .and_then(Path::parent) // .system_generated/
                .filter(|sg| sg.file_name().is_some_and(|n| n == ".system_generated"))
                .and_then(Path::parent); // <uuid>/
            if let Some(dir) = conv_dir {
                out.push(dir.to_path_buf());
            }
        }

        out.sort();
        out.dedup();
        out
    }

    /// True when the conversation's transcript is newer than `since_ts`.
    fn conversation_modified_since(conversation_dir: &Path, since_ts: Option<i64>) -> bool {
        if since_ts.is_none() {
            return true;
        }
        file_modified_since(&Self::transcript_path(conversation_dir), since_ts)
            || file_modified_since(&Self::transcript_full_path(conversation_dir), since_ts)
    }

    /// Read a transcript file into per-step JSON records, tolerating blank lines
    /// and individual malformed lines (skipped + logged, never fatal).
    fn read_transcript_records(transcript: &Path) -> Vec<Value> {
        let Ok(text) = fs::read_to_string(transcript) else {
            return Vec::new();
        };
        let mut records = Vec::new();
        for (lineno, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(trimmed) {
                Ok(value) => records.push(value),
                Err(err) => tracing::warn!(
                    transcript = %transcript.display(),
                    line = lineno + 1,
                    error = %err,
                    "antigravity: skipping malformed transcript line"
                ),
            }
        }
        records
    }
}

/// Extract the inner text of every `<TAG>…</TAG>` block in `content`.
fn extract_tagged_blocks(content: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = content;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else {
            break;
        };
        out.push(after[..end].trim().to_string());
        rest = &after[end + close.len()..];
    }
    out
}

/// Split a wrapped `USER_INPUT` payload into (request body, settings-change text,
/// metadata text). agy wraps the real prompt as `<USER_REQUEST>` and may append
/// `<USER_SETTINGS_CHANGE>` and `<ADDITIONAL_METADATA>`. A single record can
/// carry several `<USER_REQUEST>` blocks; they are joined. If no wrapper is
/// present we fall back to the raw content.
fn extract_user_request(content: &str) -> (String, Option<String>, Option<String>) {
    let requests = extract_tagged_blocks(content, "USER_REQUEST");
    let settings = extract_tagged_blocks(content, "USER_SETTINGS_CHANGE")
        .into_iter()
        .next();
    let metadata = extract_tagged_blocks(content, "ADDITIONAL_METADATA")
        .into_iter()
        .next();
    let body = if requests.is_empty() {
        content.trim().to_string()
    } else {
        requests.join("\n\n")
    };
    (body, settings, metadata)
}

/// Pull the model name out of a `<USER_SETTINGS_CHANGE>` body such as
/// "The user changed setting `Model Selection` from None to Gemini 3.1 Pro
/// (High). No need to comment…" → `Some("Gemini 3.1 Pro (High)")`.
fn model_from_settings(settings: &str) -> Option<String> {
    let marker = " to ";
    let start = settings.find(marker)? + marker.len();
    let tail = &settings[start..];
    let end = tail.find(". ").unwrap_or(tail.len());
    let model = tail[..end].trim().trim_end_matches('.').trim();
    if model.is_empty() || model.eq_ignore_ascii_case("none") {
        return None;
    }
    Some(model.to_string())
}

/// The first model recorded by any `<USER_SETTINGS_CHANGE>` in the transcript.
fn detect_model(records: &[Value]) -> Option<String> {
    for rec in records {
        if rec.get("type").and_then(Value::as_str) != Some("USER_INPUT") {
            continue;
        }
        let content = rec.get("content").and_then(Value::as_str).unwrap_or("");
        if let Some(settings) = extract_tagged_blocks(content, "USER_SETTINGS_CHANGE")
            .into_iter()
            .next()
        {
            if let Some(model) = model_from_settings(&settings) {
                return Some(model);
            }
        }
    }
    None
}

/// Parse `tool_calls` into normalized invocations. When the array is absent we
/// still synthesize one invocation named after the step `type` (e.g.
/// `VIEW_FILE` → `view_file`) so the tool remains searchable.
fn parse_tool_calls(tool_calls: Option<&Value>, step_type: &str) -> Vec<NormalizedInvocation> {
    let synthesized_name = step_type.to_ascii_lowercase();
    let Some(arr) = tool_calls
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
    else {
        return vec![NormalizedInvocation {
            kind: "tool".to_string(),
            name: synthesized_name,
            raw_name: None,
            call_id: None,
            arguments: None,
        }];
    };

    arr.iter()
        .map(|tc| {
            let name = tc
                .get("name")
                .or_else(|| tc.get("tool_name"))
                .or_else(|| tc.pointer("/function/name"))
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map_or_else(|| synthesized_name.clone(), String::from);
            let call_id = tc
                .get("id")
                .or_else(|| tc.get("call_id"))
                .or_else(|| tc.get("tool_call_id"))
                .and_then(Value::as_str)
                .map(String::from);
            let arguments = tc
                .get("arguments")
                .or_else(|| tc.get("args"))
                .or_else(|| tc.get("input"))
                .or_else(|| tc.pointer("/function/arguments"))
                .cloned()
                .map(|raw| match raw {
                    // agy may store arguments as a JSON string; parse if possible.
                    Value::String(s) => {
                        serde_json::from_str::<Value>(&s).unwrap_or(Value::String(s))
                    }
                    other => other,
                });
            NormalizedInvocation {
                kind: "tool".to_string(),
                name,
                raw_name: None,
                call_id,
                arguments,
            }
        })
        .collect()
}

/// Build a [`NormalizedMessage`] (idx assigned later by `reindex_messages`).
fn message(
    role: &str,
    author: Option<&str>,
    created_at: Option<i64>,
    content: String,
    extra: Map<String, Value>,
    invocations: Vec<NormalizedInvocation>,
) -> NormalizedMessage {
    NormalizedMessage {
        idx: 0,
        role: role.to_string(),
        author: author.map(String::from),
        created_at,
        content,
        extra: Value::Object(extra),
        invocations,
        snippets: Vec::new(),
    }
}

/// Map a single transcript record to a normalized message, or `None` for records
/// that carry no timeline content (e.g. `CONVERSATION_HISTORY` markers).
#[allow(clippy::too_many_lines)]
fn record_to_message(rec: &Value) -> Option<NormalizedMessage> {
    let source = rec.get("source").and_then(Value::as_str).unwrap_or("");
    let step_type = rec.get("type").and_then(Value::as_str).unwrap_or("");
    let created = rec.get("created_at").and_then(parse_timestamp);
    let content = rec
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let thinking = rec
        .get("thinking")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let tool_calls = rec.get("tool_calls").filter(|v| v.is_array());

    match step_type {
        "USER_INPUT" => {
            let (body, settings, metadata) = extract_user_request(&content);
            if body.trim().is_empty() {
                return None;
            }
            let mut extra = Map::new();
            if let Some(s) = settings {
                extra.insert("settings_change".to_string(), Value::String(s));
            }
            if let Some(m) = metadata {
                extra.insert("additional_metadata".to_string(), Value::String(m));
            }
            Some(message("user", None, created, body, extra, Vec::new()))
        }
        "PLANNER_RESPONSE" => {
            if content.trim().is_empty() && thinking.is_none() {
                return None;
            }
            let mut extra = Map::new();
            if let Some(t) = thinking {
                extra.insert("thinking".to_string(), Value::String(t));
            }
            Some(message(
                "assistant",
                None,
                created,
                content,
                extra,
                Vec::new(),
            ))
        }
        "CONVERSATION_HISTORY" => None,
        "EPHEMERAL_MESSAGE" | "SYSTEM_MESSAGE" => {
            if content.trim().is_empty() {
                return None;
            }
            let mut extra = Map::new();
            extra.insert("agy_type".to_string(), Value::String(step_type.to_string()));
            let author = if step_type == "EPHEMERAL_MESSAGE" {
                "ephemeral"
            } else {
                "system"
            };
            Some(message(
                "system",
                Some(author),
                created,
                content,
                extra,
                Vec::new(),
            ))
        }
        _ => {
            // A MODEL step that is not a planner response is a tool action/result
            // (VIEW_FILE, EDIT_FILE, RUN_COMMAND, …, or an unknown future kind).
            if source == "MODEL" {
                let invocations = parse_tool_calls(tool_calls, step_type);
                if content.trim().is_empty() && thinking.is_none() && invocations.is_empty() {
                    return None;
                }
                let mut extra = Map::new();
                extra.insert("agy_type".to_string(), Value::String(step_type.to_string()));
                if let Some(t) = thinking {
                    extra.insert("thinking".to_string(), Value::String(t));
                }
                let author = step_type.to_ascii_lowercase();
                Some(message(
                    "tool",
                    Some(author.as_str()),
                    created,
                    content,
                    extra,
                    invocations,
                ))
            } else {
                // Unknown non-MODEL kind: preserve as a system message rather than
                // dropping it. Never crash on an unrecognized schema.
                if content.trim().is_empty() {
                    return None;
                }
                let mut extra = Map::new();
                extra.insert("agy_type".to_string(), Value::String(step_type.to_string()));
                if !source.is_empty() {
                    extra.insert("agy_source".to_string(), Value::String(source.to_string()));
                }
                Some(message("system", None, created, content, extra, Vec::new()))
            }
        }
    }
}

fn parse_conversation(
    conversation_dir: &Path,
    _scan_root: &ScanRoot,
) -> Option<NormalizedConversation> {
    let transcript = AntigravityConnector::transcript_path(conversation_dir);
    let records = AntigravityConnector::read_transcript_records(&transcript);
    if records.is_empty() {
        return None;
    }

    // Sort by step_index (gaps are expected; ties keep input order via stable sort).
    let mut ordered: Vec<&Value> = records.iter().collect();
    ordered.sort_by_key(|r| {
        r.get("step_index")
            .and_then(Value::as_i64)
            .unwrap_or(i64::MAX)
    });

    let external_id = AntigravityConnector::conversation_uuid(conversation_dir);
    let model = detect_model(&records);

    let mut messages: Vec<NormalizedMessage> = Vec::new();
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;

    for rec in ordered {
        if let Some(ts) = rec.get("created_at").and_then(parse_timestamp) {
            started_at = Some(started_at.map_or(ts, |cur| cur.min(ts)));
            ended_at = Some(ended_at.map_or(ts, |cur| cur.max(ts)));
        }
        if let Some(msg) = record_to_message(rec) {
            messages.push(msg);
        }
    }

    if messages.is_empty() {
        return None;
    }

    reindex_messages(&mut messages);

    let title = messages
        .iter()
        .find(|m| m.role == "user")
        .or_else(|| messages.first())
        .and_then(|m| m.content.lines().find(|l| !l.trim().is_empty()))
        .map(|line| line.chars().take(100).collect::<String>());

    let mut metadata = Map::new();
    metadata.insert("source".to_string(), Value::String(AGENT_SLUG.to_string()));
    if let Some(model) = model {
        metadata.insert("model".to_string(), Value::String(model));
    }

    Some(NormalizedConversation {
        agent_slug: AGENT_SLUG.to_string(),
        external_id,
        title,
        workspace: None,
        source_path: transcript,
        started_at,
        ended_at,
        metadata: Value::Object(metadata),
        messages,
    })
}

fn scan_antigravity_with_callback(
    ctx: &ScanContext,
    on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
) -> Result<()> {
    let roots = AntigravityConnector::source_roots(ctx);
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for root in roots {
        if !root.path.exists() {
            continue;
        }
        for conversation_dir in AntigravityConnector::conversation_dirs(&root.path) {
            if !seen.insert(dedupe_path_key(&conversation_dir)) {
                continue;
            }
            if !AntigravityConnector::conversation_modified_since(&conversation_dir, ctx.since_ts) {
                continue;
            }
            if let Some(conversation) = parse_conversation(&conversation_dir, &root) {
                on_conversation(conversation).with_context(|| {
                    format!(
                        "emit antigravity conversation {}",
                        conversation_dir.display()
                    )
                })?;
            }
        }
    }

    Ok(())
}

fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
    let roots = AntigravityConnector::source_roots(ctx);
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for root in roots {
        if !root.path.exists() {
            continue;
        }
        for conversation_dir in AntigravityConnector::conversation_dirs(&root.path) {
            if !AntigravityConnector::conversation_modified_since(&conversation_dir, ctx.since_ts) {
                continue;
            }

            // The transcript we actually parse — required for reconstruction.
            let transcript = AntigravityConnector::transcript_path(&conversation_dir);
            if transcript.is_file() && seen.insert(dedupe_path_key(&transcript)) {
                out.push(
                    DiscoveredSourceFile::new(
                        AGENT_SLUG,
                        &root,
                        transcript,
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }

            // The fuller transcript variant, if present (optional).
            let transcript_full = AntigravityConnector::transcript_full_path(&conversation_dir);
            if transcript_full.is_file() && seen.insert(dedupe_path_key(&transcript_full)) {
                out.push(
                    DiscoveredSourceFile::new(
                        AGENT_SLUG,
                        &root,
                        transcript_full,
                        DiscoveredSourceRole::PrimarySessionLog,
                        false,
                    )
                    .with_fs_metadata(),
                );
            }

            // The durable per-conversation SQLite database — the canonical source
            // of truth worth mirroring, though we read the transcript instead.
            if let Some(db) = AntigravityConnector::sibling_db_path(&conversation_dir) {
                if seen.insert(dedupe_path_key(&db)) {
                    out.push(
                        DiscoveredSourceFile::new(
                            AGENT_SLUG,
                            &root,
                            db,
                            DiscoveredSourceRole::SqliteDatabase,
                            false,
                        )
                        .with_fs_metadata(),
                    );
                }
            }
        }
    }

    out
}

impl Connector for AntigravityConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector(AGENT_SLUG).unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        scan_antigravity_with_callback(ctx, &mut |conv| {
            convs.push(conv);
            Ok(())
        })?;
        Ok(convs)
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(discover_sources(ctx))
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        scan_antigravity_with_callback(ctx, on_conversation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::assert_discovery_covers_scan_sources;
    use std::fs;
    use tempfile::TempDir;

    const FIXTURE_UUID: &str = "f1e2d3c4-b5a6-4789-9abc-def012345678";

    /// The `antigravity-cli`-equivalent base directory of the checked-in fixture.
    fn fixture_base() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("antigravity")
    }

    fn fixture_conversation_dir() -> PathBuf {
        fixture_base().join("brain").join(FIXTURE_UUID)
    }

    fn fixture_ctx() -> ScanContext {
        let base = fixture_base();
        ScanContext::with_roots(base.clone(), vec![ScanRoot::local(base)], None)
    }

    fn only_conversation() -> NormalizedConversation {
        let convs = AntigravityConnector::new().scan(&fixture_ctx()).unwrap();
        assert_eq!(convs.len(), 1, "fixture is a single conversation");
        convs.into_iter().next().unwrap()
    }

    #[test]
    fn new_creates_connector() {
        let _ = AntigravityConnector::new();
        let _ = AntigravityConnector;
    }

    #[test]
    fn is_conversation_dir_requires_transcript() {
        let dir = TempDir::new().unwrap();
        assert!(!AntigravityConnector::is_conversation_dir(dir.path()));
        let logs = dir.path().join(".system_generated").join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("transcript.jsonl"), "{}\n").unwrap();
        assert!(AntigravityConnector::is_conversation_dir(dir.path()));
    }

    #[test]
    fn extract_tagged_blocks_handles_multiple_and_missing() {
        assert_eq!(
            extract_tagged_blocks("<A>one</A> mid <A>two</A>", "A"),
            vec!["one".to_string(), "two".to_string()]
        );
        assert!(extract_tagged_blocks("no tags here", "A").is_empty());
        // Unterminated open tag does not panic or loop forever.
        assert!(extract_tagged_blocks("<A>oops", "A").is_empty());
    }

    #[test]
    fn extract_user_request_unwraps_and_keeps_settings() {
        let raw = "<USER_REQUEST>\ndo the thing\n</USER_REQUEST>\n<ADDITIONAL_METADATA>\ntime\n</ADDITIONAL_METADATA>\n<USER_SETTINGS_CHANGE>\nchanged to Gemini 3.1 Pro (High). ok\n</USER_SETTINGS_CHANGE>";
        let (body, settings, metadata) = extract_user_request(raw);
        assert_eq!(body, "do the thing");
        assert!(settings.unwrap().contains("Gemini 3.1 Pro (High)"));
        assert_eq!(metadata.as_deref(), Some("time"));
    }

    #[test]
    fn extract_user_request_falls_back_to_raw_when_unwrapped() {
        let (body, settings, metadata) = extract_user_request("plain prompt with no tags");
        assert_eq!(body, "plain prompt with no tags");
        assert!(settings.is_none() && metadata.is_none());
    }

    #[test]
    fn model_from_settings_extracts_human_name() {
        assert_eq!(
            model_from_settings(
                "The user changed setting `Model Selection` from None to Gemini 3.1 Pro (High). No need to comment."
            )
            .as_deref(),
            Some("Gemini 3.1 Pro (High)")
        );
        assert_eq!(model_from_settings("changed from X to None. done"), None);
    }

    #[test]
    fn parse_tool_calls_synthesizes_name_from_type_when_absent() {
        let invs = parse_tool_calls(None, "VIEW_FILE");
        assert_eq!(invs.len(), 1);
        assert_eq!(invs[0].name, "view_file");
        assert_eq!(invs[0].kind, "tool");
        assert!(invs[0].arguments.is_none());
    }

    #[test]
    fn parse_tool_calls_reads_structured_object_args() {
        let tc = serde_json::json!([
            {"name":"run_command","id":"c1","arguments":{"command":"echo hi"}}
        ]);
        let invs = parse_tool_calls(Some(&tc), "RUN_COMMAND");
        assert_eq!(invs[0].name, "run_command");
        assert_eq!(invs[0].call_id.as_deref(), Some("c1"));
        assert_eq!(invs[0].arguments.as_ref().unwrap()["command"], "echo hi");
    }

    #[test]
    fn parse_tool_calls_parses_stringified_json_args() {
        let tc = serde_json::json!([
            {"tool_name":"edit_file","id":"c2","arguments":"{\"path\":\"out.txt\"}"}
        ]);
        let invs = parse_tool_calls(Some(&tc), "EDIT_FILE");
        assert_eq!(invs[0].name, "edit_file");
        assert_eq!(invs[0].arguments.as_ref().unwrap()["path"], "out.txt");
    }

    #[test]
    fn scan_parses_fixture_metadata_and_roles() {
        let conv = only_conversation();
        assert_eq!(conv.agent_slug, "antigravity");
        assert_eq!(conv.external_id.as_deref(), Some(FIXTURE_UUID));
        assert_eq!(conv.metadata["model"], "Gemini 3.1 Pro (High)");
        assert_eq!(conv.metadata["source"], "antigravity");
        assert!(conv.title.as_deref().unwrap().starts_with("Read data.txt"));
        assert!(conv.started_at.unwrap() <= conv.ended_at.unwrap());
        assert_eq!(
            conv.source_path,
            AntigravityConnector::transcript_path(&fixture_conversation_dir())
        );

        // CONVERSATION_HISTORY is dropped; every other record becomes a message.
        assert_eq!(conv.messages.len(), 9);
        for (i, m) in conv.messages.iter().enumerate() {
            assert_eq!(m.idx, i64::try_from(i).unwrap());
        }
        assert!(conv.messages.iter().any(|m| m.role == "user"));
        assert!(conv.messages.iter().any(|m| m.role == "assistant"));
        assert!(conv.messages.iter().any(|m| m.role == "tool"));
        assert!(conv.messages.iter().any(|m| m.role == "system"));
    }

    #[test]
    fn user_message_unwraps_request_and_keeps_settings_extra() {
        let conv = only_conversation();
        let user = conv.messages.iter().find(|m| m.role == "user").unwrap();
        assert!(user.content.starts_with("Read data.txt"));
        assert!(!user.content.contains("USER_REQUEST"));
        assert!(
            user.extra["settings_change"]
                .as_str()
                .unwrap()
                .contains("Gemini 3.1 Pro (High)")
        );
        assert!(user.extra.get("additional_metadata").is_some());
    }

    #[test]
    fn planner_response_preserves_thinking() {
        let conv = only_conversation();
        let planner = conv
            .messages
            .iter()
            .find(|m| m.role == "assistant" && m.extra.get("thinking").is_some())
            .expect("a planner response with thinking");
        assert!(planner.content.contains("data.txt"));
        assert!(
            planner.extra["thinking"]
                .as_str()
                .unwrap()
                .contains("Planning the steps")
        );
    }

    #[test]
    fn view_file_becomes_tool_message_with_synthesized_invocation() {
        let conv = only_conversation();
        let view = conv
            .messages
            .iter()
            .find(|m| m.extra.get("agy_type").and_then(Value::as_str) == Some("VIEW_FILE"))
            .expect("VIEW_FILE message");
        assert_eq!(view.role, "tool");
        assert!(view.content.contains("1234"));
        assert_eq!(view.invocations[0].name, "view_file");
        assert!(view.invocations[0].arguments.is_none());
    }

    #[test]
    fn run_command_invocation_carries_structured_args() {
        let conv = only_conversation();
        let run = conv
            .messages
            .iter()
            .find(|m| m.invocations.iter().any(|i| i.name == "run_command"))
            .expect("run_command message");
        assert_eq!(run.role, "tool");
        assert!(run.content.contains("HELLO_FROM_AGY"));
        let inv = &run.invocations[0];
        assert_eq!(inv.call_id.as_deref(), Some("call_run_0001"));
        assert_eq!(
            inv.arguments.as_ref().unwrap()["command"],
            "echo HELLO_FROM_AGY"
        );
    }

    #[test]
    fn edit_file_invocation_parses_stringified_args() {
        let conv = only_conversation();
        let edit = conv
            .messages
            .iter()
            .find(|m| m.invocations.iter().any(|i| i.name == "edit_file"))
            .expect("edit_file message");
        let inv = &edit.invocations[0];
        assert_eq!(inv.call_id.as_deref(), Some("call_edit_0002"));
        assert_eq!(inv.arguments.as_ref().unwrap()["path"], "out.txt");
        assert_eq!(inv.arguments.as_ref().unwrap()["content"], "DONE");
    }

    #[test]
    fn ephemeral_and_system_messages_preserved_as_system() {
        let conv = only_conversation();
        let ephemeral = conv
            .messages
            .iter()
            .find(|m| m.extra.get("agy_type").and_then(Value::as_str) == Some("EPHEMERAL_MESSAGE"))
            .expect("ephemeral message");
        assert_eq!(ephemeral.role, "system");
        assert_eq!(ephemeral.author.as_deref(), Some("ephemeral"));

        let system = conv
            .messages
            .iter()
            .find(|m| m.extra.get("agy_type").and_then(Value::as_str) == Some("SYSTEM_MESSAGE"))
            .expect("system message");
        assert_eq!(system.role, "system");
        assert_eq!(system.author.as_deref(), Some("system"));
    }

    #[test]
    fn unknown_model_step_type_is_preserved_not_dropped() {
        // BROWSER_PREVIEW is an unknown-to-us MODEL kind; the reader must never
        // crash or silently drop it (agy version-compat robustness).
        let conv = only_conversation();
        let unknown = conv
            .messages
            .iter()
            .find(|m| m.extra.get("agy_type").and_then(Value::as_str) == Some("BROWSER_PREVIEW"))
            .expect("unknown BROWSER_PREVIEW message preserved");
        assert_eq!(unknown.role, "tool");
        assert!(unknown.content.contains("preview"));
        assert_eq!(unknown.invocations[0].name, "browser_preview");
    }

    #[test]
    fn discovery_lists_transcript_full_and_db() {
        let connector = AntigravityConnector::new();
        let discovered = connector.discover_source_files(&fixture_ctx()).unwrap();

        assert!(discovered.iter().all(|d| d.provider_slug == "antigravity"));
        assert!(
            discovered
                .iter()
                .any(|d| d.source_path.ends_with("transcript.jsonl")
                    && d.role == DiscoveredSourceRole::PrimarySessionLog
                    && d.required_for_reconstruction),
            "transcript.jsonl must be a required primary source"
        );
        assert!(
            discovered
                .iter()
                .any(|d| d.source_path.ends_with("transcript_full.jsonl")),
            "transcript_full.jsonl should be discovered"
        );
        assert!(
            discovered
                .iter()
                .any(|d| d.role == DiscoveredSourceRole::SqliteDatabase
                    && d.source_path.extension().is_some_and(|e| e == "db")),
            "the conversations/<uuid>.db should be discovered as the sqlite source"
        );
    }

    #[test]
    fn discovery_covers_scan_sources_for_fixture() {
        assert_discovery_covers_scan_sources(&AntigravityConnector::new(), &fixture_ctx());
    }

    #[test]
    fn scan_with_callback_matches_scan() {
        let connector = AntigravityConnector::new();
        let scanned = connector.scan(&fixture_ctx()).unwrap();
        let mut streamed = Vec::new();
        connector
            .scan_with_callback(&fixture_ctx(), &mut |c| {
                streamed.push(c);
                Ok(())
            })
            .unwrap();
        assert_eq!(streamed.len(), scanned.len());
        assert_eq!(streamed[0].messages.len(), scanned[0].messages.len());
    }

    #[test]
    fn scan_resolves_conversation_from_direct_dir() {
        let dir = fixture_conversation_dir();
        let ctx = ScanContext::with_roots(dir.clone(), vec![ScanRoot::local(dir)], None);
        let convs = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn scan_returns_empty_for_missing_root() {
        let ctx = ScanContext::with_roots(
            PathBuf::from("/no/such/antigravity"),
            vec![ScanRoot::local(PathBuf::from("/no/such/antigravity"))],
            None,
        );
        assert!(AntigravityConnector::new().scan(&ctx).unwrap().is_empty());
    }

    #[test]
    fn since_ts_in_future_skips_conversation() {
        let base = fixture_base();
        let ctx =
            ScanContext::with_roots(base.clone(), vec![ScanRoot::local(base)], Some(i64::MAX));
        assert!(AntigravityConnector::new().scan(&ctx).unwrap().is_empty());
    }

    #[test]
    fn ignores_legacy_gemini_cli_layout_under_shared_dot_gemini() {
        // Both the legacy Gemini CLI (~/.gemini/tmp/<hash>/chats/session-*.json)
        // and agy (~/.gemini/antigravity-cli/...) live under ~/.gemini. The agy
        // connector must resolve ONLY the antigravity-cli transcript, never the
        // gemini session files. Root at the shared `.gemini` parent to prove it.
        let tmp = TempDir::new().unwrap();
        let dot_gemini = tmp.path().join(".gemini");

        // Legacy gemini-cli session (must be ignored).
        let chats = dot_gemini.join("tmp").join("deadbeef").join("chats");
        fs::create_dir_all(&chats).unwrap();
        fs::write(chats.join("session-1.json"), "{\"messages\":[]}").unwrap();

        // agy conversation transcript (must be found).
        let logs = dot_gemini
            .join("antigravity-cli")
            .join("brain")
            .join("11111111-2222-3333-4444-555555555555")
            .join(".system_generated")
            .join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(
            logs.join("transcript.jsonl"),
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"status\":\"DONE\",\"created_at\":\"2026-06-11T20:14:42Z\",\"content\":\"<USER_REQUEST>\\nhi\\n</USER_REQUEST>\"}\n",
        )
        .unwrap();

        let ctx =
            ScanContext::with_roots(dot_gemini.clone(), vec![ScanRoot::local(dot_gemini)], None);
        let convs = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1, "only the agy conversation should be found");
        assert_eq!(convs[0].agent_slug, "antigravity");
        assert_eq!(
            convs[0].external_id.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
    }
}
