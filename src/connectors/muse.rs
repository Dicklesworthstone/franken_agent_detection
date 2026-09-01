//! Muse Code (`muse`) connector.
//!
//! Muse Code is Meta's terminal coding agent (installed from
//! `dev.meta.ai/install.sh` to `~/.local/bin/muse`), new as of August 2026.
//!
//! ## Provenance
//!
//! The storage layout and event schema below come from a field report
//! (GitHub issue #15, reverse-engineered against Muse Code 0.1.0
//! `0.1.0-R708.1` on Linux, a 5-session corpus). They are NOT vendor
//! documentation, so this connector parses strictly but skips-and-logs on
//! anything that does not match the reported shapes. Known open questions
//! from the report: macOS paths are unverified (XDG only below), whether
//! `input_tokens` is cache-inclusive is unknown, and the event vocabulary
//! is likely larger than the observed set.
//!
//! ## Storage layout (per the field report)
//!
//! ```text
//! ~/.local/share/muse/
//!   sessions/<YYYY>/<MM>/<DD>/<session-uuid>/
//!     session.jsonl                       ← the transcript
//!     .session.lock, cron.db              ← harness state (ignored)
//!     subagent/<subagent-uuid>/
//!       session.jsonl                     ← nested, same format
//!   tui-history.jsonl                     ← TUI input history (ignored)
//!   skills/…, plugins/…                   ← (ignored)
//! ~/.config/muse/{settings,auth,trust}.json
//! ```
//!
//! ## `session.jsonl` line envelope
//!
//! Append-only JSONL, one envelope per line:
//!
//! ```json
//! {"schema_version":1,"id":"…","stream":{"kind":"session","id":"…"},
//!  "sequence":1,"recorded_at":1785972468194395,"record_type":"event",
//!  "durability":"durable","causation_id":null,
//!  "payload_type":"runtime.session.metadata","payload_schema_version":1,
//!  "payload":{…}}
//! ```
//!
//! - `recorded_at` is **microseconds** since epoch (1.78e15 falls outside
//!   the shared [`parse_timestamp`](super::parse_timestamp) seconds/millis
//!   heuristics, so this module converts locally).
//! - `sequence` is the authoritative turn order; records are sorted by it
//!   rather than trusting file order.
//! - Conversation lives in `payload_type == "runtime.session"` records with
//!   `payload.kind == "run"`, discriminated by `payload.event.kind`. Only
//!   four kinds carry conversation (`started`,
//!   `assistant_message_committed`, `assistant_tool_calls_committed`,
//!   `tool_result_batch_committed`); the rest is telemetry and skipped.
//! - `payload.event.tool_calls[].args` is a JSON-encoded *string*, not an
//!   object, so it is reparsed into structure.
//!
//! ## The two reported gotchas, and how they are handled
//!
//! 1. **Subagent logs have no `workspace_root`.** Only the root log emits a
//!    `runtime.session.metadata` record. Subagent transcripts at
//!    `…/<session>/subagent/<id>/session.jsonl` inherit the workspace from
//!    the parent's `../../session.jsonl` (they run in the parent's
//!    workspace).
//! 2. **`model_completed` carries no correlation id and its ordering
//!    relative to the assistant message is unstable** (after it in the
//!    reporter's main session, before it in all subagents). Per-message
//!    adjacency attribution is therefore unsafe; usage is summed at the
//!    session level into conversation `metadata` instead of being attached
//!    to individual messages. `goal_usage_attribution` events restate the
//!    same numbers (plus zeroed `tool` rows), so they are deliberately NOT
//!    summed — that would double-count. `reasoning_tokens` is contained by
//!    `output_tokens` (not additive), so it is carried as-is without adding.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Map, Value};

use super::flatten_content;
use super::scan::{
    DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot, SourceCompletion,
    SourceScanHooks,
};
use super::utils::{dedupe_path_key, env_path_nonempty};
use super::{Connector, file_modified_since, franken_detection_for_connector};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
    reindex_messages,
};

/// Normalized agent slug emitted for every Muse Code conversation.
const AGENT_SLUG: &str = "muse";

/// The transcript filename inside every session (and subagent) directory.
const SESSION_FILE: &str = "session.jsonl";

/// Maximum directory depth walked below a scan target when hunting for
/// transcripts: `sessions/<YYYY>/<MM>/<DD>/<uuid>/subagent/<uuid>/session.jsonl`
/// is 7 components below the base root; 8 leaves headroom for one wrapper dir.
const MAX_WALK_DEPTH: usize = 8;

/// Connector for Meta's Muse Code (`muse`) coding agent.
pub struct MuseConnector;

impl Default for MuseConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl MuseConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Base data directory. Respects the `CASS_MUSE_DATA_ROOT` override
    /// (mirroring the aider/antigravity/openhands override convention),
    /// otherwise the field-reported XDG default `~/.local/share/muse`.
    /// macOS placement is unverified per the field report; XDG covers the
    /// observed installs and overrides cover the rest.
    fn base_root() -> PathBuf {
        if let Some(explicit) = env_path_nonempty("CASS_MUSE_DATA_ROOT") {
            return explicit;
        }
        dirs::home_dir()
            .unwrap_or_default()
            .join(".local")
            .join("share")
            .join("muse")
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots = if ctx.use_default_detection() {
            // Mirror the explicit-root acceptance: a default-detection
            // data_dir that itself looks like muse storage (the
            // `~/.local/share/muse` base with a `sessions/` tree, or the
            // `sessions/` dir itself) scopes the scan to it, so
            // fixture/mirror scans stay hermetic; otherwise probe the
            // system base. `CASS_MUSE_DATA_ROOT` keeps precedence so CI
            // redirection is unaffected.
            let d = &ctx.data_dir;
            let env_override = env_path_nonempty("CASS_MUSE_DATA_ROOT").is_some();
            let looks_like_base =
                d.join("sessions").is_dir() || d.file_name().is_some_and(|n| n == "sessions");
            if !env_override && looks_like_base {
                vec![ScanRoot::local(d.clone())]
            } else {
                vec![ScanRoot::local(Self::base_root())]
            }
        } else {
            ctx.scan_roots.clone()
        };
        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    /// Resolve every `session.jsonl` reachable from a scan target. The
    /// target may be a transcript file itself, a session directory, the
    /// `sessions/` tree (or any date level inside it), or the base
    /// `~/.local/share/muse` root. Only files literally named
    /// `session.jsonl` are transcripts — `tui-history.jsonl`, `cron.db`,
    /// and lock files are harness state and never match.
    fn session_files(scan_target: &Path) -> Vec<PathBuf> {
        if scan_target.is_file() {
            if scan_target.file_name().is_some_and(|n| n == SESSION_FILE) {
                return vec![scan_target.to_path_buf()];
            }
            return Vec::new();
        }
        if !scan_target.is_dir() {
            return Vec::new();
        }

        // From the base root, narrow to sessions/ so plugin caches and
        // bundled skills are never traversed.
        let walk_root = {
            let sessions = scan_target.join("sessions");
            if sessions.is_dir() {
                sessions
            } else {
                scan_target.to_path_buf()
            }
        };

        let mut out: Vec<PathBuf> = walkdir::WalkDir::new(&walk_root)
            .max_depth(MAX_WALK_DEPTH)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .filter(|entry| entry.file_name() == SESSION_FILE)
            .map(walkdir::DirEntry::into_path)
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// Convert a Muse `recorded_at` value to epoch milliseconds.
///
/// The field report established `recorded_at` as **microseconds** since
/// epoch (e.g. `1785972468194395` ≈ 2026-08-05). That magnitude falls
/// outside the shared `parse_timestamp` seconds/millis heuristics, so this
/// local variant adds a microseconds band. Seconds and milliseconds are
/// still accepted defensively in case other builds log differently.
fn muse_ts_to_millis(val: &Value) -> Option<i64> {
    let raw = val.as_i64().or_else(|| {
        #[allow(clippy::cast_possible_truncation)]
        val.as_f64()
            .filter(|f| f.is_finite() && *f > 0.0)
            .map(|f| f.round() as i64)
    })?;
    if raw <= 0 {
        return None;
    }
    if raw >= 100_000_000_000_000 {
        // Microseconds (>= ~year 5138 if read as millis).
        Some(raw / 1000)
    } else if raw >= 100_000_000_000 {
        // Milliseconds.
        Some(raw)
    } else {
        // Seconds.
        Some(raw.saturating_mul(1000))
    }
}

// ---------------------------------------------------------------------------
// Record parsing
// ---------------------------------------------------------------------------

/// One decoded `session.jsonl` envelope, holding just what the connector
/// consumes.
struct MuseRecord {
    /// Sort key: `(0, sequence)` for records carrying the authoritative
    /// `sequence`; `(1, file position)` for records without one. The band
    /// keeps the unsequenced tail after every well-formed record while a
    /// plain `i64::MAX - lineno` fallback would have emitted it in REVERSED
    /// append order.
    sort_key: (i64, i64),
    recorded_at_ms: Option<i64>,
    payload_type: String,
    payload: Value,
    stream_id: Option<String>,
}
/// Strict on the envelope basics (`payload_type` string + `payload`
/// present); tolerant elsewhere. A missing `sequence` sorts the record by
/// its file position (after every sequenced record) rather than dropping
/// it.
fn parse_record(line: &str, lineno: usize) -> Option<MuseRecord> {
    let val: Value = serde_json::from_str(line).ok()?;
    let obj = val.as_object()?;
    let payload_type = obj.get("payload_type")?.as_str()?.to_string();
    let payload = obj.get("payload")?.clone();
    let sort_key = obj.get("sequence").and_then(Value::as_i64).map_or_else(
        || (1, i64::try_from(lineno).unwrap_or(i64::MAX)),
        |seq| (0, seq),
    );
    let recorded_at_ms = obj.get("recorded_at").and_then(muse_ts_to_millis);
    let stream_id = obj
        .get("stream")
        .and_then(|stream| stream.get("id"))
        .and_then(Value::as_str)
        .map(String::from);
    Some(MuseRecord {
        sort_key,
        recorded_at_ms,
        payload_type,
        payload,
        stream_id,
    })
}

/// Read and sequence-sort every well-formed record in a transcript.
fn read_records(session_file: &Path) -> Vec<MuseRecord> {
    let Ok(file) = fs::File::open(session_file) else {
        return Vec::new();
    };
    let mut records: Vec<MuseRecord> = Vec::new();
    for (lineno, line) in BufReader::new(file).lines().enumerate() {
        let Ok(line) = line else {
            tracing::warn!(
                transcript = %session_file.display(),
                line = lineno + 1,
                "muse: stopping at unreadable transcript line"
            );
            break;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(record) = parse_record(line, lineno) {
            records.push(record);
        } else {
            tracing::warn!(
                transcript = %session_file.display(),
                line = lineno + 1,
                "muse: skipping malformed transcript line"
            );
        }
    }
    // `sequence` is the authoritative order per the field report; records
    // without one sort after all sequenced records, in file order (the
    // two-band key in `MuseRecord::sort_key`).
    records.sort_by_key(|r| r.sort_key);
    records
}

/// Scan a transcript for its `runtime.session.metadata` record and return
/// `payload.record.workspace_root`, if any. Used both for the session's own
/// workspace and for subagent inheritance (gotcha 1).
fn workspace_root_of(session_file: &Path) -> Option<PathBuf> {
    let Ok(file) = fs::File::open(session_file) else {
        tracing::debug!(transcript = %session_file.display(), "muse: cannot open transcript for workspace lookup");
        return None;
    };
    for (lineno, line) in BufReader::new(file).lines().enumerate() {
        // A single unreadable line must not abort workspace extraction for
        // the whole transcript — skip and keep scanning.
        let Ok(line) = line else {
            tracing::debug!(transcript = %session_file.display(), line = lineno + 1, "muse: skipping unreadable line during workspace lookup");
            continue;
        };
        let line = line.trim();
        if line.is_empty() || !line.contains("runtime.session.metadata") {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if val.get("payload_type").and_then(Value::as_str) != Some("runtime.session.metadata") {
            continue;
        }
        if let Some(root) = val
            .pointer("/payload/record/workspace_root")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
        {
            return Some(PathBuf::from(root));
        }
    }
    None
}

/// If `session_file` is a subagent transcript
/// (`…/<session>/subagent/<id>/session.jsonl`), return
/// `(parent_session_dir, parent_transcript)`.
fn subagent_parent(session_file: &Path) -> Option<(PathBuf, PathBuf)> {
    let subagent_dir = session_file.parent()?; // <subagent-uuid>/
    let marker = subagent_dir.parent()?; // subagent/
    if marker.file_name()? != "subagent" {
        return None;
    }
    let parent_session_dir = marker.parent()?.to_path_buf();
    let parent_transcript = parent_session_dir.join(SESSION_FILE);
    Some((parent_session_dir, parent_transcript))
}

/// Token usage summed across a session's `model_completed` events.
///
/// Per gotcha 2, `model_completed` has no correlation id and its position
/// relative to the committed assistant message is unstable, so usage is
/// aggregated at file level rather than attributed per message.
/// `goal_usage_attribution` restates these numbers (double-count hazard)
/// and is intentionally excluded. `reasoning_tokens` is a subset of
/// `output_tokens` per the report, so it is tracked but never added on top.
#[derive(Default)]
struct UsageTotals {
    model_requests: u64,
    input_tokens: u64,
    output_tokens: u64,
    reasoning_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
}

impl UsageTotals {
    fn add(&mut self, usage: &Value) {
        let field = |key: &str| usage.get(key).and_then(Value::as_u64).unwrap_or(0);
        self.model_requests += 1;
        self.input_tokens += field("input_tokens");
        self.output_tokens += field("output_tokens");
        self.reasoning_tokens += field("reasoning_tokens");
        self.cache_read_tokens += field("cache_read_tokens");
        self.cache_write_tokens += field("cache_write_tokens");
    }

    fn to_value(&self) -> Value {
        serde_json::json!({
            "model_requests": self.model_requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            // Contained by output_tokens, NOT additive (field report).
            "reasoning_tokens": self.reasoning_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
        })
    }
}

/// Parse `event.tool_calls[]` into normalized invocations, reparsing the
/// JSON-encoded `args` string into structure (field-report note).
fn parse_tool_calls(event: &Value) -> Vec<NormalizedInvocation> {
    let Some(calls) = event.get("tool_calls").and_then(Value::as_array) else {
        return Vec::new();
    };
    calls
        .iter()
        .filter_map(|call| {
            let name = call
                .get("name")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())?
                .to_string();
            let arguments = call.get("args").map(|args| match args {
                // `args` is documented as a JSON-encoded string; reparse it.
                // Keep the raw string when it is not valid JSON rather than
                // dropping the information.
                Value::String(s) => {
                    serde_json::from_str::<Value>(s).unwrap_or_else(|_| args.clone())
                }
                other => other.clone(),
            });
            Some(NormalizedInvocation {
                kind: "tool".to_string(),
                name,
                raw_name: None,
                call_id: call
                    .get("call_id")
                    .and_then(Value::as_str)
                    .map(String::from),
                arguments,
            })
        })
        .collect()
}

/// Flatten a prompt/text value that is usually a string but tolerated as
/// structured content.
fn text_of(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(other) => flatten_content(other),
        None => String::new(),
    }
}

/// Join `event.results[].text` for a `tool_result_batch_committed` event and
/// collect the correlated `tool_call_id`s.
fn tool_result_batch(event: &Value) -> (String, Vec<String>) {
    let Some(results) = event.get("results").and_then(Value::as_array) else {
        return (String::new(), Vec::new());
    };
    let mut parts: Vec<String> = Vec::new();
    let mut call_ids: Vec<String> = Vec::new();
    for result in results {
        let text = text_of(result.get("text"));
        if !text.trim().is_empty() {
            parts.push(text);
        }
        if let Some(id) = result.get("tool_call_id").and_then(Value::as_str) {
            call_ids.push(id.to_string());
        }
    }
    (parts.join("\n"), call_ids)
}

fn push_message(
    messages: &mut Vec<NormalizedMessage>,
    role: &str,
    content: String,
    ts: Option<i64>,
    event_kind: &str,
    mut extra: Map<String, Value>,
    invocations: Vec<NormalizedInvocation>,
) {
    extra.insert(
        "event_kind".to_string(),
        Value::String(event_kind.to_string()),
    );
    messages.push(NormalizedMessage {
        idx: 0,
        role: role.to_string(),
        author: None,
        created_at: ts,
        content,
        extra: Value::Object(extra),
        invocations,
        snippets: Vec::new(),
    });
}

#[allow(clippy::too_many_lines)]
fn parse_session(session_file: &Path) -> Option<NormalizedConversation> {
    let records = read_records(session_file);
    if records.is_empty() {
        return None;
    }

    let external_id = records
        .iter()
        .find_map(|r| r.stream_id.clone())
        .or_else(|| {
            session_file
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .map(String::from)
        });

    let mut workspace: Option<PathBuf> = None;
    let mut build: Option<Value> = None;
    let mut model_name: Option<String> = None;
    let mut usage = UsageTotals::default();
    let mut end_reason: Option<Value> = None;
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    let mut messages: Vec<NormalizedMessage> = Vec::new();

    for record in &records {
        if let Some(t) = record.recorded_at_ms {
            started_at = Some(started_at.map_or(t, |s| s.min(t)));
            ended_at = Some(ended_at.map_or(t, |e| e.max(t)));
        }

        match record.payload_type.as_str() {
            "runtime.session.metadata" => {
                if let Some(root) = record
                    .payload
                    .pointer("/record/workspace_root")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                {
                    workspace = Some(PathBuf::from(root));
                }
                if let Some(b) = record.payload.pointer("/record/build") {
                    if !b.is_null() {
                        build = Some(b.clone());
                    }
                }
            }
            "session.end" => {
                if let Some(reason) = record
                    .payload
                    .get("reason")
                    .or_else(|| record.payload.get("end_reason"))
                {
                    if !reason.is_null() {
                        end_reason = Some(reason.clone());
                    }
                }
            }
            "runtime.session" => {
                // Conversation rides only in `payload.kind == "run"` records.
                if record.payload.get("kind").and_then(Value::as_str) != Some("run") {
                    continue;
                }
                let Some(event) = record.payload.get("event") else {
                    continue;
                };
                let Some(event_kind) = event.get("kind").and_then(Value::as_str) else {
                    continue;
                };
                let ts = record.recorded_at_ms;
                match event_kind {
                    "started" => {
                        let prompt = text_of(event.get("prompt"));
                        if !prompt.trim().is_empty() {
                            push_message(
                                &mut messages,
                                "user",
                                prompt,
                                ts,
                                event_kind,
                                Map::new(),
                                Vec::new(),
                            );
                        }
                    }
                    "assistant_message_committed" => {
                        let text = text_of(event.get("text"));
                        if !text.trim().is_empty() {
                            push_message(
                                &mut messages,
                                "assistant",
                                text,
                                ts,
                                event_kind,
                                Map::new(),
                                Vec::new(),
                            );
                        }
                    }
                    "assistant_tool_calls_committed" => {
                        let invocations = parse_tool_calls(event);
                        let text = text_of(event.get("text"));
                        if !text.trim().is_empty() || !invocations.is_empty() {
                            push_message(
                                &mut messages,
                                "assistant",
                                text,
                                ts,
                                event_kind,
                                Map::new(),
                                invocations,
                            );
                        }
                    }
                    "tool_result_batch_committed" => {
                        let (text, call_ids) = tool_result_batch(event);
                        if !text.trim().is_empty() || !call_ids.is_empty() {
                            let mut extra = Map::new();
                            if !call_ids.is_empty() {
                                extra.insert(
                                    "tool_call_ids".to_string(),
                                    Value::Array(call_ids.into_iter().map(Value::String).collect()),
                                );
                            }
                            push_message(
                                &mut messages,
                                "tool",
                                text,
                                ts,
                                event_kind,
                                extra,
                                Vec::new(),
                            );
                        }
                    }
                    "model_completed" => {
                        // No correlation id + unstable ordering (gotcha 2):
                        // aggregate at session level, never per message.
                        if let Some(u) = event.get("usage") {
                            usage.add(u);
                        }
                        if let Some(model) = event
                            .get("model")
                            .and_then(Value::as_str)
                            .filter(|s| !s.trim().is_empty())
                        {
                            model_name = Some(model.to_string());
                        }
                    }
                    // `goal_usage_attribution` restates model_completed usage
                    // (double-count hazard); everything else in the observed
                    // vocabulary — and any future kind — is telemetry.
                    _ => {}
                }
            }
            // Other envelope payload types (`session.opened.observed`,
            // `run.model.configured`, `command.invoked`, …) are telemetry.
            _ => {}
        }
    }

    if messages.is_empty() {
        // Un-run or telemetry-only transcript; nothing to index.
        return None;
    }
    reindex_messages(&mut messages);

    // Gotcha 1: subagent transcripts never carry a metadata record; they run
    // in the parent's workspace, so inherit it from ../../session.jsonl.
    let mut metadata = Map::new();
    metadata.insert("source".to_string(), Value::String(AGENT_SLUG.to_string()));
    if let Some((parent_session_dir, parent_transcript)) = subagent_parent(session_file) {
        metadata.insert("subagent".to_string(), Value::Bool(true));
        if let Some(parent_id) = parent_session_dir
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|s| !s.is_empty())
        {
            metadata.insert(
                "parent_session_id".to_string(),
                Value::String(parent_id.to_string()),
            );
        }
        if workspace.is_none() && parent_transcript.is_file() {
            workspace = workspace_root_of(&parent_transcript);
        }
    }
    if let Some(model) = &model_name {
        metadata.insert("model".to_string(), Value::String(model.clone()));
    }
    if usage.model_requests > 0 {
        metadata.insert("usage".to_string(), usage.to_value());
    }
    if let Some(b) = build {
        metadata.insert("build".to_string(), b);
    }
    if let Some(reason) = end_reason {
        metadata.insert("end_reason".to_string(), reason);
    }

    let title = messages
        .iter()
        .find(|m| m.role == "user")
        .or_else(|| messages.first())
        .and_then(|m| m.content.lines().find(|l| !l.trim().is_empty()))
        .map(|line| line.chars().take(100).collect::<String>());

    Some(NormalizedConversation {
        agent_slug: AGENT_SLUG.to_string(),
        external_id,
        title,
        workspace,
        source_path: session_file.to_path_buf(),
        started_at,
        ended_at,
        metadata: Value::Object(metadata),
        messages,
    })
}

fn scan_muse_with_callback(
    ctx: &ScanContext,
    on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
) -> Result<()> {
    scan_muse_with_hooks(ctx, &mut SourceScanHooks::default(), on_conversation)
}

fn scan_muse_with_hooks(
    ctx: &ScanContext,
    hooks: &mut SourceScanHooks<'_>,
    on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
) -> Result<()> {
    let roots = MuseConnector::source_roots(ctx);
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for root in roots {
        if !root.path.exists() {
            continue;
        }
        for session_file in MuseConnector::session_files(&root.path) {
            if !seen.insert(dedupe_path_key(&session_file)) {
                continue;
            }
            if !file_modified_since(&session_file, ctx.since_ts) {
                continue;
            }
            // Pre-parse identity, mirrored from discover_sources() (FAD#22).
            let discovered = DiscoveredSourceFile::new(
                AGENT_SLUG,
                &root,
                session_file.clone(),
                DiscoveredSourceRole::PrimarySessionLog,
                true,
            )
            .with_fs_metadata();
            if !hooks.should_scan(&discovered) {
                continue;
            }
            if let Some(conversation) = parse_session(&session_file) {
                on_conversation(conversation).with_context(|| {
                    format!("emit muse conversation {}", session_file.display())
                })?;
                // Withheld when the file changed while being parsed.
                if !discovered.fs_metadata_changed() {
                    hooks.complete(&SourceCompletion {
                        source: discovered,
                        required_sidecars: Vec::new(),
                        conversations_emitted: 1,
                    })?;
                }
            }
        }
    }

    Ok(())
}

fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
    let roots = MuseConnector::source_roots(ctx);
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for root in roots {
        if !root.path.exists() {
            continue;
        }
        for session_file in MuseConnector::session_files(&root.path) {
            if !file_modified_since(&session_file, ctx.since_ts) {
                continue;
            }
            if seen.insert(dedupe_path_key(&session_file)) {
                out.push(
                    DiscoveredSourceFile::new(
                        AGENT_SLUG,
                        &root,
                        session_file,
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }
        }
    }

    out
}

impl Connector for MuseConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector(AGENT_SLUG).unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        scan_muse_with_callback(ctx, &mut |conv| {
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
        scan_muse_with_callback(ctx, on_conversation)
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
        scan_muse_with_hooks(ctx, hooks, on_conversation)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Fixture transcripts below are constructed from the schema documented in the
// field report (issue #15), NOT captured from a real Muse Code install.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::assert_discovery_covers_scan_sources;
    use serde_json::json;
    use tempfile::TempDir;

    const SESSION_ID: &str = "216854bc-9df1-4a01-93b5-000000000001";
    const SUBAGENT_ID: &str = "5f0c2c1e-77aa-4bcd-9a10-000000000002";

    /// 2026-08-05T…Z in microseconds, matching the field report's magnitude.
    const BASE_US: i64 = 1_785_972_468_194_395;

    /// Wrap a payload in the reported envelope shape.
    fn envelope(sequence: i64, payload_type: &str, payload: &serde_json::Value) -> String {
        serde_json::to_string(&json!({
            "schema_version": 1,
            "id": format!("705d0e90-0000-0000-0000-{sequence:012}"),
            "stream": {"kind": "session", "id": SESSION_ID},
            "sequence": sequence,
            "recorded_at": BASE_US + sequence * 1_000_000,
            "record_type": "event",
            "durability": "durable",
            "causation_id": null,
            "payload_type": payload_type,
            "payload": payload,
        }))
        .expect("serialize envelope")
    }

    // Fixture builder: the owned Value reads naturally at call sites and is
    // only borrowed by the envelope macro.
    #[allow(clippy::needless_pass_by_value)]
    fn run_event(sequence: i64, event: serde_json::Value) -> String {
        envelope(
            sequence,
            "runtime.session",
            &json!({"kind": "run", "event": event}),
        )
    }

    /// A root-session transcript exercising every conversation-bearing event
    /// kind plus the telemetry that must be skipped.
    fn root_session_lines(workspace: &str) -> Vec<String> {
        vec![
            envelope(
                1,
                "runtime.session.metadata",
                &json!({"record": {"workspace_root": workspace, "build": "0.1.0-R708.1"}}),
            ),
            envelope(2, "session.opened.observed", &json!({})),
            run_event(
                3,
                json!({"kind": "started", "prompt": "Fix the failing test"}),
            ),
            run_event(
                4,
                json!({"kind": "model_request_configured", "model": "muse-spark-1.2"}),
            ),
            run_event(
                5,
                json!({
                    "kind": "assistant_tool_calls_committed",
                    "text": "Looking at the test file.",
                    "tool_calls": [{
                        "name": "read_file",
                        "call_id": "call-1",
                        // JSON-encoded STRING, per the field report.
                        "args": "{\"path\":\"/data/projects/demo/tests/it.rs\"}"
                    }]
                }),
            ),
            run_event(
                6,
                json!({
                    "kind": "tool_result_batch_committed",
                    "results": [{"tool_call_id": "call-1", "text": "fn it_works() { … }"}]
                }),
            ),
            // model_completed BEFORE the committed assistant message here
            // (the subagent-style ordering) to prove adjacency isn't assumed.
            run_event(
                7,
                json!({
                    "kind": "model_completed",
                    "duration_ms": 4122,
                    "model": "muse-spark-1.2",
                    "usage": {
                        "input_tokens": 21_433, "output_tokens": 97,
                        "reasoning_tokens": 74, "cache_read_tokens": 0,
                        "cache_write_tokens": 0, "cached_tokens": 0
                    }
                }),
            ),
            run_event(
                8,
                json!({"kind": "assistant_message_committed", "text": "The assertion was inverted; fixed."}),
            ),
            // Restates model_completed — must NOT be double-counted.
            run_event(
                9,
                json!({
                    "kind": "goal_usage_attribution",
                    "usage_family": "provider",
                    "usage": {"input_tokens": 21_433, "output_tokens": 97}
                }),
            ),
            envelope(10, "session.end", &json!({"reason": "completed"})),
        ]
    }

    fn write_lines(path: &Path, lines: &[String]) {
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, lines.join("\n")).expect("write transcript");
    }

    /// Build the reported on-disk layout: base/sessions/YYYY/MM/DD/<uuid>/…
    fn build_fixture(base: &Path) -> (PathBuf, PathBuf) {
        let session_dir = base.join("sessions/2026/08/05").join(SESSION_ID);
        let root_log = session_dir.join(SESSION_FILE);
        write_lines(&root_log, &root_session_lines("/data/projects/demo"));
        // Harness state that must never be scanned.
        fs::write(session_dir.join(".session.lock"), b"").expect("lock");
        fs::write(session_dir.join("cron.db"), b"sqlite?").expect("cron");
        fs::write(base.join("tui-history.jsonl"), "{\"input\":\"ls\"}\n").expect("tui history");

        // Subagent: runtime.session records ONLY — no metadata record.
        let sub_log = session_dir
            .join("subagent")
            .join(SUBAGENT_ID)
            .join(SESSION_FILE);
        write_lines(
            &sub_log,
            &[
                run_event(
                    1,
                    json!({"kind": "started", "prompt": "Search the repo for usages"}),
                ),
                run_event(
                    2,
                    json!({
                        "kind": "model_completed",
                        "model": "muse-spark-1.2",
                        "usage": {"input_tokens": 900, "output_tokens": 40, "reasoning_tokens": 12}
                    }),
                ),
                run_event(
                    3,
                    json!({"kind": "assistant_message_committed", "text": "Found 3 usages."}),
                ),
            ],
        );
        (root_log, sub_log)
    }

    fn ctx_for(base: &Path) -> ScanContext {
        ScanContext::with_roots(
            base.to_path_buf(),
            vec![ScanRoot::local(base.to_path_buf())],
            None,
        )
    }

    #[test]
    fn default_detection_scopes_to_muse_base_data_dir() {
        // build_fixture lays out the real store shape under the temp base;
        // default detection with this base as data_dir must scan HERE, not
        // the machine's real ~/.local/share/muse.
        let temp = TempDir::new().expect("tempdir");
        let (root_log, sub_log) = build_fixture(temp.path());

        let convs = MuseConnector::new()
            .scan(&ScanContext::local_default(temp.path().to_path_buf(), None))
            .expect("scan");
        let mut paths: Vec<&Path> = convs.iter().map(|c| c.source_path.as_path()).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec![root_log.as_path(), sub_log.as_path()],
            "default detection with a muse-base data_dir must scan that base"
        );
    }

    #[test]
    fn muse_ts_to_millis_handles_all_bands() {
        // Microseconds (the reported unit).
        assert_eq!(
            muse_ts_to_millis(&json!(1_785_972_468_194_395_i64)),
            Some(1_785_972_468_194)
        );
        // Milliseconds pass through.
        assert_eq!(
            muse_ts_to_millis(&json!(1_700_000_000_000_i64)),
            Some(1_700_000_000_000)
        );
        // Seconds are upconverted.
        assert_eq!(
            muse_ts_to_millis(&json!(1_700_000_000_i64)),
            Some(1_700_000_000_000)
        );
        assert_eq!(muse_ts_to_millis(&json!(0)), None);
        assert_eq!(muse_ts_to_millis(&json!(-5)), None);
        assert_eq!(muse_ts_to_millis(&json!("nope")), None);
    }

    #[test]
    fn parses_root_session_with_all_event_kinds() {
        let temp = TempDir::new().expect("tempdir");
        let (root_log, _) = build_fixture(temp.path());

        let conv = parse_session(&root_log).expect("root conversation");
        assert_eq!(conv.agent_slug, "muse");
        assert_eq!(conv.external_id.as_deref(), Some(SESSION_ID));
        assert_eq!(conv.workspace, Some(PathBuf::from("/data/projects/demo")));
        assert_eq!(conv.title.as_deref(), Some("Fix the failing test"));

        // Timestamps came from microsecond recorded_at values.
        let started = conv.started_at.expect("started_at");
        assert!(
            (1_700_000_000_000..1_900_000_000_000).contains(&started),
            "microsecond recorded_at must land in plausible epoch-millis range, got {started}"
        );

        // user, assistant(tool_calls), tool, assistant — telemetry skipped.
        let roles: Vec<&str> = conv.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, vec!["user", "assistant", "tool", "assistant"]);

        // JSON-encoded args string was reparsed into structure.
        let inv = &conv.messages[1].invocations[0];
        assert_eq!(inv.name, "read_file");
        assert_eq!(inv.call_id.as_deref(), Some("call-1"));
        assert_eq!(
            inv.arguments
                .as_ref()
                .and_then(|a| a.get("path"))
                .and_then(Value::as_str),
            Some("/data/projects/demo/tests/it.rs")
        );

        // Tool result joined + correlated.
        assert!(conv.messages[2].content.contains("it_works"));
        assert_eq!(conv.messages[2].extra["tool_call_ids"], json!(["call-1"]));

        // Usage summed once from model_completed only (no
        // goal_usage_attribution double count), reasoning not added on top.
        let usage = &conv.metadata["usage"];
        assert_eq!(usage["model_requests"], json!(1));
        assert_eq!(usage["input_tokens"], json!(21_433));
        assert_eq!(usage["output_tokens"], json!(97));
        assert_eq!(usage["reasoning_tokens"], json!(74));
        assert_eq!(conv.metadata["model"], json!("muse-spark-1.2"));
        assert_eq!(conv.metadata["build"], json!("0.1.0-R708.1"));
        assert_eq!(conv.metadata["end_reason"], json!("completed"));
        assert!(conv.metadata.get("subagent").is_none());
    }

    #[test]
    fn subagent_inherits_parent_workspace() {
        let temp = TempDir::new().expect("tempdir");
        let (_, sub_log) = build_fixture(temp.path());

        let conv = parse_session(&sub_log).expect("subagent conversation");
        // Gotcha 1: no metadata record of its own, workspace inherited from
        // ../../session.jsonl.
        assert_eq!(conv.workspace, Some(PathBuf::from("/data/projects/demo")));
        assert_eq!(conv.metadata["subagent"], json!(true));
        assert_eq!(conv.metadata["parent_session_id"], json!(SESSION_ID));
        let roles: Vec<&str> = conv.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, vec!["user", "assistant"]);
    }

    #[test]
    fn scan_finds_root_and_subagent_but_not_harness_state() {
        let temp = TempDir::new().expect("tempdir");
        let (root_log, sub_log) = build_fixture(temp.path());

        let convs = MuseConnector::new()
            .scan(&ctx_for(temp.path()))
            .expect("scan");
        let mut paths: Vec<&Path> = convs.iter().map(|c| c.source_path.as_path()).collect();
        paths.sort();
        assert_eq!(paths, vec![root_log.as_path(), sub_log.as_path()]);
    }

    #[test]
    fn sequence_order_wins_over_file_order() {
        let temp = TempDir::new().expect("tempdir");
        let log = temp
            .path()
            .join("sessions/2026/08/05/s1")
            .join(SESSION_FILE);
        // Assistant line written BEFORE the user line; sequence says otherwise.
        write_lines(
            &log,
            &[
                run_event(
                    5,
                    json!({"kind": "assistant_message_committed", "text": "answer"}),
                ),
                run_event(2, json!({"kind": "started", "prompt": "question"})),
            ],
        );
        let conv = parse_session(&log).expect("conversation");
        let roles: Vec<&str> = conv.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, vec!["user", "assistant"]);
        assert_eq!(conv.messages[0].content, "question");
    }

    #[test]
    fn unsequenced_records_keep_append_order() {
        let temp = TempDir::new().expect("tempdir");
        let log = temp
            .path()
            .join("sessions/2026/08/05/s4")
            .join(SESSION_FILE);
        // Envelope without a `sequence` field: must trail every sequenced
        // record and preserve file order among itself. The old
        // `i64::MAX - lineno` fallback emitted this band in REVERSE.
        let unsequenced = |payload_type: &str, payload: serde_json::Value| -> String {
            serde_json::to_string(&json!({
                "schema_version": 1,
                "stream": {"kind": "session", "id": SESSION_ID},
                "recorded_at": BASE_US,
                "record_type": "event",
                "durability": "durable",
                "payload_type": payload_type,
                "payload": payload,
            }))
            .expect("serialize unsequenced envelope")
        };
        write_lines(
            &log,
            &[
                run_event(
                    7,
                    json!({"kind": "assistant_message_committed", "text": "answer"}),
                ),
                run_event(3, json!({"kind": "started", "prompt": "question"})),
                unsequenced(
                    "runtime.session",
                    json!({"kind": "run", "event": {"kind": "started", "prompt": "late-a"}}),
                ),
                unsequenced(
                    "runtime.session",
                    json!({
                        "kind": "run",
                        "event": {"kind": "assistant_message_committed", "text": "late-b"}
                    }),
                ),
            ],
        );
        let conv = parse_session(&log).expect("conversation");
        let roles: Vec<&str> = conv.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, vec!["user", "assistant", "user", "assistant"]);
        // Sequenced records sort by sequence; the unsequenced tail keeps
        // append order (late-a before late-b).
        assert_eq!(conv.messages[0].content, "question");
        assert_eq!(conv.messages[1].content, "answer");
        assert_eq!(conv.messages[2].content, "late-a");
        assert_eq!(conv.messages[3].content, "late-b");
    }

    #[test]
    fn workspace_lookup_survives_unreadable_line() {
        let temp = TempDir::new().expect("tempdir");
        let session_dir = temp.path().join("sessions/2026/08/05").join(SESSION_ID);
        let root_log = session_dir.join(SESSION_FILE);
        // Parent transcript: valid event, an invalid-UTF-8 region, THEN the
        // metadata record. The workspace lookup must skip the bad line and
        // still find the record (a hard stop would lose the workspace).
        let mut bytes = run_event(1, json!({"kind": "started", "prompt": "question"})).into_bytes();
        bytes.push(b'\n');
        bytes.extend_from_slice(b"\xff\xfe not valid utf-8\n");
        bytes.extend_from_slice(
            envelope(
                2,
                "runtime.session.metadata",
                &json!({"record": {"workspace_root": "/data/projects/demo"}}),
            )
            .as_bytes(),
        );
        bytes.push(b'\n');
        fs::create_dir_all(&session_dir).expect("mkdir");
        fs::write(&root_log, &bytes).expect("write transcript");

        // Subagent transcript with no metadata of its own (gotcha 1): the
        // workspace must be inherited from the parent despite its bad line.
        let sub_log = session_dir
            .join("subagent")
            .join(SUBAGENT_ID)
            .join(SESSION_FILE);
        write_lines(
            &sub_log,
            &[run_event(1, json!({"kind": "started", "prompt": "search"}))],
        );

        let conv = parse_session(&sub_log).expect("subagent conversation");
        assert_eq!(conv.workspace, Some(PathBuf::from("/data/projects/demo")));
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let temp = TempDir::new().expect("tempdir");
        let log = temp
            .path()
            .join("sessions/2026/08/05/s2")
            .join(SESSION_FILE);
        write_lines(
            &log,
            &[
                "not json at all".to_string(),
                "{\"payload_type\":42}".to_string(), // wrong type
                "{\"no_payload_type\":true,\"payload\":{}}".to_string(),
                run_event(1, json!({"kind": "started", "prompt": "still parses"})),
                run_event(
                    2,
                    json!({"kind": "assistant_message_committed", "text": "yes"}),
                ),
            ],
        );
        let conv = parse_session(&log).expect("conversation despite noise");
        assert_eq!(conv.messages.len(), 2);
    }

    #[test]
    fn telemetry_only_transcript_yields_nothing() {
        let temp = TempDir::new().expect("tempdir");
        let log = temp
            .path()
            .join("sessions/2026/08/05/s3")
            .join(SESSION_FILE);
        write_lines(
            &log,
            &[
                envelope(
                    1,
                    "runtime.session.metadata",
                    &json!({"record": {"workspace_root": "/w"}}),
                ),
                run_event(2, json!({"kind": "resource_usage_sampled", "rss": 1})),
                envelope(3, "session.end", &json!({"reason": "completed"})),
            ],
        );
        assert!(parse_session(&log).is_none());
    }

    #[test]
    fn unparseable_args_string_is_kept_raw() {
        let event = json!({
            "tool_calls": [{"name": "bash", "call_id": "c9", "args": "not{json"}]
        });
        let invs = parse_tool_calls(&event);
        assert_eq!(invs.len(), 1);
        assert_eq!(invs[0].arguments, Some(json!("not{json")));
    }

    #[test]
    fn discovery_covers_scan_sources() {
        let temp = TempDir::new().expect("tempdir");
        build_fixture(temp.path());
        assert_discovery_covers_scan_sources(&MuseConnector::new(), &ctx_for(temp.path()));
    }

    #[test]
    fn discovery_reports_transcripts_as_required_primary_logs() {
        let temp = TempDir::new().expect("tempdir");
        build_fixture(temp.path());
        let sources = MuseConnector::new()
            .discover_source_files(&ctx_for(temp.path()))
            .expect("discovery");
        assert_eq!(sources.len(), 2);
        assert!(sources.iter().all(|s| {
            s.provider_slug == "muse"
                && s.role == DiscoveredSourceRole::PrimarySessionLog
                && s.required_for_reconstruction
        }));
        assert!(
            sources
                .iter()
                .all(|s| s.source_path.file_name().is_some_and(|n| n == SESSION_FILE))
        );
    }

    #[test]
    fn scan_root_may_point_at_single_session_dir_or_file() {
        let temp = TempDir::new().expect("tempdir");
        let (root_log, _) = build_fixture(temp.path());

        // Directly at the transcript file.
        let ctx = ScanContext::with_roots(
            temp.path().to_path_buf(),
            vec![ScanRoot::local(root_log.clone())],
            None,
        );
        let convs = MuseConnector::new().scan(&ctx).expect("scan file root");
        assert_eq!(convs.len(), 1);

        // At the session directory (also picks up its subagent).
        let session_dir = root_log.parent().expect("session dir").to_path_buf();
        let ctx = ScanContext::with_roots(
            temp.path().to_path_buf(),
            vec![ScanRoot::local(session_dir)],
            None,
        );
        let convs = MuseConnector::new().scan(&ctx).expect("scan dir root");
        assert_eq!(convs.len(), 2);
    }
}
