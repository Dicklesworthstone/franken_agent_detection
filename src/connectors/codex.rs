use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::{dedupe_path_key, env_path_nonempty, is_injected_context_message, read_capped};
use super::{
    Connector, extract_invocations_from_content_blocks, flatten_content,
    franken_detection_for_connector, parse_timestamp,
};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
};

pub struct CodexConnector;

const LARGE_SESSION_EXTRA_COMPACT_THRESHOLD_BYTES: u64 = 32 * 1024 * 1024;

enum FileScanMetadata {
    Process(Option<fs::Metadata>),
    Skip,
}

impl Default for CodexConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl CodexConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn is_under_codex_dir(path: &Path) -> bool {
        path.ancestors().any(|ancestor| {
            ancestor
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == ".codex")
        })
    }

    fn append_explicit_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        if base.is_file() {
            roots.push(base.to_path_buf());
            return;
        }

        roots.push(base.to_path_buf());

        if !Self::is_under_codex_dir(base) {
            roots.push(base.join(".codex"));
        }
    }

    fn home() -> PathBuf {
        if let Some(explicit) = env_path_nonempty("CODEX_HOME") {
            return explicit;
        }
        dirs::home_dir().unwrap_or_default().join(".codex")
    }

    fn sessions_dir(home: &Path) -> PathBuf {
        let sessions = home.join("sessions");
        if sessions.exists() {
            sessions
        } else {
            home.to_path_buf()
        }
    }

    fn is_rollout_file(path: &Path) -> bool {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return false;
        };
        if !name.starts_with("rollout-") {
            return false;
        }
        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                ext.eq_ignore_ascii_case("jsonl") || ext.eq_ignore_ascii_case("json")
            })
    }

    fn sessions_dir_for_explicit_file(path: &Path) -> Option<PathBuf> {
        path.ancestors()
            .find(|ancestor| {
                ancestor.file_name().and_then(|name| name.to_str()) == Some("sessions")
            })
            .map(Path::to_path_buf)
    }

    fn rollout_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let sessions = Self::sessions_dir(root);
        if !sessions.exists() {
            return out;
        }
        for entry in WalkDir::new(sessions).into_iter().flatten() {
            if entry.file_type().is_file() {
                let name = entry.file_name().to_str().unwrap_or("");
                // Match both modern .jsonl and legacy .json formats
                if name.starts_with("rollout-")
                    && entry
                        .path()
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| {
                            ext.eq_ignore_ascii_case("jsonl") || ext.eq_ignore_ascii_case("json")
                        })
                {
                    out.push(entry.path().to_path_buf());
                }
            }
        }
        // Keep connector traversal deterministic across filesystems/runs.
        out.sort();
        out
    }

    fn is_token_usage_target_message(message: &NormalizedMessage) -> bool {
        // Attribute token_count usage to concrete assistant turns only.
        // This avoids attaching usage to synthetic reasoning helper
        // messages AND to the synthetic "[Tool: name]" placeholders pushed
        // for function_call items — a token_count following a tool call
        // belongs to the surrounding turn, not the placeholder.
        message.role == "assistant" && message.author.is_none() && message.invocations.is_empty()
    }

    fn token_usage_from_payload(payload: &Value) -> Option<Value> {
        // Modern rollouts (verified against live 2026-01..2026-08 history)
        // nest per-turn usage at `info.last_token_usage`;
        // `info.total_token_usage` is CUMULATIVE across the session and
        // must never be attached per turn (downstream sums would double
        // count). Legacy shapes carried the fields directly on the payload.
        let usage_block = payload
            .pointer("/info/last_token_usage")
            .filter(|block| {
                block.get("input_tokens").is_some() || block.get("output_tokens").is_some()
            })
            .unwrap_or(payload);

        let input_tokens = usage_block.get("input_tokens").and_then(Value::as_i64);
        let output_tokens = usage_block
            .get("output_tokens")
            .and_then(Value::as_i64)
            .or_else(|| usage_block.get("tokens").and_then(Value::as_i64));

        if input_tokens.is_none() && output_tokens.is_none() {
            return None;
        }

        let mut usage = serde_json::Map::new();
        if let Some(input) = input_tokens {
            usage.insert("input_tokens".to_string(), Value::from(input));
        }
        if let Some(output) = output_tokens {
            usage.insert("output_tokens".to_string(), Value::from(output));
        }
        // Codex reports prompt-cache hits as `cached_input_tokens`, a
        // SUBSET of input_tokens, not additive on top of it.
        if let Some(cache_read) = usage_block
            .get("cached_input_tokens")
            .and_then(Value::as_i64)
        {
            usage.insert("cache_read_tokens".to_string(), Value::from(cache_read));
        }
        usage.insert("data_source".to_string(), Value::String("api".to_string()));

        Some(Value::Object(usage))
    }

    fn should_compact_large_message_extra(file_size_bytes: Option<u64>) -> bool {
        file_size_bytes.is_some_and(|size| size >= LARGE_SESSION_EXTRA_COMPACT_THRESHOLD_BYTES)
    }

    fn file_metadata_if_modified(path: &Path, since_ts: Option<i64>) -> FileScanMetadata {
        let Ok(metadata) = fs::metadata(path) else {
            return FileScanMetadata::Process(None);
        };
        if Self::metadata_modified_since(&metadata, since_ts) {
            FileScanMetadata::Process(Some(metadata))
        } else {
            FileScanMetadata::Skip
        }
    }

    fn metadata_modified_since(metadata: &fs::Metadata, since_ts: Option<i64>) -> bool {
        since_ts.is_none_or(|ts| {
            let threshold = ts.saturating_sub(1_000);
            metadata.modified().map_or(true, |modified| {
                modified
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(true, |duration| {
                        i64::try_from(duration.as_millis()).unwrap_or(i64::MAX) >= threshold
                    })
            })
        })
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let is_codex_dir = ctx.data_dir.to_str().is_some_and(|s| {
            s.contains(".codex") || s.ends_with("/codex") || s.ends_with("\\codex")
        }) && ctx.data_dir.join("sessions").exists();

        let mut roots: Vec<ScanRoot> =
            if ctx.use_default_detection() {
                if is_codex_dir {
                    vec![ScanRoot::local(ctx.data_dir.clone())]
                } else {
                    vec![ScanRoot::local(Self::home())]
                }
            } else {
                let mut explicit = Vec::new();
                for scan_root in &ctx.scan_roots {
                    Self::append_explicit_roots(&mut explicit, &scan_root.path);
                }
                explicit
                    .into_iter()
                    .map(|path| {
                        if let Some(root) = ctx.scan_roots.iter().find(|root| {
                            path.starts_with(&root.path) || root.path.starts_with(&path)
                        }) {
                            root.with_path(path)
                        } else {
                            ScanRoot::local(path)
                        }
                    })
                    .collect()
            };

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let roots = Self::source_roots(ctx);
        let mut out = Vec::new();
        let mut seen_files: HashSet<PathBuf> = HashSet::new();

        for root in roots {
            let explicit_file = root
                .path
                .is_file()
                .then_some(root.path.clone())
                .filter(|path| Self::is_rollout_file(path));
            let home = explicit_file
                .as_ref()
                .and_then(|path| path.parent().map(Path::to_path_buf))
                .unwrap_or_else(|| root.path.clone());
            if !home.exists() {
                continue;
            }

            let files = explicit_file
                .clone()
                .map_or_else(|| Self::rollout_files(&home), |path| vec![path]);

            for file in files {
                if !seen_files.insert(dedupe_path_key(&file)) {
                    continue;
                }
                if matches!(
                    Self::file_metadata_if_modified(&file, ctx.since_ts),
                    FileScanMetadata::Skip
                ) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "codex",
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

    fn compact_message_extra(raw: &Value) -> Value {
        let mut cass = serde_json::Map::new();

        if let Some(model) = raw
            .get("model")
            .or_else(|| raw.pointer("/response/model"))
            .and_then(|v| v.as_str())
            .filter(|value| !value.trim().is_empty())
        {
            cass.insert("model".to_string(), Value::String(model.to_string()));
        }

        if let Some(attachments) = raw
            .get("attachment_refs")
            .or_else(|| raw.get("attachments"))
            .cloned()
        {
            cass.insert("attachments".to_string(), attachments);
        }

        if cass.is_empty() {
            Value::Object(serde_json::Map::new())
        } else {
            let mut out = serde_json::Map::new();
            out.insert("cass".to_string(), Value::Object(cass));
            Value::Object(out)
        }
    }

    fn attach_token_usage_to_latest_assistant(
        messages: &mut [NormalizedMessage],
        token_usage: Value,
        source_path: &Path,
        line_number: usize,
    ) {
        if let Some(target) = messages
            .iter_mut()
            .rev()
            .find(|m| Self::is_token_usage_target_message(m))
        {
            if !target.extra.is_object() {
                target.extra = Value::Object(serde_json::Map::new());
            }

            if let Some(extra) = target.extra.as_object_mut() {
                let cass = extra
                    .entry("cass".to_string())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));

                if !cass.is_object() {
                    *cass = Value::Object(serde_json::Map::new());
                }

                if let Some(cass_obj) = cass.as_object_mut() {
                    // Multiple token_count events for the same assistant turn:
                    // deterministic rule = last write wins.
                    cass_obj.insert("token_usage".to_string(), token_usage);
                }
            }
        } else {
            tracing::debug!(
                path = %source_path.display(),
                line_number,
                "codex token_count event had no preceding assistant message; skipping"
            );
        }
    }
}

fn update_time_bounds(started_at: &mut Option<i64>, ended_at: &mut Option<i64>, ts: Option<i64>) {
    if let Some(ts) = ts {
        *started_at = Some(started_at.map_or(ts, |curr| curr.min(ts)));
        *ended_at = Some(ended_at.map_or(ts, |curr| curr.max(ts)));
    }
}

/// Parse the arguments of a modern Codex `response_item` tool call.
///
/// `function_call` payloads carry `arguments` as a JSON-encoded string (e.g.
/// `"{\"cmd\":\"ls\"}"`); `custom_tool_call` payloads (e.g. `apply_patch`) carry
/// freeform `input`. Returns the decoded JSON when the string parses, otherwise
/// the raw string, so downstream consumers never lose the original payload.
fn parse_tool_call_arguments(payload: &Value) -> Option<Value> {
    let raw = payload.get("arguments").or_else(|| payload.get("input"))?;
    match raw {
        Value::String(s) if !s.is_empty() => {
            Some(serde_json::from_str::<Value>(s).unwrap_or_else(|_| Value::String(s.clone())))
        }
        other => Some(other.clone()),
    }
}

/// Extract the textual output of a modern Codex `response_item` tool result.
///
/// `output` is almost always a plain string, but the Responses API can also
/// nest it as `{"content":[{"text":...}]}`; handle both shapes and fall back to
/// flattening so structured results still surface as searchable text.
fn tool_output_text(payload: &Value) -> String {
    let Some(output) = payload.get("output") else {
        return String::new();
    };
    if let Some(text) = output.as_str() {
        return text.to_string();
    }
    if let Some(content) = output.get("content") {
        let flattened = flatten_content(content);
        if !flattened.trim().is_empty() {
            return flattened;
        }
    }
    flatten_content(output)
}

#[allow(clippy::too_many_lines)]
fn scan_codex_with_callback(
    ctx: &ScanContext,
    on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
) -> Result<()> {
    let roots: Vec<PathBuf> = CodexConnector::source_roots(ctx)
        .into_iter()
        .map(|root| root.path)
        .collect();

    if roots.is_empty() {
        return Ok(());
    }

    let mut seen_files: HashSet<PathBuf> = HashSet::new();

    for root in roots {
        let explicit_file = root
            .is_file()
            .then_some(root.clone())
            .filter(|path| CodexConnector::is_rollout_file(path));
        let home = explicit_file
            .as_ref()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| root.clone());
        if !home.exists() {
            continue;
        }

        let files = explicit_file
            .clone()
            .map_or_else(|| CodexConnector::rollout_files(&home), |path| vec![path]);
        let sessions_dir = explicit_file
            .as_ref()
            .and_then(|path| CodexConnector::sessions_dir_for_explicit_file(path))
            .unwrap_or_else(|| CodexConnector::sessions_dir(&home));

        for file in files {
            if !seen_files.insert(dedupe_path_key(&file)) {
                continue;
            }
            let source_path = file.clone();
            let file_metadata = match CodexConnector::file_metadata_if_modified(&file, ctx.since_ts)
            {
                FileScanMetadata::Process(metadata) => metadata,
                FileScanMetadata::Skip => continue,
            };
            let file_size_bytes = file_metadata.as_ref().map(std::fs::Metadata::len);
            let compact_message_extra =
                CodexConnector::should_compact_large_message_extra(file_size_bytes);
            if compact_message_extra {
                tracing::debug!(
                    path = %file.display(),
                    size_bytes = file_size_bytes.unwrap_or_default(),
                    "codex compacting per-message extra payloads for large session"
                );
            }
            let external_id = source_path
                .strip_prefix(&sessions_dir)
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
            let ext = file.extension().and_then(|e| e.to_str());
            let mut messages = Vec::new();
            let mut started_at = None;
            let mut ended_at = None;
            let mut session_cwd: Option<PathBuf> = None;
            // Dual-stream-era rollouts (Jan–Jun 2026) record every user
            // prompt TWICE: once as event_msg/user_message and once as a
            // response_item role=user (verified in 33/61 sampled files).
            // Track both streams so the post-pass can drop the
            // event_msg copy when the same text arrived via response_item.
            let mut event_msg_user_idx: Vec<usize> = Vec::new();
            let mut response_item_user_texts: HashSet<String> = HashSet::new();

            if ext == Some("jsonl") {
                let f = std::fs::File::open(&file)
                    .with_context(|| format!("open rollout {}", file.display()))?;
                let reader = std::io::BufReader::new(f);

                for (line_idx, line_res) in std::io::BufRead::lines(reader).enumerate() {
                    let Ok(line) = line_res else {
                        continue;
                    };
                    if line.trim().is_empty() {
                        continue;
                    }
                    // A UTF-8 BOM on the first line would otherwise silently
                    // drop that record (often session_meta or the first
                    // prompt); gemini's replay strips it for the same reason.
                    let line = line.trim_start_matches('\u{feff}');
                    let Ok(val) = serde_json::from_str::<Value>(line) else {
                        continue;
                    };

                    let entry_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let created = val.get("timestamp").and_then(parse_timestamp);

                    match entry_type {
                        "session_meta" => {
                            if let Some(payload) = val.get("payload") {
                                session_cwd = payload
                                    .get("cwd")
                                    .and_then(|v| v.as_str())
                                    .map(PathBuf::from);
                            }
                            update_time_bounds(&mut started_at, &mut ended_at, created);
                        }
                        "response_item" => {
                            if let Some(payload) = val.get("payload") {
                                let payload_type = payload.get("type").and_then(|v| v.as_str());

                                match payload_type {
                                    // Modern Codex encodes tool calls as
                                    // `response_item` entries rather than
                                    // `event_msg`/`tool_call`. `function_call`
                                    // is a structured tool (e.g. `exec_command`);
                                    // `custom_tool_call` is a freeform tool
                                    // (e.g. `apply_patch`). Both lack a `content`
                                    // field, so without explicit handling they
                                    // flatten to empty and get dropped.
                                    Some("function_call" | "custom_tool_call") => {
                                        let tool_name = payload
                                            .get("name")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("unknown")
                                            .to_string();
                                        let arguments = parse_tool_call_arguments(payload);
                                        let call_id = payload
                                            .get("call_id")
                                            .or_else(|| payload.get("id"))
                                            .and_then(|v| v.as_str())
                                            .map(String::from);

                                        let content_text = format!("[Tool: {tool_name}]");
                                        update_time_bounds(&mut started_at, &mut ended_at, created);
                                        messages.push(NormalizedMessage {
                                            idx: 0,
                                            role: "assistant".to_string(),
                                            author: None,
                                            created_at: created,
                                            content: content_text,
                                            extra: if compact_message_extra {
                                                CodexConnector::compact_message_extra(&val)
                                            } else {
                                                val
                                            },
                                            invocations: vec![NormalizedInvocation {
                                                kind: "tool".to_string(),
                                                name: tool_name,
                                                raw_name: None,
                                                call_id,
                                                arguments,
                                            }],
                                            snippets: Vec::new(),
                                        });
                                    }
                                    // Tool results: `output` carries the captured
                                    // stdout / patch summary. Emit as a
                                    // first-class `tool` timeline entry; the
                                    // linking `call_id` is preserved in `extra`.
                                    Some("function_call_output" | "custom_tool_call_output") => {
                                        let output_text = tool_output_text(payload);
                                        if output_text.trim().is_empty() {
                                            continue;
                                        }
                                        update_time_bounds(&mut started_at, &mut ended_at, created);
                                        messages.push(NormalizedMessage {
                                            idx: 0,
                                            role: "tool".to_string(),
                                            author: None,
                                            created_at: created,
                                            content: output_text,
                                            extra: if compact_message_extra {
                                                CodexConnector::compact_message_extra(&val)
                                            } else {
                                                val
                                            },
                                            invocations: Vec::new(),
                                            snippets: Vec::new(),
                                        });
                                    }
                                    // Plain messages: assistant `output_text`,
                                    // user/developer `input_text`, or legacy
                                    // string content. Encrypted `reasoning`
                                    // items have no plaintext content and are
                                    // intentionally skipped here (plaintext
                                    // reasoning arrives via `event_msg`).
                                    _ => {
                                        let role = payload
                                            .get("role")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("agent");

                                        let content_str = payload
                                            .get("content")
                                            .map(flatten_content)
                                            .unwrap_or_default();

                                        if content_str.trim().is_empty() {
                                            continue;
                                        }

                                        update_time_bounds(&mut started_at, &mut ended_at, created);
                                        if role == "user" {
                                            response_item_user_texts
                                                .insert(content_str.trim().to_string());
                                        }
                                        let invocations = payload.get("content").map_or_else(
                                            Vec::new,
                                            extract_invocations_from_content_blocks,
                                        );

                                        messages.push(NormalizedMessage {
                                            idx: 0,
                                            role: role.to_string(),
                                            author: None,
                                            created_at: created,
                                            content: content_str,
                                            extra: if compact_message_extra {
                                                CodexConnector::compact_message_extra(&val)
                                            } else {
                                                val
                                            },
                                            invocations,
                                            snippets: Vec::new(),
                                        });
                                    }
                                }
                            }
                        }
                        "event_msg" => {
                            if let Some(payload) = val.get("payload") {
                                let event_type = payload.get("type").and_then(|v| v.as_str());

                                match event_type {
                                    Some("user_message") => {
                                        let text = payload
                                            .get("message")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("");
                                        if !text.is_empty() {
                                            update_time_bounds(
                                                &mut started_at,
                                                &mut ended_at,
                                                created,
                                            );
                                            messages.push(NormalizedMessage {
                                                idx: 0,
                                                role: "user".to_string(),
                                                author: None,
                                                created_at: created,
                                                content: text.to_string(),
                                                extra: if compact_message_extra {
                                                    CodexConnector::compact_message_extra(&val)
                                                } else {
                                                    val
                                                },
                                                invocations: Vec::new(),
                                                snippets: Vec::new(),
                                            });
                                            event_msg_user_idx.push(messages.len() - 1);
                                        }
                                    }
                                    Some("agent_reasoning") => {
                                        let text = payload
                                            .get("text")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("");
                                        if !text.is_empty() {
                                            update_time_bounds(
                                                &mut started_at,
                                                &mut ended_at,
                                                created,
                                            );
                                            messages.push(NormalizedMessage {
                                                idx: 0,
                                                role: "assistant".to_string(),
                                                author: Some("reasoning".to_string()),
                                                created_at: created,
                                                content: text.to_string(),
                                                extra: if compact_message_extra {
                                                    CodexConnector::compact_message_extra(&val)
                                                } else {
                                                    val
                                                },
                                                invocations: Vec::new(),
                                                snippets: Vec::new(),
                                            });
                                        }
                                    }
                                    Some("tool_call") => {
                                        // Codex event_msg/tool_call events carry structured
                                        // tool data that should produce invocations.
                                        let tool_name = payload
                                            .get("name")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("unknown")
                                            .to_string();
                                        let arguments = payload
                                            .get("input")
                                            .or_else(|| payload.get("arguments"))
                                            .cloned();
                                        let call_id = payload
                                            .get("call_id")
                                            .or_else(|| payload.get("id"))
                                            .and_then(|v| v.as_str())
                                            .map(String::from);

                                        let content_text = format!("[Tool: {tool_name}]");
                                        update_time_bounds(&mut started_at, &mut ended_at, created);
                                        messages.push(NormalizedMessage {
                                            idx: 0,
                                            role: "assistant".to_string(),
                                            author: None,
                                            created_at: created,
                                            content: content_text,
                                            extra: if compact_message_extra {
                                                CodexConnector::compact_message_extra(&val)
                                            } else {
                                                val
                                            },
                                            invocations: vec![NormalizedInvocation {
                                                kind: "tool".to_string(),
                                                name: tool_name,
                                                raw_name: None,
                                                call_id,
                                                arguments,
                                            }],
                                            snippets: Vec::new(),
                                        });
                                    }
                                    Some("token_count") => {
                                        if let Some(token_usage) =
                                            CodexConnector::token_usage_from_payload(payload)
                                        {
                                            CodexConnector::attach_token_usage_to_latest_assistant(
                                                &mut messages,
                                                token_usage,
                                                &source_path,
                                                line_idx + 1,
                                            );
                                        } else {
                                            tracing::debug!(
                                                path = %source_path.display(),
                                                line_number = line_idx + 1,
                                                "codex token_count event missing token fields; skipping"
                                            );
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                // Drop event_msg copies of user prompts that the
                // response_item stream already recorded (dual-stream era).
                if !event_msg_user_idx.is_empty() && !response_item_user_texts.is_empty() {
                    let dropped: HashSet<usize> = event_msg_user_idx
                        .iter()
                        .filter(|&&idx| {
                            messages.get(idx).is_some_and(|m| {
                                response_item_user_texts.contains(m.content.trim())
                            })
                        })
                        .copied()
                        .collect();
                    if !dropped.is_empty() {
                        let mut kept: Vec<NormalizedMessage> = Vec::with_capacity(messages.len());
                        for (idx, message) in messages.into_iter().enumerate() {
                            if !dropped.contains(&idx) {
                                kept.push(message);
                            }
                        }
                        messages = kept;
                    }
                }
                crate::types::reindex_messages(&mut messages);
            } else if ext == Some("json") {
                // Legacy single-file rollouts can be huge; enforce the
                // project's 100MB scan cap (chatgpt policy).
                let content = match read_capped(&file) {
                    Ok(Some(content)) => content,
                    Ok(None) => {
                        tracing::warn!(
                            file = %file.display(),
                            "codex: legacy rollout exceeds the scan size cap; skipping"
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(file = %file.display(), error = %e, "codex: unreadable legacy rollout");
                        continue;
                    }
                };
                let content = content.trim_start_matches('\u{feff}');
                let val: Value = match serde_json::from_str(content) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                session_cwd = val
                    .get("session")
                    .and_then(|s| s.get("cwd"))
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from);

                if let Some(items) = val.get("items").and_then(|v| v.as_array()) {
                    for item in items {
                        let role = item.get("role").and_then(|v| v.as_str()).unwrap_or("agent");
                        let content_str =
                            item.get("content").map(flatten_content).unwrap_or_default();

                        if content_str.trim().is_empty() {
                            continue;
                        }

                        let created = item.get("timestamp").and_then(parse_timestamp);
                        update_time_bounds(&mut started_at, &mut ended_at, created);

                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: role.to_string(),
                            author: None,
                            created_at: created,
                            content: content_str,
                            extra: if compact_message_extra {
                                CodexConnector::compact_message_extra(item)
                            } else {
                                item.clone()
                            },
                            invocations: item
                                .get("content")
                                .map_or_else(Vec::new, extract_invocations_from_content_blocks),
                            snippets: Vec::new(),
                        });
                    }
                }
                crate::types::reindex_messages(&mut messages);
            }

            if messages.is_empty() {
                continue;
            }

            let title = messages
                .iter()
                .find(|m| m.role == "user" && !is_injected_context_message(&m.content))
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
                    messages
                        .first()
                        .and_then(|m| m.content.lines().next())
                        .map(|s| s.chars().take(100).collect())
                });

            on_conversation(NormalizedConversation {
                agent_slug: "codex".to_string(),
                external_id,
                title,
                workspace: session_cwd,
                source_path: source_path.clone(),
                started_at,
                ended_at,
                metadata: serde_json::json!({"source": if ext == Some("json") { "rollout_json" } else { "rollout" }}),
                messages,
            })?;
        }
    }

    Ok(())
}

impl Connector for CodexConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("codex").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        scan_codex_with_callback(ctx, &mut |conv| {
            convs.push(conv);
            Ok(())
        })?;
        Ok(convs)
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        scan_codex_with_callback(ctx, on_conversation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use serde_json::json;
    use std::fs;
    use std::time::Instant;
    use tempfile::TempDir;

    // =====================================================
    // Constructor Tests
    // =====================================================

    #[test]
    fn new_creates_connector() {
        let connector = CodexConnector::new();
        // Just verify it doesn't panic - struct has no fields
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = CodexConnector;
        let _ = connector;
    }

    // =====================================================
    // home() Tests
    // =====================================================

    #[test]
    fn home_returns_path_ending_with_codex() {
        // Note: We can't reliably test CODEX_HOME env var due to parallel test execution.
        // Testing that home() returns a valid path structure is sufficient.
        // The function uses CODEX_HOME if set, otherwise defaults to ~/.codex
        let home = CodexConnector::home();
        // Either the env var is set (ends with some path) or default (ends with .codex)
        let path_str = home.to_str().unwrap();
        let has_codex_dir = home
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.eq_ignore_ascii_case(".codex") || name.eq_ignore_ascii_case("codex")
            });
        assert!(
            has_codex_dir || path_str.to_ascii_lowercase().contains("codex"),
            "home() should return a path related to codex, got: {}",
            path_str
        );
    }

    // =====================================================
    // rollout_files() Tests
    // =====================================================

    #[test]
    fn rollout_files_finds_jsonl_files() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let rollout = sessions.join("rollout-abc123.jsonl");
        fs::write(&rollout, "{}").unwrap();

        let files = CodexConnector::rollout_files(dir.path());
        assert_eq!(files.len(), 1);
        assert!(files[0].to_str().unwrap().contains("rollout-abc123.jsonl"));
    }

    #[test]
    fn rollout_files_finds_json_files() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let rollout = sessions.join("rollout-legacy.json");
        fs::write(&rollout, "{}").unwrap();

        let files = CodexConnector::rollout_files(dir.path());
        assert_eq!(files.len(), 1);
        assert!(files[0].to_str().unwrap().contains("rollout-legacy.json"));
    }

    #[test]
    fn rollout_files_ignores_non_rollout_files() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Create various non-rollout files
        fs::write(sessions.join("config.json"), "{}").unwrap();
        fs::write(sessions.join("session.jsonl"), "{}").unwrap();
        fs::write(sessions.join("other.txt"), "test").unwrap();

        let files = CodexConnector::rollout_files(dir.path());
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn scan_with_explicit_home_root_finds_codex_sessions() {
        let dir = TempDir::new().unwrap();
        let home = dir.path().join("home");
        let sessions = home.join(".codex").join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"Hello Codex"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"assistant","content":"Hi there!"}}
"#;
        let rollout = sessions.join("rollout-home.jsonl");
        fs::write(&rollout, content).unwrap();

        let connector = CodexConnector::new();
        let ctx =
            ScanContext::with_roots(dir.path().join("cass"), vec![ScanRoot::local(home)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].content, "Hello Codex");
        assert_eq!(convs[0].messages[1].content, "Hi there!");
    }

    #[test]
    fn title_skips_injected_context_user_records() {
        let dir = TempDir::new().unwrap();
        let home = dir.path().join("home");
        let sessions = home.join(".codex").join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r##"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"# AGENTS.md instructions for /data/projects/demo\nBe helpful."}}
{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"user","content":"Fix the flaky test"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:02Z","payload":{"role":"assistant","content":"On it."}}
"##;
        fs::write(sessions.join("rollout-title.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx =
            ScanContext::with_roots(dir.path().join("cass"), vec![ScanRoot::local(home)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].title.as_deref(), Some("Fix the flaky test"));
    }

    #[test]
    fn dual_stream_user_prompts_are_deduplicated() {
        let dir = TempDir::new().unwrap();
        let home = dir.path().join("home");
        let sessions = home.join(".codex").join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Dual-stream era: the same prompt arrives via BOTH streams.
        let content = r#"{"type":"event_msg","timestamp":"2025-12-01T10:00:00Z","payload":{"type":"user_message","message":"First read ALL of the AGENTS.md file"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"user","content":"First read ALL of the AGENTS.md file"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:02Z","payload":{"role":"assistant","content":"Reading it now."}}
"#;
        fs::write(sessions.join("rollout-dual.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx =
            ScanContext::with_roots(dir.path().join("cass"), vec![ScanRoot::local(home)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        let user_texts: Vec<&str> = convs[0]
            .messages
            .iter()
            .filter(|m| m.role == "user")
            .map(|m| m.content.as_str())
            .collect();
        assert_eq!(
            user_texts,
            vec!["First read ALL of the AGENTS.md file"],
            "the event_msg copy of a response_item user prompt must be suppressed"
        );
    }

    #[test]
    fn token_count_reads_nested_last_token_usage() {
        let dir = TempDir::new().unwrap();
        let home = dir.path().join("home");
        let sessions = home.join(".codex").join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Real payload shape (sampled live 2026-06): usage nested under
        // info.last_token_usage, NOT flat on the payload.
        let usage_line = r#"{"timestamp":"2026-06-14T02:46:39.992Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":42187,"cached_input_tokens":5504,"output_tokens":733,"reasoning_output_tokens":516,"total_tokens":42920},"last_token_usage":{"input_tokens":42187,"cached_input_tokens":5504,"output_tokens":733,"reasoning_output_tokens":516,"total_tokens":42920}}}}"#;
        let content = format!(
            "{}\n{}\n{}\n{}\n",
            r#"{"type":"response_item","timestamp":"2026-06-14T02:45:00.000Z","payload":{"role":"assistant","content":"Working on it."}}"#,
            usage_line,
            r#"{"type":"response_item","timestamp":"2026-06-14T02:47:00.000Z","payload":{"role":"assistant","content":"Done."}}"#,
            usage_line.replace("\"input_tokens\":42187", "\"input_tokens\":500")
        );
        fs::write(sessions.join("rollout-tokens.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx =
            ScanContext::with_roots(dir.path().join("cass"), vec![ScanRoot::local(home)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        let with_usage: Vec<&Value> = convs[0]
            .messages
            .iter()
            .filter(|m| m.extra.pointer("/cass/token_usage/input_tokens").is_some())
            .map(|m| &m.extra)
            .collect();
        assert_eq!(with_usage.len(), 2, "each turn carries its own usage");
        let first = with_usage[0]
            .pointer("/cass/token_usage/input_tokens")
            .and_then(Value::as_i64);
        let second = with_usage[1]
            .pointer("/cass/token_usage/input_tokens")
            .and_then(Value::as_i64);
        assert_eq!(first, Some(42_187));
        assert_eq!(second, Some(500));
    }

    #[test]
    fn rollout_files_finds_nested_rollouts() {
        let dir = TempDir::new().unwrap();
        let nested = dir
            .path()
            .join("sessions")
            .join("2025")
            .join("12")
            .join("17");
        fs::create_dir_all(&nested).unwrap();

        let rollout = nested.join("rollout-nested.jsonl");
        fs::write(&rollout, "{}").unwrap();

        let files = CodexConnector::rollout_files(dir.path());
        assert_eq!(files.len(), 1);
        assert!(files[0].to_str().unwrap().contains("rollout-nested.jsonl"));
    }

    #[test]
    fn rollout_files_returns_sorted_order() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        fs::write(sessions.join("rollout-z.jsonl"), "{}").unwrap();
        fs::write(sessions.join("rollout-a.jsonl"), "{}").unwrap();

        let files = CodexConnector::rollout_files(dir.path());
        assert_eq!(files.len(), 2);

        let names: Vec<_> = files
            .iter()
            .map(|p| {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        assert_eq!(names, vec!["rollout-a.jsonl", "rollout-z.jsonl"]);
    }

    #[test]
    fn rollout_files_returns_empty_when_no_sessions_dir() {
        let dir = TempDir::new().unwrap();
        let files = CodexConnector::rollout_files(dir.path());
        assert_eq!(files.len(), 0);
    }

    // =====================================================
    // scan() JSONL Format Tests
    // =====================================================

    #[test]
    fn scan_parses_jsonl_response_item_messages() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"Hello Codex"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"assistant","content":"Hello! How can I help?"}}
"#;
        fs::write(sessions.join("rollout-test.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok());
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Codex");
        assert_eq!(convs[0].messages[1].role, "assistant");
    }

    #[test]
    fn scan_parses_modern_response_item_output_text_and_tool_calls() {
        // Regression test for #13: modern Codex rollout files encode assistant
        // text as `output_text` content blocks and encode tool calls/results as
        // `response_item` payloads (`function_call`, `function_call_output`,
        // `custom_tool_call`, `custom_tool_call_output`). None of these were
        // captured before, silently dropping assistant output and tool activity.
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("codex");

        let connector = CodexConnector::new();
        let ctx = ScanContext::with_roots(fixture.clone(), vec![ScanRoot::local(fixture)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1, "fixture is a single rollout");
        let conv = &convs[0];
        assert_eq!(conv.workspace, Some(PathBuf::from("/tmp/demo-project")));

        // user, assistant output_text, function_call, function_call_output,
        // custom_tool_call, custom_tool_call_output = 6 messages. The encrypted
        // reasoning item carries no plaintext content and is skipped.
        assert_eq!(
            conv.messages.len(),
            6,
            "all modern shapes captured (encrypted reasoning skipped): {:#?}",
            conv.messages
                .iter()
                .map(|m| (m.role.clone(), m.content.clone()))
                .collect::<Vec<_>>()
        );

        // Assistant `output_text` is no longer dropped.
        let assistant = conv
            .messages
            .iter()
            .find(|m| {
                m.role == "assistant"
                    && m.content == "I will inspect the files and then apply a patch."
            })
            .expect("assistant output_text message captured");
        assert!(assistant.invocations.is_empty());

        // `function_call` -> tool invocation with JSON-string arguments parsed.
        let exec = conv
            .messages
            .iter()
            .find(|m| m.invocations.iter().any(|i| i.name == "exec_command"))
            .expect("exec_command function_call captured");
        let exec_inv = &exec.invocations[0];
        assert_eq!(exec_inv.kind, "tool");
        assert_eq!(exec_inv.call_id.as_deref(), Some("call_1"));
        assert_eq!(
            exec_inv
                .arguments
                .as_ref()
                .and_then(|a| a.get("cmd"))
                .and_then(|v| v.as_str()),
            Some("ls"),
            "JSON-string arguments are decoded into structured JSON"
        );

        // `function_call_output` -> tool result, linkable via call_id in extra.
        let exec_out = conv
            .messages
            .iter()
            .find(|m| m.role == "tool" && m.content.contains("README.md"))
            .expect("function_call_output captured as tool result");
        assert_eq!(
            exec_out
                .extra
                .pointer("/payload/call_id")
                .and_then(|v| v.as_str()),
            Some("call_1"),
            "tool result remains linkable to its originating call"
        );

        // `custom_tool_call` (apply_patch) -> tool invocation; freeform input kept.
        let patch = conv
            .messages
            .iter()
            .find(|m| m.invocations.iter().any(|i| i.name == "apply_patch"))
            .expect("apply_patch custom_tool_call captured");
        let patch_inv = &patch.invocations[0];
        assert_eq!(patch_inv.call_id.as_deref(), Some("call_2"));
        assert!(
            patch_inv
                .arguments
                .as_ref()
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.contains("Begin Patch")),
            "non-JSON tool input is retained as a raw string"
        );

        // `custom_tool_call_output` -> tool result message.
        assert!(
            conv.messages
                .iter()
                .any(|m| m.role == "tool" && m.content.contains("A hello.txt")),
            "custom_tool_call_output captured as tool result"
        );
    }

    #[test]
    fn scan_with_callback_matches_scan_for_jsonl_rollout() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"Hello Codex"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"assistant","content":"Hello! How can I help?"}}
"#;
        fs::write(sessions.join("rollout-stream.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let scanned = connector.scan(&ctx).unwrap();
        let mut streamed = Vec::new();
        connector
            .scan_with_callback(&ctx, &mut |conversation| {
                streamed.push(conversation);
                Ok(())
            })
            .unwrap();

        assert_eq!(streamed.len(), scanned.len());
        assert_eq!(streamed[0].messages.len(), scanned[0].messages.len());
        assert_eq!(
            streamed[0].messages[0].content,
            scanned[0].messages[0].content
        );
        assert_eq!(
            streamed[0].messages[1].content,
            scanned[0].messages[1].content
        );
    }

    #[test]
    fn discover_source_files_matches_scanned_rollout_sources() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"Hello Codex"}}"#;
        let rollout = sessions.join("rollout-discovery.jsonl");
        fs::write(&rollout, content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir, None);
        let discovered = connector.discover_source_files(&ctx).unwrap();
        let scanned = connector.scan(&ctx).unwrap();

        assert_eq!(scanned.len(), 1);
        assert_eq!(
            discovered
                .iter()
                .map(|source| source.source_path.clone())
                .collect::<Vec<_>>(),
            vec![scanned[0].source_path.clone()]
        );
        assert_eq!(discovered[0].role, DiscoveredSourceRole::PrimarySessionLog);
        assert!(discovered[0].required_for_reconstruction);
        assert_eq!(discovered[0].provider_slug, "codex");
        assert_eq!(discovered[0].source_path, rollout);
    }

    #[test]
    fn scan_with_explicit_rollout_file_only_reads_that_file_and_keeps_relative_external_id() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir
            .join("sessions")
            .join("2025")
            .join("12")
            .join("18");
        fs::create_dir_all(&sessions).unwrap();

        let first = sessions.join("rollout-one.jsonl");
        let second = sessions.join("rollout-two.jsonl");
        fs::write(
            &first,
            r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"first only"}}"#,
        )
        .unwrap();
        fs::write(
            &second,
            r#"{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"user","content":"second only"}}"#,
        )
        .unwrap();

        let connector = CodexConnector::new();
        let ctx =
            ScanContext::with_roots(first.clone(), vec![ScanRoot::local(first.clone())], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "first only");
        assert_eq!(
            convs[0].external_id.as_deref(),
            Some("2025/12/18/rollout-one")
        );
        assert_eq!(convs[0].source_path, first);
    }

    #[test]
    #[ignore = "release-mode performance harness; run explicitly for Codex scan wall-clock evidence"]
    fn perf_scan_large_codex_fixture() {
        let file_count = std::env::var("FAD_CODEX_SCAN_BENCH_FILES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(2_000);
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");

        for i in 0..file_count {
            let day_dir = sessions
                .join("2026")
                .join("05")
                .join(format!("{:02}", (i % 28) + 1));
            fs::create_dir_all(&day_dir).unwrap();
            let ts = 1_746_265_600_000_u64 + u64::try_from(i).unwrap();
            fs::write(
                day_dir.join(format!("rollout-{i:06}.jsonl")),
                format!(
                    r#"{{"type":"event_msg","timestamp":{ts},"payload":{{"type":"user_message","message":"bench user {i}"}}}}
{{"type":"response_item","timestamp":{},"payload":{{"role":"assistant","content":"bench assistant {i}"}}}}
"#,
                    ts + 1
                ),
            )
            .unwrap();
        }

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir, None);
        let start = Instant::now();
        let convs = connector.scan(&ctx).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(convs.len(), file_count);
        eprintln!(
            "fad_codex_scan_large_fixture files={} elapsed_ms={} ns_per_file={}",
            file_count,
            elapsed.as_millis(),
            elapsed.as_nanos() / u128::try_from(file_count).unwrap()
        );
    }

    #[test]
    fn compact_message_extra_keeps_only_cass_metadata() {
        let raw = json!({
            "model": "gpt-5-codex",
            "attachments": [{"path": "/tmp/screenshot.png"}],
            "payload": {
                "content": "very large duplicated content"
            }
        });

        let compact = CodexConnector::compact_message_extra(&raw);
        assert_eq!(compact["cass"]["model"], "gpt-5-codex");
        assert_eq!(
            compact["cass"]["attachments"][0]["path"],
            "/tmp/screenshot.png"
        );
        assert!(compact.get("payload").is_none());
    }

    #[test]
    fn should_compact_large_message_extra_respects_threshold() {
        assert!(!CodexConnector::should_compact_large_message_extra(Some(
            LARGE_SESSION_EXTRA_COMPACT_THRESHOLD_BYTES - 1,
        )));
        assert!(CodexConnector::should_compact_large_message_extra(Some(
            LARGE_SESSION_EXTRA_COMPACT_THRESHOLD_BYTES,
        )));
        assert!(!CodexConnector::should_compact_large_message_extra(None));
    }

    #[test]
    fn file_metadata_if_modified_preserves_scan_fallbacks() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("rollout-meta.jsonl");
        fs::write(&file, "{}").unwrap();

        assert!(matches!(
            CodexConnector::file_metadata_if_modified(&file, None),
            FileScanMetadata::Process(Some(_))
        ));
        assert!(
            matches!(
                CodexConnector::file_metadata_if_modified(&file, Some(i64::MAX)),
                FileScanMetadata::Skip
            ),
            "future since_ts should skip older files"
        );

        let missing = dir.path().join("missing.jsonl");
        assert!(matches!(
            CodexConnector::file_metadata_if_modified(&missing, Some(i64::MAX)),
            FileScanMetadata::Process(None)
        ));
    }

    #[test]
    fn scan_parses_event_msg_user_message() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"event_msg","timestamp":"2025-12-01T10:00:00Z","payload":{"type":"user_message","message":"User typed this"}}
"#;
        fs::write(sessions.join("rollout-user.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "User typed this");
        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
    }

    #[test]
    fn scan_parses_event_msg_agent_reasoning() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"event_msg","timestamp":"2025-12-01T10:00:00Z","payload":{"type":"agent_reasoning","text":"Let me think about this..."}}
"#;
        fs::write(sessions.join("rollout-reasoning.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].role, "assistant");
        assert_eq!(convs[0].messages[0].author, Some("reasoning".to_string()));
        assert_eq!(convs[0].messages[0].content, "Let me think about this...");
        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
    }

    #[test]
    fn scan_extracts_workspace_from_session_meta() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"session_meta","timestamp":"2025-12-01T10:00:00Z","payload":{"cwd":"/home/user/project"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"user","content":"Test"}}
"#;
        fs::write(sessions.join("rollout-meta.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/project"))
        );
    }

    #[test]
    fn scan_skips_empty_lines_in_jsonl() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"Message 1"}}

{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"user","content":"Message 2"}}
"#;
        fs::write(sessions.join("rollout-empty-lines.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn scan_skips_invalid_json_lines() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"Valid"}}
not valid json at all
{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"user","content":"Also valid"}}
"#;
        fs::write(sessions.join("rollout-invalid.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn scan_skips_empty_content_messages() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"Has content"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"assistant","content":""}}
{"type":"response_item","timestamp":"2025-12-01T10:00:02Z","payload":{"role":"assistant","content":"   "}}
"#;
        fs::write(sessions.join("rollout-empty-content.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        // Only the message with actual content should be included
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Has content");
    }

    #[test]
    fn scan_skips_unknown_event_types() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"Real message"}}
{"type":"event_msg","timestamp":"2025-12-01T10:00:01Z","payload":{"type":"token_count","tokens":100}}
{"type":"event_msg","timestamp":"2025-12-01T10:00:02Z","payload":{"type":"turn_aborted"}}
{"type":"turn_context","timestamp":"2025-12-01T10:00:03Z","payload":{}}
"#;
        fs::write(sessions.join("rollout-unknown.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        // Only the response_item should be included
        assert_eq!(convs[0].messages.len(), 1);
    }

    #[test]
    fn scan_assigns_sequential_indices() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"First"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"assistant","content":"Second"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:02Z","payload":{"role":"user","content":"Third"}}
"#;
        fs::write(sessions.join("rollout-idx.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].idx, 0);
        assert_eq!(convs[0].messages[1].idx, 1);
        assert_eq!(convs[0].messages[2].idx, 2);
    }

    #[test]
    fn scan_attaches_token_count_to_nearest_preceding_assistant() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"Question"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"assistant","content":"First answer"}}
{"type":"event_msg","timestamp":"2025-12-01T10:00:02Z","payload":{"type":"token_count","input_tokens":10,"output_tokens":20}}
{"type":"response_item","timestamp":"2025-12-01T10:00:03Z","payload":{"role":"assistant","content":"Second answer"}}
{"type":"event_msg","timestamp":"2025-12-01T10:00:04Z","payload":{"type":"token_count","input_tokens":30,"output_tokens":40}}
"#;
        fs::write(sessions.join("rollout-attach-nearest.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            3,
            "no synthetic token_count messages"
        );

        let first = &convs[0].messages[1];
        assert_eq!(first.content, "First answer");
        assert_eq!(
            first
                .extra
                .pointer("/cass/token_usage/input_tokens")
                .and_then(Value::as_i64),
            Some(10)
        );
        assert_eq!(
            first
                .extra
                .pointer("/cass/token_usage/output_tokens")
                .and_then(Value::as_i64),
            Some(20)
        );

        let second = &convs[0].messages[2];
        assert_eq!(second.content, "Second answer");
        assert_eq!(
            second
                .extra
                .pointer("/cass/token_usage/input_tokens")
                .and_then(Value::as_i64),
            Some(30)
        );
        assert_eq!(
            second
                .extra
                .pointer("/cass/token_usage/output_tokens")
                .and_then(Value::as_i64),
            Some(40)
        );
        assert_eq!(
            second
                .extra
                .pointer("/cass/token_usage/data_source")
                .and_then(|v| v.as_str()),
            Some("api")
        );
    }

    #[test]
    fn scan_ignores_token_count_without_preceding_assistant() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"Question"}}
{"type":"event_msg","timestamp":"2025-12-01T10:00:01Z","payload":{"type":"token_count","input_tokens":11,"output_tokens":22}}
{"type":"response_item","timestamp":"2025-12-01T10:00:02Z","payload":{"role":"assistant","content":"Answer later"}}
"#;
        fs::write(sessions.join("rollout-unmatched-token.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert!(
            convs[0].messages[1]
                .extra
                .pointer("/cass/token_usage")
                .is_none(),
            "token_count before first assistant must not attach to future message"
        );
    }

    #[test]
    fn scan_multiple_token_count_for_one_assistant_prefers_last() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"Question"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:01Z","payload":{"role":"assistant","content":"Answer"}}
{"type":"event_msg","timestamp":"2025-12-01T10:00:02Z","payload":{"type":"token_count","input_tokens":5,"output_tokens":10}}
{"type":"event_msg","timestamp":"2025-12-01T10:00:03Z","payload":{"type":"token_count","input_tokens":7,"output_tokens":14}}
"#;
        fs::write(sessions.join("rollout-token-last-wins.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        let assistant = &convs[0].messages[1];
        assert_eq!(
            assistant
                .extra
                .pointer("/cass/token_usage/input_tokens")
                .and_then(Value::as_i64),
            Some(7)
        );
        assert_eq!(
            assistant
                .extra
                .pointer("/cass/token_usage/output_tokens")
                .and_then(Value::as_i64),
            Some(14)
        );
    }

    // =====================================================
    // scan() Legacy JSON Format Tests
    // =====================================================

    #[test]
    fn scan_parses_legacy_json_format() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = json!({
            "session": {"cwd": "/home/user/legacy"},
            "items": [
                {"role": "user", "content": "Legacy user message", "timestamp": "2025-12-01T10:00:00Z"},
                {"role": "assistant", "content": "Legacy assistant response", "timestamp": "2025-12-01T10:00:01Z"}
            ]
        });
        fs::write(sessions.join("rollout-legacy.json"), content.to_string()).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].workspace, Some(PathBuf::from("/home/user/legacy")));
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Legacy user message");
        assert_eq!(convs[0].messages[1].role, "assistant");
    }

    #[test]
    fn scan_legacy_json_skips_empty_content() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = json!({
            "session": {},
            "items": [
                {"role": "user", "content": "Has content"},
                {"role": "assistant", "content": ""},
                {"role": "assistant", "content": "   "}
            ]
        });
        fs::write(
            sessions.join("rollout-empty-legacy.json"),
            content.to_string(),
        )
        .unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
    }

    #[test]
    fn scan_legacy_json_handles_missing_items() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = json!({"session": {}});
        fs::write(sessions.join("rollout-no-items.json"), content.to_string()).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // No messages = conversation is skipped
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_invalid_legacy_json() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        fs::write(sessions.join("rollout-bad.json"), "not valid json").unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    // =====================================================
    // Title Extraction Tests
    // =====================================================

    #[test]
    fn scan_extracts_title_from_first_user_message() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","payload":{"role":"assistant","content":"I'm an assistant"}}
{"type":"response_item","payload":{"role":"user","content":"This should be the title"}}
"#;
        fs::write(sessions.join("rollout-title.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("This should be the title".to_string()));
    }

    #[test]
    fn scan_truncates_long_titles() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let long_title = "x".repeat(200);
        let content = format!(
            r#"{{"type":"response_item","payload":{{"role":"user","content":"{}"}}}}"#,
            long_title
        );
        fs::write(sessions.join("rollout-long.jsonl"), content + "\n").unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title.as_ref().unwrap().len(), 100);
    }

    #[test]
    fn scan_uses_first_line_for_multiline_title() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","payload":{"role":"user","content":"First line\nSecond line\nThird line"}}
"#;
        fs::write(sessions.join("rollout-multiline.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("First line".to_string()));
    }

    #[test]
    fn scan_falls_back_to_first_message_for_title() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // No user messages, only assistant
        let content = r#"{"type":"response_item","payload":{"role":"assistant","content":"Assistant speaks first"}}
"#;
        fs::write(sessions.join("rollout-assistant-only.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("Assistant speaks first".to_string()));
    }

    // =====================================================
    // External ID Tests
    // =====================================================

    #[test]
    fn scan_uses_relative_path_as_external_id() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir
            .join("sessions")
            .join("2025")
            .join("12")
            .join("17");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","payload":{"role":"user","content":"Test"}}
"#;
        fs::write(sessions.join("rollout-nested-id.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // External ID should be the relative path from sessions dir
        assert!(convs[0].external_id.is_some());
        let ext_id = convs[0].external_id.as_ref().unwrap();
        assert!(ext_id.contains("2025") || ext_id.contains("rollout-nested-id"));
    }

    // =====================================================
    // Metadata Tests
    // =====================================================

    #[test]
    fn scan_sets_metadata_source_for_jsonl() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","payload":{"role":"user","content":"Test"}}
"#;
        fs::write(sessions.join("rollout-meta-jsonl.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["source"], "rollout");
    }

    #[test]
    fn scan_sets_metadata_source_for_json() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = json!({
            "session": {},
            "items": [{"role": "user", "content": "Test"}]
        });
        fs::write(sessions.join("rollout-meta-json.json"), content.to_string()).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["source"], "rollout_json");
    }

    // =====================================================
    // Agent Slug Tests
    // =====================================================

    #[test]
    fn scan_sets_agent_slug_to_codex() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","payload":{"role":"user","content":"Test"}}
"#;
        fs::write(sessions.join("rollout-slug.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].agent_slug, "codex");
    }

    // =====================================================
    // Timestamp Tests
    // =====================================================

    #[test]
    fn scan_parses_timestamps() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"First"}}
{"type":"response_item","timestamp":"2025-12-01T11:00:00Z","payload":{"role":"user","content":"Last"}}
"#;
        fs::write(sessions.join("rollout-ts.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
        assert!(convs[0].messages[0].created_at.is_some());
    }

    #[test]
    fn scan_tracks_timestamp_bounds_for_out_of_order_events() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","timestamp":"2025-12-01T11:00:00Z","payload":{"role":"assistant","content":"Second chronologically"}}
{"type":"response_item","timestamp":"2025-12-01T10:00:00Z","payload":{"role":"user","content":"First chronologically"}}
"#;
        fs::write(sessions.join("rollout-out-of-order.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        let expected_start = conv.messages.iter().filter_map(|m| m.created_at).min();
        let expected_end = conv.messages.iter().filter_map(|m| m.created_at).max();

        assert_eq!(conv.started_at, expected_start);
        assert_eq!(conv.ended_at, expected_end);
        assert!(conv.ended_at >= conv.started_at);
    }

    // =====================================================
    // Edge Cases
    // =====================================================

    #[test]
    fn scan_handles_empty_sessions_dir() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        // No files in sessions directory

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_handles_multiple_rollout_files() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content1 = r#"{"type":"response_item","payload":{"role":"user","content":"Session 1"}}
"#;
        let content2 = r#"{"type":"response_item","payload":{"role":"user","content":"Session 2"}}
"#;
        fs::write(sessions.join("rollout-1.jsonl"), content1).unwrap();
        fs::write(sessions.join("rollout-2.jsonl"), content2).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
    }

    #[test]
    fn scan_skips_conversations_with_no_messages() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Only metadata, no actual messages
        let content = r#"{"type":"session_meta","payload":{"cwd":"/test"}}
{"type":"turn_context","payload":{}}
"#;
        fs::write(sessions.join("rollout-no-msgs.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should be skipped because no actual messages
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_handles_array_content_in_response_item() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Content as array of text blocks (like Claude API format)
        let content = json!({
            "type": "response_item",
            "payload": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Part one."},
                    {"type": "text", "text": " Part two."}
                ]
            }
        });
        fs::write(
            sessions.join("rollout-array.jsonl"),
            content.to_string() + "\n",
        )
        .unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        // flatten_content should combine the parts
        assert!(convs[0].messages[0].content.contains("Part one"));
    }

    #[test]
    fn scan_uses_default_role_when_missing() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // No role specified in payload
        let content = r#"{"type":"response_item","payload":{"content":"No role specified"}}
"#;
        fs::write(sessions.join("rollout-no-role.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        // Default role should be "agent"
        assert_eq!(convs[0].messages[0].role, "agent");
    }

    #[test]
    fn scan_stores_source_path() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = r#"{"type":"response_item","payload":{"role":"user","content":"Test"}}
"#;
        let file_path = sessions.join("rollout-path.jsonl");
        fs::write(&file_path, content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].source_path, file_path);
    }

    // =====================================================
    // Edge case tests — malformed input robustness (br-fiiv)
    // =====================================================

    #[test]
    fn truncated_jsonl_mid_json_returns_partial_results() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // First line valid, second truncated mid-JSON
        let content = b"{\"type\":\"response_item\",\"payload\":{\"role\":\"user\",\"content\":\"Valid\"}}\n{\"type\":\"response_item\",\"payload\":{\"role\":\"assistant\",\"con";
        fs::write(sessions.join("rollout-truncated.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "truncated file should not cause an error");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            1,
            "should yield only the 1 valid message from truncated file"
        );
        assert_eq!(convs[0].messages[0].content, "Valid");
    }

    #[test]
    fn truncated_mid_utf8_does_not_panic() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            b"{\"type\":\"response_item\",\"payload\":{\"role\":\"user\",\"content\":\"OK\"}}\n",
        );
        // Incomplete 4-byte UTF-8 sequence (U+1F600 = F0 9F 98 80, only 2 bytes)
        bytes.extend_from_slice(b"\xF0\x9F");

        fs::write(sessions.join("rollout-utf8trunc.jsonl"), &bytes).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "truncated mid-UTF8 should not panic");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "OK");
    }

    #[test]
    fn invalid_utf8_skips_corrupted_lines() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            b"{\"type\":\"response_item\",\"payload\":{\"role\":\"user\",\"content\":\"Before\"}}\n",
        );
        bytes.extend_from_slice(b"\xFF\xFE invalid utf8 line\n");
        bytes.extend_from_slice(
            b"{\"type\":\"response_item\",\"payload\":{\"role\":\"user\",\"content\":\"After\"}}\n",
        );

        fs::write(sessions.join("rollout-badbytes.jsonl"), &bytes).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "invalid UTF-8 should not cause a panic");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            2,
            "should extract valid messages around invalid UTF-8"
        );
        assert_eq!(convs[0].messages[0].content, "Before");
        assert_eq!(convs[0].messages[1].content, "After");
    }

    #[test]
    fn empty_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        fs::write(sessions.join("rollout-empty.jsonl"), b"").unwrap();
        fs::write(sessions.join("rollout-empty.json"), b"").unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "empty files should not cause errors");
        let convs = result.unwrap();
        assert!(
            convs.is_empty(),
            "empty files should produce no conversations"
        );
    }

    #[test]
    fn whitespace_only_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        fs::write(sessions.join("rollout-ws.jsonl"), "  \n\n  \t\n").unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "whitespace-only file should not cause errors"
        );
        let convs = result.unwrap();
        assert!(
            convs.is_empty(),
            "whitespace-only file should produce no conversations"
        );
    }

    #[test]
    fn json_type_mismatch_skips_gracefully() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = concat!(
            // payload is a string instead of object
            "{\"type\":\"response_item\",\"payload\":\"not an object\"}\n",
            // type is a number
            "{\"type\":123,\"payload\":{\"role\":\"user\",\"content\":\"num type\"}}\n",
            // content is a number
            "{\"type\":\"response_item\",\"payload\":{\"role\":\"user\",\"content\":99}}\n",
            // Correct entry
            "{\"type\":\"response_item\",\"payload\":{\"role\":\"user\",\"content\":\"Correct\"}}\n",
        );
        fs::write(sessions.join("rollout-types.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "type mismatches should not cause errors");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert!(
            convs[0].messages.iter().any(|m| m.content == "Correct"),
            "should extract the correctly typed entry"
        );
    }

    #[test]
    fn deeply_nested_json_does_not_stack_overflow() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // serde_json has a recursion limit of 128; 200 levels will trigger parse error
        let mut nested = String::new();
        for _ in 0..200 {
            nested.push_str("{\"a\":");
        }
        nested.push('1');
        for _ in 0..200 {
            nested.push('}');
        }

        let content = format!(
            "{}\n{}\n",
            nested,
            r#"{"type":"response_item","payload":{"role":"user","content":"After nesting"}}"#
        );
        fs::write(sessions.join("rollout-deep.jsonl"), &content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "deeply nested JSON should not cause stack overflow"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "After nesting");
    }

    #[test]
    fn large_message_body_handled_without_oom() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let large_content = "x".repeat(1_000_000);
        let line = format!(
            r#"{{"type":"response_item","payload":{{"role":"user","content":"{}"}}}}"#,
            large_content
        );
        fs::write(sessions.join("rollout-large.jsonl"), &line).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "large message body should not cause OOM");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content.len(), 1_000_000);
    }

    #[test]
    fn null_bytes_embedded_in_content_handled() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = concat!(
            r#"{"type":"response_item","payload":{"role":"user","content":"before\u0000after"}}"#,
            "\n",
            r#"{"type":"response_item","payload":{"role":"user","content":"Clean"}}"#,
            "\n"
        );
        fs::write(sessions.join("rollout-null.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "null bytes in content should not cause errors"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert!(!convs[0].messages.is_empty());
    }

    #[test]
    fn bom_marker_at_file_start_handled() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xEF\xBB\xBF"); // UTF-8 BOM
        bytes.extend_from_slice(
            b"{\"type\":\"response_item\",\"payload\":{\"role\":\"user\",\"content\":\"BOM line\"}}\n",
        );
        bytes.extend_from_slice(
            b"{\"type\":\"response_item\",\"payload\":{\"role\":\"user\",\"content\":\"Second\"}}\n",
        );
        fs::write(sessions.join("rollout-bom.jsonl"), &bytes).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "BOM marker should not cause errors");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert!(
            !convs[0].messages.is_empty(),
            "should extract at least the second line after BOM"
        );
        assert!(
            convs[0].messages.iter().any(|m| m.content == "Second"),
            "second line should parse correctly regardless of BOM"
        );
    }

    // =====================================================
    // Codex-specific edge cases (br-fiiv)
    // =====================================================

    #[test]
    fn missing_payload_field_skipped() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // response_item and event_msg without payload field
        let content = concat!(
            "{\"type\":\"response_item\",\"timestamp\":\"2025-12-01T10:00:00Z\"}\n",
            "{\"type\":\"event_msg\",\"timestamp\":\"2025-12-01T10:00:01Z\"}\n",
            "{\"type\":\"session_meta\",\"timestamp\":\"2025-12-01T10:00:02Z\"}\n",
            "{\"type\":\"response_item\",\"payload\":{\"role\":\"user\",\"content\":\"Has payload\"}}\n",
        );
        fs::write(sessions.join("rollout-nopayload.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "missing payload should not cause errors");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Has payload");
    }

    #[test]
    fn timestamp_parsing_edge_cases() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        let content = concat!(
            // ISO 8601 with milliseconds
            "{\"type\":\"response_item\",\"timestamp\":\"2025-12-01T10:00:00.123Z\",\"payload\":{\"role\":\"user\",\"content\":\"ms precision\"}}\n",
            // ISO 8601 with timezone offset
            "{\"type\":\"response_item\",\"timestamp\":\"2025-12-01T10:00:00+05:30\",\"payload\":{\"role\":\"user\",\"content\":\"tz offset\"}}\n",
            // Unix epoch milliseconds as number
            "{\"type\":\"response_item\",\"timestamp\":1700000000000,\"payload\":{\"role\":\"user\",\"content\":\"epoch millis\"}}\n",
            // No timestamp at all
            "{\"type\":\"response_item\",\"payload\":{\"role\":\"user\",\"content\":\"no timestamp\"}}\n",
            // Null timestamp
            "{\"type\":\"response_item\",\"timestamp\":null,\"payload\":{\"role\":\"user\",\"content\":\"null ts\"}}\n",
        );
        fs::write(sessions.join("rollout-timestamps.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "varied timestamp formats should not cause errors"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            5,
            "all 5 messages should be extracted regardless of timestamp format"
        );
        // Messages with valid timestamps should have created_at set
        assert!(convs[0].messages[0].created_at.is_some());
        assert!(convs[0].messages[1].created_at.is_some());
        assert!(convs[0].messages[2].created_at.is_some());
    }

    #[test]
    fn workspace_path_encoding_edge_cases() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Test various workspace path formats in session_meta
        let content = concat!(
            // Path with spaces
            "{\"type\":\"session_meta\",\"payload\":{\"cwd\":\"/home/user/my project/src\"}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"role\":\"user\",\"content\":\"Spaces path\"}}\n",
        );
        fs::write(sessions.join("rollout-spaces.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/my project/src"))
        );

        // Unicode workspace path
        let content2 = concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"cwd\":\"/home/\u{00FC}ser/projekt\"}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"role\":\"user\",\"content\":\"Unicode path\"}}\n",
        );
        fs::write(sessions.join("rollout-unicode.jsonl"), content2).unwrap();

        let convs2 = connector.scan(&ctx).unwrap();
        assert!(
            !convs2.is_empty(),
            "unicode workspace paths should be handled"
        );
    }

    #[test]
    fn event_msg_with_unknown_subtypes_skipped() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Various event_msg subtypes that should be gracefully skipped
        let content = concat!(
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"streaming_start\"}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"streaming_delta\",\"delta\":\"partial\"}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"streaming_end\"}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"tool_call\",\"name\":\"bash\",\"input\":{\"cmd\":\"ls\"}}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"tool_result\",\"output\":\"file.txt\"}}\n",
            "{\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"Real user input\"}}\n",
        );
        fs::write(sessions.join("rollout-events.jsonl"), content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "unknown event subtypes should not cause errors"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        // user_message + tool_call events should produce messages
        assert_eq!(convs[0].messages.len(), 2);

        // tool_call event should produce an assistant message with invocation
        let tool_msg = &convs[0].messages[0];
        assert_eq!(tool_msg.role, "assistant");
        assert_eq!(tool_msg.invocations.len(), 1);
        assert_eq!(tool_msg.invocations[0].kind, "tool");
        assert_eq!(tool_msg.invocations[0].name, "bash");
        assert!(tool_msg.invocations[0].arguments.is_some());

        // user_message event should still produce a user message
        let user_msg = &convs[0].messages[1];
        assert_eq!(user_msg.content, "Real user input");
        assert_eq!(user_msg.role, "user");
    }

    #[test]
    fn tool_call_format_variations() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex");
        let sessions = codex_dir.join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // response_item with tool_use content blocks (like Claude API format)
        let content = json!({
            "type": "response_item",
            "payload": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Let me check that."},
                    {"type": "tool_use", "name": "read_file", "input": {"path": "/etc/hosts"}}
                ]
            }
        })
        .to_string()
            + "\n"
            + &json!({
                "type": "response_item",
                "payload": {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "name": "bash", "input": {"command": "ls -la"}},
                        {"type": "text", "text": "Here are the results."}
                    ]
                }
            })
            .to_string()
            + "\n";

        fs::write(sessions.join("rollout-tools.jsonl"), &content).unwrap();

        let connector = CodexConnector::new();
        let ctx = ScanContext::local_default(codex_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "tool call format variations should not cause errors"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        // flatten_content should handle tool_use blocks
        assert!(convs[0].messages[0].content.contains("Let me check"));
        assert!(
            convs[0].messages[1]
                .content
                .contains("Here are the results")
        );
    }
}
