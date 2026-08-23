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
//! omp-specific extensions handled tolerantly:
//! - `title` entries (`{"type":"title","title":...}`) supply the
//!   conversation title when present; otherwise the `session` header title,
//!   then the first user message, is used.
//! - `model_change` entries carry a bare `model` field (pi-mono writes
//!   `provider` + `modelId`); either spelling updates the tracked model.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;
use walkdir::WalkDir;

use super::utils::dedupe_path_key;
use crate::types::{NormalizedConversation, NormalizedMessage};

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

/// Parse one pi-family session JSONL file into a normalized conversation.
///
/// Returns `None` for unreadable files (logged at debug with `agent_slug`
/// context) and for files that yield zero usable messages — mirroring the
/// skip semantics of the original per-connector scan loops.
///
/// `sessions_dir` is used to derive the conversation's external id as a path
/// relative to the sessions directory (falling back to the file stem).
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

    let content = match fs::read_to_string(&source_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(path = %source_path.display(), error = %e, "{agent_slug}: skipping unreadable session");
            return None;
        }
    };

    let mut messages = Vec::new();
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    let mut session_cwd: Option<PathBuf> = None;
    let mut session_id: Option<String> = None;
    let mut provider: Option<String> = None;
    let mut model_id: Option<String> = None;
    let mut header_title: Option<String> = None;
    let mut title_entry: Option<String> = None;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let val: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let entry_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match entry_type {
            "session" => {
                // Session header - extract metadata
                session_id = val.get("id").and_then(|v| v.as_str()).map(String::from);
                session_cwd = val.get("cwd").and_then(|v| v.as_str()).map(PathBuf::from);
                provider = val
                    .get("provider")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                model_id = val
                    .get("modelId")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                header_title = val
                    .get("title")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .filter(|t| !t.is_empty());

                // Parse timestamp
                if let Some(ts_val) = val.get("timestamp") {
                    started_at = super::parse_timestamp(ts_val);
                }
            }
            "title" => {
                // omp writes standalone title lines; prefer the most recent
                // non-empty one over the session-header title.
                if let Some(title) = val
                    .get("title")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .filter(|t| !t.is_empty())
                {
                    title_entry = Some(title);
                }
            }
            "message" => {
                // Message entry - extract the nested message object
                let created = val.get("timestamp").and_then(super::parse_timestamp);

                if let Some(msg) = val.get("message") {
                    let role = msg
                        .get("role")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");

                    // Normalize role names
                    let normalized_role = match role {
                        "user" => "user",
                        "assistant" => "assistant",
                        "toolResult" => "tool",
                        _ => role,
                    };

                    // Extract content
                    let content_str = msg
                        .get("content")
                        .map(flatten_message_content)
                        .unwrap_or_default();

                    if content_str.trim().is_empty() {
                        continue;
                    }

                    // Update timestamps
                    started_at = match (started_at, created) {
                        (Some(curr), Some(ts)) => Some(curr.min(ts)),
                        (None, Some(ts)) => Some(ts),
                        (other, None) => other,
                    };
                    ended_at = match (ended_at, created) {
                        (Some(curr), Some(ts)) => Some(curr.max(ts)),
                        (None, Some(ts)) => Some(ts),
                        (other, None) => other,
                    };

                    // Extract author (model) for assistant messages
                    // Check message.model first, fall back to tracked model_id
                    let author = if normalized_role == "assistant" {
                        msg.get("model")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .or_else(|| model_id.clone())
                    } else {
                        None
                    };

                    let invocations = msg
                        .get("content")
                        .and_then(|c| c.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter(|item| {
                                    item.get("type").and_then(|t| t.as_str()) == Some("toolCall")
                                })
                                .map(|item| {
                                    let name = item
                                        .get("name")
                                        .and_then(|n| n.as_str())
                                        .unwrap_or("unknown")
                                        .to_string();
                                    crate::types::NormalizedInvocation {
                                        kind: "tool".to_string(),
                                        name,
                                        raw_name: None,
                                        call_id: item
                                            .get("id")
                                            .and_then(|v| v.as_str())
                                            .map(String::from),
                                        arguments: item.get("arguments").cloned(),
                                    }
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    messages.push(NormalizedMessage {
                        idx: i64::try_from(messages.len()).unwrap_or(i64::MAX),
                        role: normalized_role.to_string(),
                        author,
                        created_at: created,
                        content: content_str,
                        extra: val.clone(),
                        invocations,
                        snippets: Vec::new(),
                    });
                }
            }
            "model_change" => {
                // Track model changes (useful metadata). pi-mono writes
                // `provider` + `modelId`; omp writes a bare `model`. A
                // record lacking one field must not erase the previously
                // tracked value.
                if let Some(p) = val.get("provider").and_then(|v| v.as_str()) {
                    provider = Some(p.to_string());
                }
                if let Some(m) = val
                    .get("modelId")
                    .and_then(|v| v.as_str())
                    .or_else(|| val.get("model").and_then(|v| v.as_str()))
                {
                    model_id = Some(m.to_string());
                }
            }
            _ => {
                // Skip thinking_level_change and unknown types
            }
        }
    }

    if messages.is_empty() {
        return None;
    }

    // Title precedence: explicit omp `title` entry, then session-header
    // title, then the first user message, then the first message at all.
    let title = title_entry.or(header_title).or_else(|| {
        messages
            .iter()
            .find(|m| m.role == "user")
            .map(|m| first_line_truncated(&m.content))
    });
    let title = title.or_else(|| messages.first().map(|m| first_line_truncated(&m.content)));
    // Build metadata
    let metadata = serde_json::json!({
        "source": agent_slug,
        "session_id": session_id,
        "provider": provider,
        "model_id": model_id,
    });

    Some(NormalizedConversation {
        agent_slug: agent_slug.to_string(),
        external_id,
        title,
        workspace: session_cwd,
        source_path: source_path.clone(),
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

/// Discover deduplicated session files across `homes`, filtered by
/// `since_ts`, wrapped as primary session-log sources attributed to
/// `agent_slug`.
#[must_use]
pub fn discover_sources(
    homes: &[PathBuf],
    ctx: &super::ScanContext,
    agent_slug: &'static str,
) -> Vec<super::DiscoveredSourceFile> {
    use super::{DiscoveredSourceFile, DiscoveredSourceRole, ScanRoot};
    use crate::connectors::file_modified_since;

    let mut out = Vec::new();
    let mut seen_session_paths: HashSet<PathBuf> = HashSet::new();
    for home in homes {
        let root = ScanRoot::local(home.clone());
        for file in session_files(home) {
            if !seen_session_paths.insert(dedupe_path_key(&file)) {
                continue;
            }
            if !file_modified_since(&file, ctx.since_ts) {
                continue;
            }
            out.push(
                DiscoveredSourceFile::new(
                    agent_slug,
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
    use crate::connectors::file_modified_since;

    let mut convs = Vec::new();
    let mut seen_session_paths: HashSet<PathBuf> = HashSet::new();

    for home in homes {
        let files = session_files(home);
        if files.is_empty() {
            continue;
        }
        let sessions = sessions_dir(home);

        for file in files {
            // Guard against the same session file being reached through
            // two homes (e.g. via symlinks).
            let dedupe_key = dedupe_path_key(&file);
            if !seen_session_paths.insert(dedupe_key) {
                continue;
            }
            // Skip files not modified since last scan
            if !file_modified_since(&file, ctx.since_ts) {
                continue;
            }

            if let Some(conversation) = parse_session_file(&file, &sessions, agent_slug) {
                convs.push(conversation);
            }
        }
    }

    Ok(convs)
}
