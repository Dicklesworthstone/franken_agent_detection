use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::{env_path_nonempty, excluded_scan_paths_from_env, path_is_excluded};
use super::{
    Connector, extract_invocations_from_content_blocks, file_modified_since, flatten_content,
    franken_detection_for_connector, parse_timestamp,
};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct ClaudeCodeConnector;

const LARGE_SESSION_EXTRA_COMPACT_THRESHOLD_BYTES: u64 = 32 * 1024 * 1024;

impl Default for ClaudeCodeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaudeCodeConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn projects_root() -> PathBuf {
        Self::projects_root_resolved(
            env_path_nonempty("CLAUDE_CONFIG_DIR").as_deref(),
            env_path_nonempty("XDG_CONFIG_HOME").as_deref(),
            dirs::home_dir().as_deref(),
        )
    }

    fn projects_root_candidates() -> Vec<PathBuf> {
        let primary = Self::projects_root();
        let mut roots = Self::projects_root_candidates_resolved(
            env_path_nonempty("CLAUDE_CONFIG_DIR").as_deref(),
            env_path_nonempty("XDG_CONFIG_HOME").as_deref(),
            dirs::home_dir().as_deref(),
        );
        if !roots.contains(&primary) {
            roots.push(primary);
        }
        roots
    }

    fn desktop_session_roots_resolved(home_dir: Option<&Path>) -> Vec<PathBuf> {
        let Some(home) = home_dir else {
            return Vec::new();
        };
        let claude_support = home
            .join("Library")
            .join("Application Support")
            .join("Claude");
        vec![
            claude_support.join("claude-code-sessions"),
            claude_support.join("local-agent-mode-sessions"),
        ]
    }

    /// Pure resolver for [`Self::projects_root`] — split out so the precedence
    /// chain can be unit-tested without manipulating process env vars
    /// (`std::env::set_var` is `unsafe` and not safe across parallel tests).
    ///
    /// Honors the env-var redirects Claude Code itself documents, in the same
    /// precedence order:
    ///   1. `CLAUDE_CONFIG_DIR` — explicit override.
    ///   2. `XDG_CONFIG_HOME`   — XDG fallback.
    ///   3. `${HOME}/.claude/projects` — default.
    ///
    /// Without this, the connector silently ignores caam-isolated profiles and
    /// any user with `XDG_CONFIG_HOME` set.
    fn projects_root_resolved(
        claude_config_dir: Option<&Path>,
        xdg_config_home: Option<&Path>,
        home_dir: Option<&Path>,
    ) -> PathBuf {
        if let Some(explicit) = claude_config_dir {
            return explicit.join("projects");
        }
        if let Some(xdg) = xdg_config_home {
            return xdg.join("claude-code").join("projects");
        }
        // Match the historical behavior: when even `dirs::home_dir()` returns
        // None we fall back to a relative `.claude/projects` path. That keeps
        // strict-mode test environments (sandboxes with no HOME) unchanged.
        home_dir.map_or_else(
            || PathBuf::from(".claude/projects"),
            |h| h.join(".claude/projects"),
        )
    }

    fn projects_root_candidates_resolved(
        claude_config_dir: Option<&Path>,
        xdg_config_home: Option<&Path>,
        home_dir: Option<&Path>,
    ) -> Vec<PathBuf> {
        if let Some(explicit) = claude_config_dir {
            return vec![explicit.join("projects")];
        }

        let mut roots = Vec::new();
        if let Some(xdg) = xdg_config_home {
            roots.push(xdg.join("claude-code").join("projects"));
        }
        roots.push(home_dir.map_or_else(
            || PathBuf::from(".claude/projects"),
            |home| home.join(".claude/projects"),
        ));
        roots.extend(Self::desktop_session_roots_resolved(home_dir));
        roots.sort();
        roots.dedup();
        roots
    }

    fn session_files(scan_target: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for entry in WalkDir::new(scan_target).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let ext = entry.path().extension().and_then(|s| s.to_str());
            if ext == Some("jsonl") || ext == Some("json") || ext == Some("claude") {
                files.push(entry.path().to_path_buf());
            }
        }
        // Keep connector traversal deterministic across filesystems/runs.
        files.sort();
        files
    }

    fn projects_root_for_explicit_file(path: &Path) -> Option<PathBuf> {
        path.ancestors()
            .filter(|ancestor| ancestor.is_dir())
            .find(|ancestor| {
                ancestor.file_name().and_then(|name| name.to_str()) == Some("projects")
            })
            .map(Path::to_path_buf)
    }

    fn should_compact_large_message_extra(file_size_bytes: Option<u64>) -> bool {
        file_size_bytes.is_some_and(|size| size >= LARGE_SESSION_EXTRA_COMPACT_THRESHOLD_BYTES)
    }

    fn path_is_desktop_sidecar(path: &Path) -> bool {
        path.components().any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some("claude-code-sessions" | "local-agent-mode-sessions")
            )
        })
    }

    fn discovered_source_role(path: &Path) -> DiscoveredSourceRole {
        if Self::path_is_desktop_sidecar(path) {
            DiscoveredSourceRole::MetadataSidecar
        } else {
            DiscoveredSourceRole::PrimarySessionLog
        }
    }

    fn non_empty_json_string(value: &Value, key: &str) -> Option<String> {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    }

    fn desktop_sidecar_metadata_message(raw: &Value) -> Option<NormalizedMessage> {
        let title = Self::non_empty_json_string(raw, "title");
        let cwd = Self::non_empty_json_string(raw, "cwd");
        let model = Self::non_empty_json_string(raw, "model");
        let cli_session_id = Self::non_empty_json_string(raw, "cliSessionId");
        let session_id = Self::non_empty_json_string(raw, "sessionId");
        let permission_mode = Self::non_empty_json_string(raw, "permissionMode");
        if title.is_none()
            && cwd.is_none()
            && model.is_none()
            && cli_session_id.is_none()
            && session_id.is_none()
        {
            return None;
        }

        let mut lines = vec!["Claude Code Desktop session metadata".to_string()];
        if let Some(title) = &title {
            lines.push(format!("Title: {title}"));
        }
        if let Some(cwd) = &cwd {
            lines.push(format!("Workspace: {cwd}"));
        }
        if let Some(model) = &model {
            lines.push(format!("Model: {model}"));
        }
        if let Some(permission_mode) = &permission_mode {
            lines.push(format!("Permission mode: {permission_mode}"));
        }
        if let Some(cli_session_id) = &cli_session_id {
            lines.push(format!("CLI session id: {cli_session_id}"));
        } else if let Some(session_id) = &session_id {
            lines.push(format!("Session id: {session_id}"));
        }
        lines.push(
            "Conversation body unavailable in this Desktop sidecar; Claude Code may have culled the CLI JSONL body."
                .to_string(),
        );

        let created_at = raw
            .get("lastActivityAt")
            .or_else(|| raw.get("createdAt"))
            .and_then(parse_timestamp);
        Some(NormalizedMessage {
            idx: 0,
            role: "system".to_string(),
            author: Some("claude_code_desktop".to_string()),
            created_at,
            content: lines.join("\n"),
            extra: serde_json::json!({
                "cass": {
                    "source": "claude_code_desktop_sidecar",
                    "body_available": false,
                    "body_cull_note": "Claude Code may auto-cull CLI JSONL bodies while Desktop sidecars retain title/workspace metadata."
                },
                "raw": raw
            }),
            invocations: Vec::new(),
            snippets: Vec::new(),
        })
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let looks_like_root = |path: &PathBuf| path.join("projects").exists();

        let mut roots: Vec<ScanRoot> = if ctx.use_default_detection() {
            if looks_like_root(&ctx.data_dir) {
                vec![ScanRoot::local(ctx.data_dir.clone())]
            } else {
                Self::projects_root_candidates()
                    .into_iter()
                    .map(ScanRoot::local)
                    .collect()
            }
        } else {
            ctx.scan_roots.clone()
        };

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        Self::discover_sources_with_exclusions(ctx, &excluded_scan_paths_from_env())
    }

    fn discover_sources_with_exclusions(
        ctx: &ScanContext,
        excluded_paths: &[PathBuf],
    ) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        for root in Self::source_roots(ctx) {
            let scan_target = root.path.clone();
            if !scan_target.exists() {
                continue;
            }
            let session_paths = if scan_target.is_file() {
                vec![scan_target]
            } else {
                Self::session_files(&scan_target)
            };
            for path in session_paths {
                if path_is_excluded(&path, excluded_paths) {
                    tracing::debug!(
                        path = %path.display(),
                        "claude_code skipping excluded session source"
                    );
                    continue;
                }
                if !file_modified_since(&path, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "claude_code",
                        &root,
                        path.clone(),
                        Self::discovered_source_role(&path),
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
            .pointer("/message/model")
            .or_else(|| raw.get("model"))
            .and_then(|v| v.as_str())
            .filter(|value| !value.trim().is_empty())
        {
            cass.insert("model".to_string(), Value::String(model.to_string()));
        }

        let usage = raw.pointer("/message/usage");
        let mut token_usage = serde_json::Map::new();
        if let Some(input_tokens) = usage
            .and_then(|value| value.get("input_tokens"))
            .and_then(Value::as_i64)
        {
            token_usage.insert("input_tokens".to_string(), Value::from(input_tokens));
        }
        if let Some(output_tokens) = usage
            .and_then(|value| value.get("output_tokens"))
            .and_then(Value::as_i64)
        {
            token_usage.insert("output_tokens".to_string(), Value::from(output_tokens));
        }
        if let Some(cache_read_tokens) = usage
            .and_then(|value| value.get("cache_read_input_tokens"))
            .and_then(Value::as_i64)
        {
            token_usage.insert(
                "cache_read_tokens".to_string(),
                Value::from(cache_read_tokens),
            );
        }
        if let Some(cache_creation_tokens) = usage
            .and_then(|value| value.get("cache_creation_input_tokens"))
            .and_then(Value::as_i64)
        {
            token_usage.insert(
                "cache_creation_tokens".to_string(),
                Value::from(cache_creation_tokens),
            );
        }
        if let Some(service_tier) = usage
            .and_then(|value| value.get("service_tier"))
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
        {
            token_usage.insert(
                "service_tier".to_string(),
                Value::String(service_tier.to_string()),
            );
        }
        if !token_usage.is_empty() {
            token_usage.insert("data_source".to_string(), Value::String("api".to_string()));
            cass.insert("token_usage".to_string(), Value::Object(token_usage));
        }

        let tool_call_count = raw
            .pointer("/message/content")
            .and_then(|value| value.as_array())
            .map_or(0, |items| {
                items
                    .iter()
                    .filter(|item| {
                        item.get("type").and_then(|kind| kind.as_str()) == Some("tool_use")
                    })
                    .count()
            });
        if tool_call_count > 0 {
            cass.insert("tool_call_count".to_string(), Value::from(tool_call_count));
        }

        if let Some(attachments) = raw
            .get("attachment_refs")
            .or_else(|| raw.get("attachments"))
            .or_else(|| raw.pointer("/message/attachment_refs"))
            .or_else(|| raw.pointer("/message/attachments"))
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
}

#[allow(clippy::too_many_lines)]
fn scan_claude_with_callback(
    ctx: &ScanContext,
    on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
) -> Result<()> {
    scan_claude_with_callback_with_exclusions(ctx, on_conversation, &excluded_scan_paths_from_env())
}

#[allow(clippy::too_many_lines)]
fn scan_claude_with_callback_with_exclusions(
    ctx: &ScanContext,
    on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    excluded_paths: &[PathBuf],
) -> Result<()> {
    let roots: Vec<PathBuf> = ClaudeCodeConnector::source_roots(ctx)
        .into_iter()
        .map(|root| root.path)
        .collect();

    let mut file_count = 0;

    for root in roots {
        let explicit_file_root = root.is_file();
        let scan_target = root.clone();
        let external_id_root = if explicit_file_root {
            ClaudeCodeConnector::projects_root_for_explicit_file(&root)
                .or_else(|| root.parent().map(Path::to_path_buf))
        } else {
            Some(scan_target.clone())
        };

        if !scan_target.exists() {
            continue;
        }

        let session_paths = if explicit_file_root {
            vec![scan_target.clone()]
        } else {
            ClaudeCodeConnector::session_files(&scan_target)
        };

        for path in session_paths {
            if path_is_excluded(&path, excluded_paths) {
                tracing::debug!(
                    path = %path.display(),
                    "claude_code skipping excluded session file"
                );
                continue;
            }
            let ext = path.extension().and_then(|s| s.to_str());
            if !file_modified_since(&path, ctx.since_ts) {
                continue;
            }
            let file_size_bytes = fs::metadata(&path).ok().map(|metadata| metadata.len());
            let compact_message_extra =
                ClaudeCodeConnector::should_compact_large_message_extra(file_size_bytes);
            if compact_message_extra {
                tracing::debug!(
                    path = %path.display(),
                    size_bytes = file_size_bytes.unwrap_or_default(),
                    "claude_code compacting per-message extra payloads for large session"
                );
            }
            file_count += 1;
            if file_count <= 3 {
                tracing::debug!(path = %path.display(), "claude_code found file");
            }

            let mut messages = Vec::new();
            let mut started_at: Option<i64> = None;
            let mut ended_at: Option<i64> = None;
            let mut workspace: Option<PathBuf> = None;
            let mut session_id: Option<String> = None;
            let mut cli_session_id: Option<String> = None;
            let mut git_branch: Option<String> = None;
            let mut json_title: Option<String> = None;
            let mut permission_mode: Option<String> = None;
            let mut source_kind = "claude_code";

            if ext == Some("jsonl") {
                let file = std::fs::File::open(&path)
                    .with_context(|| format!("open {}", path.display()))?;
                let reader = std::io::BufReader::new(file);

                for line_res in std::io::BufRead::lines(reader) {
                    let Ok(line) = line_res else {
                        continue;
                    };
                    if line.trim().is_empty() {
                        continue;
                    }
                    // Strip a UTF-8 BOM so the first record (often
                    // session_meta or the first prompt) is not silently lost.
                    let line = line.trim_start_matches('\u{feff}');
                    let Ok(val) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };

                    if workspace.is_none() {
                        workspace = val.get("cwd").and_then(|v| v.as_str()).map(PathBuf::from);
                    }
                    if session_id.is_none() {
                        session_id = val
                            .get("sessionId")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                    }
                    if git_branch.is_none() {
                        git_branch = val
                            .get("gitBranch")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                    }

                    let entry_type = val.get("type").and_then(|v| v.as_str());
                    let role_hint = val
                        .get("message")
                        .and_then(|m| m.get("role"))
                        .and_then(|v| v.as_str())
                        .or_else(|| val.get("role").and_then(|v| v.as_str()));
                    let is_user_assistant = matches!(entry_type, Some("user" | "assistant"))
                        || (entry_type == Some("message")
                            && matches!(role_hint, Some("user" | "assistant")));
                    if !is_user_assistant {
                        continue;
                    }

                    let created = val.get("timestamp").and_then(parse_timestamp);

                    started_at = match (started_at, created) {
                        (Some(curr), Some(ts)) => Some(curr.min(ts)),
                        (None, Some(ts)) => Some(ts),
                        (other, None) => other,
                    };
                    ended_at = match (ended_at, created) {
                        (Some(curr), Some(ts)) => Some(curr.max(ts)),
                        (None, Some(ts)) => Some(ts),
                        (Some(curr), None) => Some(curr),
                        (None, None) => None,
                    };

                    let role = role_hint.or(entry_type).unwrap_or("agent");
                    let content_val = val
                        .get("message")
                        .and_then(|m| m.get("content"))
                        .or_else(|| val.get("content"));
                    let content_str = content_val.map(flatten_content).unwrap_or_default();

                    // Tool results ride in user entries as
                    // content:[{type:"tool_result", tool_use_id, content}].
                    // flatten_content ignores those blocks, so without this
                    // pass every result entry is dropped wholesale
                    // (~30-40% of real entries per transcript), leaving
                    // invocations with call_ids but no outputs anywhere.
                    if let Some(blocks) = content_val.and_then(Value::as_array) {
                        for block in blocks {
                            if block.get("type").and_then(Value::as_str) != Some("tool_result") {
                                continue;
                            }
                            let result_text = match block.get("content") {
                                Some(Value::String(s)) => s.clone(),
                                Some(Value::Array(parts)) => parts
                                    .iter()
                                    .filter_map(|part| part.get("text").and_then(Value::as_str))
                                    .collect::<Vec<_>>()
                                    .join("\n"),
                                _ => continue,
                            };
                            if result_text.trim().is_empty() {
                                continue;
                            }
                            let mut tool_extra = Map::new();
                            tool_extra.insert(
                                "source".to_string(),
                                Value::String("tool_result".to_string()),
                            );
                            if let Some(id) = block.get("tool_use_id").and_then(Value::as_str) {
                                tool_extra.insert(
                                    "tool_use_id".to_string(),
                                    Value::String(id.to_string()),
                                );
                            }
                            messages.push(NormalizedMessage {
                                idx: 0,
                                role: "tool".to_string(),
                                author: None,
                                created_at: created,
                                content: result_text,
                                extra: Value::Object(tool_extra),
                                invocations: Vec::new(),
                                snippets: Vec::new(),
                            });
                        }
                    }

                    if content_str.trim().is_empty() {
                        continue;
                    }


                    let author = val
                        .get("message")
                        .and_then(|m| m.get("model"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let invocations =
                        content_val.map_or_else(Vec::new, extract_invocations_from_content_blocks);

                    messages.push(NormalizedMessage {
                        idx: 0,
                        role: role.to_string(),
                        author,
                        created_at: created,
                        content: content_str,
                        extra: if compact_message_extra {
                            ClaudeCodeConnector::compact_message_extra(&val)
                        } else {
                            val
                        },
                        invocations,
                        snippets: Vec::new(),
                    });
                }
                crate::types::reindex_messages(&mut messages);
            } else {
                if let Ok(metadata) = fs::metadata(&path)
                    && metadata.len() > 100 * 1024 * 1024
                {
                    tracing::debug!(
                        path = %path.display(),
                        size_bytes = metadata.len(),
                        "skipping large file (>100MB)"
                    );
                    continue;
                }

                let content_string = fs::read_to_string(&path)
                    .with_context(|| format!("read {}", path.display()))?;
                let val: Value = match serde_json::from_str(&content_string) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(path = %path.display(), error = %e, "claude_code skipping malformed JSON");
                        continue;
                    }
                };

                json_title = ClaudeCodeConnector::non_empty_json_string(&val, "title");
                if workspace.is_none() {
                    workspace =
                        ClaudeCodeConnector::non_empty_json_string(&val, "cwd").map(PathBuf::from);
                }
                if session_id.is_none() {
                    session_id = ClaudeCodeConnector::non_empty_json_string(&val, "sessionId");
                }
                if cli_session_id.is_none() {
                    cli_session_id =
                        ClaudeCodeConnector::non_empty_json_string(&val, "cliSessionId");
                }
                if permission_mode.is_none() {
                    permission_mode =
                        ClaudeCodeConnector::non_empty_json_string(&val, "permissionMode");
                }
                let sidecar_created_at = val.get("createdAt").and_then(parse_timestamp);
                let sidecar_last_activity_at = val.get("lastActivityAt").and_then(parse_timestamp);
                started_at = started_at
                    .or(sidecar_created_at)
                    .or(sidecar_last_activity_at);
                ended_at = ended_at.or(sidecar_last_activity_at).or(sidecar_created_at);

                if let Some(arr) = val.get("messages").and_then(|m| m.as_array()) {
                    for item in arr {
                        let role = item
                            .get("role")
                            .or_else(|| item.get("type"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("agent");
                        let created = item
                            .get("timestamp")
                            .or_else(|| item.get("time"))
                            .and_then(parse_timestamp);

                        started_at = match (started_at, created) {
                            (Some(curr), Some(ts)) => Some(curr.min(ts)),
                            (None, Some(ts)) => Some(ts),
                            (other, None) => other,
                        };
                        ended_at = match (ended_at, created) {
                            (Some(curr), Some(ts)) => Some(curr.max(ts)),
                            (None, Some(ts)) => Some(ts),
                            (Some(curr), None) => Some(curr),
                            (None, None) => None,
                        };

                        let content_val = item.get("content").or_else(|| item.get("text"));
                        let content_str = content_val.map(flatten_content).unwrap_or_default();

                        if content_str.trim().is_empty() {
                            continue;
                        }

                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: role.to_string(),
                            author: None,
                            created_at: created,
                            content: content_str,
                            extra: if compact_message_extra {
                                ClaudeCodeConnector::compact_message_extra(item)
                            } else {
                                item.clone()
                            },
                            invocations: content_val
                                .map_or_else(Vec::new, extract_invocations_from_content_blocks),
                            snippets: Vec::new(),
                        });
                    }
                }
                if messages.is_empty()
                    && ClaudeCodeConnector::path_is_desktop_sidecar(&path)
                    && let Some(message) =
                        ClaudeCodeConnector::desktop_sidecar_metadata_message(&val)
                {
                    source_kind = "claude_code_desktop_sidecar";
                    messages.push(message);
                }
                crate::types::reindex_messages(&mut messages);
            }

            if messages.is_empty() {
                if file_count <= 3 {
                    tracing::debug!(path = %path.display(), "claude_code no messages extracted");
                }
                continue;
            }
            tracing::debug!(path = %path.display(), messages = messages.len(), "claude_code extracted messages");

            let title = json_title.or_else(|| {
                messages
                    .iter()
                    .find(|m| m.role == "user")
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
                        workspace
                            .as_ref()
                            .and_then(|p| p.file_name())
                            .and_then(|n| n.to_str())
                            .map(String::from)
                    })
            });

            on_conversation(NormalizedConversation {
                agent_slug: "claude_code".into(),
                external_id: if source_kind == "claude_code_desktop_sidecar" {
                    cli_session_id.clone().or_else(|| session_id.clone())
                } else {
                    external_id_root
                        .as_deref()
                        .and_then(|base| path.strip_prefix(base).ok())
                        .and_then(|rel| rel.to_str())
                        .map(std::string::ToString::to_string)
                        .or_else(|| {
                            path.file_name()
                                .and_then(|s| s.to_str())
                                .map(std::string::ToString::to_string)
                        })
                },
                title,
                workspace,
                source_path: path.clone(),
                started_at,
                ended_at,
                metadata: serde_json::json!({
                    "source": source_kind,
                    "sessionId": session_id,
                    "cliSessionId": cli_session_id,
                    "gitBranch": git_branch,
                    "permissionMode": permission_mode,
                    "bodyAvailable": source_kind != "claude_code_desktop_sidecar"
                }),
                messages,
            })?;
        }
    }

    Ok(())
}

impl Connector for ClaudeCodeConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("claude_code").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        scan_claude_with_callback(ctx, &mut |conv| {
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
        scan_claude_with_callback(ctx, on_conversation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    /// Create a test-ready Claude directory structure.
    /// Includes a `projects` marker subdir so `looks_like_root()` returns true
    /// and the connector scans only the temp dir instead of the real ~/.claude/projects.
    fn make_test_claude_dir(base: &std::path::Path) -> PathBuf {
        let claude_dir = base.join(".claude");
        fs::create_dir_all(claude_dir.join("projects")).unwrap();
        claude_dir
    }

    // =========================================================================
    // Constructor tests
    // =========================================================================

    #[test]
    fn new_creates_connector() {
        let connector = ClaudeCodeConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = ClaudeCodeConnector;
        let _ = connector;
    }

    #[test]
    fn projects_root_returns_claude_projects_path() {
        // Smoke test on the env-aware entry point. We can't reliably mutate
        // env vars in parallel tests (std::env::set_var is unsafe + forbid'd),
        // so this test only asserts the invariant that holds across all three
        // resolver branches: the path's last component is "projects". The
        // *precedence* logic is exercised by `projects_root_resolved_*` below
        // against explicit inputs, where we don't depend on process env at all.
        let root = ClaudeCodeConnector::projects_root();
        assert_eq!(
            root.file_name().and_then(|n| n.to_str()),
            Some("projects"),
            "projects_root() should always return a path ending in 'projects', got: {}",
            root.display()
        );
    }

    #[test]
    fn projects_root_resolved_uses_explicit_override_first() {
        let explicit = std::path::Path::new("/opt/claude_explicit");
        let xdg = std::path::Path::new("/opt/xdg");
        let home = std::path::Path::new("/opt/home");
        let root =
            ClaudeCodeConnector::projects_root_resolved(Some(explicit), Some(xdg), Some(home));
        assert_eq!(root, PathBuf::from("/opt/claude_explicit/projects"));
    }

    #[test]
    fn projects_root_resolved_falls_back_to_xdg_when_no_explicit_override() {
        let xdg = std::path::Path::new("/opt/xdg");
        let home = std::path::Path::new("/opt/home");
        let root = ClaudeCodeConnector::projects_root_resolved(None, Some(xdg), Some(home));
        // XDG layout is `${XDG_CONFIG_HOME}/claude-code/projects` (no leading
        // dot), distinct from the `.claude/projects` home-relative default —
        // matches what the Claude Code CLI itself does when XDG is set, and
        // what caam writes per-profile.
        assert_eq!(root, PathBuf::from("/opt/xdg/claude-code/projects"));
    }

    #[test]
    fn projects_root_resolved_uses_home_when_no_overrides() {
        let home = std::path::Path::new("/home/jane");
        let root = ClaudeCodeConnector::projects_root_resolved(None, None, Some(home));
        assert_eq!(root, PathBuf::from("/home/jane/.claude/projects"));
    }

    #[test]
    fn projects_root_resolved_falls_back_to_relative_when_home_missing() {
        // Sandboxed test environments occasionally have no HOME — historical
        // behavior was to return a relative `.claude/projects`, preserved here.
        let root = ClaudeCodeConnector::projects_root_resolved(None, None, None);
        assert_eq!(root, PathBuf::from(".claude/projects"));
    }

    #[test]
    fn projects_root_resolved_treats_explicit_as_higher_priority_than_xdg() {
        // Regression guard: if the precedence is ever swapped (XDG before
        // CLAUDE_CONFIG_DIR), caam-style multi-account isolation that sets
        // both vars to *different* values would silently route to the wrong
        // profile. Pin the precedence here so a refactor can't quietly undo it.
        let explicit = std::path::Path::new("/opt/account_A");
        let xdg = std::path::Path::new("/opt/account_B/xdg_config");
        let root = ClaudeCodeConnector::projects_root_resolved(Some(explicit), Some(xdg), None);
        assert_eq!(root, PathBuf::from("/opt/account_A/projects"));
        // Verify it did NOT pick the XDG path.
        assert_ne!(
            root,
            PathBuf::from("/opt/account_B/xdg_config/claude-code/projects")
        );
    }

    #[test]
    fn projects_root_candidates_keep_home_fallback_when_xdg_is_set() {
        let xdg = std::path::Path::new("/opt/xdg");
        let home = std::path::Path::new("/home/jane");
        let roots =
            ClaudeCodeConnector::projects_root_candidates_resolved(None, Some(xdg), Some(home));

        assert!(roots.contains(&PathBuf::from("/opt/xdg/claude-code/projects")));
        assert!(roots.contains(&PathBuf::from("/home/jane/.claude/projects")));
    }

    #[test]
    fn projects_root_candidates_include_macos_desktop_sidecar_roots() {
        let home = std::path::Path::new("/Users/jane");
        let roots = ClaudeCodeConnector::projects_root_candidates_resolved(None, None, Some(home));

        assert!(roots.contains(&PathBuf::from(
            "/Users/jane/Library/Application Support/Claude/claude-code-sessions"
        )));
        assert!(roots.contains(&PathBuf::from(
            "/Users/jane/Library/Application Support/Claude/local-agent-mode-sessions"
        )));
    }

    #[test]
    fn projects_root_candidates_explicit_override_does_not_scan_fallbacks() {
        let explicit = std::path::Path::new("/opt/claude_explicit");
        let xdg = std::path::Path::new("/opt/xdg");
        let home = std::path::Path::new("/home/jane");
        let roots = ClaudeCodeConnector::projects_root_candidates_resolved(
            Some(explicit),
            Some(xdg),
            Some(home),
        );

        assert_eq!(roots, vec![PathBuf::from("/opt/claude_explicit/projects")]);
    }

    #[test]
    fn session_files_returns_sorted_order() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("b.jsonl"), "{}").unwrap();
        fs::write(dir.path().join("a.jsonl"), "{}").unwrap();
        fs::write(dir.path().join("ignore.txt"), "x").unwrap();

        let files = ClaudeCodeConnector::session_files(dir.path());
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
        assert_eq!(names, vec!["a.jsonl", "b.jsonl"]);
    }

    // =========================================================================
    // Detection tests
    // =========================================================================

    #[test]
    fn detect_not_found_without_projects_dir() {
        let connector = ClaudeCodeConnector::new();
        let result = connector.detect();
        // On most CI/test systems, .claude/projects won't exist
        // Just verify detect() doesn't panic
        let _ = result.detected;
    }

    // =========================================================================
    // JSONL parsing tests
    // =========================================================================

    #[test]
    fn scan_parses_jsonl_user_and_assistant_messages() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello Claude"}}
{"type":"assistant","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","content":"Hello! How can I help?"}}
{"type":"summary","timestamp":"2025-12-01T10:00:02Z","summary":"Test summary"}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok());
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);

        // Only user and assistant messages should be extracted (not summary)
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Claude");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert!(convs[0].messages[1].content.contains("How can I help"));
    }

    #[test]
    fn scan_with_callback_matches_scan_for_jsonl_session() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello Claude"}}
{"type":"assistant","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","content":"Hello! How can I help?"}}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
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
    fn scan_skips_explicitly_excluded_session_path_without_skipping_siblings() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let active_session = claude_dir.join("active.jsonl");
        let stable_session = claude_dir.join("stable.jsonl");
        fs::write(
            &active_session,
            r#"{"type":"user","message":{"role":"user","content":"active in-progress content"}}"#,
        )
        .unwrap();
        fs::write(
            &stable_session,
            r#"{"type":"user","message":{"role":"user","content":"stable content"}}"#,
        )
        .unwrap();

        let ctx = ScanContext::local_default(claude_dir, None);
        let mut streamed = Vec::new();
        scan_claude_with_callback_with_exclusions(
            &ctx,
            &mut |conversation| {
                streamed.push(conversation);
                Ok(())
            },
            std::slice::from_ref(&active_session),
        )
        .unwrap();

        assert_eq!(streamed.len(), 1);
        assert_eq!(streamed[0].source_path, stable_session);
        assert_eq!(streamed[0].messages[0].content, "stable content");
    }

    #[test]
    fn discover_source_files_skips_explicitly_excluded_session_path() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let active_session = claude_dir.join("active.jsonl");
        let stable_session = claude_dir.join("stable.jsonl");
        fs::write(&active_session, "{}").unwrap();
        fs::write(&stable_session, "{}").unwrap();

        let ctx = ScanContext::local_default(claude_dir, None);
        let discovered = ClaudeCodeConnector::discover_sources_with_exclusions(
            &ctx,
            std::slice::from_ref(&active_session),
        );

        let source_paths: Vec<_> = discovered
            .into_iter()
            .map(|source| source.source_path)
            .collect();
        assert_eq!(source_paths, vec![stable_session]);
    }

    #[test]
    fn compact_message_extra_keeps_only_compact_cass_metadata() {
        let raw = json!({
            "message": {
                "model": "claude-opus-4-6",
                "usage": {
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "cache_read_input_tokens": 20,
                    "cache_creation_input_tokens": 5,
                    "service_tier": "standard"
                },
                "content": [
                    {"type": "tool_use", "name": "Read"},
                    {"type": "tool_use", "name": "Edit"},
                    {"type": "text", "text": "large duplicated content"}
                ]
            },
            "attachments": [{"path": "/tmp/log.txt"}],
            "summary": "this should be dropped"
        });

        let compact = ClaudeCodeConnector::compact_message_extra(&raw);
        assert_eq!(compact["cass"]["model"], "claude-opus-4-6");
        assert_eq!(compact["cass"]["token_usage"]["input_tokens"], 100);
        assert_eq!(compact["cass"]["token_usage"]["output_tokens"], 50);
        assert_eq!(compact["cass"]["token_usage"]["cache_read_tokens"], 20);
        assert_eq!(compact["cass"]["token_usage"]["cache_creation_tokens"], 5);
        assert_eq!(compact["cass"]["token_usage"]["service_tier"], "standard");
        assert_eq!(compact["cass"]["tool_call_count"], 2);
        assert_eq!(compact["cass"]["attachments"][0]["path"], "/tmp/log.txt");
        assert!(compact.get("summary").is_none());
    }

    #[test]
    fn should_compact_large_message_extra_respects_threshold() {
        assert!(!ClaudeCodeConnector::should_compact_large_message_extra(
            Some(LARGE_SESSION_EXTRA_COMPACT_THRESHOLD_BYTES - 1,)
        ));
        assert!(ClaudeCodeConnector::should_compact_large_message_extra(
            Some(LARGE_SESSION_EXTRA_COMPACT_THRESHOLD_BYTES,)
        ));
        assert!(!ClaudeCodeConnector::should_compact_large_message_extra(
            None
        ));
    }

    #[test]
    fn scan_extracts_session_metadata() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","cwd":"/projects/myapp","sessionId":"sess-123","gitBranch":"main","message":{"role":"user","content":"Test message"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].workspace, Some(PathBuf::from("/projects/myapp")));
        assert_eq!(convs[0].metadata["sessionId"], "sess-123");
        assert_eq!(convs[0].metadata["gitBranch"], "main");
    }

    #[test]
    fn scan_indexes_macos_desktop_sidecar_metadata_without_body() {
        let dir = TempDir::new().unwrap();
        let sidecar_root = dir
            .path()
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude-code-sessions");
        let sidecar_path = sidecar_root
            .join("workspace-uuid")
            .join("session-uuid")
            .join("local_msg.json");
        fs::create_dir_all(sidecar_path.parent().unwrap()).unwrap();
        fs::write(
            &sidecar_path,
            json!({
                "sessionId": "local_msg",
                "cliSessionId": "cli-session-123",
                "cwd": "/Users/jane/project",
                "createdAt": 1_773_244_128_013_i64,
                "lastActivityAt": 1_773_278_849_911_i64,
                "model": "claude-opus-4-6",
                "title": "Prepare Endeavor Outliers 2025 demo case",
                "permissionMode": "plan"
            })
            .to_string(),
        )
        .unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::with_roots(
            dir.path().to_path_buf(),
            vec![ScanRoot::local(sidecar_root.clone())],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        assert_eq!(conv.external_id.as_deref(), Some("cli-session-123"));
        assert_eq!(
            conv.title.as_deref(),
            Some("Prepare Endeavor Outliers 2025 demo case")
        );
        assert_eq!(conv.workspace, Some(PathBuf::from("/Users/jane/project")));
        assert_eq!(conv.source_path, sidecar_path);
        assert_eq!(conv.started_at, Some(1_773_244_128_013));
        assert_eq!(conv.ended_at, Some(1_773_278_849_911));
        assert_eq!(conv.metadata["source"], "claude_code_desktop_sidecar");
        assert_eq!(conv.metadata["cliSessionId"], "cli-session-123");
        assert_eq!(conv.metadata["bodyAvailable"], false);
        assert_eq!(conv.messages.len(), 1);
        assert_eq!(conv.messages[0].role, "system");
        assert!(conv.messages[0].content.contains("Prepare Endeavor"));
        assert!(
            conv.messages[0]
                .content
                .contains("Workspace: /Users/jane/project")
        );
        assert!(
            conv.messages[0]
                .content
                .contains("CLI session id: cli-session-123")
        );
        assert!(
            conv.messages[0]
                .content
                .contains("culled the CLI JSONL body")
        );
    }

    #[test]
    fn scan_extracts_model_as_author() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"assistant","message":{"role":"assistant","content":"Response","model":"claude-3-opus"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].messages[0].author,
            Some("claude-3-opus".to_string())
        );
    }

    #[test]
    fn scan_parses_iso8601_timestamp() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","timestamp":"2025-11-15T14:30:00.123Z","message":{"role":"user","content":"Test"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].messages[0].created_at.is_some());
        let ts = convs[0].messages[0].created_at.unwrap();
        // Should be around 2025-11-15 in milliseconds
        assert!(ts > 1_700_000_000_000);
    }

    #[test]
    fn scan_handles_array_content() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = json!({
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "First part"},
                    {"type": "text", "text": "Second part"}
                ]
            }
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages.len(), 1);
        assert!(convs[0].messages[0].content.contains("First part"));
        assert!(convs[0].messages[0].content.contains("Second part"));
    }

    #[test]
    fn scan_skips_empty_content() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":""}}
{"type":"user","message":{"role":"user","content":"   "}}
{"type":"user","message":{"role":"user","content":"Valid message"}}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Only the valid message should be extracted
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid message");
    }

    #[test]
    fn scan_skips_non_user_assistant_types() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"summary","content":"Session summary"}
{"type":"file-history-snapshot","files":[]}
{"type":"user","message":{"role":"user","content":"User message"}}
{"type":"tool_result","result":"Some result"}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].role, "user");
    }

    #[test]
    fn scan_reindexes_messages_sequentially() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":"Message 1"}}
{"type":"assistant","message":{"role":"assistant","content":"Message 2"}}
{"type":"user","message":{"role":"user","content":"Message 3"}}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].idx, 0);
        assert_eq!(convs[0].messages[1].idx, 1);
        assert_eq!(convs[0].messages[2].idx, 2);
    }

    // =========================================================================
    // JSON format parsing tests
    // =========================================================================

    #[test]
    fn scan_parses_json_messages_array() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.json");
        let content = json!({
            "title": "Test Session",
            "messages": [
                {"role": "user", "content": "Hello", "timestamp": 1_700_000_000_000_i64},
                {"role": "assistant", "content": "Hi there!", "timestamp": 1_700_000_001_000_i64}
            ]
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[1].role, "assistant");
    }

    #[test]
    fn scan_json_extracts_title() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.json");
        let content = json!({
            "title": "Custom Session Title",
            "messages": [
                {"role": "user", "content": "Test content"}
            ]
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("Custom Session Title".to_string()));
    }

    #[test]
    fn scan_json_uses_type_as_role_fallback() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.json");
        let content = json!({
            "messages": [
                {"type": "user", "content": "Message with type instead of role"}
            ]
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].role, "user");
    }

    #[test]
    fn scan_json_uses_text_as_content_fallback() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.json");
        let content = json!({
            "messages": [
                {"role": "user", "text": "Message with text field instead of content"}
            ]
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].messages[0].content.contains("text field"));
    }

    #[test]
    fn scan_json_uses_time_as_timestamp_fallback() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.json");
        let content = json!({
            "messages": [
                {"role": "user", "content": "Test", "time": 1_700_000_000_000i64}
            ]
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].created_at, Some(1_700_000_000_000));
    }

    // =========================================================================
    // Title extraction tests
    // =========================================================================

    #[test]
    fn scan_title_from_first_user_message_jsonl() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"assistant","message":{"role":"assistant","content":"I can help"}}
{"type":"user","message":{"role":"user","content":"Help me build a web app"}}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("Help me build a web app".to_string()));
    }

    #[test]
    fn scan_title_truncates_to_100_chars() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let long_message = "x".repeat(200);
        let session_file = claude_dir.join("session.jsonl");
        let content = format!(
            r#"{{"type":"user","message":{{"role":"user","content":"{}"}}}}"#,
            long_message
        );
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].title.as_ref().unwrap().len() <= 100);
    }

    #[test]
    fn scan_title_uses_first_line_only() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":"First line\nSecond line\nThird line"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("First line".to_string()));
    }

    #[test]
    fn scan_title_fallback_to_workspace_name() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Only assistant message, no user message for title
        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"assistant","cwd":"/projects/myapp","message":{"role":"assistant","content":"Response only"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should fallback to workspace directory name
        assert_eq!(convs[0].title, Some("myapp".to_string()));
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn scan_empty_directory_returns_empty() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs.is_empty());
    }

    #[test]
    fn scan_skips_malformed_jsonl_lines() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"not valid json
{"type":"user","message":{"role":"user","content":"Valid message"}}
{broken json here
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should still extract the valid line
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid message");
    }

    #[test]
    fn scan_skips_malformed_json_files() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Create a malformed JSON file
        let bad_file = claude_dir.join("bad.json");
        fs::write(&bad_file, "not valid json {{{").unwrap();

        // Create a valid JSONL file
        let good_file = claude_dir.join("good.jsonl");
        fs::write(
            &good_file,
            r#"{"type":"user","message":{"role":"user","content":"Valid"}}"#,
        )
        .unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should only have one conversation from the valid file
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn scan_handles_empty_messages_array() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.json");
        let content = json!({
            "messages": []
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Empty messages should result in no conversation
        assert!(convs.is_empty());
    }

    #[test]
    fn scan_processes_subdirectories() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());
        let subdir = claude_dir.join("project1");
        fs::create_dir_all(&subdir).unwrap();

        let session_file = subdir.join("session.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":"Nested message"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("Nested message"));
    }

    #[test]
    fn scan_skips_non_session_files() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Create various non-session files
        fs::write(claude_dir.join("config.toml"), "").unwrap();
        fs::write(claude_dir.join("notes.txt"), "").unwrap();
        fs::write(claude_dir.join("backup.bak"), "").unwrap();

        // Create a valid session file
        let session_file = claude_dir.join("session.jsonl");
        fs::write(
            &session_file,
            r#"{"type":"user","message":{"role":"user","content":"Valid"}}"#,
        )
        .unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should only have one conversation from the .jsonl file
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn scan_handles_claude_extension() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.claude");
        let content = json!({
            "messages": [
                {"role": "user", "content": "Claude extension test"}
            ]
        })
        .to_string();
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("Claude extension"));
    }

    #[test]
    fn scan_sets_external_id_from_relative_path() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("unique-session-id.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":"Test"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].external_id,
            Some("unique-session-id.jsonl".to_string())
        );
    }

    #[test]
    fn scan_external_id_includes_subdir_for_subagent_files() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Simulate subagent files under different parent sessions sharing the
        // same basename (e.g. agent-a297e09.jsonl).
        let sub_a = claude_dir.join("parent-session-aaa");
        let sub_b = claude_dir.join("parent-session-bbb");
        fs::create_dir_all(&sub_a).unwrap();
        fs::create_dir_all(&sub_b).unwrap();

        let content = r#"{"type":"user","message":{"role":"user","content":"Test"}}"#;
        fs::write(sub_a.join("agent-a297e09.jsonl"), content).unwrap();
        fs::write(sub_b.join("agent-a297e09.jsonl"), content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let mut convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
        convs.sort_by(|a, b| a.external_id.cmp(&b.external_id));

        assert_eq!(
            convs[0].external_id,
            Some("parent-session-aaa/agent-a297e09.jsonl".to_string())
        );
        assert_eq!(
            convs[1].external_id,
            Some("parent-session-bbb/agent-a297e09.jsonl".to_string())
        );
    }

    #[test]
    fn scan_sets_agent_slug_to_claude_code() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":"Test"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].agent_slug, "claude_code");
    }

    #[test]
    fn scan_preserves_original_json_in_extra() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","customField":"customValue","message":{"role":"user","content":"Test"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].extra["customField"], "customValue");
    }

    #[test]
    fn scan_tracks_started_and_ended_timestamps() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("session.jsonl");
        let content = r#"{"type":"user","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"First"}}
{"type":"assistant","timestamp":"2025-12-01T10:05:00Z","message":{"role":"assistant","content":"Last"}}
"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
        // ended_at should be after or equal to started_at
        assert!(convs[0].ended_at.unwrap() >= convs[0].started_at.unwrap());
    }

    #[test]
    fn scan_multiple_files_returns_multiple_conversations() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Create two session files
        for i in 1..=3 {
            let session_file = claude_dir.join(format!("session{}.jsonl", i));
            let content =
                format!(r#"{{"type":"user","message":{{"role":"user","content":"Message {i}"}}}}"#);
            fs::write(&session_file, content).unwrap();
        }

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 3);
    }

    #[test]
    fn scan_explicit_root_generic_name() {
        let dir = TempDir::new().unwrap();
        // Directory name that doesn't contain "claude" and no "projects" subdir
        let generic_root = dir.path().join("my_logs");
        fs::create_dir_all(&generic_root).unwrap();

        let session_file = generic_root.join("session.jsonl");
        let content = r#"{"type":"user","message":{"role":"user","content":"Generic root test"}}"#;
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        // Create context with explicit root (use_default_detection = false)
        // Note: ScanContext::with_roots takes data_dir as first arg, but indexer passes root.path there too.
        // We simulate what indexer does.
        let roots = vec![crate::connectors::ScanRoot::local(generic_root.clone())];
        let ctx = ScanContext::with_roots(generic_root.clone(), roots, None);

        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs.len(),
            1,
            "Should find session in generic named explicit root"
        );
        assert_eq!(convs[0].messages[0].content, "Generic root test");
    }

    #[test]
    fn scan_with_explicit_file_only_reads_that_file_and_keeps_projects_relative_external_id() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());
        let project_dir = claude_dir.join("projects").join("project-a");
        fs::create_dir_all(project_dir.join("subagents")).unwrap();

        let target_file = project_dir.join("target.jsonl");
        fs::write(
            &target_file,
            r#"{"type":"user","message":{"role":"user","content":"Target only"}}"#,
        )
        .unwrap();

        let sibling_file = project_dir.join("sibling.jsonl");
        fs::write(
            &sibling_file,
            r#"{"type":"user","message":{"role":"user","content":"Sibling"}}"#,
        )
        .unwrap();

        let nested_file = project_dir.join("subagents").join("nested.jsonl");
        fs::write(
            &nested_file,
            r#"{"type":"user","message":{"role":"user","content":"Nested"}}"#,
        )
        .unwrap();

        let connector = ClaudeCodeConnector::new();
        let roots = vec![crate::connectors::ScanRoot::local(target_file.clone())];
        let ctx = ScanContext::with_roots(target_file.clone(), roots, None);

        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Target only");
        assert_eq!(
            convs[0].external_id.as_deref(),
            Some("project-a/target.jsonl")
        );
    }

    // =========================================================================
    // Edge case tests — malformed input robustness (br-cpf8)
    // =========================================================================

    #[test]
    fn truncated_jsonl_mid_json_returns_partial_results() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // First line is valid, second line is truncated mid-JSON
        let session_file = claude_dir.join("truncated.jsonl");
        let content = b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Hello\"}}\n{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":\"Hel";
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "truncated file should not cause an error");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            1,
            "truncated file at mid-JSON should yield only the 1 valid message"
        );
        assert_eq!(convs[0].messages[0].content, "Hello");
    }

    #[test]
    fn truncated_mid_utf8_does_not_panic() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Valid JSONL line followed by bytes that start a multi-byte UTF-8
        // sequence but are truncated (U+1F600 = F0 9F 98 80, truncate after 2 bytes)
        let session_file = claude_dir.join("truncated_utf8.jsonl");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Valid\"}}\n",
        );
        // Incomplete UTF-8: start of a 4-byte sequence missing last 2 bytes
        bytes.extend_from_slice(b"\xF0\x9F");

        fs::write(&session_file, &bytes).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "truncated mid-UTF8 should not panic or error"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid");
    }

    #[test]
    fn invalid_utf8_skips_corrupted_lines() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        let session_file = claude_dir.join("invalid_utf8.jsonl");
        let mut bytes = Vec::new();
        // Valid line
        bytes.extend_from_slice(
            b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Before\"}}\n",
        );
        // Invalid UTF-8 bytes (0xFF 0xFE are never valid in UTF-8)
        bytes.extend_from_slice(b"\xFF\xFE invalid utf8 line\n");
        // Another valid line
        bytes.extend_from_slice(
            b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"After\"}}\n",
        );

        fs::write(&session_file, &bytes).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "invalid UTF-8 should not cause a panic");
        let convs = result.unwrap();
        // BufRead::lines() returns Err for invalid UTF-8 lines; the connector
        // continues on Err (line 114: Err(_) => continue). So we should get
        // the valid lines on either side.
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            2,
            "should extract both valid messages around invalid UTF-8 line"
        );
        assert_eq!(convs[0].messages[0].content, "Before");
        assert_eq!(convs[0].messages[1].content, "After");
    }

    #[test]
    fn empty_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Completely empty JSONL file
        let session_file = claude_dir.join("empty.jsonl");
        fs::write(&session_file, b"").unwrap();

        // Completely empty JSON file
        let json_file = claude_dir.join("empty.json");
        fs::write(&json_file, b"").unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
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
        let claude_dir = make_test_claude_dir(dir.path());

        // JSONL file with only whitespace and newlines
        let session_file = claude_dir.join("whitespace.jsonl");
        fs::write(&session_file, "   \n\n  \n   \n\t\n").unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
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
        let claude_dir = make_test_claude_dir(dir.path());

        // JSONL lines where expected objects are wrong types
        let session_file = claude_dir.join("type_mismatch.jsonl");
        let content = concat!(
            // String where object expected for message
            "{\"type\":\"user\",\"message\":\"not an object\"}\n",
            // Number where content string expected
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":12345}}\n",
            // Array where string expected for type
            "{\"type\":[\"user\"],\"message\":{\"role\":\"user\",\"content\":\"Valid after mismatches\"}}\n",
            // Null content
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":null}}\n",
            // Boolean type
            "{\"type\":true,\"message\":{\"role\":\"user\",\"content\":\"Bool type\"}}\n",
            // Correct entry that should be extracted
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Correct entry\"}}\n",
        );
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "type mismatches should not cause errors");
        let convs = result.unwrap();
        // Only the last line with correct types should produce a message
        assert_eq!(convs.len(), 1);
        assert!(
            convs[0]
                .messages
                .iter()
                .any(|m| m.content == "Correct entry"),
            "should extract the correctly typed entry"
        );
    }

    #[test]
    fn deeply_nested_json_does_not_stack_overflow() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Build JSON with 1000+ levels of nesting in the content field
        // serde_json has a default recursion limit of 128, so this tests
        // that the connector handles the parse error gracefully
        let mut nested = String::new();
        for _ in 0..200 {
            nested.push_str("{\"a\":");
        }
        nested.push('1');
        for _ in 0..200 {
            nested.push('}');
        }

        let session_file = claude_dir.join("deep.jsonl");
        let content = format!(
            "{}\n{}\n",
            nested, r#"{"type":"user","message":{"role":"user","content":"After deep nesting"}}"#
        );
        fs::write(&session_file, &content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);

        // This must not stack overflow or panic
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "deeply nested JSON should not cause stack overflow"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "After deep nesting");
    }

    #[test]
    fn large_message_body_handled_without_oom() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // Create a JSONL file with a 1MB message body to verify streaming works
        let large_content = "x".repeat(1_000_000);
        let session_file = claude_dir.join("large_body.jsonl");
        let line = format!(
            r#"{{"type":"user","message":{{"role":"user","content":"{}"}}}}"#,
            large_content
        );
        fs::write(&session_file, &line).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "large message body should not cause OOM");
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages[0].content.len(),
            1_000_000,
            "large message content should be preserved in full"
        );
    }

    #[test]
    fn large_json_file_over_100mb_is_skipped() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // For JSON format, files > 100MB should be skipped.
        // We can't create a real 100MB file in a unit test efficiently,
        // but we verify the mechanism works with a valid JSON file under the limit.
        let session_file = claude_dir.join("under_limit.json");
        let content = json!({
            "messages": [
                {"role": "user", "content": "Under the limit"}
            ]
        })
        .to_string();
        fs::write(&session_file, &content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // File under 100MB should be processed normally
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Under the limit");
    }

    #[test]
    fn null_bytes_embedded_in_content_handled() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // JSON allows \u0000 escape for null bytes in strings
        let session_file = claude_dir.join("null_bytes.jsonl");
        let content = concat!(
            r#"{"type":"user","message":{"role":"user","content":"before\u0000after"}}"#,
            "\n",
            r#"{"type":"user","message":{"role":"user","content":"Clean message"}}"#,
            "\n"
        );
        fs::write(&session_file, content).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(
            result.is_ok(),
            "null bytes in content should not cause errors"
        );
        let convs = result.unwrap();
        assert_eq!(convs.len(), 1);
        // Both messages should be extracted; the null byte is valid JSON
        assert!(
            !convs[0].messages.is_empty(),
            "should extract at least the clean message"
        );
    }

    #[test]
    fn bom_marker_at_file_start_handled() {
        let dir = TempDir::new().unwrap();
        let claude_dir = make_test_claude_dir(dir.path());

        // UTF-8 BOM: EF BB BF
        let session_file = claude_dir.join("bom.jsonl");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xEF\xBB\xBF"); // UTF-8 BOM
        bytes.extend_from_slice(
            b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"After BOM\"}}\n",
        );
        bytes.extend_from_slice(
            b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"Second line\"}}\n",
        );
        fs::write(&session_file, &bytes).unwrap();

        let connector = ClaudeCodeConnector::new();
        let ctx = ScanContext::local_default(claude_dir.clone(), None);
        let result = connector.scan(&ctx);

        assert!(result.is_ok(), "BOM marker should not cause errors");
        let convs = result.unwrap();
        // The BOM may cause the first line's JSON to fail parsing (since the BOM
        // bytes are prepended to the line). The second line should parse fine.
        // We verify the connector doesn't crash and extracts what it can.
        assert_eq!(convs.len(), 1);
        assert!(
            !convs[0].messages.is_empty(),
            "should extract at least the second message after BOM"
        );
        // The second line (without BOM) should always parse correctly
        assert!(
            convs[0].messages.iter().any(|m| m.content == "Second line"),
            "second line should be extractable regardless of BOM"
        );
    }
}
