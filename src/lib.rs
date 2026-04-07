//! Local coding-agent installation detection.
//!
//! Provides synchronous, filesystem-based probes for known coding-agent CLIs.
//!
//! ## Types
//!
//! The [`types`] module contains normalized types for representing agent conversations:
//! - [`DetectionResult`](types::DetectionResult) — always available
//! - [`NormalizedConversation`], [`NormalizedMessage`], [`NormalizedSnippet`]
//!   — available with the `connectors` feature

#![forbid(unsafe_code)]

#[cfg(feature = "connectors")]
pub mod connectors;
pub mod types;

// Re-export core types at crate root for convenience.
pub use types::DetectionResult;
#[cfg(feature = "connectors")]
pub use types::{
    // Scan & provenance types
    LOCAL_SOURCE_ID,
    NormalizedConversation,
    NormalizedInvocation,
    NormalizedMessage,
    NormalizedSnippet,
    Origin,
    PathMapping,
    Platform,
    SourceKind,
    reindex_messages,
};
// Re-export connector infrastructure at crate root.
#[cfg(feature = "chatgpt")]
pub use connectors::chatgpt::ChatGptConnector;
#[cfg(feature = "crush")]
pub use connectors::crush::CrushConnector;
#[cfg(feature = "cursor")]
pub use connectors::cursor::CursorConnector;
#[cfg(feature = "goose")]
pub use connectors::goose::GooseConnector;
#[cfg(feature = "opencode")]
pub use connectors::opencode::OpenCodeConnector;
#[cfg(feature = "connectors")]
pub use connectors::token_extraction::{ExtractedTokenUsage, ModelInfo, TokenDataSource};
#[cfg(feature = "connectors")]
pub use connectors::{
    Connector, PathTrie, ScanContext, ScanRoot, WorkspaceCache, aider::AiderConnector,
    amp::AmpConnector, claude_code::ClaudeCodeConnector, clawdbot::ClawdbotConnector,
    cline::ClineConnector, codex::CodexConnector, copilot::CopilotConnector,
    copilot_cli::CopilotCliConnector, estimate_tokens_from_content, extract_claude_code_tokens,
    extract_codex_tokens, extract_tokens_for_agent, factory::FactoryConnector, file_modified_since,
    extract_invocations_from_content_blocks, flatten_content,
    franken_detection_for_connector, gemini::GeminiConnector,
    get_connector_factories, kimi::KimiConnector, normalize_model, openclaw::OpenClawConnector,
    parse_timestamp, pi_agent::PiAgentConnector, qwen::QwenConnector, token_extraction,
    vibe::VibeConnector,
};

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct AgentDetectOptions {
    /// Restrict detection to specific connector slugs (e.g. `["codex", "gemini"]`).
    ///
    /// When `None`, all known connectors are evaluated.
    pub only_connectors: Option<Vec<String>>,

    /// When false, omit entries that were not detected.
    pub include_undetected: bool,

    /// Optional per-connector root overrides for deterministic detection (tests/fixtures).
    pub root_overrides: Vec<AgentDetectRootOverride>,
}

#[derive(Debug, Clone)]
pub struct AgentDetectRootOverride {
    pub slug: String,
    pub root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledAgentDetectionSummary {
    pub detected_count: usize,
    pub total_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledAgentDetectionEntry {
    /// Stable connector/agent identifier (e.g. `codex`, `claude`, `gemini`).
    pub slug: String,
    pub detected: bool,
    pub evidence: Vec<String>,
    pub root_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledAgentDetectionReport {
    pub format_version: u32,
    pub generated_at: String,
    pub installed_agents: Vec<InstalledAgentDetectionEntry>,
    pub summary: InstalledAgentDetectionSummary,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentDetectError {
    #[error("agent detection is disabled (compile with feature `agent-detect`)")]
    FeatureDisabled,

    #[error("unknown connector(s): {connectors:?}")]
    UnknownConnectors { connectors: Vec<String> },
}

const KNOWN_CONNECTORS: &[&str] = &[
    "aider",
    "amp",
    "chatgpt",
    "claude",
    "clawdbot",
    "cline",
    "codex",
    "continue",
    "copilot_cli",
    "crush",
    "cursor",
    "factory",
    "gemini",
    "github-copilot",
    "goose",
    "kimi",
    "opencode",
    "openclaw",
    "pi_agent",
    "qwen",
    "vibe",
    "windsurf",
];

fn canonical_connector_slug(slug: &str) -> Option<&'static str> {
    match slug {
        "aider" | "aider-cli" => Some("aider"),
        "amp" | "amp-cli" => Some("amp"),
        "chatgpt" | "chat-gpt" | "chatgpt-desktop" => Some("chatgpt"),
        "claude" | "claude-code" => Some("claude"),
        "clawdbot" | "clawd-bot" => Some("clawdbot"),
        "cline" => Some("cline"),
        "codex" | "codex-cli" => Some("codex"),
        "continue" | "continue-dev" => Some("continue"),
        "copilot_cli" | "copilot-cli" | "gh-copilot" => Some("copilot_cli"),
        "crush" | "charm-crush" => Some("crush"),
        "cursor" => Some("cursor"),
        "factory" | "factory-droid" => Some("factory"),
        "gemini" | "gemini-cli" => Some("gemini"),
        "github-copilot" | "copilot" => Some("github-copilot"),
        "goose" | "goose-ai" => Some("goose"),
        "kimi" | "kimi-code" | "kimi-ai" => Some("kimi"),
        "opencode" | "open-code" => Some("opencode"),
        "openclaw" | "open-claw" => Some("openclaw"),
        "pi_agent" | "pi-agent" | "piagent" => Some("pi_agent"),
        "qwen" | "qwen-code" | "qwen-cli" => Some("qwen"),
        "vibe" | "vibe-cli" => Some("vibe"),
        "windsurf" => Some("windsurf"),
        _ => None,
    }
}

fn normalize_slug(raw: &str) -> Option<String> {
    let slug = raw.trim().to_ascii_lowercase();
    if slug.is_empty() { None } else { Some(slug) }
}

fn canonical_or_normalized_slug(raw: &str) -> Option<String> {
    let normalized = normalize_slug(raw)?;
    Some(canonical_connector_slug(&normalized).map_or(normalized, std::string::ToString::to_string))
}

fn home_join(parts: &[&str]) -> Option<PathBuf> {
    let mut path = dirs::home_dir()?;
    for part in parts {
        path.push(part);
    }
    Some(path)
}

fn cwd_join(parts: &[&str]) -> Option<PathBuf> {
    let mut path = std::env::current_dir().ok()?;
    for part in parts {
        path.push(part);
    }
    Some(path)
}

fn amp_xdg_probe_root_from_env_value(xdg_data_home: &str) -> Option<PathBuf> {
    let trimmed = xdg_data_home.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(PathBuf::from(trimmed).join("amp"))
}

fn amp_xdg_probe_root_from_env() -> Option<PathBuf> {
    std::env::var("XDG_DATA_HOME")
        .ok()
        .and_then(|value| amp_xdg_probe_root_from_env_value(&value))
}

fn cline_storage_probe_roots_from_home(home: &std::path::Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for ext in ["saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline"] {
        roots.push(home.join(".config/Code/User/globalStorage").join(ext));
        roots.push(home.join(".config/Cursor/User/globalStorage").join(ext));
        roots.push(
            home.join("Library/Application Support/Code/User/globalStorage")
                .join(ext),
        );
        roots.push(
            home.join("Library/Application Support/Cursor/User/globalStorage")
                .join(ext),
        );
        roots.push(home.join("AppData/Roaming/Code/User/globalStorage").join(ext));
        roots.push(home.join("AppData/Roaming/Cursor/User/globalStorage").join(ext));
    }
    roots
}

fn env_override_roots(slug: &str) -> Option<Vec<PathBuf>> {
    let read = |key: &str| std::env::var(key).ok().map(|v| v.trim().to_string());

    match slug {
        "aider" => {
            let root = read("CASS_AIDER_DATA_ROOT")?;
            if root.is_empty() {
                return None;
            }
            Some(vec![PathBuf::from(root)])
        }
        "codex" => {
            let root = read("CODEX_HOME")?;
            if root.is_empty() {
                return None;
            }
            Some(vec![PathBuf::from(root).join("sessions")])
        }
        "pi_agent" => {
            let root = read("PI_CODING_AGENT_DIR")?;
            if root.is_empty() {
                return None;
            }
            Some(vec![PathBuf::from(root).join("sessions")])
        }
        "goose" => {
            let root = read("GOOSE_PATH_ROOT")?;
            if root.is_empty() {
                return None;
            }
            Some(vec![PathBuf::from(root).join("data").join("sessions")])
        }
        _ => None,
    }
}

#[allow(clippy::too_many_lines)]
fn default_probe_roots(slug: &str) -> Vec<PathBuf> {
    fn maybe_push(out: &mut Vec<PathBuf>, parts: &[&str]) {
        if let Some(path) = home_join(parts) {
            out.push(path);
        }
    }

    let mut out = Vec::new();

    match slug {
        "aider" => {
            maybe_push(&mut out, &[".aider.chat.history.md"]);
            maybe_push(&mut out, &[".aider"]);
            if let Some(cwd_marker) = cwd_join(&[".aider.chat.history.md"]) {
                out.push(cwd_marker);
            }
        }
        "amp" => {
            if let Some(path) = amp_xdg_probe_root_from_env() {
                out.push(path);
            }
            maybe_push(&mut out, &[".local", "share", "amp"]);
            maybe_push(&mut out, &["Library", "Application Support", "amp"]);
            maybe_push(&mut out, &["AppData", "Roaming", "amp"]);
            maybe_push(
                &mut out,
                &[".config", "Code", "User", "globalStorage", "sourcegraph.amp"],
            );
            maybe_push(
                &mut out,
                &[
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "sourcegraph.amp",
                ],
            );
            maybe_push(
                &mut out,
                &[
                    "AppData",
                    "Roaming",
                    "Code",
                    "User",
                    "globalStorage",
                    "sourcegraph.amp",
                ],
            );
        }
        "chatgpt" => {
            maybe_push(&mut out, &["Library", "Application Support", "com.openai.chat"]);
        }
        "claude" => {
            maybe_push(&mut out, &[".claude"]);
            maybe_push(&mut out, &[".config", "claude"]);
        }
        "clawdbot" => {
            maybe_push(&mut out, &[".clawdbot"]);
            maybe_push(&mut out, &[".clawdbot", "sessions"]);
        }
        "cline" => {
            if let Some(home) = dirs::home_dir() {
                out.extend(cline_storage_probe_roots_from_home(&home));
            }
        }
        "codex" => {
            maybe_push(&mut out, &[".codex", "sessions"]);
        }
        "continue" => {
            maybe_push(&mut out, &[".continue", "sessions"]);
            maybe_push(&mut out, &[".continue"]);
        }
        "copilot_cli" => {
            maybe_push(&mut out, &[".copilot", "session-state"]);
            maybe_push(&mut out, &[".copilot", "history-session-state"]);
            maybe_push(&mut out, &[".config", "gh-copilot"]);
            maybe_push(&mut out, &[".config", "gh", "copilot"]);
            maybe_push(&mut out, &[".local", "share", "github-copilot"]);
        }
        "crush" => {
            maybe_push(&mut out, &[".crush"]);
            maybe_push(&mut out, &[".crush", "crush.db"]);
        }
        "cursor" => {
            maybe_push(&mut out, &[".cursor"]);
            maybe_push(&mut out, &[".config", "Cursor"]);
        }
        "factory" => {
            maybe_push(&mut out, &[".factory-droid"]);
            maybe_push(&mut out, &[".config", "factory-droid"]);
        }
        "gemini" => {
            maybe_push(&mut out, &[".gemini"]);
            maybe_push(&mut out, &[".config", "gemini"]);
        }
        "github-copilot" => {
            maybe_push(&mut out, &[".github-copilot"]);
            maybe_push(&mut out, &[".config", "github-copilot"]);
            maybe_push(&mut out, &[".copilot", "session-state"]);
            maybe_push(&mut out, &[".copilot", "history-session-state"]);
        }
        "goose" => {
            maybe_push(&mut out, &[".local", "share", "goose", "sessions"]);
            maybe_push(&mut out, &[".config", "goose"]);
            maybe_push(&mut out, &[".goose", "sessions"]);
            maybe_push(&mut out, &[".goose"]);
        }
        "kimi" => {
            maybe_push(&mut out, &[".kimi", "sessions"]);
            maybe_push(&mut out, &[".kimi"]);
        }
        "opencode" => {
            maybe_push(&mut out, &[".opencode"]);
            maybe_push(&mut out, &[".config", "opencode"]);
        }
        "openclaw" => {
            maybe_push(&mut out, &[".openclaw"]);
            maybe_push(&mut out, &[".openclaw", "agents"]);
        }
        "pi_agent" => {
            maybe_push(&mut out, &[".pi", "agent", "sessions"]);
        }
        "qwen" => {
            maybe_push(&mut out, &[".qwen", "tmp"]);
            maybe_push(&mut out, &[".qwen"]);
        }
        "vibe" => {
            maybe_push(&mut out, &[".vibe"]);
            maybe_push(&mut out, &[".vibe", "logs", "session"]);
        }
        "windsurf" => {
            maybe_push(&mut out, &[".windsurf"]);
            maybe_push(&mut out, &[".config", "windsurf"]);
        }
        _ => {}
    }

    out
}

fn detect_roots(
    slug: &'static str,
    roots: &[PathBuf],
    source_label: &str,
) -> InstalledAgentDetectionEntry {
    let mut detected = false;
    let mut evidence: Vec<String> = Vec::new();
    let mut root_paths: Vec<String> = Vec::new();

    if roots.is_empty() {
        evidence.push("no probe roots available".to_string());
    }

    for root in roots {
        let root_str = root.display().to_string();
        if root.exists() {
            detected = true;
            root_paths.push(root_str.clone());
            evidence.push(format!("{source_label} root exists: {root_str}"));
        } else {
            evidence.push(format!("{source_label} root missing: {root_str}"));
        }
    }

    root_paths.sort();
    InstalledAgentDetectionEntry {
        slug: slug.to_string(),
        detected,
        evidence,
        root_paths,
    }
}

fn entry_from_detect(slug: &'static str) -> InstalledAgentDetectionEntry {
    if let Some(override_roots) = env_override_roots(slug) {
        return detect_roots(slug, &override_roots, "env");
    }
    let roots = default_probe_roots(slug);
    detect_roots(slug, &roots, "default")
}

fn entry_from_override(slug: &'static str, roots: &[PathBuf]) -> InstalledAgentDetectionEntry {
    detect_roots(slug, roots, "override")
}

fn build_overrides_map(overrides: &[AgentDetectRootOverride]) -> HashMap<String, Vec<PathBuf>> {
    let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for override_root in overrides {
        let Some(slug) = canonical_or_normalized_slug(&override_root.slug) else {
            continue;
        };
        out.entry(slug)
            .or_default()
            .push(override_root.root.clone());
    }
    out
}

fn validate_known_connectors(
    available: &HashSet<&'static str>,
    only: Option<&HashSet<String>>,
    overrides: &HashMap<String, Vec<PathBuf>>,
) -> Result<(), AgentDetectError> {
    let mut unknown: Vec<String> = Vec::new();
    if let Some(only) = only {
        unknown.extend(
            only.iter()
                .filter(|slug| !available.contains(slug.as_str()))
                .cloned(),
        );
    }
    unknown.extend(
        overrides
            .keys()
            .filter(|slug| !available.contains(slug.as_str()))
            .cloned(),
    );
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort();
    unknown.dedup();
    Err(AgentDetectError::UnknownConnectors {
        connectors: unknown,
    })
}

/// Returns default probe paths for all known connectors using tilde-relative paths.
///
/// These paths use `~/` prefix instead of resolved home directories, making them
/// suitable for SSH probe scripts where the remote home directory is unknown.
/// Each entry is `(slug, paths)` where `paths` are bash-friendly strings like
/// `~/.claude/projects`.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn default_probe_paths_tilde() -> Vec<(&'static str, Vec<String>)> {
    fn tilde(parts: &[&str]) -> String {
        let mut path = String::from("~/");
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                path.push('/');
            }
            path.push_str(part);
        }
        path
    }

    KNOWN_CONNECTORS
        .iter()
        .map(|&slug| {
            let paths: Vec<String> = match slug {
                "aider" => vec![tilde(&[".aider.chat.history.md"]), tilde(&[".aider"])],
                "amp" => vec![
                    tilde(&[".local", "share", "amp"]),
                    tilde(&[
                        ".config",
                        "Code",
                        "User",
                        "globalStorage",
                        "sourcegraph.amp",
                    ]),
                    tilde(&[
                        "Library",
                        "Application Support",
                        "Code",
                        "User",
                        "globalStorage",
                        "sourcegraph.amp",
                    ]),
                ],
                "chatgpt" => vec![tilde(&[
                    "Library",
                    "Application Support",
                    "com.openai.chat",
                ])],
                "claude" => vec![tilde(&[".claude", "projects"]), tilde(&[".claude"])],
                "clawdbot" => vec![tilde(&[".clawdbot", "sessions"]), tilde(&[".clawdbot"])],
                "cline" => {
                    let mut paths = Vec::new();
                    for ext in ["saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline"] {
                        paths.push(tilde(&[
                            ".config",
                            "Code",
                            "User",
                            "globalStorage",
                            ext,
                        ]));
                        paths.push(tilde(&[
                            ".config",
                            "Cursor",
                            "User",
                            "globalStorage",
                            ext,
                        ]));
                        paths.push(tilde(&[
                            "Library",
                            "Application Support",
                            "Code",
                            "User",
                            "globalStorage",
                            ext,
                        ]));
                        paths.push(tilde(&[
                            "Library",
                            "Application Support",
                            "Cursor",
                            "User",
                            "globalStorage",
                            ext,
                        ]));
                    }
                    paths
                }
                "codex" => vec![tilde(&[".codex", "sessions"])],
                "continue" => vec![tilde(&[".continue", "sessions"])],
                "copilot_cli" => vec![
                    tilde(&[".copilot", "session-state"]),
                    tilde(&[".copilot", "history-session-state"]),
                    tilde(&[".config", "gh-copilot"]),
                    tilde(&[".config", "gh", "copilot"]),
                    tilde(&[".local", "share", "github-copilot"]),
                ],
                "crush" => vec![tilde(&[".crush", "crush.db"]), tilde(&[".crush"])],
                "cursor" => vec![tilde(&[".cursor"])],
                "factory" => vec![tilde(&[".factory", "sessions"])],
                "gemini" => vec![tilde(&[".gemini", "tmp"]), tilde(&[".gemini"])],
                "github-copilot" => vec![
                    tilde(&[
                        ".config",
                        "Code",
                        "User",
                        "globalStorage",
                        "github.copilot-chat",
                    ]),
                    tilde(&[
                        "Library",
                        "Application Support",
                        "Code",
                        "User",
                        "globalStorage",
                        "github.copilot-chat",
                    ]),
                    tilde(&[".config", "gh-copilot"]),
                    // Copilot CLI session-state (v2, since 0.0.342)
                    tilde(&[".copilot", "session-state"]),
                    // Copilot CLI legacy session-state (v1)
                    tilde(&[".copilot", "history-session-state"]),
                ],
                "goose" => vec![
                    tilde(&[".local", "share", "goose", "sessions"]),
                    tilde(&[".config", "goose"]),
                    tilde(&[".goose", "sessions"]),
                    tilde(&[".goose"]),
                ],
                "kimi" => vec![tilde(&[".kimi", "sessions"])],
                "opencode" => vec![tilde(&[".local", "share", "opencode"])],
                "openclaw" => vec![tilde(&[".openclaw", "agents"])],
                "pi_agent" => vec![tilde(&[".pi", "agent", "sessions"])],
                "qwen" => vec![tilde(&[".qwen", "tmp"])],
                "vibe" => vec![tilde(&[".vibe", "logs", "session"])],
                "windsurf" => vec![tilde(&[".windsurf"])],
                _ => vec![],
            };
            (slug, paths)
        })
        .collect()
}

/// Detect installed/available coding agents by running local filesystem probes.
///
/// This returns a stable JSON shape (via `serde`) intended for CLI/resource consumption.
///
/// # Errors
/// Returns [`AgentDetectError::UnknownConnectors`] when `only_connectors`
/// includes unknown slugs.
#[allow(clippy::missing_const_for_fn)]
pub fn detect_installed_agents(
    opts: &AgentDetectOptions,
) -> Result<InstalledAgentDetectionReport, AgentDetectError> {
    let available: HashSet<&'static str> = KNOWN_CONNECTORS.iter().copied().collect();
    let overrides = build_overrides_map(&opts.root_overrides);

    let only: Option<HashSet<String>> = opts.only_connectors.as_ref().map(|slugs| {
        slugs
            .iter()
            .filter_map(|slug| canonical_or_normalized_slug(slug))
            .collect()
    });

    validate_known_connectors(&available, only.as_ref(), &overrides)?;

    let mut all_entries: Vec<InstalledAgentDetectionEntry> = KNOWN_CONNECTORS
        .iter()
        .copied()
        .filter(|slug| only.as_ref().is_none_or(|set| set.contains(*slug)))
        .map(|slug| {
            overrides.get(slug).map_or_else(
                || entry_from_detect(slug),
                |roots| entry_from_override(slug, roots),
            )
        })
        .collect();

    all_entries.sort_by(|a, b| a.slug.cmp(&b.slug));

    let detected_count = all_entries.iter().filter(|entry| entry.detected).count();
    let total_count = all_entries.len();

    Ok(InstalledAgentDetectionReport {
        format_version: 1,
        generated_at: chrono::Utc::now().to_rfc3339(),
        installed_agents: if opts.include_undetected {
            all_entries
        } else {
            all_entries
                .into_iter()
                .filter(|entry| entry.detected)
                .collect()
        },
        summary: InstalledAgentDetectionSummary {
            detected_count,
            total_count,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_installed_agents_can_be_scoped_to_specific_connectors() {
        let tmp = tempfile::tempdir().expect("tempdir");

        let codex_root = tmp.path().join("codex-home").join("sessions");
        std::fs::create_dir_all(&codex_root).expect("create codex sessions");

        let gemini_root = tmp.path().join("gemini-home").join("tmp");
        std::fs::create_dir_all(&gemini_root).expect("create gemini root");

        let report = detect_installed_agents(&AgentDetectOptions {
            only_connectors: Some(vec!["codex".to_string(), "gemini".to_string()]),
            include_undetected: true,
            root_overrides: vec![
                AgentDetectRootOverride {
                    slug: "codex".to_string(),
                    root: codex_root,
                },
                AgentDetectRootOverride {
                    slug: "gemini".to_string(),
                    root: gemini_root.clone(),
                },
            ],
        })
        .expect("detect");

        assert_eq!(report.format_version, 1);
        assert!(!report.generated_at.is_empty());
        assert_eq!(report.summary.total_count, 2);
        assert_eq!(report.summary.detected_count, 2);

        let slugs: Vec<&str> = report
            .installed_agents
            .iter()
            .map(|entry| entry.slug.as_str())
            .collect();
        assert_eq!(slugs, vec!["codex", "gemini"]);

        let codex = report
            .installed_agents
            .iter()
            .find(|entry| entry.slug == "codex")
            .expect("codex entry");
        assert!(codex.detected);
        assert!(
            codex
                .root_paths
                .iter()
                .any(|path| path.ends_with("/sessions"))
        );

        let gemini = report
            .installed_agents
            .iter()
            .find(|entry| entry.slug == "gemini")
            .expect("gemini entry");
        assert!(gemini.detected);
        assert_eq!(gemini.root_paths, vec![gemini_root.display().to_string()]);
    }

    #[test]
    fn unknown_connectors_are_rejected() {
        let err = detect_installed_agents(&AgentDetectOptions {
            only_connectors: Some(vec!["not-a-real-connector".to_string()]),
            include_undetected: true,
            root_overrides: vec![],
        })
        .expect_err("should error");

        match err {
            AgentDetectError::UnknownConnectors { connectors } => {
                assert_eq!(connectors, vec!["not-a-real-connector".to_string()]);
            }
            AgentDetectError::FeatureDisabled => {
                panic!("unexpected error: FeatureDisabled")
            }
        }
    }

    #[test]
    fn unknown_overrides_are_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = detect_installed_agents(&AgentDetectOptions {
            only_connectors: Some(vec!["codex".to_string()]),
            include_undetected: true,
            root_overrides: vec![AgentDetectRootOverride {
                slug: "definitely-unknown".to_string(),
                root: tmp.path().join("does-not-matter"),
            }],
        })
        .expect_err("should error");

        match err {
            AgentDetectError::UnknownConnectors { connectors } => {
                assert_eq!(connectors, vec!["definitely-unknown".to_string()]);
            }
            AgentDetectError::FeatureDisabled => {
                panic!("unexpected error: FeatureDisabled")
            }
        }
    }

    #[test]
    fn cass_connectors_and_aliases_detect_via_overrides() {
        let tmp = tempfile::tempdir().expect("tempdir");

        let aider_file = tmp.path().join("aider").join(".aider.chat.history.md");
        std::fs::create_dir_all(aider_file.parent().expect("aider parent")).expect("mkdir aider");
        std::fs::write(&aider_file, "stub").expect("write aider file");

        let amp_root = tmp.path().join("amp-root");
        std::fs::create_dir_all(&amp_root).expect("mkdir amp");

        let chatgpt_root = tmp.path().join("chatgpt-root");
        std::fs::create_dir_all(&chatgpt_root).expect("mkdir chatgpt");

        let clawdbot_sessions = tmp.path().join("clawdbot").join("sessions");
        std::fs::create_dir_all(&clawdbot_sessions).expect("mkdir clawdbot");

        let openclaw_agents = tmp.path().join("openclaw").join("agents");
        std::fs::create_dir_all(&openclaw_agents).expect("mkdir openclaw");

        let pi_sessions = tmp.path().join("pi").join("agent").join("sessions");
        std::fs::create_dir_all(&pi_sessions).expect("mkdir pi");

        let vibe_sessions = tmp.path().join("vibe").join("logs").join("session");
        std::fs::create_dir_all(&vibe_sessions).expect("mkdir vibe");

        let report = detect_installed_agents(&AgentDetectOptions {
            only_connectors: Some(vec![
                "aider".to_string(),
                "amp".to_string(),
                "chatgpt".to_string(),
                "clawdbot".to_string(),
                "open-claw".to_string(),
                "pi-agent".to_string(),
                "vibe".to_string(),
            ]),
            include_undetected: true,
            root_overrides: vec![
                AgentDetectRootOverride {
                    slug: "aider-cli".to_string(),
                    root: aider_file,
                },
                AgentDetectRootOverride {
                    slug: "amp".to_string(),
                    root: amp_root,
                },
                AgentDetectRootOverride {
                    slug: "chatgpt-desktop".to_string(),
                    root: chatgpt_root,
                },
                AgentDetectRootOverride {
                    slug: "clawdbot".to_string(),
                    root: clawdbot_sessions,
                },
                AgentDetectRootOverride {
                    slug: "open-claw".to_string(),
                    root: openclaw_agents,
                },
                AgentDetectRootOverride {
                    slug: "pi-agent".to_string(),
                    root: pi_sessions.clone(),
                },
                AgentDetectRootOverride {
                    slug: "vibe-cli".to_string(),
                    root: vibe_sessions,
                },
            ],
        })
        .expect("detect");

        assert_eq!(report.summary.total_count, 7);
        assert_eq!(report.summary.detected_count, 7);

        let slugs: Vec<&str> = report
            .installed_agents
            .iter()
            .map(|entry| entry.slug.as_str())
            .collect();
        assert_eq!(
            slugs,
            vec![
                "aider", "amp", "chatgpt", "clawdbot", "openclaw", "pi_agent", "vibe"
            ]
        );

        let pi = report
            .installed_agents
            .iter()
            .find(|entry| entry.slug == "pi_agent")
            .expect("pi_agent entry");
        assert_eq!(pi.root_paths, vec![pi_sessions.display().to_string()]);
    }

    #[test]
    fn amp_xdg_probe_root_uses_trimmed_env_value() {
        let root = amp_xdg_probe_root_from_env_value("  /tmp/cass-xdg  ")
            .expect("amp xdg root");
        assert_eq!(root, PathBuf::from("/tmp/cass-xdg").join("amp"));
    }

    #[test]
    fn amp_xdg_probe_root_rejects_blank_env_value() {
        assert!(amp_xdg_probe_root_from_env_value("   ").is_none());
    }

    #[test]
    fn cline_storage_probe_roots_cover_vscode_and_cursor_layouts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let roots = cline_storage_probe_roots_from_home(tmp.path());

        assert!(
            roots.contains(
                &tmp.path()
                    .join(".config/Code/User/globalStorage/saoudrizwan.claude-dev")
            ),
            "expected VS Code Cline storage root in {roots:?}"
        );
        assert!(
            roots.contains(
                &tmp.path()
                    .join(".config/Cursor/User/globalStorage/rooveterinaryinc.roo-cline")
            ),
            "expected Cursor Roo-Cline storage root in {roots:?}"
        );
    }
}
