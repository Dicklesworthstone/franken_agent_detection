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
#![cfg_attr(test, allow(clippy::uninlined_format_args, clippy::redundant_clone))]

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
#[cfg(feature = "hermes")]
pub use connectors::hermes::HermesConnector;
#[cfg(feature = "opencode")]
pub use connectors::opencode::OpenCodeConnector;
#[cfg(feature = "connectors")]
pub use connectors::token_extraction::{ExtractedTokenUsage, ModelInfo, TokenDataSource};
#[cfg(feature = "connectors")]
pub use connectors::{
    Connector, DiscoveredSourceFile, DiscoveredSourceRole, PathTrie, ScanContext, ScanRoot,
    WorkspaceCache, aider::AiderConnector, amp::AmpConnector, antigravity::AntigravityConnector,
    claude_code::ClaudeCodeConnector, clawdbot::ClawdbotConnector, cline::ClineConnector,
    codex::CodexConnector, devin::DevinConnector, copilot::CopilotConnector, copilot_cli::CopilotCliConnector,
    estimate_tokens_from_content, extract_claude_code_tokens, extract_codex_tokens,
    extract_invocations_from_content_blocks, extract_tokens_for_agent, factory::FactoryConnector,
    file_modified_since, flatten_content, franken_detection_for_connector, gemini::GeminiConnector,
    get_connector_factories, grok::GrokConnector, kimi::KimiConnector, normalize_model,
    omp::OmpConnector, openclaw::OpenClawConnector, openhands::OpenHandsConnector, parse_timestamp,
    pi_agent::PiAgentConnector, qwen::QwenConnector, token_extraction, vibe::VibeConnector,
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
    "antigravity",
    "chatgpt",
    "claude",
    "clawdbot",
    "cline",
    "codex",
    "continue",
    "copilot_cli",
    "crush",
    "cursor",
    "devin",
    "factory",
    "gemini",
    "github-copilot",
    "goose",
    "grok",
    "hermes",
    "kimi",
    "muse",
    "omp",
    "opencode",
    "openclaw",
    "openhands",
    "pi_agent",
    "qwen",
    "vibe",
    "windsurf",
];

fn canonical_connector_slug(slug: &str) -> Option<&'static str> {
    match slug {
        "aider" | "aider-cli" => Some("aider"),
        "amp" | "amp-cli" => Some("amp"),
        "antigravity" | "agy" | "antigravity-cli" => Some("antigravity"),
        "chatgpt" | "chat-gpt" | "chatgpt-desktop" => Some("chatgpt"),
        "claude" | "claude-code" => Some("claude"),
        "clawdbot" | "clawd-bot" => Some("clawdbot"),
        "cline" => Some("cline"),
        "codex" | "codex-cli" => Some("codex"),
        "continue" | "continue-dev" => Some("continue"),
        "copilot_cli" | "copilot-cli" | "gh-copilot" => Some("copilot_cli"),
        "crush" | "charm-crush" => Some("crush"),
        "cursor" => Some("cursor"),
        "devin" | "devin-cli" => Some("devin"),
        "factory" | "factory-droid" => Some("factory"),
        "gemini" | "gemini-cli" => Some("gemini"),
        "github-copilot" | "copilot" => Some("github-copilot"),
        "goose" | "goose-ai" => Some("goose"),
        "grok" | "grok-cli" | "grok-build" | "xai-grok" => Some("grok"),
        "hermes" | "hermes-agent" => Some("hermes"),
        "kimi" | "kimi-code" | "kimi-ai" => Some("kimi"),
        "muse" | "muse-code" | "muse_code" | "musecode" | "meta-muse" => Some("muse"),
        "omp" | "oh-my-pi" => Some("omp"),
        "opencode" | "open-code" => Some("opencode"),
        "openclaw" | "open-claw" => Some("openclaw"),
        "openhands" | "open-hands" => Some("openhands"),
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
        roots.push(
            home.join(".config/Code - Insiders/User/globalStorage")
                .join(ext),
        );
        roots.push(home.join(".config/VSCodium/User/globalStorage").join(ext));
        roots.push(home.join(".config/Cursor/User/globalStorage").join(ext));
        roots.push(
            home.join("Library/Application Support/Code/User/globalStorage")
                .join(ext),
        );
        roots.push(
            home.join("Library/Application Support/Code - Insiders/User/globalStorage")
                .join(ext),
        );
        roots.push(
            home.join("Library/Application Support/VSCodium/User/globalStorage")
                .join(ext),
        );
        roots.push(
            home.join("Library/Application Support/Cursor/User/globalStorage")
                .join(ext),
        );
        roots.push(
            home.join("AppData/Roaming/Code/User/globalStorage")
                .join(ext),
        );
        roots.push(
            home.join("AppData/Roaming/Code - Insiders/User/globalStorage")
                .join(ext),
        );
        roots.push(
            home.join("AppData/Roaming/VSCodium/User/globalStorage")
                .join(ext),
        );
        roots.push(
            home.join("AppData/Roaming/Cursor/User/globalStorage")
                .join(ext),
        );
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
        "antigravity" => {
            let root = read("CASS_ANTIGRAVITY_DATA_ROOT")?;
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
        "kimi" => {
            let root = read("KIMI_CODE_HOME")?;
            if root.is_empty() {
                return None;
            }
            Some(vec![PathBuf::from(root).join("sessions")])
        }
        "openhands" => {
            let root = read("CASS_OPENHANDS_DATA_ROOT")?;
            if root.is_empty() {
                return None;
            }
            Some(vec![PathBuf::from(root)])
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
        "muse" => {
            let root = read("CASS_MUSE_DATA_ROOT")?;
            if root.is_empty() {
                return None;
            }
            Some(vec![PathBuf::from(root)])
        }
        "grok" => {
            // Mirrors GrokConnector::base_root(): scans honor $GROK_HOME,
            // so detection must too — otherwise a relocated install reports
            // not-found while scan finds sessions.
            let root = read("GROK_HOME")?;
            if root.is_empty() {
                return None;
            }
            let root = PathBuf::from(root);
            Some(vec![root.join("sessions"), root])
        }
        "omp" => {
            let root = read("CASS_OMP_DATA_ROOT")?;
            if root.is_empty() {
                return None;
            }
            Some(vec![PathBuf::from(root)])
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
                &[
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "sourcegraph.amp",
                ],
            );
            maybe_push(
                &mut out,
                &[
                    ".config",
                    "Code - Insiders",
                    "User",
                    "globalStorage",
                    "sourcegraph.amp",
                ],
            );
            maybe_push(
                &mut out,
                &[
                    ".config",
                    "VSCodium",
                    "User",
                    "globalStorage",
                    "sourcegraph.amp",
                ],
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
                    "Library",
                    "Application Support",
                    "Code - Insiders",
                    "User",
                    "globalStorage",
                    "sourcegraph.amp",
                ],
            );
            maybe_push(
                &mut out,
                &[
                    "Library",
                    "Application Support",
                    "VSCodium",
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
            maybe_push(
                &mut out,
                &[
                    "AppData",
                    "Roaming",
                    "Code - Insiders",
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
                    "VSCodium",
                    "User",
                    "globalStorage",
                    "sourcegraph.amp",
                ],
            );
        }
        "chatgpt" => {
            maybe_push(
                &mut out,
                &["Library", "Application Support", "com.openai.chat"],
            );
        }
        "claude" => {
            maybe_push(&mut out, &[".claude"]);
            maybe_push(&mut out, &[".config", "claude"]);
            maybe_push(
                &mut out,
                &[
                    "Library",
                    "Application Support",
                    "Claude",
                    "claude-code-sessions",
                ],
            );
            maybe_push(
                &mut out,
                &[
                    "Library",
                    "Application Support",
                    "Claude",
                    "local-agent-mode-sessions",
                ],
            );
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
            maybe_push(&mut out, &[".config", "Cursor", "User"]);
            maybe_push(
                &mut out,
                &["Library", "Application Support", "Cursor", "User"],
            );
            maybe_push(&mut out, &["AppData", "Roaming", "Cursor", "User"]);
        }
        "devin" => {
            maybe_push(&mut out, &[".local", "bin", "devin"]);
            maybe_push(&mut out, &[".local", "share", "devin"]);
            maybe_push(&mut out, &[".local", "share", "devin", "cli"]);
        }
        "factory" => {
            maybe_push(&mut out, &[".factory"]);
            maybe_push(&mut out, &[".factory", "sessions"]);
            maybe_push(&mut out, &[".factory-droid"]);
            maybe_push(&mut out, &[".config", "factory-droid"]);
        }
        "antigravity" => {
            maybe_push(&mut out, &[".gemini", "antigravity-cli", "conversations"]);
            maybe_push(&mut out, &[".gemini", "antigravity-cli", "brain"]);
            maybe_push(&mut out, &[".gemini", "antigravity-cli"]);
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
            maybe_push(
                &mut out,
                &[
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "github.copilot-chat",
                ],
            );
            maybe_push(
                &mut out,
                &[
                    ".config",
                    "Code - Insiders",
                    "User",
                    "globalStorage",
                    "github.copilot-chat",
                ],
            );
            maybe_push(
                &mut out,
                &[
                    ".config",
                    "VSCodium",
                    "User",
                    "globalStorage",
                    "github.copilot-chat",
                ],
            );
            maybe_push(
                &mut out,
                &[
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "github.copilot-chat",
                ],
            );
            maybe_push(
                &mut out,
                &[
                    "Library",
                    "Application Support",
                    "Code - Insiders",
                    "User",
                    "globalStorage",
                    "github.copilot-chat",
                ],
            );
            maybe_push(
                &mut out,
                &[
                    "Library",
                    "Application Support",
                    "VSCodium",
                    "User",
                    "globalStorage",
                    "github.copilot-chat",
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
                    "github.copilot-chat",
                ],
            );
            maybe_push(
                &mut out,
                &[
                    "AppData",
                    "Roaming",
                    "Code - Insiders",
                    "User",
                    "globalStorage",
                    "github.copilot-chat",
                ],
            );
            maybe_push(
                &mut out,
                &[
                    "AppData",
                    "Roaming",
                    "VSCodium",
                    "User",
                    "globalStorage",
                    "github.copilot-chat",
                ],
            );
        }
        "goose" => {
            maybe_push(&mut out, &[".local", "share", "goose", "sessions"]);
            maybe_push(&mut out, &[".config", "goose"]);
            maybe_push(&mut out, &[".goose", "sessions"]);
            maybe_push(&mut out, &[".goose"]);
        }
        "grok" => {
            // xAI Grok CLI / Grok Build TUI keep their state under ~/.grok/.
            // Probe the sessions directory first (the highest-signal artifact),
            // then the parent so detection still fires for fresh installs that
            // haven't created a session yet. The auth.json file is universally
            // present once `grok` has been authenticated and is a useful
            // additional probe target for accounts that wipe sessions between
            // runs.
            maybe_push(&mut out, &[".grok", "sessions"]);
            maybe_push(&mut out, &[".grok", "auth.json"]);
            maybe_push(&mut out, &[".grok"]);
        }
        "hermes" => {
            maybe_push(&mut out, &[".hermes", "state.db"]);
            maybe_push(&mut out, &[".hermes"]);
        }
        "kimi" => {
            // Modern Kimi Code (0.28+) stores sessions under ~/.kimi-code/;
            // probe it first so detection surfaces the current layout. The
            // legacy ~/.kimi/ layout is retained for older installs.
            maybe_push(&mut out, &[".kimi-code", "sessions"]);
            maybe_push(&mut out, &[".kimi-code"]);
            maybe_push(&mut out, &[".kimi", "sessions"]);
            maybe_push(&mut out, &[".kimi"]);
        }
        "muse" => {
            // Meta's Muse Code CLI (Aug 2026). Layout per a field report
            // (issue #15): XDG data dir holds sessions, XDG config holds
            // auth. Probe the sessions tree first (highest-signal), then
            // auth.json (present once authenticated, survives session
            // wipes), then the parents. macOS placement is unverified —
            // XDG paths only until confirmed.
            maybe_push(&mut out, &[".local", "share", "muse", "sessions"]);
            maybe_push(&mut out, &[".config", "muse", "auth.json"]);
            maybe_push(&mut out, &[".local", "share", "muse"]);
            maybe_push(&mut out, &[".config", "muse"]);
        }
        "opencode" => {
            // The canonical v1.2+ SQLite database. Probed first so diagnostic
            // output surfaces the data file (not the sibling config directory)
            // whenever it exists. See cass issue #188 — `~/.config/opencode/`
            // is the config dir and does NOT hold session data.
            maybe_push(&mut out, &[".local", "share", "opencode", "opencode.db"]);
            maybe_push(&mut out, &[".local", "share", "opencode"]);
            maybe_push(&mut out, &[".config", "opencode", "opencode.db"]);
            maybe_push(&mut out, &[".config", "opencode"]);
        }
        "openclaw" => {
            maybe_push(&mut out, &[".openclaw"]);
            maybe_push(&mut out, &[".openclaw", "agents"]);
        }
        "openhands" => {
            maybe_push(&mut out, &[".openhands", "conversations"]);
            maybe_push(&mut out, &[".openhands"]);
        }
        "omp" => {
            // Oh My Pi (`omp`, https://omp.sh) v18 resolves its store via
            // profiles + XDG (see connectors::omp). Probe the sessions
            // directory first (highest-signal), then the parent so
            // detection still fires for fresh installs that haven't
            // created a session yet, then named-profile and XDG homes.
            maybe_push(&mut out, &[".omp", "agent", "sessions"]);
            maybe_push(&mut out, &[".omp", "agent"]);
            maybe_push(&mut out, &[".omp", "profiles"]);
            if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
                let app = PathBuf::from(xdg).join("omp");
                out.push(app.join("sessions"));
                out.push(app);
            } else {
                maybe_push(&mut out, &[".local", "share", "omp", "sessions"]);
                maybe_push(&mut out, &[".local", "share", "omp"]);
            }
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

    // Preserve probe order — probes are already arranged by priority
    // (see default_probe_roots), so the first existing root is the most
    // preferred display path. A lexicographic sort would cause config
    // directories to shadow data directories — e.g. `.config/opencode`
    // would mask `.local/share/opencode/opencode.db` (cass issue #188).
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
                    tilde(&["Library", "Application Support", "amp"]),
                    tilde(&["AppData", "Roaming", "amp"]),
                    tilde(&[
                        ".config",
                        "Code",
                        "User",
                        "globalStorage",
                        "sourcegraph.amp",
                    ]),
                    tilde(&[
                        ".config",
                        "Code - Insiders",
                        "User",
                        "globalStorage",
                        "sourcegraph.amp",
                    ]),
                    tilde(&[
                        ".config",
                        "VSCodium",
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
                    tilde(&[
                        "Library",
                        "Application Support",
                        "Code - Insiders",
                        "User",
                        "globalStorage",
                        "sourcegraph.amp",
                    ]),
                    tilde(&[
                        "Library",
                        "Application Support",
                        "VSCodium",
                        "User",
                        "globalStorage",
                        "sourcegraph.amp",
                    ]),
                    tilde(&[
                        "AppData",
                        "Roaming",
                        "Code",
                        "User",
                        "globalStorage",
                        "sourcegraph.amp",
                    ]),
                    tilde(&[
                        "AppData",
                        "Roaming",
                        "Code - Insiders",
                        "User",
                        "globalStorage",
                        "sourcegraph.amp",
                    ]),
                    tilde(&[
                        "AppData",
                        "Roaming",
                        "VSCodium",
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
                "claude" => vec![
                    tilde(&[".claude", "projects"]),
                    tilde(&[".claude"]),
                    tilde(&[".config", "claude"]),
                    tilde(&[
                        "Library",
                        "Application Support",
                        "Claude",
                        "claude-code-sessions",
                    ]),
                    tilde(&[
                        "Library",
                        "Application Support",
                        "Claude",
                        "local-agent-mode-sessions",
                    ]),
                ],
                "clawdbot" => vec![tilde(&[".clawdbot", "sessions"]), tilde(&[".clawdbot"])],
                "cline" => {
                    let mut paths = Vec::new();
                    for ext in ["saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline"] {
                        paths.push(tilde(&[".config", "Code", "User", "globalStorage", ext]));
                        paths.push(tilde(&[
                            ".config",
                            "Code - Insiders",
                            "User",
                            "globalStorage",
                            ext,
                        ]));
                        paths.push(tilde(&[
                            ".config",
                            "VSCodium",
                            "User",
                            "globalStorage",
                            ext,
                        ]));
                        paths.push(tilde(&[".config", "Cursor", "User", "globalStorage", ext]));
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
                            "Code - Insiders",
                            "User",
                            "globalStorage",
                            ext,
                        ]));
                        paths.push(tilde(&[
                            "Library",
                            "Application Support",
                            "VSCodium",
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
                        paths.push(tilde(&[
                            "AppData",
                            "Roaming",
                            "Code",
                            "User",
                            "globalStorage",
                            ext,
                        ]));
                        paths.push(tilde(&[
                            "AppData",
                            "Roaming",
                            "Code - Insiders",
                            "User",
                            "globalStorage",
                            ext,
                        ]));
                        paths.push(tilde(&[
                            "AppData",
                            "Roaming",
                            "VSCodium",
                            "User",
                            "globalStorage",
                            ext,
                        ]));
                        paths.push(tilde(&[
                            "AppData",
                            "Roaming",
                            "Cursor",
                            "User",
                            "globalStorage",
                            ext,
                        ]));
                    }
                    paths
                }
                "codex" => vec![tilde(&[".codex", "sessions"])],
                "continue" => vec![tilde(&[".continue", "sessions"]), tilde(&[".continue"])],
                "copilot_cli" => vec![
                    tilde(&[".copilot", "session-state"]),
                    tilde(&[".copilot", "history-session-state"]),
                    tilde(&[".config", "gh-copilot"]),
                    tilde(&[".config", "gh", "copilot"]),
                    tilde(&[".local", "share", "github-copilot"]),
                ],
                "crush" => vec![tilde(&[".crush", "crush.db"]), tilde(&[".crush"])],
                "cursor" => vec![
                    tilde(&[".cursor"]),
                    tilde(&[".config", "Cursor"]),
                    tilde(&[".config", "Cursor", "User"]),
                    tilde(&["Library", "Application Support", "Cursor", "User"]),
                    tilde(&["AppData", "Roaming", "Cursor", "User"]),
                ],
                "devin" => vec![
                    tilde(&[".local", "bin", "devin"]),
                    tilde(&[".local", "share", "devin"]),
                    tilde(&[".local", "share", "devin", "cli"]),
                ],
                "factory" => vec![
                    tilde(&[".factory"]),
                    tilde(&[".factory", "sessions"]),
                    tilde(&[".factory-droid"]),
                    tilde(&[".config", "factory-droid"]),
                ],
                "antigravity" => vec![
                    tilde(&[".gemini", "antigravity-cli", "conversations"]),
                    tilde(&[".gemini", "antigravity-cli", "brain"]),
                    tilde(&[".gemini", "antigravity-cli"]),
                ],
                "gemini" => vec![
                    tilde(&[".gemini", "tmp"]),
                    tilde(&[".gemini"]),
                    tilde(&[".config", "gemini"]),
                ],
                "github-copilot" => vec![
                    tilde(&[".github-copilot"]),
                    tilde(&[".config", "github-copilot"]),
                    tilde(&[
                        ".config",
                        "Code",
                        "User",
                        "globalStorage",
                        "github.copilot-chat",
                    ]),
                    tilde(&[
                        ".config",
                        "Code - Insiders",
                        "User",
                        "globalStorage",
                        "github.copilot-chat",
                    ]),
                    tilde(&[
                        ".config",
                        "VSCodium",
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
                    tilde(&[
                        "Library",
                        "Application Support",
                        "Code - Insiders",
                        "User",
                        "globalStorage",
                        "github.copilot-chat",
                    ]),
                    tilde(&[
                        "Library",
                        "Application Support",
                        "VSCodium",
                        "User",
                        "globalStorage",
                        "github.copilot-chat",
                    ]),
                    tilde(&[
                        "AppData",
                        "Roaming",
                        "Code",
                        "User",
                        "globalStorage",
                        "github.copilot-chat",
                    ]),
                    tilde(&[
                        "AppData",
                        "Roaming",
                        "Code - Insiders",
                        "User",
                        "globalStorage",
                        "github.copilot-chat",
                    ]),
                    tilde(&[
                        "AppData",
                        "Roaming",
                        "VSCodium",
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
                "grok" => vec![
                    tilde(&[".grok", "sessions"]),
                    tilde(&[".grok", "auth.json"]),
                    tilde(&[".grok"]),
                ],
                "hermes" => vec![tilde(&[".hermes", "state.db"]), tilde(&[".hermes"])],
                "kimi" => vec![
                    tilde(&[".kimi-code", "sessions"]),
                    tilde(&[".kimi-code"]),
                    tilde(&[".kimi", "sessions"]),
                    tilde(&[".kimi"]),
                ],
                "muse" => vec![
                    tilde(&[".local", "share", "muse", "sessions"]),
                    tilde(&[".config", "muse", "auth.json"]),
                    tilde(&[".local", "share", "muse"]),
                    tilde(&[".config", "muse"]),
                ],
                "opencode" => vec![
                    // Direct path to the v1.2+ SQLite database — probed first
                    // so display/diagnostics surface the data file (not the
                    // sibling config dir). See cass issue #188.
                    tilde(&[".local", "share", "opencode", "opencode.db"]),
                    tilde(&[".local", "share", "opencode"]),
                    tilde(&[".config", "opencode", "opencode.db"]),
                    tilde(&[".config", "opencode"]),
                ],
                "openclaw" => vec![tilde(&[".openclaw", "agents"]), tilde(&[".openclaw"])],
                "openhands" => vec![
                    tilde(&[".openhands", "conversations"]),
                    tilde(&[".openhands"]),
                ],
                "omp" => vec![
                    // Oh My Pi (`omp`, https://omp.sh) canonical stores; the
                    // dedicated omp connector owns these roots. Remote
                    // probes are static paths, so named profiles use the
                    // profiles parent and XDG uses the conventional
                    // ~/.local/share location.
                    tilde(&[".omp", "agent", "sessions"]),
                    tilde(&[".omp", "agent"]),
                    tilde(&[".omp", "profiles"]),
                    tilde(&[".local", "share", "omp", "sessions"]),
                    tilde(&[".local", "share", "omp"]),
                ],
                "pi_agent" => vec![tilde(&[".pi", "agent", "sessions"])],
                "qwen" => vec![tilde(&[".qwen", "tmp"]), tilde(&[".qwen"])],
                "vibe" => vec![tilde(&[".vibe", "logs", "session"]), tilde(&[".vibe"])],
                "windsurf" => vec![tilde(&[".windsurf"]), tilde(&[".config", "windsurf"])],
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
    fn omp_connector_detects_via_overrides_and_aliases() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sessions = tmp.path().join(".omp").join("agent").join("sessions");
        std::fs::create_dir_all(&sessions).expect("mkdir omp sessions");

        // "oh-my-pi" alias must canonicalize to the omp connector.
        let report = detect_installed_agents(&AgentDetectOptions {
            only_connectors: Some(vec!["oh-my-pi".to_string()]),
            include_undetected: true,
            root_overrides: vec![AgentDetectRootOverride {
                slug: "omp".to_string(),
                root: sessions,
            }],
        })
        .expect("detect");

        assert_eq!(report.summary.total_count, 1);
        assert_eq!(report.summary.detected_count, 1);
        let entry = &report.installed_agents[0];
        assert_eq!(entry.slug, "omp");
        assert!(entry.detected);
    }

    #[test]
    fn unknown_connectors_are_rejected() {
        let err = detect_installed_agents(&AgentDetectOptions {
            only_connectors: Some(vec!["not-a-real-connector".to_string()]),
            include_undetected: true,
            root_overrides: vec![],
        })
        .expect_err("should error");

        let err_msg = err.to_string();
        assert!(
            matches!(
                err,
                AgentDetectError::UnknownConnectors { connectors }
                    if connectors == vec!["not-a-real-connector".to_string()]
            ),
            "unexpected error: {err_msg}"
        );
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

        let err_msg = err.to_string();
        assert!(
            matches!(
                err,
                AgentDetectError::UnknownConnectors { connectors }
                    if connectors == vec!["definitely-unknown".to_string()]
            ),
            "unexpected error: {err_msg}"
        );
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
        let root = amp_xdg_probe_root_from_env_value("  /tmp/cass-xdg  ").expect("amp xdg root");
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
                    .join(".config/Code - Insiders/User/globalStorage/saoudrizwan.claude-dev")
            ),
            "expected VS Code Insiders Cline storage root in {roots:?}"
        );
        assert!(
            roots.contains(
                &tmp.path()
                    .join(".config/VSCodium/User/globalStorage/saoudrizwan.claude-dev")
            ),
            "expected VSCodium Cline storage root in {roots:?}"
        );
        assert!(
            roots.contains(
                &tmp.path()
                    .join(".config/Cursor/User/globalStorage/rooveterinaryinc.roo-cline")
            ),
            "expected Cursor Roo-Cline storage root in {roots:?}"
        );
    }

    #[test]
    fn default_probe_paths_tilde_covers_expected_roots() {
        let mut by_slug: std::collections::HashMap<&'static str, Vec<String>> =
            std::collections::HashMap::new();
        for (slug, paths) in default_probe_paths_tilde() {
            by_slug.insert(slug, paths);
        }

        let factory = by_slug.get("factory").expect("factory paths");
        assert!(factory.contains(&"~/.factory".to_string()));
        assert!(factory.contains(&"~/.factory/sessions".to_string()));
        assert!(factory.contains(&"~/.factory-droid".to_string()));
        assert!(factory.contains(&"~/.config/factory-droid".to_string()));

        let amp = by_slug.get("amp").expect("amp paths");
        assert!(
            amp.contains(
                &"~/.config/Code - Insiders/User/globalStorage/sourcegraph.amp".to_string()
            )
        );
        assert!(
            amp.contains(
                &"~/Library/Application Support/VSCodium/User/globalStorage/sourcegraph.amp"
                    .to_string()
            )
        );

        let opencode = by_slug.get("opencode").expect("opencode paths");
        assert!(opencode.contains(&"~/.local/share/opencode".to_string()));
        assert!(opencode.contains(&"~/.config/opencode".to_string()));

        let copilot = by_slug.get("github-copilot").expect("github-copilot paths");
        assert!(
            copilot.contains(&"~/.config/Code/User/globalStorage/github.copilot-chat".to_string())
        );
        assert!(
            copilot.contains(
                &"~/Library/Application Support/Code/User/globalStorage/github.copilot-chat"
                    .to_string()
            )
        );
        assert!(copilot.contains(
            &"~/AppData/Roaming/Code/User/globalStorage/github.copilot-chat".to_string()
        ));
        assert!(copilot.contains(&"~/.github-copilot".to_string()));
        assert!(copilot.contains(&"~/.config/github-copilot".to_string()));

        let cursor = by_slug.get("cursor").expect("cursor paths");
        assert!(cursor.contains(&"~/.config/Cursor".to_string()));
        assert!(cursor.contains(&"~/.config/Cursor/User".to_string()));
        assert!(cursor.contains(&"~/Library/Application Support/Cursor/User".to_string()));
        assert!(cursor.contains(&"~/AppData/Roaming/Cursor/User".to_string()));

        let windsurf = by_slug.get("windsurf").expect("windsurf paths");
        assert!(windsurf.contains(&"~/.config/windsurf".to_string()));

        let hermes = by_slug.get("hermes").expect("hermes paths");
        assert!(hermes.contains(&"~/.hermes/state.db".to_string()));
        assert!(hermes.contains(&"~/.hermes".to_string()));

        let grok = by_slug.get("grok").expect("grok paths");
        assert!(grok.contains(&"~/.grok/sessions".to_string()));
        assert!(grok.contains(&"~/.grok/auth.json".to_string()));
        assert!(grok.contains(&"~/.grok".to_string()));

        let muse = by_slug.get("muse").expect("muse paths");
        assert!(muse.contains(&"~/.local/share/muse/sessions".to_string()));
        assert!(muse.contains(&"~/.config/muse/auth.json".to_string()));
        assert!(muse.contains(&"~/.local/share/muse".to_string()));
        assert!(muse.contains(&"~/.config/muse".to_string()));

        let kimi = by_slug.get("kimi").expect("kimi paths");
        assert!(kimi.contains(&"~/.kimi-code/sessions".to_string()));
        assert!(kimi.contains(&"~/.kimi-code".to_string()));
        assert!(kimi.contains(&"~/.kimi/sessions".to_string()));
        assert!(kimi.contains(&"~/.kimi".to_string()));

        // Oh My Pi (`omp`) now has its own first-class connector; pi_agent
        // is scoped back to the upstream pi-mono home only.
        let pi_agent = by_slug.get("pi_agent").expect("pi_agent paths");
        assert!(pi_agent.contains(&"~/.pi/agent/sessions".to_string()));
        assert!(!pi_agent.iter().any(|p| p.contains(".omp")));

        let omp = by_slug.get("omp").expect("omp paths");
        assert!(omp.contains(&"~/.omp/agent/sessions".to_string()));
        assert!(omp.contains(&"~/.omp/agent".to_string()));

        let cline = by_slug.get("cline").expect("cline paths");
        assert!(
            cline.contains(&"~/.config/Code/User/globalStorage/saoudrizwan.claude-dev".to_string())
        );
        assert!(cline.contains(
            &"~/.config/Code - Insiders/User/globalStorage/saoudrizwan.claude-dev".to_string()
        ));
        assert!(
            cline.contains(
                &"~/.config/VSCodium/User/globalStorage/saoudrizwan.claude-dev".to_string()
            )
        );
        assert!(cline.contains(
            &"~/AppData/Roaming/Cursor/User/globalStorage/rooveterinaryinc.roo-cline".to_string()
        ));
    }

    /// Registry invariants: the five registration points
    /// (`KNOWN_CONNECTORS`, `canonical_connector_slug`,
    /// `default_probe_roots`, `default_probe_paths_tilde`, and the factory
    /// list) must agree exactly. Range-editing one table has twice silently
    /// dropped a sibling row (kimi/openclaw module arms, "open-claw" alias);
    /// this pins every table to the slug set mechanically.
    #[test]
    fn registry_tables_agree_exactly() {
        let known: HashSet<&str> = KNOWN_CONNECTORS.iter().copied().collect();
        assert!(!known.is_empty());

        // 1. Every known connector resolves to itself (canonical self-arm).
        for slug in KNOWN_CONNECTORS {
            assert_eq!(
                canonical_connector_slug(slug),
                Some(*slug),
                "connector {slug} must be its own canonical slug"
            );
        }

        // 2. Every known connector has default probe roots.
        for slug in KNOWN_CONNECTORS {
            assert!(
                !default_probe_roots(slug).is_empty(),
                "connector {slug} must have at least one default probe root"
            );
        }

        // 3. The tilde table covers exactly the known set — no missing rows,
        // no orphaned rows for retired slugs.
        let tilde_slugs: Vec<&str> = default_probe_paths_tilde()
            .into_iter()
            .map(|(slug, _)| slug)
            .collect();
        let tilde_set: HashSet<&str> = tilde_slugs.iter().copied().collect();
        assert_eq!(
            tilde_set,
            known,
            "tilde table slugs must equal KNOWN_CONNECTORS; missing={:?} extra={:?}",
            known.difference(&tilde_set).collect::<Vec<_>>(),
            tilde_set.difference(&known).collect::<Vec<_>>(),
        );
        assert_eq!(
            tilde_slugs.len(),
            tilde_set.len(),
            "tilde table must not repeat a connector"
        );
        for (slug, paths) in default_probe_paths_tilde() {
            assert!(!paths.is_empty(), "connector {slug} has empty tilde paths");
        }

        // 4. The compiled factory registry covers every scanning connector.
        // Detection-only slugs (no scan implementation) are enumerated so a
        // new full connector can't be forgotten: add it to
        // `get_connector_factories` or to this allowlist. Connectors that
        // live behind their own cargo feature (SQLite/crypto deps) register
        // only when compiled in, so they are checked against `cfg!` rather
        // than assumed present — this leg must hold for `--features
        // connectors`, `--all-features`, and every mix in between. The
        // factory list itself only exists with `connectors` (`default = []`),
        // so the leg is gated; checks 1-3 still run under a plain
        // `cargo test`.
        #[cfg(feature = "connectors")]
        {
            // Slugs with no scan implementation at all (no module under
            // `connectors/`). Everything else must register a factory.
            let detection_only: HashSet<&str> = HashSet::from(["continue", "windsurf"]);
            let feature_gated: HashMap<&str, bool> = HashMap::from([
                ("chatgpt", cfg!(feature = "chatgpt")),
                ("crush", cfg!(feature = "crush")),
                ("cursor", cfg!(feature = "cursor")),
                ("goose", cfg!(feature = "goose")),
                ("hermes", cfg!(feature = "hermes")),
                ("opencode", cfg!(feature = "opencode")),
            ]);
            // Factory slugs are the connector-native names (e.g. `copilot`
            // for VS Code Copilot chat, which this registry knows as
            // `github-copilot`), so compare after canonicalising. Every
            // factory must map into KNOWN_CONNECTORS: a factory registered
            // under a slug the registry cannot name is unreachable from
            // `franken_detection_for_connector`, and a slug registered twice
            // means two factories fight over one connector.
            let mut factory_slugs: HashSet<&str> = HashSet::new();
            for (raw, _) in get_connector_factories() {
                let canonical = canonical_connector_slug(raw).unwrap_or_else(|| {
                    panic!("factory slug {raw} does not canonicalise into KNOWN_CONNECTORS")
                });
                assert!(
                    factory_slugs.insert(canonical),
                    "connector {canonical} is registered twice in the factory list (via {raw})"
                );
            }
            for slug in KNOWN_CONNECTORS {
                if detection_only.contains(slug) {
                    assert!(
                        !factory_slugs.contains(slug),
                        "connector {slug} has a factory and must leave the detection-only allowlist"
                    );
                    continue;
                }
                match feature_gated.get(slug) {
                    Some(false) => assert!(
                        !factory_slugs.contains(slug),
                        "connector {slug} registered a factory although its cargo feature is off"
                    ),
                    Some(true) | None => assert!(
                        factory_slugs.contains(slug),
                        "connector {slug} needs a factory registration, a feature gate entry, or a detection-only listing"
                    ),
                }
            }
        }
    }
}
