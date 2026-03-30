//! Shared connector infrastructure.
//!
//! Utilities, data structures, and scan primitives used by all 15 connectors.

pub mod aider;
pub mod amp;
#[cfg(feature = "chatgpt")]
pub mod chatgpt;
pub mod claude_code;
pub mod clawdbot;
pub mod cline;
pub mod codex;
pub mod copilot;
pub mod copilot_cli;
#[cfg(feature = "crush")]
pub mod crush;
#[cfg(feature = "cursor")]
pub mod cursor;
pub mod factory;
pub mod gemini;
pub mod kimi;
pub mod openclaw;
#[cfg(feature = "opencode")]
pub mod opencode;
pub mod path_trie;
pub mod pi_agent;
pub mod qwen;
pub mod scan;
pub mod token_extraction;
pub mod utils;
pub mod vibe;
pub mod workspace_cache;

pub use path_trie::PathTrie;
pub use scan::{ScanContext, ScanRoot};
pub use token_extraction::{
    ExtractedTokenUsage, ModelInfo, TokenDataSource, estimate_tokens_from_content,
    extract_claude_code_tokens, extract_codex_tokens, extract_tokens_for_agent, normalize_model,
};
pub use utils::{
    extract_invocations_from_content_blocks, file_modified_since, flatten_content, parse_timestamp,
    unwrap_skill_invocations,
};
pub use workspace_cache::WorkspaceCache;

use std::path::PathBuf;

use crate::types::{DetectionResult, NormalizedConversation};
use crate::{AgentDetectError, AgentDetectOptions, detect_installed_agents};

/// The interface that all agent connectors implement.
///
/// Each connector knows how to detect whether a particular coding agent
/// is installed and how to scan its conversation history.
pub trait Connector {
    /// Detect whether this agent is installed on the system.
    fn detect(&self) -> DetectionResult;

    /// Scan conversation history for this agent.
    fn scan(&self, ctx: &ScanContext) -> anyhow::Result<Vec<NormalizedConversation>>;

    /// Whether this connector implements true callback-based streaming.
    ///
    /// Connectors that return `true` guarantee `scan_with_callback()` does not
    /// first materialize the full corpus via `scan()`.
    fn supports_streaming_scan(&self) -> bool {
        false
    }

    /// Scan conversation history and emit conversations incrementally.
    ///
    /// Connectors that can stream their traversal should override this to avoid
    /// materializing their full corpus in memory. The default implementation
    /// preserves current behavior by delegating to `scan()`.
    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        for conversation in self.scan(ctx)? {
            on_conversation(conversation)?;
        }
        Ok(())
    }
}

/// Map connector slugs to franken-agent-detection slugs.
fn connector_to_franken_slug(connector_slug: &str) -> String {
    match connector_slug.trim().to_ascii_lowercase().as_str() {
        "claude_code" | "claude-code" => "claude".to_string(),
        "copilot" => "github-copilot".to_string(),
        "copilot_cli" | "copilot-cli" | "gh-copilot" => "copilot_cli".to_string(),
        other => other.to_string(),
    }
}

/// Best-effort detection from franken-agent-detection for supported connectors.
///
/// Returns `None` when a connector is not mapped to the franken slug set.
/// Returns `Some(DetectionResult)` (including `detected=false`) for mapped
/// connectors when the franken report is available.
pub fn franken_detection_for_connector(connector_slug: &str) -> Option<DetectionResult> {
    let slug = connector_to_franken_slug(connector_slug);
    let dashed = slug.replace('_', "-");
    let candidates = if dashed == slug {
        vec![slug]
    } else {
        vec![slug, dashed]
    };

    for candidate in candidates {
        let opts = AgentDetectOptions {
            only_connectors: Some(vec![candidate.clone()]),
            include_undetected: true,
            root_overrides: Vec::new(),
        };

        let report = match detect_installed_agents(&opts) {
            Ok(report) => report,
            Err(AgentDetectError::UnknownConnectors { .. }) => continue,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "franken-agent-detection unavailable; connector detection will report not found"
                );
                return None;
            }
        };

        let entry = report.installed_agents.into_iter().next()?;
        let mut evidence = entry.evidence;
        if evidence.is_empty() {
            evidence.push(format!("franken detect slug={}", entry.slug));
        }
        return Some(DetectionResult {
            detected: entry.detected,
            evidence,
            root_paths: entry.root_paths.into_iter().map(PathBuf::from).collect(),
        });
    }
    None
}

/// Get all available connector factories.
///
/// Returns a vec of (slug, constructor) pairs for every connector compiled into
/// this build. Feature-gated connectors (chatgpt, cursor) are conditionally
/// included based on the enabled Cargo features.
#[allow(clippy::type_complexity)]
pub fn get_connector_factories() -> Vec<(&'static str, fn() -> Box<dyn Connector + Send>)> {
    let mut v: Vec<(&'static str, fn() -> Box<dyn Connector + Send>)> = vec![
        ("codex", || Box::new(codex::CodexConnector::new())),
        ("cline", || Box::new(cline::ClineConnector::new())),
        ("gemini", || Box::new(gemini::GeminiConnector::new())),
        ("claude", || {
            Box::new(claude_code::ClaudeCodeConnector::new())
        }),
        ("clawdbot", || Box::new(clawdbot::ClawdbotConnector::new())),
        ("vibe", || Box::new(vibe::VibeConnector::new())),
        ("amp", || Box::new(amp::AmpConnector::new())),
        ("aider", || Box::new(aider::AiderConnector::new())),
        ("pi_agent", || Box::new(pi_agent::PiAgentConnector::new())),
        ("factory", || Box::new(factory::FactoryConnector::new())),
        ("kimi", || Box::new(kimi::KimiConnector::new())),
        ("openclaw", || Box::new(openclaw::OpenClawConnector::new())),
        ("copilot", || Box::new(copilot::CopilotConnector::new())),
        ("copilot_cli", || {
            Box::new(copilot_cli::CopilotCliConnector::new())
        }),
        ("qwen", || Box::new(qwen::QwenConnector::new())),
    ];
    #[cfg(feature = "opencode")]
    v.push(("opencode", || Box::new(opencode::OpenCodeConnector::new())));
    #[cfg(feature = "chatgpt")]
    v.push(("chatgpt", || Box::new(chatgpt::ChatGptConnector::new())));
    #[cfg(feature = "cursor")]
    v.push(("cursor", || Box::new(cursor::CursorConnector::new())));
    #[cfg(feature = "crush")]
    v.push(("crush", || Box::new(crush::CrushConnector::new())));
    v
}
