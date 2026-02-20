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
pub mod copilot;
pub mod factory;
pub mod gemini;
pub mod path_trie;
pub mod pi_agent;
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
pub use utils::{file_modified_since, flatten_content, parse_timestamp};
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
}

/// Map connector slugs to franken-agent-detection slugs.
fn connector_to_franken_slug(connector_slug: &str) -> String {
    match connector_slug.trim().to_ascii_lowercase().as_str() {
        "claude_code" | "claude-code" => "claude".to_string(),
        "copilot" => "github-copilot".to_string(),
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
