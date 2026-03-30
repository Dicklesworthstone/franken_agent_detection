//! Normalized types for representing agent conversations.
//!
//! These are the lingua franca types that ALL connectors produce.
//! Any tool (not just cass) can use these types to work with agent session data.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// High-level detection status for a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub detected: bool,
    pub evidence: Vec<String>,
    pub root_paths: Vec<PathBuf>,
}

impl DetectionResult {
    #[must_use]
    pub const fn not_found() -> Self {
        Self {
            detected: false,
            evidence: Vec::new(),
            root_paths: Vec::new(),
        }
    }
}

/// Normalized conversation emitted by connectors.
#[cfg(feature = "connectors")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedConversation {
    pub agent_slug: String,
    pub external_id: Option<String>,
    pub title: Option<String>,
    pub workspace: Option<PathBuf>,
    pub source_path: PathBuf,
    pub started_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub metadata: serde_json::Value,
    pub messages: Vec<NormalizedMessage>,
}

#[cfg(feature = "connectors")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedMessage {
    pub idx: i64,
    pub role: String,
    pub author: Option<String>,
    pub created_at: Option<i64>,
    pub content: String,
    pub extra: serde_json::Value,
    pub snippets: Vec<NormalizedSnippet>,
    /// Structured tool/skill invocations extracted from this message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invocations: Vec<NormalizedInvocation>,
}

/// A single tool or skill invocation within a message.
#[cfg(feature = "connectors")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedInvocation {
    /// Classification: `"tool"` or `"skill"`.
    pub kind: String,
    /// Canonical searchable name (e.g. `"github-prs"`, `"Read"`, `"bash"`).
    /// For wrapper tools like Amp's `skill("github-prs")`, this is the
    /// unwrapped semantic name, not `"skill"`.
    pub name: String,
    /// Original tool name when different from `name` (e.g. `"skill"` for
    /// Amp skill wrapper calls).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_name: Option<String>,
    /// Provider-assigned call ID, useful for joining with tool results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// Raw input/arguments passed to the tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Value>,
}

#[cfg(feature = "connectors")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedSnippet {
    pub file_path: Option<PathBuf>,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
    pub language: Option<String>,
    pub snippet_text: Option<String>,
}

/// Re-assign sequential indices to messages starting from 0.
/// Use this after filtering or sorting messages to ensure idx values are contiguous.
#[cfg(feature = "connectors")]
#[inline]
pub fn reindex_messages(messages: &mut [NormalizedMessage]) {
    for (i, msg) in messages.iter_mut().enumerate() {
        msg.idx = i64::try_from(i).unwrap_or(i64::MAX);
    }
}

// -------------------------------------------------------------------------
// Scan & provenance types (feature-gated behind `connectors`)
// -------------------------------------------------------------------------

/// The default source ID for local conversations.
#[cfg(feature = "connectors")]
pub const LOCAL_SOURCE_ID: &str = "local";

/// The kind/type of a source.
#[cfg(feature = "connectors")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    /// Local machine (default).
    #[default]
    Local,
    /// Remote machine via SSH.
    Ssh,
}

#[cfg(feature = "connectors")]
impl SourceKind {
    /// Returns true if this is a remote source kind.
    #[must_use]
    pub const fn is_remote(&self) -> bool {
        !matches!(self, Self::Local)
    }

    /// Get the string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Ssh => "ssh",
        }
    }

    /// Parse from string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "local" => Some(Self::Local),
            "ssh" => Some(Self::Ssh),
            _ => None,
        }
    }
}

#[cfg(feature = "connectors")]
impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Per-conversation provenance metadata.
#[cfg(feature = "connectors")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Origin {
    /// References Source.id.
    pub source_id: String,
    /// Denormalized source kind for convenience.
    pub kind: SourceKind,
    /// Display host label (may differ from source's `host_label`).
    pub host: Option<String>,
}

#[cfg(feature = "connectors")]
impl Origin {
    /// Create an origin for local conversations.
    #[must_use]
    pub fn local() -> Self {
        Self {
            source_id: LOCAL_SOURCE_ID.to_string(),
            kind: SourceKind::Local,
            host: None,
        }
    }

    /// Create an origin for remote conversations.
    #[must_use]
    pub fn remote(source_id: impl Into<String>) -> Self {
        let id = source_id.into();
        Self {
            source_id: id.clone(),
            kind: SourceKind::Ssh,
            host: Some(id),
        }
    }

    /// Create an origin for remote conversations with explicit host label.
    #[must_use]
    pub fn remote_with_host(source_id: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            kind: SourceKind::Ssh,
            host: Some(host.into()),
        }
    }

    /// Check if this origin is from a remote source.
    #[must_use]
    pub const fn is_remote(&self) -> bool {
        self.kind.is_remote()
    }

    /// Check if this origin is local.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.source_id == LOCAL_SOURCE_ID && self.kind == SourceKind::Local
    }

    /// Get a display label for this origin.
    #[must_use]
    pub fn display_label(&self) -> String {
        match (&self.host, &self.kind) {
            (Some(host), SourceKind::Ssh) => format!("{host} (remote)"),
            (Some(host), SourceKind::Local) => host.clone(),
            (None, SourceKind::Local) => "local".to_string(),
            (None, SourceKind::Ssh) => format!("{} (remote)", self.source_id),
        }
    }

    /// Get a short display label (just the identifier, no suffix).
    #[must_use]
    pub fn short_label(&self) -> &str {
        self.host.as_deref().unwrap_or(&self.source_id)
    }
}

#[cfg(feature = "connectors")]
impl Default for Origin {
    fn default() -> Self {
        Self::local()
    }
}

/// A single path mapping rule for rewriting paths.
#[cfg(feature = "connectors")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathMapping {
    /// Source path prefix to match.
    pub from: String,
    /// Target path prefix to replace with.
    pub to: String,
    /// Optional: only apply this mapping for specific agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<String>>,
}

#[cfg(feature = "connectors")]
impl PathMapping {
    /// Create a new path mapping.
    #[must_use]
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            agents: None,
        }
    }

    /// Create a new path mapping with agent filter.
    #[must_use]
    pub fn with_agents(
        from: impl Into<String>,
        to: impl Into<String>,
        agents: Vec<String>,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            agents: Some(agents),
        }
    }

    /// Apply this mapping to a path if it matches.
    #[must_use]
    pub fn apply(&self, path: &str) -> Option<String> {
        if path == self.from {
            return Some(self.to.clone());
        }

        if !path.starts_with(&self.from) {
            return None;
        }

        let rest = &path[self.from.len()..];
        let boundary_ok =
            self.from.ends_with('/') || self.from.ends_with('\\') || rest.starts_with(['/', '\\']);
        if boundary_ok {
            let from_sep = if self.from.ends_with('/') {
                Some('/')
            } else if self.from.ends_with('\\') {
                Some('\\')
            } else {
                None
            };

            let needs_sep = from_sep.is_some()
                && !self.to.ends_with('/')
                && !self.to.ends_with('\\')
                && !rest.starts_with(['/', '\\']);

            if needs_sep {
                Some(format!("{}{}{}", self.to, from_sep.unwrap(), rest))
            } else {
                Some(format!("{}{}", self.to, rest))
            }
        } else {
            None
        }
    }

    /// Check if this mapping applies to a given agent.
    #[must_use]
    pub fn applies_to_agent(&self, agent: Option<&str>) -> bool {
        match (&self.agents, agent) {
            (None, _) | (Some(_), None) => true,
            (Some(agents), Some(a)) => agents.iter().any(|allowed| allowed == a),
        }
    }
}

/// Platform hint for choosing default paths.
#[cfg(feature = "connectors")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Macos,
    Linux,
    Windows,
}

#[cfg(feature = "connectors")]
impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Macos => write!(f, "macos"),
            Self::Linux => write!(f, "linux"),
            Self::Windows => write!(f, "windows"),
        }
    }
}
