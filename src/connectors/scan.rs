//! Scan root and context types for multi-root connector scanning.

use crate::connectors::path_trie::PathTrie;
use crate::types::{Origin, PathMapping, Platform};
use once_cell::sync::OnceCell;
use std::path::PathBuf;
use std::sync::Arc;

/// A root directory to scan with associated provenance.
#[derive(Debug)]
pub struct ScanRoot {
    /// Path to scan.
    pub path: PathBuf,

    /// Provenance for conversations found under this root.
    pub origin: Origin,

    /// Optional platform hint (affects path interpretation for workspace mapping).
    pub platform: Option<Platform>,

    /// Optional path rewrite rules.
    pub workspace_rewrites: Vec<PathMapping>,

    /// Cached trie for fast workspace rewriting.
    rewrite_trie: OnceCell<Arc<PathTrie>>,
}

impl Clone for ScanRoot {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            origin: self.origin.clone(),
            platform: self.platform,
            workspace_rewrites: self.workspace_rewrites.clone(),
            rewrite_trie: OnceCell::new(),
        }
    }
}

impl ScanRoot {
    /// Create a local scan root with default provenance.
    #[must_use]
    pub fn local(path: PathBuf) -> Self {
        Self {
            path,
            origin: Origin::local(),
            platform: None,
            workspace_rewrites: Vec::new(),
            rewrite_trie: OnceCell::new(),
        }
    }

    /// Create a remote scan root.
    #[must_use]
    pub const fn remote(path: PathBuf, origin: Origin, platform: Option<Platform>) -> Self {
        Self {
            path,
            origin,
            platform,
            workspace_rewrites: Vec::new(),
            rewrite_trie: OnceCell::new(),
        }
    }

    /// Add a workspace rewrite rule.
    #[must_use]
    pub fn with_rewrite(
        mut self,
        src_prefix: impl Into<String>,
        dst_prefix: impl Into<String>,
    ) -> Self {
        self.workspace_rewrites
            .push(PathMapping::new(src_prefix, dst_prefix));
        self.rewrite_trie = OnceCell::new();
        self
    }

    /// Get or build the cached rewrite trie.
    fn get_trie(&self) -> &Arc<PathTrie> {
        self.rewrite_trie
            .get_or_init(|| Arc::new(PathTrie::from_mappings(&self.workspace_rewrites)))
    }

    /// Apply workspace rewriting rules to a path.
    #[must_use]
    pub fn rewrite_workspace(&self, path: &str, agent: Option<&str>) -> String {
        if self.workspace_rewrites.is_empty() {
            return path.to_string();
        }

        let trie = self.get_trie();
        trie.lookup(path, agent)
    }

    /// Apply workspace rewriting using linear search (original algorithm).
    #[allow(dead_code)]
    #[must_use]
    pub fn rewrite_workspace_linear(&self, path: &str, agent: Option<&str>) -> String {
        let mut mappings: Vec<_> = self
            .workspace_rewrites
            .iter()
            .filter(|m| m.applies_to_agent(agent))
            .collect();
        mappings.sort_by_key(|m| std::cmp::Reverse(m.from.len()));

        for mapping in mappings {
            if let Some(rewritten) = mapping.apply(path) {
                return rewritten;
            }
        }

        path.to_string()
    }
}

/// Shared scan context parameters.
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// Primary data directory (cass internal state).
    pub data_dir: PathBuf,

    /// Scan roots to search for agent logs.
    /// If empty, connectors use their default detection logic (backward compat).
    pub scan_roots: Vec<ScanRoot>,

    /// High-water mark for incremental indexing (milliseconds since epoch).
    pub since_ts: Option<i64>,
}

impl ScanContext {
    /// Create a context for local-only scanning (backward compatible).
    #[must_use]
    pub const fn local_default(data_dir: PathBuf, since_ts: Option<i64>) -> Self {
        Self {
            data_dir,
            scan_roots: Vec::new(),
            since_ts,
        }
    }

    /// Create a context with explicit scan roots.
    #[must_use]
    pub const fn with_roots(
        data_dir: PathBuf,
        scan_roots: Vec<ScanRoot>,
        since_ts: Option<i64>,
    ) -> Self {
        Self {
            data_dir,
            scan_roots,
            since_ts,
        }
    }

    /// Legacy accessor for backward compatibility.
    #[deprecated(note = "Use data_dir directly or check scan_roots for explicit roots")]
    #[must_use]
    pub const fn data_root(&self) -> &PathBuf {
        &self.data_dir
    }

    /// Check if we should use default detection logic (no explicit roots).
    #[must_use]
    pub fn use_default_detection(&self) -> bool {
        self.scan_roots.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Origin;

    #[test]
    fn scan_root_local_creates_with_defaults() {
        let root = ScanRoot::local(PathBuf::from("/home/user/.claude"));
        assert_eq!(root.path, PathBuf::from("/home/user/.claude"));
        assert!(root.origin.is_local());
        assert!(root.platform.is_none());
    }

    #[test]
    fn scan_root_remote_sets_origin() {
        let origin = Origin::remote("laptop");
        let root = ScanRoot::remote(
            PathBuf::from("/data/remotes/laptop/mirror/.claude"),
            origin,
            Some(Platform::Linux),
        );
        assert_eq!(
            root.path,
            PathBuf::from("/data/remotes/laptop/mirror/.claude")
        );
        assert!(root.origin.is_remote());
        assert_eq!(root.platform, Some(Platform::Linux));
    }

    #[test]
    fn scan_root_with_rewrite_adds_rule() {
        let root = ScanRoot::local(PathBuf::from("/home/user/.claude"))
            .with_rewrite("/remote/path", "/local/path");
        assert_eq!(root.workspace_rewrites.len(), 1);
        assert_eq!(root.workspace_rewrites[0].from, "/remote/path");
        assert_eq!(root.workspace_rewrites[0].to, "/local/path");
    }

    #[test]
    fn scan_root_rewrite_workspace_applies_rules() {
        let root =
            ScanRoot::local(PathBuf::from("/home")).with_rewrite("/remote/home", "/local/home");
        assert_eq!(
            root.rewrite_workspace("/remote/home/project/file.rs", None),
            "/local/home/project/file.rs"
        );
    }

    #[test]
    fn scan_root_rewrite_with_agent_filter() {
        let mut root = ScanRoot::local(PathBuf::from("/home"));
        root.workspace_rewrites.push(PathMapping::with_agents(
            "/remote".to_string(),
            "/local/claude".to_string(),
            vec!["claude_code".to_string()],
        ));
        root.workspace_rewrites.push(PathMapping::with_agents(
            "/remote".to_string(),
            "/local/copilot".to_string(),
            vec!["copilot".to_string()],
        ));

        assert_eq!(
            root.rewrite_workspace("/remote/project", Some("claude_code")),
            "/local/claude/project"
        );
        assert_eq!(
            root.rewrite_workspace("/remote/project", Some("copilot")),
            "/local/copilot/project"
        );
    }

    #[test]
    fn scan_root_rewrite_uses_trie() {
        let root = ScanRoot::local(PathBuf::from("/home")).with_rewrite("/a", "/b");

        // First call builds the trie
        assert_eq!(root.rewrite_workspace("/a/file", None), "/b/file");
        // Second call uses cached trie
        assert_eq!(root.rewrite_workspace("/a/other", None), "/b/other");
    }

    #[test]
    fn scan_root_rewrite_empty() {
        let root = ScanRoot::local(PathBuf::from("/home"));
        assert_eq!(root.rewrite_workspace("/any/path", None), "/any/path");
    }

    #[test]
    fn scan_root_trie_vs_linear_equivalence() {
        let root = ScanRoot::local(PathBuf::from("/home"))
            .with_rewrite("/remote/a", "/local/a")
            .with_rewrite("/remote/b", "/local/b");

        let test_paths = ["/remote/a/file", "/remote/b/file", "/other/path"];
        for path in &test_paths {
            assert_eq!(
                root.rewrite_workspace(path, None),
                root.rewrite_workspace_linear(path, None),
                "trie and linear disagree on {path}"
            );
        }
    }

    #[test]
    fn scan_context_local_default_has_empty_roots() {
        let ctx = ScanContext::local_default(PathBuf::from("/data"), None);
        assert!(ctx.scan_roots.is_empty());
        assert!(ctx.use_default_detection());
    }

    #[test]
    fn scan_context_with_roots_sets_roots() {
        let roots = vec![ScanRoot::local(PathBuf::from("/home/.claude"))];
        let ctx = ScanContext::with_roots(PathBuf::from("/data"), roots, Some(1000));
        assert_eq!(ctx.scan_roots.len(), 1);
        assert!(!ctx.use_default_detection());
        assert_eq!(ctx.since_ts, Some(1000));
    }
}
