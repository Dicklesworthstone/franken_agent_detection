//! Prefix trie for workspace path rewriting.

use crate::types::{PathMapping, agent_name_matches_filter};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// A mapping entry stored at trie nodes.
#[derive(Debug, Clone)]
struct TrieMapping {
    /// Target path prefix to rewrite to.
    to: Box<str>,
    /// Optional agent filter (None = applies to all).
    agents: Option<Vec<String>>,
}

impl TrieMapping {
    fn applies_to_agent(&self, agent: Option<&str>) -> bool {
        match (&self.agents, agent) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(agents), Some(a)) => agents
                .iter()
                .any(|allowed| agent_name_matches_filter(allowed, a)),
        }
    }
}

/// Trie node for path component matching.
#[derive(Debug, Default)]
struct PathTrieNode {
    /// Children indexed by path component.
    children: HashMap<Box<str>, Self>,
    /// Mappings at this node (multiple mappings can share a prefix with different agent filters).
    mappings: Vec<TrieMapping>,
}

/// Prefix trie optimized for workspace path rewriting.
///
/// Provides O(k) lookup where k is the path depth, instead of O(n) where n is
/// the number of mappings.
#[derive(Debug, Default)]
pub struct PathTrie {
    root: PathTrieNode,
    /// Lookup count for observability.
    lookup_count: AtomicU64,
    /// Hit count (successful rewrites) for observability.
    hit_count: AtomicU64,
}

impl PathTrie {
    /// Create a new empty trie.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a trie from a list of path mappings.
    #[must_use]
    pub fn from_mappings(mappings: &[PathMapping]) -> Self {
        let mut trie = Self::new();
        for mapping in mappings {
            trie.insert(&mapping.from, &mapping.to, mapping.agents.clone());
        }
        trie
    }

    /// Split a path into components, handling both Unix and Windows separators.
    fn split_path(path: &str) -> Vec<&str> {
        path.split(['/', '\\']).filter(|s| !s.is_empty()).collect()
    }

    /// Insert a path mapping into the trie.
    pub fn insert(&mut self, from: &str, to: &str, agents: Option<Vec<String>>) {
        let components = Self::split_path(from);
        let mut current = &mut self.root;

        for component in components {
            current = current.children.entry(component.into()).or_default();
        }

        current.mappings.push(TrieMapping {
            to: to.into(),
            agents,
        });
    }

    /// Lookup and rewrite a path using longest-prefix matching.
    #[must_use]
    pub fn lookup(&self, path: &str, agent: Option<&str>) -> String {
        self.lookup_count.fetch_add(1, Ordering::Relaxed);

        let components = Self::split_path(path);
        let mut current = &self.root;
        let mut best_match: Option<(&TrieMapping, usize)> = None;

        // Check root-level mappings (empty prefix)
        for mapping in &current.mappings {
            if mapping.applies_to_agent(agent) {
                best_match = Some((mapping, 0));
            }
        }

        // Walk the trie as deep as possible, tracking the deepest matching mapping
        for (depth, component) in components.iter().enumerate() {
            match current.children.get(*component) {
                Some(child) => {
                    current = child;
                    let current_depth = depth + 1;

                    for mapping in &current.mappings {
                        if mapping.applies_to_agent(agent) {
                            best_match = Some((mapping, current_depth));
                        }
                    }
                }
                None => break,
            }
        }

        // Apply the best match if found
        if let Some((mapping, depth)) = best_match {
            self.hit_count.fetch_add(1, Ordering::Relaxed);

            let remaining: Vec<&str> = components.into_iter().skip(depth).collect();
            if remaining.is_empty() {
                return mapping.to.to_string();
            }

            let sep = if path.contains('\\') { '\\' } else { '/' };
            let remainder = remaining.join(&sep.to_string());

            if mapping.to.ends_with('/') || mapping.to.ends_with('\\') {
                format!("{}{}", mapping.to, remainder)
            } else {
                format!("{}{}{}", mapping.to, sep, remainder)
            }
        } else {
            path.to_string()
        }
    }

    /// Get lookup statistics for observability.
    #[must_use]
    pub fn stats(&self) -> (u64, u64) {
        (
            self.lookup_count.load(Ordering::Relaxed),
            self.hit_count.load(Ordering::Relaxed),
        )
    }

    /// Check if the trie is empty (no mappings).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.root.children.is_empty() && self.root.mappings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_trie_empty_lookup() {
        let trie = PathTrie::new();
        assert_eq!(
            trie.lookup("/home/user/project", None),
            "/home/user/project"
        );
        assert!(trie.is_empty());
    }

    #[test]
    fn path_trie_simple_rewrite() {
        let mut trie = PathTrie::new();
        trie.insert("/remote/home", "/local/home", None);
        assert_eq!(
            trie.lookup("/remote/home/project/file.rs", None),
            "/local/home/project/file.rs"
        );
    }

    #[test]
    fn path_trie_exact_match() {
        let mut trie = PathTrie::new();
        trie.insert("/remote/home", "/local/home", None);
        assert_eq!(trie.lookup("/remote/home", None), "/local/home");
    }

    #[test]
    fn path_trie_no_match() {
        let mut trie = PathTrie::new();
        trie.insert("/remote/home", "/local/home", None);
        assert_eq!(trie.lookup("/other/path", None), "/other/path");
    }

    #[test]
    fn path_trie_longest_prefix_match() {
        let mut trie = PathTrie::new();
        trie.insert("/remote", "/base", None);
        trie.insert("/remote/home/user", "/local/user", None);

        // Should match the deeper prefix
        assert_eq!(
            trie.lookup("/remote/home/user/project", None),
            "/local/user/project"
        );
        // Should match the shallower prefix
        assert_eq!(trie.lookup("/remote/other/path", None), "/base/other/path");
    }

    #[test]
    fn path_trie_agent_filter() {
        let mut trie = PathTrie::new();
        trie.insert(
            "/remote/home",
            "/local/claude",
            Some(vec!["claude_code".to_string()]),
        );
        trie.insert(
            "/remote/home",
            "/local/copilot",
            Some(vec!["copilot".to_string()]),
        );

        assert_eq!(
            trie.lookup("/remote/home/project", Some("claude_code")),
            "/local/claude/project"
        );
        assert_eq!(
            trie.lookup("/remote/home/project", Some("copilot")),
            "/local/copilot/project"
        );
        // None agent should not match agent-specific mappings
        assert_eq!(
            trie.lookup("/remote/home/project", None),
            "/remote/home/project"
        );
    }

    #[test]
    fn path_trie_agent_filter_matches_hyphenated_and_underscored_aliases() {
        let mut trie = PathTrie::new();
        trie.insert(
            "/remote/home",
            "/local/hyphen",
            Some(vec!["claude-code".to_string()]),
        );
        trie.insert(
            "/remote/other",
            "/local/underscore",
            Some(vec!["claude_code".to_string()]),
        );

        assert_eq!(
            trie.lookup("/remote/home/project", Some("claude_code")),
            "/local/hyphen/project"
        );
        assert_eq!(
            trie.lookup("/remote/other/project", Some("claude-code")),
            "/local/underscore/project"
        );
    }

    #[test]
    fn path_trie_windows_paths() {
        let mut trie = PathTrie::new();
        trie.insert("C:\\Users\\remote", "D:\\local", None);
        assert_eq!(
            trie.lookup("C:\\Users\\remote\\project\\file.rs", None),
            "D:\\local\\project\\file.rs"
        );
    }

    #[test]
    fn path_trie_stats() {
        let mut trie = PathTrie::new();
        trie.insert("/a", "/b", None);

        let _ = trie.lookup("/a/file", None);
        let _ = trie.lookup("/c/file", None);
        let _ = trie.lookup("/a/other", None);

        let (lookups, hits) = trie.stats();
        assert_eq!(lookups, 3);
        assert_eq!(hits, 2);
    }

    #[test]
    fn path_trie_from_mappings() {
        let mappings = vec![
            PathMapping::new("/remote/a", "/local/a"),
            PathMapping::new("/remote/b", "/local/b"),
        ];
        let trie = PathTrie::from_mappings(&mappings);
        assert!(!trie.is_empty());
        assert_eq!(trie.lookup("/remote/a/file", None), "/local/a/file");
        assert_eq!(trie.lookup("/remote/b/file", None), "/local/b/file");
    }
}
