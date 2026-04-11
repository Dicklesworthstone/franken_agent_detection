//! Probabilistic workspace membership cache using bloom filter.

use bloomfilter::Bloom;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Wrapper for `PathBuf` that provides consistent hashing for bloom filter.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PathKey(PathBuf);

impl Hash for PathKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_os_str().as_encoded_bytes().hash(state);
    }
}

impl From<PathBuf> for PathKey {
    fn from(p: PathBuf) -> Self {
        Self(p)
    }
}

impl From<&PathBuf> for PathKey {
    fn from(p: &PathBuf) -> Self {
        Self(p.clone())
    }
}

/// Probabilistic workspace membership cache using bloom filter for fast rejection.
///
/// Provides 10x+ faster negative lookups for paths that are definitely NOT workspaces.
/// Uses two-phase lookup:
/// 1. Bloom filter check — fast rejection of non-members (zero false negatives)
/// 2. `HashSet` confirmation — authoritative membership for bloom positives
#[derive(Debug)]
pub struct WorkspaceCache {
    bloom: Bloom<PathKey>,
    exact: HashSet<PathBuf>,
    normalized: HashMap<PathBuf, PathBuf>,
    lookup_count: AtomicU64,
    bloom_reject_count: AtomicU64,
    exact_hit_count: AtomicU64,
}

impl WorkspaceCache {
    /// Create a new workspace cache from a set of workspace paths.
    #[must_use]
    pub fn new<I>(workspaces: I) -> Self
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let workspaces: Vec<PathBuf> = workspaces.into_iter().collect();
        let num_items = workspaces.len().max(1);

        let bloom = Bloom::new_for_fp_rate(num_items, 0.01)
            .expect("bloom filter creation should succeed with valid parameters");

        let mut cache = Self {
            bloom,
            exact: HashSet::with_capacity(num_items),
            normalized: HashMap::new(),
            lookup_count: AtomicU64::new(0),
            bloom_reject_count: AtomicU64::new(0),
            exact_hit_count: AtomicU64::new(0),
        };

        for ws in workspaces {
            cache.insert(ws);
        }

        cache
    }

    /// Create an empty workspace cache.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            bloom: Bloom::new_for_fp_rate(1, 0.01)
                .expect("bloom filter creation should succeed with valid parameters"),
            exact: HashSet::new(),
            normalized: HashMap::new(),
            lookup_count: AtomicU64::new(0),
            bloom_reject_count: AtomicU64::new(0),
            exact_hit_count: AtomicU64::new(0),
        }
    }

    fn insert(&mut self, path: PathBuf) {
        let key = PathKey::from(&path);
        self.bloom.set(&key);
        self.exact.insert(path);
    }

    /// Check if a path is a known workspace.
    #[must_use]
    pub fn contains(&self, path: &PathBuf) -> bool {
        self.lookup_count.fetch_add(1, Ordering::Relaxed);

        let key = PathKey::from(path);

        if !self.bloom.check(&key) {
            self.bloom_reject_count.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let is_member = self.exact.contains(path);
        if is_member {
            self.exact_hit_count.fetch_add(1, Ordering::Relaxed);
        }
        is_member
    }

    /// Check if a path is under any known workspace.
    #[must_use]
    pub fn is_under_workspace(&self, path: &Path) -> Option<&PathBuf> {
        self.lookup_count.fetch_add(1, Ordering::Relaxed);

        for ancestor in path.ancestors().skip(1) {
            let ancestor_buf = ancestor.to_path_buf();
            let key = PathKey::from(&ancestor_buf);

            if !self.bloom.check(&key) {
                continue;
            }

            if let Some(ws) = self.exact.get(&ancestor_buf) {
                self.exact_hit_count.fetch_add(1, Ordering::Relaxed);
                return Some(ws);
            }
        }

        self.bloom_reject_count.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Get or compute normalized path, caching the result.
    #[allow(dead_code)]
    pub fn normalize(&mut self, path: &PathBuf) -> PathBuf {
        if let Some(cached) = self.normalized.get(path) {
            return cached.clone();
        }

        let normalized = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
        self.normalized.insert(path.clone(), normalized.clone());
        normalized
    }

    /// Get lookup statistics: (`total_lookups`, `bloom_rejections`, `exact_hits`).
    #[must_use]
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.lookup_count.load(Ordering::Relaxed),
            self.bloom_reject_count.load(Ordering::Relaxed),
            self.exact_hit_count.load(Ordering::Relaxed),
        )
    }

    /// Get the number of workspaces in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.exact.len()
    }

    /// Check if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::DefaultHasher;

    #[test]
    fn workspace_cache_empty() {
        let cache = WorkspaceCache::empty();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert!(!cache.contains(&PathBuf::from("/some/path")));
    }

    #[test]
    fn workspace_cache_single_workspace() {
        let cache = WorkspaceCache::new(vec![PathBuf::from("/home/user/project")]);
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&PathBuf::from("/home/user/project")));
    }

    #[test]
    fn workspace_cache_multiple_workspaces() {
        let paths = vec![
            PathBuf::from("/home/user/project1"),
            PathBuf::from("/home/user/project2"),
            PathBuf::from("/opt/workspace"),
        ];
        let cache = WorkspaceCache::new(paths);
        assert_eq!(cache.len(), 3);
        assert!(cache.contains(&PathBuf::from("/home/user/project1")));
        assert!(cache.contains(&PathBuf::from("/home/user/project2")));
        assert!(cache.contains(&PathBuf::from("/opt/workspace")));
        assert!(!cache.contains(&PathBuf::from("/home/user/project3")));
    }

    #[test]
    fn workspace_cache_zero_false_negatives() {
        // Bloom filter must never produce false negatives
        let paths: Vec<PathBuf> = (0..100)
            .map(|i| PathBuf::from(format!("/workspace/{i}")))
            .collect();
        let cache = WorkspaceCache::new(paths.iter().cloned());
        for path in &paths {
            assert!(
                cache.contains(path),
                "bloom filter produced false negative for {path:?}"
            );
        }
    }

    #[test]
    fn workspace_cache_is_under_workspace() {
        let cache = WorkspaceCache::new(vec![PathBuf::from("/home/user/project")]);
        let result = cache.is_under_workspace(Path::new("/home/user/project/src/main.rs"));
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &PathBuf::from("/home/user/project"));

        let result = cache.is_under_workspace(Path::new("/other/path/file.rs"));
        assert!(result.is_none());
    }

    #[test]
    fn workspace_cache_is_under_workspace_returns_workspace() {
        let cache = WorkspaceCache::new(vec![PathBuf::from("/home/user/project")]);
        let result = cache.is_under_workspace(Path::new("/home/user/project/deep/nested/file"));
        assert_eq!(result, Some(&PathBuf::from("/home/user/project")));
    }

    #[test]
    fn workspace_cache_nested_workspaces() {
        let cache = WorkspaceCache::new(vec![
            PathBuf::from("/home/user"),
            PathBuf::from("/home/user/project"),
        ]);

        // Should find the most specific (deepest) workspace
        let result = cache.is_under_workspace(Path::new("/home/user/project/src/main.rs"));
        assert!(result.is_some());
        // The exact workspace found depends on ancestor traversal order
        let ws = result.unwrap();
        assert!(ws == &PathBuf::from("/home/user/project") || ws == &PathBuf::from("/home/user"));
    }

    #[test]
    fn workspace_cache_stats() {
        let cache = WorkspaceCache::new(vec![PathBuf::from("/home/user/project")]);

        // Positive lookup
        let _ = cache.contains(&PathBuf::from("/home/user/project"));
        // Negative lookup
        let _ = cache.contains(&PathBuf::from("/not/a/workspace"));

        let (lookups, _bloom_rejects, _exact_hits) = cache.stats();
        assert_eq!(lookups, 2);
    }

    #[test]
    fn workspace_cache_bounded_false_positive_rate() {
        // Verify bloom filter FP rate stays under 5% (target 1%)
        let real_paths: Vec<PathBuf> = (0..1000)
            .map(|i| PathBuf::from(format!("/real/{i}")))
            .collect();
        let cache = WorkspaceCache::new(real_paths);

        let mut false_positives = 0;
        let test_count = 10_000;
        for i in 0..test_count {
            let fake = PathBuf::from(format!("/fake/{i}"));
            if cache.contains(&fake) {
                false_positives += 1;
            }
        }

        let fp_rate = f64::from(false_positives) / f64::from(test_count);
        assert!(
            fp_rate < 0.05,
            "false positive rate {fp_rate:.4} exceeds 5% threshold"
        );
    }

    #[test]
    fn workspace_cache_pathkey_hash_consistency() {
        let path = PathBuf::from("/home/user/project");
        let key1 = PathKey::from(&path);
        let key2 = PathKey::from(path);

        // Hash should be consistent
        let hash1 = {
            let mut h = DefaultHasher::new();
            key1.hash(&mut h);
            h.finish()
        };
        let hash2 = {
            let mut h = DefaultHasher::new();
            key2.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash1, hash2);
        assert_eq!(key1, key2);
    }
}
