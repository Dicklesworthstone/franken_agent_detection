//! Read-only expansion of CASS SSH mirror containers (CASS #520).
//!
//! Sync keeps `<safe-configured-path>_<fnv64>/<basename>`, not a synthetic
//! remote home. Recognize only provider-specific component suffixes, on roots
//! explicitly carrying remote provenance. Never decode a remote path into a
//! local path, change sync's collision-resistant names, or create symlinks.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use super::scan::{ScanContext, ScanRoot};

/// `layouts` contains native provider components, e.g. `.prime/agent/sessions`.
/// A mirror may contain the whole provider directory or just its storage leaf.
/// Also accept a whole mirror directory and already-selected payload subtrees.
/// Expansion is shallow; session enumeration remains the connector's job.
pub(super) fn roots(ctx: &ScanContext, layouts: &[&[&str]]) -> Vec<ScanRoot> {
    let mut result = Vec::new();
    for root in &ctx.scan_roots {
        if !root.origin.kind.is_remote()
            || root.path.components().any(|c| matches!(c, Component::ParentDir))
        {
            continue;
        }
        let mut wrappers = BTreeSet::new();
        // Ancestors only establish ownership; candidates are intersected with
        // the requested scope below, never used to broaden a narrow scan.
        for ancestor in root.path.ancestors() {
            if wrapper_stem(ancestor).is_some() {
                wrappers.insert(ancestor.to_path_buf());
                break;
            }
        }
        if fs::symlink_metadata(&root.path).is_ok_and(|m| m.is_dir()) {
            if let Ok(entries) = fs::read_dir(&root.path) {
                for entry in entries.flatten() {
                    if entry.file_type().is_ok_and(|kind| kind.is_dir())
                        && wrapper_stem(&entry.path()).is_some()
                    {
                        wrappers.insert(entry.path());
                    }
                }
            }
        }
        let mut candidates = BTreeSet::new();
        for wrapper in wrappers {
            let Some(stem) = wrapper_stem(&wrapper) else { continue };
            for layout in layouts {
                for cut in 0..layout.len() {
                    let suffix = layout[..=cut].join("_").replace(' ', "_");
                    if stem != suffix
                        && !stem.strip_suffix(&suffix).is_some_and(|prefix| prefix.ends_with('_'))
                    {
                        continue;
                    }
                    // Only compile-time provider components are ever joined.
                    let payload = layout[cut..].iter().fold(wrapper.clone(), |p, c| p.join(c));
                    let selected = if payload.starts_with(&root.path) {
                        payload
                    } else if root.path.starts_with(&payload) {
                        root.path.clone()
                    } else {
                        continue;
                    };
                    if safe_existing_path(&wrapper, &selected) {
                        candidates.insert(selected);
                    }
                }
            }
        }
        // Prefer the containing candidate when multiple Cursor layouts match
        // one User directory. Otherwise discovery would read each DB twice.
        let mut selected: Vec<PathBuf> = Vec::new();
        for candidate in candidates {
            if !selected.iter().any(|parent| candidate.starts_with(parent)) {
                selected.push(candidate);
            }
        }
        result.extend(selected.into_iter().map(|path| root.with_path(path)));
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    result.dedup_by(|a, b| a.path == b.path && a.origin == b.origin);
    result
}

/// CASS formats the u64 FNV hash with a minimum width of eight hexadecimal
/// digits, not a fixed width of eight. The hash is opaque, not reversible.
fn wrapper_stem(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    let (stem, hash) = name.rsplit_once('_')?;
    (!stem.is_empty()
        && (8..=16).contains(&hash.len())
        && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some(stem)
}

/// Refuse symlinks at the wrapper and every component down to the selected
/// payload. No canonicalization can silently redirect discovery outside the
/// mirror. WalkDir's existing no-follow policy protects the remaining walk.
fn safe_existing_path(wrapper: &Path, selected: &Path) -> bool {
    let Ok(relative) = selected.strip_prefix(wrapper) else { return false };
    let mut current = wrapper.to_path_buf();
    if !fs::symlink_metadata(&current).is_ok_and(|m| m.is_dir()) {
        return false;
    }
    for component in relative.components() {
        let Component::Normal(name) = component else { return false };
        current.push(name);
        if !fs::symlink_metadata(&current)
            .is_ok_and(|m| !m.file_type().is_symlink() && (m.is_dir() || m.is_file()))
        {
            return false;
        }
    }
    current.exists()
}
