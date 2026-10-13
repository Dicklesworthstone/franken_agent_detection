//! A qualified Factory mirror has one authoritative payload, not a second home.

use super::ScanRoot;

/// `None` keeps native/custom-path detection. `Some(empty)` is an owned but
/// missing or rejected mirror and must not trigger generic container probing.
/// Only use the configured identity for matching; never join a remote path to
/// the local filesystem or infer ownership from the hashed container's name.
pub(super) fn roots(root: &ScanRoot) -> Option<Vec<ScanRoot>> {
    if !root.origin.is_remote() {
        return None;
    }
    let source = root.mirrored_source_path.as_deref()?;
    let components: Vec<_> = source
        .split(['/', '\\'])
        .filter(|part| !part.is_empty())
        .collect();
    let qualified = components.last() == Some(&".factory")
        || components
            .windows(2)
            .any(|parts| parts == [".factory", "sessions"]);
    if !qualified {
        return None;
    }
    // Qualification deliberately precedes path validation: a traversal or a
    // bad basename is a rejected owned request, not an invitation to scan more.
    Some(
        root.mirrored_store(&[".factory", "sessions"])
            .map(|path| root.with_path(path))
            .into_iter()
            .collect(),
    )
}
