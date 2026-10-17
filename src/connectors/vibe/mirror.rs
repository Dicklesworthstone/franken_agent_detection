//! Keep a Vibe session's logical identity separate from its copied directory.

use std::path::{Path, PathBuf};

use super::ScanRoot;

pub(super) struct SessionRoot {
    pub(super) root: ScanRoot,
    identity_prefix: PathBuf,
}

impl SessionRoot {
    pub(super) fn native(root: ScanRoot) -> Self {
        Self {
            root,
            identity_prefix: PathBuf::new(),
        }
    }

    pub(super) fn external_id(&self, file: &Path) -> Option<String> {
        file.parent()
            .and_then(|parent| parent.strip_prefix(&self.root.path).ok())
            .and_then(|relative| {
                let mut identity = self.identity_prefix.clone();
                if !relative.as_os_str().is_empty() {
                    identity.push(relative);
                }
                identity.to_str().map(str::to_owned)
            })
            .or_else(|| {
                file.parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    .map(str::to_owned)
            })
    }
}

/// `None` retains existing local, whole-home and complete-store detection.
/// `Some(empty)` is a recognized but unsafe/missing selected subtree: callers
/// must not fall back to broader probing of the transport container.
///
/// A derived `ScanRoot` intentionally drops transport metadata. Capture the
/// logical prefix here rather than attaching source metadata to a non-container.
pub(super) fn subtree(root: &ScanRoot) -> Option<Vec<SessionRoot>> {
    if !root.origin.is_remote() {
        return None;
    }
    let source = root.mirrored_source_path.as_deref()?;
    let components: Vec<_> = source
        .split(['/', '\\'])
        .filter(|part| !part.is_empty())
        .collect();
    let start = components
        .windows(3)
        .position(|parts| parts == [".vibe", "logs", "session"])?;
    let store = &components[start..];
    if store.len() == 3 {
        return None;
    }

    // Use the complete provider-qualified suffix as the selected store.
    // The shared resolver validates source components, symlinks and containment
    // and chooses basename-preserving versus trailing-slash contents copies.
    let Some(path) = root.mirrored_store(store) else {
        return Some(Vec::new());
    };
    let mut identity_prefix = PathBuf::new();
    for component in &store[3..] {
        identity_prefix.push(component);
    }
    Some(vec![SessionRoot {
        root: root.with_path(path),
        identity_prefix,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Origin;

    #[test]
    fn native_identity_projection_keeps_existing_relative_paths() {
        let root = SessionRoot::native(ScanRoot::local(PathBuf::from("store")));
        assert_eq!(
            root.external_id(Path::new("store/team/run/messages.jsonl")),
            Some(Path::new("team/run").to_string_lossy().into_owned())
        );
        // The old direct-root behavior remains unchanged for local callers.
        assert_eq!(
            root.external_id(Path::new("store/messages.jsonl")),
            Some(String::new())
        );
    }

    #[test]
    fn selected_identity_prefix_is_not_the_local_transport_basename() {
        let root = SessionRoot {
            root: ScanRoot::remote(
                PathBuf::from("opaque_hash/run"),
                Origin::remote("host"),
                None,
            ),
            identity_prefix: Path::new("team").join("run"),
        };
        assert_eq!(
            root.external_id(Path::new("opaque_hash/run/messages.jsonl")),
            Some(Path::new("team").join("run").to_string_lossy().into_owned())
        );
        assert_eq!(
            root.external_id(Path::new("opaque_hash/run/child/messages.jsonl")),
            Some(
                Path::new("team")
                    .join("run")
                    .join("child")
                    .to_string_lossy()
                    .into_owned()
            )
        );
    }

    #[test]
    fn local_and_existing_store_roots_keep_their_detection_path() {
        for source in [
            "~",
            "~/.vibe",
            "~/.vibe/logs",
            "~/.vibe/logs/session",
            "~/.vibe-backup/logs/session/run",
        ] {
            let root = ScanRoot::remote(PathBuf::from("opaque"), Origin::remote("host"), None)
                .with_mirrored_source_path(source);
            assert!(subtree(&root).is_none(), "{source}");
        }
        let local = ScanRoot::local(PathBuf::from("opaque"))
            .with_mirrored_source_path("~/.vibe/logs/session/run");
        assert!(subtree(&local).is_none());
    }
}
