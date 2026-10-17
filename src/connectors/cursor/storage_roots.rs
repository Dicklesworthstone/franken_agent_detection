//! Cursor database roots, including transport containers with lost parent names.

use std::fs;
use std::path::{Component, Path, PathBuf};

use super::ScanRoot;

/// Enumerate only the documented workspace level; never walk project trees.
/// Local callers retain their existing symlink behavior. Mirror callers apply
/// the stricter transport-boundary check below before admitting each file.
pub(super) fn workspace_db_files(base: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let direct = base.join("state.vscdb");
    if direct.is_file() {
        files.push(direct);
    }
    if let Ok(entries) = fs::read_dir(base) {
        for entry in entries.flatten() {
            let file = entry.path().join("state.vscdb");
            if file.is_file() {
                files.push(file);
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

/// `None` retains ordinary structural detection (including whole-home scans).
/// `Some`, even when empty, means an explicitly identified Cursor transport
/// container was handled. Do not fall back through a rejected symlink or let
/// the container's unrelated children expand the requested provider scope.
pub(super) fn mirrored_db_files(root: &ScanRoot) -> Option<Vec<PathBuf>> {
    if !root.origin.is_remote() {
        return None;
    }
    let source = root.mirrored_source_path.as_deref()?;
    let parts: Vec<_> = source
        .split(['/', '\\'])
        .filter(|part| !part.is_empty())
        .collect();
    let user_start = parts
        .windows(2)
        .rposition(|part| part == ["Cursor", "User"]);
    let user_suffix = user_start.map(|start| &parts[start + 2..]);
    let is_home = parts.last() == Some(&"Cursor");
    let is_store = matches!(
        user_suffix,
        Some([] | ["globalStorage" | "workspaceStorage"])
    );
    let is_workspace = matches!(user_suffix, Some(["workspaceStorage", _]));
    if !is_home && !is_store && !is_workspace {
        return None;
    }

    let mut files = Vec::new();
    if is_workspace {
        // For a selected workspace, its full provider-qualified source suffix
        // is the store identity. The resolver returns just the copied leaf,
        // even when its local parent no longer says `workspaceStorage`.
        let start = user_start?;
        if let Some(workspace) = root.mirrored_store(&parts[start..]) {
            files.push(workspace.join("state.vscdb"));
        }
    } else {
        if let Some(global) = root.mirrored_store(&["Cursor", "User", "globalStorage"]) {
            files.push(global.join("state.vscdb"));
        }
        if let Some(workspaces) = root.mirrored_store(&["Cursor", "User", "workspaceStorage"]) {
            files.extend(workspace_db_files(&workspaces));
        }
    }
    files.retain(|file| regular_mirror_file(&root.path, file));
    files.sort();
    files.dedup();
    Some(files)
}

/// Only admit existing regular files reached without links below the transport
/// boundary. Checking the canonical endpoint alone would accept internal aliases
/// and could let an alias broaden a single-workspace request to other stores.
fn regular_mirror_file(container: &Path, file: &Path) -> bool {
    if container
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return false;
    }
    let Ok(relative) = file.strip_prefix(container) else {
        return false;
    };
    if !fs::symlink_metadata(container).is_ok_and(|metadata| metadata.is_dir()) {
        return false;
    }
    let mut current = container.to_path_buf();
    let mut parts = relative.components().peekable();
    while let Some(part) = parts.next() {
        let Component::Normal(name) = part else {
            return false;
        };
        current.push(name);
        let Ok(metadata) = fs::symlink_metadata(&current) else {
            return false;
        };
        if parts.peek().is_some() {
            if !metadata.is_dir() {
                return false;
            }
        } else {
            return metadata.is_file();
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Origin;

    fn put(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"discovery-only fixture").unwrap();
    }

    fn remote(path: PathBuf, source: &str) -> ScanRoot {
        ScanRoot::remote(path, Origin::remote("laptop"), None).with_mirrored_source_path(source)
    }

    #[test]
    fn workspace_enumeration_is_shallow_sorted_and_unique() {
        let temp = tempfile::tempdir().unwrap();
        for relative in [
            "state.vscdb",
            "b/state.vscdb",
            "a/state.vscdb",
            "a/project/nested/state.vscdb",
        ] {
            put(&temp.path().join(relative));
        }
        assert_eq!(
            workspace_db_files(temp.path()),
            ["a/state.vscdb", "b/state.vscdb", "state.vscdb"]
                .map(|relative| temp.path().join(relative))
        );
    }

    #[test]
    fn workspace_mirrors_support_retained_basename_and_contents_copies() {
        for (slash, retained) in [(false, true), (true, true), (true, false)] {
            let temp = tempfile::tempdir().unwrap();
            let container = temp.path().join("opaque_hash");
            let payload = if retained {
                container.join("workspaceStorage")
            } else {
                container.clone()
            };
            let a = payload.join("a/state.vscdb");
            let b = payload.join("b/state.vscdb");
            put(&a);
            put(&b);
            let source = format!(
                "~/.config/Cursor/User/workspaceStorage{}",
                if slash { "/" } else { "" }
            );
            assert_eq!(
                mirrored_db_files(&remote(container, &source)),
                Some(vec![a, b])
            );
        }
    }

    #[test]
    fn global_and_individual_workspace_mirrors_remain_narrow() {
        for (source, leaf) in [
            ("~/.config/Cursor/User/globalStorage", "globalStorage"),
            (
                "~/.config/Cursor/User/workspaceStorage/selected",
                "selected",
            ),
        ] {
            for (slash, retained) in [(false, true), (true, true), (true, false)] {
                let temp = tempfile::tempdir().unwrap();
                let container = temp.path().join("opaque_hash");
                let payload = if retained {
                    container.join(leaf)
                } else {
                    container.clone()
                };
                let selected = payload.join("state.vscdb");
                put(&selected);
                put(&container.join("other/state.vscdb"));
                let source = format!("{source}{}", if slash { "/" } else { "" });
                assert_eq!(
                    mirrored_db_files(&remote(container, &source)),
                    Some(vec![selected])
                );
            }
        }
    }

    #[test]
    fn user_and_application_mirrors_include_both_database_stores() {
        for (source, payload) in [
            ("~/.config/Cursor", "Cursor/User"),
            ("~/Library/Application Support/Cursor/User", "User"),
            (r"C:\Users\alice\AppData\Roaming\Cursor\User", "User"),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let container = temp.path().join("opaque_hash");
            let global = container.join(payload).join("globalStorage/state.vscdb");
            let workspace = container
                .join(payload)
                .join("workspaceStorage/a/state.vscdb");
            put(&global);
            put(&workspace);
            assert_eq!(
                mirrored_db_files(&remote(container, source)),
                Some(vec![global, workspace])
            );
        }
    }

    #[test]
    fn local_and_whole_home_scans_keep_structural_detection() {
        let temp = tempfile::tempdir().unwrap();
        for source in [
            "~",
            "/home/alice",
            "~/.config/Code/User",
            "~/workspaceStorage",
        ] {
            assert!(mirrored_db_files(&remote(temp.path().to_path_buf(), source)).is_none());
        }
        let local = ScanRoot::local(temp.path().to_path_buf())
            .with_mirrored_source_path("~/.config/Cursor/User");
        assert!(mirrored_db_files(&local).is_none());
    }

    #[test]
    fn unsafe_or_missing_owned_mirrors_do_not_fall_back_to_generic_probing() {
        let temp = tempfile::tempdir().unwrap();
        put(&temp.path().join("globalStorage/state.vscdb"));
        for source in ["~/.config/../Cursor/User/", "~/.config/\n/Cursor/User/"] {
            assert_eq!(
                mirrored_db_files(&remote(temp.path().to_path_buf(), source)),
                Some(vec![])
            );
        }
        assert_eq!(
            mirrored_db_files(&remote(
                temp.path().join("missing"),
                "~/.config/Cursor/User"
            )),
            Some(vec![])
        );
    }

    #[cfg(unix)]
    #[test]
    fn remote_workspace_links_and_database_links_are_not_followed() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let container = temp.path().join("opaque_hash");
        let payload = container.join("workspaceStorage");
        let good = payload.join("good/state.vscdb");
        put(&good);
        let outside = temp.path().join("outside");
        put(&outside.join("state.vscdb"));
        symlink(&outside, payload.join("linked-directory")).unwrap();
        fs::create_dir_all(payload.join("linked-file")).unwrap();
        symlink(
            outside.join("state.vscdb"),
            payload.join("linked-file/state.vscdb"),
        )
        .unwrap();
        assert_eq!(
            mirrored_db_files(&remote(container, "~/.config/Cursor/User/workspaceStorage")),
            Some(vec![good])
        );
    }
}
