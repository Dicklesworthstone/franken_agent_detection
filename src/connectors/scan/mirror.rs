//! Resolve provider-owned stores inside basename-preserving SSH containers.

use std::fs;
use std::path::{Component, Path, PathBuf};

/// Map source identity to local paths; never join the remote path itself.
pub(super) fn resolve(container: &Path, source: &str, store: &[&str]) -> Option<PathBuf> {
    if store.is_empty()
        || store.iter().any(|part| {
            part.is_empty()
                || matches!(*part, "." | ".." | "~")
                || part.contains(['/', '\\', ':'])
        })
        || source.chars().any(char::is_control)
    {
        return None;
    }
    let components: Vec<_> = source
        .split(['/', '\\'])
        .filter(|part| !part.is_empty())
        .collect();
    if components.iter().any(|part| matches!(*part, "." | "..")) {
        return None;
    }

    // Recognize a complete owned store before shorter ancestor suffixes.
    // A project named `.factory` below `.factory/sessions` is still a
    // selected project, not a new application root needing `sessions/`.
    // Structural connectors use their own subtree/identity handling.
    let strict_layout = matches!(
        store,
        [".factory", "sessions"] | [".prime", "agent", "sessions"]
    );
    let matched = if strict_layout && components.windows(store.len()).any(|window| window == store) {
        store.len()
    } else {
        (1..=store.len())
            .rev()
            .find(|&len| components.ends_with(&store[..len]))?
    };
    let leaf = container.join(components.last()?);
    let mut candidate = match fs::symlink_metadata(&leaf) {
        Ok(metadata) if metadata.is_dir() => leaf,
        // Only an absent basename permits rsync's contents-copy interpretation.
        // is_dir() conflates absence, dangling links, files and access errors;
        // those must not broaden the request to the entire container.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && source.ends_with('/') => {
            container.to_path_buf()
        }
        Ok(_) | Err(_) => return None,
    };
    for component in &store[matched..] {
        candidate.push(component);
    }
    if !directory_without_links(container, &candidate) {
        return None;
    }
    let resolved_container = fs::canonicalize(container).ok()?;
    let resolved_candidate = fs::canonicalize(&candidate).ok()?;
    resolved_candidate
        .starts_with(resolved_container)
        .then_some(candidate)
}

/// Check the transport boundary and every newly inferred directory component.
/// Canonical-prefix checking alone accepts a symlinked container or an internal
/// alias (including a link back to the container), broadening the selected root.
fn directory_without_links(container: &Path, candidate: &Path) -> bool {
    if container
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return false;
    }
    let Ok(relative) = candidate.strip_prefix(container) else {
        return false;
    };
    let mut current = container.to_path_buf();
    if !fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.is_dir()) {
        return false;
    }
    for component in relative.components() {
        match component {
            Component::Normal(name) => current.push(name),
            Component::CurDir => continue,
            _ => return false,
        }
        if !fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.is_dir()) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_subtrees_remain_narrow_for_strict_layout_providers() {
        for (source, store) in [
            ("~/.factory/sessions/project-a", &[".factory", "sessions"][..]),
            (
                "~/.prime/agent/sessions/project-a",
                &[".prime", "agent", "sessions"][..],
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let container = temp.path().join("opaque_hash");
            let leaf = container.join(source.rsplit('/').next().unwrap());
            fs::create_dir_all(&leaf).unwrap();
            fs::create_dir_all(container.join("unrelated-sibling")).unwrap();
            assert_eq!(resolve(&container, source, store), Some(leaf));
        }
    }

    #[test]
    fn structural_connectors_do_not_acquire_duplicate_nested_roots() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("chats")).unwrap();
        fs::create_dir_all(temp.path().join("globalStorage")).unwrap();
        assert!(resolve(temp.path(), "~/.gemini/tmp/hash/chats", &[".gemini", "tmp"]).is_none());
        assert!(
            resolve(
                temp.path(),
                "~/.config/Cursor/User/globalStorage",
                &["Cursor", "User"]
            )
            .is_none()
        );
        fs::create_dir_all(temp.path().join("run-a")).unwrap();
        assert!(
            resolve(
                temp.path(),
                "~/.vibe/logs/session/run-a",
                &[".vibe", "logs", "session"]
            )
            .is_none()
        );
    }

    #[test]
    fn ancestors_and_contents_copies_keep_the_existing_contract() {
        let temp = tempfile::tempdir().unwrap();
        let container = temp.path().join("opaque_hash");
        fs::create_dir_all(container.join("logs/session")).unwrap();
        let store = [".vibe", "logs", "session"];
        assert_eq!(
            resolve(&container, "~/.vibe/logs", &store),
            Some(container.join("logs/session"))
        );
        let contents = temp.path().join("contents_hash");
        fs::create_dir_all(contents.join("session")).unwrap();
        assert_eq!(
            resolve(&contents, "~/.vibe/logs/", &store),
            Some(contents.join("session"))
        );
        assert!(resolve(&contents, "~/.vibe/logs", &store).is_none());
    }

    #[test]
    fn subtree_ownership_requires_whole_components_and_no_traversal() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("project")).unwrap();
        for source in [
            "~/.pi/agent/sessions/project",
            "~/.omp/agent/sessions/project",
            "~/.prime-backup/agent/sessions/project",
            "~/.prime/agent/sessions-extra/project",
            "~/.prime/agent/sessions/../project",
            "~/.prime/agent/sessions/./project",
            "~/.prime/agent/sessions/\nproject",
            "~/sessions/project",
        ] {
            assert!(
                resolve(temp.path(), source, &[".prime", "agent", "sessions"]).is_none(),
                "{source}"
            );
        }
        for store in [&[][..], &[".prime", "../project"][..], &["/project"][..]] {
            assert!(resolve(temp.path(), "~/.prime/project", store).is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn inferred_roots_reject_boundary_links_internal_aliases_and_parent_paths() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        fs::create_dir_all(real.join("sessions")).unwrap();
        let linked = temp.path().join("linked");
        symlink(&real, &linked).unwrap();
        let store = [".factory", "sessions"];
        assert!(resolve(&linked, "~/.factory/sessions", &store).is_none());
        assert!(resolve(&linked, "~/.factory/sessions/", &store).is_none());
        let alias = temp.path().join("alias");
        fs::create_dir_all(alias.join("owned")).unwrap();
        symlink(alias.join("owned"), alias.join("sessions")).unwrap();
        assert!(resolve(&alias, "~/.factory/sessions", &store).is_none());
        let parent_path = real.join("sessions/..");
        assert!(resolve(&parent_path, "~/.factory/sessions", &store).is_none());
    }
    #[test]
    fn owned_projects_named_like_application_roots_remain_projects() {
        for store in [
            &[".factory", "sessions"][..],
            &[".prime", "agent", "sessions"][..],
        ] {
            for (slash, retained) in [(false, true), (true, true), (true, false)] {
                let temp = tempfile::tempdir().unwrap();
                let container = temp.path().join("opaque_hash");
                let leaf_name = store[0];
                let selected = if retained {
                    container.join(leaf_name)
                } else {
                    container.clone()
                };
                fs::create_dir_all(&selected).unwrap();
                fs::write(selected.join("session.jsonl"), b"selected session").unwrap();
                let source = format!(
                    "~/{}/{}{}",
                    store.join("/"),
                    leaf_name,
                    if slash { "/" } else { "" }
                );
                assert_eq!(resolve(&container, &source, store), Some(selected), "{source}");
            }
        }
    }

    #[test]
    fn contents_copy_fallback_requires_an_absent_leaf_for_every_provider() {
        for store in [
            &[".factory", "sessions"][..],
            &[".prime", "agent", "sessions"][..],
            &[".gemini", "tmp"][..],
            &[".vibe", "logs", "session"][..],
            &["Cursor", "User"][..],
        ] {
            let temp = tempfile::tempdir().unwrap();
            let container = temp.path().join("opaque_hash");
            fs::create_dir_all(&container).unwrap();
            let source = format!("~/{}/", store.join("/"));
            // A genuinely absent basename keeps the ordinary rsync contract.
            assert_eq!(resolve(&container, &source, store), Some(container.clone()));
            let leaf = container.join(store.last().unwrap());
            fs::write(&leaf, b"not a directory").unwrap();
            assert!(resolve(&container, &source, store).is_none(), "{source}");
            assert_eq!(fs::read(&leaf).unwrap(), b"not a directory");
        }
    }

    #[cfg(unix)]
    #[test]
    fn dangling_and_file_links_never_authorize_contents_copy_fallback() {
        use std::os::unix::fs::symlink;

        for store in [
            &[".factory", "sessions"][..],
            &[".prime", "agent", "sessions"][..],
            &[".gemini", "tmp"][..],
            &[".vibe", "logs", "session"][..],
            &["Cursor", "User"][..],
        ] {
            for target_exists in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let container = temp.path().join("opaque_hash");
                fs::create_dir_all(container.join("unselected")).unwrap();
                let outside = temp.path().join("outside");
                if target_exists {
                    fs::write(&outside, b"not a directory").unwrap();
                }
                let leaf = container.join(store.last().unwrap());
                symlink(&outside, &leaf).unwrap();
                let source = format!("~/{}/", store.join("/"));
                assert!(resolve(&container, &source, store).is_none(), "{source}");
                assert_eq!(fs::read_link(&leaf).unwrap(), outside);
            }
        }
    }

}
