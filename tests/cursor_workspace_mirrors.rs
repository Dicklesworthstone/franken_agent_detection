#![cfg(feature = "cursor")]

use std::fs;
use std::path::Path;

use franken_agent_detection::{
    Connector, CursorConnector, Origin, Platform, ScanContext, ScanRoot,
};

include!("support/cursor_workspace_fixture.rs");

fn put(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

#[test]
fn workspace_and_global_mirrors_parse_across_all_copy_layouts() {
    for (source, relative, native_relative) in [
        (
            "~/.config/Cursor",
            "User/workspaceStorage/selected/state.vscdb",
            "workspaceStorage/selected/state.vscdb",
        ),
        (
            "~/.config/Cursor/User",
            "workspaceStorage/selected/state.vscdb",
            "workspaceStorage/selected/state.vscdb",
        ),
        (
            "~/Library/Application Support/Cursor/User",
            "workspaceStorage/selected/state.vscdb",
            "workspaceStorage/selected/state.vscdb",
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Cursor\User",
            "workspaceStorage/selected/state.vscdb",
            "workspaceStorage/selected/state.vscdb",
        ),
        (
            "~/.config/Cursor/User/globalStorage",
            "state.vscdb",
            "globalStorage/state.vscdb",
        ),
        (
            "~/.config/Cursor/User/workspaceStorage",
            "selected/state.vscdb",
            "workspaceStorage/selected/state.vscdb",
        ),
        (
            "~/.config/Cursor/User/workspaceStorage/selected",
            "state.vscdb",
            "workspaceStorage/selected/state.vscdb",
        ),
    ] {
        for (slash, retained) in [(false, true), (true, true), (true, false)] {
            let temp = tempfile::tempdir().unwrap();
            let wrapper = temp.path().join("opaque_transport_hash");
            let leaf = source.rsplit(['/', '\\']).next().unwrap();
            let payload = if retained {
                wrapper.join(leaf)
            } else {
                wrapper.clone()
            };
            let file = payload.join(relative);
            let bytes = cursor_fixture();
            put(&file, &bytes);
            let configured = format!("{source}{}", if slash { "/" } else { "" });
            let origin = Origin::remote_with_host("laptop", "alice@laptop");
            let root = ScanRoot::remote(wrapper, origin.clone(), Some(Platform::Linux))
                .with_mirrored_source_path(&configured);
            let mut ctx =
                ScanContext::with_roots(temp.path().join("state"), vec![root.clone(), root], None);
            let connector = CursorConnector::new();
            let label = format!("{configured}, retained={retained}");
            let discovered = connector.discover_source_files(&ctx).unwrap();
            assert_eq!(discovered.len(), 1, "{label}");
            assert_eq!(discovered[0].source_path, file, "{label}");
            assert_eq!(discovered[0].origin, origin);
            assert_eq!(discovered[0].platform, Some(Platform::Linux));
            let conversations = connector.scan(&ctx).unwrap();
            assert_eq!(conversations.len(), 1, "{label}");
            let conversation = &conversations[0];
            assert_eq!(conversation.external_id.as_deref(), Some("mirror-cursor"));
            assert_eq!(conversation.source_path, file.join("mirror-cursor"));
            assert_eq!(conversation.messages.len(), 2);
            assert_eq!(conversation.messages[0].role, "user");
            assert_eq!(conversation.messages[0].content, "mirror question");
            assert_eq!(conversation.messages[1].role, "assistant");
            assert_eq!(conversation.messages[1].content, "mirror answer");
            let mut streamed = Vec::new();
            connector
                .scan_with_callback(&ctx, &mut |conversation| {
                    streamed.push(conversation);
                    Ok(())
                })
                .unwrap();
            assert_eq!(streamed.len(), 1);
            assert_eq!(streamed[0].external_id, conversation.external_id);
            let native = temp.path().join("native/.config/Cursor/User");
            put(&native.join(native_relative), &bytes);
            let local = ScanContext::with_roots(
                temp.path().join("state"),
                vec![ScanRoot::local(native)],
                None,
            );
            let expected = connector.scan(&local).unwrap();
            assert_eq!(expected.len(), 1);
            assert_eq!(expected[0].external_id, conversation.external_id);
            assert_eq!(fs::read(&file).unwrap(), bytes);
            ctx.since_ts = Some(i64::MAX);
            assert!(connector.discover_source_files(&ctx).unwrap().is_empty());
            assert!(connector.scan(&ctx).unwrap().is_empty());
        }
    }
}

#[test]
fn direct_local_workspace_roots_and_overlapping_roots_discover_each_db_once() {
    let temp = tempfile::tempdir().unwrap();
    let user = temp.path().join(".config/Cursor/User");
    let workspaces = user.join("workspaceStorage");
    let file = workspaces.join("selected/state.vscdb");
    put(&file, &cursor_fixture());
    let connector = CursorConnector::new();
    for roots in [
        vec![ScanRoot::local(workspaces.clone())],
        vec![
            ScanRoot::local(user),
            ScanRoot::local(workspaces),
            ScanRoot::local(file.clone()),
        ],
    ] {
        let ctx = ScanContext::with_roots(temp.path().join("state"), roots, None);
        let discovered = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].source_path, file);
        assert_eq!(connector.scan(&ctx).unwrap().len(), 1);
    }
}

#[cfg(unix)]
#[test]
fn owned_remote_scope_does_not_fall_back_through_a_linked_workspace_store() {
    let temp = tempfile::tempdir().unwrap();
    let wrapper = temp.path().join("opaque_transport_hash");
    fs::create_dir_all(&wrapper).unwrap();
    let outside = temp.path().join("outside");
    put(&outside.join("selected/state.vscdb"), &cursor_fixture());
    std::os::unix::fs::symlink(&outside, wrapper.join("workspaceStorage")).unwrap();
    let root = ScanRoot::remote(wrapper, Origin::remote("laptop"), None)
        .with_mirrored_source_path("~/.config/Cursor/User/workspaceStorage");
    let ctx = ScanContext::with_roots(temp.path().join("state"), vec![root], None);
    let connector = CursorConnector::new();
    assert!(connector.discover_source_files(&ctx).unwrap().is_empty());
    assert!(connector.scan(&ctx).unwrap().is_empty());
}
