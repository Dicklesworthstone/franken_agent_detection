#![cfg(feature = "connectors")]

use std::fs;
use std::path::Path;

use franken_agent_detection::{
    Connector, FactoryConnector, Origin, Platform, PrimeAgentConnector, ScanContext, ScanRoot,
};

fn put(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

struct Case {
    connector: Box<dyn Connector>,
    source: &'static str,
    file: &'static str,
    content: &'static str,
}

#[test]
fn strict_provider_project_mirrors_ingest_only_the_selected_payload() {
    let cases = [
        Case {
            connector: Box::new(FactoryConnector::new()),
            source: ".factory/sessions/project-a",
            file: "session.jsonl",
            content: concat!(
                "{\"type\":\"session_start\",\"id\":\"factory-subtree\"}\n",
                "{\"type\":\"message\",\"message\":{\"role\":\"user\",\"content\":\"selected payload\"}}\n"
            ),
        },
        Case {
            connector: Box::new(PrimeAgentConnector::new()),
            source: ".prime/agent/sessions/project-a",
            file: "session.jsonl",
            content: concat!(
                "{\"type\":\"session\",\"version\":1,\"id\":\"prime-subtree\"}\n",
                "{\"type\":\"message\",\"message\":{\"role\":\"user\",\"content\":\"selected payload\"}}\n"
            ),
        },
    ];
    for case in cases {
        for (trailing_slash, retain_basename) in [(false, true), (true, true), (true, false)] {
            let temp = tempfile::tempdir().unwrap();
            let wrapper = temp.path().join("opaque_hash");
            let leaf = Path::new(case.source).file_name().unwrap();
            let payload = if retain_basename {
                wrapper.join(leaf)
            } else {
                wrapper.clone()
            };
            let file = payload.join(case.file);
            put(&file, case.content.as_bytes());
            // A retained leaf must not broaden into other payloads. In
            // contents-copy mode the whole container is the selected payload.
            if retain_basename {
                put(
                    &wrapper.join("not-selected").join(case.file),
                    case.content.as_bytes(),
                );
            }
            let source = format!(
                "~/{}{}",
                case.source,
                if trailing_slash { "/" } else { "" }
            );
            let origin = Origin::remote_with_host("remote", "alice@remote");
            let root = ScanRoot::remote(wrapper, origin.clone(), Some(Platform::Linux))
                .with_mirrored_source_path(source);
            let ctx = ScanContext::with_roots(temp.path().join("state"), vec![root], None);
            let discovered = case.connector.discover_source_files(&ctx).unwrap();
            assert_eq!(discovered.len(), 1, "{}", case.source);
            assert_eq!(discovered[0].source_path, file);
            assert_eq!(discovered[0].origin, origin);
            let actual = case.connector.scan(&ctx).unwrap();
            assert_eq!(actual.len(), 1, "{}", case.source);
            assert_eq!(actual[0].source_path, file);
            assert_eq!(actual[0].messages[0].content, "selected payload");

            // Local detection still receives a real home layout, not the
            // transport metadata or inferred remote paths.
            let native = temp.path().join("native");
            put(
                &native.join(case.source).join(case.file),
                case.content.as_bytes(),
            );
            let local = ScanContext::with_roots(
                temp.path().join("state"),
                vec![ScanRoot::local(native)],
                None,
            );
            let expected = case.connector.scan(&local).unwrap();
            assert_eq!(expected.len(), 1);
            assert_eq!(actual[0].agent_slug, expected[0].agent_slug);
            assert_eq!(actual[0].external_id, expected[0].external_id);
            assert_eq!(fs::read(&file).unwrap(), case.content.as_bytes());
        }
    }
}
