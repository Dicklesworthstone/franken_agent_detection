//! Custom-store detection must work without any connector feature enabled.
//! Empty regular files exercise filesystem admission, not SQLite validity;
//! connector-backed fixtures separately test parsing actual session stores.
//! Unix subprocesses isolate HOME and environment overrides from other tests.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

use franken_agent_detection::{
    AgentDetectOptions, AgentDetectRootOverride, detect_installed_agents,
};
use tempfile::TempDir;

const CHILD_ROOT: &str = "FAD_ROOT_PROBE_TEST_ROOT";
const CHILD_SLUG: &str = "FAD_ROOT_PROBE_TEST_SLUG";
const CHILD_EXPECTED: &str = "FAD_ROOT_PROBE_TEST_EXPECTED";
const VARIABLES: [&str; 9] = [
    "GEMINI_HOME",
    "OPENCODE_STORAGE_ROOT",
    "OPENCODE_SQLITE_DB",
    "HERMES_HOME",
    "HERMES_SQLITE_DB",
    "CRUSH_SQLITE_DB",
    "GOOSE_PATH_ROOT",
    "GOOSE_SQLITE_DB",
    "CASS_CURSOR_PROJECTS_ROOT",
];

// Table columns: overrides, existing directories, existing files, expected roots.
type ProbeCase<'a> = (
    &'a [(&'a str, &'a str)],
    &'a [&'a str],
    &'a [&'a str],
    &'a [&'a str],
);
type DefaultProbeCase<'a> = (&'a str, &'a [&'a str], &'a [&'a str], &'a [&'a str]);

fn run_cases(slug: &str, cases: &[ProbeCase<'_>]) {
    for &(variables, directories, files, expected) in cases {
        let root = TempDir::new().unwrap();
        for relative in directories
            .iter()
            .copied()
            .chain(["home", "explicit-scope"])
        {
            std::fs::create_dir_all(root.path().join(relative)).unwrap();
        }
        for relative in files {
            let path = root.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, []).unwrap();
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "custom_root_probe_child", "--nocapture"])
            .current_dir(root.path())
            .env(CHILD_ROOT, root.path())
            .env(CHILD_SLUG, slug)
            .env(CHILD_EXPECTED, expected.join("\n"))
            .env("HOME", root.path().join("home"))
            .env("XDG_DATA_HOME", root.path().join("home/.local/share"))
            .env("XDG_CONFIG_HOME", root.path().join("home/.config"));
        for variable in VARIABLES {
            command.env_remove(variable);
        }
        for &(variable, value) in variables {
            if value.trim().is_empty() {
                command.env(variable, value);
            } else {
                command.env(variable, root.path().join(value));
            }
        }
        let output = command
            .output()
            .expect("run isolated root-probe regression");
        assert!(
            output.status.success(),
            "slug={slug} env={variables:?} dirs={directories:?} files={files:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        for relative in files {
            assert!(
                std::fs::read(root.path().join(relative))
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

fn assert_detected_roots(slug: &str, scope: Option<&Path>, expected: &[String]) {
    for include_undetected in [true, false] {
        let report = detect_installed_agents(&AgentDetectOptions {
            only_connectors: Some(vec![slug.into()]),
            include_undetected,
            root_overrides: scope
                .map(|root| AgentDetectRootOverride {
                    slug: slug.into(),
                    root: root.to_path_buf(),
                })
                .into_iter()
                .collect(),
        })
        .unwrap();
        let detected = !expected.is_empty();
        assert_eq!(report.summary.total_count, 1);
        assert_eq!(report.summary.detected_count, usize::from(detected));
        assert_eq!(
            report.installed_agents.len(),
            usize::from(detected || include_undetected),
        );
        if let Some(entry) = report.installed_agents.first() {
            assert_eq!(entry.slug, slug);
            assert_eq!(entry.detected, detected);
            // Priority is part of the public report; do not sort or deduplicate.
            assert_eq!(entry.root_paths, expected);
        }
    }
}

#[test]
fn custom_root_probe_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let slug = std::env::var(CHILD_SLUG).unwrap();
    let expected: Vec<_> = std::env::var(CHILD_EXPECTED)
        .unwrap()
        .lines()
        .map(|relative| root.join(relative).display().to_string())
        .collect();
    assert_detected_roots(&slug, None, &expected);

    // Caller-supplied scopes bypass environment/default policy in every case.
    let scope = root.join("explicit-scope");
    assert_detected_roots(&slug, Some(&scope), &[scope.display().to_string()]);
    assert_detected_roots(&slug, Some(&root.join("missing-scope")), &[]);
}

#[test]
fn gemini_home_replaces_defaults_and_admits_only_supported_file_shapes() {
    run_cases(
        "gemini",
        &[
            (&[("GEMINI_HOME", "custom")], &["custom"], &[], &["custom"]),
            (
                &[("GEMINI_HOME", "custom/chats/session-one.JSON")],
                &["home/.gemini"],
                &["custom/chats/session-one.JSON"],
                &["custom/chats/session-one.JSON"],
            ),
            (
                &[("GEMINI_HOME", "custom/chats/session-two.jsonl")],
                &[],
                &["custom/chats/session-two.jsonl"],
                &["custom/chats/session-two.jsonl"],
            ),
            (&[("GEMINI_HOME", "missing")], &["home/.gemini"], &[], &[]),
            (
                &[("GEMINI_HOME", "custom/session-one.json")],
                &["home/.gemini"],
                &["custom/session-one.json"],
                &[],
            ),
            (
                &[("GEMINI_HOME", "custom/chats/unrelated.json")],
                &["home/.gemini"],
                &["custom/chats/unrelated.json"],
                &[],
            ),
            (
                &[("GEMINI_HOME", "custom/chats/session-one.txt")],
                &["home/.gemini"],
                &["custom/chats/session-one.txt"],
                &[],
            ),
        ],
    );
}

#[test]
fn opencode_custom_stores_are_additive_and_invalid_kinds_allow_fallbacks() {
    run_cases(
        "opencode",
        &[
            (
                &[("OPENCODE_STORAGE_ROOT", "custom/storage")],
                &["custom/storage"],
                &[],
                &["custom/storage"],
            ),
            (
                &[("OPENCODE_SQLITE_DB", "custom/selected")],
                &[],
                &["custom/selected"],
                &["custom/selected"],
            ),
            (
                &[
                    ("OPENCODE_SQLITE_DB", "custom/db"),
                    ("OPENCODE_STORAGE_ROOT", "custom/storage"),
                ],
                &["custom/storage"],
                &["custom/db", "home/.local/share/opencode/opencode.db"],
                &[
                    "custom/db",
                    "custom/storage",
                    "home/.local/share/opencode/opencode.db",
                    "home/.local/share/opencode",
                ],
            ),
            (
                &[
                    ("OPENCODE_SQLITE_DB", "missing"),
                    ("OPENCODE_STORAGE_ROOT", "missing-storage"),
                ],
                &[],
                &["home/.local/share/opencode/opencode.db"],
                &[
                    "home/.local/share/opencode/opencode.db",
                    "home/.local/share/opencode",
                ],
            ),
            (
                &[
                    ("OPENCODE_SQLITE_DB", "directory"),
                    ("OPENCODE_STORAGE_ROOT", "file"),
                ],
                &["directory", "home/.config/opencode/storage"],
                &["file"],
                &["home/.config/opencode"],
            ),
        ],
    );
}

#[test]
fn hermes_selects_explicit_database_then_home_then_defaults() {
    run_cases(
        "hermes",
        &[
            (
                &[("HERMES_SQLITE_DB", "selected")],
                &[],
                &["selected"],
                &["selected"],
            ),
            (
                &[("HERMES_HOME", "custom")],
                &[],
                &["custom/state.db"],
                &["custom/state.db"],
            ),
            (
                &[("HERMES_SQLITE_DB", "selected"), ("HERMES_HOME", "custom")],
                &[],
                &["selected", "custom/state.db", "home/.hermes/state.db"],
                &["selected"],
            ),
            (
                &[("HERMES_SQLITE_DB", "directory"), ("HERMES_HOME", "custom")],
                &["directory"],
                &["custom/state.db", "home/.hermes/state.db"],
                &["custom/state.db"],
            ),
            (
                &[("HERMES_SQLITE_DB", "missing"), ("HERMES_HOME", "custom")],
                &["custom/state.db"],
                &["home/.hermes/state.db"],
                &["home/.hermes/state.db", "home/.hermes"],
            ),
            (
                &[("HERMES_SQLITE_DB", "missing"), ("HERMES_HOME", "file")],
                &[],
                &["file", "home/.hermes/state.db"],
                &["home/.hermes/state.db", "home/.hermes"],
            ),
        ],
    );
}

#[test]
fn crush_selects_an_explicit_file_and_falls_back_when_unavailable() {
    run_cases(
        "crush",
        &[
            (
                &[("CRUSH_SQLITE_DB", "selected")],
                &[],
                &["selected"],
                &["selected"],
            ),
            (
                &[("CRUSH_SQLITE_DB", "selected")],
                &[],
                &["selected", "home/.crush/crush.db"],
                &["selected"],
            ),
            (
                &[("CRUSH_SQLITE_DB", "missing")],
                &[],
                &["home/.crush/crush.db"],
                &["home/.crush", "home/.crush/crush.db"],
            ),
            (
                &[("CRUSH_SQLITE_DB", "directory")],
                &["directory"],
                &["home/.crush/crush.db"],
                &["home/.crush", "home/.crush/crush.db"],
            ),
        ],
    );
}

#[test]
fn goose_database_and_jsonl_directory_fallbacks_are_independent() {
    run_cases(
        "goose",
        &[
            (
                &[("GOOSE_SQLITE_DB", "selected")],
                &[],
                &["selected"],
                &["selected"],
            ),
            (
                &[
                    ("GOOSE_SQLITE_DB", "selected"),
                    ("GOOSE_PATH_ROOT", "missing"),
                ],
                &[],
                &["selected"],
                &["selected"],
            ),
            (
                &[("GOOSE_PATH_ROOT", "custom")],
                &["custom/data/sessions"],
                &[],
                &["custom/data/sessions"],
            ),
            (
                &[
                    ("GOOSE_SQLITE_DB", "selected"),
                    ("GOOSE_PATH_ROOT", "missing"),
                ],
                &["home/.local/share/goose/sessions"],
                &["selected"],
                &["selected", "home/.local/share/goose/sessions"],
            ),
            (
                &[
                    ("GOOSE_SQLITE_DB", "missing"),
                    ("GOOSE_PATH_ROOT", "custom"),
                ],
                &["custom/data/sessions"],
                &["home/.local/share/goose/sessions/sessions.db"],
                &[
                    "home/.local/share/goose/sessions/sessions.db",
                    "custom/data/sessions",
                ],
            ),
            (
                &[
                    ("GOOSE_SQLITE_DB", "directory"),
                    ("GOOSE_PATH_ROOT", "custom"),
                ],
                &["directory", "home/.local/share/goose/sessions"],
                &["custom/data/sessions/sessions.db"],
                &["custom/data/sessions/sessions.db", "custom/data/sessions"],
            ),
            (
                &[("GOOSE_PATH_ROOT", "file")],
                &[],
                &["file", "home/.goose/sessions/sessions.db"],
                &["home/.goose/sessions/sessions.db", "home/.goose/sessions"],
            ),
        ],
    );
}

#[test]
fn cursor_projects_replace_agent_history_and_preserve_composer_probes() {
    run_cases(
        "cursor",
        &[
            (
                &[("CASS_CURSOR_PROJECTS_ROOT", "custom")],
                &["custom"],
                &[],
                &["custom"],
            ),
            (
                &[("CASS_CURSOR_PROJECTS_ROOT", "custom")],
                &[
                    "custom",
                    "home/.cursor/projects",
                    "home/.config/Cursor/User",
                ],
                &[],
                &["custom", "home/.config/Cursor", "home/.config/Cursor/User"],
            ),
            (
                &[("CASS_CURSOR_PROJECTS_ROOT", "missing")],
                &["home/.cursor/projects"],
                &[],
                &[],
            ),
            (
                &[("CASS_CURSOR_PROJECTS_ROOT", "file")],
                &["home/.cursor/projects", "home/.config/Cursor/User"],
                &["file"],
                &["home/.config/Cursor", "home/.config/Cursor/User"],
            ),
        ],
    );
}

#[test]
fn unset_and_blank_custom_variables_preserve_default_probe_roots() {
    let defaults: &[DefaultProbeCase<'_>] = &[
        (
            "gemini",
            &["GEMINI_HOME"],
            &["home/.gemini"],
            &["home/.gemini"],
        ),
        (
            "opencode",
            &["OPENCODE_STORAGE_ROOT", "OPENCODE_SQLITE_DB"],
            &["home/.local/share/opencode"],
            &["home/.local/share/opencode"],
        ),
        (
            "hermes",
            &["HERMES_HOME", "HERMES_SQLITE_DB"],
            &["home/.hermes"],
            &["home/.hermes"],
        ),
        (
            "crush",
            &["CRUSH_SQLITE_DB"],
            &["home/.crush"],
            &["home/.crush"],
        ),
        (
            "goose",
            &["GOOSE_SQLITE_DB", "GOOSE_PATH_ROOT"],
            &["home/.goose/sessions"],
            &["home/.goose/sessions", "home/.goose"],
        ),
        (
            "cursor",
            &["CASS_CURSOR_PROJECTS_ROOT"],
            &["home/.cursor"],
            &["home/.cursor"],
        ),
    ];
    for &(slug, variables, directories, expected) in defaults {
        run_cases(slug, &[(&[], directories, &[], expected)]);
        for blank in ["", " \t "] {
            let environment: Vec<_> = variables.iter().map(|&key| (key, blank)).collect();
            run_cases(slug, &[(&environment, directories, &[], expected)]);
        }
    }
}
