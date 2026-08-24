//! Connector for Oh My Pi (`omp`, <https://omp.sh>).
//!
//! `omp` is a pi-mono derivative coding agent with a native Rust engine. As
//! of OMP v18 the session store is selected by a resolver
//! (`packages/utils/src/dirs.ts` upstream) rather than a single pinned home:
//!
//! - default: `~/.omp/agent/sessions` (config dir name overridable via
//!   `PI_CONFIG_DIR`);
//! - named profiles (`OMP_PROFILE`, legacy fallback `PI_PROFILE`):
//!   `~/.omp/profiles/<name>/agent/sessions`;
//! - XDG (Linux/macOS, existence-gated, flattens the `agent/` segment):
//!   `$XDG_DATA_HOME/omp/sessions` and
//!   `$XDG_DATA_HOME/omp/profiles/<name>/sessions`;
//! - direct overrides: `PI_CODING_AGENT_SESSION_DIR` (exact sessions dir)
//!   and `PI_CODING_AGENT_DIR` (agent dir; ignored by upstream when a named
//!   profile is active).
//!
//! Because this crate indexes archives rather than resolving one live
//! location, discovery takes the existence-gated *union* of every root the
//! upstream resolver could select and deduplicates by canonical path;
//! upstream's precedence rules matter for which env vars are honoured (see
//! [`OmpConnector::v18_roots_from`]) but never shrink the union. Session
//! layout under each root:
//!
//! - `<root>/sessions/<safe-path>/<timestamp>_<uuid>.jsonl` — main
//!   transcripts, where `<safe-path>` is derived from the working directory
//! - `<root>/sessions/<safe-path>/<timestamp>_<uuid>/<AgentName>.jsonl`
//!   — sub-agent transcripts (each a complete session document)
//!
//! The wire format is the pi-mono JSONL store (`session` header, `message`,
//! `model_change`, `thinking_level_change` entries) plus omp-specific `title`
//! entries and bare-`model` `model_change` records; both are handled by the
//! shared pi-family parser in [`super::pi_wire`].

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;

use super::scan::{DiscoveredSourceFile, ScanContext, ScanRoot};
use super::{Connector, franken_detection_for_connector};
use crate::types::{DetectionResult, NormalizedConversation};

pub struct OmpConnector;

impl Default for OmpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl OmpConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Normalize and validate an OMP profile name, mirroring upstream
    /// `normalizeProfileName` (dirs.ts): trim; empty and the literal
    /// `"default"` mean the default profile (`None`). Where upstream throws
    /// (invalid syntax, `.`/`..`, trailing dot, Windows reserved device
    /// names), this returns `None` — matching upstream's *module-load* safe
    /// path, which falls back to the default profile instead of crashing.
    fn normalize_profile_name(profile: &str) -> Option<String> {
        let name = profile.trim();
        if name.is_empty() || name == "default" || name == "." || name == ".." {
            return None;
        }
        if name.ends_with('.') || name.len() > 64 {
            return None;
        }
        let mut chars = name.chars();
        let first_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        if !first_ok
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
        {
            return None;
        }
        // Windows reserved device basenames (CON, PRN, AUX, NUL, COM0-9,
        // LPT0-9), including any `BASENAME.<ext>` form, case-insensitive.
        let base = name.split('.').next().unwrap_or(name);
        let upper = base.to_ascii_uppercase();
        let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (upper.len() == 4
                && (upper.starts_with("COM") || upper.starts_with("LPT"))
                && upper.as_bytes()[3].is_ascii_digit());
        if reserved {
            return None;
        }
        Some(name.to_string())
    }

    /// Resolve the active profile from the two profile env vars, mirroring
    /// upstream `resolveProfileEnv`: `OMP_PROFILE` is canonical and takes
    /// precedence whenever it is *set* — an explicitly-empty `OMP_PROFILE`
    /// selects the default profile rather than falling through to the
    /// legacy `PI_PROFILE`.
    fn active_profile(env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
        env("OMP_PROFILE").map_or_else(
            || env("PI_PROFILE").and_then(|pi| Self::normalize_profile_name(&pi)),
            |omp| Self::normalize_profile_name(&omp),
        )
    }

    /// Enumerate `<profiles_root>/<name>` subdirectories whose names are
    /// valid OMP profile names, sorted for determinism.
    fn enumerate_profiles(profiles_root: &Path) -> Vec<(String, PathBuf)> {
        let mut out: Vec<(String, PathBuf)> = std::fs::read_dir(profiles_root)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| {
                let raw = entry.file_name().to_str()?.to_string();
                // A directory literally named "default" is not a valid
                // named profile (upstream maps it to the default profile).
                Self::normalize_profile_name(&raw).map(|name| (name, entry.path()))
            })
            .collect();
        out.sort();
        out
    }

    /// Test-accessible derivation of candidate omp agent homes with profile
    /// provenance, from an explicit home directory and an env lookup —
    /// split out so precedence stays unit-testable without touching process
    /// environment.
    ///
    /// Mirrors the OMP v18 resolver (upstream `DirResolver` in dirs.ts),
    /// as an existence-gated union suitable for archive indexing:
    ///
    /// 1. `PI_CODING_AGENT_SESSION_DIR` — the exact launch-time sessions
    ///    dir, attributed to the active profile;
    /// 2. `PI_CODING_AGENT_DIR` — agent-dir override; upstream ignores it
    ///    while a named profile is active, so we do too;
    /// 3. the default agent dir `~/<cfg>/agent`, where `<cfg>` is
    ///    `PI_CONFIG_DIR` or `.omp`;
    /// 4. every named-profile agent dir `~/<cfg>/profiles/<name>/agent`;
    /// 5. XDG roots `$XDG_DATA_HOME/omp` and
    ///    `$XDG_DATA_HOME/omp/profiles/<name>` when those directories
    ///    exist (upstream gates XDG on existence; the app-root name is the
    ///    `omp` constant, not `PI_CONFIG_DIR`). XDG flattens the `agent/`
    ///    segment, which `pi_wire::sessions_dir` already handles.
    ///
    /// Entries 1–3 are pushed unconditionally (scanning tolerates missing
    /// dirs); 4–5 are enumerated from the filesystem. Callers dedupe by
    /// canonical path, first-wins, so more-specific provenance stays ahead.
    fn v18_roots_from(
        home: Option<&Path>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Vec<(PathBuf, Option<String>)> {
        let mut out: Vec<(PathBuf, Option<String>)> = Vec::new();
        let profile = Self::active_profile(env);

        if let Some(session_dir) = env("PI_CODING_AGENT_SESSION_DIR").filter(|v| !v.is_empty()) {
            out.push((PathBuf::from(session_dir), profile.clone()));
        }
        if profile.is_none() {
            if let Some(agent_dir) = env("PI_CODING_AGENT_DIR").filter(|v| !v.is_empty()) {
                out.push((PathBuf::from(agent_dir), None));
            }
        }

        if let Some(home) = home {
            let cfg_name = env("PI_CONFIG_DIR")
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| ".omp".to_string());
            // Upstream resolves the config root via Node `path.join(home,
            // name)`, which keeps even an absolute-looking override *under*
            // home; Rust `Path::join` would replace the whole path, so
            // strip leading separators to preserve upstream semantics.
            let base = home.join(cfg_name.trim_start_matches(['/', '\\']));
            out.push((base.join("agent"), None));
            for (name, dir) in Self::enumerate_profiles(&base.join("profiles")) {
                out.push((dir.join("agent"), Some(name)));
            }
        }

        if let Some(xdg_data) = env("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
            let app_root = PathBuf::from(xdg_data).join("omp");
            if app_root.is_dir() {
                for (name, dir) in Self::enumerate_profiles(&app_root.join("profiles")) {
                    out.push((dir, Some(name)));
                }
                out.push((app_root, None));
            }
        }

        out
    }

    /// All candidate omp agent home directories (with profile provenance)
    /// in priority order, resolved from the live environment.
    fn default_homes_tagged() -> Vec<(PathBuf, Option<String>)> {
        Self::v18_roots_from(dirs::home_dir().as_deref(), &|key| std::env::var(key).ok())
    }

    /// True when `path` plausibly names an omp store: either an explicit
    /// `sessions` directory handed over by a caller, or any path carrying
    /// the canonical `.omp` marker.
    fn looks_like_root(path: &Path) -> bool {
        if path
            .file_name()
            .is_some_and(|n| n == "sessions" || n == "omp")
        {
            return true;
        }
        path.to_str().is_some_and(|s| s.contains(".omp"))
    }

    /// Expand one explicit scan root (typically a copied/mounted home dir)
    /// into every omp store layout it may contain, with profile provenance.
    fn explicit_root_candidates(root: &Path) -> Vec<(PathBuf, Option<String>)> {
        let mut out: Vec<(PathBuf, Option<String>)> = vec![
            (root.to_path_buf(), None),
            (root.join(".omp/agent"), None),
            (root.join(".omp/agent/sessions"), None),
        ];
        for (name, dir) in Self::enumerate_profiles(&root.join(".omp/profiles")) {
            out.push((dir.join("agent"), Some(name)));
        }
        // XDG profile stores must come before the XDG app root: when the
        // app root has no `sessions/` child, `pi_wire::sessions_dir` falls
        // back to walking the whole app root, and first-wins dedup must
        // keep the profile attribution for files under `profiles/`.
        for (name, dir) in Self::enumerate_profiles(&root.join(".local/share/omp/profiles")) {
            out.push((dir, Some(name)));
        }
        out.push((root.join(".local/share/omp"), None));
        out
    }

    fn source_roots(ctx: &ScanContext) -> Vec<(ScanRoot, Option<String>)> {
        let is_omp_agent_dir = ctx
            .data_dir
            .to_str()
            .is_some_and(|s| s.contains(".omp/agent"));

        let mut homes: Vec<(ScanRoot, Option<String>)> = Vec::new();
        if ctx.use_default_detection() {
            if is_omp_agent_dir {
                homes.push((ScanRoot::local(ctx.data_dir.clone()), None));
            } else {
                homes.extend(
                    Self::default_homes_tagged()
                        .into_iter()
                        .map(|(path, profile)| (ScanRoot::local(path), profile)),
                );
            }
        } else {
            if Self::looks_like_root(&ctx.data_dir) {
                homes.push((ScanRoot::local(ctx.data_dir.clone()), None));
            }

            for scan_root in &ctx.scan_roots {
                for (candidate, profile) in Self::explicit_root_candidates(&scan_root.path) {
                    // Existence gate: string-marker acceptance must not
                    // fabricate phantom roots under unrelated scan roots.
                    // (Profile candidates are enumerated from the fs, so
                    // they exist by construction; the marker check keeps
                    // unrelated bare scan roots out.)
                    if candidate.exists()
                        && (profile.is_some() || Self::looks_like_root(&candidate))
                    {
                        homes.push((scan_root.with_path(candidate), profile));
                    }
                }
            }
        }

        for (home, _) in &mut homes {
            if home.path.is_file() {
                home.path = home.path.parent().unwrap_or(&home.path).to_path_buf();
            }
        }

        let mut seen = HashSet::new();
        homes.retain(|(root, _)| {
            let canonical = std::fs::canonicalize(&root.path).unwrap_or_else(|_| root.path.clone());
            seen.insert(canonical)
        });
        homes
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        // Pass full ScanRoots (profile tags don't participate in discovery)
        // so remote-origin/platform provenance survives into each source.
        let roots: Vec<ScanRoot> = Self::source_roots(ctx)
            .into_iter()
            .map(|(root, _)| root)
            .collect();
        super::pi_wire::discover_sources(&roots, ctx, "omp")
    }
}

impl Connector for OmpConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("omp").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let homes: Vec<(PathBuf, Option<String>)> = Self::source_roots(ctx)
            .into_iter()
            .map(|(root, profile)| (root.path, profile))
            .collect();
        super::pi_wire::scan_homes_tagged(&homes, ctx, "omp")
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use serde_json::json;
    use std::fs;

    const SESSION_STEM: &str = "2026-08-23T17-54-58-682Z_01a02fc2-ebfa-72f6-af9a-d40ae5078aa4";
    const WORKSPACE_CWD: &str = "/Users/jemanuel/projects/franken_agent_detection";

    // =====================================================
    // Constructor Tests
    // =====================================================

    #[test]
    fn new_creates_connector() {
        let _ = OmpConnector::new();
    }

    #[test]
    fn default_creates_connector() {
        let _ = OmpConnector;
    }

    // =====================================================
    // v18 resolver tests (profile env precedence, config/agent overrides,
    // profile enumeration, XDG) — all through the pure `v18_roots_from`
    // so no process environment is touched.
    // =====================================================

    /// Env closure over a fixed set of (key, value) pairs.
    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn v18_roots_pin_the_canonical_omp_agent_dir_by_default() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(
            OmpConnector::v18_roots_from(Some(dir.path()), &env_of(&[])),
            vec![(dir.path().join(".omp").join("agent"), None)]
        );
    }

    #[test]
    fn v18_roots_are_empty_without_a_home_or_env() {
        assert!(OmpConnector::v18_roots_from(None, &env_of(&[])).is_empty());
    }

    #[test]
    fn normalize_profile_name_matches_upstream_rules() {
        let ok = |s: &str| OmpConnector::normalize_profile_name(s);
        assert_eq!(ok("work"), Some("work".to_string()));
        assert_eq!(ok("  work  "), Some("work".to_string()));
        assert_eq!(ok("a-1._x"), Some("a-1._x".to_string()));
        // Default sentinels.
        assert_eq!(ok(""), None);
        assert_eq!(ok("   "), None);
        assert_eq!(ok("default"), None);
        // Invalid syntax → safe default (upstream module-load behavior).
        assert_eq!(ok("Work"), None); // uppercase
        assert_eq!(ok("-work"), None); // bad first char
        assert_eq!(ok("work."), None); // trailing dot
        assert_eq!(ok("."), None);
        assert_eq!(ok(".."), None);
        assert_eq!(ok(&"a".repeat(65)), None); // too long
        // Windows reserved device names, with and without extension.
        assert_eq!(ok("con"), None);
        assert_eq!(ok("con.txt"), None);
        assert_eq!(ok("com7"), None);
        assert_eq!(ok("lpt0.log"), None);
        // Near-misses of the reserved set stay valid.
        assert_eq!(ok("com77"), Some("com77".to_string()));
        assert_eq!(ok("console"), Some("console".to_string()));
    }

    #[test]
    fn omp_profile_env_takes_precedence_including_explicit_empty() {
        let both = env_of(&[("OMP_PROFILE", "work"), ("PI_PROFILE", "legacy")]);
        assert_eq!(
            OmpConnector::active_profile(&both),
            Some("work".to_string())
        );

        // Explicitly-empty OMP_PROFILE selects the default profile and
        // must NOT fall back to PI_PROFILE.
        let explicit_empty = env_of(&[("OMP_PROFILE", ""), ("PI_PROFILE", "legacy")]);
        assert_eq!(OmpConnector::active_profile(&explicit_empty), None);

        // PI_PROFILE is honoured only when OMP_PROFILE is unset.
        let legacy_only = env_of(&[("PI_PROFILE", "legacy")]);
        assert_eq!(
            OmpConnector::active_profile(&legacy_only),
            Some("legacy".to_string())
        );
    }

    #[test]
    fn v18_roots_honor_pi_config_dir_rename() {
        let dir = tempfile::TempDir::new().unwrap();
        let pairs = [("PI_CONFIG_DIR", ".pi2")];
        let roots = OmpConnector::v18_roots_from(Some(dir.path()), &env_of(&pairs));
        assert_eq!(roots, vec![(dir.path().join(".pi2").join("agent"), None)]);

        // Node path.join keeps an absolute-looking name under home; the
        // Rust port must not let it escape.
        let abs_pairs = [("PI_CONFIG_DIR", "/etc/omp-cfg")];
        let roots = OmpConnector::v18_roots_from(Some(dir.path()), &env_of(&abs_pairs));
        assert_eq!(
            roots,
            vec![(dir.path().join("etc/omp-cfg").join("agent"), None)]
        );
    }

    #[test]
    fn v18_roots_include_named_profiles_under_home() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().join(".omp");
        fs::create_dir_all(base.join("profiles").join("work").join("agent")).unwrap();
        fs::create_dir_all(base.join("profiles").join("play")).unwrap();
        // Invalid / sentinel profile dirs are skipped.
        fs::create_dir_all(base.join("profiles").join("default")).unwrap();
        fs::create_dir_all(base.join("profiles").join("Bad.Name.")).unwrap();

        let roots = OmpConnector::v18_roots_from(Some(dir.path()), &env_of(&[]));
        assert_eq!(
            roots,
            vec![
                (base.join("agent"), None),
                (
                    base.join("profiles").join("play").join("agent"),
                    Some("play".to_string())
                ),
                (
                    base.join("profiles").join("work").join("agent"),
                    Some("work".to_string())
                ),
            ]
        );
    }

    #[test]
    fn v18_roots_honor_agent_dir_override_only_without_a_named_profile() {
        let dir = tempfile::TempDir::new().unwrap();
        let custom = dir.path().join("custom-agent");

        let plain_pairs = [("PI_CODING_AGENT_DIR", custom.to_str().unwrap())];
        let plain = env_of(&plain_pairs);
        let roots = OmpConnector::v18_roots_from(Some(dir.path()), &plain);
        assert_eq!(roots[0], (custom.clone(), None));

        // Upstream ignores the agent-dir override while a named profile is
        // active; the resolver must too.
        let profile_pairs = [
            ("PI_CODING_AGENT_DIR", custom.to_str().unwrap()),
            ("OMP_PROFILE", "work"),
        ];
        let with_profile = env_of(&profile_pairs);
        let roots = OmpConnector::v18_roots_from(Some(dir.path()), &with_profile);
        assert!(!roots.iter().any(|(p, _)| *p == custom));
    }

    #[test]
    fn v18_roots_put_the_direct_session_dir_first_with_profile_provenance() {
        let dir = tempfile::TempDir::new().unwrap();
        let session_dir = dir.path().join("launch-sessions");
        let pairs = [
            ("PI_CODING_AGENT_SESSION_DIR", session_dir.to_str().unwrap()),
            ("OMP_PROFILE", "work"),
        ];
        let env = env_of(&pairs);
        let roots = OmpConnector::v18_roots_from(Some(dir.path()), &env);
        assert_eq!(roots[0], (session_dir.clone(), Some("work".to_string())));
    }
    #[test]
    fn discovery_preserves_remote_scan_root_provenance() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = dir.path().join(".omp").join("agent");
        write_omp_fixture(&agent);

        let ctx = ScanContext::with_roots(
            PathBuf::from("/nonexistent"),
            vec![ScanRoot::remote(
                dir.path().to_path_buf(),
                crate::types::Origin::remote_with_host("host-b", "host-b.example"),
                Some(crate::types::Platform::Macos),
            )],
            None,
        );
        let sources = OmpConnector::new()
            .discover_source_files(&ctx)
            .expect("discovery");
        assert_eq!(sources.len(), 2, "main + sub-agent transcripts");
        for source in &sources {
            assert!(
                source.origin.is_remote(),
                "remote provenance must survive omp discovery, got {:?}",
                source.origin
            );
            assert_eq!(source.platform, Some(crate::types::Platform::Macos));
            assert_eq!(source.provider_slug, "omp");
        }
    }

    #[test]
    fn v18_roots_include_existing_xdg_default_and_profile_stores() {
        let dir = tempfile::TempDir::new().unwrap();
        let xdg = dir.path().join("xdg-data");

        let app = xdg.join("omp");
        fs::create_dir_all(app.join("sessions")).unwrap();
        fs::create_dir_all(app.join("profiles").join("work").join("sessions")).unwrap();

        let pairs = [("XDG_DATA_HOME", xdg.to_str().unwrap())];
        let env = env_of(&pairs);
        let roots = OmpConnector::v18_roots_from(Some(dir.path()), &env);

        // Profile XDG roots come before the app root so first-wins dedup
        // keeps profile attribution for files under profiles/.
        assert_eq!(
            roots,
            vec![
                (dir.path().join(".omp").join("agent"), None),
                (app.join("profiles").join("work"), Some("work".to_string())),
                (app.clone(), None),
            ]
        );

        // XDG is existence-gated: no app dir, no roots.
        let missing_pairs = [("XDG_DATA_HOME", "/nonexistent-xdg-data-home")];
        let missing = env_of(&missing_pairs);
        let roots = OmpConnector::v18_roots_from(Some(dir.path()), &missing);
        assert_eq!(roots, vec![(dir.path().join(".omp").join("agent"), None)]);
    }

    // =====================================================
    // looks_like_root / source_roots Tests
    // =====================================================

    #[test]
    fn looks_like_root_accepts_omp_agent_and_sessions_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = dir.path().join(".omp").join("agent");
        fs::create_dir_all(agent.join("sessions")).unwrap();

        assert!(OmpConnector::looks_like_root(&agent));
        assert!(OmpConnector::looks_like_root(&agent.join("sessions")));

        // Unrelated directories are rejected even when they contain a
        // sessions child.
        let other = dir.path().join("claude-home");
        fs::create_dir_all(other.join("sessions")).unwrap();
        assert!(!OmpConnector::looks_like_root(&other));
    }

    #[test]
    fn source_roots_use_default_home_when_ctx_data_dir_is_unrelated() {
        let dir = tempfile::TempDir::new().unwrap();
        let ctx = ScanContext::local_default(dir.path().join("cass-state"), None);
        let roots = OmpConnector::source_roots(&ctx);
        // The live environment may add profile/XDG/env-override roots, but
        // the canonical default agent home is always present.
        assert!(roots.iter().any(|(root, profile)| root.path
            == dirs::home_dir().unwrap().join(".omp/agent")
            && profile.is_none()));
    }

    #[test]
    fn source_roots_prefer_an_omp_shaped_data_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = dir.path().join(".omp").join("agent");
        fs::create_dir_all(&agent).unwrap();

        let ctx = ScanContext::local_default(agent.clone(), None);
        let roots = OmpConnector::source_roots(&ctx);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].0.path, agent);
    }

    #[test]
    fn source_roots_expand_explicit_scan_roots_to_omp_layouts() {
        let dir = tempfile::TempDir::new().unwrap();

        // Root whose `.omp/agent/sessions` tree must be discovered by
        // expansion (a typical remote-home scan root).
        let nested = dir.path().join("another-home");
        fs::create_dir_all(
            nested
                .join(".omp")
                .join("agent")
                .join("sessions")
                .join("--data-projects-app--"),
        )
        .unwrap();

        let ctx = ScanContext::with_roots(
            dir.path().join("cass-state"),
            vec![ScanRoot::local(nested.clone())],
            None,
        );

        let mut paths: Vec<PathBuf> = OmpConnector::source_roots(&ctx)
            .into_iter()
            .map(|(root, _)| root.path)
            .collect();
        paths.sort();

        // Both the agent home and its sessions subtree qualify; scans
        // deduplicate files reached through overlapping roots.
        assert_eq!(
            paths,
            vec![
                nested.join(".omp").join("agent"),
                nested.join(".omp").join("agent").join("sessions"),
            ]
        );
    }

    #[test]
    fn source_roots_expand_explicit_scan_roots_to_profile_and_xdg_layouts() {
        let dir = tempfile::TempDir::new().unwrap();
        let nested = dir.path().join("copied-home");
        fs::create_dir_all(
            nested
                .join(".omp")
                .join("profiles")
                .join("work")
                .join("agent"),
        )
        .unwrap();
        fs::create_dir_all(nested.join(".local/share/omp").join("sessions")).unwrap();
        fs::create_dir_all(
            nested
                .join(".local/share/omp")
                .join("profiles")
                .join("play")
                .join("sessions"),
        )
        .unwrap();

        let ctx = ScanContext::with_roots(
            dir.path().join("cass-state"),
            vec![ScanRoot::local(nested.clone())],
            None,
        );

        let roots = OmpConnector::source_roots(&ctx);
        let find = |p: &Path| {
            roots
                .iter()
                .find(|(root, _)| root.path == p)
                .map(|(_, pr)| pr)
        };

        assert_eq!(
            find(&nested.join(".omp/profiles/work/agent")),
            Some(&Some("work".to_string()))
        );
        assert_eq!(find(&nested.join(".local/share/omp")), Some(&None));
        assert_eq!(
            find(&nested.join(".local/share/omp/profiles/play")),
            Some(&Some("play".to_string()))
        );
    }

    #[test]
    fn source_roots_accept_a_bare_sessions_dir_as_explicit_root() {
        let dir = tempfile::TempDir::new().unwrap();
        let sessions = dir.path().join("anywhere").join("sessions");
        fs::create_dir_all(sessions.join("--proj--")).unwrap();

        let ctx = ScanContext::with_roots(
            dir.path().join("state"),
            vec![ScanRoot::local(sessions.clone())],
            None,
        );
        let roots = OmpConnector::source_roots(&ctx);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].0.path, sessions);
    }

    #[test]
    fn source_roots_demote_file_roots_to_their_parent() {
        let dir = tempfile::TempDir::new().unwrap();
        let sessions = dir.path().join(".omp").join("agent").join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        let file_root = sessions.join(format!("{SESSION_STEM}.jsonl"));
        fs::write(&file_root, "{}").unwrap();

        let ctx = ScanContext::with_roots(
            dir.path().join("state"),
            vec![ScanRoot::local(file_root)],
            None,
        );
        let roots = OmpConnector::source_roots(&ctx);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].0.path, sessions);
    }

    // =====================================================
    // detect() Tests
    // =====================================================

    #[test]
    fn detect_returns_a_result_with_evidence() {
        let connector = OmpConnector::new();
        let detection = connector.detect();
        // On machines without ~/.omp this reports not-found with evidence;
        // on omp hosts it reports detected. Either way franken detection
        // populates the evidence list.
        assert!(!detection.evidence.is_empty());
    }

    // =====================================================
    // scan()/discovery fixture tests (shared wire parser via omp roots)
    // =====================================================

    /// Build a realistic omp session tree under an agent home: workspace slug
    /// directory, a main transcript named `<timestamp>_<uuid>.jsonl`, plus a
    /// sub-agent transcript inside the sibling `<timestamp>_<uuid>/` directory.
    ///
    /// The main transcript exercises the omp wire-format extensions: a
    /// standalone `title` entry and a `model_change` record with the bare
    /// `model` field.
    fn write_omp_fixture(agent_home: &Path) {
        let slug = agent_home
            .join("sessions")
            .join("-projects-franken_agent_detection");
        fs::create_dir_all(slug.join(SESSION_STEM)).unwrap();

        let title_entry = json!({"type":"title","v":1,"title":"Add omp.sh support to project","source":"auto","updatedAt":"2026-08-23T17:57:16.363Z"});
        let header = json!({
            "type": "session",
            "version": 3,
            "id": "01a02fc2-ebfa-72f6-af9a-d40ae5078aa4",
            "timestamp": "2026-08-23T17:54:58.682Z",
            "cwd": WORKSPACE_CWD,
        });
        let model_change = json!({
            "type": "model_change",
            "id": "91857b1f",
            "parentId": null,
            "timestamp": "2026-08-23T17:54:59.232Z",
            "model": "openrouter/stealth/ox-alpha",
        });
        let user_msg = json!({
            "type": "message",
            "id": "8b70814d",
            "parentId": "9d354805",
            "timestamp": "2026-08-23T17:55:17.199Z",
            "message": {"role": "user", "content": [{"type": "text", "text": "Add complete support for omp"}]},
        });
        let assistant_msg = json!({
            "type": "message",
            "id": "cc0c570e",
            "parentId": "32d6f8a6",
            "timestamp": "2026-08-23T17:55:27.407Z",
            "message": {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "Plan the connector"},
                {"type": "toolCall", "id": "fc_123", "name": "read", "arguments": {"path": "README.md"}},
                {"type": "text", "text": "On it."},
            ]},
        });
        let transcript = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            title_entry, header, model_change, user_msg, assistant_msg
        );
        fs::write(slug.join(format!("{SESSION_STEM}.jsonl")), transcript).unwrap();

        // Sub-agent transcript inside the session directory: own session
        // header, single user message, no underscore in its file name.
        let sub_header = json!({
            "type": "session",
            "version": 3,
            "id": "sub-0001",
            "timestamp": "2026-08-23T17:56:00.000Z",
            "cwd": WORKSPACE_CWD,
        });
        let sub_msg = json!({
            "type": "message",
            "id": "m2",
            "timestamp": "2026-08-23T17:56:05.000Z",
            "message": {"role": "user", "content": [{"type": "text", "text": "Sub-agent task"}]},
        });
        fs::write(
            slug.join(SESSION_STEM).join("BenchBatch1.jsonl"),
            format!("{sub_header}\n{sub_msg}\n"),
        )
        .unwrap();
    }

    fn fixture_ctx(agent_home: &Path) -> ScanContext {
        ScanContext::with_roots(
            PathBuf::from("/nonexistent-cass-state"),
            vec![ScanRoot::local(agent_home.to_path_buf())],
            None,
        )
    }

    #[test]
    fn scan_reads_main_and_subagent_transcripts_from_live_store() {
        let Some(real_home) = dirs::home_dir() else {
            return;
        };
        let agent = real_home.join(".omp").join("agent");
        if !agent.join("sessions").exists() {
            // Graceful empty path on machines without omp.
            let ctx = ScanContext::local_default(PathBuf::from("/nonexistent"), None);
            let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
            assert!(convs.is_empty());
            return;
        }

        let ctx = ScanContext::local_default(PathBuf::from("/nonexistent"), None);
        let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
        assert!(
            !convs.is_empty(),
            "live ~/.omp store should yield conversations"
        );
        let allowed = OmpConnector::default_homes_tagged();
        for conv in &convs {
            assert_eq!(conv.agent_slug, "omp");
            assert!(
                allowed
                    .iter()
                    .any(|(root, _)| conv.source_path.starts_with(root)),
                "omp scan must stay inside resolver-selected roots, got {}",
                conv.source_path.display()
            );
        }
    }

    #[test]
    fn scan_attributes_profile_provenance_and_deduplicates_across_layouts() {
        let dir = tempfile::TempDir::new().unwrap();
        let home = dir.path().join("copied-home");

        // Default store, a named home profile, and an XDG named profile.
        let default_agent = home.join(".omp").join("agent");
        write_omp_fixture(&default_agent);
        let work_agent = home
            .join(".omp")
            .join("profiles")
            .join("work")
            .join("agent");
        write_omp_fixture(&work_agent);
        let xdg_play = home.join(".local/share/omp").join("profiles").join("play");
        write_omp_fixture(&xdg_play); // XDG flattens agent/: sessions sit directly under the profile dir

        let ctx = ScanContext::with_roots(
            PathBuf::from("/nonexistent-cass-state"),
            vec![ScanRoot::local(home.clone())],
            None,
        );
        let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");

        // 3 stores x (main + sub-agent transcript), no duplicates.
        assert_eq!(convs.len(), 6);

        let profile_of = |conv: &crate::types::NormalizedConversation| {
            conv.metadata
                .get("profile")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        for conv in &convs {
            assert_eq!(conv.agent_slug, "omp");
            assert_eq!(conv.metadata["source"], "omp");
            let expect = if conv.source_path.starts_with(&work_agent) {
                Some("work".to_string())
            } else if conv.source_path.starts_with(&xdg_play) {
                Some("play".to_string())
            } else {
                assert!(conv.source_path.starts_with(&default_agent));
                None
            };
            assert_eq!(
                profile_of(conv),
                expect,
                "profile provenance mismatch for {}",
                conv.source_path.display()
            );
        }
        assert_eq!(
            convs.iter().filter(|c| profile_of(c).is_some()).count(),
            4,
            "both profile stores must carry provenance"
        );
    }

    #[test]
    fn scan_parses_titles_models_and_tool_calls_via_explicit_roots() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = dir.path().join(".omp").join("agent");
        write_omp_fixture(&agent);

        let mut convs = OmpConnector::new()
            .scan(&fixture_ctx(&agent))
            .expect("scan should succeed");
        convs.sort_by(|a, b| a.external_id.cmp(&b.external_id));

        assert_eq!(convs.len(), 2, "main transcript + sub-agent transcript");

        // Main transcript conversation: omp `title` entry wins over the
        // first-user-message fallback.
        let main = convs
            .iter()
            .find(|conv| conv.title.as_deref() == Some("Add omp.sh support to project"))
            .expect("main conversation with title-entry title");
        assert_eq!(main.agent_slug, "omp");
        assert_eq!(main.workspace.as_deref(), Some(Path::new(WORKSPACE_CWD)));
        assert_eq!(
            main.metadata["source"], "omp",
            "metadata must attribute sessions to the omp connector"
        );
        assert_eq!(
            main.metadata["model_id"], "openrouter/stealth/ox-alpha",
            "bare-model model_change entries must update tracked model"
        );
        let roles: Vec<&str> = main.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, vec!["user", "assistant"]);
        let assistant = &main.messages[1];
        assert_eq!(
            assistant.author.as_deref(),
            Some("openrouter/stealth/ox-alpha")
        );
        assert_eq!(assistant.invocations.len(), 1);
        assert_eq!(assistant.invocations[0].name, "read");
        assert_eq!(assistant.invocations[0].call_id.as_deref(), Some("fc_123"));

        // Sub-agent transcript becomes its own conversation.
        let sub = convs
            .iter()
            .find(|conv| conv.messages.iter().any(|m| m.content == "Sub-agent task"))
            .expect("sub-agent conversation");
        assert_eq!(sub.agent_slug, "omp");
        assert!(
            sub.source_path.ends_with("BenchBatch1.jsonl"),
            "sub-agent transcript should be indexed as its own conversation"
        );

        // External ids are sessions-relative paths.
        assert!(
            main.external_id
                .as_deref()
                .is_some_and(|id| id.starts_with("-projects-franken_agent_detection/")),
            "external id should be sessions-relative, got {:?}",
            main.external_id
        );
    }

    #[test]
    fn discovery_matches_scan_sources_on_fixture() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = dir.path().join(".omp").join("agent");
        write_omp_fixture(&agent);

        crate::connectors::assert_discovery_covers_scan_sources(
            &OmpConnector::new(),
            &fixture_ctx(&agent),
        );
    }

    #[test]
    fn scan_respects_since_ts_filtering() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = dir.path().join(".omp").join("agent");
        write_omp_fixture(&agent);

        // A high-water mark far in the future excludes everything.
        let ctx = ScanContext::with_roots(
            PathBuf::from("/nonexistent"),
            vec![ScanRoot::local(agent)],
            Some(i64::MAX / 2),
        );
        let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
        assert!(convs.is_empty());
    }

    #[test]
    fn scan_handles_missing_and_empty_roots_gracefully() {
        let dir = tempfile::TempDir::new().unwrap();
        // Explicit root without any omp layout yields nothing and no error.
        let empty_root = dir.path().join("not-omp");
        fs::create_dir_all(&empty_root).unwrap();
        let ctx = ScanContext::with_roots(
            dir.path().join("state"),
            vec![ScanRoot::local(empty_root)],
            None,
        );
        let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
        assert!(convs.is_empty());

        // A nonexistent explicit root is equally harmless.
        let ctx = ScanContext::with_roots(
            dir.path().join("state"),
            vec![ScanRoot::local(dir.path().join("missing-root"))],
            None,
        );
        let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
        assert!(convs.is_empty());
    }

    // =====================================================
    // omp-specific wire extensions through the shared parser
    // =====================================================

    #[test]
    fn title_entry_overrides_header_title_and_message_fallback() {
        let parsed = super::super::pi_wire::parse_session_file;
        let dir = tempfile::TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Title entry present → wins over header title and message text.
        let file = sessions.join("2026-08-23T10-00-00_alpha.jsonl");
        fs::write(
            &file,
            format!(
                "{}\n{}\n{}\n",
                json!({"type":"title","title":"Entry title"}),
                json!({"type":"session","version":3,"id":"x","timestamp":"2026-08-23T10:00:00Z","cwd":"/w","title":"Header title"}),
                json!({"type":"message","timestamp":"2026-08-23T10:00:05Z","message":{"role":"user","content":"User text"}}),
            ),
        )
        .unwrap();
        let conv = parsed(&file, &sessions, "omp").expect("parses");
        assert_eq!(conv.title.as_deref(), Some("Entry title"));

        // No title entry → header title used.
        let file2 = sessions.join("2026-08-23T10-00-01_beta.jsonl");
        fs::write(
            &file2,
            format!(
                "{}\n{}\n",
                json!({"type":"session","version":3,"id":"y","timestamp":"2026-08-23T10:00:00Z","cwd":"/w","title":"Header only"}),
                json!({"type":"message","timestamp":"2026-08-23T10:00:05Z","message":{"role":"user","content":"User text"}}),
            ),
        )
        .unwrap();
        let conv2 = parsed(&file2, &sessions, "omp").expect("parses");
        assert_eq!(conv2.title.as_deref(), Some("Header only"));

        // Neither → first user message line, truncated to 100 chars.
        let long_text = "x".repeat(250);
        let file3 = sessions.join("2026-08-23T10-00-02_gamma.jsonl");
        fs::write(
            &file3,
            format!(
                "{}\n{}\n",
                json!({"type":"session","version":3,"id":"z","timestamp":"2026-08-23T10:00:00Z"}),
                json!({"type":"message","timestamp":"2026-08-23T10:00:05Z","message":{"role":"user","content":long_text}}),
            ),
        )
        .unwrap();
        let conv3 = parsed(&file3, &sessions, "omp").expect("parses");
        assert_eq!(conv3.title.map(|t| t.chars().count()), Some(100));

        // Files without usable messages parse to None.
        let file4 = sessions.join("2026-08-23T10-00-03_delta.jsonl");
        fs::write(&file4, "{\"type\":\"model_change\"}\n").unwrap();
        assert!(parsed(&file4, &sessions, "omp").is_none());
    }

    #[test]
    fn model_change_bare_model_field_updates_tracked_model() {
        let dir = tempfile::TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        let file = sessions.join("2026-08-23T11-00-00_eps.jsonl");
        fs::write(
            &file,
            format!(
                "{}\n{}\n{}\n{}\n",
                json!({"type":"session","version":3,"id":"m","timestamp":"2026-08-23T11:00:00Z","cwd":"/w"}),
                json!({"type":"model_change","timestamp":"2026-08-23T11:00:01Z","provider":"openrouter","modelId":"first-model"}),
                json!({"type":"model_change","timestamp":"2026-08-23T11:00:02Z","model":"second-model"}),
                json!({"type":"message","timestamp":"2026-08-23T11:00:03Z","message":{"role":"assistant","content":[{"type":"text","text":"reply"}]}}),
            ),
        )
        .unwrap();

        let conv =
            super::super::pi_wire::parse_session_file(&file, &sessions, "omp").expect("parses");
        assert_eq!(conv.messages[0].author.as_deref(), Some("second-model"));
        assert_eq!(conv.metadata["model_id"], "second-model");
        assert_eq!(conv.metadata["provider"], "openrouter");
    }
}
