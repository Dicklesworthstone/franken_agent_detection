# Upgrade Log

## 2026-06-17 — third-party dependency bumps

Updated compatible third-party dependencies (Cargo.lock only; semver ranges in
Cargo.toml already permit these):

- chrono 0.4.44 → 0.4.45 (patch)
- serde_json 1.0.149 → 1.0.150 (patch)
- serial_test 3.4.0 → 3.5.0 (minor, dev-dep)

Deferred:

- fsqlite 0.1.3 → 0.1.10 deferred — coordinated franken release (handled by parent).
