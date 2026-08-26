# Changelog

All notable changes to **franken-agent-detection** are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Repository: <https://github.com/Dicklesworthstone/franken_agent_detection>
Crate: <https://crates.io/crates/franken-agent-detection>

> **Release vs. tag:** GitHub Releases exist for
> [`v0.1.4`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.4),
> [`v0.1.5`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.5),
> [`v0.1.6`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.6),
> [`v0.1.7`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.7),
> [`v0.1.9`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.9),
> and [`v0.1.10`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.10)
> (latest, published 2026-08-16). `v0.1.1`, `v0.1.2`, and `v0.1.3` are git tags;
> they do **not** have GitHub Release pages — do not invent them. `v0.1.2` was
> never published to crates.io. `v0.1.0` was never published (crates.io
> rejected wildcard dependency versions). There is no `v0.1.8` tag or Release.
> In-tree Cargo is `0.1.10`.

Scope window: 2026-02-15 through HEAD
[`4f60c71`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/4f60c71e8b2c6016ffd928b339ec6848b1466666)
(2026-08-19). Current Unreleased window is since GitHub Release
[`v0.1.10`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.10).

## Version Timeline

| Version | Kind | Date | Summary |
|---------|------|------|---------|
| [`v0.2.2`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.2.2) | GitHub Release | 2026-08-24 | Cross-connector audit fixes (opencode, muse, clawdbot, chatgpt, amp, aider, copilot-cli, cursor, grok); registry invariant hardening. |
| [`v0.2.1`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.2.1) | GitHub Release | 2026-08-23 | Fresh-eyes fixes: pi-family discovery preserves scan-root provenance; registry invariant tests. |
| [`v0.2.0`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.2.0) | GitHub Release | 2026-08-23 | First-class Oh My Pi (`omp`) connector; shared pi-family wire parser; dep refresh (aes-gcm 0.11, base64 0.23, fsqlite 0.3.8 + asupersync 0.4.9). |
| [`v0.1.10`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.10) | GitHub Release | 2026-08-16 | Muse Code, Grok Build, Kimi current layout, Oh My Pi, OpenCode scan perf. |
| [`v0.1.9`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.9) | GitHub Release | 2026-07-02 | Codex `output_text` / `response_item` tool-call capture (#13). |
| [`v0.1.7`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.7) | GitHub Release | 2026-05-17 | See Release page; not reconstructed as a wave in this file. |
| [`v0.1.4`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.4)–[`v0.1.6`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.6) | GitHub Releases | 2026-05-16 | See Release pages; not reconstructed as waves in this file. |
| `v0.1.3` / `v0.1.2` / `v0.1.1` | Git tags (not GitHub Releases) | 2026-03-22 / 2026-03-02 / 2026-02-22 | Tag-only; no Release pages. |
| `v0.1.0` | Unpublished | 2026-02-15 | crates.io rejected wildcard dependency versions. |

---

## [Unreleased]

### Fixed

- **Muse default-detection no longer ignores a Cursor-style base `data_dir`.**
  The muse connector was the last of the three single-surface connectors
  (with Grok and Antigravity, both fixed in 0.2.2) whose default-detection
  scan probed the machine's real store unconditionally: a `data_dir` that is
  itself a muse base (`sessions/` tree) or the `sessions/` dir never scoped
  the scan, so fixture/mirror scans collected — or missed — sessions from
  `~/.local/share/muse` depending on the machine. `CASS_MUSE_DATA_ROOT`
  keeps precedence so CI redirection is unaffected.
- **Goose, Hermes, and Crush sqlite scans no longer double-probe the
  machine's real store in default-detection mode.** Their JSONL sides
  already scoped a `data_dir` that held connector storage, but the sqlite
  side pushed BOTH the `data_dir` candidate and the system store
  (`~/.goose/sessions.db`, Hermes `state.db`, crush global + per-project
  dbs), so scoped fixture/mirror scans collected foreign sessions from the
  local machine. A `<connector>` db under `data_dir` now scopes the scan;
  only otherwise does it fall through to the system store. Env overrides
  (`GOOSE_SQLITE_DB`, `HERMES_SQLITE_DB`, `CRUSH_SQLITE_DB`) keep
  precedence, and scan/discovery parity holds. Regression tests pin exact
  source paths for all three.
- **Codex token usage is captured from real rollouts again.** The
  `token_count` reader expected flat `payload.{input_tokens,output_tokens}`
  — a shape that exists only in a repo fixture. Every sampled real rollout
  (2026-01..2026-08) nests per-turn usage at `payload.info.last_token_usage`,
  so ALL codex token accounting silently dropped. The nested block is now
  parsed (`cached_input_tokens` mapped to cache reads; cumulative
  `info.total_token_usage` deliberately NOT attached per turn), the same
  stale fallback in `token_extraction::extract_codex_tokens` is fixed, and a
  regression test uses a real payload shape.
- **Claude Code tool results are no longer dropped wholesale.** Tool
  results ride in `type:"user"` entries as `content:[{type:"tool_result"}]`
  blocks, which `flatten_content` ignores — so every result entry failed the
  empty-content check and vanished (~30-40% of real entries per measured
  transcript), leaving invocations with call_ids but zero outputs. They are
  now emitted as first-class `role:"tool"` messages carrying `tool_use_id`.
- **Dual-stream Codex rollouts no longer duplicate user prompts.** Files
  from the Jan–Jun 2026 era record each prompt both as
  `event_msg/user_message` and as a `response_item` user record (33/61
  sampled files); the event_msg copy is now suppressed when the same text
  arrived via response_item, and token counts no longer attach to synthetic
  `[Tool: …]` placeholder messages.
- **Cursor conversations are deduped across mirrored databases**, matching
  the opencode fix: globalStorage/workspaceStorage mirrors or overlapping
  explicit roots emitted the same composer twice. A failed Cursor bubble
  range-query is also surfaced at warn instead of silently emptying the
  conversation, and OpenCode SQLite queries guard NULL/BLOB id, key and
  data cells on every query variant (one malformed row used to abort an
  entire store at debug-level silence) with store failures escalated to
  warn. Codex cache hits are preserved under their own
  `cached_input_tokens` key rather than remapped onto the additive
  `cache_read_tokens` contract; Claude tool results carry `is_error`.
  Cursor and OpenCode row-level `since_ts` filters now apply the same
  −1s granularity slack as `file_modified_since`, closing an
  incremental-scan window where a conversation touched right around the
  watermark was skipped on every subsequent run.
- **The 100MB scan cap (chatgpt policy) now applies everywhere**: a shared
  `read_capped` helper (pre-read stat + post-read backstop) covers cursor
  agent transcripts, copilot-vscode native sessions, amp threads,
  opencode session/message/part files, codex legacy `.json` rollouts,
  gemini legacy whole-file sessions, and
  pi-family transcripts; UTF-8 BOMs are stripped on first-line parses in
  codex, claude_code, kimi, and opencode message/part files so leading
  records survive; `file://localhost/path` URIs no longer decode to bogus
  relative paths, while authority-less drive forms (`file://C:/x`) keep
  their path intact (cursor + copilot_vscode); Copilot assistant turns keep
  their request timestamp; amp's cross-root dedupe key is lossless;
  pi-family homes are canonicalized once per scan so symlinked agent dirs
  dedupe correctly; and `parse_timestamp` recognizes microsecond epochs
  instead of reading them as milliseconds ~55 millennia out.
- **Claude Code surfaces subagent provenance and its own generated
  titles.** Transcripts under a session's `subagents/` directory now carry
  `metadata.sidechain = true` and the parent session id, and Claude's
  `ai-title` records are preferred over first-line truncation when naming
  conversations.
- **Kimi Code token accounting works.** The documented `usage.record`
  event was parsed nowhere; it is now attached to the latest assistant
  turn as API-sourced token usage (tolerant of flat and nested field
  spellings), instead of being silently ignored.

### Changed

- **Amp conversation identity no longer uses bare file stems.** A stem
  like `thread.json` is shared by every thread in a store and collided
  downstream. The thread's own `id` field is preferred, falling back to
  the root-relative path, then the full path. Downstream consumers keying
  on slug + external_id will see new identities for id-less exports.
- **Claude Code titles skip harness-injected context** (`# AGENTS.md`
  instructions, `<environment_context>`, `<session_context>`,
  `<user_instructions>` headers) via a shared helper also used by codex
  and gemini title selection.

### Added

- **Default-detection scoping regression tests** for grok, antigravity, and
  muse: a `local_default` scan over a fixture laid out as each connector's
  real store must index exactly the fixture's sessions, which fails on
  pre-fix code on any machine (empty system store yields nothing to leak,
  and the assertion pins exact source paths).
- **Schema conformance contract is enforced, not decorative.** The
  `validate_conversation`/`validate_message` checkers were dead code — the
  "Schema Conformance" contract gated nothing. A new conformance test
  scans each checked-in fixture store (antigravity, codex, openhands) and
  validates every produced conversation and message against it: non-empty
  slug/source path, sequential message indices, standard roles,
  well-formed invocation kinds, and consistent time bounds.
- **Second fresh-eyes sweep across the copilot family and six mid-tier
  connectors.** The VS Code native chat-store pipeline — advertised by
  discovery with `required_for_reconstruction` but never called from
  `scan()` — is now scanned, with cross-surface external-id dedupe;
  qwen default detection scopes exclusively instead of scanning both the
  pinned mirror AND live `~/.qwen/tmp`; cline, aider, and qwen enforce
  the 100MB scan cap on their largest reads; vibe and clawdbot discovery
  dedupe across overlapping/symlinked roots like their scans do; Claude
  tool results carry `is_error`; copilot-vscode legacy state-db failures
  warn instead of vanishing; native-store segment matching is
  case-insensitive so a case-altered mirrored `data_dir` still pins; BOM
  first-record loss fixed in factory/clawdbot/vibe; and detection
  determinism now compares full agent vectors rather than just counts.
  Copilot CLI dual-ingestion cleanup is tracked separately (bead).

## [0.2.2] -- 2026-08-24

Post-0.2.1 fix wave: connector correctness fixes surfaced by a cross-connector
audit, plus registry invariant hardening.

### Fixed

- **OpenCode no longer loses or duplicates sessions three ways**.
  Sessions whose timestamps are all unparseable are kept instead of being
  pruned forever by every incremental scan (the `since_ts` filter now applies
  only when a timestamp actually parsed); a `seen_db_session_ids` set spans
  all db candidates so stale migrated databases (`~/.config/opencode` vs
  `~/.local/share`) stop double-indexing shared session ids, while
  conversations with no `external_id` pass through uncollapsed; and a
  leading UTF-8 BOM is trimmed before JSON parsing instead of skipping the
  whole file.

- **Muse unsequenced records keep append order, and workspace inheritance
  survives unreadable lines.** A record without `sequence` used to fall back
  to `i64::MAX - lineno`, emitting the unsequenced tail in REVERSED order
  after every sequenced record; the two-band sort key keeps that tail after
  all sequenced records but in file order. The subagent parent-transcript
  workspace lookup skips an unreadable line instead of aborting, so one bad
  region no longer erases workspace inheritance. Regression tests cover both
  behaviors.
- **Clawdbot dedupes session files across overlapping scan roots.** The
  connector walked each root independently and emitted shared files once per
  covering root; a `HashSet` of shared `dedupe_path_key`s now spans ALL
  roots, checked before the mtime filter.
- **ChatGPT enforces the 100MB read cap after the read too**, closing the
  bypass where a pre-read `fs::metadata` error skipped the size guard
  entirely.
- **Amp threads are keyed by path, roles normalized, and workspace URIs
  percent-decoded**; role-less Factory entries default to `assistant`
  instead of `"unknown"`.
- **Aider, copilot-cli, and cursor no longer silently discard sessions.**
- **Grok detection honors `GROK_HOME`** when resolving override roots.
- **Cursor default-detection no longer leaks the machine's real
  `~/.cursor/projects` into scoped scans.** When a scan's `data_dir` is
  itself a Cursor base (fixture, mirror, or alternate install), Agent
  transcripts were still collected from the system projects root — the one
  connector surface that ignored the Composer root policy — duplicating or
  polluting results on machines with local Cursor data. Agent-transcript
  discovery now mirrors the Composer policy (`data_dir` base wins;
  `CASS_CURSOR_PROJECTS_ROOT` still takes precedence for CI). Regression
  test covers a combined composer + agent-transcript base.

- **Antigravity and Grok default-detection scan roots are scoped the same
  way as Cursor's** -- a scan whose `data_dir` is itself an agent base no
  longer leaks the machine's real home-directory roots into fixture or
  mirror scans
  ([`5d4996e`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/5d4996e)).

### Added

- **Registry invariant hardening**: factory slugs are canonicalized,
  duplicate registrations are rejected, and the factory cross-check is
  feature-aware — the slug-set drift class caught by hand during 0.2.x now
  fails CI mechanically.

## [0.2.1] -- 2026-08-23

Patch over the 0.2.0 window, from a fresh-eyes audit of everything that
shipped in it.

### Fixed

- **Pi-family discovery no longer downgrades remote scan roots to local**.
  The shared `pi_wire::discover_sources` helper took bare paths and
  re-wrapped every home in `ScanRoot::local`, so `DiscoveredSourceFile`
  entries for remote roots lost their `Origin` (Ssh) and platform hint —
  fields downstream consumers key mirroring and path-mapping decisions off.
  The helper now takes full `ScanRoot`s; the `pi_agent` and `omp` callers
  pass `source_roots()` through untouched. Regression tests on both
  connectors prove remote provenance survives discovery end-to-end.

### Added

- **Registry invariant test**: all five registration points
  (`KNOWN_CONNECTORS`, canonical alias arms, `default_probe_roots`,
  `default_probe_paths_tilde`, the factory list) must agree exactly with one
  slug set. Two sibling rows were silently dropped by range edits during the
  0.2.0 window (caught by hand); this class of mistake now fails CI
  mechanically.

---
## [0.2.0] -- 2026-08-23

First-class Oh My Pi (`omp`) support plus dependency refresh.

### Added

- **Oh My Pi (`omp`, <https://omp.sh>) connector** — `OmpConnector` is now a
  first-class connector slug instead of a piggyback surface on `pi_agent`.
  omp pins its session store to `~/.omp/agent/` (no relocation env var in
  the CLI itself), so detection probes `~/.omp/agent/sessions` first and the
  parent second; `CASS_OMP_DATA_ROOT` overrides detection for tests and CI,
  and the aliases `oh-my-pi` / `omp` both canonicalize to `omp`. Scanning
  covers main transcripts
  (`sessions/<safe-path>/<timestamp>_<uuid>.jsonl`) and sub-agent
  transcripts (`<timestamp>_<uuid>/<AgentName>.jsonl`), handles omp's
  standalone `title` entries (preferred over the session-header title) and
  bare-`model` `model_change` records, and stamps conversations with
  `agent_slug: "omp"`.
- **Named-profile provenance for omp homes**
  (`franken_agent_detection#17`): profile-aware scan entry points tag every
  conversation with `metadata.profile` so consumers can reconstruct
  `omp --profile <name> --resume <id>`; `OMP_PROFILE` takes precedence over
  legacy `PI_PROFILE`, mirroring upstream `resolveProfileEnv`.
- **Shared pi-family wire parser** (`connectors/pi_wire.rs`): the JSONL v3
  traversal/parsing primitives moved out of `pi_agent.rs` into one module
  consumed by both the `pi_agent` and `omp` connectors, so the two
  distributions can no longer drift apart at the parser level.

### Changed

- **`pi_agent` is scoped back to `~/.pi/agent`** (behavior change): with omp
  owned by its own connector, `pi_agent` no longer walks `.omp` trees by
  default. Machines with both distributions now get correctly attributed
  conversations per slug instead of double-counted sessions; explicit scan
  roots are unaffected.
- Dependencies refreshed: `aes-gcm` 0.10 → 0.11 (with the deprecated
  `Nonce::from_slice` call migrated to `TryFrom` + `&nonce` decrypt),
  `base64` 0.22 → 0.23, `serial_test` 3 → 4, and the SQLite engine pair
  moved in lockstep (`fsqlite` 0.3.8 with `asupersync` 0.4.9).

### Fixed

- Restored the `"open-claw"` alias arm in `canonical_connector_slug` that an
  insertion during this window accidentally dropped.
- omp root discovery existence-gates its expansion candidates so unrelated
  explicit scan roots cannot fabricate phantom `.omp/...` probe paths.

---

Current window after the [`v0.1.10`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.10)
GitHub Release (tag [`f68fc8b`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/f68fc8bb0efe8027a99531b90c555a77bc6fabd7),
2026-08-14; Release published 2026-08-16) through HEAD
[`4f60c71`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/4f60c71e8b2c6016ffd928b339ec6848b1466666)
(2026-08-19): 3 non-merge commits.

### Delivered capability

- VS Code native Copilot chat-session store is now a scan surface (#16).
- `UPGRADE_LOG.md` lives under `docs/planning/`; skill-loop scratch is gitignored.

### Closed workstreams

- [#16](https://github.com/Dicklesworthstone/franken_agent_detection/issues/16) VS Code native Copilot store.
- Tracker: [`.beads/issues.jsonl`](https://github.com/Dicklesworthstone/franken_agent_detection/blob/main/.beads/issues.jsonl).

### Added

- **VS Code native Copilot chat-session store** ([#16](https://github.com/Dicklesworthstone/franken_agent_detection/issues/16)).
  Scan now covers VS Code's native Copilot chat-session store in addition to
  the existing Copilot surfaces.

  [`c8816ff`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/c8816fff484378f362dd517f1f0dd9691c8aeb5a)

### Janitor docs-reorg (2026-08-19)

`UPGRADE_LOG.md` moved to
[`docs/planning/UPGRADE_LOG.md`](docs/planning/UPGRADE_LOG.md).
Skill-loop scratch is gitignored. No connector behavior change.

**Representative commits**
- [`80bd71f`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/80bd71fa90b21c440d43d0569bd0740c7ef08132) — `chore(janitor): untrack skill-loop scratch; move root planning docs into docs/planning/`
- [`4f60c71`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/4f60c71e8b2c6016ffd928b339ec6848b1466666) — `chore(janitor): relocate remaining root reports and planning docs`

---

## [0.1.10] -- 2026-08-14

GitHub Release [`v0.1.10`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.10)
published 2026-08-16. Tag points at
[`f68fc8b`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/f68fc8bb0efe8027a99531b90c555a77bc6fabd7).
Cargo is `0.1.10`.

### Added

- **Muse Code (Meta) connector** per
  [#15](https://github.com/Dicklesworthstone/franken_agent_detection/issues/15)
  field report.
  [`f68fc8b`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/f68fc8bb0efe8027a99531b90c555a77bc6fabd7)

- **Grok Build connector (`GrokConnector`)** — full parser + factory for
  xAI's official `grok` coding CLI
  (Dicklesworthstone/coding_agent_session_search#328). Reads `$GROK_HOME/sessions/`
  (default `~/.grok/sessions/`), whose layout is
  `sessions/<percent-encoded-cwd>/<session-uuid>/`: `updates.jsonl` (the ACP
  session-update stream the CLI's own docs call the authoritative
  conversation log) is the primary read path, `summary.json` supplies
  metadata (id, cwd, title, timestamps, `current_model_id`), and
  `chat_history.jsonl` is a fallback so user prompts still index when every
  model call in a session failed. The empirical grok-0.2.103 line envelope
  (`method: "_x.ai/session/update"`, `params.update.sessionUpdate`,
  `_meta.agentTimestampMs` at either level) is parsed tolerantly; ACP chunk
  kinds (`user_message_chunk` / `agent_message_chunk` /
  `agent_thought_chunk`) coalesce into single messages, `tool_call` /
  `tool_call_update` become `tool`-role messages with structured
  invocations and streamed output (updates supersede one another), and
  unknown kinds (`hook_execution`, `retry_state`, `plan`, future additions)
  are skipped without dropping the session. Workspace resolution prefers
  `summary.json` `info.cwd`, then a group-level `.cwd` file, then
  percent-decoding the group directory name. Registered in
  `get_connector_factories` as `grok`; streaming scan + source discovery
  (`updates.jsonl` primary, `chat_history.jsonl` + `summary.json`
  sidecars) included, with synthetic-fixture tests for chunk coalescing,
  tool-call lifecycle, the chat-history fallback, cwd decoding, and
  scan-root flexibility.
  [`e90eb77`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/e90eb77744a67c43381bd61a1ef8d95efc4ae10a)

- **Kimi Code current layout** alongside legacy `~/.kimi`, including the
  current event schema (cass#351).
  [`f685a69`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/f685a69b9ed77f51f05256dd0e35852e16a7817b)

- **Oh My Pi (`omp`) sessions** on the `pi_agent` connector: probe roots and
  sub-agent transcripts. `PI_SESSIONS_DIR` is honored; unsupported V2/SQLite
  stores diagnose instead of silently dropping.
  [`1a25887`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/1a258873315644914e81d637d651673ac9211e3b)

### Changed

- **OpenCode incremental SQLite scan** skips old sessions' message/part decode
  (cass#372). Optional `ScanContext` progress-tick for long scans (cass#373).
  Remote-root scans never pull local canonical DBs (cass#357).
  [`63b19eb`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/63b19eb846262b8cc15877c2577519f82263fbcd)

- **fsqlite 0.2 async engine** bridged through an asupersync sync wrapper;
  lockstep bump to fsqlite 0.3.0 + asupersync 0.4.3.
  [`530d8a9`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/530d8a91081e4c5cd45651789312c6dcbafd4afa)

---

## [0.1.9] -- 2026-06-30

GitHub Release [`v0.1.9`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.9)
(published 2026-07-02).

### Fixed

- **Codex connector now captures modern `output_text` assistant messages and
  `response_item` tool calls/results** ([#13]). Modern Codex rollout JSONL
  (Codex Desktop / Responses-API format) encodes assistant text as
  `{"type":"output_text"}` content blocks and encodes tool activity as
  `response_item` payloads (`function_call`, `function_call_output`,
  `custom_tool_call`, `custom_tool_call_output`) rather than
  `event_msg`/`tool_call`. The connector previously dropped all of these:
  - `extract_content_part` did not treat `output_text` as a text-bearing block,
    so assistant `response_item` messages flattened to empty and were skipped.
  - The `response_item` handler only read `payload.content`; tool calls/results
    carry no `content`, so they were dropped entirely.

  The `response_item` handler now dispatches on `payload.type`:
  `function_call` / `custom_tool_call` become assistant messages with a
  normalized tool invocation (name, `call_id`, and arguments decoded from the
  JSON-string `arguments` / freeform `input`, falling back to the raw string);
  `function_call_output` / `custom_tool_call_output` become first-class `tool`
  timeline messages carrying the captured output, with `call_id` preserved in
  `extra`. Encrypted `reasoning` items (no plaintext) and the legacy JSON
  format are unaffected. Verified against real `~/.codex` sessions; adds a
  checked-in modern rollout fixture plus regression tests.

  [#13]: https://github.com/Dicklesworthstone/franken_agent_detection/issues/13

---

## [0.1.3] -- 2026-03-21

Work that accumulated on `main` after the v0.1.2 tag (2026-03-02), now
published to crates.io as v0.1.3.

### New connectors

- **Copilot CLI** (`copilot_cli.rs`) -- standalone connector for `gh copilot` event logs, separate from the VS Code Copilot Chat connector. Discovers JSONL event logs in `~/.copilot/session-state/` (v2, since CLI 0.0.342) and legacy single-JSON files in `~/.copilot/history-session-state/`. Supports multiple event type naming conventions and content field names. 14 unit tests. ([ae68b95](https://github.com/Dicklesworthstone/franken_agent_detection/commit/ae68b95a3cfd6bcf9a115fb03771ae309876f0e6))
- **Kimi Code** (`kimi.rs`) -- Moonshot AI coding agent. Parses JSONL `wire.jsonl` files from `~/.kimi/sessions/<workspace-hash>/<session-uuid>/` with TurnBegin, ContentPart, and ToolCall message types. Reads workspace metadata from `state.json`. ([963a594](https://github.com/Dicklesworthstone/franken_agent_detection/commit/963a59465b8946da2f1822da6f5e9c780495db16))
- **Qwen Code** (`qwen.rs`) -- Alibaba coding agent. Parses JSON session files from `~/.qwen/tmp/<project-hash>/chats/` with user/assistant message extraction. Reads workspace metadata from `config.json`. ([963a594](https://github.com/Dicklesworthstone/franken_agent_detection/commit/963a59465b8946da2f1822da6f5e9c780495db16))

### Copilot Chat enhancements

- Expanded the existing VS Code Copilot Chat connector to also discover `~/.copilot/session-state/` and `~/.copilot/history-session-state/` paths, recognize `.jsonl` files, parse CLI event log format line-by-line, and handle legacy single-JSON session files. Added `is_cli_event_log()`, `parse_cli_event_log()`, `parse_cli_session_json()`, and `extract_cli_event_message()` helpers. 11 new tests. ([fd25ae9](https://github.com/Dicklesworthstone/franken_agent_detection/commit/fd25ae9d6699df6db82ecee47a1764b7db404f99))

### Amp connector fixes

- Extract workspace paths from `env.initial.trees[].uri` and timestamps from the `"created"` field, fixing non-functional `--workspace` and `--days` filtering for Amp sessions. Closes [coding_agent_session_search#100](https://github.com/Dicklesworthstone/coding_agent_session_search/issues/100). ([102b46b](https://github.com/Dicklesworthstone/franken_agent_detection/commit/102b46b597499f880418c99cfa00114f220cf5bc))
- Rework `cache_root()` to use `std::env::var` instead of `dotenvy::var`, add existence checks at each discovery step, add explicit XDG default path as a middle fallback, and return `Option<PathBuf>` so callers handle the "no Amp data" case explicitly. ([3885140](https://github.com/Dicklesworthstone/franken_agent_detection/commit/38851402dfed74cfc4f42cdfc9a467a327601d10))
- Filter out non-file URI schemes (`ssh://`, `https://`, `vscode-remote://`) that were being passed through as filesystem paths, creating invalid `PathBuf`s. ([35e2a3a](https://github.com/Dicklesworthstone/franken_agent_detection/commit/35e2a3a100f2053d22f0253f06e76af1ac30076b))

### Other fixes

- **OpenCode** -- correct SQLite column names to `time_created`/`time_updated` (matching the real v1.2+ schema). The old names caused `prepare` failures, making the connector silently fall back to flat-file scanning and miss all sessions. ([73cf7af](https://github.com/Dicklesworthstone/franken_agent_detection/commit/73cf7afac555e755cddc3e116761cfc1c75f034f))
- **Qwen** -- normalize unknown message types to `"assistant"` instead of preserving raw type strings, for forward compatibility. ([5b0eb1a](https://github.com/Dicklesworthstone/franken_agent_detection/commit/5b0eb1a7ece0c741f30b0e280d73488b8c4dd783))
- **Kimi** -- log JSONL line read errors via `tracing::debug` instead of silently continuing. ([5b0eb1a](https://github.com/Dicklesworthstone/franken_agent_detection/commit/5b0eb1a7ece0c741f30b0e280d73488b8c4dd783))

### Internal

- Additional detection helpers in connector utils. ([228ed12](https://github.com/Dicklesworthstone/franken_agent_detection/commit/228ed122fb001089fb65052d91de838089fc5dd9))
- Clippy and rustfmt cleanup across all connectors and `lib.rs` -- no behavioral changes. ([ba9e1c2](https://github.com/Dicklesworthstone/franken_agent_detection/commit/ba9e1c2aac9c0ff0fee35aec44eec8ba61a6083b))

---

## [0.1.2] -- 2026-03-02

Git tag: [`v0.1.2`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.2). Published to crates.io.

### New connectors

- **Continue** -- `continue-dev` agent detection at `~/.continue/sessions`. ([eeca45c](https://github.com/Dicklesworthstone/franken_agent_detection/commit/eeca45c086bdba2f4ffebb410517b8f2c3ab7e4f))
- **Goose** -- `goose-ai` agent detection at `~/.goose/sessions`. ([eeca45c](https://github.com/Dicklesworthstone/franken_agent_detection/commit/eeca45c086bdba2f4ffebb410517b8f2c3ab7e4f))

### OpenCode SQLite support

- OpenCode v1.2+ migrated from flat JSON files to a SQLite database (`opencode.db`). The connector now probes for SQLite first (with `OPENCODE_SQLITE_DB` env override), extracts sessions/messages/parts with robust timestamp normalization (handles Drizzle ORM TEXT or INTEGER formats), then falls back to pre-v1.2 JSON files for older installations. Deduplicates sessions across both sources. Added `dep:rusqlite` to the `opencode` feature gate. ([7c534b6](https://github.com/Dicklesworthstone/franken_agent_detection/commit/7c534b6087acc0ec3f0898c0d62ba6d07e202575))

### SSH probe path API

- New `default_probe_paths_tilde()` public function returns all known connector probe paths using `~/...` tilde notation instead of resolved home directories. Designed for SSH probe scripts where the remote home directory is unknown at build time, ensuring new connectors are automatically picked up by downstream tools like cass's `probe.rs`. ([eeca45c](https://github.com/Dicklesworthstone/franken_agent_detection/commit/eeca45c086bdba2f4ffebb410517b8f2c3ab7e4f))

### Bug fixes

- **OpenClaw** -- `detect()` now uses `detect_from_agents_root()` (which walks the `agents/<name>/sessions/` layout) instead of `franken_detection_for_connector()` (which only checks for directory existence). The old approach could report false negatives. Also fixed the hardcoded wrong path in `default_probe_paths_tilde()` that assumed a single-agent layout. Fixes [coding_agent_session_search#86](https://github.com/Dicklesworthstone/coding_agent_session_search/issues/86). ([6ae73d5](https://github.com/Dicklesworthstone/franken_agent_detection/commit/6ae73d5f78d2800b3fd1cadec27b0db43f483817))
- **Pi-Agent** -- accept the sessions directory itself (e.g. `~/.pi/agent/sessions`) as a valid root in `scan_roots`. Previously, the `looks_like_root` check rejected it because it only looked for a child `sessions` subdir, causing the watch callback and scan_roots code path to silently skip all sessions. Closes [coding_agent_session_search#85](https://github.com/Dicklesworthstone/coding_agent_session_search/issues/85). ([b540606](https://github.com/Dicklesworthstone/franken_agent_detection/commit/b5406060c4219399ce36f77a250864f43f48e392))

---

## [0.1.1] -- 2026-02-22

Git tag: [`v0.1.1`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.1). First successful crates.io publish (v0.1.0 was rejected due to wildcard dependency versions).

### Connector infrastructure

- Introduced modular `src/connectors/` architecture with feature-gated dependencies. Feature groups: `connectors` (base), `chatgpt`, `cursor`, `all-connectors`. Each connector can be compiled independently without pulling unnecessary dependencies. ([0bc91d6](https://github.com/Dicklesworthstone/franken_agent_detection/commit/0bc91d6f4b45a0664ead3eef0697955d199bfc1b))
- Shared utilities: `path_trie.rs` (prefix tree for path matching), `scan.rs` (directory walking), `utils.rs` (common helpers), `workspace_cache.rs` (workspace resolution cache). ([0bc91d6](https://github.com/Dicklesworthstone/franken_agent_detection/commit/0bc91d6f4b45a0664ead3eef0697955d199bfc1b))
- Shared type definitions in `src/types.rs` used across all connectors. ([0bc91d6](https://github.com/Dicklesworthstone/franken_agent_detection/commit/0bc91d6f4b45a0664ead3eef0697955d199bfc1b))
- Centralized `get_connector_factories()` registry for instantiating all compiled connectors without hardcoding the list. ([96d8014](https://github.com/Dicklesworthstone/franken_agent_detection/commit/96d80142872d38810587702ef12881674567a2d8))

### New connectors (full session parsing implementations)

- **Aider** (`aider.rs`) -- parses `.aider.chat.history.md` markdown-based session logs with quote-prefix stripping and chat history extraction. ([da0cd9d](https://github.com/Dicklesworthstone/franken_agent_detection/commit/da0cd9de368193d98f691ba653e3088ac91a2d1d), [cb7bb8b](https://github.com/Dicklesworthstone/franken_agent_detection/commit/cb7bb8b1b3c901af97422f55bff54ea42b9af31c))
- **Amp** (`amp.rs`) -- Sourcegraph AMP; scans `XDG_DATA_HOME/amp` and VS Code `globalStorage` for session files, supports JSONL log format with tool calls and thinking blocks. ([11bf51f](https://github.com/Dicklesworthstone/franken_agent_detection/commit/11bf51fce6cb345ddd2959a3cc5516945b9c5976))
- **ChatGPT** (`chatgpt.rs`) -- OpenAI ChatGPT conversation exports supporting both JSON export format and API-style conversation logs with tool use and image inputs. ([c5832f7](https://github.com/Dicklesworthstone/franken_agent_detection/commit/c5832f7d4956a14913508b46c3284236be6f5cb9))
- **Claude Code** (`claude_code.rs`) -- session parser migrated from `coding_agent_session_search`. ([2d93ded](https://github.com/Dicklesworthstone/franken_agent_detection/commit/2d93dede03f909386b5b8a72b2a1366a9945ce73))
- **Cline/Roo-Cline** (`cline.rs`) -- discovers sessions in VS Code and Cursor `globalStorage` directories, handles `settings.json` and task-based conversation format with API request metadata. ([11bf51f](https://github.com/Dicklesworthstone/franken_agent_detection/commit/11bf51fce6cb345ddd2959a3cc5516945b9c5976))
- **Codex** (`codex.rs`) -- ingests OpenAI Codex CLI session logs. ([96d8014](https://github.com/Dicklesworthstone/franken_agent_detection/commit/96d80142872d38810587702ef12881674567a2d8))
- **Copilot Chat** (`copilot.rs`) -- GitHub Copilot Chat for VS Code; parses `conversations.json` and individual session files with turn-based request/response format, also checks `gh-copilot` CLI history. ([11bf51f](https://github.com/Dicklesworthstone/franken_agent_detection/commit/11bf51fce6cb345ddd2959a3cc5516945b9c5976))
- **Cursor** (`cursor.rs`) -- reads Cursor IDE `state.vscdb` SQLite databases; feature-gated behind `cursor` with `urlencoding` dependency. ([96d8014](https://github.com/Dicklesworthstone/franken_agent_detection/commit/96d80142872d38810587702ef12881674567a2d8))
- **Factory Droid** (`factory.rs`) -- reads `~/.factory/sessions/` JSONL files, decodes workspace path slugs, extracts `settings.json` metadata. ([11bf51f](https://github.com/Dicklesworthstone/franken_agent_detection/commit/11bf51fce6cb345ddd2959a3cc5516945b9c5976))
- **Gemini** (`gemini.rs`) -- simplified detection logic by removing redundant path probing in favor of the shared `franken_detection` helper. ([11bf51f](https://github.com/Dicklesworthstone/franken_agent_detection/commit/11bf51fce6cb345ddd2959a3cc5516945b9c5976), [c5832f7](https://github.com/Dicklesworthstone/franken_agent_detection/commit/c5832f7d4956a14913508b46c3284236be6f5cb9))
- **OpenClaw** (`openclaw.rs`) -- JSONL session log ingestion at `~/.openclaw/agents/` with discriminated-union line format (session, message, model_change, thinking_level_change types). ([2920985](https://github.com/Dicklesworthstone/franken_agent_detection/commit/292098525a12711108801213fac7a94fa42a875a))
- **OpenCode** (`opencode.rs`) -- parses OpenCode session files. ([96d8014](https://github.com/Dicklesworthstone/franken_agent_detection/commit/96d80142872d38810587702ef12881674567a2d8))
- **Pi-Agent** (`pi_agent.rs`) -- scans `~/.pi/agent/sessions/` for timestamped JSONL files, handles `TextContent`/`ThinkingContent` message arrays and model/thinking-level change events. ([11bf51f](https://github.com/Dicklesworthstone/franken_agent_detection/commit/11bf51fce6cb345ddd2959a3cc5516945b9c5976))
- **Vibe** (`vibe.rs`) -- included as part of the initial connector infrastructure. ([0bc91d6](https://github.com/Dicklesworthstone/franken_agent_detection/commit/0bc91d6f4b45a0664ead3eef0697955d199bfc1b))
- **ClawdBot** (`clawdbot.rs`) -- included as part of the initial connector infrastructure. ([0bc91d6](https://github.com/Dicklesworthstone/franken_agent_detection/commit/0bc91d6f4b45a0664ead3eef0697955d199bfc1b))

### Detection registry expansion

- Added aider, amp, chatgpt, clawdbot, openclaw, pi_agent, and vibe to `KNOWN_CONNECTORS` with alias resolution (e.g. `aider-cli` -> `aider`, `amp-cli` -> `amp`, `chatgpt-desktop`/`chat-gpt` -> `chatgpt`) and cross-platform default probe roots. ([4ca7d98](https://github.com/Dicklesworthstone/franken_agent_detection/commit/4ca7d98a4c4adf03ac933a8c818ab9c1a84e5f9f))

### Environment variable overrides

- `CASS_AIDER_DATA_ROOT`, `CODEX_HOME`, `PI_CODING_AGENT_DIR` environment variables redirect detection to custom data directories. New `cwd_join()` helper constructs probe paths rooted at the current working directory for per-project marker detection (e.g. `.aider.chat.history.md` in the project root). ([a933965](https://github.com/Dicklesworthstone/franken_agent_detection/commit/a933965f48e94bef6d1c391c85d981850bbaead4))

### Token extraction

- New `token_extraction.rs` module with `ExtractedTokenUsage`, `ModelInfo`, `TokenDataSource` types. Provider-specific extractors for Claude Code and Codex sessions, a unified `extract_tokens_for_agent` dispatcher, heuristic `estimate_tokens_from_content`, and `normalize_model` for canonicalizing model name strings. ([7a731a0](https://github.com/Dicklesworthstone/franken_agent_detection/commit/7a731a000b3dfd6ac9212a587c9a793b26921aac))

### Probe path refinements

- Narrowed codex probe from `.codex` to `.codex/sessions` and pi_agent from `.pi/agent` to `.pi/agent/sessions` to reduce false positives. ([a933965](https://github.com/Dicklesworthstone/franken_agent_detection/commit/a933965f48e94bef6d1c391c85d981850bbaead4))

### Packaging

- Pinned all wildcard dependency versions to proper semver ranges, as crates.io rejects wildcard constraints. ([98f296c](https://github.com/Dicklesworthstone/franken_agent_detection/commit/98f296ca097085729642f7c234435bc5908b68d9))

---

## [0.1.0] -- 2026-02-15

Initial public release. No git tag. Not published to crates.io (rejected due to wildcard dependency versions; superseded by v0.1.1).

### Core detection API

- `detect_installed_agents()` -- run filesystem probes and produce a full report. ([fa960bc](https://github.com/Dicklesworthstone/franken_agent_detection/commit/fa960bcdc294c9f7e16eafc5cbaf43b972c95eab))
- `AgentDetectOptions` -- control connector filtering (`only_connectors`) and override roots (`root_overrides`). ([fa960bc](https://github.com/Dicklesworthstone/franken_agent_detection/commit/fa960bcdc294c9f7e16eafc5cbaf43b972c95eab))
- `AgentDetectRootOverride` -- per-connector custom probe root for deterministic testing in CI. ([fa960bc](https://github.com/Dicklesworthstone/franken_agent_detection/commit/fa960bcdc294c9f7e16eafc5cbaf43b972c95eab))
- `InstalledAgentDetectionReport` -- stable JSON-serializable report with `format_version` for downstream tooling and snapshot tests. ([fa960bc](https://github.com/Dicklesworthstone/franken_agent_detection/commit/fa960bcdc294c9f7e16eafc5cbaf43b972c95eab))
- `AgentDetectError` -- `UnknownConnectors` and feature-related errors. ([fa960bc](https://github.com/Dicklesworthstone/franken_agent_detection/commit/fa960bcdc294c9f7e16eafc5cbaf43b972c95eab))

### Design properties

- Synchronous, runtime-neutral API (no tokio or async runtime required).
- Local filesystem probing only (no network access).
- Deterministic fixture mode via `root_overrides` with temp directories.
- Canonical slug normalization (e.g. `claude-code` -> `claude`, `codex-cli` -> `codex`).
- Explicit `UnknownConnectors` errors for unrecognized slugs.

### Initial connector registry (detection only, no session parsing)

- 9 connectors: `claude`, `cline`, `codex`, `cursor`, `factory`, `gemini`, `github-copilot`, `opencode`, `windsurf`.
- Cross-platform default probe roots: macOS `Library/Application Support`, Linux `~/.config` / `~/.local/share`, Windows `AppData/Roaming`.

### Project scaffolding

- CI workflow (GitHub Actions) and release workflow. ([fa960bc](https://github.com/Dicklesworthstone/franken_agent_detection/commit/fa960bcdc294c9f7e16eafc5cbaf43b972c95eab))
- MIT license. ([fa960bc](https://github.com/Dicklesworthstone/franken_agent_detection/commit/fa960bcdc294c9f7e16eafc5cbaf43b972c95eab))
- README with usage examples, API reference, troubleshooting guide, and FAQ. ([fa960bc](https://github.com/Dicklesworthstone/franken_agent_detection/commit/fa960bcdc294c9f7e16eafc5cbaf43b972c95eab), [ac56a11](https://github.com/Dicklesworthstone/franken_agent_detection/commit/ac56a11dc9b3652e2ae8adcda7b60ee46bdffc78))

---

## Connector coverage timeline

| Version | Connectors added | Cumulative |
|---------|-----------------|------------|
| 0.1.0 | claude, cline, codex, cursor, factory, gemini, github-copilot, opencode, windsurf | 9 |
| 0.1.1 | aider, amp, chatgpt, clawdbot, openclaw, pi_agent, vibe | 16 |
| 0.1.2 | continue, goose | 18 |
| 0.1.3 | copilot_cli, kimi, qwen | 21 |
| 0.1.10 | grok, muse, kimi-current-layout, pi_agent omp | (plus VS Code native Copilot store on Unreleased) |

> Note: The `github-copilot` connector (VS Code Copilot Chat) was in the
> detection registry since v0.1.0; the full session-parsing implementation
> (`copilot.rs`) was added in v0.1.1, and the separate `copilot_cli` connector
> for `gh copilot` CLI event logs arrived in v0.1.3. VS Code's native Copilot
> chat-session store landed after `v0.1.10` (Unreleased, issue #16).

> `v0.1.4`–`v0.1.7` exist as GitHub Releases (2026-05-16 / 2026-05-17) and are
> listed above in the Release-vs-tag note. They are not reconstructed as
> capability-wave sections in this file.

[Unreleased]: https://github.com/Dicklesworthstone/franken_agent_detection/compare/v0.1.10...HEAD
[0.1.10]: https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.10
[0.1.9]: https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.9
[0.1.7]: https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.7
[0.1.6]: https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.6
[0.1.5]: https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.5
[0.1.4]: https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.4
[0.1.3]: https://github.com/Dicklesworthstone/franken_agent_detection/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Dicklesworthstone/franken_agent_detection/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Dicklesworthstone/franken_agent_detection/compare/fa960bcdc294c9f7e16eafc5cbaf43b972c95eab...v0.1.1
[0.1.0]: https://github.com/Dicklesworthstone/franken_agent_detection/commit/fa960bcdc294c9f7e16eafc5cbaf43b972c95eab
