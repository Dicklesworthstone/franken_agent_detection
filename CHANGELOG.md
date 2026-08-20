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
| `main` @ [`4f60c71`](https://github.com/Dicklesworthstone/franken_agent_detection/commit/4f60c71e8b2c6016ffd928b339ec6848b1466666) | Unreleased `main` tip | 2026-08-19 | VS Code native Copilot store (#16); janitor moved `UPGRADE_LOG.md` to `docs/planning/`. |
| [`v0.1.10`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.10) | GitHub Release | 2026-08-16 | Muse Code, Grok Build, Kimi current layout, Oh My Pi, OpenCode scan perf. |
| [`v0.1.9`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.9) | GitHub Release | 2026-07-02 | Codex `output_text` / `response_item` tool-call capture (#13). |
| [`v0.1.7`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.7) | GitHub Release | 2026-05-17 | See Release page; not reconstructed as a wave in this file. |
| [`v0.1.4`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.4)–[`v0.1.6`](https://github.com/Dicklesworthstone/franken_agent_detection/releases/tag/v0.1.6) | GitHub Releases | 2026-05-16 | See Release pages; not reconstructed as waves in this file. |
| `v0.1.3` / `v0.1.2` / `v0.1.1` | Git tags (not GitHub Releases) | 2026-03-22 / 2026-03-02 / 2026-02-22 | Tag-only; no Release pages. |
| `v0.1.0` | Unpublished | 2026-02-15 | crates.io rejected wildcard dependency versions. |

---

## [Unreleased] -- since v0.1.10

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
