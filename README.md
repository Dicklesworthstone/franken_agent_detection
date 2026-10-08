# franken-agent-detection

<div align="center">
  <img src="fad_illustration.webp" alt="franken-agent-detection - local deterministic coding-agent installation detection">
</div>

<div align="center">

[![crates.io](https://img.shields.io/crates/v/franken-agent-detection.svg)](https://crates.io/crates/franken-agent-detection)
[![docs.rs](https://img.shields.io/docsrs/franken-agent-detection)](https://docs.rs/franken-agent-detection)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

A Rust crate with two layers for working with local coding-agent tools:

1. **Detection** (always available, no features): which coding agents are
   installed on this machine, as one stable, JSON-serializable report.
2. **Connectors** (`connectors` feature and friends): read each agent's own
   session history into one normalized conversation model, with discovery,
   provenance, streaming and resumable ingestion. This is the parsing layer
   [`cass`](https://github.com/Dicklesworthstone/coding_agent_session_search)
   builds its search index on.

```bash
cargo add franken-agent-detection                                # detection only
cargo add franken-agent-detection --features all-connectors      # every connector
```

Everything is synchronous, local and read-only: no async runtime, no network,
and no connector ever writes to an agent's store.

## Detection

```rust
use franken_agent_detection::{
    detect_installed_agents, AgentDetectOptions, AgentDetectRootOverride,
};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let report = detect_installed_agents(&AgentDetectOptions {
        only_connectors: Some(vec!["codex".into(), "gemini".into()]),
        include_undetected: true,
        root_overrides: vec![AgentDetectRootOverride {
            slug: "codex".into(),
            root: PathBuf::from("/tmp/mock-codex"),
        }],
    })?;

    println!(
        "Detected {} of {}",
        report.summary.detected_count, report.summary.total_count
    );
    Ok(())
}
```

| Item | Purpose |
|---|---|
| `detect_installed_agents` | Run filesystem probes and produce the full report |
| `AgentDetectOptions` | Connector filtering (`only_connectors`), `include_undetected`, `root_overrides` |
| `InstalledAgentDetectionReport` | `format_version`, `installed_agents` (slug, evidence, root paths), `summary` |
| `default_probe_paths_tilde` | The `~/…` probe table, e.g. for remote probing over SSH |
| `AgentDetectError` | `UnknownConnectors` (slug not recognized) |

Slugs are normalized (`claude-code` → `claude`, `oh-my-pi` → `omp`, …);
unknown slugs are an explicit error. Probe roots honor the agents' own
environment overrides (`CODEX_HOME`, `PI_CODING_AGENT_DIR`, `CLAUDE_CONFIG_DIR`,
…) and `root_overrides` makes tests deterministic.

## Connectors

```rust
use franken_agent_detection::{
    Connector, PiAgentConnector, ScanContext, ScanRoot, get_connector_factories,
};
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    // Default locations for one agent.
    let ctx = ScanContext::local_default(PathBuf::from("/tmp/cass-state"), None);
    for conversation in PiAgentConnector::new().scan(&ctx)? {
        println!("{:?}: {} messages", conversation.title, conversation.messages.len());
    }

    // Every compiled-in connector, over explicit roots, streaming.
    let ctx = ScanContext::with_roots(
        PathBuf::from("/tmp/cass-state"),
        vec![ScanRoot::local(PathBuf::from("/home/me/.codex"))],
        None, // or Some(since_ms) for incremental scans
    );
    for (slug, make) in get_connector_factories() {
        make().scan_with_callback(&ctx, &mut |conversation| {
            println!("{slug}: {:?}", conversation.external_id);
            Ok(())
        })?;
    }
    Ok(())
}
```

Every connector produces `NormalizedConversation`s: `agent_slug`,
`external_id`, `title`, `workspace`, `source_path`, timestamps, `metadata`,
and `NormalizedMessage`s (`role`, `author`, `content`, `created_at`, structured
tool `invocations`, and the raw provider record in `extra`). Connector-derived
annotations live under `extra.cass` (for example branch and context membership
for Pi sessions). `extract_tokens_for_agent` turns a message's `extra` into
exact token usage where the agent records it, and an estimate otherwise.

Beyond `scan`:

| API | Purpose |
|---|---|
| `discover_source_files` | Pre-parse list of the files a scan will read (role, origin, size/mtime), so hosts can mirror sources before parsing |
| `scan_with_callback` / `supports_streaming_scan` | Emit conversations incrementally instead of materializing the corpus |
| `scan_with_source_boundaries` / `supports_source_boundaries` | Resumable ingestion: a pre-parse skip predicate and a per-source completion event (with required sidecars such as SQLite WALs) |
| `ScanRoot::remote` + `Origin` | Scan synced copies of remote machines, keeping host provenance |
| `CASS_EXCLUDE_PATHS` | Comma/newline-separated files or directories the Claude Code, Codex and Pi-family connectors skip before opening them. Entries match whole path components; relative, `..` and symlinked spellings of an existing directory match too. Other connectors read every source; hosts filter their conversations by `source_path` |

### Feature flags

| Feature | Enables |
|---|---|
| `connectors` | Connector framework and every connector that needs no extra dependencies |
| `chatgpt` | ChatGPT desktop, including AES-GCM encrypted v2/v3 conversations |
| `cursor`, `opencode`, `goose`, `hermes`, `crush`, `devin`, `shelley` | SQLite-backed stores for those agents |
| `openclaw-sqlite` | OpenClaw 2 per-agent SQLite transcripts (zstd events included) |
| `codex-zstd` | Codex rollouts compressed to `rollout-*.jsonl.zst` (Codex's `local_thread_store_compression`) |
| `copilot-vscdb` | Legacy VS Code Copilot chat sessions in `state.vscdb` |
| `pi-sqlite` | `pi_agent_rust` SQLite sessions for the Pi family |
| `pi-durable` | SQLite stores of Pi's experimental durable harness |
| `codebuff`, `grok-bot` | Codebuff / Freebuff shared history; Grok Bot desktop replicas |
| `all-connectors` | All of the above |

SQLite stores are read with [FrankenSQLite](https://crates.io/crates/fsqlite)
opened read-only inside one read transaction, so a live WAL is seen as one
coherent snapshot and nothing is recovered or checkpointed.

### Coverage

| Slug | Agent | Storage read |
|---|---|---|
| `aider` | Aider | `.aider.chat.history.md` |
| `amp` | Amp | thread JSON |
| `antigravity` | Antigravity IDE and `agy` CLI | transcripts and conversation stores |
| `chatgpt` | ChatGPT desktop | conversation JSON (encrypted generations with `chatgpt`) |
| `claude` | Claude Code | session JSONL (`CLAUDE_CONFIG_DIR`, `XDG_CONFIG_HOME` aware) |
| `clawdbot` | Clawdbot | session JSONL |
| `cline` | Cline | task JSON |
| `codebuff` | Codebuff / Freebuff (one shared store) | `~/.config/manicode` chats |
| `codex` | Codex CLI | rollout JSONL (`.jsonl.zst` with `codex-zstd`) |
| `copilot` / `github-copilot` | VS Code Copilot Chat | chat-session JSON and append logs; legacy `state.vscdb` |
| `copilot_cli` | Copilot CLI | session event logs |
| `crush` | Charm Crush | SQLite |
| `cursor` | Cursor | `state.vscdb` and agent transcripts |
| `devin` | Devin CLI | `sessions.db` (detection-only without `devin`) |
| `factory` | Factory Droid | session JSONL |
| `gemini` | Gemini CLI | session JSON |
| `goose` | Goose | `sessions.db` and legacy JSONL |
| `grok` / `grok_bot` | Grok Build CLI / Grok Bot desktop | session logs / rolling replicas |
| `hermes` | Hermes Agent | `state.db` |
| `kimi`, `kiro`, `qwen`, `vibe`, `muse` | Kimi Code, Kiro CLI, Qwen Code, Mistral Vibe, Muse Code | their session logs |
| `omp` | Oh My Pi | session JSONL, profiles and XDG layouts |
| `openclaw` | OpenClaw | session JSONL; OpenClaw 2 SQLite |
| `opencode` | OpenCode | JSON files and `opencode.db` |
| `openhands` | OpenHands | conversation event JSON |
| `pi_agent` | pi-mono and `pi_agent_rust` | session JSONL; SQLite sessions with `pi-sqlite` |
| `pi_durable` | Pi durable harness | `main.jsonl` commit logs; `session.sqlite` with `pi-durable` |
| `prime_agent` | Prime Agent | session JSONL |
| `shelley` | Shelley | `shelley.db` |
| `continue`, `windsurf` | Continue, Windsurf | detection only |

Pi-family transcripts keep every branch of a session (abandoned branches stay
searchable), and each message records whether it is on the active branch and
in the active model context, with summaries, injected context and shell runs
labeled by kind.

## Design goals

1. Keep output stable for downstream tooling and snapshot tests.
2. Keep behavior explicit: connector normalization, unknown slugs, unsupported
   store versions and incomplete sources are reported, never guessed at.
3. Stay local and read-only: filesystem and read-only SQLite access only.
4. Stay runtime-neutral with a synchronous API.

## Installation

```toml
[dependencies]
franken-agent-detection = "0.3"                                          # detection
franken-agent-detection = { version = "0.3", features = ["all-connectors"] } # parsing
```

From source:

```bash
git clone https://github.com/Dicklesworthstone/franken_agent_detection
cd franken_agent_detection
cargo test --all-features
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `UnknownConnectors` error | Connector slug not recognized | Use known slugs (`codex`, `claude`, `omp`, `gemini`, …) |
| Empty detection results | No roots exist on this machine | Set `include_undetected = true` to inspect evidence |
| A connector scans nothing | Its storage needs a cargo feature (SQLite, crypto) | Enable the feature from the table above, or `all-connectors` |
| Non-deterministic tests | Real home-dir probing | Use `root_overrides` / explicit `ScanRoot`s over temp directories |
| Stack overflow in SQLite tests | fsqlite's large debug-mode futures | `.cargo/config.toml` sets `RUST_MIN_STACK`; keep it when vendoring |

## Limitations

- Default probe roots are opinionated; custom layouts need overrides or
  explicit scan roots.
- No background watching; scans run only when called (`since_ts` makes them
  incremental, source boundaries make them resumable).
- Remote SQLite stores are not read: a live database and its WAL cannot be
  synced as one consistent snapshot. Index them on their own host.

## About Contributions

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

MIT
