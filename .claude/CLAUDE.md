# Graph Hunter — Project Conventions

## Project Overview

Graph-based Threat Hunting engine. Ingests security logs (Sysmon, Azure Sentinel), builds a temporal knowledge graph, and hunts for attack patterns via hypothesis-driven DFS.

**Stack:** Rust 2024 (core) + Tauri v2 (desktop) + React 19 + TypeScript + Cytoscape (graph viz)

## Repository Structure

```
graph_hunter_core/       # Rust library — all domain logic, zero UI
app/src-tauri/           # Tauri backend — thin command layer over core
app/src/                 # React frontend — components, types, styles
demo_data/               # JSON simulation files for testing/demo
```

## Commands

| Action | Command | Directory |
|--------|---------|-----------|
| Run tests | `cargo test` | `graph_hunter_core/` |
| Type check frontend | `npx tsc --noEmit` | `app/` |
| Dev mode | `npm run tauri dev` | `app/` |
| Build production | `npm run tauri build` | `app/` |
| Check Tauri compiles | `cargo check` | `app/src-tauri/` |

## Rust Conventions (graph_hunter_core)

### Architecture

- **All logic lives in `graph_hunter_core`**. The Tauri layer is a thin adapter.
- Parsers implement the `LogParser` trait (stateless, `Send + Sync`).
- Each parser goes in its own module (`sysmon.rs`, `sentinel.rs`, etc.).
- New parsers must be registered in `lib.rs`: `pub mod <name>` + `pub use <name>::<Parser>`.
- All tests go in the `mod tests` block at the bottom of `lib.rs`, not in separate test files.

### Parser Pattern

Every log parser follows this structure (see `sysmon.rs` and `sentinel.rs`):

```rust
pub struct FooParser;

impl FooParser {
    fn parse_timestamp(ts: &str) -> Option<i64> { ... }
    fn extract_str<'a>(event: &'a Value, key: &str) -> Option<&'a str> { ... }
    fn parse_event(event: &Value) -> Vec<ParsedTriple> { ... }
    // Per-event-type private methods...
}

impl LogParser for FooParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        // Try JSON array, fallback to NDJSON
        // Use rayon par_iter for parallelism
    }
}
```

- `ParsedTriple = (Entity, Relation, Entity)` — source, edge, destination.
- Malformed/unrecognized events are silently skipped (best-effort ingestion).
- Timestamps are Unix epoch seconds (`i64`). Default to `0` if unparseable.
- Use `extract_str` helper to safely get non-empty string fields from JSON.

### Graph Types

- **EntityType**: `IP`, `Host`, `User`, `Process`, `File`, `Domain`
- **RelationType**: `Auth`, `Connect`, `Execute`, `Read`, `Write`, `DNS`
- Entity equality/hashing is by `id` only (not type or score).
- Metadata is `HashMap<String, String>` — use `.with_metadata(key, value)` builder.

### Test Conventions

- Tests are grouped by phase with ASCII headers: `// ══ Phase N: ... ══`
- Test names: `{parser}_{table_or_feature}_{what_is_tested}` (e.g., `sentinel_security_event_4624_auth_success`)
- Each new parser should have: per-table tests, detection tests, format tests (JSON array, NDJSON, mixed), edge cases, integration (ingest→hunt), and a demo data test.
- Demo data test loads from `../demo_data/` relative path and verifies ingestion + hunt results.

### Error Handling

- `GraphError` enum: `EntityNotFound`, `DuplicateEntity`, `InvalidHypothesis`.
- Parsers never return errors — they return empty `Vec` for bad input.
- Tauri commands return `Result<T, String>` (string errors for frontend display).

## Tauri Backend Conventions (app/src-tauri)

- Global `AppState` with `RwLock<GraphHunter>`.
- Commands prefixed `cmd_` (e.g., `cmd_load_data`, `cmd_get_graph_stats`).
- Format string passed from frontend, matched in `cmd_load_data`:
  ```rust
  "sysmon" => graph.ingest_logs(&contents, &SysmonJsonParser),
  "sentinel" => graph.ingest_logs(&contents, &SentinelJsonParser),
  ```
- Adding a new format: import parser, add match arm, update error message.
- Auto-compute scores after every `cmd_load_data` call.

## Frontend Conventions (app/src)

- Functional components with hooks (`useState`, `useCallback`).
- Types defined in `src/types.ts` — mirrors Tauri response structs.
- Tauri calls: `invoke<ResponseType>("cmd_name", { params })`.
- Two modes: `"hunt"` (HypothesisBuilder) and `"explore"` (ExplorerPanel).
- IngestPanel owns format state and passes it to `cmd_load_data`.
- Inline styles for component-specific layout; `App.css` for global theme.
- Icons from `lucide-react` — use `size={14}` for consistency.
- Activity log: `onLog({ time: now(), message, level: "info"|"success"|"error" })`.

## Adding a New Log Format (Checklist)

1. Create `graph_hunter_core/src/<format>.rs` — implement `LogParser` trait
2. Register in `graph_hunter_core/src/lib.rs` — `pub mod` + `pub use`
3. Add match arm in `app/src-tauri/src/lib.rs` — `cmd_load_data`
4. Add option in `app/src/components/IngestPanel.tsx` — format dropdown
5. Create demo data in `demo_data/<format>_simulation.json`
6. Write tests in `graph_hunter_core/src/lib.rs` — `mod tests` block
7. Verify: `cargo test` + `npx tsc --noEmit` + `cargo check` (in src-tauri)

## Git

- Commit messages: imperative, concise summary line, body for details if needed.
- Co-author tag when AI-assisted: `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`
- Branch: `master`.
- `.gitignore` excludes: `**/target/`, `**/node_modules/`, `app/dist/`, `.claude/`.
