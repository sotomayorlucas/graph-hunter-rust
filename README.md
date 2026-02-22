# Graph Hunter

Graph-based Threat Hunting engine built with Rust and Tauri. Ingest security logs, build a temporal knowledge graph, and hunt for attack patterns using hypothesis-driven search.

![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange)
![Tauri](https://img.shields.io/badge/Tauri-v2-blue)
![React](https://img.shields.io/badge/React-19-61dafb)
![Tests](https://img.shields.io/badge/Tests-99_passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

## How It Works

```
Security Logs ──► Parser ──► Knowledge Graph ──► Hypothesis Search ──► Attack Paths
  (JSON/NDJSON)              (Entities + Relations)    (Temporal DFS)
```

1. **Ingest** — Load Sysmon or Azure Sentinel logs. The parser extracts entities (IPs, hosts, users, processes, files, domains) and relations (Auth, Connect, Execute, Read, Write, DNS) with timestamps.
2. **Build Graph** — Entities become nodes, relations become directed edges. Duplicate entities are deduplicated; metadata is merged.
3. **Hunt** — Define a hypothesis as a chain of typed steps (e.g., `IP →[Connect]→ Host →[Auth]→ User →[Execute]→ Process`). The engine finds all paths matching the pattern with **causal monotonicity** (each step must occur at or after the previous one).
4. **Explore** — Search for IOCs, expand node neighborhoods, inspect metadata and anomaly scores.

## Supported Log Formats

### Sysmon (Windows Event Log)

| Event ID | Description | Triples |
|----------|-------------|---------|
| 1 | Process Create | `User →[Execute]→ Process` + `Parent →[Execute]→ Child` |
| 3 | Network Connection | `Host →[Connect]→ IP` |
| 11 | File Create | `Process →[Write]→ File` |
| 22 | DNS Query | `Process →[DNS]→ Domain` |

### Azure Sentinel (Microsoft Sentinel)

| Table | Triples |
|-------|---------|
| SecurityEvent (4624/4625) | `User →[Auth]→ Host` |
| SecurityEvent (4688) | `User →[Execute]→ Process` + `Parent →[Execute]→ Child` |
| SecurityEvent (4663) | `Process →[Read]→ File` |
| SigninLogs | `User →[Auth]→ IP` |
| DeviceProcessEvents | `User →[Execute]→ Process` + `Parent →[Execute]→ Child` |
| DeviceNetworkEvents | `Host →[Connect]→ IP` |
| DeviceFileEvents | `Process →[Write/Read]→ File` |
| CommonSecurityLog | `IP →[Connect]→ IP` |

Sentinel records are auto-classified by their `Type` field, with heuristic fallback for data without it.

## Architecture

```
graph-hunter-rust/
├── graph_hunter_core/          # Rust core library
│   └── src/
│       ├── graph.rs            # GraphHunter engine (add, search, ingest)
│       ├── sysmon.rs           # Sysmon log parser
│       ├── sentinel.rs         # Azure Sentinel log parser
│       ├── parser.rs           # LogParser trait
│       ├── analytics.rs        # Neighborhood, search, scoring, summaries
│       ├── hypothesis.rs       # Hypothesis + step definitions
│       ├── entity.rs           # Entity struct
│       ├── relation.rs         # Relation struct
│       ├── types.rs            # EntityType, RelationType enums
│       └── errors.rs           # Error types
├── app/
│   ├── src/                    # React + TypeScript frontend
│   │   ├── components/
│   │   │   ├── IngestPanel.tsx      # Data loading + format selector
│   │   │   ├── HypothesisBuilder.tsx # Hunt mode query builder
│   │   │   ├── GraphCanvas.tsx      # Cytoscape graph visualization
│   │   │   ├── ExplorerPanel.tsx    # IOC search + node expansion
│   │   │   └── NodeDetailPanel.tsx  # Node detail sidebar
│   │   └── App.tsx
│   └── src-tauri/              # Tauri backend (commands)
│       └── src/lib.rs
└── demo_data/
    ├── apt_attack_simulation.json       # Sysmon APT kill chain (34 events)
    └── sentinel_attack_simulation.json  # Sentinel cloud-to-on-prem attack (26 events)
```

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (edition 2024)
- [Node.js](https://nodejs.org/) (v18+)
- [Tauri CLI v2](https://v2.tauri.app/start/prerequisites/)

### Run in Development

```bash
cd app
npm install
npm run tauri dev
```

### Run Tests

```bash
cd graph_hunter_core
cargo test
```

### Build for Production

```bash
cd app
npm run tauri build
```

## Demo Data

Two attack simulation datasets are included in `demo_data/`:

**APT Attack Simulation** (`apt_attack_simulation.json`) — Sysmon format. Simulates a full APT kill chain: initial compromise via spearphishing, discovery, credential theft with Mimikatz, lateral movement with PsExec, malware deployment, C2 beaconing, and data exfiltration.

**Sentinel Attack Simulation** (`sentinel_attack_simulation.json`) — Azure Sentinel format. Simulates a cloud-to-on-prem compromise: brute-force against DC, Azure AD abuse from compromised service account, lateral movement to finance workstation, beacon deployment, credential dumping, and data exfiltration.

### Try It

1. Launch the app with `npm run tauri dev`
2. Select format (Sysmon or Azure Sentinel) from the dropdown
3. Click "Select File" and load a demo data file
4. Switch to **Hunt Mode** and build a hypothesis, e.g.:
   - `User →[Execute]→ Process →[Write]→ File` (malware drop)
   - `User →[Auth]→ Host` (brute force)
   - `Host →[Connect]→ IP` (C2 communication)
5. Switch to **Explorer Mode** to search for IOCs and expand neighborhoods

## Core Engine Features

- **Temporal pattern matching** — DFS with causal monotonicity enforcement (events must follow chronological order)
- **Time window filtering** — Restrict hunts to a specific time range
- **Anomaly scoring** — Normalized degree centrality (0–100) highlights hub nodes
- **Parallel parsing** — Rayon-based parallel ingestion for large log files
- **Deduplication** — Entities are deduplicated by ID; metadata from first occurrence is preserved
- **Multi-format** — JSON arrays and NDJSON (newline-delimited JSON)

## License

MIT
