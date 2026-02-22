import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import {
  Upload,
  BarChart3,
  FolderOpen,
  Database,
  Activity,
} from "lucide-react";
import type { GraphStats, LoadResult, LogEntry, EntityType } from "../types";
import { ENTITY_COLORS } from "../types";

interface IngestPanelProps {
  stats: GraphStats;
  onStatsUpdate: (stats: GraphStats) => void;
  log: LogEntry[];
  onLog: (entry: LogEntry) => void;
}

function now(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

export default function IngestPanel({
  stats,
  onStatsUpdate,
  log,
  onLog,
}: IngestPanelProps) {
  const [filePath, setFilePath] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [format, setFormat] = useState<"sysmon" | "sentinel">("sysmon");

  async function pickFile() {
    try {
      const selected = await open({
        multiple: false,
        filters: [
          {
            name: format === "sysmon" ? "Sysmon JSON" : "Sentinel JSON",
            extensions: ["json", "ndjson"],
          },
        ],
      });
      if (selected) {
        setFilePath(selected as string);
        onLog({
          time: now(),
          message: `Selected: ${(selected as string).split(/[/\\]/).pop()}`,
          level: "info",
        });
      }
    } catch (e) {
      onLog({ time: now(), message: `File dialog error: ${e}`, level: "error" });
    }
  }

  async function loadData() {
    if (!filePath) return;
    setLoading(true);
    onLog({ time: now(), message: "Ingesting logs...", level: "info" });

    try {
      const result = await invoke<LoadResult>("cmd_load_data", {
        path: filePath,
        format,
      });

      onStatsUpdate({
        entity_count: result.total_entities,
        relation_count: result.total_relations,
      });

      onLog({
        time: now(),
        message: `+${result.new_entities} entities, +${result.new_relations} relations`,
        level: "success",
      });
    } catch (e) {
      onLog({ time: now(), message: `${e}`, level: "error" });
    } finally {
      setLoading(false);
    }
  }

  async function refreshStats() {
    try {
      const s = await invoke<GraphStats>("cmd_get_graph_stats");
      onStatsUpdate(s);
    } catch (e) {
      onLog({ time: now(), message: `${e}`, level: "error" });
    }
  }

  return (
    <div className="panel panel-left">
      <h2>
        <Database size={14} style={{ marginRight: 6, verticalAlign: "middle" }} />
        Data Ingestion
      </h2>

      {/* Format Selection */}
      <div style={{ marginBottom: 8 }}>
        <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
          Log Format
        </label>
        <select
          className="select"
          value={format}
          onChange={(e) => setFormat(e.target.value as "sysmon" | "sentinel")}
          style={{
            width: "100%",
            padding: "6px 8px",
            background: "var(--bg-tertiary)",
            color: "var(--text-primary)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            fontSize: 12,
          }}
        >
          <option value="sysmon">Sysmon (Event Log)</option>
          <option value="sentinel">Azure Sentinel</option>
        </select>
      </div>

      {/* File Selection */}
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <button className="btn" onClick={pickFile}>
          <FolderOpen size={14} />
          {format === "sysmon" ? "Select Sysmon File" : "Select Sentinel File"}
        </button>
        {filePath && (
          <div className="file-info">{filePath.split(/[/\\]/).pop()}</div>
        )}
        <button
          className="btn btn-primary"
          onClick={loadData}
          disabled={!filePath || loading}
        >
          <Upload size={14} />
          {loading ? "Loading..." : "Ingest Logs"}
        </button>
      </div>

      <hr className="section-divider" />

      {/* Stats */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <h2>
          <BarChart3 size={14} style={{ marginRight: 6, verticalAlign: "middle" }} />
          Graph Stats
        </h2>
        <button className="btn btn-sm" onClick={refreshStats}>
          <Activity size={12} />
        </button>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="value">{stats.entity_count.toLocaleString()}</div>
          <div className="label">Entities</div>
        </div>
        <div className="stat-card">
          <div className="value">{stats.relation_count.toLocaleString()}</div>
          <div className="label">Relations</div>
        </div>
      </div>

      <hr className="section-divider" />

      {/* Status Log */}
      <h2>
        <Activity size={14} style={{ marginRight: 6, verticalAlign: "middle" }} />
        Activity Log
      </h2>
      <div className="status-log">
        {log.length === 0 && (
          <div className="entry" style={{ color: "var(--text-muted)" }}>
            No activity yet
          </div>
        )}
        {log.map((entry, i) => (
          <div key={i} className={`entry ${entry.level}`}>
            <span className="time">{entry.time}</span>
            {entry.message}
          </div>
        ))}
      </div>

      {/* Legend */}
      <div className="legend">
        {(Object.entries(ENTITY_COLORS) as [EntityType, string][]).map(
          ([type, color]) => (
            <div key={type} className="legend-item">
              <span className="legend-dot" style={{ background: color }} />
              {type}
            </div>
          )
        )}
      </div>
    </div>
  );
}
