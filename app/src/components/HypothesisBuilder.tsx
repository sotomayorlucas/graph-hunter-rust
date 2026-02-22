import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Plus, Trash2, Crosshair, X } from "lucide-react";
import type {
  HypothesisStep,
  Hypothesis,
  HuntResults,
  LogEntry,
} from "../types";
import { ENTITY_TYPES, RELATION_TYPES } from "../types";

interface HypothesisBuilderProps {
  onHuntResults: (results: HuntResults) => void;
  onLog: (entry: LogEntry) => void;
}

const DEFAULT_STEP: HypothesisStep = {
  origin_type: "IP",
  relation_type: "Connect",
  dest_type: "Host",
};

function now(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

// ── Preset hypotheses for quick demo at Black Hat ──
const PRESETS: { name: string; steps: HypothesisStep[] }[] = [
  {
    name: "Lateral Movement",
    steps: [
      { origin_type: "User", relation_type: "Execute", dest_type: "Process" },
      { origin_type: "Process", relation_type: "Execute", dest_type: "Process" },
      { origin_type: "Process", relation_type: "Write", dest_type: "File" },
    ],
  },
  {
    name: "DNS Exfiltration",
    steps: [
      { origin_type: "User", relation_type: "Execute", dest_type: "Process" },
      { origin_type: "Process", relation_type: "DNS", dest_type: "Domain" },
    ],
  },
  {
    name: "Malware Drop",
    steps: [
      { origin_type: "User", relation_type: "Execute", dest_type: "Process" },
      { origin_type: "Process", relation_type: "Write", dest_type: "File" },
    ],
  },
];

export default function HypothesisBuilder({
  onHuntResults,
  onLog,
}: HypothesisBuilderProps) {
  const [steps, setSteps] = useState<HypothesisStep[]>([{ ...DEFAULT_STEP }]);
  const [hunting, setHunting] = useState(false);
  const [results, setResults] = useState<HuntResults | null>(null);

  function addStep() {
    const lastStep = steps[steps.length - 1];
    setSteps([
      ...steps,
      {
        origin_type: lastStep ? lastStep.dest_type : "IP",
        relation_type: "Connect",
        dest_type: "Host",
      },
    ]);
  }

  function removeStep(idx: number) {
    if (steps.length <= 1) return;
    setSteps(steps.filter((_, i) => i !== idx));
  }

  function updateStep(
    idx: number,
    field: keyof HypothesisStep,
    value: string
  ) {
    const updated = [...steps];
    updated[idx] = { ...updated[idx], [field]: value };
    setSteps(updated);
  }

  function loadPreset(preset: (typeof PRESETS)[number]) {
    setSteps(preset.steps.map((s) => ({ ...s })));
    setResults(null);
    onLog({ time: now(), message: `Loaded preset: ${preset.name}`, level: "info" });
  }

  async function runHunt() {
    setHunting(true);
    setResults(null);
    onLog({ time: now(), message: "Running hunt...", level: "info" });

    const hypothesis: Hypothesis = {
      name: "Hunt",
      steps,
    };

    try {
      const res = await invoke<HuntResults>("cmd_run_hunt", {
        hypothesisJson: JSON.stringify(hypothesis),
        timeWindow: null,
      });

      setResults(res);
      onHuntResults(res);

      if (res.path_count > 0) {
        onLog({
          time: now(),
          message: `FOUND ${res.path_count} attack path(s)!`,
          level: "success",
        });
      } else {
        onLog({
          time: now(),
          message: "No matching paths found",
          level: "info",
        });
      }
    } catch (e) {
      onLog({ time: now(), message: `Hunt error: ${e}`, level: "error" });
    } finally {
      setHunting(false);
    }
  }

  return (
    <div className="hypothesis-content">
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <h2>
          <Crosshair
            size={14}
            style={{ marginRight: 6, verticalAlign: "middle" }}
          />
          Hypothesis Builder
        </h2>
        <div style={{ display: "flex", gap: 6 }}>
          {PRESETS.map((preset) => (
            <button
              key={preset.name}
              className="btn btn-sm"
              onClick={() => loadPreset(preset)}
            >
              {preset.name}
            </button>
          ))}
        </div>
      </div>

      {/* Steps Chain */}
      <div className="hypothesis-chain">
        {steps.map((step, idx) => (
          <div key={idx} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            {idx > 0 && <span className="step-arrow">&rarr;</span>}
            <div className="step-group">
              <select
                value={step.origin_type}
                onChange={(e) =>
                  updateStep(idx, "origin_type", e.target.value)
                }
              >
                {ENTITY_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>

              <span style={{ color: "var(--accent)", fontSize: 11 }}>
                &mdash;[
              </span>

              <select
                value={step.relation_type}
                onChange={(e) =>
                  updateStep(idx, "relation_type", e.target.value)
                }
              >
                {RELATION_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>

              <span style={{ color: "var(--accent)", fontSize: 11 }}>
                ]&rarr;
              </span>

              <select
                value={step.dest_type}
                onChange={(e) =>
                  updateStep(idx, "dest_type", e.target.value)
                }
              >
                {ENTITY_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>

              {steps.length > 1 && (
                <span
                  className="step-remove"
                  onClick={() => removeStep(idx)}
                  title="Remove step"
                >
                  <X size={12} />
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Actions */}
      <div className="hypothesis-actions">
        <button className="btn" onClick={addStep}>
          <Plus size={14} /> Add Step
        </button>
        <button
          className="btn btn-primary"
          onClick={runHunt}
          disabled={hunting}
        >
          <Crosshair size={14} />
          {hunting ? "Hunting..." : "Run Hunt"}
        </button>
        {results && (
          <button
            className="btn btn-danger btn-sm"
            onClick={() => setResults(null)}
          >
            <Trash2 size={12} /> Clear
          </button>
        )}
        {results && (
          <span
            style={{
              color:
                results.path_count > 0 ? "var(--danger)" : "var(--text-muted)",
              fontWeight: "bold",
              fontSize: 13,
            }}
          >
            {results.path_count > 0
              ? `${results.path_count} path(s) found`
              : "No matches"}
          </span>
        )}
      </div>
    </div>
  );
}
