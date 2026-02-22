import { X, Expand, Crosshair, Copy } from "lucide-react";
import type { NodeDetails, EntityType } from "../types";
import { ENTITY_COLORS } from "../types";

interface NodeDetailPanelProps {
  details: NodeDetails;
  onClose: () => void;
  onExpand: (nodeId: string) => void;
  onSetCenter: (nodeId: string) => void;
}

export default function NodeDetailPanel({
  details,
  onClose,
  onExpand,
  onSetCenter,
}: NodeDetailPanelProps) {
  const color =
    ENTITY_COLORS[details.entity_type as EntityType] || "#94a3b8";

  const copyToClipboard = () => {
    navigator.clipboard.writeText(details.id);
  };

  const formatTimestamp = (ts: number) => {
    return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19);
  };

  return (
    <div className="node-detail-panel">
      {/* Header */}
      <div className="detail-header">
        <div className="detail-title" title={details.id}>
          {details.id.length > 28
            ? "..." + details.id.slice(-25)
            : details.id}
        </div>
        <button className="detail-close" onClick={onClose}>
          <X size={14} />
        </button>
      </div>

      {/* Type + Score */}
      <div className="detail-type-row">
        <span className="legend-dot" style={{ backgroundColor: color }} />
        <span className="detail-type">{details.entity_type}</span>
        {details.score > 0 && (
          <span className="detail-score">
            Score: {details.score.toFixed(1)}
          </span>
        )}
      </div>

      {/* Degrees */}
      <div className="detail-degrees">
        <div className="degree-item">
          <span className="degree-value">{details.in_degree}</span>
          <span className="degree-label">In</span>
        </div>
        <div className="degree-item">
          <span className="degree-value">{details.out_degree}</span>
          <span className="degree-label">Out</span>
        </div>
        <div className="degree-item">
          <span className="degree-value">
            {details.in_degree + details.out_degree}
          </span>
          <span className="degree-label">Total</span>
        </div>
      </div>

      {/* Time range */}
      {details.time_range && (
        <div className="detail-section">
          <div className="detail-section-title">Time Range</div>
          <div className="detail-time">
            {formatTimestamp(details.time_range[0])} &mdash;{" "}
            {formatTimestamp(details.time_range[1])}
          </div>
        </div>
      )}

      {/* Metadata */}
      {Object.keys(details.metadata).length > 0 && (
        <div className="detail-section">
          <div className="detail-section-title">Metadata</div>
          <div className="detail-metadata">
            {Object.entries(details.metadata).map(([k, v]) => (
              <div key={k} className="metadata-row">
                <span className="metadata-key">{k}</span>
                <span className="metadata-value" title={v}>
                  {v.length > 30 ? v.slice(0, 30) + "..." : v}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Neighbor type breakdown */}
      {Object.keys(details.neighbor_types).length > 0 && (
        <div className="detail-section">
          <div className="detail-section-title">Neighbors</div>
          <div className="detail-neighbor-types">
            {Object.entries(details.neighbor_types).map(([type_, count]) => (
              <div key={type_} className="neighbor-type-item">
                <span
                  className="legend-dot"
                  style={{
                    backgroundColor:
                      ENTITY_COLORS[type_ as EntityType] || "#94a3b8",
                  }}
                />
                <span>{type_}</span>
                <span className="neighbor-count">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="detail-actions">
        <button
          className="btn btn-sm btn-primary"
          onClick={() => onExpand(details.id)}
        >
          <Expand size={12} /> Expand
        </button>
        <button
          className="btn btn-sm"
          onClick={() => onSetCenter(details.id)}
        >
          <Crosshair size={12} /> Center
        </button>
        <button className="btn btn-sm" onClick={copyToClipboard}>
          <Copy size={12} /> Copy
        </button>
      </div>
    </div>
  );
}
