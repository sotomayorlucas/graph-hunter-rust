import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import IngestPanel from "./components/IngestPanel";
import HypothesisBuilder from "./components/HypothesisBuilder";
import GraphCanvas from "./components/GraphCanvas";
import ExplorerPanel from "./components/ExplorerPanel";
import NodeDetailPanel from "./components/NodeDetailPanel";
import type {
  GraphStats,
  HuntResults,
  Subgraph,
  Neighborhood,
  NodeDetails,
  ExpandFilter,
  LogEntry,
} from "./types";
import "./App.css";

type AppMode = "hunt" | "explore";

function App() {
  const [stats, setStats] = useState<GraphStats>({
    entity_count: 0,
    relation_count: 0,
  });
  const [log, setLog] = useState<LogEntry[]>([]);
  const [mode, setMode] = useState<AppMode>("hunt");

  // Hunt mode state
  const [subgraph, setSubgraph] = useState<Subgraph | null>(null);
  const [highlightPaths, setHighlightPaths] = useState<string[][] | null>(null);

  // Explorer mode state
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [nodeDetails, setNodeDetails] = useState<NodeDetails | null>(null);
  const [explorerNeighborhood, setExplorerNeighborhood] =
    useState<Neighborhood | null>(null);

  const addLog = useCallback((entry: LogEntry) => {
    setLog((prev) => [entry, ...prev].slice(0, 100));
  }, []);

  // ── Hunt mode handler ──
  const handleHuntResults = useCallback(
    async (results: HuntResults) => {
      if (results.path_count === 0) {
        setSubgraph(null);
        setHighlightPaths(null);
        return;
      }

      const allNodeIds = new Set<string>();
      for (const path of results.paths) {
        for (const nodeId of path) {
          allNodeIds.add(nodeId);
        }
      }

      try {
        const sg = await invoke<Subgraph>("cmd_get_subgraph", {
          nodeIds: Array.from(allNodeIds),
        });
        setSubgraph(sg);
        setHighlightPaths(results.paths);
      } catch (e) {
        addLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Subgraph error: ${e}`,
          level: "error",
        });
      }
    },
    [addLog]
  );

  // ── Explorer mode: expand a node ──
  const handleExploreNode = useCallback(
    async (nodeId: string, filter?: ExpandFilter) => {
      try {
        const hood = await invoke<Neighborhood>("cmd_expand_node", {
          nodeId,
          maxHops: 1,
          maxNodes: 50,
          filter: filter || null,
        });
        setExplorerNeighborhood(hood);
        setSelectedNodeId(nodeId);

        // Also fetch details
        const details = await invoke<NodeDetails>("cmd_get_node_details", {
          nodeId,
        });
        setNodeDetails(details);
      } catch (e) {
        addLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Explore error: ${e}`,
          level: "error",
        });
      }
    },
    [addLog]
  );

  // ── Explorer mode: click a node to see details ──
  const handleNodeClick = useCallback(
    async (nodeId: string) => {
      if (mode !== "explore") return;
      setSelectedNodeId(nodeId);
      try {
        const details = await invoke<NodeDetails>("cmd_get_node_details", {
          nodeId,
        });
        setNodeDetails(details);
      } catch (e) {
        console.error("Failed to get node details:", e);
      }
    },
    [mode]
  );

  // ── Explorer mode: double-click to expand ──
  const handleNodeDoubleClick = useCallback(
    async (nodeId: string) => {
      if (mode !== "explore") return;
      handleExploreNode(nodeId);
    },
    [mode, handleExploreNode]
  );

  // ── Mode switch ──
  const handleModeChange = useCallback((newMode: AppMode) => {
    setMode(newMode);
    setSelectedNodeId(null);
    setNodeDetails(null);
    if (newMode === "hunt") {
      setExplorerNeighborhood(null);
    } else {
      setSubgraph(null);
      setHighlightPaths(null);
    }
  }, []);

  return (
    <div className="app-container">
      <IngestPanel
        stats={stats}
        onStatsUpdate={setStats}
        log={log}
        onLog={addLog}
      />
      <GraphCanvas
        subgraph={subgraph}
        highlightPaths={highlightPaths}
        explorerMode={mode === "explore"}
        neighborhood={explorerNeighborhood}
        selectedNodeId={selectedNodeId}
        onNodeClick={handleNodeClick}
        onNodeDoubleClick={handleNodeDoubleClick}
      />

      {/* Bottom panel with mode tabs */}
      <div className="panel panel-bottom-container">
        <div className="mode-tabs">
          <button
            className={`mode-tab ${mode === "hunt" ? "active" : ""}`}
            onClick={() => handleModeChange("hunt")}
          >
            Hunt Mode
          </button>
          <button
            className={`mode-tab ${mode === "explore" ? "active" : ""}`}
            onClick={() => handleModeChange("explore")}
          >
            Explorer Mode
          </button>
        </div>

        {mode === "hunt" ? (
          <HypothesisBuilder
            onHuntResults={handleHuntResults}
            onLog={addLog}
          />
        ) : (
          <ExplorerPanel
            onExploreNode={handleExploreNode}
            neighborhood={explorerNeighborhood}
          />
        )}
      </div>

      {/* Node detail sidebar */}
      {nodeDetails && mode === "explore" && (
        <NodeDetailPanel
          details={nodeDetails}
          onClose={() => {
            setNodeDetails(null);
            setSelectedNodeId(null);
          }}
          onExpand={handleExploreNode}
          onSetCenter={handleExploreNode}
        />
      )}
    </div>
  );
}

export default App;
