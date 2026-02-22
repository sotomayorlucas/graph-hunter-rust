import { useEffect, useRef, useCallback } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
// @ts-expect-error no types for cytoscape-dagre
import dagre from "cytoscape-dagre";
import type { Subgraph, Neighborhood } from "../types";
import { ENTITY_COLORS, type EntityType } from "../types";

// Register dagre layout
cytoscape.use(dagre);

interface GraphCanvasProps {
  subgraph: Subgraph | null;
  highlightPaths: string[][] | null;
  // Explorer mode props
  explorerMode: boolean;
  neighborhood: Neighborhood | null;
  selectedNodeId: string | null;
  onNodeClick?: (nodeId: string) => void;
  onNodeDoubleClick?: (nodeId: string) => void;
}

// ── Entity type → shape mapping ──
const ENTITY_SHAPES: Record<string, string> = {
  IP: "diamond",
  Host: "round-rectangle",
  User: "ellipse",
  Process: "hexagon",
  File: "rectangle",
  Domain: "triangle",
};

export default function GraphCanvas({
  subgraph,
  highlightPaths,
  explorerMode,
  neighborhood,
  selectedNodeId,
  onNodeClick,
  onNodeDoubleClick,
}: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  // ── Initialize Cytoscape ──
  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "text-valign": "bottom",
            "text-halign": "center",
            "font-size": "10px",
            "font-family": "JetBrains Mono, Fira Code, monospace",
            color: "#94a3b8",
            "text-margin-y": 6,
            "background-color": "data(color)",
            "border-width": 2,
            "border-color": "data(color)",
            "border-opacity": 0.6,
            width: "data(size)",
            height: "data(size)",
            shape: "data(shape)" as unknown as cytoscape.Css.NodeShape,
            "text-max-width": "120px",
            "text-wrap": "ellipsis",
          },
        },
        {
          selector: "node.highlighted",
          style: {
            "border-color": "#ff4444",
            "border-width": 3,
            "border-opacity": 1,
            "background-opacity": 1,
            "overlay-color": "#ff4444",
            "overlay-opacity": 0.1,
          },
        },
        {
          selector: "node.selected-node",
          style: {
            "border-color": "#00ff88",
            "border-width": 3,
            "border-opacity": 1,
            "overlay-color": "#00ff88",
            "overlay-opacity": 0.15,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#2d3748",
            "target-arrow-color": "#2d3748",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": "9px",
            "font-family": "JetBrains Mono, Fira Code, monospace",
            color: "#64748b",
            "text-rotation": "autorotate",
            "text-margin-y": -8,
          },
        },
        {
          selector: "edge.highlighted",
          style: {
            width: 3,
            "line-color": "#ff4444",
            "target-arrow-color": "#ff4444",
            "overlay-color": "#ff4444",
            "overlay-opacity": 0.1,
          },
        },
      ],
      layout: { name: "grid" },
      minZoom: 0.2,
      maxZoom: 4,
      wheelSensitivity: 0.3,
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, []);

  // ── Register click handlers ──
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    const handleTap = (evt: cytoscape.EventObject) => {
      const nodeId = evt.target.id();
      if (nodeId && onNodeClick) {
        onNodeClick(nodeId);
      }
    };

    const handleDbltap = (evt: cytoscape.EventObject) => {
      const nodeId = evt.target.id();
      if (nodeId && onNodeDoubleClick) {
        onNodeDoubleClick(nodeId);
      }
    };

    cy.on("tap", "node", handleTap);
    cy.on("dbltap", "node", handleDbltap);

    return () => {
      cy.off("tap", "node", handleTap);
      cy.off("dbltap", "node", handleDbltap);
    };
  }, [onNodeClick, onNodeDoubleClick]);

  // ── Score-based sizing helper ──
  const scoreToSize = useCallback((score: number) => {
    // Map score [0, 100] to size [30, 60]
    return 30 + (score / 100) * 30;
  }, []);

  // ── Build Cytoscape elements from subgraph ──
  const buildElements = useCallback(
    (sg: { nodes: Array<{ id: string; entity_type: string; score: number }>; edges: Array<{ source: string; target: string; rel_type: string; timestamp: number }> }): ElementDefinition[] => {
      const elements: ElementDefinition[] = [];

      for (const node of sg.nodes) {
        const entityType = node.entity_type as EntityType;
        const shortLabel =
          node.id.length > 30
            ? "..." + node.id.slice(-27)
            : node.id;

        elements.push({
          group: "nodes",
          data: {
            id: node.id,
            label: shortLabel,
            color: ENTITY_COLORS[entityType] || "#94a3b8",
            shape: ENTITY_SHAPES[node.entity_type] || "ellipse",
            entityType: node.entity_type,
            score: node.score,
            size: scoreToSize(node.score),
          },
        });
      }

      for (let i = 0; i < sg.edges.length; i++) {
        const edge = sg.edges[i];
        elements.push({
          group: "edges",
          data: {
            id: `e-${edge.source}-${edge.target}-${i}`,
            source: edge.source,
            target: edge.target,
            label: edge.rel_type,
            timestamp: edge.timestamp,
          },
        });
      }

      return elements;
    },
    [scoreToSize]
  );

  // ── Update graph in Hunt mode ──
  useEffect(() => {
    if (explorerMode) return;
    const cy = cyRef.current;
    if (!cy) return;

    if (!subgraph || (subgraph.nodes.length === 0 && subgraph.edges.length === 0)) {
      cy.elements().remove();
      return;
    }

    const elements = buildElements(subgraph);

    cy.elements().remove();
    cy.add(elements);

    cy.layout({
      name: "dagre",
      rankDir: "LR",
      nodeSep: 60,
      rankSep: 100,
      animate: true,
      animationDuration: 600,
      animationEasing: "ease-out-cubic" as unknown as cytoscape.Css.TransitionTimingFunction,
      fit: true,
      padding: 50,
    } as cytoscape.LayoutOptions).run();
  }, [subgraph, buildElements, explorerMode]);

  // ── Update graph in Explorer mode (incremental) ──
  useEffect(() => {
    if (!explorerMode) return;
    const cy = cyRef.current;
    if (!cy || !neighborhood) return;

    const elements = buildElements(neighborhood);

    // Add only new elements (incremental)
    const existingIds = new Set(cy.elements().map((el) => el.id()));
    const newElements = elements.filter(
      (el) => el.data.id && !existingIds.has(el.data.id)
    );

    if (newElements.length > 0) {
      cy.add(newElements);
    }

    // Run layout on all elements
    cy.layout({
      name: "dagre",
      rankDir: "LR",
      nodeSep: 60,
      rankSep: 100,
      animate: true,
      animationDuration: 600,
      animationEasing: "ease-out-cubic" as unknown as cytoscape.Css.TransitionTimingFunction,
      fit: true,
      padding: 50,
    } as cytoscape.LayoutOptions).run();
  }, [neighborhood, buildElements, explorerMode]);

  // ── Highlight attack paths (Hunt mode) ──
  useEffect(() => {
    if (explorerMode) return;
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass("highlighted");

    if (!highlightPaths || highlightPaths.length === 0) return;

    for (const path of highlightPaths) {
      for (const nodeId of path) {
        cy.getElementById(nodeId).addClass("highlighted");
      }
      for (let i = 0; i < path.length - 1; i++) {
        const sourceId = path[i];
        const targetId = path[i + 1];
        cy.edges().forEach((edge) => {
          if (
            edge.data("source") === sourceId &&
            edge.data("target") === targetId
          ) {
            edge.addClass("highlighted");
          }
        });
      }
    }
  }, [highlightPaths, explorerMode]);

  // ── Highlight selected node ──
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.nodes().removeClass("selected-node");
    if (selectedNodeId) {
      cy.getElementById(selectedNodeId).addClass("selected-node");
    }
  }, [selectedNodeId]);

  // ── Clear canvas on mode switch ──
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().remove();
  }, [explorerMode]);

  const isEmpty = explorerMode
    ? !neighborhood || neighborhood.nodes.length === 0
    : !subgraph || subgraph.nodes.length === 0;

  return (
    <div className="panel panel-center">
      <div
        ref={containerRef}
        style={{ width: "100%", height: "100%", position: "absolute", top: 0, left: 0 }}
      />
      {isEmpty && (
        <div className="watermark">GRAPH HUNTER</div>
      )}
    </div>
  );
}
