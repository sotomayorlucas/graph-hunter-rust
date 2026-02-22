// ── Types mirroring the Rust backend ──

export const ENTITY_TYPES = ["IP", "Host", "User", "Process", "File", "Domain"] as const;
export type EntityType = (typeof ENTITY_TYPES)[number];

export const RELATION_TYPES = ["Auth", "Connect", "Execute", "Read", "Write", "DNS"] as const;
export type RelationType = (typeof RELATION_TYPES)[number];

export interface HypothesisStep {
  origin_type: EntityType;
  relation_type: RelationType;
  dest_type: EntityType;
}

export interface Hypothesis {
  name: string;
  steps: HypothesisStep[];
}

// ── Backend response types ──

export interface GraphStats {
  entity_count: number;
  relation_count: number;
}

export interface LoadResult {
  new_entities: number;
  new_relations: number;
  total_entities: number;
  total_relations: number;
}

export interface HuntResults {
  paths: string[][];
  path_count: number;
}

export interface SubgraphNode {
  id: string;
  entity_type: string;
  score: number;
  metadata: Record<string, string>;
}

export interface SubgraphEdge {
  source: string;
  target: string;
  rel_type: string;
  timestamp: number;
  metadata: Record<string, string>;
}

export interface Subgraph {
  nodes: SubgraphNode[];
  edges: SubgraphEdge[];
}

// ── Color mapping for entity types ──

export const ENTITY_COLORS: Record<EntityType, string> = {
  IP: "#ff6b6b",
  Host: "#4ecdc4",
  User: "#45b7d1",
  Process: "#f9ca24",
  File: "#a29bfe",
  Domain: "#fd79a8",
};

// ── Explorer mode types ──

export interface SearchResult {
  id: string;
  entity_type: string;
  score: number;
  connections: number;
}

export interface NeighborNode {
  id: string;
  entity_type: string;
  score: number;
  metadata: Record<string, string>;
}

export interface NeighborEdge {
  source: string;
  target: string;
  rel_type: string;
  timestamp: number;
  metadata: Record<string, string>;
}

export interface Neighborhood {
  center: string;
  nodes: NeighborNode[];
  edges: NeighborEdge[];
  truncated: boolean;
}

export interface NodeDetails {
  id: string;
  entity_type: string;
  score: number;
  metadata: Record<string, string>;
  in_degree: number;
  out_degree: number;
  time_range: [number, number] | null;
  neighbor_types: Record<string, number>;
}

export interface TypeDistribution {
  entity_type: string;
  count: number;
}

export interface TopAnomaly {
  id: string;
  entity_type: string;
  score: number;
}

export interface GraphSummary {
  entity_count: number;
  relation_count: number;
  type_distribution: TypeDistribution[];
  time_range: [number, number] | null;
  top_anomalies: TopAnomaly[];
}

export interface ExpandFilter {
  entity_types?: string[];
  relation_types?: string[];
  time_start?: number;
  time_end?: number;
  min_score?: number;
}

// ── Status log entry ──

export interface LogEntry {
  time: string;
  message: string;
  level: "info" | "success" | "error";
}
