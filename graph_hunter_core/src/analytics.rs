use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::graph::GraphHunter;
use crate::types::{EntityType, RelationType};

// ── Serializable structs ──

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NeighborhoodFilter {
    pub entity_types: Option<Vec<EntityType>>,
    pub relation_types: Option<Vec<RelationType>>,
    pub time_start: Option<i64>,
    pub time_end: Option<i64>,
    pub min_score: Option<f64>,
}

#[derive(Serialize, Clone, Debug)]
pub struct NeighborNode {
    pub id: String,
    pub entity_type: String,
    pub score: f64,
    pub metadata: HashMap<String, String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct NeighborEdge {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub timestamp: i64,
    pub metadata: HashMap<String, String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Neighborhood {
    pub center: String,
    pub nodes: Vec<NeighborNode>,
    pub edges: Vec<NeighborEdge>,
    pub truncated: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct SearchResult {
    pub id: String,
    pub entity_type: String,
    pub score: f64,
    pub connections: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct NodeDetails {
    pub id: String,
    pub entity_type: String,
    pub score: f64,
    pub metadata: HashMap<String, String>,
    pub in_degree: usize,
    pub out_degree: usize,
    pub time_range: Option<(i64, i64)>,
    pub neighbor_types: HashMap<String, usize>,
}

#[derive(Serialize, Clone, Debug)]
pub struct TypeDistribution {
    pub entity_type: String,
    pub count: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct TopAnomaly {
    pub id: String,
    pub entity_type: String,
    pub score: f64,
}

#[derive(Serialize, Clone, Debug)]
pub struct GraphSummary {
    pub entity_count: usize,
    pub relation_count: usize,
    pub type_distribution: Vec<TypeDistribution>,
    pub time_range: Option<(i64, i64)>,
    pub top_anomalies: Vec<TopAnomaly>,
}

// ── Implementations on GraphHunter ──

impl GraphHunter {
    /// Searches entities by substring match on ID (case-insensitive).
    /// Optionally filters by entity type. Returns up to `limit` results.
    pub fn search_entities(
        &self,
        query: &str,
        type_filter: Option<&EntityType>,
        limit: usize,
    ) -> Vec<SearchResult> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        // If type_filter is specified, use type_index for fast lookup
        let candidate_ids: Box<dyn Iterator<Item = &String>> = match type_filter {
            Some(et) => {
                if let Some(ids) = self.type_index.get(et) {
                    Box::new(ids.iter())
                } else {
                    return results;
                }
            }
            None => Box::new(self.entities.keys()),
        };

        for id in candidate_ids {
            if results.len() >= limit {
                break;
            }
            if id.to_lowercase().contains(&query_lower) {
                if let Some(entity) = self.entities.get(id) {
                    let out_degree = self
                        .adjacency_list
                        .get(id)
                        .map(|v| v.len())
                        .unwrap_or(0);
                    let in_degree = self
                        .reverse_adj
                        .get(id)
                        .map(|v| v.len())
                        .unwrap_or(0);
                    results.push(SearchResult {
                        id: entity.id.clone(),
                        entity_type: format!("{}", entity.entity_type),
                        score: entity.score,
                        connections: out_degree + in_degree,
                    });
                }
            }
        }

        results
    }

    /// BFS-based neighborhood expansion from a center node.
    /// Explores both outgoing (adjacency_list) and incoming (reverse_adj) edges.
    /// Caps at max_nodes to prevent explosion. Supports filtering.
    pub fn get_neighborhood(
        &self,
        center: &str,
        max_hops: usize,
        max_nodes: usize,
        filter: Option<&NeighborhoodFilter>,
    ) -> Option<Neighborhood> {
        if !self.entities.contains_key(center) {
            return None;
        }

        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        let mut node_ids: Vec<String> = Vec::new();
        let mut edges: Vec<NeighborEdge> = Vec::new();
        let mut truncated = false;

        visited.insert(center.to_string());
        queue.push_back((center.to_string(), 0));
        node_ids.push(center.to_string());

        while let Some((current_id, depth)) = queue.pop_front() {
            if depth >= max_hops {
                continue;
            }

            // Outgoing edges
            if let Some(rels) = self.adjacency_list.get(&current_id) {
                for rel in rels {
                    if !self.passes_filter(rel, &rel.dest_id, filter) {
                        continue;
                    }
                    let edge = NeighborEdge {
                        source: rel.source_id.clone(),
                        target: rel.dest_id.clone(),
                        rel_type: format!("{}", rel.rel_type),
                        timestamp: rel.timestamp,
                        metadata: rel.metadata.clone(),
                    };

                    if !visited.contains(&rel.dest_id) {
                        if node_ids.len() >= max_nodes {
                            truncated = true;
                            continue;
                        }
                        visited.insert(rel.dest_id.clone());
                        node_ids.push(rel.dest_id.clone());
                        queue.push_back((rel.dest_id.clone(), depth + 1));
                    }

                    // Add edge if both endpoints are in the neighborhood
                    if visited.contains(&rel.dest_id) {
                        edges.push(edge);
                    }
                }
            }

            // Incoming edges (via reverse_adj)
            if let Some(sources) = self.reverse_adj.get(&current_id) {
                for source_id in sources {
                    // Get the actual relation(s) from source_id to current_id
                    if let Some(rels) = self.adjacency_list.get(source_id) {
                        for rel in rels {
                            if rel.dest_id != current_id {
                                continue;
                            }
                            if !self.passes_filter(rel, source_id, filter) {
                                continue;
                            }

                            if !visited.contains(source_id) {
                                if node_ids.len() >= max_nodes {
                                    truncated = true;
                                    continue;
                                }
                                visited.insert(source_id.clone());
                                node_ids.push(source_id.clone());
                                queue.push_back((source_id.clone(), depth + 1));
                            }

                            if visited.contains(source_id) {
                                edges.push(NeighborEdge {
                                    source: rel.source_id.clone(),
                                    target: rel.dest_id.clone(),
                                    rel_type: format!("{}", rel.rel_type),
                                    timestamp: rel.timestamp,
                                    metadata: rel.metadata.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Deduplicate edges (same source-target-timestamp can appear from both directions)
        let mut seen_edges: HashSet<(String, String, i64)> = HashSet::new();
        edges.retain(|e| seen_edges.insert((e.source.clone(), e.target.clone(), e.timestamp)));

        // Build node list
        let nodes: Vec<NeighborNode> = node_ids
            .iter()
            .filter_map(|id| {
                self.entities.get(id).map(|e| NeighborNode {
                    id: e.id.clone(),
                    entity_type: format!("{}", e.entity_type),
                    score: e.score,
                    metadata: e.metadata.clone(),
                })
            })
            .collect();

        Some(Neighborhood {
            center: center.to_string(),
            nodes,
            edges,
            truncated,
        })
    }

    /// Checks whether a relation and its neighbor node pass the given filter.
    fn passes_filter(
        &self,
        rel: &crate::relation::Relation,
        neighbor_id: &str,
        filter: Option<&NeighborhoodFilter>,
    ) -> bool {
        let filter = match filter {
            Some(f) => f,
            None => return true,
        };

        // Filter by relation type
        if let Some(ref rel_types) = filter.relation_types {
            if !rel_types.contains(&rel.rel_type) {
                return false;
            }
        }

        // Filter by time range
        if let Some(start) = filter.time_start {
            if rel.timestamp < start {
                return false;
            }
        }
        if let Some(end) = filter.time_end {
            if rel.timestamp > end {
                return false;
            }
        }

        // Filter by entity type of neighbor
        if let Some(ref entity_types) = filter.entity_types {
            if let Some(entity) = self.entities.get(neighbor_id) {
                if !entity_types.contains(&entity.entity_type) {
                    return false;
                }
            }
        }

        // Filter by min score of neighbor
        if let Some(min_score) = filter.min_score {
            if let Some(entity) = self.entities.get(neighbor_id) {
                if entity.score < min_score {
                    return false;
                }
            }
        }

        true
    }

    /// Computes degree centrality scores for all entities.
    /// Score = normalized total degree (in + out) as percentage [0, 100].
    pub fn compute_scores(&mut self) {
        if self.entities.is_empty() {
            return;
        }

        // Compute degrees
        let mut degrees: HashMap<&str, usize> = HashMap::new();
        let mut max_degree: usize = 0;

        for (id, rels) in &self.adjacency_list {
            let out_deg = rels.len();
            *degrees.entry(id.as_str()).or_default() += out_deg;
        }
        for (id, sources) in &self.reverse_adj {
            *degrees.entry(id.as_str()).or_default() += sources.len();
        }

        for &deg in degrees.values() {
            if deg > max_degree {
                max_degree = deg;
            }
        }

        // Normalize to [0, 100]
        if max_degree == 0 {
            return;
        }

        for (id, entity) in &mut self.entities {
            let deg = degrees.get(id.as_str()).copied().unwrap_or(0);
            entity.score = (deg as f64 / max_degree as f64) * 100.0;
        }
    }

    /// Returns detailed information about a specific node.
    pub fn get_node_details(&self, node_id: &str) -> Option<NodeDetails> {
        let entity = self.entities.get(node_id)?;

        let out_degree = self
            .adjacency_list
            .get(node_id)
            .map(|v| v.len())
            .unwrap_or(0);
        let in_degree = self
            .reverse_adj
            .get(node_id)
            .map(|v| v.len())
            .unwrap_or(0);

        // Compute time range from all edges touching this node
        let mut min_ts = i64::MAX;
        let mut max_ts = i64::MIN;
        let mut has_timestamps = false;

        if let Some(rels) = self.adjacency_list.get(node_id) {
            for rel in rels {
                if rel.timestamp != 0 {
                    min_ts = min_ts.min(rel.timestamp);
                    max_ts = max_ts.max(rel.timestamp);
                    has_timestamps = true;
                }
            }
        }
        if let Some(sources) = self.reverse_adj.get(node_id) {
            for source_id in sources {
                if let Some(rels) = self.adjacency_list.get(source_id) {
                    for rel in rels {
                        if rel.dest_id == node_id && rel.timestamp != 0 {
                            min_ts = min_ts.min(rel.timestamp);
                            max_ts = max_ts.max(rel.timestamp);
                            has_timestamps = true;
                        }
                    }
                }
            }
        }

        // Build neighbor type breakdown
        let mut neighbor_types: HashMap<String, usize> = HashMap::new();

        if let Some(rels) = self.adjacency_list.get(node_id) {
            for rel in rels {
                if let Some(dest) = self.entities.get(&rel.dest_id) {
                    *neighbor_types
                        .entry(format!("{}", dest.entity_type))
                        .or_default() += 1;
                }
            }
        }
        if let Some(sources) = self.reverse_adj.get(node_id) {
            for source_id in sources {
                if let Some(src) = self.entities.get(source_id) {
                    *neighbor_types
                        .entry(format!("{}", src.entity_type))
                        .or_default() += 1;
                }
            }
        }

        Some(NodeDetails {
            id: entity.id.clone(),
            entity_type: format!("{}", entity.entity_type),
            score: entity.score,
            metadata: entity.metadata.clone(),
            in_degree,
            out_degree,
            time_range: if has_timestamps {
                Some((min_ts, max_ts))
            } else {
                None
            },
            neighbor_types,
        })
    }

    /// Returns a summary of the entire graph.
    pub fn get_graph_summary(&self) -> GraphSummary {
        // Type distribution
        let mut type_distribution: Vec<TypeDistribution> = self
            .type_index
            .iter()
            .map(|(et, ids)| TypeDistribution {
                entity_type: format!("{}", et),
                count: ids.len(),
            })
            .collect();
        type_distribution.sort_by(|a, b| b.count.cmp(&a.count));

        // Global time range
        let mut min_ts = i64::MAX;
        let mut max_ts = i64::MIN;
        let mut has_timestamps = false;

        for rels in self.adjacency_list.values() {
            for rel in rels {
                if rel.timestamp != 0 {
                    min_ts = min_ts.min(rel.timestamp);
                    max_ts = max_ts.max(rel.timestamp);
                    has_timestamps = true;
                }
            }
        }

        // Top anomalies (highest score entities)
        let mut entities_by_score: Vec<_> = self.entities.values().collect();
        entities_by_score.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        let top_anomalies: Vec<TopAnomaly> = entities_by_score
            .into_iter()
            .take(10)
            .filter(|e| e.score > 0.0)
            .map(|e| TopAnomaly {
                id: e.id.clone(),
                entity_type: format!("{}", e.entity_type),
                score: e.score,
            })
            .collect();

        GraphSummary {
            entity_count: self.entity_count(),
            relation_count: self.relation_count(),
            type_distribution,
            time_range: if has_timestamps {
                Some((min_ts, max_ts))
            } else {
                None
            },
            top_anomalies,
        }
    }
}
