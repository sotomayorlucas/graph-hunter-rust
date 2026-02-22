use std::collections::{HashMap, HashSet};

use crate::entity::Entity;
use crate::errors::GraphError;
use crate::hypothesis::Hypothesis;
use crate::relation::Relation;
use crate::types::EntityType;

/// Result of a successful pattern match: an ordered list of entity IDs
/// representing the attack path through the graph.
pub type HuntResult = Vec<String>;

/// The core threat hunting graph engine.
///
/// Stores entities in a HashMap (arena-style by ID) and relations in an
/// adjacency list keyed by source entity ID. This avoids all borrow checker
/// complexity while enabling O(1) entity lookups and efficient edge traversal.
pub struct GraphHunter {
    pub entities: HashMap<String, Entity>,
    pub adjacency_list: HashMap<String, Vec<Relation>>,
    /// Index: entity type → set of entity IDs of that type.
    pub type_index: HashMap<EntityType, HashSet<String>>,
    /// Reverse adjacency: dest_id → vec of source_ids that have edges pointing to it.
    pub reverse_adj: HashMap<String, Vec<String>>,
}

impl GraphHunter {
    /// Creates a new empty graph.
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
            adjacency_list: HashMap::new(),
            type_index: HashMap::new(),
            reverse_adj: HashMap::new(),
        }
    }

    /// Returns the number of entities (nodes) in the graph.
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    /// Returns the total number of relations (edges) in the graph.
    pub fn relation_count(&self) -> usize {
        self.adjacency_list.values().map(|edges| edges.len()).sum()
    }

    /// Adds an entity to the graph.
    /// Returns an error if an entity with the same ID already exists.
    pub fn add_entity(&mut self, entity: Entity) -> Result<(), GraphError> {
        if self.entities.contains_key(&entity.id) {
            return Err(GraphError::DuplicateEntity(entity.id.clone()));
        }
        let id = entity.id.clone();
        self.type_index
            .entry(entity.entity_type.clone())
            .or_default()
            .insert(id.clone());
        self.entities.insert(id.clone(), entity);
        self.adjacency_list.entry(id.clone()).or_default();
        self.reverse_adj.entry(id).or_default();
        Ok(())
    }

    /// Adds a relation (directed edge) to the graph.
    /// Returns an error if either the source or destination entity does not exist.
    pub fn add_relation(&mut self, relation: Relation) -> Result<(), GraphError> {
        if !self.entities.contains_key(&relation.source_id) {
            return Err(GraphError::EntityNotFound(relation.source_id.clone()));
        }
        if !self.entities.contains_key(&relation.dest_id) {
            return Err(GraphError::EntityNotFound(relation.dest_id.clone()));
        }
        self.reverse_adj
            .entry(relation.dest_id.clone())
            .or_default()
            .push(relation.source_id.clone());
        self.adjacency_list
            .entry(relation.source_id.clone())
            .or_default()
            .push(relation);
        Ok(())
    }

    /// Retrieves an entity by its ID.
    pub fn get_entity(&self, id: &str) -> Option<&Entity> {
        self.entities.get(id)
    }

    /// Retrieves all outgoing relations from a given entity.
    pub fn get_relations(&self, source_id: &str) -> &[Relation] {
        self.adjacency_list
            .get(source_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Searches for all paths in the graph that match a temporal hypothesis pattern.
    ///
    /// # Algorithm
    /// Recursive DFS with backtracking. At each step:
    /// 1. **Type pruning**: Only follow edges whose `rel_type` matches the step's `relation_type`
    ///    and whose destination entity's `entity_type` matches the step's `dest_type`.
    /// 2. **Causal monotonicity**: The timestamp of relation N+1 must be >= timestamp of relation N.
    /// 3. **Time window**: If provided, only consider relations within `[start, end]` inclusive.
    /// 4. **Cycle avoidance**: A `HashSet<&str>` tracks visited nodes in the current path.
    ///
    /// # Returns
    /// A `Vec<Vec<String>>` where each inner vec is an ordered sequence of entity IDs
    /// forming a complete match of the hypothesis.
    pub fn search_temporal_pattern(
        &self,
        hypothesis: &Hypothesis,
        time_window: Option<(i64, i64)>,
    ) -> Result<Vec<HuntResult>, GraphError> {
        hypothesis
            .validate()
            .map_err(GraphError::InvalidHypothesis)?;

        let mut results: Vec<HuntResult> = Vec::new();

        // Find all candidate starting nodes matching the first step's origin_type.
        // Uses type_index for O(1) lookup instead of scanning all entities.
        let first_step = &hypothesis.steps[0];
        let start_nodes: Vec<&str> = self
            .type_index
            .get(&first_step.origin_type)
            .map(|ids| ids.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default();

        for start_id in start_nodes {
            let mut visited = HashSet::new();
            visited.insert(start_id);
            let mut path = vec![start_id.to_string()];

            self.dfs_match(
                start_id,
                &hypothesis.steps,
                0,            // current step index
                i64::MIN,     // last timestamp (no constraint for first edge)
                time_window,
                &mut visited,
                &mut path,
                &mut results,
            );
        }

        Ok(results)
    }

    /// Recursive DFS core. Tries to extend `path` by matching `steps[step_idx]`.
    fn dfs_match<'a>(
        &'a self,
        current_node: &str,
        steps: &[crate::hypothesis::HypothesisStep],
        step_idx: usize,
        last_timestamp: i64,
        time_window: Option<(i64, i64)>,
        visited: &mut HashSet<&'a str>,
        path: &mut Vec<String>,
        results: &mut Vec<HuntResult>,
    ) {
        // Base case: all steps matched — we have a complete path.
        if step_idx >= steps.len() {
            results.push(path.clone());
            return;
        }

        let step = &steps[step_idx];
        let edges = self.get_relations(current_node);

        for edge in edges {
            // ── Pruning checks ──

            // 1. Relation type must match the hypothesis step.
            if edge.rel_type != step.relation_type {
                continue;
            }

            // 2. Destination entity must exist and match the expected type.
            let dest_entity = match self.entities.get(&edge.dest_id) {
                Some(e) if e.entity_type == step.dest_type => e,
                _ => continue,
            };

            // 3. Causal monotonicity: this edge must be >= the previous edge's timestamp.
            if edge.timestamp < last_timestamp {
                continue;
            }

            // 4. Time window filter (if specified).
            if let Some((tw_start, tw_end)) = time_window {
                if edge.timestamp < tw_start || edge.timestamp > tw_end {
                    continue;
                }
            }

            // 5. Cycle avoidance: skip if we've already visited this node in the current path.
            let dest_id_str = dest_entity.id.as_str();
            if visited.contains(dest_id_str) {
                continue;
            }

            // ── Recurse ──
            visited.insert(dest_id_str);
            path.push(dest_entity.id.clone());

            self.dfs_match(
                dest_id_str,
                steps,
                step_idx + 1,
                edge.timestamp,
                time_window,
                visited,
                path,
                results,
            );

            // ── Backtrack ──
            path.pop();
            visited.remove(dest_id_str);
        }
    }

    /// Ingests raw log data using the provided parser.
    ///
    /// Entities are deduplicated by ID: if an entity already exists, its metadata
    /// is merged (new keys are added, existing keys are preserved).
    /// All relations are always inserted (edges are never deduplicated, since
    /// the same source→dest pair can have multiple events at different timestamps).
    ///
    /// Returns the count of (new_entities, new_relations) inserted.
    pub fn ingest_logs<P: crate::parser::LogParser>(
        &mut self,
        logs: &str,
        parser: &P,
    ) -> (usize, usize) {
        let triples = parser.parse(logs);
        let mut new_entities = 0usize;
        let mut new_relations = 0usize;

        for (src, rel, dst) in triples {
            // Upsert source entity
            if let Some(existing) = self.entities.get_mut(&src.id) {
                // Merge metadata: add new keys only
                for (k, v) in &src.metadata {
                    existing.metadata.entry(k.clone()).or_insert_with(|| v.clone());
                }
            } else {
                let id = src.id.clone();
                self.type_index
                    .entry(src.entity_type.clone())
                    .or_default()
                    .insert(id.clone());
                self.entities.insert(id.clone(), src);
                self.adjacency_list.entry(id.clone()).or_default();
                self.reverse_adj.entry(id).or_default();
                new_entities += 1;
            }

            // Upsert destination entity
            if let Some(existing) = self.entities.get_mut(&dst.id) {
                for (k, v) in &dst.metadata {
                    existing.metadata.entry(k.clone()).or_insert_with(|| v.clone());
                }
            } else {
                let id = dst.id.clone();
                self.type_index
                    .entry(dst.entity_type.clone())
                    .or_default()
                    .insert(id.clone());
                self.entities.insert(id.clone(), dst);
                self.adjacency_list.entry(id.clone()).or_default();
                self.reverse_adj.entry(id).or_default();
                new_entities += 1;
            }

            // Always insert relation
            self.reverse_adj
                .entry(rel.dest_id.clone())
                .or_default()
                .push(rel.source_id.clone());
            self.adjacency_list
                .entry(rel.source_id.clone())
                .or_default()
                .push(rel);
            new_relations += 1;
        }

        (new_entities, new_relations)
    }
}

impl Default for GraphHunter {
    fn default() -> Self {
        Self::new()
    }
}
