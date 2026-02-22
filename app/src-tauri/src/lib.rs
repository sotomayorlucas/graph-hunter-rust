use std::sync::RwLock;

use graph_hunter_core::{
    EntityType, GraphHunter, Hypothesis, NeighborhoodFilter, SentinelJsonParser,
    SysmonJsonParser,
};
use serde::{Deserialize, Serialize};
use tauri::State;

/// Global application state holding the graph engine behind a RwLock.
///
/// RwLock allows concurrent reads (stats, subgraph queries) while
/// exclusive writes (data loading) block readers momentarily.
pub struct AppState {
    pub graph: RwLock<GraphHunter>,
}

// ── Serializable response types for the frontend ──

#[derive(Serialize)]
pub struct GraphStats {
    pub entity_count: usize,
    pub relation_count: usize,
}

#[derive(Serialize)]
pub struct LoadResult {
    pub new_entities: usize,
    pub new_relations: usize,
    pub total_entities: usize,
    pub total_relations: usize,
}

#[derive(Serialize)]
pub struct HuntResults {
    pub paths: Vec<Vec<String>>,
    pub path_count: usize,
}

#[derive(Serialize)]
pub struct SubgraphNode {
    pub id: String,
    pub entity_type: String,
    pub score: f64,
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
pub struct SubgraphEdge {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub timestamp: i64,
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
pub struct Subgraph {
    pub nodes: Vec<SubgraphNode>,
    pub edges: Vec<SubgraphEdge>,
}

/// Filter struct received from the frontend for neighborhood expansion.
#[derive(Deserialize, Default)]
pub struct ExpandFilter {
    pub entity_types: Option<Vec<String>>,
    pub relation_types: Option<Vec<String>>,
    pub time_start: Option<i64>,
    pub time_end: Option<i64>,
    pub min_score: Option<f64>,
}

/// Converts a string like "IP", "Host", etc. to EntityType.
fn parse_entity_type(s: &str) -> Option<EntityType> {
    match s {
        "IP" => Some(EntityType::IP),
        "Host" => Some(EntityType::Host),
        "User" => Some(EntityType::User),
        "Process" => Some(EntityType::Process),
        "File" => Some(EntityType::File),
        "Domain" => Some(EntityType::Domain),
        _ => None,
    }
}

/// Converts a string to RelationType.
fn parse_relation_type(s: &str) -> Option<graph_hunter_core::RelationType> {
    match s {
        "Auth" => Some(graph_hunter_core::RelationType::Auth),
        "Connect" => Some(graph_hunter_core::RelationType::Connect),
        "Execute" => Some(graph_hunter_core::RelationType::Execute),
        "Read" => Some(graph_hunter_core::RelationType::Read),
        "Write" => Some(graph_hunter_core::RelationType::Write),
        "DNS" => Some(graph_hunter_core::RelationType::DNS),
        _ => None,
    }
}

/// Converts frontend ExpandFilter to core NeighborhoodFilter.
fn to_core_filter(f: &ExpandFilter) -> NeighborhoodFilter {
    NeighborhoodFilter {
        entity_types: f.entity_types.as_ref().map(|types| {
            types.iter().filter_map(|s| parse_entity_type(s)).collect()
        }),
        relation_types: f.relation_types.as_ref().map(|types| {
            types
                .iter()
                .filter_map(|s| parse_relation_type(s))
                .collect()
        }),
        time_start: f.time_start,
        time_end: f.time_end,
        min_score: f.min_score,
    }
}

// ── Tauri Commands ──

/// Reads a file from disk and ingests its log events into the graph.
/// Auto-computes scores after loading.
#[tauri::command]
fn cmd_load_data(
    state: State<AppState>,
    path: String,
    format: String,
) -> Result<LoadResult, String> {
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;

    let mut graph = state
        .graph
        .write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    let (new_entities, new_relations) = match format.to_lowercase().as_str() {
        "sysmon" => graph.ingest_logs(&contents, &SysmonJsonParser),
        "sentinel" => graph.ingest_logs(&contents, &SentinelJsonParser),
        other => return Err(format!("Unsupported format: '{}'. Use 'sysmon' or 'sentinel'.", other)),
    };

    // Auto-compute scores after loading
    graph.compute_scores();

    Ok(LoadResult {
        new_entities,
        new_relations,
        total_entities: graph.entity_count(),
        total_relations: graph.relation_count(),
    })
}

/// Returns current graph statistics (node and edge counts).
#[tauri::command]
fn cmd_get_graph_stats(state: State<AppState>) -> Result<GraphStats, String> {
    let graph = state
        .graph
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    Ok(GraphStats {
        entity_count: graph.entity_count(),
        relation_count: graph.relation_count(),
    })
}

/// Executes a temporal pattern search using the provided hypothesis.
#[tauri::command]
fn cmd_run_hunt(
    state: State<AppState>,
    hypothesis_json: String,
    time_window: Option<(i64, i64)>,
) -> Result<HuntResults, String> {
    let hypothesis: Hypothesis = serde_json::from_str(&hypothesis_json)
        .map_err(|e| format!("Invalid hypothesis JSON: {}", e))?;

    let graph = state
        .graph
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    let paths = graph
        .search_temporal_pattern(&hypothesis, time_window)
        .map_err(|e| format!("Search failed: {}", e))?;

    let path_count = paths.len();
    Ok(HuntResults { paths, path_count })
}

/// Returns the complete subgraph (nodes + edges) for the given entity IDs.
#[tauri::command]
fn cmd_get_subgraph(
    state: State<AppState>,
    node_ids: Vec<String>,
) -> Result<Subgraph, String> {
    let graph = state
        .graph
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    let id_set: std::collections::HashSet<&str> =
        node_ids.iter().map(|s| s.as_str()).collect();

    let nodes: Vec<SubgraphNode> = node_ids
        .iter()
        .filter_map(|id| graph.get_entity(id))
        .map(|e| SubgraphNode {
            id: e.id.clone(),
            entity_type: format!("{}", e.entity_type),
            score: e.score,
            metadata: e.metadata.clone(),
        })
        .collect();

    let mut edges: Vec<SubgraphEdge> = Vec::new();
    for source_id in &node_ids {
        for rel in graph.get_relations(source_id) {
            if id_set.contains(rel.dest_id.as_str()) {
                edges.push(SubgraphEdge {
                    source: rel.source_id.clone(),
                    target: rel.dest_id.clone(),
                    rel_type: format!("{}", rel.rel_type),
                    timestamp: rel.timestamp,
                    metadata: rel.metadata.clone(),
                });
            }
        }
    }

    Ok(Subgraph { nodes, edges })
}

/// Searches entities by substring match. Used for IOC search in Explorer mode.
#[tauri::command]
fn cmd_search_entities(
    state: State<AppState>,
    query: String,
    type_filter: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<graph_hunter_core::SearchResult>, String> {
    let graph = state
        .graph
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    let et = type_filter.as_deref().and_then(parse_entity_type);
    let results = graph.search_entities(&query, et.as_ref(), limit.unwrap_or(50));
    Ok(results)
}

/// Expands a node's neighborhood for interactive exploration.
#[tauri::command]
fn cmd_expand_node(
    state: State<AppState>,
    node_id: String,
    max_hops: Option<usize>,
    max_nodes: Option<usize>,
    filter: Option<ExpandFilter>,
) -> Result<graph_hunter_core::Neighborhood, String> {
    let graph = state
        .graph
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    let core_filter = filter.as_ref().map(to_core_filter);
    graph
        .get_neighborhood(
            &node_id,
            max_hops.unwrap_or(1),
            max_nodes.unwrap_or(50),
            core_filter.as_ref(),
        )
        .ok_or_else(|| format!("Entity not found: {}", node_id))
}

/// Returns detailed information about a specific node.
#[tauri::command]
fn cmd_get_node_details(
    state: State<AppState>,
    node_id: String,
) -> Result<graph_hunter_core::NodeDetails, String> {
    let graph = state
        .graph
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    graph
        .get_node_details(&node_id)
        .ok_or_else(|| format!("Entity not found: {}", node_id))
}

/// Returns a summary of the entire graph.
#[tauri::command]
fn cmd_get_graph_summary(
    state: State<AppState>,
) -> Result<graph_hunter_core::GraphSummary, String> {
    let graph = state
        .graph
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    Ok(graph.get_graph_summary())
}

/// Recalculates scores for all entities.
#[tauri::command]
fn cmd_compute_scores(state: State<AppState>) -> Result<(), String> {
    let mut graph = state
        .graph
        .write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    graph.compute_scores();
    Ok(())
}

/// Entry point for the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            graph: RwLock::new(GraphHunter::new()),
        })
        .invoke_handler(tauri::generate_handler![
            cmd_load_data,
            cmd_get_graph_stats,
            cmd_run_hunt,
            cmd_get_subgraph,
            cmd_search_entities,
            cmd_expand_node,
            cmd_get_node_details,
            cmd_get_graph_summary,
            cmd_compute_scores,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Graph Hunter");
}
