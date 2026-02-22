pub mod analytics;
pub mod types;
pub mod entity;
pub mod errors;
pub mod graph;
pub mod hypothesis;
pub mod parser;
pub mod relation;
pub mod sentinel;
pub mod sysmon;

// Re-export core types at crate root for ergonomic imports.
pub use analytics::{
    GraphSummary, Neighborhood, NeighborhoodFilter, NeighborNode, NeighborEdge,
    NodeDetails, SearchResult, TopAnomaly, TypeDistribution,
};
pub use entity::Entity;
pub use errors::GraphError;
pub use graph::GraphHunter;
pub use hypothesis::{Hypothesis, HypothesisStep};
pub use parser::{LogParser, ParsedTriple};
pub use relation::Relation;
pub use sentinel::SentinelJsonParser;
pub use sysmon::SysmonJsonParser;
pub use types::{EntityType, RelationType};

#[cfg(test)]
mod tests {
    use super::*;

    // ── Entity Tests ──

    #[test]
    fn entity_creation_default() {
        let e = Entity::new("192.168.1.1", EntityType::IP);
        assert_eq!(e.id, "192.168.1.1");
        assert_eq!(e.entity_type, EntityType::IP);
        assert_eq!(e.score, 0.0);
        assert!(e.metadata.is_empty());
    }

    #[test]
    fn entity_with_score() {
        let e = Entity::with_score("malware.exe", EntityType::File, 95.0);
        assert_eq!(e.score, 95.0);
    }

    #[test]
    fn entity_builder_metadata() {
        let e = Entity::new("10.0.0.1", EntityType::IP)
            .with_metadata("geo", "US")
            .with_metadata("asn", "AS15169");
        assert_eq!(e.metadata.get("geo").unwrap(), "US");
        assert_eq!(e.metadata.get("asn").unwrap(), "AS15169");
    }

    #[test]
    fn entity_equality_by_id() {
        let e1 = Entity::new("host-1", EntityType::Host);
        let e2 = Entity::with_score("host-1", EntityType::Host, 50.0);
        assert_eq!(e1, e2); // Same ID = equal, regardless of score
    }

    // ── Relation Tests ──

    #[test]
    fn relation_creation() {
        let r = Relation::new("10.0.0.1", "server-1", RelationType::Connect, 1700000000);
        assert_eq!(r.source_id, "10.0.0.1");
        assert_eq!(r.dest_id, "server-1");
        assert_eq!(r.rel_type, RelationType::Connect);
        assert_eq!(r.timestamp, 1700000000);
    }

    #[test]
    fn relation_builder_metadata() {
        let r = Relation::new("user-admin", "cmd.exe", RelationType::Execute, 1700000100)
            .with_metadata("cmdline", "whoami")
            .with_metadata("pid", "4512");
        assert_eq!(r.metadata.get("cmdline").unwrap(), "whoami");
        assert_eq!(r.metadata.get("pid").unwrap(), "4512");
    }

    // ── Hypothesis Tests ──

    #[test]
    fn hypothesis_builder() {
        let h = Hypothesis::new("Lateral Movement")
            .add_step(HypothesisStep::new(
                EntityType::IP,
                RelationType::Connect,
                EntityType::Host,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Auth,
                EntityType::User,
            ))
            .add_step(HypothesisStep::new(
                EntityType::User,
                RelationType::Execute,
                EntityType::Process,
            ));

        assert_eq!(h.name, "Lateral Movement");
        assert_eq!(h.len(), 3);
        assert!(!h.is_empty());
    }

    #[test]
    fn hypothesis_validation_ok() {
        let h = Hypothesis::new("DNS Exfil")
            .add_step(HypothesisStep::new(
                EntityType::Process,
                RelationType::DNS,
                EntityType::Domain,
            ));
        assert!(h.validate().is_ok());
    }

    #[test]
    fn hypothesis_validation_chained_ok() {
        let h = Hypothesis::new("Full Kill Chain")
            .add_step(HypothesisStep::new(
                EntityType::IP,
                RelationType::Connect,
                EntityType::Host,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Auth,
                EntityType::User,
            ));
        assert!(h.validate().is_ok());
    }

    #[test]
    fn hypothesis_validation_type_mismatch() {
        let h = Hypothesis::new("Bad Chain")
            .add_step(HypothesisStep::new(
                EntityType::IP,
                RelationType::Connect,
                EntityType::Host,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Process, // Mismatch: previous step ends with Host
                RelationType::Execute,
                EntityType::File,
            ));
        assert!(h.validate().is_err());
    }

    #[test]
    fn hypothesis_validation_empty() {
        let h = Hypothesis::new("Empty");
        assert!(h.validate().is_err());
    }

    // ── Serialization Round-Trip Tests ──

    #[test]
    fn entity_serde_roundtrip() {
        let original = Entity::new("192.168.1.100", EntityType::IP)
            .with_metadata("reputation", "malicious");

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Entity = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, original.id);
        assert_eq!(deserialized.entity_type, original.entity_type);
        assert_eq!(
            deserialized.metadata.get("reputation").unwrap(),
            "malicious"
        );
    }

    #[test]
    fn relation_serde_roundtrip() {
        let original =
            Relation::new("attacker-ip", "victim-host", RelationType::Connect, 1700000000)
                .with_metadata("port", "445");

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Relation = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.source_id, "attacker-ip");
        assert_eq!(deserialized.dest_id, "victim-host");
        assert_eq!(deserialized.rel_type, RelationType::Connect);
        assert_eq!(deserialized.timestamp, 1700000000);
        assert_eq!(deserialized.metadata.get("port").unwrap(), "445");
    }

    #[test]
    fn hypothesis_serde_roundtrip() {
        let original = Hypothesis::new("Lateral Movement")
            .add_step(HypothesisStep::new(
                EntityType::IP,
                RelationType::Connect,
                EntityType::Host,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Auth,
                EntityType::User,
            ));

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Hypothesis = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name, "Lateral Movement");
        assert_eq!(deserialized.len(), 2);
        assert!(deserialized.validate().is_ok());
    }

    #[test]
    fn entity_type_display() {
        assert_eq!(format!("{}", EntityType::IP), "IP");
        assert_eq!(format!("{}", EntityType::Process), "Process");
    }

    #[test]
    fn relation_type_display() {
        assert_eq!(format!("{}", RelationType::DNS), "DNS");
        assert_eq!(format!("{}", RelationType::Execute), "Execute");
    }

    #[test]
    fn entity_hash_consistency() {
        use std::collections::HashSet;
        let e1 = Entity::new("node-1", EntityType::Host);
        let e2 = Entity::new("node-1", EntityType::Host);
        let mut set = HashSet::new();
        set.insert(e1);
        set.insert(e2);
        assert_eq!(set.len(), 1); // Deduplication by ID
    }

    #[test]
    fn hypothesis_json_structure() {
        let h = Hypothesis::new("Test")
            .add_step(HypothesisStep::new(
                EntityType::IP,
                RelationType::Connect,
                EntityType::Host,
            ));

        let json: serde_json::Value = serde_json::to_value(&h).unwrap();
        assert!(json["name"].is_string());
        assert!(json["steps"].is_array());
        assert_eq!(json["steps"].as_array().unwrap().len(), 1);

        let step = &json["steps"][0];
        assert_eq!(step["origin_type"], "IP");
        assert_eq!(step["relation_type"], "Connect");
        assert_eq!(step["dest_type"], "Host");
    }

    // ══════════════════════════════════════════════════
    // ── Phase 2: GraphHunter Engine Tests ──
    // ══════════════════════════════════════════════════

    /// Helper: builds a realistic lateral movement graph.
    ///
    /// Topology:
    /// ```text
    /// attacker-ip -[Connect@100]-> web-server -[Auth@200]-> admin-user -[Execute@300]-> cmd.exe -[Write@400]-> payload.dll
    /// ```
    fn build_lateral_movement_graph() -> GraphHunter {
        let mut g = GraphHunter::new();

        g.add_entity(Entity::new("attacker-ip", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("web-server", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("admin-user", EntityType::User)).unwrap();
        g.add_entity(Entity::new("cmd.exe", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("payload.dll", EntityType::File)).unwrap();

        g.add_relation(Relation::new("attacker-ip", "web-server", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("web-server", "admin-user", RelationType::Auth, 200)).unwrap();
        g.add_relation(Relation::new("admin-user", "cmd.exe", RelationType::Execute, 300)).unwrap();
        g.add_relation(Relation::new("cmd.exe", "payload.dll", RelationType::Write, 400)).unwrap();

        g
    }

    // ── Graph Construction Tests ──

    #[test]
    fn graph_new_is_empty() {
        let g = GraphHunter::new();
        assert_eq!(g.entity_count(), 0);
        assert_eq!(g.relation_count(), 0);
    }

    #[test]
    fn graph_add_entity_and_count() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("node-1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("node-2", EntityType::Host)).unwrap();
        assert_eq!(g.entity_count(), 2);
    }

    #[test]
    fn graph_duplicate_entity_error() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("dup", EntityType::IP)).unwrap();
        let err = g.add_entity(Entity::new("dup", EntityType::IP)).unwrap_err();
        assert_eq!(err, GraphError::DuplicateEntity("dup".into()));
    }

    #[test]
    fn graph_add_relation_validates_source() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("dest", EntityType::Host)).unwrap();
        let err = g
            .add_relation(Relation::new("ghost", "dest", RelationType::Connect, 100))
            .unwrap_err();
        assert_eq!(err, GraphError::EntityNotFound("ghost".into()));
    }

    #[test]
    fn graph_add_relation_validates_dest() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("src", EntityType::IP)).unwrap();
        let err = g
            .add_relation(Relation::new("src", "ghost", RelationType::Connect, 100))
            .unwrap_err();
        assert_eq!(err, GraphError::EntityNotFound("ghost".into()));
    }

    #[test]
    fn graph_relation_count() {
        let g = build_lateral_movement_graph();
        assert_eq!(g.entity_count(), 5);
        assert_eq!(g.relation_count(), 4);
    }

    #[test]
    fn graph_get_entity() {
        let g = build_lateral_movement_graph();
        let e = g.get_entity("web-server").unwrap();
        assert_eq!(e.entity_type, EntityType::Host);
    }

    #[test]
    fn graph_get_relations() {
        let g = build_lateral_movement_graph();
        let rels = g.get_relations("attacker-ip");
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].dest_id, "web-server");
    }

    #[test]
    fn graph_get_relations_empty() {
        let g = build_lateral_movement_graph();
        let rels = g.get_relations("payload.dll"); // leaf node, no outgoing
        assert!(rels.is_empty());
    }

    // ── Pattern Search: Positive Tests ──

    #[test]
    fn search_full_lateral_movement_chain() {
        let g = build_lateral_movement_graph();

        let hypothesis = Hypothesis::new("Lateral Movement")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User))
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0],
            vec!["attacker-ip", "web-server", "admin-user", "cmd.exe", "payload.dll"]
        );
    }

    #[test]
    fn search_partial_chain() {
        let g = build_lateral_movement_graph();

        // Only search for the first two steps: IP -> Connect -> Host -> Auth -> User
        let hypothesis = Hypothesis::new("Initial Access")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], vec!["attacker-ip", "web-server", "admin-user"]);
    }

    #[test]
    fn search_single_step() {
        let g = build_lateral_movement_graph();

        let hypothesis = Hypothesis::new("Connection")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], vec!["attacker-ip", "web-server"]);
    }

    // ── Pattern Search: Negative / Pruning Tests ──

    #[test]
    fn search_no_match_wrong_relation_type() {
        let g = build_lateral_movement_graph();

        // IP -> Auth (wrong: should be Connect) -> Host
        let hypothesis = Hypothesis::new("Wrong Relation")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Auth, EntityType::Host));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn search_no_match_wrong_dest_type() {
        let g = build_lateral_movement_graph();

        // IP -> Connect -> User (wrong: web-server is a Host, not User)
        let hypothesis = Hypothesis::new("Wrong Dest Type")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::User));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn search_invalid_hypothesis_returns_error() {
        let g = build_lateral_movement_graph();
        let hypothesis = Hypothesis::new("Empty");
        let err = g.search_temporal_pattern(&hypothesis, None).unwrap_err();
        assert!(matches!(err, GraphError::InvalidHypothesis(_)));
    }

    // ── Causal Monotonicity Tests ──

    #[test]
    fn search_enforces_causal_monotonicity() {
        let mut g = GraphHunter::new();

        g.add_entity(Entity::new("ip-1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("host-1", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("user-1", EntityType::User)).unwrap();

        // Connection at t=500, Auth at t=200 (BEFORE the connection — violates causality)
        g.add_relation(Relation::new("ip-1", "host-1", RelationType::Connect, 500)).unwrap();
        g.add_relation(Relation::new("host-1", "user-1", RelationType::Auth, 200)).unwrap();

        let hypothesis = Hypothesis::new("Broken Causality")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert!(results.is_empty(), "Should not match when Auth happens before Connect");
    }

    #[test]
    fn search_allows_same_timestamp() {
        let mut g = GraphHunter::new();

        g.add_entity(Entity::new("ip-1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("host-1", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("user-1", EntityType::User)).unwrap();

        // Same timestamp is valid (simultaneous events in same log batch)
        g.add_relation(Relation::new("ip-1", "host-1", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("host-1", "user-1", RelationType::Auth, 100)).unwrap();

        let hypothesis = Hypothesis::new("Same Time")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert_eq!(results.len(), 1);
    }

    // ── Time Window Tests ──

    #[test]
    fn search_time_window_includes_match() {
        let g = build_lateral_movement_graph(); // timestamps: 100, 200, 300, 400

        let hypothesis = Hypothesis::new("Windowed")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User));

        // Window [50, 250] includes both edges (t=100, t=200)
        let results = g.search_temporal_pattern(&hypothesis, Some((50, 250))).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_time_window_excludes_match() {
        let g = build_lateral_movement_graph(); // timestamps: 100, 200, 300, 400

        let hypothesis = Hypothesis::new("Windowed Excluded")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User));

        // Window [150, 250] excludes first edge (t=100)
        let results = g.search_temporal_pattern(&hypothesis, Some((150, 250))).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn search_time_window_partial_chain_cutoff() {
        let g = build_lateral_movement_graph();

        let hypothesis = Hypothesis::new("Full Chain Windowed")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User))
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        // Window [50, 350] excludes the Write at t=400
        let results = g.search_temporal_pattern(&hypothesis, Some((50, 350))).unwrap();
        assert!(results.is_empty());
    }

    // ── Cycle Avoidance Tests ──

    #[test]
    fn search_avoids_cycles() {
        let mut g = GraphHunter::new();

        g.add_entity(Entity::new("ip-1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("host-1", EntityType::Host)).unwrap();
        // Create a Host that also acts as an IP (unusual but tests cycle detection)
        // Instead: create a cycle-like scenario where DFS could loop
        g.add_entity(Entity::new("host-2", EntityType::Host)).unwrap();

        g.add_relation(Relation::new("ip-1", "host-1", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("ip-1", "host-2", RelationType::Connect, 100)).unwrap();

        let hypothesis = Hypothesis::new("Fan Out")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert_eq!(results.len(), 2); // Two distinct paths, no cycles
    }

    // ── Multiple Paths Tests ──

    #[test]
    fn search_finds_multiple_attack_paths() {
        let mut g = GraphHunter::new();

        // Two attackers, same target chain
        g.add_entity(Entity::new("attacker-1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("attacker-2", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("server", EntityType::Host)).unwrap();

        g.add_relation(Relation::new("attacker-1", "server", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("attacker-2", "server", RelationType::Connect, 200)).unwrap();

        let hypothesis = Hypothesis::new("Multi-Source")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert_eq!(results.len(), 2);

        let paths: Vec<Vec<&str>> = results
            .iter()
            .map(|p| p.iter().map(|s| s.as_str()).collect())
            .collect();
        assert!(paths.contains(&vec!["attacker-1", "server"]));
        assert!(paths.contains(&vec!["attacker-2", "server"]));
    }

    #[test]
    fn search_branching_paths() {
        let mut g = GraphHunter::new();

        g.add_entity(Entity::new("ip", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("host", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("user-a", EntityType::User)).unwrap();
        g.add_entity(Entity::new("user-b", EntityType::User)).unwrap();

        g.add_relation(Relation::new("ip", "host", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("host", "user-a", RelationType::Auth, 200)).unwrap();
        g.add_relation(Relation::new("host", "user-b", RelationType::Auth, 300)).unwrap();

        let hypothesis = Hypothesis::new("Branch")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert_eq!(results.len(), 2);
    }

    // ── Complex Realistic Scenario ──

    #[test]
    fn search_realistic_apt_scenario() {
        let mut g = GraphHunter::new();

        // Build APT kill chain:
        // C2-IP -> Connect -> DMZ-Host -> Auth -> Service-Account -> Execute -> PowerShell
        // -> Write -> Beacon.exe -> Execute -> Mimikatz -> Read -> LSASS
        g.add_entity(Entity::new("c2-server", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("dmz-host", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("svc-account", EntityType::User)).unwrap();
        g.add_entity(Entity::new("powershell.exe", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("beacon.exe", EntityType::File)).unwrap();

        g.add_relation(Relation::new("c2-server", "dmz-host", RelationType::Connect, 1000)).unwrap();
        g.add_relation(Relation::new("dmz-host", "svc-account", RelationType::Auth, 1005)).unwrap();
        g.add_relation(Relation::new("svc-account", "powershell.exe", RelationType::Execute, 1010)).unwrap();
        g.add_relation(Relation::new("powershell.exe", "beacon.exe", RelationType::Write, 1015)).unwrap();

        // Search for: IP -> Connect -> Host -> Auth -> User -> Execute -> Process -> Write -> File
        let hypothesis = Hypothesis::new("APT Kill Chain")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User))
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0],
            vec!["c2-server", "dmz-host", "svc-account", "powershell.exe", "beacon.exe"]
        );

        // Same search but with tight time window
        let results_windowed = g
            .search_temporal_pattern(&hypothesis, Some((999, 1020)))
            .unwrap();
        assert_eq!(results_windowed.len(), 1);

        // Too narrow window excludes the Write
        let results_narrow = g
            .search_temporal_pattern(&hypothesis, Some((999, 1012)))
            .unwrap();
        assert!(results_narrow.is_empty());
    }

    #[test]
    fn graph_error_display() {
        let err = GraphError::EntityNotFound("ghost-node".into());
        assert_eq!(format!("{err}"), "Entity not found: ghost-node");

        let err = GraphError::InvalidHypothesis("empty".into());
        assert_eq!(format!("{err}"), "Invalid hypothesis: empty");

        let err = GraphError::DuplicateEntity("dup".into());
        assert_eq!(format!("{err}"), "Duplicate entity ID: dup");
    }

    #[test]
    fn graph_default_trait() {
        let g = GraphHunter::default();
        assert_eq!(g.entity_count(), 0);
    }

    // ══════════════════════════════════════════════════
    // ── Phase 3: Parser & Ingestion Tests ──
    // ══════════════════════════════════════════════════

    // ── Sysmon Event 1: Process Create ──

    #[test]
    fn sysmon_parse_event1_process_create() {
        let json = r#"[{
            "EventID": 1,
            "UtcTime": "2024-01-15 14:30:00.123",
            "User": "CORP\\admin",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ProcessId": 4512,
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ParentProcessId": 1200,
            "Computer": "WORKSTATION-01"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);

        // Event 1 produces 2 triples: User->Execute->Process and Parent->Execute->Child
        assert_eq!(triples.len(), 2);

        // Triple 1: User -> Execute -> Process
        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "CORP\\admin");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Execute);
        assert_eq!(dst.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(dst.entity_type, EntityType::Process);
        assert_eq!(dst.metadata.get("pid").unwrap(), "4512");
        assert_eq!(dst.metadata.get("cmdline").unwrap(), "cmd.exe /c whoami");

        // Triple 2: ParentProcess -> Execute -> ChildProcess
        let (src2, rel2, dst2) = &triples[1];
        assert_eq!(src2.id, "C:\\Windows\\explorer.exe");
        assert_eq!(src2.entity_type, EntityType::Process);
        assert_eq!(rel2.rel_type, RelationType::Execute);
        assert_eq!(dst2.id, "C:\\Windows\\System32\\cmd.exe");

        // Verify timestamp parsing: 2024-01-15 14:30:00.123 UTC
        assert_eq!(rel.timestamp, 1705329000);
    }

    // ── Sysmon Event 3: Network Connection ──

    #[test]
    fn sysmon_parse_event3_network_connection() {
        let json = r#"[{
            "EventID": 3,
            "UtcTime": "2024-01-15 14:35:00.000",
            "Computer": "WORKSTATION-01",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "SourceIp": "192.168.1.100",
            "SourcePort": "49152",
            "DestinationIp": "10.0.0.50",
            "DestinationPort": "445",
            "DestinationHostname": "DC-01",
            "Protocol": "tcp"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "WORKSTATION-01");
        assert_eq!(src.entity_type, EntityType::Host);
        assert_eq!(src.metadata.get("source_ip").unwrap(), "192.168.1.100");
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(rel.metadata.get("image").unwrap(), "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(dst.id, "10.0.0.50");
        assert_eq!(dst.entity_type, EntityType::IP);
        assert_eq!(dst.metadata.get("dest_port").unwrap(), "445");
        assert_eq!(dst.metadata.get("hostname").unwrap(), "DC-01");
        assert_eq!(dst.metadata.get("protocol").unwrap(), "tcp");
    }

    // ── Sysmon Event 11: File Create ──

    #[test]
    fn sysmon_parse_event11_file_create() {
        let json = r#"[{
            "EventID": 11,
            "UtcTime": "2024-01-15 14:40:00.000",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "TargetFilename": "C:\\Temp\\payload.dll",
            "Hashes": "SHA256=ABCDEF1234567890"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Write);
        assert_eq!(dst.id, "C:\\Temp\\payload.dll");
        assert_eq!(dst.entity_type, EntityType::File);
        assert_eq!(dst.metadata.get("hashes").unwrap(), "SHA256=ABCDEF1234567890");
    }

    // ── Sysmon Event 22: DNS Query ──

    #[test]
    fn sysmon_parse_event22_dns_query() {
        let json = r#"[{
            "EventID": 22,
            "UtcTime": "2024-01-15 14:45:00.000",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "QueryName": "evil-c2.attacker.com",
            "QueryResults": "185.220.101.1",
            "QueryType": "A"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::DNS);
        assert_eq!(dst.id, "evil-c2.attacker.com");
        assert_eq!(dst.entity_type, EntityType::Domain);
        assert_eq!(dst.metadata.get("query_results").unwrap(), "185.220.101.1");
        assert_eq!(dst.metadata.get("query_type").unwrap(), "A");
    }

    // ── NDJSON Parsing ──

    #[test]
    fn sysmon_parse_ndjson_format() {
        let ndjson = r#"{"EventID": 22, "UtcTime": "2024-01-15 14:45:00", "Image": "powershell.exe", "QueryName": "c2.evil.com"}
{"EventID": 22, "UtcTime": "2024-01-15 14:46:00", "Image": "powershell.exe", "QueryName": "exfil.evil.com"}"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(ndjson);
        assert_eq!(triples.len(), 2);
        assert_eq!(triples[0].2.id, "c2.evil.com");
        assert_eq!(triples[1].2.id, "exfil.evil.com");
    }

    // ── Malformed / Edge Cases ──

    #[test]
    fn sysmon_parse_unknown_event_id_skipped() {
        let json = r#"[{"EventID": 999, "UtcTime": "2024-01-15 14:30:00"}]"#;
        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert!(triples.is_empty());
    }

    #[test]
    fn sysmon_parse_missing_required_fields_skipped() {
        // Event 1 without Image field — should produce 0 triples
        let json = r#"[{"EventID": 1, "UtcTime": "2024-01-15 14:30:00", "User": "admin"}]"#;
        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert!(triples.is_empty());
    }

    #[test]
    fn sysmon_parse_garbage_input_returns_empty() {
        let parser = SysmonJsonParser;
        assert!(parser.parse("not json at all!").is_empty());
        assert!(parser.parse("").is_empty());
        assert!(parser.parse("{}").is_empty()); // single object without EventID
    }

    #[test]
    fn sysmon_parse_missing_timestamp_defaults_to_zero() {
        let json = r#"[{
            "EventID": 22,
            "Image": "cmd.exe",
            "QueryName": "test.com"
        }]"#;
        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].1.timestamp, 0);
    }

    // ── Ingestion Pipeline ──

    #[test]
    fn ingest_logs_populates_graph() {
        let json = r#"[
            {
                "EventID": 3,
                "UtcTime": "2024-01-15 14:35:00.000",
                "Computer": "WORKSTATION-01",
                "DestinationIp": "10.0.0.50",
                "DestinationPort": "445"
            },
            {
                "EventID": 22,
                "UtcTime": "2024-01-15 14:36:00.000",
                "Image": "cmd.exe",
                "QueryName": "evil.com"
            }
        ]"#;

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(json, &SysmonJsonParser);

        assert_eq!(entities, 4); // WORKSTATION-01, 10.0.0.50, cmd.exe, evil.com
        assert_eq!(relations, 2);
        assert_eq!(g.entity_count(), 4);
        assert_eq!(g.relation_count(), 2);
    }

    #[test]
    fn ingest_logs_deduplicates_entities() {
        // Two events reference the same process "cmd.exe"
        let json = r#"[
            {
                "EventID": 22,
                "UtcTime": "2024-01-15 14:36:00",
                "Image": "cmd.exe",
                "QueryName": "domain-a.com"
            },
            {
                "EventID": 22,
                "UtcTime": "2024-01-15 14:37:00",
                "Image": "cmd.exe",
                "QueryName": "domain-b.com"
            }
        ]"#;

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(json, &SysmonJsonParser);

        // cmd.exe appears once (deduplicated), 2 domains = 3 entities total
        assert_eq!(entities, 3);
        assert_eq!(relations, 2);
        assert_eq!(g.entity_count(), 3);
    }

    #[test]
    fn ingest_logs_metadata_merge() {
        let batch1 = r#"[{
            "EventID": 3,
            "UtcTime": "2024-01-15 14:35:00",
            "Computer": "HOST-1",
            "SourceIp": "192.168.1.1",
            "DestinationIp": "10.0.0.1",
            "DestinationPort": "80"
        }]"#;
        let batch2 = r#"[{
            "EventID": 3,
            "UtcTime": "2024-01-15 14:36:00",
            "Computer": "HOST-1",
            "SourceIp": "192.168.1.1",
            "DestinationIp": "10.0.0.1",
            "DestinationPort": "443"
        }]"#;

        let mut g = GraphHunter::new();
        g.ingest_logs(batch1, &SysmonJsonParser);
        g.ingest_logs(batch2, &SysmonJsonParser);

        // Same entities, 2 different relations (different timestamps)
        assert_eq!(g.entity_count(), 2);
        assert_eq!(g.relation_count(), 2);

        // First metadata wins (dest_port stays "80" from batch1)
        let dest = g.get_entity("10.0.0.1").unwrap();
        assert_eq!(dest.metadata.get("dest_port").unwrap(), "80");
    }

    // ── Full Pipeline: Ingest → Hunt ──

    #[test]
    fn full_pipeline_ingest_then_hunt() {
        // Simulate APT kill chain via Sysmon events:
        // 1. Network connection to compromised host
        // 2. User executes process
        // 3. Process creates file
        // 4. Process queries C2 domain
        let events = r#"[
            {
                "EventID": 3,
                "UtcTime": "2024-01-15 14:30:00",
                "Computer": "DMZ-SERVER",
                "DestinationIp": "185.220.101.1",
                "DestinationPort": "443",
                "Image": "svchost.exe"
            },
            {
                "EventID": 1,
                "UtcTime": "2024-01-15 14:31:00",
                "User": "CORP\\svc-web",
                "Image": "C:\\Temp\\beacon.exe",
                "CommandLine": "beacon.exe --c2 185.220.101.1",
                "ProcessId": 6789,
                "ParentImage": "C:\\Windows\\System32\\svchost.exe",
                "ParentProcessId": 512
            },
            {
                "EventID": 11,
                "UtcTime": "2024-01-15 14:32:00",
                "Image": "C:\\Temp\\beacon.exe",
                "TargetFilename": "C:\\Windows\\Temp\\mimikatz.exe",
                "Hashes": "SHA256=DEADBEEF"
            },
            {
                "EventID": 22,
                "UtcTime": "2024-01-15 14:33:00",
                "Image": "C:\\Temp\\beacon.exe",
                "QueryName": "exfil.evil-corp.com",
                "QueryResults": "185.220.101.2"
            }
        ]"#;

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(events, &SysmonJsonParser);

        assert!(entities > 0);
        assert!(relations > 0);

        // Hunt: User -> Execute -> Process -> Write -> File
        let hypothesis = Hypothesis::new("Beacon Drop")
            .add_step(HypothesisStep::new(
                EntityType::User,
                RelationType::Execute,
                EntityType::Process,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Process,
                RelationType::Write,
                EntityType::File,
            ));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert!(!results.is_empty(), "Should find User -> beacon.exe -> mimikatz.exe path");

        // Verify the path
        let path = &results[0];
        assert_eq!(path[0], "CORP\\svc-web");
        assert_eq!(path[1], "C:\\Temp\\beacon.exe");
        assert_eq!(path[2], "C:\\Windows\\Temp\\mimikatz.exe");
    }

    #[test]
    fn full_pipeline_dns_exfil_hunt() {
        let events = r#"[
            {
                "EventID": 1,
                "UtcTime": "2024-01-15 14:31:00",
                "User": "CORP\\admin",
                "Image": "powershell.exe",
                "ProcessId": 1111,
                "ParentImage": "explorer.exe",
                "ParentProcessId": 500
            },
            {
                "EventID": 22,
                "UtcTime": "2024-01-15 14:32:00",
                "Image": "powershell.exe",
                "QueryName": "data.exfil-tunnel.com",
                "QueryType": "TXT"
            }
        ]"#;

        let mut g = GraphHunter::new();
        g.ingest_logs(events, &SysmonJsonParser);

        // Hunt: User -> Execute -> Process -> DNS -> Domain
        let hypothesis = Hypothesis::new("DNS Exfiltration")
            .add_step(HypothesisStep::new(
                EntityType::User,
                RelationType::Execute,
                EntityType::Process,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Process,
                RelationType::DNS,
                EntityType::Domain,
            ));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], vec!["CORP\\admin", "powershell.exe", "data.exfil-tunnel.com"]);
    }

    #[test]
    fn full_pipeline_time_windowed_hunt() {
        let events = r#"[
            {
                "EventID": 1,
                "UtcTime": "2024-01-15 14:31:00",
                "User": "admin",
                "Image": "evil.exe",
                "ProcessId": 100,
                "ParentImage": "explorer.exe",
                "ParentProcessId": 50
            },
            {
                "EventID": 22,
                "UtcTime": "2024-01-15 14:32:00",
                "Image": "evil.exe",
                "QueryName": "c2.bad.com"
            }
        ]"#;

        let mut g = GraphHunter::new();
        g.ingest_logs(events, &SysmonJsonParser);

        let hypothesis = Hypothesis::new("Windowed DNS")
            .add_step(HypothesisStep::new(
                EntityType::User,
                RelationType::Execute,
                EntityType::Process,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Process,
                RelationType::DNS,
                EntityType::Domain,
            ));

        // Timestamps: Execute at 1705329060 (14:31), DNS at 1705329120 (14:32)
        // Window that includes both
        let results = g
            .search_temporal_pattern(&hypothesis, Some((1705329000, 1705329200)))
            .unwrap();
        assert_eq!(results.len(), 1);

        // Window that excludes the DNS event
        let results_narrow = g
            .search_temporal_pattern(&hypothesis, Some((1705329000, 1705329070)))
            .unwrap();
        assert!(results_narrow.is_empty());
    }

    // ── Demo Data Integration Test ──

    #[test]
    fn demo_data_all_presets_produce_results() {
        let demo_json = std::fs::read_to_string("../demo_data/apt_attack_simulation.json")
            .expect("Demo data file should exist at demo_data/apt_attack_simulation.json");

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(&demo_json, &SysmonJsonParser);

        assert!(entities > 15, "Should ingest many entities, got {entities}");
        assert!(relations > 20, "Should ingest many relations, got {relations}");

        // ── Preset 1: Lateral Movement ──
        // User → Execute → Process → Execute → Process → Write → File
        let lateral = Hypothesis::new("Lateral Movement")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let lateral_results = g.search_temporal_pattern(&lateral, None).unwrap();
        assert!(
            !lateral_results.is_empty(),
            "Lateral Movement should find paths (PsExec → dropper → file)"
        );

        // Verify one path goes through the PsExec → dropper chain
        let has_psexec_path = lateral_results.iter().any(|path| {
            path.iter().any(|n| n.contains("PsExec"))
                && path.iter().any(|n| n.contains("dropper"))
        });
        assert!(has_psexec_path, "Should find PsExec→dropper lateral movement path");

        // ── Preset 2: DNS Exfiltration ──
        // User → Execute → Process → DNS → Domain
        let dns_exfil = Hypothesis::new("DNS Exfiltration")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::DNS, EntityType::Domain));

        let dns_results = g.search_temporal_pattern(&dns_exfil, None).unwrap();
        assert!(
            dns_results.len() >= 3,
            "DNS Exfiltration should find multiple paths (malicious + benign), got {}",
            dns_results.len()
        );

        // Should include both malicious and benign DNS
        let has_evil_dns = dns_results.iter().any(|path| {
            path.iter().any(|n| n.contains("evil-c2") || n.contains("exfil-tunnel"))
        });
        let has_benign_dns = dns_results.iter().any(|path| {
            path.iter().any(|n| n.contains("google.com") || n.contains("office365"))
        });
        assert!(has_evil_dns, "Should find malicious DNS paths");
        assert!(has_benign_dns, "Should also find benign DNS paths (shows noise)");

        // ── Preset 3: Malware Drop ──
        // User → Execute → Process → Write → File
        let malware_drop = Hypothesis::new("Malware Drop")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let drop_results = g.search_temporal_pattern(&malware_drop, None).unwrap();
        assert!(
            drop_results.len() >= 2,
            "Malware Drop should find multiple paths, got {}",
            drop_results.len()
        );

        // Should find dropper writing malicious files
        let has_dropper = drop_results.iter().any(|path| {
            path.iter().any(|n| n.contains("dropper"))
        });
        assert!(has_dropper, "Should find dropper writing files");

        println!("=== Demo Data Results ===");
        println!("Entities: {}, Relations: {}", g.entity_count(), g.relation_count());
        println!("Lateral Movement: {} paths", lateral_results.len());
        println!("DNS Exfiltration: {} paths", dns_results.len());
        println!("Malware Drop: {} paths", drop_results.len());
    }

    // ══════════════════════════════════════════════════
    // ── Phase 4: Index & Analytics Tests ──
    // ══════════════════════════════════════════════════

    #[test]
    fn type_index_populated_on_add_entity() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("ip-1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("ip-2", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("host-1", EntityType::Host)).unwrap();

        let ip_ids = g.type_index.get(&EntityType::IP).unwrap();
        assert_eq!(ip_ids.len(), 2);
        assert!(ip_ids.contains("ip-1"));
        assert!(ip_ids.contains("ip-2"));

        let host_ids = g.type_index.get(&EntityType::Host).unwrap();
        assert_eq!(host_ids.len(), 1);
        assert!(host_ids.contains("host-1"));
    }

    #[test]
    fn type_index_populated_on_ingest() {
        let json = r#"[{
            "EventID": 22,
            "UtcTime": "2024-01-15 14:45:00",
            "Image": "cmd.exe",
            "QueryName": "evil.com"
        }]"#;

        let mut g = GraphHunter::new();
        g.ingest_logs(json, &SysmonJsonParser);

        let process_ids = g.type_index.get(&EntityType::Process).unwrap();
        assert!(process_ids.contains("cmd.exe"));

        let domain_ids = g.type_index.get(&EntityType::Domain).unwrap();
        assert!(domain_ids.contains("evil.com"));
    }

    #[test]
    fn reverse_adj_correct() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("a", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("b", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("c", EntityType::Host)).unwrap();

        g.add_relation(Relation::new("a", "b", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("a", "c", RelationType::Connect, 200)).unwrap();

        let rev_b = g.reverse_adj.get("b").unwrap();
        assert_eq!(rev_b, &vec!["a".to_string()]);

        let rev_c = g.reverse_adj.get("c").unwrap();
        assert_eq!(rev_c, &vec!["a".to_string()]);

        // "a" has no incoming edges
        let rev_a = g.reverse_adj.get("a").unwrap();
        assert!(rev_a.is_empty());
    }

    #[test]
    fn search_entities_substring() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("beacon.exe", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("cmd.exe", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("evil-beacon.com", EntityType::Domain)).unwrap();

        let results = g.search_entities("beacon", None, 50);
        assert_eq!(results.len(), 2);
        let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"beacon.exe"));
        assert!(ids.contains(&"evil-beacon.com"));
    }

    #[test]
    fn search_entities_type_filter() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("beacon.exe", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("evil-beacon.com", EntityType::Domain)).unwrap();

        let results = g.search_entities("beacon", Some(&EntityType::Process), 50);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "beacon.exe");
    }

    #[test]
    fn search_entities_empty_query() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("test", EntityType::IP)).unwrap();

        // Empty query matches everything
        let results = g.search_entities("", None, 50);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn get_neighborhood_basic() {
        let g = build_lateral_movement_graph();

        let hood = g.get_neighborhood("web-server", 1, 100, None).unwrap();
        assert_eq!(hood.center, "web-server");
        // web-server is connected to attacker-ip (incoming) and admin-user (outgoing)
        assert!(hood.nodes.len() >= 3); // web-server + at least 2 neighbors
        assert!(!hood.edges.is_empty());
        assert!(!hood.truncated);
    }

    #[test]
    fn get_neighborhood_cap() {
        let g = build_lateral_movement_graph();

        // Cap at 2 nodes: center + 1 neighbor
        let hood = g.get_neighborhood("web-server", 2, 2, None).unwrap();
        assert_eq!(hood.nodes.len(), 2);
        assert!(hood.truncated);
    }

    #[test]
    fn get_neighborhood_nonexistent_node() {
        let g = build_lateral_movement_graph();
        assert!(g.get_neighborhood("ghost", 1, 100, None).is_none());
    }

    #[test]
    fn get_neighborhood_with_filter() {
        let g = build_lateral_movement_graph();

        let filter = analytics::NeighborhoodFilter {
            entity_types: Some(vec![EntityType::User]),
            relation_types: None,
            time_start: None,
            time_end: None,
            min_score: None,
        };

        let hood = g.get_neighborhood("web-server", 1, 100, Some(&filter)).unwrap();
        // Should only include User type neighbors (admin-user) + center
        let non_center_nodes: Vec<_> = hood.nodes.iter().filter(|n| n.id != "web-server").collect();
        for node in &non_center_nodes {
            assert_eq!(node.entity_type, "User");
        }
    }

    #[test]
    fn compute_scores_high_degree_high_score() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("hub", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("a", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("b", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("c", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("leaf", EntityType::IP)).unwrap();

        g.add_relation(Relation::new("a", "hub", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("b", "hub", RelationType::Connect, 200)).unwrap();
        g.add_relation(Relation::new("c", "hub", RelationType::Connect, 300)).unwrap();
        g.add_relation(Relation::new("hub", "leaf", RelationType::Connect, 400)).unwrap();

        g.compute_scores();

        let hub_score = g.get_entity("hub").unwrap().score;
        let leaf_score = g.get_entity("leaf").unwrap().score;
        assert!(hub_score > leaf_score, "Hub ({hub_score}) should have higher score than leaf ({leaf_score})");
        assert_eq!(hub_score, 100.0); // max degree = highest score
    }

    #[test]
    fn get_node_details_complete() {
        let g = build_lateral_movement_graph();

        let details = g.get_node_details("web-server").unwrap();
        assert_eq!(details.id, "web-server");
        assert_eq!(details.entity_type, "Host");
        assert_eq!(details.out_degree, 1); // web-server -> admin-user
        assert_eq!(details.in_degree, 1);  // attacker-ip -> web-server
        assert!(details.time_range.is_some());
        assert!(!details.neighbor_types.is_empty());
    }

    #[test]
    fn get_node_details_nonexistent() {
        let g = build_lateral_movement_graph();
        assert!(g.get_node_details("ghost").is_none());
    }

    #[test]
    fn get_graph_summary_complete() {
        let g = build_lateral_movement_graph();

        let summary = g.get_graph_summary();
        assert_eq!(summary.entity_count, 5);
        assert_eq!(summary.relation_count, 4);
        assert!(!summary.type_distribution.is_empty());
        assert!(summary.time_range.is_some());
    }

    #[test]
    fn search_temporal_pattern_still_works_with_indices() {
        // Regression: make sure the optimized search_temporal_pattern still produces correct results
        let g = build_lateral_movement_graph();

        let hypothesis = Hypothesis::new("Full Chain")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User))
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0],
            vec!["attacker-ip", "web-server", "admin-user", "cmd.exe", "payload.dll"]
        );
    }

    // ══════════════════════════════════════════════════
    // ── Phase 5: Sentinel Parser Tests ──
    // ══════════════════════════════════════════════════

    // ── Per-Table Tests ──

    #[test]
    fn sentinel_security_event_4624_auth_success() {
        let json = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 4624,
            "Computer": "DC-01.contoso.local",
            "TargetUserName": "admin",
            "IpAddress": "10.0.0.5",
            "LogonType": 3
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "admin");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Auth);
        assert_eq!(rel.metadata.get("status").unwrap(), "Success");
        assert_eq!(rel.metadata.get("event_id").unwrap(), "4624");
        assert_eq!(rel.metadata.get("logon_type").unwrap(), "3");
        assert_eq!(dst.id, "DC-01.contoso.local");
        assert_eq!(dst.entity_type, EntityType::Host);
        assert_eq!(dst.metadata.get("source_ip").unwrap(), "10.0.0.5");
        assert_eq!(rel.timestamp, 1705329000);
    }

    #[test]
    fn sentinel_security_event_4625_auth_failure() {
        let json = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 4625,
            "Computer": "DC-01.contoso.local",
            "TargetUserName": "admin",
            "IpAddress": "198.51.100.77"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (_, rel, _) = &triples[0];
        assert_eq!(rel.metadata.get("status").unwrap(), "Failure");
        assert_eq!(rel.metadata.get("event_id").unwrap(), "4625");
    }

    #[test]
    fn sentinel_security_event_4688_process_create() {
        let json = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 4688,
            "Computer": "WS-01.contoso.local",
            "SubjectUserName": "admin",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "NewProcessId": "0x1234",
            "CommandLine": "cmd.exe /c whoami",
            "ParentProcessName": "C:\\Windows\\explorer.exe"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "admin");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Execute);
        assert_eq!(dst.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(dst.entity_type, EntityType::Process);
        assert_eq!(dst.metadata.get("cmdline").unwrap(), "cmd.exe /c whoami");
        assert_eq!(dst.metadata.get("pid").unwrap(), "0x1234");

        let (src2, rel2, dst2) = &triples[1];
        assert_eq!(src2.id, "C:\\Windows\\explorer.exe");
        assert_eq!(src2.entity_type, EntityType::Process);
        assert_eq!(rel2.rel_type, RelationType::Execute);
        assert_eq!(dst2.id, "C:\\Windows\\System32\\cmd.exe");
    }

    #[test]
    fn sentinel_security_event_4663_file_access() {
        let json = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 4663,
            "Computer": "WS-01",
            "ProcessName": "C:\\beacon.exe",
            "ObjectName": "C:\\Users\\admin\\secret.docx"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\beacon.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Read);
        assert_eq!(dst.id, "C:\\Users\\admin\\secret.docx");
        assert_eq!(dst.entity_type, EntityType::File);
    }

    #[test]
    fn sentinel_signin_logs() {
        let json = r#"[{
            "Type": "SigninLogs",
            "TimeGenerated": "2024-01-15T10:05:00Z",
            "UserPrincipalName": "user@contoso.com",
            "IPAddress": "198.51.100.77",
            "AppDisplayName": "Azure Portal",
            "ResultType": "0",
            "Location": "RU"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "user@contoso.com");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Auth);
        assert_eq!(rel.metadata.get("status").unwrap(), "Success");
        assert_eq!(rel.metadata.get("app").unwrap(), "Azure Portal");
        assert_eq!(dst.id, "198.51.100.77");
        assert_eq!(dst.entity_type, EntityType::IP);
        assert_eq!(dst.metadata.get("location").unwrap(), "RU");
    }

    #[test]
    fn sentinel_device_process_events() {
        let json = r#"[{
            "Type": "DeviceProcessEvents",
            "Timestamp": "2024-01-15T10:22:00Z",
            "DeviceName": "WS-01",
            "AccountName": "admin",
            "FileName": "beacon.exe",
            "FolderPath": "C:\\Users\\Public\\beacon.exe",
            "ProcessCommandLine": "beacon.exe --c2 evil.com",
            "InitiatingProcessFileName": "powershell.exe",
            "InitiatingProcessFolderPath": "C:\\Windows\\System32\\powershell.exe",
            "SHA256": "deadbeef"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "admin");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Execute);
        assert_eq!(dst.id, "C:\\Users\\Public\\beacon.exe");
        assert_eq!(dst.entity_type, EntityType::Process);
        assert_eq!(dst.metadata.get("cmdline").unwrap(), "beacon.exe --c2 evil.com");
        assert_eq!(dst.metadata.get("sha256").unwrap(), "deadbeef");

        let (src2, _, _) = &triples[1];
        assert_eq!(src2.id, "C:\\Windows\\System32\\powershell.exe");
        assert_eq!(src2.entity_type, EntityType::Process);
    }

    #[test]
    fn sentinel_device_network_events() {
        let json = r#"[{
            "Type": "DeviceNetworkEvents",
            "Timestamp": "2024-01-15T10:26:00Z",
            "DeviceName": "WS-01",
            "RemoteIP": "198.51.100.77",
            "RemotePort": 443,
            "RemoteUrl": "https://evil.com/beacon",
            "Protocol": "TCP",
            "ActionType": "ConnectionSuccess",
            "LocalPort": 52341
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "WS-01");
        assert_eq!(src.entity_type, EntityType::Host);
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(rel.metadata.get("action").unwrap(), "ConnectionSuccess");
        assert_eq!(rel.metadata.get("local_port").unwrap(), "52341");
        assert_eq!(dst.id, "198.51.100.77");
        assert_eq!(dst.entity_type, EntityType::IP);
        assert_eq!(dst.metadata.get("remote_port").unwrap(), "443");
        assert_eq!(dst.metadata.get("url").unwrap(), "https://evil.com/beacon");
        assert_eq!(dst.metadata.get("protocol").unwrap(), "TCP");
    }

    #[test]
    fn sentinel_device_file_events_write() {
        let json = r#"[{
            "Type": "DeviceFileEvents",
            "Timestamp": "2024-01-15T10:23:00Z",
            "ActionType": "FileCreated",
            "FileName": "beacon.exe",
            "FolderPath": "C:\\Users\\Public\\beacon.exe",
            "InitiatingProcessFileName": "powershell.exe",
            "InitiatingProcessFolderPath": "C:\\Windows\\powershell.exe",
            "SHA256": "deadbeef"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Windows\\powershell.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Write);
        assert_eq!(dst.id, "C:\\Users\\Public\\beacon.exe");
        assert_eq!(dst.entity_type, EntityType::File);
        assert_eq!(dst.metadata.get("sha256").unwrap(), "deadbeef");
    }

    #[test]
    fn sentinel_device_file_events_read() {
        let json = r#"[{
            "Type": "DeviceFileEvents",
            "Timestamp": "2024-01-15T10:25:00Z",
            "ActionType": "FileRead",
            "FileName": "secret.docx",
            "FolderPath": "C:\\Users\\admin\\secret.docx",
            "InitiatingProcessFileName": "beacon.exe",
            "InitiatingProcessFolderPath": "C:\\Users\\Public\\beacon.exe"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (_, rel, _) = &triples[0];
        assert_eq!(rel.rel_type, RelationType::Read);
    }

    #[test]
    fn sentinel_common_security_log() {
        let json = r#"[{
            "Type": "CommonSecurityLog",
            "TimeGenerated": "2024-01-15T08:30:00Z",
            "SourceIP": "10.1.0.50",
            "DestinationIP": "8.8.8.8",
            "DestinationPort": 53,
            "DeviceVendor": "Palo Alto Networks",
            "DeviceAction": "Allow",
            "Protocol": "UDP"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "10.1.0.50");
        assert_eq!(src.entity_type, EntityType::IP);
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(rel.metadata.get("vendor").unwrap(), "Palo Alto Networks");
        assert_eq!(rel.metadata.get("action").unwrap(), "Allow");
        assert_eq!(rel.metadata.get("protocol").unwrap(), "UDP");
        assert_eq!(dst.id, "8.8.8.8");
        assert_eq!(dst.entity_type, EntityType::IP);
        assert_eq!(dst.metadata.get("dest_port").unwrap(), "53");
    }

    // ── Detection Tests ──

    #[test]
    fn sentinel_detect_by_type_field() {
        // When Type field is present, it takes priority
        let json = r#"[{
            "Type": "SigninLogs",
            "TimeGenerated": "2024-01-15T10:00:00Z",
            "UserPrincipalName": "test@contoso.com",
            "IPAddress": "1.2.3.4",
            "ResultType": "0"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].0.entity_type, EntityType::User);
        assert_eq!(triples[0].2.entity_type, EntityType::IP);
    }

    #[test]
    fn sentinel_detect_by_heuristic() {
        // No Type field — fallback to heuristic (EventID + Computer = SecurityEvent)
        let json = r#"[{
            "TimeGenerated": "2024-01-15T10:00:00Z",
            "EventID": 4624,
            "Computer": "DC-01",
            "TargetUserName": "admin"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].1.rel_type, RelationType::Auth);
    }

    #[test]
    fn sentinel_unknown_type_skipped() {
        let json = r#"[{
            "Type": "UnknownTableXYZ",
            "TimeGenerated": "2024-01-15T10:00:00Z",
            "SomeField": "value"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert!(triples.is_empty());
    }

    // ── Format Tests ──

    #[test]
    fn sentinel_ndjson_format() {
        let ndjson = concat!(
            r#"{"Type":"SigninLogs","TimeGenerated":"2024-01-15T10:00:00Z","UserPrincipalName":"a@x.com","IPAddress":"1.1.1.1","ResultType":"0"}"#,
            "\n",
            r#"{"Type":"SigninLogs","TimeGenerated":"2024-01-15T10:01:00Z","UserPrincipalName":"b@x.com","IPAddress":"2.2.2.2","ResultType":"0"}"#,
        );

        let parser = SentinelJsonParser;
        let triples = parser.parse(ndjson);
        assert_eq!(triples.len(), 2);
        assert_eq!(triples[0].0.id, "a@x.com");
        assert_eq!(triples[1].0.id, "b@x.com");
    }

    #[test]
    fn sentinel_json_array_format() {
        let json = r#"[
            {"Type":"CommonSecurityLog","TimeGenerated":"2024-01-15T08:30:00Z","SourceIP":"10.0.0.1","DestinationIP":"8.8.8.8","DestinationPort":53,"DeviceVendor":"PAN","DeviceAction":"Allow"},
            {"Type":"CommonSecurityLog","TimeGenerated":"2024-01-15T08:31:00Z","SourceIP":"10.0.0.2","DestinationIP":"8.8.4.4","DestinationPort":53,"DeviceVendor":"PAN","DeviceAction":"Allow"}
        ]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);
    }

    #[test]
    fn sentinel_mixed_tables_in_one_file() {
        let json = r#"[
            {"Type":"SecurityEvent","TimeGenerated":"2024-01-15T10:00:00Z","EventID":4624,"Computer":"DC-01","TargetUserName":"admin","IpAddress":"10.0.0.1"},
            {"Type":"SigninLogs","TimeGenerated":"2024-01-15T10:01:00Z","UserPrincipalName":"admin@contoso.com","IPAddress":"10.0.0.2","ResultType":"0"},
            {"Type":"DeviceNetworkEvents","Timestamp":"2024-01-15T10:02:00Z","DeviceName":"WS-01","RemoteIP":"198.51.100.1","RemotePort":443,"Protocol":"TCP"}
        ]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 3);

        // SecurityEvent -> Auth
        assert_eq!(triples[0].1.rel_type, RelationType::Auth);
        // SigninLogs -> Auth
        assert_eq!(triples[1].1.rel_type, RelationType::Auth);
        // DeviceNetworkEvents -> Connect
        assert_eq!(triples[2].1.rel_type, RelationType::Connect);
    }

    // ── Edge Cases ──

    #[test]
    fn sentinel_missing_required_fields_skipped() {
        let json = r#"[{
            "Type": "SigninLogs",
            "TimeGenerated": "2024-01-15T10:00:00Z",
            "UserPrincipalName": "user@contoso.com"
        }]"#;
        // Missing IPAddress → should produce 0 triples
        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert!(triples.is_empty());
    }

    #[test]
    fn sentinel_garbage_input_returns_empty() {
        let parser = SentinelJsonParser;
        assert!(parser.parse("not json at all!").is_empty());
        assert!(parser.parse("").is_empty());
        assert!(parser.parse("{}").is_empty());
    }

    #[test]
    fn sentinel_missing_timestamp_defaults_to_zero() {
        let json = r#"[{
            "Type": "SigninLogs",
            "UserPrincipalName": "user@contoso.com",
            "IPAddress": "1.2.3.4",
            "ResultType": "0"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].1.timestamp, 0);
    }

    #[test]
    fn sentinel_iso8601_variants() {
        // Test different ISO 8601 timestamp formats
        let json_z = r#"[{"Type":"SigninLogs","TimeGenerated":"2024-01-15T14:30:00Z","UserPrincipalName":"a@x.com","IPAddress":"1.1.1.1","ResultType":"0"}]"#;
        let json_frac = r#"[{"Type":"SigninLogs","TimeGenerated":"2024-01-15T14:30:00.1234567Z","UserPrincipalName":"a@x.com","IPAddress":"1.1.1.1","ResultType":"0"}]"#;
        let json_offset = r#"[{"Type":"SigninLogs","TimeGenerated":"2024-01-15T14:30:00+00:00","UserPrincipalName":"a@x.com","IPAddress":"1.1.1.1","ResultType":"0"}]"#;

        let parser = SentinelJsonParser;
        let ts_z = parser.parse(json_z)[0].1.timestamp;
        let ts_frac = parser.parse(json_frac)[0].1.timestamp;
        let ts_offset = parser.parse(json_offset)[0].1.timestamp;

        assert_eq!(ts_z, 1705329000);
        assert_eq!(ts_frac, 1705329000);
        assert_eq!(ts_offset, 1705329000);
    }

    // ── Integration Tests ──

    #[test]
    fn sentinel_ingest_populates_graph() {
        let json = r#"[
            {"Type":"SecurityEvent","TimeGenerated":"2024-01-15T10:00:00Z","EventID":4624,"Computer":"DC-01","TargetUserName":"admin","IpAddress":"10.0.0.1"},
            {"Type":"DeviceNetworkEvents","Timestamp":"2024-01-15T10:02:00Z","DeviceName":"WS-01","RemoteIP":"198.51.100.1","RemotePort":443,"Protocol":"TCP"}
        ]"#;

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(json, &SentinelJsonParser);

        assert_eq!(entities, 4); // admin, DC-01, WS-01, 198.51.100.1
        assert_eq!(relations, 2);
        assert_eq!(g.entity_count(), 4);
        assert_eq!(g.relation_count(), 2);
    }

    #[test]
    fn sentinel_deduplication() {
        // Same user authenticating to same host twice
        let json = r#"[
            {"Type":"SecurityEvent","TimeGenerated":"2024-01-15T10:00:00Z","EventID":4624,"Computer":"DC-01","TargetUserName":"admin"},
            {"Type":"SecurityEvent","TimeGenerated":"2024-01-15T10:01:00Z","EventID":4624,"Computer":"DC-01","TargetUserName":"admin"}
        ]"#;

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(json, &SentinelJsonParser);

        assert_eq!(entities, 2); // admin, DC-01 (deduplicated)
        assert_eq!(relations, 2); // Two distinct relations (different timestamps)
    }

    #[test]
    fn sentinel_full_pipeline_ingest_then_hunt() {
        let events = r#"[
            {"Type":"SecurityEvent","TimeGenerated":"2024-01-15T10:00:00Z","EventID":4624,"Computer":"DC-01","TargetUserName":"attacker"},
            {"Type":"SecurityEvent","TimeGenerated":"2024-01-15T10:01:00Z","EventID":4688,"Computer":"DC-01","SubjectUserName":"attacker","NewProcessName":"C:\\cmd.exe","ParentProcessName":"C:\\explorer.exe"},
            {"Type":"DeviceFileEvents","Timestamp":"2024-01-15T10:02:00Z","ActionType":"FileCreated","FileName":"payload.dll","FolderPath":"C:\\Temp\\payload.dll","InitiatingProcessFileName":"cmd.exe","InitiatingProcessFolderPath":"C:\\cmd.exe"}
        ]"#;

        let mut g = GraphHunter::new();
        g.ingest_logs(events, &SentinelJsonParser);

        // Hunt: User -> Execute -> Process -> Write -> File
        let hypothesis = Hypothesis::new("Sentinel Kill Chain")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let results = g.search_temporal_pattern(&hypothesis, None).unwrap();
        assert!(!results.is_empty(), "Should find attacker -> cmd.exe -> payload.dll");

        let path = &results[0];
        assert_eq!(path[0], "attacker");
        assert_eq!(path[1], "C:\\cmd.exe");
        assert_eq!(path[2], "C:\\Temp\\payload.dll");
    }

    // ── Demo Data Test ──

    #[test]
    fn sentinel_demo_data_ingestion_and_hunt() {
        let demo_json = std::fs::read_to_string("../demo_data/sentinel_attack_simulation.json")
            .expect("Demo data file should exist at demo_data/sentinel_attack_simulation.json");

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(&demo_json, &SentinelJsonParser);

        assert!(entities > 10, "Should ingest many entities, got {entities}");
        assert!(relations > 15, "Should ingest many relations, got {relations}");

        // Hunt: User -> Auth -> Host (brute force success)
        let auth_hunt = Hypothesis::new("Auth Chain")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::Host));

        let auth_results = g.search_temporal_pattern(&auth_hunt, None).unwrap();
        assert!(!auth_results.is_empty(), "Should find auth events");

        // Hunt: User -> Execute -> Process -> Write -> File (malware drop)
        let drop_hunt = Hypothesis::new("Malware Drop")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let drop_results = g.search_temporal_pattern(&drop_hunt, None).unwrap();
        assert!(!drop_results.is_empty(), "Should find malware drop paths");

        // Hunt: Host -> Connect -> IP (C2 comms)
        let c2_hunt = Hypothesis::new("C2 Communication")
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Connect, EntityType::IP));

        let c2_results = g.search_temporal_pattern(&c2_hunt, None).unwrap();
        assert!(!c2_results.is_empty(), "Should find C2 connection paths");

        // Verify the attacker IP shows up
        let has_attacker_ip = c2_results.iter().any(|path| {
            path.iter().any(|n| n.contains("198.51.100"))
        });
        assert!(has_attacker_ip, "Should find connections to attacker IPs");

        println!("=== Sentinel Demo Data Results ===");
        println!("Entities: {}, Relations: {}", g.entity_count(), g.relation_count());
        println!("Auth events: {} paths", auth_results.len());
        println!("Malware drops: {} paths", drop_results.len());
        println!("C2 connections: {} paths", c2_results.len());
    }
}
