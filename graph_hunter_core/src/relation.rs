use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::RelationType;

/// A directed edge in the threat graph representing an observed relationship
/// between two entities at a specific point in time.
///
/// The `timestamp` field stores Unix epoch seconds and is critical for
/// temporal pattern matching (causal monotonicity enforcement).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Relation {
    pub source_id: String,
    pub dest_id: String,
    pub rel_type: RelationType,
    pub timestamp: i64,
    pub metadata: HashMap<String, String>,
}

impl Relation {
    /// Creates a new relation with empty metadata.
    pub fn new(
        source_id: impl Into<String>,
        dest_id: impl Into<String>,
        rel_type: RelationType,
        timestamp: i64,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            dest_id: dest_id.into(),
            rel_type,
            timestamp,
            metadata: HashMap::new(),
        }
    }

    /// Adds a metadata key-value pair, returning self for builder-pattern chaining.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}
