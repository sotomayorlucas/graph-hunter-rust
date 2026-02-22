use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::EntityType;

/// A node in the threat graph representing an observable entity.
///
/// Uses String IDs instead of references to avoid borrow checker complexity.
/// Metadata is a flexible key-value store for enrichment data (GeoIP, reputation, etc.).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entity {
    pub id: String,
    pub entity_type: EntityType,
    pub score: f64,
    pub metadata: HashMap<String, String>,
}

impl Entity {
    /// Creates a new entity with zero threat score and empty metadata.
    pub fn new(id: impl Into<String>, entity_type: EntityType) -> Self {
        Self {
            id: id.into(),
            entity_type,
            score: 0.0,
            metadata: HashMap::new(),
        }
    }

    /// Creates a new entity with an initial threat score.
    pub fn with_score(id: impl Into<String>, entity_type: EntityType, score: f64) -> Self {
        Self {
            id: id.into(),
            entity_type,
            score,
            metadata: HashMap::new(),
        }
    }

    /// Adds a metadata key-value pair, returning self for builder-pattern chaining.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

impl PartialEq for Entity {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Entity {}

impl std::hash::Hash for Entity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
