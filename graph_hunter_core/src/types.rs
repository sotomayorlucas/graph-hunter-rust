use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents the type of entity observed in the network/host telemetry.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum EntityType {
    IP,
    Host,
    User,
    Process,
    File,
    Domain,
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntityType::IP => write!(f, "IP"),
            EntityType::Host => write!(f, "Host"),
            EntityType::User => write!(f, "User"),
            EntityType::Process => write!(f, "Process"),
            EntityType::File => write!(f, "File"),
            EntityType::Domain => write!(f, "Domain"),
        }
    }
}

/// Represents the type of relationship between two entities.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RelationType {
    Auth,
    Connect,
    Execute,
    Read,
    Write,
    DNS,
}

impl fmt::Display for RelationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelationType::Auth => write!(f, "Auth"),
            RelationType::Connect => write!(f, "Connect"),
            RelationType::Execute => write!(f, "Execute"),
            RelationType::Read => write!(f, "Read"),
            RelationType::Write => write!(f, "Write"),
            RelationType::DNS => write!(f, "DNS"),
        }
    }
}
