use chrono::NaiveDateTime;
use rayon::prelude::*;
use serde_json::Value;

use crate::entity::Entity;
use crate::parser::{LogParser, ParsedTriple};
use crate::relation::Relation;
use crate::types::{EntityType, RelationType};

/// Parser for Sysmon events exported as JSON.
///
/// Supports the following Sysmon Event IDs:
///
/// | Event ID | Name               | Triples Produced                                |
/// |----------|--------------------|-------------------------------------------------|
/// | 1        | Process Create     | User -[Execute]-> Process, Process -[Execute]-> Process (parent→child) |
/// | 3        | Network Connection | Host -[Connect]-> IP (destination)              |
/// | 11       | File Create        | Process -[Write]-> File                         |
/// | 22       | DNS Query          | Process -[DNS]-> Domain                         |
///
/// # Expected JSON Format
///
/// The parser accepts either:
/// - A JSON array of event objects: `[{...}, {...}]`
/// - Newline-delimited JSON (NDJSON): one event per line
///
/// Each event object must have an `EventID` (integer) field and the corresponding
/// Sysmon fields (e.g., `Image`, `User`, `SourceIp`, etc.).
///
/// Timestamps are parsed from the `UtcTime` field using the Sysmon format
/// `"YYYY-MM-DD HH:MM:SS.fff"` and converted to Unix epoch seconds.
pub struct SysmonJsonParser;

impl SysmonJsonParser {
    /// Parses a Sysmon UTC timestamp string into Unix epoch seconds.
    ///
    /// Sysmon format: "2024-01-15 14:30:00.123"
    fn parse_timestamp(utc_time: &str) -> Option<i64> {
        // Try full precision first, then fall back to no fractional seconds
        let trimmed = utc_time.trim();
        NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S%.f")
            .or_else(|_| NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S"))
            .map(|dt| dt.and_utc().timestamp())
            .ok()
    }

    /// Extracts a non-empty string from a JSON value, returning None for
    /// missing, null, or empty-string fields.
    fn extract_str<'a>(event: &'a Value, key: &str) -> Option<&'a str> {
        event
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }

    /// Parses a single Sysmon event object into zero or more triples.
    fn parse_event(event: &Value) -> Vec<ParsedTriple> {
        let event_id = match event.get("EventID").and_then(|v| v.as_u64()) {
            Some(id) => id,
            None => return Vec::new(),
        };

        let timestamp = Self::extract_str(event, "UtcTime")
            .and_then(Self::parse_timestamp)
            .unwrap_or(0);

        match event_id {
            1 => Self::parse_process_create(event, timestamp),
            3 => Self::parse_network_connection(event, timestamp),
            11 => Self::parse_file_create(event, timestamp),
            22 => Self::parse_dns_query(event, timestamp),
            _ => Vec::new(), // Unsupported event ID — skip silently
        }
    }

    /// Event 1: Process Create
    ///
    /// Produces:
    /// - User -[Execute]-> Process (child)
    /// - Process (parent) -[Execute]-> Process (child)
    fn parse_process_create(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let mut triples = Vec::new();

        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return triples,
        };

        // Build child process entity with metadata
        let mut child = Entity::new(image, EntityType::Process);
        if let Some(pid) = event.get("ProcessId").and_then(|v| v.as_u64()) {
            child.metadata.insert("pid".into(), pid.to_string());
        }
        if let Some(cmdline) = Self::extract_str(event, "CommandLine") {
            child.metadata.insert("cmdline".into(), cmdline.into());
        }
        if let Some(computer) = Self::extract_str(event, "Computer") {
            child.metadata.insert("computer".into(), computer.into());
        }

        // Triple 1: User -[Execute]-> Process
        if let Some(user_name) = Self::extract_str(event, "User") {
            let user_entity = Entity::new(user_name, EntityType::User);
            let rel = Relation::new(&user_entity.id, &child.id, RelationType::Execute, timestamp);
            triples.push((user_entity, rel, child.clone()));
        }

        // Triple 2: ParentProcess -[Execute]-> ChildProcess
        if let Some(parent_image) = Self::extract_str(event, "ParentImage") {
            let mut parent = Entity::new(parent_image, EntityType::Process);
            if let Some(ppid) = event.get("ParentProcessId").and_then(|v| v.as_u64()) {
                parent.metadata.insert("pid".into(), ppid.to_string());
            }
            let rel = Relation::new(&parent.id, &child.id, RelationType::Execute, timestamp);
            triples.push((parent, rel, child));
        }

        triples
    }

    /// Event 3: Network Connection
    ///
    /// Produces: Host (source computer) -[Connect]-> IP (destination)
    fn parse_network_connection(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let dest_ip = match Self::extract_str(event, "DestinationIp") {
            Some(v) => v,
            None => return Vec::new(),
        };

        // Source is the computer/host generating the event
        let source_name = Self::extract_str(event, "Computer")
            .or_else(|| Self::extract_str(event, "SourceHostname"))
            .unwrap_or("unknown-host");

        let mut source = Entity::new(source_name, EntityType::Host);
        if let Some(src_ip) = Self::extract_str(event, "SourceIp") {
            source.metadata.insert("source_ip".into(), src_ip.into());
        }
        if let Some(src_port) = Self::extract_str(event, "SourcePort") {
            source.metadata.insert("source_port".into(), src_port.into());
        }

        let mut dest = Entity::new(dest_ip, EntityType::IP);
        if let Some(dst_port) = Self::extract_str(event, "DestinationPort") {
            dest.metadata.insert("dest_port".into(), dst_port.into());
        }
        if let Some(dst_host) = Self::extract_str(event, "DestinationHostname") {
            dest.metadata.insert("hostname".into(), dst_host.into());
        }
        if let Some(proto) = Self::extract_str(event, "Protocol") {
            dest.metadata.insert("protocol".into(), proto.into());
        }

        let mut rel = Relation::new(&source.id, &dest.id, RelationType::Connect, timestamp);
        if let Some(image) = Self::extract_str(event, "Image") {
            rel.metadata.insert("image".into(), image.into());
        }

        vec![(source, rel, dest)]
    }

    /// Event 11: File Create
    ///
    /// Produces: Process -[Write]-> File
    fn parse_file_create(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let target = match Self::extract_str(event, "TargetFilename") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(image, EntityType::Process);
        let mut file = Entity::new(target, EntityType::File);
        if let Some(hash) = Self::extract_str(event, "Hashes") {
            file.metadata.insert("hashes".into(), hash.into());
        }

        let rel = Relation::new(&process.id, &file.id, RelationType::Write, timestamp);
        vec![(process, rel, file)]
    }

    /// Event 22: DNS Query
    ///
    /// Produces: Process -[DNS]-> Domain
    fn parse_dns_query(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let query_name = match Self::extract_str(event, "QueryName") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(image, EntityType::Process);
        let mut domain = Entity::new(query_name, EntityType::Domain);
        if let Some(result) = Self::extract_str(event, "QueryResults") {
            domain.metadata.insert("query_results".into(), result.into());
        }
        if let Some(qtype) = Self::extract_str(event, "QueryType") {
            domain.metadata.insert("query_type".into(), qtype.into());
        }

        let rel = Relation::new(&process.id, &domain.id, RelationType::DNS, timestamp);
        vec![(process, rel, domain)]
    }
}

impl LogParser for SysmonJsonParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let trimmed = data.trim();

        // Try JSON array first
        if trimmed.starts_with('[') {
            if let Ok(events) = serde_json::from_str::<Vec<Value>>(trimmed) {
                return events
                    .par_iter()
                    .flat_map(|event| Self::parse_event(event))
                    .collect();
            }
        }

        // Fall back to NDJSON (one JSON object per line)
        let lines: Vec<&str> = trimmed.lines().filter(|l| !l.trim().is_empty()).collect();
        lines
            .par_iter()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .flat_map(|event| Self::parse_event(&event))
            .collect()
    }
}
