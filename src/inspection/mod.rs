
pub mod packet;
pub mod rules;

// Re-export only what's actually needed
pub use packet::{ProtocolParser, ParsedPacket, PacketError, FixParser, BinaryParser, validate_packet_length, PacketHeader, PacketTrailer};
pub use rules::{RuleEngine, RuleMatch};

use crate::config::{MatchPattern, FixParserConfig};
use std::net::SocketAddr;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct InspectionResult {
    pub is_valid: bool,
    pub message_length: usize,
    pub matches_patterns: Vec<String>,
    pub violations: Vec<String>,
    pub parsed_packets: Vec<ParsedPacket>,
    pub rule_matches: Vec<RuleMatch>,
    pub anomalies: Vec<String>,
    pub fix_inspected_tags: Option<std::collections::HashMap<u32, String>>,
}

pub struct PacketInspector {
    rules: Vec<MatchPattern>,
    rule_engine: RuleEngine,
    fix_parser: FixParser,
}

impl PacketInspector {
    pub fn new(rules: Vec<MatchPattern>, fix_config: FixParserConfig) -> Self {
        Self {
            rules,
            rule_engine: RuleEngine::new(),
            fix_parser: FixParser::new(fix_config),
        }
    }

    pub fn with_default_config(rules: Vec<MatchPattern>) -> Self {
        Self {
            rules,
            rule_engine: RuleEngine::new(),
            fix_parser: FixParser::with_default_config(),
        }
    }

    pub async fn inspect(&self, data: &[u8], source: &SocketAddr) -> InspectionResult {
        let mut result = InspectionResult {
            is_valid: true,
            message_length: data.len(),
            matches_patterns: Vec::new(),
            violations: Vec::new(),
            parsed_packets: Vec::new(),
            rule_matches: Vec::new(),
            anomalies: Vec::new(),
            fix_inspected_tags: None,
        };

        debug!("Inspecting packet from {}: {} bytes", source, data.len());

        let parsers: Vec<Box<dyn ProtocolParser>> = vec![
            Box::new(FixParser::new(self.fix_parser.config.clone())),
            Box::new(BinaryParser::new(8, 4)),
        ];

        for parser in parsers {
            match parser.parse_packet(data) {
                Ok(parsed) => {
                    debug!("Parser succeeded for packet from {}", source);

                    if let Some(ref inspected_tags) = parsed.inspected_tags {
                        result.fix_inspected_tags = Some(inspected_tags.clone());
                        debug!("FIX tags inspected: {:?}", inspected_tags.keys());
                    }

                    result.parsed_packets.push(parsed);
                }
                Err(e) => {
                    debug!("Parser failed for packet from {}: {}", source, e);
                    result.violations.push(format!("Parser error: {}", e));
                }
            }
        }

        result.rule_matches = self.rule_engine.evaluate_rules(data, source, &self.rules);
        debug!("Rule matches for {}: {:?}", source, result.rule_matches);

        result.anomalies = self.rule_engine.detect_anomalies(data, source);

        if let Err(e) = validate_packet_length(data, 1, 4096) {
            result.is_valid = false;
            result.violations.push(format!("Length validation: {}", e));
        }

        let checksum_valid = self.rule_engine.parsers.iter().any(|parser| parser.validate_checksum(data));
        if !checksum_valid {
            debug!("Checksum validation failed for packet from {}", source);
            result.violations.push("Checksum validation failed".to_string());
        } else {
            debug!("Checksum validation passed for packet from {}", source);
        }

        for parser in &self.rule_engine.parsers {
            if let Some(msg_type) = parser.extract_msg_type(data) {
                debug!("Extracted message type '{}' for packet from {}", msg_type, source);
                result.matches_patterns.push(msg_type);
            }
        }

        debug!("Inspection result for {}: valid={}, matches={:?}, inspected_tags={:?}",
               source, result.is_valid, result.matches_patterns, result.fix_inspected_tags);

        result
    }
}