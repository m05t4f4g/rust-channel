use crate::config::MatchPattern;
use crate::inspection::{ProtocolParser, ParsedPacket, PacketError}; // Use re-exported types
use std::net::SocketAddr;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_name: String,
    pub matched: bool,
    pub details: String,
}

pub struct RuleEngine {
    pub parsers: Vec<Box<dyn ProtocolParser>>,
    blacklisted_ips: HashSet<std::net::IpAddr>,
    whitelisted_ips: HashSet<std::net::IpAddr>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            parsers: vec![
                Box::new(crate::inspection::FixParser::with_default_config()), // Use re-exported type
                Box::new(crate::inspection::BinaryParser::new(8, 4)), // Use re-exported type
            ],
            blacklisted_ips: HashSet::new(),
            whitelisted_ips: HashSet::new(),
        }
    }

    // ... rest of your RuleEngine implementation remains the same ...
    pub fn add_parser<P: ProtocolParser + 'static>(&mut self, parser: P) {
        self.parsers.push(Box::new(parser));
    }

    pub fn blacklist_ip(&mut self, ip: std::net::IpAddr) {
        self.blacklisted_ips.insert(ip);
        self.whitelisted_ips.remove(&ip);
    }

    pub fn whitelist_ip(&mut self, ip: std::net::IpAddr) {
        self.whitelisted_ips.insert(ip);
        self.blacklisted_ips.remove(&ip);
    }

    pub fn evaluate_rules(
        &self,
        data: &[u8],
        source_addr: &SocketAddr,
        patterns: &[MatchPattern],
    ) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        // IP-based rules
        if self.blacklisted_ips.contains(&source_addr.ip()) {
            matches.push(RuleMatch {
                rule_name: "ip_blacklist".to_string(),
                matched: true,
                details: format!("IP {} is blacklisted", source_addr.ip()),
            });
            return matches;
        }

        if self.whitelisted_ips.contains(&source_addr.ip()) {
            matches.push(RuleMatch {
                rule_name: "ip_whitelist".to_string(),
                matched: true,
                details: format!("IP {} is whitelisted", source_addr.ip()),
            });
        }

        // Parse packet with available parsers
        let parsed_packets: Vec<Result<ParsedPacket, PacketError>> = self
            .parsers
            .iter()
            .map(|parser| parser.parse_packet(data))
            .collect();

        // Evaluate each pattern against parsed packets
        for (i, pattern) in patterns.iter().enumerate() {
            let rule_name = format!("rule_{}", i);

            if let Some(match_result) = self.evaluate_pattern(&parsed_packets, pattern, source_addr) {
                matches.push(RuleMatch {
                    rule_name,
                    matched: match_result.0,
                    details: match_result.1,
                });
            }
        }

        matches
    }

    fn evaluate_pattern(
        &self,
        parsed_packets: &[Result<ParsedPacket, PacketError>],
        pattern: &MatchPattern,
        source_addr: &SocketAddr,
    ) -> Option<(bool, String)> {
        let mut details = String::new();

        // Check message type pattern
        if let Some(ref expected_msg_type) = pattern.msg_type {
            let mut msg_type_matched = false;

            for parsed in parsed_packets {
                if let Ok(packet) = parsed {
                    if let Some(ref header) = packet.header {
                        if header.msg_type == *expected_msg_type {
                            msg_type_matched = true;
                            details.push_str(&format!("Msg type '{}' matched", expected_msg_type));
                            break;
                        }
                    }
                }
            }

            if !msg_type_matched {
                return Some((false, "Message type mismatch".to_string()));
            }
        }

        // Check length patterns
        for parsed in parsed_packets {
            if let Ok(packet) = parsed {
                let total_len = packet.payload.len()
                    + packet.header.as_ref().map_or(0, |_| 8)
                    + packet.trailer.as_ref().map_or(0, |_| 4);

                if let Some(min_len) = pattern.min_length {
                    if total_len < min_len {
                        return Some((false, format!("Packet too short: {} < {}", total_len, min_len)));
                    }
                }

                if let Some(max_len) = pattern.max_length {
                    if total_len > max_len {
                        return Some((false, format!("Packet too long: {} > {}", total_len, max_len)));
                    }
                }
            }
        }

        // Check source IP pattern
        if let Some(ref expected_ip) = pattern.source_ip {
            if &source_addr.ip().to_string() != expected_ip {
                return Some((false, format!("Source IP mismatch: {} != {}", source_addr.ip(), expected_ip)));
            }
        }

        Some((true, if details.is_empty() { "Pattern matched".to_string() } else { details }))
    }

    pub fn validate_timestamp(&self, timestamp: u64, max_skew_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        (now as i64 - timestamp as i64).abs() <= max_skew_secs as i64
    }

    pub fn detect_anomalies(&self, data: &[u8], _source_addr: &SocketAddr) -> Vec<String> {
        let mut anomalies = Vec::new();

        if data.len() > 4096 {
            anomalies.push("Oversized packet".to_string());
        }

        if data.iter().all(|&b| b == 0) {
            anomalies.push("All-zero payload".to_string());
        }

        if data.windows(4).any(|window| window == b"\x00\x00\x00\x00") {
            anomalies.push("Contains null padding".to_string());
        }

        anomalies
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}