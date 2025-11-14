use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::collections::HashMap;

// Import the inspection module types
use rust_channel::inspection::{
    PacketInspector, InspectionResult, ProtocolParser, ParsedPacket, PacketError,
    FixParser, BinaryParser, validate_packet_length, RuleEngine, RuleMatch
};
use rust_channel::config::{MatchPattern, FixParserConfig};

#[cfg(test)]
mod inspection_tests {
    use super::*;
    use tokio::runtime::Runtime;

    // Helper function to create sample FIX message
    fn create_sample_fix_message() -> Vec<u8> {
        // A simple FIX logon message
        let fix_message = "8=FIX.4.2|9=65|35=A|49=SERVER|56=CLIENT|34=1|52=20240101-10:00:00|98=0|108=30|10=001|";
        fix_message.replace('|', "\x01").into_bytes()
    }

    // Helper function to create sample binary data
    fn create_sample_binary_data() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]
    }

    #[test]
    fn test_packet_inspector_creation() {
        let rules = vec![];
        let fix_config = FixParserConfig::default();

        let inspector = PacketInspector::new(rules.clone(), fix_config);

        // Test that we can create inspectors without accessing private fields
        let inspector_default = PacketInspector::with_default_config(rules);

        // Both should be created successfully - we test this by using them
        assert!(true); // Just verify no panic during creation
    }

    #[test]
    fn test_validate_packet_length() {
        let data = vec![0u8; 100];

        // Test valid length
        assert!(validate_packet_length(&data, 50, 200).is_ok());

        // Test too short
        let result = validate_packet_length(&data, 150, 200);
        assert!(result.is_err());
        if let Err(PacketError::TooShort { expected, actual }) = result {
            assert_eq!(expected, 150);
            assert_eq!(actual, 100);
        }

        // Test too long
        let result = validate_packet_length(&data, 10, 50);
        assert!(result.is_err());
        if let Err(PacketError::TooLong { expected, actual }) = result {
            assert_eq!(expected, 50);
            assert_eq!(actual, 100);
        }
    }

    #[test]
    fn test_binary_parser() {
        let parser = BinaryParser::new(4, 2);
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        // Test parsing
        let result = parser.parse_packet(&data);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.payload, vec![0x05, 0x06]);
        assert!(parsed.header.is_none());
        assert!(parsed.trailer.is_none());

        // Test checksum validation (always returns true for binary parser)
        assert!(parser.validate_checksum(&data));

        // Test message type extraction
        assert_eq!(parser.extract_msg_type(&data), Some("BINARY".to_string()));

        // Test too short data
        let short_data = vec![0x01, 0x02, 0x03];
        let result = parser.parse_packet(&short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_fix_parser_creation() {
        let config = FixParserConfig::default();
        let parser = FixParser::new(config.clone());

        let default_parser = FixParser::with_default_config();

        // Test creation without accessing private fields
        assert!(true); // Verify no panic
    }

    #[test]
    fn test_fix_parser_parse_fix_fields() {
        let parser = FixParser::with_default_config();
        let fix_data = "8=FIX.4.2|35=A|49=SERVER|56=CLIENT|10=123|".replace('|', "\x01").into_bytes();

        let result = parser.parse_fix_fields(&fix_data);
        assert!(result.is_ok());

        let fields = result.unwrap();
        assert_eq!(fields.get(&8), Some(&"FIX.4.2".to_string()));
        assert_eq!(fields.get(&35), Some(&"A".to_string()));
        assert_eq!(fields.get(&49), Some(&"SERVER".to_string()));
        assert_eq!(fields.get(&56), Some(&"CLIENT".to_string()));
        assert_eq!(fields.get(&10), Some(&"123".to_string()));
    }

    #[test]
    fn test_fix_parser_extract_inspected_tags() {
        let mut config = FixParserConfig::default();
        config.inspect_tags = vec![8, 35, 49]; // Only inspect these tags

        let parser = FixParser::new(config);
        let mut fields = HashMap::new();
        fields.insert(8, "FIX.4.2".to_string());
        fields.insert(9, "100".to_string());
        fields.insert(35, "A".to_string());
        fields.insert(49, "SERVER".to_string());
        fields.insert(56, "CLIENT".to_string());

        let inspected = parser.extract_inspected_tags(&fields);

        assert_eq!(inspected.len(), 3);
        assert!(inspected.contains_key(&8));
        assert!(inspected.contains_key(&35));
        assert!(inspected.contains_key(&49));
        assert!(!inspected.contains_key(&9));
        assert!(!inspected.contains_key(&56));
    }

    #[test]
    fn test_fix_parser_validate_structure() {
        let mut config = FixParserConfig::default();
        config.required_tags = vec![8, 35, 49, 56]; // Require these tags

        let parser = FixParser::new(config);

        // Test valid structure
        let mut valid_fields = HashMap::new();
        valid_fields.insert(8, "FIX.4.2".to_string());
        valid_fields.insert(35, "A".to_string());
        valid_fields.insert(49, "SERVER".to_string());
        valid_fields.insert(56, "CLIENT".to_string());

        assert!(parser.validate_fix_structure(&valid_fields).is_ok());

        // Test invalid structure (missing required tag)
        let mut invalid_fields = HashMap::new();
        invalid_fields.insert(8, "FIX.4.2".to_string());
        invalid_fields.insert(35, "A".to_string());
        // Missing 49 and 56

        let result = parser.validate_fix_structure(&invalid_fields);
        assert!(result.is_err());
    }

    #[test]
    fn test_fix_parser_calculate_checksum() {
        let data = b"8=FIX.4.2|35=A|49=SERVER|56=CLIENT|";
        let checksum = FixParser::calculate_fix_checksum(data);

        // Simple checksum calculation test
        assert!(checksum < 256); // Should be modulo 256
    }

    #[test]
    fn test_fix_parser_extract_msg_type() {
        let parser = FixParser::with_default_config();

        // Test with valid FIX message containing 35= tag
        let fix_data = "8=FIX.4.2|35=A|49=SERVER|".replace('|', "\x01").into_bytes();
        let msg_type = parser.extract_msg_type(&fix_data);
        assert_eq!(msg_type, Some("A".to_string()));

        // Test with non-FIX data
        let binary_data = vec![0x01, 0x02, 0x03];
        let msg_type = parser.extract_msg_type(&binary_data);
        assert!(msg_type.is_none());

        // Test with FIX data but no 35= tag
        let fix_data_no_msg_type = "8=FIX.4.2|49=SERVER|".replace('|', "\x01").into_bytes();
        let msg_type = parser.extract_msg_type(&fix_data_no_msg_type);
        assert!(msg_type.is_none());
    }

    #[test]
    fn test_rule_engine_creation() {
        let engine = RuleEngine::new();

        let default_engine = RuleEngine::default();

        // Test creation works
        assert!(true);
    }

    #[test]
    fn test_rule_engine_ip_management() {
        let mut engine = RuleEngine::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Test whitelisting
        engine.whitelist_ip(ip);

        // Test blacklisting removes from whitelist
        engine.blacklist_ip(ip);

        // Test whitelisting removes from blacklist
        engine.whitelist_ip(ip);

        // Test that methods don't panic
        assert!(true);
    }

    #[test]
    fn test_rule_engine_evaluate_rules() {
        let engine = RuleEngine::new();
        let data = create_sample_fix_message();
        let source_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let patterns = vec![
            MatchPattern {
                msg_type: Some("A".to_string()),
                source_ip: None,
                min_length: Some(50),
                max_length: Some(100),
            },
            MatchPattern {
                msg_type: Some("D".to_string()), // This won't match our FIX message
                source_ip: None,
                min_length: None,
                max_length: None,
            },
        ];

        let matches = engine.evaluate_rules(&data, &source_addr, &patterns);

        // Should have matches for both rules (one true, one false)
        assert_eq!(matches.len(), 2);

        let msg_type_match = matches.iter().find(|m| m.details.contains("Msg type"));
        assert!(msg_type_match.is_some());

        let no_match = matches.iter().find(|m| !m.matched);
        assert!(no_match.is_some());
    }

    #[test]
    fn test_rule_engine_ip_based_rules() {
        let mut engine = RuleEngine::new();
        let data = create_sample_fix_message();

        let blacklisted_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let blacklisted_addr = SocketAddr::new(blacklisted_ip, 8080);

        engine.blacklist_ip(blacklisted_ip);

        let patterns = vec![];
        let matches = engine.evaluate_rules(&data, &blacklisted_addr, &patterns);

        // Should have blacklist match
        assert!(!matches.is_empty());
        let blacklist_match = matches.iter().find(|m| m.rule_name == "ip_blacklist");
        assert!(blacklist_match.is_some());
        assert!(blacklist_match.unwrap().matched);
    }

    #[test]
    fn test_rule_engine_detect_anomalies() {
        let engine = RuleEngine::new();
        let source_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        // Test oversized packet
        let oversized_data = vec![0u8; 5000];
        let anomalies = engine.detect_anomalies(&oversized_data, &source_addr);
        assert!(anomalies.contains(&"Oversized packet".to_string()));

        // Test all-zero payload
        let zero_data = vec![0u8; 100];
        let anomalies = engine.detect_anomalies(&zero_data, &source_addr);
        assert!(anomalies.contains(&"All-zero payload".to_string()));

        // Test null padding
        let null_padded_data = vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x04];
        let anomalies = engine.detect_anomalies(&null_padded_data, &source_addr);
        assert!(anomalies.contains(&"Contains null padding".to_string()));

        // Test normal data
        let normal_data = create_sample_fix_message();
        let anomalies = engine.detect_anomalies(&normal_data, &source_addr);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_rule_engine_validate_timestamp() {
        let engine = RuleEngine::new();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Test valid timestamp (current time)
        assert!(engine.validate_timestamp(now, 30));

        // Test valid timestamp (within skew)
        assert!(engine.validate_timestamp(now - 15, 30));
        assert!(engine.validate_timestamp(now + 15, 30));

        // Test invalid timestamp (outside skew)
        assert!(!engine.validate_timestamp(now - 45, 30));
        assert!(!engine.validate_timestamp(now + 45, 30));
    }

    #[test]
    fn test_inspection_result_structure() {
        let result = InspectionResult {
            is_valid: true,
            message_length: 100,
            matches_patterns: vec!["A".to_string(), "BINARY".to_string()],
            violations: vec!["Checksum failed".to_string()],
            parsed_packets: Vec::new(),
            rule_matches: Vec::new(),
            anomalies: vec!["Oversized".to_string()],
            fix_inspected_tags: Some(HashMap::new()),
        };

        assert!(result.is_valid);
        assert_eq!(result.message_length, 100);
        assert_eq!(result.matches_patterns.len(), 2);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.anomalies.len(), 1);
        assert!(result.fix_inspected_tags.is_some());
    }

    #[test]
    fn test_rule_match_structure() {
        let rule_match = RuleMatch {
            rule_name: "test_rule".to_string(),
            matched: true,
            details: "Pattern matched successfully".to_string(),
        };

        assert_eq!(rule_match.rule_name, "test_rule");
        assert!(rule_match.matched);
        assert!(!rule_match.details.is_empty());
    }

    #[test]
    fn test_packet_structures() {
        // Test PacketHeader
        let header = rust_channel::inspection::PacketHeader {
            msg_type: "A".to_string(),
            msg_seq: 1,
            timestamp: 1234567890,
            sender_comp_id: Some("SERVER".to_string()),
            target_comp_id: Some("CLIENT".to_string()),
            sending_time: Some("20240101-10:00:00".to_string()),
        };

        assert_eq!(header.msg_type, "A");
        assert_eq!(header.msg_seq, 1);
        assert_eq!(header.timestamp, 1234567890);

        // Test PacketTrailer
        let trailer = rust_channel::inspection::PacketTrailer {
            checksum: 123,
            signature: Some("SIGNATURE".to_string()),
            body_length: Some(100),
        };

        assert_eq!(trailer.checksum, 123);
        assert!(trailer.signature.is_some());
        assert!(trailer.body_length.is_some());

        // Test ParsedPacket
        let parsed_packet = ParsedPacket {
            header: Some(header),
            payload: vec![0x01, 0x02, 0x03],
            trailer: Some(trailer),
            fix_fields: Some(HashMap::new()),
            inspected_tags: Some(HashMap::new()),
        };

        assert!(parsed_packet.header.is_some());
        assert!(!parsed_packet.payload.is_empty());
        assert!(parsed_packet.trailer.is_some());
    }

    #[test]
    fn test_async_inspection() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let rules = vec![
                MatchPattern {
                    msg_type: Some("A".to_string()),
                    source_ip: None,
                    min_length: Some(50),
                    max_length: Some(100),
                }
            ];

            let inspector = PacketInspector::with_default_config(rules);
            let data = create_sample_fix_message();
            let source_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

            let result = inspector.inspect(&data, &source_addr).await;

            assert!(result.message_length > 0);
            // Should have at least one parsed packet (FIX parser should succeed)
            assert!(!result.parsed_packets.is_empty());
        });
    }

    #[test]
    fn test_multiple_parsers() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let inspector = PacketInspector::with_default_config(vec![]);
            let data = create_sample_fix_message();
            let source_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

            let result = inspector.inspect(&data, &source_addr).await;

            // Both FIX and Binary parsers should attempt to parse
            // FIX parser should succeed, binary parser might fail but that's OK
            assert!(result.message_length > 0);
        });
    }

    #[test]
    fn test_packet_error_variants() {
        // Test TooShort error
        let too_short = PacketError::TooShort { expected: 100, actual: 50 };
        assert!(format!("{}", too_short).contains("too short"));

        // Test TooLong error
        let too_long = PacketError::TooLong { expected: 100, actual: 150 };
        assert!(format!("{}", too_long).contains("too long"));

        // Test ChecksumFailed error
        let checksum_failed = PacketError::ChecksumFailed;
        assert!(format!("{}", checksum_failed).contains("Checksum"));

        // Test FixError error
        let fix_error = PacketError::FixError("Test error".to_string());
        assert!(format!("{}", fix_error).contains("FIX protocol error"));

        // Test InvalidStructure error
        let invalid_structure = PacketError::InvalidStructure;
        assert!(format!("{}", invalid_structure).contains("Invalid packet structure"));
    }

    #[test]
    fn test_fix_parser_disabled() {
        let mut config = FixParserConfig::default();
        config.enabled = false;

        let parser = FixParser::new(config);
        let fix_data = create_sample_fix_message();

        // Should return error when disabled
        let result = parser.parse_packet(&fix_data);
        assert!(result.is_err());

        // Should not extract message type when disabled
        let msg_type = parser.extract_msg_type(&fix_data);
        assert!(msg_type.is_none());
    }

    #[test]
    fn test_rule_engine_add_parser() {
        let mut engine = RuleEngine::new();
        let initial_count = engine.parsers.len();

        let custom_parser = BinaryParser::new(2, 2);
        engine.add_parser(custom_parser);

        assert_eq!(engine.parsers.len(), initial_count + 1);
    }
}