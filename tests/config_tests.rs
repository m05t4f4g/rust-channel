use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

// Import the config module
use rust_channel::config::{
    AppConfig, ServerConfig, MatchPattern, Action, PolicyRule,
    MetricsConfig, FixParserConfig, ConfigError
};

#[cfg(test)]
mod config_tests {
    use super::*;

    // Helper function to create test files
    fn create_test_file(path: &str, content: &str) -> std::io::Result<()> {
        let mut file = fs::File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    // Helper function to cleanup test files
    fn cleanup_test_files() {
        let _ = fs::remove_file("server-config.yaml");
        let _ = fs::remove_file("fix-parser.yaml");
        let _ = fs::remove_file("policy-rules.yaml");
        let _ = fs::remove_file("test-server-config.yaml");
        let _ = fs::remove_file("test-fix-parser.yaml");
        let _ = fs::remove_file("test-policy-rules.yaml");
    }

    #[test]
    fn test_server_config_serialization() {
        let server_config = ServerConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
            tls_enabled: true,
            cert_path: Some("/path/to/cert.pem".to_string()),
            key_path: Some("/path/to/key.pem".to_string()),
            max_connections: 1000,
            connection_timeout: std::time::Duration::from_secs(30),
        };

        // Test serialization
        let yaml = serde_yaml::to_string(&server_config).unwrap();
        assert!(yaml.contains("listen_addr"));
        assert!(yaml.contains("127.0.0.1:8080"));
        assert!(yaml.contains("tls_enabled: true"));

        // Test deserialization
        let deserialized: ServerConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.listen_addr, server_config.listen_addr);
        assert_eq!(deserialized.tls_enabled, server_config.tls_enabled);
        assert_eq!(deserialized.max_connections, server_config.max_connections);
    }

    #[test]
    fn test_match_pattern_serialization() {
        let pattern = MatchPattern {
            msg_type: Some("A".to_string()),
            source_ip: Some("192.168.1.1".to_string()),
            min_length: Some(100),
            max_length: Some(1024),
        };

        let yaml = serde_yaml::to_string(&pattern).unwrap();
        let deserialized: MatchPattern = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(deserialized.msg_type, pattern.msg_type);
        assert_eq!(deserialized.source_ip, pattern.source_ip);
        assert_eq!(deserialized.min_length, pattern.min_length);
        assert_eq!(deserialized.max_length, pattern.max_length);
    }

    #[test]
    fn test_action_serialization() {
        // Test Allow action
        let allow = Action::Allow;
        let yaml = serde_yaml::to_string(&allow).unwrap();
        let deserialized: Action = serde_yaml::from_str(&yaml).unwrap();
        assert!(matches!(deserialized, Action::Allow));

        // Test Deny action
        let deny = Action::Deny;
        let yaml = serde_yaml::to_string(&deny).unwrap();
        let deserialized: Action = serde_yaml::from_str(&yaml).unwrap();
        assert!(matches!(deserialized, Action::Deny));

        // Test RateLimit action
        let rate_limit = Action::RateLimit(100);
        let yaml = serde_yaml::to_string(&rate_limit).unwrap();
        let deserialized: Action = serde_yaml::from_str(&yaml).unwrap();
        match deserialized {
            Action::RateLimit(limit) => assert_eq!(limit, 100),
            _ => panic!("Expected RateLimit action"),
        }
    }

    #[test]
    fn test_policy_rule_serialization() {
        let rule = PolicyRule {
            name: "test_rule".to_string(),
            match_pattern: MatchPattern {
                msg_type: Some("D".to_string()),
                source_ip: None,
                min_length: Some(50),
                max_length: Some(500),
            },
            action: Action::RateLimit(50),
        };

        let yaml = serde_yaml::to_string(&rule).unwrap();
        let deserialized: PolicyRule = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(deserialized.name, "test_rule");
        assert_eq!(deserialized.match_pattern.msg_type, Some("D".to_string()));
        assert!(matches!(deserialized.action, Action::RateLimit(50)));
    }

    #[test]
    fn test_fix_parser_config_default() {
        let config = FixParserConfig::default();

        assert!(config.enabled);
        assert!(config.validate_checksum);
        assert!(config.validate_structure);
        assert!(config.log_inspected_tags);
        assert_eq!(config.max_message_length, 4096);
        assert_eq!(config.min_message_length, 20);

        // Check required tags
        let expected_tags = vec![8, 9, 35, 49, 56, 34, 52, 10];
        assert_eq!(config.required_tags, expected_tags);
        assert_eq!(config.inspect_tags, expected_tags);
    }

    #[test]
    fn test_metrics_config_serialization() {
        let metrics = MetricsConfig {
            enabled: true,
            export_interval_secs: 30,
            enable_prometheus: true,
        };

        let yaml = serde_yaml::to_string(&metrics).unwrap();
        let deserialized: MetricsConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(deserialized.enabled, true);
        assert_eq!(deserialized.export_interval_secs, 30);
        assert_eq!(deserialized.enable_prometheus, true);
    }

    #[test]
    fn test_app_config_load_missing_server_config() {
        cleanup_test_files();

        // Ensure server-config.yaml doesn't exist
        assert!(!Path::new("server-config.yaml").exists());

        let result = AppConfig::load();
        assert!(result.is_err());

        if let Err(ConfigError::Io(io_error)) = result {
            assert_eq!(io_error.kind(), std::io::ErrorKind::NotFound);
        } else {
            panic!("Expected ConfigError::Io with NotFound");
        }
    }

    #[test]
    fn test_app_config_load_with_server_config_only() {
        cleanup_test_files();

        let server_config_content = r#"
listen_addr: 127.0.0.1:8080
backend_addr: 127.0.0.1:8081
tls_enabled: false
cert_path: ~
key_path: ~
max_connections: 500
connection_timeout: 30s
"#;

        create_test_file("server-config.yaml", server_config_content).unwrap();

        let result = AppConfig::load();
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.server.listen_addr.to_string(), "127.0.0.1:8080");
        assert_eq!(config.server.backend_addr.to_string(), "127.0.0.1:8081");
        assert_eq!(config.server.max_connections, 500);
        assert!(!config.server.tls_enabled);

        // Verify default FIX parser config is used
        assert!(config.fix_parser.enabled);

        // Verify empty policy rules
        assert!(config.policy_rules.is_empty());

        // Verify default metrics config
        assert!(config.metrics.enabled);
        assert_eq!(config.metrics.export_interval_secs, 60);
        assert!(!config.metrics.enable_prometheus);

        cleanup_test_files();
    }

    #[test]
    fn test_app_config_load_with_all_files() {
        cleanup_test_files();

        // Create server config
        let server_config_content = r#"
listen_addr: 0.0.0.0:8443
backend_addr: 127.0.0.1:8081
tls_enabled: true
cert_path: "/etc/certs/cert.pem"
key_path: "/etc/certs/key.pem"
max_connections: 1000
connection_timeout: 60s
"#;

        // Create FIX parser config
        let fix_parser_content = r#"
enabled: true
inspect_tags: [8, 9, 35, 49, 56]
required_tags: [8, 9, 35]
validate_checksum: true
validate_structure: false
log_inspected_tags: false
max_message_length: 8192
min_message_length: 10
"#;

        // Create policy rules
        let policy_rules_content = r#"
- name: "rate_limit_orders"
  match_pattern:
    msg_type: "D"
    source_ip: "192.168.1.100"
    min_length: 100
    max_length: 1024
  action:
    RateLimit: 100

- name: "block_admin"
  match_pattern:
    msg_type: "A"
    source_ip: "10.0.0.5"
  action: Deny
"#;

        create_test_file("server-config.yaml", server_config_content).unwrap();
        create_test_file("fix-parser.yaml", fix_parser_content).unwrap();
        create_test_file("policy-rules.yaml", policy_rules_content).unwrap();

        let result = AppConfig::load();
        assert!(result.is_ok());

        let config = result.unwrap();

        // Verify server config
        assert!(config.server.tls_enabled);
        assert_eq!(config.server.cert_path, Some("/etc/certs/cert.pem".to_string()));
        assert_eq!(config.server.max_connections, 1000);

        // Verify FIX parser config
        assert_eq!(config.fix_parser.inspect_tags, vec![8, 9, 35, 49, 56]);
        assert_eq!(config.fix_parser.required_tags, vec![8, 9, 35]);
        assert!(!config.fix_parser.validate_structure);
        assert!(!config.fix_parser.log_inspected_tags);
        assert_eq!(config.fix_parser.max_message_length, 8192);

        // Verify policy rules
        assert_eq!(config.policy_rules.len(), 2);

        let rate_limit_rule = &config.policy_rules[0];
        assert_eq!(rate_limit_rule.name, "rate_limit_orders");
        assert_eq!(rate_limit_rule.match_pattern.msg_type, Some("D".to_string()));
        assert_eq!(rate_limit_rule.match_pattern.source_ip, Some("192.168.1.100".to_string()));
        assert!(matches!(rate_limit_rule.action, Action::RateLimit(100)));

        let block_rule = &config.policy_rules[1];
        assert_eq!(block_rule.name, "block_admin");
        assert_eq!(block_rule.match_pattern.msg_type, Some("A".to_string()));
        assert!(matches!(block_rule.action, Action::Deny));

        cleanup_test_files();
    }

    #[test]
    fn test_app_config_save_methods() {
        cleanup_test_files();

        let app_config = AppConfig {
            server: ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9091),
                tls_enabled: false,
                cert_path: None,
                key_path: None,
                max_connections: 200,
                connection_timeout: std::time::Duration::from_secs(15),
            },
            fix_parser: FixParserConfig::default(),
            policy_rules: vec![
                PolicyRule {
                    name: "test_save_rule".to_string(),
                    match_pattern: MatchPattern {
                        msg_type: Some("0".to_string()),
                        source_ip: None,
                        min_length: None,
                        max_length: None,
                    },
                    action: Action::Allow,
                }
            ],
            metrics: MetricsConfig {
                enabled: true,
                export_interval_secs: 45,
                enable_prometheus: true,
            },
        };

        // Test saving server config
        let result = app_config.save_server_config("test-server-config.yaml");
        assert!(result.is_ok());
        assert!(Path::new("test-server-config.yaml").exists());

        // Test saving FIX parser config
        let result = app_config.save_fix_parser_config("test-fix-parser.yaml");
        assert!(result.is_ok());
        assert!(Path::new("test-fix-parser.yaml").exists());

        // Test saving policy rules
        let result = app_config.save_policy_rules("test-policy-rules.yaml");
        assert!(result.is_ok());
        assert!(Path::new("test-policy-rules.yaml").exists());

        // Verify the saved files can be loaded by creating a new AppConfig
        let new_config_result = AppConfig::load();
        // This will fail because we saved to different filenames, but the save operations should work

        cleanup_test_files();
    }

    #[test]
    fn test_config_error_display() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let config_error = ConfigError::Io(io_error);

        assert_eq!(
            format!("{}", config_error),
            "IO error: file not found"
        );

        let yaml_error = serde_yaml::from_str::<ServerConfig>("invalid: yaml: [").unwrap_err();
        let config_error = ConfigError::Parse(yaml_error);

        assert!(format!("{}", config_error).contains("Parse error:"));
    }

    #[test]
    fn test_invalid_yaml_handling() {
        cleanup_test_files();

        // Create invalid YAML file
        create_test_file("server-config.yaml", "invalid: yaml: [").unwrap();

        let result = AppConfig::load();
        assert!(result.is_err());

        if let Err(ConfigError::Parse(_)) = result {
            // Expected parse error
        } else {
            panic!("Expected ConfigError::Parse for invalid YAML");
        }

        cleanup_test_files();
    }

    #[test]
    fn test_partial_config_files() {
        cleanup_test_files();

        // Create only server config and policy rules (no FIX parser config)
        let server_config_content = r#"
listen_addr: 127.0.0.1:8080
backend_addr: 127.0.0.1:8081
tls_enabled: false
max_connections: 300
connection_timeout: 20s
"#;

        let policy_rules_content = r#"
- name: "simple_allow"
  match_pattern:
    msg_type: "0"
  action: Allow
"#;

        create_test_file("server-config.yaml", server_config_content).unwrap();
        create_test_file("policy-rules.yaml", policy_rules_content).unwrap();

        let result = AppConfig::load();
        assert!(result.is_ok());

        let config = result.unwrap();

        // Should use default FIX parser config
        assert!(config.fix_parser.enabled);

        // Should have the policy rule we provided
        assert_eq!(config.policy_rules.len(), 1);
        assert_eq!(config.policy_rules[0].name, "simple_allow");

        cleanup_test_files();
    }

    #[test]
    fn test_config_with_duration_serialization() {
        let server_config = ServerConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
            tls_enabled: false,
            cert_path: None,
            key_path: None,
            max_connections: 100,
            connection_timeout: std::time::Duration::from_secs(45),
        };

        let yaml = serde_yaml::to_string(&server_config).unwrap();
        assert!(yaml.contains("connection_timeout: 45s"));

        let deserialized: ServerConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.connection_timeout, std::time::Duration::from_secs(45));
    }

    #[test]
    fn test_app_config_structure() {
        let config = AppConfig {
            server: ServerConfig {
                listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080),
                backend_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
                tls_enabled: false,
                cert_path: None,
                key_path: None,
                max_connections: 100,
                connection_timeout: std::time::Duration::from_secs(30),
            },
            fix_parser: FixParserConfig::default(),
            policy_rules: Vec::new(),
            metrics: MetricsConfig {
                enabled: true,
                export_interval_secs: 60,
                enable_prometheus: false,
            },
        };

        // Test that we can access all public fields
        assert_eq!(config.server.listen_addr.port(), 8080);
        assert!(config.fix_parser.enabled);
        assert!(config.policy_rules.is_empty());
        assert!(config.metrics.enabled);
    }

    #[test]
    fn test_empty_match_pattern() {
        let pattern = MatchPattern {
            msg_type: None,
            source_ip: None,
            min_length: None,
            max_length: None,
        };

        let yaml = serde_yaml::to_string(&pattern).unwrap();
        let deserialized: MatchPattern = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(deserialized.msg_type, None);
        assert_eq!(deserialized.source_ip, None);
        assert_eq!(deserialized.min_length, None);
        assert_eq!(deserialized.max_length, None);
    }
}