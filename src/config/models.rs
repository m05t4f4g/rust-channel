use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: std::net::SocketAddr,
    pub backend_addr: String,
    pub tls_enabled: bool,
    pub websocket_enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub max_connections: u32,
    pub connection_timeout: std::time::Duration,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            backend_addr: "127.0.0.1:8081".to_string(),
            tls_enabled: false,
            websocket_enabled: false,  // Default to false
            cert_path: None,
            key_path: None,
            max_connections: 10,
            connection_timeout: std::time::Duration::from_secs(30),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchPattern {
    pub msg_type: Option<String>,
    pub source_ip: Option<String>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
}

// Simple enum approach - this should work with serde
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Deny,
    RateLimit(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub match_pattern: MatchPattern,
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub export_interval_secs: u64,
    pub enable_prometheus: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixParserConfig {
    pub enabled: bool,
    pub inspect_tags: Vec<u32>,
    pub required_tags: Vec<u32>,
    pub validate_checksum: bool,
    pub validate_structure: bool,
    pub log_inspected_tags: bool,
    pub max_message_length: usize,
    pub min_message_length: usize,
}

impl Default for FixParserConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            inspect_tags: vec![8, 9, 35, 49, 56, 34, 52, 10],
            required_tags: vec![8, 9, 35, 49, 56, 34, 52, 10],
            validate_checksum: true,
            validate_structure: true,
            log_inspected_tags: true,
            max_message_length: 4096,
            min_message_length: 20,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub fix_parser: FixParserConfig,
    pub policy_rules: Vec<PolicyRule>,
    pub metrics: MetricsConfig,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(serde_yaml::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "IO error: {}", e),
            ConfigError::Parse(e) => write!(f, "Parse error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        ConfigError::Io(err)
    }
}

impl From<serde_yaml::Error> for ConfigError {
    fn from(err: serde_yaml::Error) -> Self {
        ConfigError::Parse(err)
    }
}