pub mod models;

pub use models::{
    ServerConfig, MatchPattern, Action, PolicyRule,
    MetricsConfig, FixParserConfig, AppConfig, ConfigError
};

use std::fs;
use std::path::Path;

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        // Load server configuration
        let server_config = if Path::new("config/server-config.yaml").exists() {
            Self::load_server_config("config/server-config.yaml")?
        } else {
            return Err(ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "config/server-config.yaml not found",
            )));
        };

        // Load FIX parser configuration
        let fix_parser_config = if Path::new("config/fix-parser.yaml").exists() {
            Self::load_fix_parser_config("config/fix-parser.yaml")?
        } else {
            FixParserConfig::default()
        };

        // Load policy rules
        let policy_rules = if Path::new("config/policy-rules.yaml").exists() {
            Self::load_policy_rules("config/policy-rules.yaml")?
        } else {
            Vec::new()
        };

        // Load metrics configuration or use default
        let metrics_config = MetricsConfig {
            enabled: true,
            export_interval_secs: 60,
            enable_prometheus: false,
        };

        Ok(AppConfig {
            server: server_config,
            fix_parser: fix_parser_config,
            policy_rules,
            metrics: metrics_config,
        })
    }

    fn load_server_config(path: &str) -> Result<ServerConfig, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: ServerConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    fn load_fix_parser_config(path: &str) -> Result<FixParserConfig, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: FixParserConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    fn load_policy_rules(path: &str) -> Result<Vec<PolicyRule>, ConfigError> {
        let content = fs::read_to_string(path)?;
        let rules: Vec<PolicyRule> = serde_yaml::from_str(&content)?;
        Ok(rules)
    }

    pub fn save_server_config(&self, path: &str) -> Result<(), ConfigError> {
        let content = serde_yaml::to_string(&self.server)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn save_fix_parser_config(&self, path: &str) -> Result<(), ConfigError> {
        let content = serde_yaml::to_string(&self.fix_parser)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn save_policy_rules(&self, path: &str) -> Result<(), ConfigError> {
        let content = serde_yaml::to_string(&self.policy_rules)?;
        fs::write(path, content)?;
        Ok(())
    }
}