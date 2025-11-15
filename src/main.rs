mod config;
mod gateway;
mod inspection;
mod policy;
mod tracker;
mod metrics;
mod logger;

use crate::logger::{Logger, LogConfig};
use crate::config::{AppConfig, ConfigError};
use crate::gateway::TransactionGateway;
use crate::inspection::PacketInspector;
use crate::policy::PolicyEngine;
use crate::tracker::ConnectionTracker;
use crate::metrics::MetricsCollector;

use std::sync::Arc;

// Update parse_args to accept config file paths with correct defaults
fn parse_args() -> (LogConfig, String, String, String) {
    let args: Vec<String> = std::env::args().collect();
    let mut log_config = LogConfig::default();
    let mut server_config_path = "config/server-config.yaml".to_string();
    let mut fix_config_path = "config/fix-parser.yaml".to_string();
    let mut policy_config_path = "config/policy-rules.yaml".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server-config" => {
                if i + 1 < args.len() {
                    server_config_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "--fix-config" => {
                if i + 1 < args.len() {
                    fix_config_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "--policy-config" => {
                if i + 1 < args.len() {
                    policy_config_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "--log-level" => {
                if i + 1 < args.len() {
                    log_config.level = match args[i + 1].to_lowercase().as_str() {
                        "error" => tracing::Level::ERROR,
                        "warn" => tracing::Level::WARN,
                        "info" => tracing::Level::INFO,
                        "debug" => tracing::Level::DEBUG,
                        "trace" => tracing::Level::TRACE,
                        _ => tracing::Level::INFO,
                    };
                    i += 1;
                }
            }
            "--log-file" => {
                log_config.enable_file = true;
            }
            "--log-file-path" => {
                if i + 1 < args.len() {
                    log_config.file_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "--log-json" => {
                log_config.enable_json = true;
            }
            "--no-color" => {
                log_config.enable_ansi = false;
            }
            "--help" | "-h" => {
                println!("rustchannel - High-performance application channel for financial systems");
                println!();
                println!("Usage: {} [OPTIONS]", args[0]);
                println!();
                println!("Options:");
                println!("  --server-config FILE     Server config file (default: config/server-config.yaml)");
                println!("  --fix-config FILE        FIX parser config file (default: config/fix-parser.yaml)");
                println!("  --policy-config FILE     Policy rules config file (default: config/policy-rules.yaml)");
                println!("  --log-level LEVEL        Log level: error, warn, info, debug, trace");
                println!("  --log-file               Enable file logging");
                println!("  --log-file-path FILE     Log file path (default: rustchannel.log)");
                println!("  --log-json               Enable JSON logging format");
                println!("  --no-color               Disable ANSI colors in console output");
                println!("  -h, --help               Show this help message");
                std::process::exit(0);
            }
            _ => {
                if args[i].starts_with('-') {
                    eprintln!("Unknown option: {}", args[i]);
                    std::process::exit(1);
                }
            }
        }
        i += 1;
    }

    (log_config, server_config_path, fix_config_path, policy_config_path)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (log_config, server_config_path, fix_config_path, policy_config_path) = parse_args();

    // Initialize logging
    Logger::init(log_config)?;

    log_info!(" Starting rustchannel ...");
    log_info!(" Server config file: {}", server_config_path);
    log_info!(" FIX config file: {}", fix_config_path);
    log_info!(" Policy config file: {}", policy_config_path);

    // Load application configuration
    let app_config = match AppConfig::load() {
        Ok(config) => {
            log_info!("✅ Loaded application configuration");
            log_info!("   Server: {} -> {}", config.server.listen_addr, config.server.backend_addr);
            log_info!("   TLS: {}", config.server.tls_enabled);
            log_info!("   WebSocket: {}", config.server.websocket_enabled);
            log_info!("   FIX Parser: {}", config.fix_parser.enabled);
            log_info!("   Policy Rules: {}", config.policy_rules.len());
            config
        }
        Err(ConfigError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            log_error!("❌ Configuration file not found: {}", e);
            log_info!("💡 Please create config/server-config.yaml file with server configuration");
            log_info!("   Directory structure:");
            log_info!("   your-project/");
            log_info!("   ├── config/");
            log_info!("   │   ├── server-config.yaml");
            log_info!("   │   ├── fix-parser.yaml");
            log_info!("   │   └── policy-rules.yaml");
            log_info!("   ├── src/");
            log_info!("   └── Cargo.toml");
            log_info!("   Example config/server-config.yaml:");
            log_info!("   listen_addr: \"0.0.0.0:8080\"");
            log_info!("   backend_addr: \"127.0.0.1:8081\"");
            log_info!("   tls_enabled: false");
            log_info!("   max_connections: 1000");
            log_info!("   connection_timeout:");
            log_info!("     secs: 30");
            log_info!("     nanos: 0");
            return Err("Missing config/server-config.yaml".into());
        }
        Err(e) => {
            log_error!("❌ Failed to load configuration: {}", e);
            return Err(e.into());
        }
    };

    // Store the config details for logging
    let server_config = &app_config.server;
    let fix_parser_config = &app_config.fix_parser;
    let policy_rules = &app_config.policy_rules;

    // Validate TLS configuration
    if server_config.tls_enabled {
        if server_config.cert_path.is_none() || server_config.key_path.is_none() {
            log_error!("TLS enabled but certificate or key file not provided in server-config.yaml");
            return Err("TLS requires both certificate and key files".into());
        }
        log_info!(" TLS encryption enabled");
        log_info!(" Certificate: {:?}", server_config.cert_path);
        log_info!(" Key: {:?}", server_config.key_path);
    }

    log_info!(" Server configuration loaded");

    // Initialize components with loaded configurations
    let inspector = Arc::new(PacketInspector::new(
        policy_rules.iter().map(|r| r.match_pattern.clone()).collect(),
        fix_parser_config.clone()
    ));

    let policy_engine = Arc::new(PolicyEngine::new(policy_rules.clone()));
    policy_engine.debug_rules();
    let connection_tracker = Arc::new(ConnectionTracker::new());
    let metrics_collector = Arc::new(MetricsCollector::new());

    log_info!(" All components initialized successfully");

    // Start metrics background task
    start_metrics_task(Arc::clone(&metrics_collector));

    log_info!(" Listening on {} (TCP{})", server_config.listen_addr, if server_config.tls_enabled { "S" } else { "" });
    log_info!(" Forwarding to backend: {}", server_config.backend_addr);
    log_info!(" FIX parser: {} (inspecting {} tags, max length: {})",
        if fix_parser_config.enabled { "enabled" } else { "disabled" },
        fix_parser_config.inspect_tags.len(),
        fix_parser_config.max_message_length
    );
    log_info!(" Max connections: {}", server_config.max_connections);
    log_info!(" Connection timeout: {:?}", server_config.connection_timeout);

    if server_config.tls_enabled {
        log_info!(" TLS enabled with certificate: {:?}", server_config.cert_path);
    }

    log_info!("  Channel ready - Press Ctrl+C to stop");

    // Create and run gateway
    let gateway = TransactionGateway::new(
        server_config.clone(),
        inspector,
        policy_engine,
        connection_tracker,
    );

    if let Err(e) = gateway.run().await {
        log_error!("Gateway crashed: {}", e);
        return Err(e);
    }

    log_info!(" Channel shutdown complete");
    Ok(())
}

fn start_metrics_task(metrics: Arc<MetricsCollector>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;

            let total_conn = metrics.get_total_connections();
            let active_conn = metrics.get_active_connections();
            let packets_processed = metrics.get_packets_processed();
            let packets_dropped = metrics.get_packets_dropped();

            if total_conn > 0 || packets_processed > 0 {
                log_info!(
                    total_connections = total_conn,
                    active_connections = active_conn,
                    packets_processed = packets_processed,
                    packets_dropped = packets_dropped,
                    packets_per_second = metrics.get_packets_per_second(),
                    bytes_per_second = metrics.get_bytes_per_second(),
                    "📊 Channel Metrics"
                );
            }
        }
    });
}