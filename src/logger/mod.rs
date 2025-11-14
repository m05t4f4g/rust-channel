use tracing::{Level};
use tracing_subscriber::{
    fmt::{self, format::Writer, time::FormatTime},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer, Registry,
};
use chrono::Utc;
use std::fs::OpenOptions;

// Custom timestamp format
struct CustomTime;

impl FormatTime for CustomTime {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        write!(w, "{}", Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"))
    }
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub level: Level,
    pub enable_console: bool,
    pub enable_file: bool,
    pub file_path: String,
    pub enable_json: bool,
    pub enable_ansi: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            enable_console: true,
            enable_file: false,
            file_path: "rustchannel.log".to_string(),
            enable_json: false,
            enable_ansi: true,
        }
    }
}

pub struct Logger;

impl Logger {
    pub fn init(config: LogConfig) -> Result<(), Box<dyn std::error::Error>> {
        let env_filter = EnvFilter::from_default_env()
            .add_directive(format!("rustchannel={}", config.level).parse()?)
            .add_directive("tokio=warn".parse()?)
            .add_directive("hyper=warn".parse()?)
            .add_directive("h2=warn".parse()?);

        let registry = Registry::default().with(env_filter);

        let mut layers = Vec::new();

        // Console layer
        if config.enable_console {
            let console_layer = fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_timer(CustomTime)
                .with_ansi(config.enable_ansi)
                .with_level(true)
                .with_file(true)
                .with_line_number(true);

            layers.push(console_layer.boxed());
        }

        // File layer
        if config.enable_file {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&config.file_path)?;

            let file_layer = if config.enable_json {
                fmt::layer()
                    .with_writer(file)
                    .json()
                    .with_current_span(false)
                    .with_span_list(false)
                    .boxed()
            } else {
                fmt::layer()
                    .with_writer(file)
                    .with_timer(CustomTime)
                    .with_target(true)
                    .with_level(true)
                    .with_thread_ids(true)
                    .boxed()
            };

            layers.push(file_layer);
        }

        // Initialize the subscriber with all layers
        registry.with(layers).init();

        Ok(())
    }

    pub fn init_with_defaults() -> Result<(), Box<dyn std::error::Error>> {
        Self::init(LogConfig::default())
    }
}

// Convenience macros for structured logging
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        tracing::error!(target: "rustchannel", $($arg)*)
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        tracing::warn!(target: "rustchannel", $($arg)*)
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        tracing::info!(target: "rustchannel", $($arg)*)
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        tracing::debug!(target: "rustchannel", $($arg)*)
    };
}

#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => {
        tracing::trace!(target: "rustchannel", $($arg)*)
    };
}

// Structured logging for specific components
pub mod components {
    use std::time::Instant;

    #[derive(Clone)]
    pub struct ConnectionMetrics {
        pub client_addr: std::net::SocketAddr,
        pub connection_id: u64,
        pub start_time: Instant,
        pub bytes_sent: std::sync::Arc<std::sync::atomic::AtomicU64>,
        pub bytes_received: std::sync::Arc<std::sync::atomic::AtomicU64>,
        pub packets_processed: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl ConnectionMetrics {
        pub fn new(addr: std::net::SocketAddr, connection_id: u64) -> Self {
            Self {
                client_addr: addr,
                connection_id,
                start_time: Instant::now(),
                bytes_sent: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                bytes_received: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                packets_processed: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            }
        }

        pub fn record_bytes_sent(&self, bytes: u64) {
            self.bytes_sent.fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
        }

        pub fn record_bytes_received(&self, bytes: u64) {
            self.bytes_received.fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
        }

        pub fn record_packets_processed(&self, count: u64) {
            self.packets_processed.fetch_add(count, std::sync::atomic::Ordering::Relaxed);
        }

        pub fn close(&self) {
            let duration = self.start_time.elapsed();
            let total_bytes_sent = self.bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
            let total_bytes_received = self.bytes_received.load(std::sync::atomic::Ordering::Relaxed);
            let total_packets = self.packets_processed.load(std::sync::atomic::Ordering::Relaxed);

            log_info!(
                client_addr = %self.client_addr,
                connection_id = self.connection_id,
                duration_ms = duration.as_millis(),
                total_bytes_sent = total_bytes_sent,
                total_bytes_received = total_bytes_received,
                total_packets = total_packets,
                " Connection closed"
            );
        }
    }
}