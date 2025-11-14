use crate::metrics::MetricsCollector;
use std::sync::Arc;
use tracing::{info, error};

#[derive(Debug)]
pub enum ExporterType {
    Prometheus,
    Json,
    Logging,
}

pub struct MetricsExporter {
    collector: Arc<MetricsCollector>,
    exporter_type: ExporterType,
    enabled: bool,
}

impl MetricsExporter {
    pub fn new(collector: Arc<MetricsCollector>, exporter_type: ExporterType) -> Self {
        Self {
            collector,
            exporter_type,
            enabled: true,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub async fn export_metrics(&self) -> Result<String, Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok("Metrics export disabled".to_string());
        }

        match self.exporter_type {
            ExporterType::Prometheus => self.export_prometheus().await,
            ExporterType::Json => self.export_json().await,
            ExporterType::Logging => self.export_logging().await,
        }
    }

    async fn export_prometheus(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut output = String::new();

        // Connection metrics
        output.push_str(&format!(
            "rustchannel_connections_total {}\n",
            self.collector.get_total_connections()
        ));
        output.push_str(&format!(
            "rustchannel_connections_active {}\n",
            self.collector.get_active_connections()
        ));
        output.push_str(&format!(
            "rustchannel_packets_processed_total {}\n",
            self.collector.get_packets_processed()
        ));
        output.push_str(&format!(
            "rustchannel_packets_dropped_total {}\n",
            self.collector.get_packets_dropped()
        ));
        output.push_str(&format!(
            "rustchannel_bytes_processed_total {}\n",
            self.collector.get_total_bytes()
        ));
        output.push_str(&format!(
            "rustchannel_packets_per_second {}\n",
            self.collector.get_packets_per_second()
        ));
        output.push_str(&format!(
            "rustchannel_bytes_per_second {}\n",
            self.collector.get_bytes_per_second()
        ));

        // Policy matches
        let policy_matches = self.collector.get_policy_matches().await;
        for (rule, count) in policy_matches {
            output.push_str(&format!(
                "rustchannel_policy_matches_total{{rule=\"{}\"}} {}\n",
                rule, count
            ));
        }

        // Latency metrics
        if let Some(avg_latency) = self.collector.get_avg_latency().await {
            output.push_str(&format!(
                "rustchannel_avg_latency_microseconds {}\n",
                avg_latency.as_micros()
            ));
        }

        Ok(output)
    }

    async fn export_json(&self) -> Result<String, Box<dyn std::error::Error>> {
        let policy_matches = self.collector.get_policy_matches().await;
        let avg_latency = self.collector.get_avg_latency().await;

        let metrics = serde_json::json!({
            "connections": {
                "total": self.collector.get_total_connections(),
                "active": self.collector.get_active_connections(),
            },
            "packets": {
                "processed": self.collector.get_packets_processed(),
                "dropped": self.collector.get_packets_dropped(),
                "bytes_total": self.collector.get_total_bytes(),
                "packets_per_second": self.collector.get_packets_per_second(),
                "bytes_per_second": self.collector.get_bytes_per_second(),
            },
            "policy_matches": policy_matches,
            "latency": {
                "avg_microseconds": avg_latency.map(|d| d.as_micros()),
            },
            "uptime_seconds": self.collector.get_uptime().as_secs_f64(),
        });

        Ok(serde_json::to_string_pretty(&metrics)?)
    }

    async fn export_logging(&self) -> Result<String, Box<dyn std::error::Error>> {
        let policy_matches = self.collector.get_policy_matches().await;
        let avg_latency = self.collector.get_avg_latency().await;

        info!(
            total_connections = self.collector.get_total_connections(),
            active_connections = self.collector.get_active_connections(),
            packets_processed = self.collector.get_packets_processed(),
            packets_dropped = self.collector.get_packets_dropped(),
            bytes_total = self.collector.get_total_bytes(),
            packets_per_second = self.collector.get_packets_per_second(),
            bytes_per_second = self.collector.get_bytes_per_second(),
            policy_matches = ?policy_matches,
            avg_latency_micros = avg_latency.map(|d| d.as_micros()),
            uptime_seconds = self.collector.get_uptime().as_secs_f64(),
            "Channel metrics exported"
        );

        Ok("Metrics logged".to_string())
    }
}

// Simple HTTP server for metrics (without warp)
pub struct MetricsServer {
    exporter: Arc<MetricsExporter>,
}

impl MetricsServer {
    pub fn new(exporter: Arc<MetricsExporter>) -> Self {
        Self { exporter }
    }

    pub async fn run_simple_export(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Simple periodic export instead of HTTP server
        let exporter = Arc::clone(&self.exporter);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                if let Err(e) = exporter.export_metrics().await {
                    error!("Failed to export metrics: {}", e);
                }
            }
        });

        Ok(())
    }
}