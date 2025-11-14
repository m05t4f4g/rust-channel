pub mod exporter;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct MetricsCollector {
    total_connections: Arc<AtomicU64>,
    active_connections: Arc<AtomicUsize>,
    packets_processed: Arc<AtomicU64>,
    packets_dropped: Arc<AtomicU64>,
    total_bytes: Arc<AtomicU64>,
    policy_matches: Arc<RwLock<HashMap<String, u64>>>,
    latency_histogram: Arc<RwLock<Vec<Duration>>>,
    start_time: Instant,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            total_connections: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            packets_processed: Arc::new(AtomicU64::new(0)),
            packets_dropped: Arc::new(AtomicU64::new(0)),
            total_bytes: Arc::new(AtomicU64::new(0)),
            policy_matches: Arc::new(RwLock::new(HashMap::new())),
            latency_histogram: Arc::new(RwLock::new(Vec::new())),
            start_time: Instant::now(),
        }
    }

    pub fn record_connection(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_disconnection(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_packet_processed(&self, bytes: usize) {
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_packet_dropped(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn record_policy_match(&self, rule_name: &str) {
        let mut matches = self.policy_matches.write().await;
        *matches.entry(rule_name.to_string()).or_insert(0) += 1;
    }

    pub async fn record_latency(&self, latency: Duration) {
        let mut histogram = self.latency_histogram.write().await;
        histogram.push(latency);

        // Keep only last 1000 measurements for memory efficiency
        if histogram.len() > 1000 {
            histogram.remove(0);
        }
    }

    // Getters for metrics
    pub fn get_total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    pub fn get_active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub fn get_packets_processed(&self) -> u64 {
        self.packets_processed.load(Ordering::Relaxed)
    }

    pub fn get_packets_dropped(&self) -> u64 {
        self.packets_dropped.load(Ordering::Relaxed)
    }

    pub fn get_total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }

    pub async fn get_policy_matches(&self) -> HashMap<String, u64> {
        self.policy_matches.read().await.clone()
    }

    pub async fn get_avg_latency(&self) -> Option<Duration> {
        let histogram = self.latency_histogram.read().await;
        if histogram.is_empty() {
            None
        } else {
            let total: Duration = histogram.iter().sum();
            Some(total / histogram.len() as u32)
        }
    }

    pub fn get_uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn get_packets_per_second(&self) -> f64 {
        let packets = self.packets_processed.load(Ordering::Relaxed);
        let uptime = self.get_uptime().as_secs_f64();

        if uptime > 0.0 {
            packets as f64 / uptime
        } else {
            0.0
        }
    }

    pub fn get_bytes_per_second(&self) -> f64 {
        let bytes = self.total_bytes.load(Ordering::Relaxed);
        let uptime = self.get_uptime().as_secs_f64();

        if uptime > 0.0 {
            bytes as f64 / uptime
        } else {
            0.0
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}