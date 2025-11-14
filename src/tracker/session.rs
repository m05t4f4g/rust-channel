use dashmap::DashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub packets_received: u64,
    pub bytes_received: u64,
    pub last_packet_time: Instant,
    pub connection_start: Instant,
}

pub struct ConnectionTracker {
    connections: DashMap<SocketAddr, RwLock<ConnectionStats>>,
    rate_limits: DashMap<SocketAddr, (u32, Instant)>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            rate_limits: DashMap::new(),
        }
    }

    pub async fn add_connection(&self, addr: SocketAddr) {
        let stats = ConnectionStats {
            packets_received: 0,
            bytes_received: 0,
            last_packet_time: Instant::now(),
            connection_start: Instant::now(),
        };

        self.connections.insert(addr, RwLock::new(stats));
    }

    pub async fn remove_connection(&self, addr: SocketAddr) {
        self.connections.remove(&addr);
        self.rate_limits.remove(&addr);
    }

    pub async fn record_packet(&self, addr: SocketAddr, bytes: usize) {
        if let Some(entry) = self.connections.get(&addr) {
            let mut stats = entry.write().await;
            stats.packets_received += 1;
            stats.bytes_received += bytes as u64;
            stats.last_packet_time = Instant::now();
        }
    }

    pub async fn check_rate_limit(&self, addr: SocketAddr, limit: u32) -> bool {
        let now = Instant::now();

        if let Some(entry) = self.rate_limits.get(&addr) {
            let (count, window_start) = *entry.value();

            if now.duration_since(window_start) > Duration::from_secs(1) {
                // Reset window
                self.rate_limits.insert(addr, (1, now));
                false
            } else if count >= limit {
                true // Rate limited
            } else {
                self.rate_limits.insert(addr, (count + 1, window_start));
                false
            }
        } else {
            self.rate_limits.insert(addr, (1, now));
            false
        }
    }

    pub async fn get_stats(&self, addr: SocketAddr) -> Option<ConnectionStats> {
        if let Some(entry) = self.connections.get(&addr) {
            Some(entry.read().await.clone())
        } else {
            None
        }
    }

    pub fn get_all_connections(&self) -> Vec<SocketAddr> {
        self.connections.iter().map(|entry| *entry.key()).collect()
    }
}