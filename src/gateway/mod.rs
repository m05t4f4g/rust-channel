pub mod tcp;
pub mod tls;
pub mod websocket;
pub mod backend;

use crate::config::ServerConfig;
use crate::inspection::PacketInspector;
use crate::policy::PolicyEngine;
use crate::tracker::ConnectionTracker;
use crate::metrics::MetricsCollector;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, error};

pub struct TransactionGateway {
    config: ServerConfig,
    inspector: Arc<PacketInspector>,
    policy_engine: Arc<PolicyEngine>,
    connection_tracker: Arc<ConnectionTracker>,
    metrics: Arc<MetricsCollector>,
}

impl TransactionGateway {
    pub fn new(
        config: ServerConfig,
        inspector: Arc<PacketInspector>,
        policy_engine: Arc<PolicyEngine>,
        connection_tracker: Arc<ConnectionTracker>,
    ) -> Self {
        Self {
            config,
            inspector,
            policy_engine,
            connection_tracker,
            metrics: Arc::new(MetricsCollector::new()),
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        info!("Gateway listening on {}", self.config.listen_addr);
        info!("Forwarding to backend: {}", self.config.backend_addr);

        // Record startup metric
        self.metrics.record_connection();

        // Choose the appropriate server based on configuration
        match (self.config.tls_enabled, self.config.websocket_enabled) {
            (true, true) => {
                info!("Starting TLS WebSocket server");
                self.run_tls_websocket_server(listener).await
            }
            (true, false) => {
                info!("Starting TLS server");
                self.run_tls_server(listener).await
            }
            (false, true) => {
                info!("Starting WebSocket server");
                self.run_websocket_server(listener).await
            }
            (false, false) => {
                info!("Starting TCP server");
                self.run_tcp_server(listener).await
            }
        }
    }

    async fn run_tcp_server(&self, listener: TcpListener) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let (socket, addr) = listener.accept().await?;

            let inspector = Arc::clone(&self.inspector);
            let policy_engine = Arc::clone(&self.policy_engine);
            let connection_tracker = Arc::clone(&self.connection_tracker);
            let config = self.config.clone();

            self.metrics.record_connection();

            tokio::spawn(async move {
                if let Err(e) = tcp::handle_tcp_connection(
                    socket,
                    addr,
                    inspector,
                    policy_engine,
                    connection_tracker,
                    config,
                ).await {
                    error!("TCP connection error: {}", e);
                }
            });
        }
    }

    async fn run_websocket_server(&self, listener: TcpListener) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let (socket, addr) = listener.accept().await?;

            let inspector = Arc::clone(&self.inspector);
            let policy_engine = Arc::clone(&self.policy_engine);
            let connection_tracker = Arc::clone(&self.connection_tracker);
            let config = self.config.clone();

            self.metrics.record_connection();

            tokio::spawn(async move {
                if let Err(e) = websocket::handle_websocket_connection(
                    socket,
                    addr,
                    inspector,
                    policy_engine,
                    connection_tracker,
                    config,
                ).await {
                    error!("WebSocket connection error: {}", e);
                }
            });
        }
    }

    async fn run_tls_server(&self, listener: TcpListener) -> Result<(), Box<dyn std::error::Error>> {
        let (cert, key) = tls::load_certificates(
            self.config.cert_path.as_ref().unwrap(),
            self.config.key_path.as_ref().unwrap(),
        )?;

        let tls_acceptor = tls::build_tls_acceptor(cert, key)?;

        loop {
            let (socket, addr) = listener.accept().await?;
            let tls_acceptor = tls_acceptor.clone();

            let inspector = Arc::clone(&self.inspector);
            let policy_engine = Arc::clone(&self.policy_engine);
            let connection_tracker = Arc::clone(&self.connection_tracker);
            let config = self.config.clone();

            self.metrics.record_connection();

            tokio::spawn(async move {
                if let Err(e) = tls::handle_tls_connection(
                    socket,
                    addr,
                    tls_acceptor,
                    inspector,
                    policy_engine,
                    connection_tracker,
                    config,
                ).await {
                    error!("TLS connection error: {}", e);
                }
            });
        }
    }

    async fn run_tls_websocket_server(&self, listener: TcpListener) -> Result<(), Box<dyn std::error::Error>> {
        let (cert, key) = tls::load_certificates(
            self.config.cert_path.as_ref().unwrap(),
            self.config.key_path.as_ref().unwrap(),
        )?;

        let tls_acceptor = tls::build_tls_acceptor(cert, key)?;

        loop {
            let (socket, addr) = listener.accept().await?;
            let tls_acceptor = tls_acceptor.clone();

            let inspector = Arc::clone(&self.inspector);
            let policy_engine = Arc::clone(&self.policy_engine);
            let connection_tracker = Arc::clone(&self.connection_tracker);
            let config = self.config.clone();

            self.metrics.record_connection();

            tokio::spawn(async move {
                if let Err(e) = tls::handle_tls_websocket_connection(
                    socket,
                    addr,
                    tls_acceptor,
                    inspector,
                    policy_engine,
                    connection_tracker,
                    config,
                ).await {
                    error!("TLS WebSocket connection error: {}", e);
                }
            });
        }
    }
}

// ... rest of your existing BackendConnection code ...