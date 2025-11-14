use crate::config::ServerConfig;
use crate::inspection::PacketInspector;
use crate::policy::PolicyEngine;
use crate::tracker::ConnectionTracker;
use crate::gateway::backend::BackendConnection;
use rustls::ServerConfig as TlsServerConfig;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn, debug, error};

pub fn load_certificates(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey), Box<dyn std::error::Error>> {
    let cert_file = std::fs::File::open(cert_path)?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)?
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    let key_file = std::fs::File::open(key_path)?;
    let mut key_reader = std::io::BufReader::new(key_file);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?;

    if keys.is_empty() {
        return Err("No private keys found".into());
    }

    Ok((certs, rustls::PrivateKey(keys.remove(0))))
}

pub fn build_tls_acceptor(
    certs: Vec<rustls::Certificate>,
    key: rustls::PrivateKey,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let config = TlsServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub async fn handle_tls_connection(
    socket: TcpStream,
    client_addr: std::net::SocketAddr,
    acceptor: TlsAcceptor,
    inspector: Arc<PacketInspector>,
    policy_engine: Arc<PolicyEngine>,
    connection_tracker: Arc<ConnectionTracker>,
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("New TLS connection from {}", client_addr);

    let mut tls_stream = match acceptor.accept(socket).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("TLS handshake failed: {}", e);
            return Ok(());
        }
    };

    // Register connection
    connection_tracker.add_connection(client_addr).await;

    // Connect to backend
    let mut backend_conn = match BackendConnection::connect(config.backend_addr).await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Failed to connect to backend {}: {}", config.backend_addr, e);
            let _ = tls_stream.write_all(b"Error: Backend unavailable\n").await;
            return Ok(());
        }
    };

    let mut client_buffer = [0u8; 4096];

    loop {
        match tls_stream.read(&mut client_buffer).await {
            Ok(0) => {
                debug!("TLS connection closed by client: {}", client_addr);
                break;
            }
            Ok(n) => {
                let packet = &client_buffer[..n];

                // Inspect packet
                let inspection_result = inspector.inspect(packet, &client_addr).await;

                // Apply policies
                let policy_result = policy_engine.evaluate(&inspection_result, &client_addr).await;

                match policy_result.action {
                    crate::config::models::Action::Allow => {
                        debug!("Allowed TLS packet from {}: {} bytes", client_addr, n);

                        // Forward to backend
                        match backend_conn.forward_data(packet).await {
                            Ok(backend_response) => {
                                // Send backend response back to client
                                if !backend_response.is_empty() {
                                    if let Err(e) = tls_stream.write_all(&backend_response).await {
                                        warn!("Failed to send backend response to client: {}", e);
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to forward data to backend: {}", e);
                                let _ = tls_stream.write_all(b"Error: Backend communication failed\n").await;
                                break;
                            }
                        }
                    }
                    crate::config::models::Action::Deny => {
                        warn!("Denied TLS packet from {}: {}", client_addr, policy_result.reason);
                        let _ = tls_stream.write_all(b"Error: Packet denied by channel policy\n").await;
                        break;
                    }
                    crate::config::models::Action::RateLimit(limit) => {
                        if connection_tracker.check_rate_limit(client_addr, limit).await {
                            warn!("Rate limited TLS packet from {} (limit: {}/sec)", client_addr, limit);
                            let _ = tls_stream.write_all(b"Error: Rate limit exceeded\n").await;
                            break;
                        }

                        // Forward if within rate limit
                        match backend_conn.forward_data(packet).await {
                            Ok(backend_response) => {
                                if !backend_response.is_empty() {
                                    if let Err(e) = tls_stream.write_all(&backend_response).await {
                                        warn!("Failed to send backend response to client: {}", e);
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to forward data to backend: {}", e);
                                let _ = tls_stream.write_all(b"Error: Backend communication failed\n").await;
                                break;
                            }
                        }
                    }
                }

                connection_tracker.record_packet(client_addr, n).await;
            }
            Err(e) => {
                warn!("Error reading from TLS stream: {}", e);
                break;
            }
        }
    }

    connection_tracker.remove_connection(client_addr).await;
    info!("TLS connection closed: {}", client_addr);

    Ok(())
}