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
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};
use futures_util::{SinkExt, StreamExt};

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

    // Convert backend_addr to String for the new backend system
    let backend_addr_str = config.backend_addr.to_string();

    // Connect to backend
    let mut backend_conn = match BackendConnection::connect(backend_addr_str.clone()).await {
        Ok(conn) => {
            info!("Connected to backend: {}", backend_addr_str);
            conn
        }
        Err(e) => {
            error!("Failed to connect to backend {}: {}", backend_addr_str, e);
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

                        // Forward to backend using the unified method
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

pub async fn handle_tls_websocket_connection(
    socket: TcpStream,
    client_addr: std::net::SocketAddr,
    acceptor: TlsAcceptor,
    inspector: Arc<PacketInspector>,
    policy_engine: Arc<PolicyEngine>,
    connection_tracker: Arc<ConnectionTracker>,
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("New TLS WebSocket connection from {}", client_addr);

    // Perform TLS handshake first
    let tls_stream = match acceptor.accept(socket).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("TLS handshake failed: {}", e);
            return Ok(());
        }
    };

    // Then perform WebSocket handshake over TLS
    let ws_stream = match tokio_tungstenite::accept_async(tls_stream).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("WebSocket handshake over TLS failed: {}", e);
            return Ok(());
        }
    };

    // Register connection
    connection_tracker.add_connection(client_addr).await;

    // Convert backend_addr to String for the new backend system
    let backend_addr_str = config.backend_addr.to_string();

    // Connect to backend
    let backend_conn = match BackendConnection::connect(backend_addr_str.clone()).await {
        Ok(conn) => {
            info!("Connected to backend: {}", backend_addr_str);
            conn
        }
        Err(e) => {
            error!("Failed to connect to backend {}: {}", backend_addr_str, e);
            return Ok(());
        }
    };

    // Clone Arc for use in processing function
    let connection_tracker_clone = Arc::clone(&connection_tracker);

    if let Err(e) = process_tls_websocket_messages(
        ws_stream,
        client_addr,
        backend_conn,
        inspector,
        policy_engine,
        connection_tracker_clone,
    ).await {
        error!("TLS WebSocket processing error for {}: {}", client_addr, e);
    }

    connection_tracker.remove_connection(client_addr).await;
    info!("TLS WebSocket connection closed: {}", client_addr);

    Ok(())
}

async fn process_tls_websocket_messages(
    mut ws_stream: WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>,
    client_addr: std::net::SocketAddr,
    mut backend_conn: BackendConnection,
    inspector: Arc<PacketInspector>,
    policy_engine: Arc<PolicyEngine>,
    connection_tracker: Arc<ConnectionTracker>,
) -> Result<(), Box<dyn std::error::Error>> {
    let connection_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    loop {
        tokio::select! {
            message = ws_stream.next() => {
                match message {
                    Some(Ok(msg)) => {
                        if let Err(e) = handle_tls_websocket_message(
                            msg,
                            &mut ws_stream,
                            client_addr,
                            connection_id,
                            &mut backend_conn,
                            &inspector,
                            &policy_engine,
                            &connection_tracker,
                        ).await {
                            warn!("Error handling TLS WebSocket message from {}: {}", client_addr, e);
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        warn!("TLS WebSocket error from {}: {}", client_addr, e);
                        break;
                    }
                    None => {
                        debug!("TLS WebSocket connection closed by client: {}", client_addr);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_tls_websocket_message(
    msg: Message,
    ws_stream: &mut WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>,
    client_addr: std::net::SocketAddr,
    connection_id: u64,
    backend_conn: &mut BackendConnection,
    inspector: &PacketInspector,
    policy_engine: &PolicyEngine,
    connection_tracker: &ConnectionTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    match msg {
        Message::Text(text) => {
            debug!(
                client_addr = %client_addr,
                connection_id = connection_id,
                message_length = text.len(),
                "Received TLS WebSocket text message"
            );

            process_tls_websocket_data(
                text.into_bytes(),
                ws_stream,
                client_addr,
                connection_id,
                backend_conn,
                inspector,
                policy_engine,
                connection_tracker,
            ).await
        }
        Message::Binary(data) => {
            debug!(
                client_addr = %client_addr,
                connection_id = connection_id,
                message_length = data.len(),
                "Received TLS WebSocket binary message"
            );

            process_tls_websocket_data(
                data,
                ws_stream,
                client_addr,
                connection_id,
                backend_conn,
                inspector,
                policy_engine,
                connection_tracker,
            ).await
        }
        Message::Close(_) => {
            info!(
                client_addr = %client_addr,
                connection_id = connection_id,
                "TLS WebSocket close frame received"
            );
            Ok(())
        }
        Message::Ping(data) => {
            debug!(
                client_addr = %client_addr,
                connection_id = connection_id,
                "TLS WebSocket ping received"
            );
            ws_stream.send(Message::Pong(data)).await?;
            Ok(())
        }
        Message::Pong(_) => {
            debug!(
                client_addr = %client_addr,
                connection_id = connection_id,
                "TLS WebSocket pong received"
            );
            Ok(())
        }
        _ => {
            debug!(
                client_addr = %client_addr,
                connection_id = connection_id,
                "Unhandled TLS WebSocket message type"
            );
            Ok(())
        }
    }
}

async fn process_tls_websocket_data(
    data: Vec<u8>,
    ws_stream: &mut WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>,
    client_addr: std::net::SocketAddr,
    connection_id: u64,
    backend_conn: &mut BackendConnection,
    inspector: &PacketInspector,
    policy_engine: &PolicyEngine,
    connection_tracker: &ConnectionTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    // Inspect packet
    let inspection_result = inspector.inspect(&data, &client_addr).await;

    // Apply policies
    let policy_result = policy_engine.evaluate(&inspection_result, &client_addr).await;

    match policy_result.action {
        crate::config::models::Action::Allow => {
            debug!(
                client_addr = %client_addr,
                connection_id = connection_id,
                "Allowed TLS WebSocket packet"
            );

            // Forward to backend using the unified method
            match backend_conn.forward_data(&data).await {
                Ok(backend_response) => {
                    if !backend_response.is_empty() {
                        let response_msg = Message::Binary(backend_response);
                        if let Err(e) = ws_stream.send(response_msg).await {
                            warn!(
                                client_addr = %client_addr,
                                connection_id = connection_id,
                                error = %e,
                                "Failed to send backend response via TLS WebSocket"
                            );
                            return Err(e.into());
                        }
                    }
                }
                Err(e) => {
                    error!(
                        client_addr = %client_addr,
                        connection_id = connection_id,
                        error = %e,
                        "Failed to forward data to backend"
                    );

                    let error_msg = Message::Text("Error: Backend communication failed".to_string());
                    let _ = ws_stream.send(error_msg).await;
                    return Err(e.into());
                }
            }
        }
        crate::config::models::Action::Deny => {
            warn!(
                client_addr = %client_addr,
                connection_id = connection_id,
                reason = %policy_result.reason,
                "Denied TLS WebSocket packet"
            );

            let deny_msg = Message::Text(format!("Error: Packet denied - {}", policy_result.reason));
            let _ = ws_stream.send(deny_msg).await;
        }
        crate::config::models::Action::RateLimit(limit) => {
            if connection_tracker.check_rate_limit(client_addr, limit).await {
                warn!(
                    client_addr = %client_addr,
                    connection_id = connection_id,
                    rate_limit = limit,
                    "Rate limited TLS WebSocket packet"
                );

                let rate_limit_msg = Message::Text("Error: Rate limit exceeded".to_string());
                let _ = ws_stream.send(rate_limit_msg).await;
                return Ok(());
            }

            match backend_conn.forward_data(&data).await {
                Ok(backend_response) => {
                    if !backend_response.is_empty() {
                        let response_msg = Message::Binary(backend_response);
                        if let Err(e) = ws_stream.send(response_msg).await {
                            warn!(
                                client_addr = %client_addr,
                                connection_id = connection_id,
                                error = %e,
                                "Failed to send backend response via TLS WebSocket"
                            );
                            return Err(e.into());
                        }
                    }
                }
                Err(e) => {
                    error!(
                        client_addr = %client_addr,
                        connection_id = connection_id,
                        error = %e,
                        "Failed to forward data to backend"
                    );

                    let error_msg = Message::Text("Error: Backend communication failed".to_string());
                    let _ = ws_stream.send(error_msg).await;
                    return Err(e.into());
                }
            }
        }
    }

    connection_tracker.record_packet(client_addr, data.len()).await;
    Ok(())
}