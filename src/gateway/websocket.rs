use crate::config::ServerConfig;
use crate::inspection::PacketInspector;
use crate::policy::PolicyEngine;
use crate::tracker::ConnectionTracker;
use crate::gateway::backend::BackendConnection;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, WebSocketStream, accept_async};
use futures_util::{SinkExt, StreamExt};
use tracing::{info, warn, debug, error};

pub async fn handle_websocket_connection(
    socket: TcpStream,
    client_addr: std::net::SocketAddr,
    inspector: Arc<PacketInspector>,
    policy_engine: Arc<PolicyEngine>,
    connection_tracker: Arc<ConnectionTracker>,
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("New WebSocket connection from {}", client_addr);

    // Accept WebSocket handshake
    let ws_stream = match accept_async(socket).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("WebSocket handshake failed from {}: {}", client_addr, e);
            return Ok(());
        }
    };

    // Register connection
    connection_tracker.add_connection(client_addr).await;

    // Convert backend_addr to String for the new backend system
    let backend_addr = config.backend_addr.to_string();

    // Connect to backend (supports both TCP and WebSocket)
    let backend_conn = match BackendConnection::connect(backend_addr.clone()).await { // Removed mut
        Ok(conn) => {
            info!("Connected to backend: {}", backend_addr);
            conn
        }
        Err(e) => {
            error!("Failed to connect to backend {}: {}", backend_addr, e);
            return Ok(());
        }
    };

    // Clone Arc for use in the processing function
    let connection_tracker_clone = Arc::clone(&connection_tracker);

    if let Err(e) = process_websocket_messages(
        ws_stream,
        client_addr,
        backend_conn,
        inspector,
        policy_engine,
        connection_tracker_clone,
    ).await {
        error!("WebSocket processing error for {}: {}", client_addr, e);
    }

    connection_tracker.remove_connection(client_addr).await;
    info!("WebSocket connection closed: {}", client_addr);

    Ok(())
}

async fn process_websocket_messages(
    mut ws_stream: WebSocketStream<TcpStream>,
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
            // Handle WebSocket messages from client
            message = ws_stream.next() => {
                match message {
                    Some(Ok(msg)) => {
                        if let Err(e) = handle_websocket_message(
                            msg,
                            &mut ws_stream,
                            client_addr,
                            connection_id,
                            &mut backend_conn,
                            &inspector,
                            &policy_engine,
                            &connection_tracker,
                        ).await {
                            warn!("Error handling WebSocket message from {}: {}", client_addr, e);
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        warn!("WebSocket error from {}: {}", client_addr, e);
                        break;
                    }
                    None => {
                        debug!("WebSocket connection closed by client: {}", client_addr);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_websocket_message(
    msg: Message,
    ws_stream: &mut WebSocketStream<TcpStream>,
    client_addr: std::net::SocketAddr,
    _connection_id: u64, // Prefix with underscore since it's not used
    backend_conn: &mut BackendConnection,
    inspector: &PacketInspector,
    policy_engine: &PolicyEngine,
    connection_tracker: &ConnectionTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    match msg {
        Message::Text(text) => {
            debug!(
                client_addr = %client_addr,
                message_length = text.len(),
                "Received WebSocket text message"
            );

            process_websocket_data(
                text.into_bytes(),
                ws_stream,
                client_addr,
                backend_conn,
                inspector,
                policy_engine,
                connection_tracker,
            ).await
        }
        Message::Binary(data) => {
            debug!(
                client_addr = %client_addr,
                message_length = data.len(),
                "Received WebSocket binary message"
            );

            process_websocket_data(
                data,
                ws_stream,
                client_addr,
                backend_conn,
                inspector,
                policy_engine,
                connection_tracker,
            ).await
        }
        Message::Close(_) => {
            info!(
                client_addr = %client_addr,
                "WebSocket close frame received"
            );
            Ok(())
        }
        Message::Ping(data) => {
            debug!(
                client_addr = %client_addr,
                "WebSocket ping received"
            );
            ws_stream.send(Message::Pong(data)).await?;
            Ok(())
        }
        Message::Pong(_) => {
            debug!(
                client_addr = %client_addr,
                "WebSocket pong received"
            );
            Ok(())
        }
        _ => {
            debug!(
                client_addr = %client_addr,
                "Unhandled WebSocket message type"
            );
            Ok(())
        }
    }
}

async fn process_websocket_data(
    data: Vec<u8>,
    ws_stream: &mut WebSocketStream<TcpStream>,
    client_addr: std::net::SocketAddr,
    backend_conn: &mut BackendConnection,
    inspector: &PacketInspector,
    policy_engine: &PolicyEngine,
    connection_tracker: &ConnectionTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("📨 Processing WebSocket data from {} ({} bytes)", client_addr, data.len());

    if let Ok(text) = std::str::from_utf8(&data) {
        info!("📝 Message content: {}", text);
    }

    // Inspect packet
    let inspection_start = std::time::Instant::now();
    let inspection_result = inspector.inspect(&data, &client_addr).await;
    let inspection_duration = inspection_start.elapsed();

    info!("🔍 Inspection completed in {:?}: is_valid={}, patterns={:?}",
          inspection_duration, inspection_result.is_valid, inspection_result.matches_patterns);

    // Apply policies
    let policy_start = std::time::Instant::now();
    let policy_result = policy_engine.evaluate(&inspection_result, &client_addr).await;
    let policy_duration = policy_start.elapsed();

    info!("⚖️ Policy evaluation completed in {:?}: {}", policy_duration, policy_result.debug_summary());

    match policy_result.action {
        crate::config::models::Action::Allow => {
            info!("✅ Allowing message from {}", client_addr);

            // Forward to backend (now supports both TCP and WebSocket)
            match backend_conn.forward_data(&data).await {
                Ok(backend_response) => {
                    if !backend_response.is_empty() {
                        let response_msg = Message::Binary(backend_response);
                        if let Err(e) = ws_stream.send(response_msg).await {
                            error!("❌ Failed to send backend response via WebSocket: {}", e);
                            return Err(e.into());
                        }
                        info!("📤 Forwarded message to backend and sent response to client");
                    } else {
                        info!("📤 Forwarded message to backend (no response)");
                    }
                }
                Err(e) => {
                    error!("❌ Failed to forward data to backend: {}", e);
                    let error_msg = Message::Text(format!("Error: Backend communication failed - {}", e));
                    let _ = ws_stream.send(error_msg).await;
                    return Err(e.into());
                }
            }
        }
        crate::config::models::Action::Deny => {
            warn!("🚫 Denied message from {}: {}", client_addr, policy_result.reason);
            let deny_msg = Message::Text(format!("Error: {}", policy_result.reason));
            let _ = ws_stream.send(deny_msg).await;
        }
        crate::config::models::Action::RateLimit(limit) => {
            if connection_tracker.check_rate_limit(client_addr, limit).await {
                warn!("⏱️ Rate limited message from {} (limit: {}/sec)", client_addr, limit);
                let rate_limit_msg = Message::Text("Error: Rate limit exceeded".to_string());
                let _ = ws_stream.send(rate_limit_msg).await;
                return Ok(());
            }

            info!("✅ Allowing rate-limited message from {} (within limit)", client_addr);
            match backend_conn.forward_data(&data).await {
                Ok(backend_response) => {
                    if !backend_response.is_empty() {
                        let response_msg = Message::Binary(backend_response);
                        if let Err(e) = ws_stream.send(response_msg).await {
                            error!("❌ Failed to send backend response via WebSocket: {}", e);
                            return Err(e.into());
                        }
                    }
                }
                Err(e) => {
                    error!("❌ Failed to forward data to backend: {}", e);
                    let error_msg = Message::Text(format!("Error: Backend communication failed - {}", e));
                    let _ = ws_stream.send(error_msg).await;
                    return Err(e.into());
                }
            }
        }
    }

    connection_tracker.record_packet(client_addr, data.len()).await;
    Ok(())
}