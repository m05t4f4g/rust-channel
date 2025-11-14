use crate::inspection::PacketInspector;
use crate::policy::PolicyEngine;
use crate::tracker::ConnectionTracker;
use crate::gateway::backend::BackendConnection;
use crate::config::ServerConfig;
use crate::logger::components;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::select;
use std::time::Instant;

// Import the logging macros
use crate::{log_error, log_warn, log_info, log_debug};

pub async fn handle_tcp_connection(
    mut client_socket: TcpStream,
    client_addr: std::net::SocketAddr,
    inspector: Arc<PacketInspector>,
    policy_engine: Arc<PolicyEngine>,
    connection_tracker: Arc<ConnectionTracker>,
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use a simple connection ID (you might want to generate a proper one)
    let connection_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let connection_metrics = components::ConnectionMetrics::new(client_addr, connection_id);

    log_info!(
        client_addr = %client_addr,
        connection_id = connection_id,
        " New TCP connection"
    );

    // Register connection
    connection_tracker.add_connection(client_addr).await;

    // Connect to backend
    let mut backend_conn = match BackendConnection::connect(config.backend_addr).await {
        Ok(conn) => {
            log_info!(backend_addr = %config.backend_addr, " Connected to backend");
            conn
        }
        Err(e) => {
            log_error!(backend_addr = %config.backend_addr, error = %e, " Failed to connect to backend");
            let _ = client_socket.write_all(b"Error: Backend unavailable\n").await;
            return Ok(());
        }
    };

    // Split client socket for bidirectional communication
    let (mut client_read, mut client_write) = client_socket.split();
    let (mut backend_read, mut backend_write) = backend_conn.stream.split();

    let mut client_buffer = [0u8; 4096];
    let mut backend_buffer = [0u8; 4096];

    log_debug!(
        client_addr = %client_addr,
        connection_id = connection_id,
        " Starting bidirectional proxy"
    );

    loop {
        select! {
            // Read from client and forward to backend
            result = client_read.read(&mut client_buffer) => {
                match result {
                    Ok(0) => {
                        log_info!(
                            client_addr = %client_addr,
                            connection_id = connection_id,
                            " Client closed connection"
                        );
                        break;
                    }
                    Ok(n) => {
                        connection_metrics.record_bytes_received(n as u64);
                        connection_metrics.record_packets_processed(1);

                        let packet = &client_buffer[..n];

                        log_debug!(
                            client_addr = %client_addr,
                            connection_id = connection_id,
                            packet_length = n,
                            " Received packet from client"
                        );

                        // Inspect packet with timing
                        let inspection_start = Instant::now();
                        let inspection_result = inspector.inspect(packet, &client_addr).await;
                        let inspection_duration = inspection_start.elapsed();

                        log_debug!(
                            client_addr = %client_addr,
                            connection_id = connection_id,
                            is_valid = inspection_result.is_valid,
                            matches_patterns = ?inspection_result.matches_patterns,
                            violations = ?inspection_result.violations,
                            inspection_time_ms = inspection_duration.as_millis(),
                            " Packet inspection completed"
                        );

                        // Apply policies with timing
                        let policy_start = Instant::now();
                        let policy_result = policy_engine.evaluate(&inspection_result, &client_addr).await;
                        let policy_duration = policy_start.elapsed();

                        log_debug!(
                            client_addr = %client_addr,
                            connection_id = connection_id,
                            action = ?policy_result.action,
                            rule_name = ?policy_result.rule_name,
                            evaluation_time_ms = policy_duration.as_millis(),
                            " Policy evaluation completed"
                        );

                        match policy_result.action {
                            crate::config::models::Action::Allow => {
                                log_info!(
                                    client_addr = %client_addr,
                                    connection_id = connection_id,
                                    packet_length = n,
                                    " Allowed packet"
                                );

                                // Forward to backend
                                if let Err(e) = backend_write.write_all(packet).await {
                                    log_error!(
                                        client_addr = %client_addr,
                                        connection_id = connection_id,
                                        error = %e,
                                        " Failed to forward data to backend"
                                    );
                                    break;
                                }

                                connection_metrics.record_bytes_sent(n as u64);

                                log_debug!(
                                    client_addr = %client_addr,
                                    connection_id = connection_id,
                                    bytes_sent = n,
                                    " Forwarded packet to backend"
                                );
                            }
                            crate::config::models::Action::Deny => {
                                log_warn!(
                                    client_addr = %client_addr,
                                    connection_id = connection_id,
                                    reason = %policy_result.reason,
                                    " Denied packet"
                                );
                                let _ = client_write.write_all(b"Error: Packet denied by channel policy\n").await;
                                break;
                            }
                            crate::config::models::Action::RateLimit(limit) => {
                                if connection_tracker.check_rate_limit(client_addr, limit).await {
                                    log_warn!(
                                        client_addr = %client_addr,
                                        connection_id = connection_id,
                                        rate_limit = limit,
                                        " Rate limited packet"
                                    );
                                    let _ = client_write.write_all(b"Error: Rate limit exceeded\n").await;
                                    break;
                                }

                                // Forward if within rate limit
                                if let Err(e) = backend_write.write_all(packet).await {
                                    log_error!(
                                        client_addr = %client_addr,
                                        connection_id = connection_id,
                                        error = %e,
                                        " Failed to forward data to backend"
                                    );
                                    break;
                                }

                                connection_metrics.record_bytes_sent(n as u64);

                                log_debug!(
                                    client_addr = %client_addr,
                                    connection_id = connection_id,
                                    bytes_sent = n,
                                    rate_limit = limit,
                                    " Forwarded packet (within rate limit)"
                                );
                            }
                        }

                        // Update metrics
                        connection_tracker.record_packet(client_addr, n).await;
                    }
                    Err(e) => {
                        log_warn!(
                            client_addr = %client_addr,
                            connection_id = connection_id,
                            error = %e,
                            " Error reading from client socket"
                        );
                        break;
                    }
                }
            }

            // Read from backend and forward to client
            result = backend_read.read(&mut backend_buffer) => {
                match result {
                    Ok(0) => {
                        log_info!(
                            client_addr = %client_addr,
                            connection_id = connection_id,
                            " Backend closed connection"
                        );
                        break;
                    }
                    Ok(n) => {
                        log_debug!(
                            client_addr = %client_addr,
                            connection_id = connection_id,
                            bytes_received = n,
                            " Received response from backend"
                        );

                        // Forward backend response to client
                        if let Err(e) = client_write.write_all(&backend_buffer[..n]).await {
                            log_warn!(
                                client_addr = %client_addr,
                                connection_id = connection_id,
                                error = %e,
                                " Failed to send backend response to client"
                            );
                            break;
                        }

                        connection_metrics.record_bytes_sent(n as u64);

                        log_debug!(
                            client_addr = %client_addr,
                            connection_id = connection_id,
                            bytes_sent = n,
                            " Forwarded backend response to client"
                        );
                    }
                    Err(e) => {
                        log_warn!(
                            client_addr = %client_addr,
                            connection_id = connection_id,
                            error = %e,
                            " Error reading from backend"
                        );
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    connection_tracker.remove_connection(client_addr).await;
    connection_metrics.close();

    Ok(())
}