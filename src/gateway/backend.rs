use tokio::net::TcpStream;
use tokio_tungstenite::{WebSocketStream, connect_async, tungstenite::Message};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use url::Url;
use tokio::io::AsyncWriteExt; // Add this import

#[derive(Debug)]
pub enum BackendError {
    ConnectionFailed(String),
    IoError(std::io::Error),
    CommunicationFailed(String),
    WebSocketError(String),
    InvalidUrl(String),
}

impl std::error::Error for BackendError {}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            BackendError::IoError(e) => write!(f, "IO error: {}", e),
            BackendError::CommunicationFailed(msg) => write!(f, "Communication failed: {}", msg),
            BackendError::WebSocketError(msg) => write!(f, "WebSocket error: {}", msg),
            BackendError::InvalidUrl(msg) => write!(f, "Invalid URL: {}", msg),
        }
    }
}

impl From<std::io::Error> for BackendError {
    fn from(error: std::io::Error) -> Self {
        BackendError::IoError(error)
    }
}

// Implement Send + Sync for BackendError
unsafe impl Send for BackendError {}
unsafe impl Sync for BackendError {}

pub enum BackendConnection {
    Tcp(TcpStream),
    WebSocket(WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>), // Fixed type
}

use crate::{log_error, log_info, log_debug}; // Removed unused log_warn

impl BackendConnection {
    pub async fn connect(backend_addr: String) -> Result<Self, BackendError> {
        log_debug!("Attempting to connect to backend: {}", backend_addr);

        // Check if it's a WebSocket URL
        if backend_addr.starts_with("ws://") || backend_addr.starts_with("wss://") {
            Self::connect_websocket(&backend_addr).await
        } else {
            Self::connect_tcp(&backend_addr).await
        }
    }

    async fn connect_tcp(backend_addr: &str) -> Result<Self, BackendError> {
        log_debug!("Connecting to TCP backend: {}", backend_addr);

        let socket_addr: std::net::SocketAddr = backend_addr.parse()
            .map_err(|e| BackendError::ConnectionFailed(format!("Invalid TCP address: {}", e)))?;

        let stream = TcpStream::connect(socket_addr).await
            .map_err(|e| BackendError::ConnectionFailed(e.to_string()))?;

        // Set non-blocking mode for the stream
        stream.set_nodelay(true).ok(); // Disable Nagle's algorithm for low latency

        log_info!("Connected to TCP backend: {}", backend_addr);
        Ok(BackendConnection::Tcp(stream))
    }

    async fn connect_websocket(backend_url: &str) -> Result<Self, BackendError> {
        log_debug!("Connecting to WebSocket backend: {}", backend_url);

        let url = Url::parse(backend_url)
            .map_err(|e| BackendError::InvalidUrl(e.to_string()))?;

        let (ws_stream, _) = connect_async(url)
            .await
            .map_err(|e| BackendError::WebSocketError(e.to_string()))?;

        log_info!("Connected to WebSocket backend: {}", backend_url);
        Ok(BackendConnection::WebSocket(ws_stream))
    }

    pub async fn forward_data(&mut self, data: &[u8]) -> Result<Vec<u8>, BackendError> {
        log_debug!("Forwarding {} bytes to backend", data.len());

        match self {
            BackendConnection::Tcp(stream) => Self::forward_tcp_data(stream, data).await,
            BackendConnection::WebSocket(ws_stream) => Self::forward_websocket_data(ws_stream, data).await,
        }
    }

    async fn forward_tcp_data(stream: &mut TcpStream, data: &[u8]) -> Result<Vec<u8>, BackendError> {
        // Send data to backend
        stream.write_all(data).await?;
        log_debug!("Sent {} bytes to TCP backend", data.len());

        // Try to read any available response without blocking
        let mut buffer = vec![0u8; 4096];
        match stream.try_read(&mut buffer) {
            Ok(0) => {
                log_debug!("TCP backend connection closed (read 0 bytes)");
                Ok(Vec::new())
            }
            Ok(n) => {
                let response = buffer[..n].to_vec();
                log_debug!("Received {} bytes from TCP backend", n);
                Ok(response)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                log_debug!("No data available from TCP backend right now");
                Ok(Vec::new()) // No data available is not an error
            }
            Err(e) => {
                log_error!("Error reading from TCP backend: {}", e);
                Err(BackendError::CommunicationFailed(e.to_string()))
            }
        }
    }

    async fn forward_websocket_data(
        ws_stream: &mut WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
        data: &[u8]
    ) -> Result<Vec<u8>, BackendError> {
        // Send WebSocket binary message
        let message = Message::Binary(data.to_vec());
        ws_stream.send(message).await
            .map_err(|e| BackendError::WebSocketError(e.to_string()))?;

        log_debug!("Sent {} bytes to WebSocket backend", data.len());

        // Try to receive response with timeout
        match tokio::time::timeout(Duration::from_secs(5), ws_stream.next()).await {
            Ok(Some(Ok(message))) => {
                match message {
                    Message::Text(text) => {
                        log_debug!("Received text response from WebSocket backend: {} bytes", text.len());
                        Ok(text.into_bytes())
                    }
                    Message::Binary(data) => {
                        log_debug!("Received binary response from WebSocket backend: {} bytes", data.len());
                        Ok(data)
                    }
                    Message::Close(_) => {
                        log_debug!("WebSocket backend closed connection");
                        Ok(Vec::new())
                    }
                    Message::Ping(data) => {
                        // Auto-respond to ping
                        log_debug!("Received ping from WebSocket backend");
                        let _ = ws_stream.send(Message::Pong(data)).await;
                        Ok(Vec::new())
                    }
                    Message::Pong(_) => {
                        log_debug!("Received pong from WebSocket backend");
                        Ok(Vec::new())
                    }
                    _ => {
                        log_debug!("Received other message type from WebSocket backend");
                        Ok(Vec::new())
                    }
                }
            }
            Ok(Some(Err(e))) => {
                log_error!("WebSocket error from backend: {}", e);
                Err(BackendError::WebSocketError(e.to_string()))
            }
            Ok(None) => {
                log_debug!("WebSocket backend connection closed");
                Ok(Vec::new())
            }
            Err(_) => {
                log_debug!("Timeout waiting for WebSocket backend response");
                Ok(Vec::new()) // Timeout is not an error
            }
        }
    }

    pub async fn is_connected(&self) -> bool {
        match self {
            BackendConnection::Tcp(stream) => {
                // Check if TCP connection is still alive
                match stream.try_read(&mut [0u8; 0]) {
                    Ok(_) => true,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
                    Err(_) => false,
                }
            }
            BackendConnection::WebSocket(_) => {
                // For WebSocket, we assume it's connected unless we get an error
                // In a real implementation, you might want to send a ping to check
                true
            }
        }
    }
}