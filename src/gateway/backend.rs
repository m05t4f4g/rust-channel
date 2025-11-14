use tokio::io::{ AsyncWriteExt};
use tokio::net::TcpStream;
// use tracing::{info, error, debug, warn};

#[derive(Debug)]
pub enum BackendError {
    ConnectionFailed(String),
    IoError(std::io::Error),
    CommunicationFailed(String),
}

impl std::error::Error for BackendError {}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            BackendError::IoError(e) => write!(f, "IO error: {}", e),
            BackendError::CommunicationFailed(msg) => write!(f, "Communication failed: {}", msg),
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

pub struct BackendConnection {
    pub stream: TcpStream,
}

use crate::{log_error, log_info, log_debug};
impl BackendConnection {
    pub async fn connect(backend_addr: std::net::SocketAddr) -> Result<Self, BackendError> {
        log_debug!("Attempting to connect to backend: {}", backend_addr);
        let stream = TcpStream::connect(backend_addr).await
            .map_err(|e| BackendError::ConnectionFailed(e.to_string()))?;

        // Set non-blocking mode for the stream
        stream.set_nodelay(true).ok(); // Disable Nagle's algorithm for low latency

        log_info!(" Connected to backend: {}", backend_addr);
        Ok(BackendConnection { stream })
    }

    pub async fn forward_data(&mut self, data: &[u8]) -> Result<Vec<u8>, BackendError> {
        log_debug!(" Forwarding {} bytes to backend", data.len());

        // Send data to backend
        self.stream.write_all(data).await?;
        log_debug!(" Sent {} bytes to backend", data.len());

        // Try to read any available response without blocking
        let mut buffer = vec![0u8; 4096];
        match self.stream.try_read(&mut buffer) {
            Ok(0) => {
                log_debug!(" Backend connection closed (read 0 bytes)");
                Ok(Vec::new())
            }
            Ok(n) => {
                let response = buffer[..n].to_vec();
                log_debug!(" Received {} bytes from backend", n);
                Ok(response)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                log_debug!(" No data available from backend right now");
                Ok(Vec::new()) // No data available is not an error
            }
            Err(e) => {
                log_error!(" Error reading from backend: {}", e);
                Err(BackendError::CommunicationFailed(e.to_string()))
            }
        }
    }

    pub async fn is_connected(&self) -> bool {
        // Check if the connection is still alive by trying to read 0 bytes
        match self.stream.try_read(&mut [0u8; 0]) {
            Ok(_) => true,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true, // WouldBlock means connected but no data
            Err(_) => false, // Any other error means disconnected
        }
    }
}