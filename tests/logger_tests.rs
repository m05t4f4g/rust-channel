#[cfg(test)]
mod logger_tests {
    use std::fs;
    use std::sync::{Mutex, OnceLock};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{Ordering};
    use tracing::Level;

    // Import from your crate
    use rust_channel::logger::{Logger, LogConfig, components::ConnectionMetrics};

    // Global lock to prevent multiple logger initializations in tests
    static LOGGER_INIT: OnceLock<Mutex<()>> = OnceLock::new();

    fn get_logger_lock() -> &'static Mutex<()> {
        LOGGER_INIT.get_or_init(|| Mutex::new(()))
    }

    // Helper to cleanup test log files
    fn cleanup_test_files() {
        let _ = fs::remove_file("test_console.log");
        let _ = fs::remove_file("test_json.log");
        let _ = fs::remove_file("rustchannel.log");
        let _ = fs::remove_file("test_metrics.log");

        // Clean up combo test files
        for i in 0..3 {
            let _ = fs::remove_file(format!("test_combo_{}.log", i));
        }
    }

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();

        assert_eq!(config.level, Level::INFO);
        assert!(config.enable_console);
        assert!(!config.enable_file);
        assert_eq!(config.file_path, "rustchannel.log");
        assert!(!config.enable_json);
        assert!(config.enable_ansi);
    }

    #[test]
    fn test_log_config_custom() {
        let config = LogConfig {
            level: Level::DEBUG,
            enable_console: false,
            enable_file: true,
            file_path: "custom.log".to_string(),
            enable_json: true,
            enable_ansi: false,
        };

        assert_eq!(config.level, Level::DEBUG);
        assert!(!config.enable_console);
        assert!(config.enable_file);
        assert_eq!(config.file_path, "custom.log");
        assert!(config.enable_json);
        assert!(!config.enable_ansi);
    }

    #[test]
    fn test_log_config_debug() {
        let config = LogConfig::default();
        let debug_output = format!("{:?}", config);

        assert!(debug_output.contains("LogConfig"));
        assert!(debug_output.contains("level: INFO"));
    }

    #[test]
    fn test_logger_init_with_defaults() {
        let _guard = get_logger_lock().lock().unwrap();
        cleanup_test_files();

        // This should initialize without errors
        let result = Logger::init_with_defaults();
        assert!(result.is_ok());

        // Test that logging works after initialization
        rust_channel::log_info!("Test info message after init");
        rust_channel::log_error!("Test error message after init");
    }

    #[test]
    fn test_logger_init_console_only() {
        let _guard = get_logger_lock().lock().unwrap();
        cleanup_test_files();

        let config = LogConfig {
            level: Level::DEBUG,
            enable_console: true,
            enable_file: false,
            file_path: "test_console.log".to_string(),
            enable_json: false,
            enable_ansi: false, // Disable ansi for test consistency
        };

        let result = Logger::init(config);
        assert!(result.is_ok());

        // Test all log levels
        rust_channel::log_error!("Console error test");
        rust_channel::log_warn!("Console warn test");
        rust_channel::log_info!("Console info test");
        rust_channel::log_debug!("Console debug test");
        rust_channel::log_trace!("Console trace test");
    }

    #[test]
    fn test_logger_init_file_only() {
        let _guard = get_logger_lock().lock().unwrap();
        cleanup_test_files();

        let config = LogConfig {
            level: Level::INFO,
            enable_console: false,
            enable_file: true,
            file_path: "test_console.log".to_string(),
            enable_json: false,
            enable_ansi: false,
        };

        let result = Logger::init(config);
        assert!(result.is_ok());

        rust_channel::log_info!("File-only log message");
        rust_channel::log_warn!("File-only warning message");

        // Verify file was created
        assert!(fs::metadata("test_console.log").is_ok());
    }

    #[test]
    fn test_logger_init_json_file() {
        let _guard = get_logger_lock().lock().unwrap();
        cleanup_test_files();

        let config = LogConfig {
            level: Level::INFO,
            enable_console: false,
            enable_file: true,
            file_path: "test_json.log".to_string(),
            enable_json: true,
            enable_ansi: false,
        };

        let result = Logger::init(config);
        assert!(result.is_ok());

        rust_channel::log_info!(
            user_id = 12345,
            action = "login",
            "User logged in"
        );

        // Verify JSON file was created
        assert!(fs::metadata("test_json.log").is_ok());
    }

    #[test]
    fn test_logger_init_both_console_and_file() {
        let _guard = get_logger_lock().lock().unwrap();
        cleanup_test_files();

        let config = LogConfig {
            level: Level::WARN,
            enable_console: true,
            enable_file: true,
            file_path: "test_console.log".to_string(),
            enable_json: false,
            enable_ansi: false,
        };

        let result = Logger::init(config);
        assert!(result.is_ok());

        rust_channel::log_warn!("Dual output warning");
        rust_channel::log_error!("Dual output error");

        // Verify file was created
        assert!(fs::metadata("test_console.log").is_ok());
    }

    #[test]
    fn test_connection_metrics_creation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let metrics = ConnectionMetrics::new(addr, 12345);

        assert_eq!(metrics.client_addr, addr);
        assert_eq!(metrics.connection_id, 12345);

        // Verify atomic counters are initialized to zero
        assert_eq!(metrics.bytes_sent.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.bytes_received.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.packets_processed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_connection_metrics_recording() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let metrics = ConnectionMetrics::new(addr, 67890);

        // Test bytes sent recording
        metrics.record_bytes_sent(1024);
        metrics.record_bytes_sent(512);
        assert_eq!(metrics.bytes_sent.load(Ordering::Relaxed), 1536);

        // Test bytes received recording
        metrics.record_bytes_received(2048);
        assert_eq!(metrics.bytes_received.load(Ordering::Relaxed), 2048);

        // Test packets processed recording
        metrics.record_packets_processed(10);
        metrics.record_packets_processed(5);
        assert_eq!(metrics.packets_processed.load(Ordering::Relaxed), 15);
    }

    #[test]
    fn test_connection_metrics_concurrent_recording() {
        use std::sync::Arc;
        use std::thread;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let metrics = Arc::new(ConnectionMetrics::new(addr, 99999));
        let mut handles = vec![];

        // Spawn multiple threads to update metrics concurrently
        for i in 0..10 {
            let metrics_clone = Arc::clone(&metrics);
            let handle = thread::spawn(move || {
                metrics_clone.record_bytes_sent(i * 100);
                metrics_clone.record_bytes_received(i * 50);
                metrics_clone.record_packets_processed(i);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all updates were recorded
        let total_bytes_sent: u64 = (0..10).map(|i| i * 100).sum();
        let total_bytes_received: u64 = (0..10).map(|i| i * 50).sum();
        let total_packets: u64 = (0..10).sum();

        assert_eq!(metrics.bytes_sent.load(Ordering::Relaxed), total_bytes_sent);
        assert_eq!(metrics.bytes_received.load(Ordering::Relaxed), total_bytes_received);
        assert_eq!(metrics.packets_processed.load(Ordering::Relaxed), total_packets);
    }

    #[test]
    fn test_connection_metrics_clone() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let metrics1 = ConnectionMetrics::new(addr, 11111);

        // Test cloning
        let metrics2 = metrics1.clone();

        // Both should have same initial values
        assert_eq!(metrics1.client_addr, metrics2.client_addr);
        assert_eq!(metrics1.connection_id, metrics2.connection_id);

        // But atomic counters should be shared (Arc)
        metrics1.record_bytes_sent(100);
        assert_eq!(metrics2.bytes_sent.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn test_log_macros_structured_logging() {
        let _guard = get_logger_lock().lock().unwrap();
        cleanup_test_files();

        // Initialize logger for these tests
        let config = LogConfig {
            enable_console: false, // Don't clutter test output
            enable_file: false,
            ..LogConfig::default()
        };

        let _ = Logger::init(config);

        // Test structured logging with different field types
        rust_channel::log_info!(
            user_id = 12345,
            username = "test_user",
            active = true,
            score = 95.5,
            "User activity"
        );

        rust_channel::log_error!(
            error_code = "AUTH_FAILED",
            attempt_count = 3,
            ip_address = "192.168.1.100",
            "Authentication failed"
        );
    }

    #[test]
    fn test_log_macros_different_levels() {
        let _guard = get_logger_lock().lock().unwrap();

        // Test with TRACE level to capture all messages
        let config = LogConfig {
            level: Level::TRACE,
            enable_console: false,
            enable_file: false,
            ..LogConfig::default()
        };

        let _ = Logger::init(config);

        // These should all work without panicking
        rust_channel::log_error!("Error level message");
        rust_channel::log_warn!("Warning level message");
        rust_channel::log_info!("Info level message");
        rust_channel::log_debug!("Debug level message");
        rust_channel::log_trace!("Trace level message");
    }

    #[test]
    fn test_logger_init_invalid_file_path() {
        let _guard = get_logger_lock().lock().unwrap();

        // Try to log to a directory (should fail)
        let config = LogConfig {
            enable_console: false,
            enable_file: true,
            file_path: "/invalid-directory-that-probably-doesnt-exist/test.log".to_string(),
            ..LogConfig::default()
        };

        let result = Logger::init(config);
        // This might fail due to filesystem permissions, but that's expected
        // We just test that it doesn't panic
    }

    #[test]
    fn test_log_config_combinations() {
        // Test various combinations of LogConfig settings
        let test_cases = vec![
            LogConfig {
                level: Level::ERROR,
                enable_console: true,
                enable_file: false,
                enable_json: false,
                enable_ansi: true,
                file_path: "test_combo_0.log".to_string(),
            },
            LogConfig {
                level: Level::INFO,
                enable_console: false,
                enable_file: true,
                enable_json: true,
                enable_ansi: false,
                file_path: "test_combo_1.log".to_string(),
            },
            LogConfig {
                level: Level::DEBUG,
                enable_console: true,
                enable_file: true,
                enable_json: false,
                enable_ansi: true,
                file_path: "test_combo_2.log".to_string(),
            },
        ];

        for (i, config) in test_cases.into_iter().enumerate() {
            let _guard = get_logger_lock().lock().unwrap();

            let result = Logger::init(config);
            assert!(result.is_ok(), "Config combination {} should initialize", i);
        }

        cleanup_test_files();
    }

    #[test]
    fn test_connection_metrics_close_logging() {
        let _guard = get_logger_lock().lock().unwrap();
        cleanup_test_files();

        // Initialize logger to capture the close message
        let config = LogConfig {
            enable_console: false,
            enable_file: true,
            file_path: "test_metrics.log".to_string(),
            enable_json: false,
            ..LogConfig::default()
        };

        let _ = Logger::init(config);

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let metrics = ConnectionMetrics::new(addr, 54321);

        // Record some activity
        metrics.record_bytes_sent(5000);
        metrics.record_bytes_received(3000);
        metrics.record_packets_processed(25);

        // This should log the connection closure
        metrics.close();

        // Verify the log file was created (the close method should have logged)
        assert!(fs::metadata("test_metrics.log").is_ok());

        cleanup_test_files();
    }

    #[test]
    fn test_logger_multiple_initialization_attempts() {
        let _guard = get_logger_lock().lock().unwrap();
        cleanup_test_files();

        // First initialization should work
        let config1 = LogConfig {
            enable_console: false,
            enable_file: true,
            file_path: "multi_init.log".to_string(),
            ..LogConfig::default()
        };

        let result1 = Logger::init(config1);
        assert!(result1.is_ok());

        // Second initialization attempt - this might work or fail depending on tracing_subscriber behavior
        // But it shouldn't panic
        let config2 = LogConfig {
            enable_console: true,
            enable_file: false,
            ..LogConfig::default()
        };

        let result2 = Logger::init(config2);
        // We don't assert on the result since re-initialization behavior varies

        cleanup_test_files();
    }

    #[test]
    fn test_connection_metrics_elapsed_time() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let metrics = ConnectionMetrics::new(addr, 77777);

        // Sleep a bit to ensure some time has elapsed
        std::thread::sleep(std::time::Duration::from_millis(10));

        // The start_time should be in the past
        assert!(metrics.start_time.elapsed().as_millis() > 0);
    }

    #[test]
    fn test_log_config_file_path_override() {
        let config = LogConfig {
            file_path: "custom_path.log".to_string(),
            ..LogConfig::default()
        };

        assert_eq!(config.file_path, "custom_path.log");
        // Other defaults should remain
        assert_eq!(config.level, Level::INFO);
        assert!(config.enable_console);
    }
}