# 🦀 RustChannel - High-Performance Application Channel for Financial Systems

![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)
![License](https://img.shields.io/badge/License-MIT-blue)
![Async](https://img.shields.io/badge/Async-Tokio-green)
![Config](https://img.shields.io/badge/Config-YAML%2FJSON-brightgreen)

rust-channel is an ultra-low-latency channel and protocol filter designed specifically for **financial and trading applications**.  
Built in **Rust** with performance and safety in mind, it filters, validates, and routes application-layer messages (FIX, ISO8583, or custom binary formats) while maintaining **microsecond-level latency**.

---

## 🚀 Features

- ⚡ High Performance: Tokio async runtime for maximum throughput

- 🧩 Protocol Support: FIX, binary, and custom message formats

- 🔍 Real-time Filtering: Packet inspection and policy-based filtering

- 🔄 Bidirectional Proxy: Full TCP/TLS proxy with connection tracking

- 🧾 Structured Logging: Rich logging with multiple severity levels

- 🚫 Rate Limiting: Per-connection DoS protection

- 🔒 TLS Support: Secure communication with rustls

- 🧵 Thread-Safe: Fully concurrent design

- ⚙️ Configurable: Flexible policy and FIX parsing via YAML/JSON files

- 📊 Metrics: Built-in metrics collection and export

- 🔧 Hot-Reload Ready: Architecture supports dynamic configuration updates

---

## 📋 Table of Contents

- [Installation](#️-installation)
- [Quick Start](#-quick-start)
- [Configuration](#️-configuration)
- [FIX Protocol](#️-fix-protocol-configuratio)
- [Logging](#-logging)
- [Policy Rules](#️-policy-rules)
- [Architecture](#-architecture)
- [Performance](#-performance)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)
- [Roadmap](#-roadmap)

---

## 🛠️ Installation

### Prerequisites
- Rust **1.70+**
- Cargo package manager

### Build from Source
```bash
git clone https://github.com/m05t4f4g/rust-channel.git
cd rustchannel
cargo build --release
./target/release/rust-channel
```

### Docker (Optional)
```dockerfile
FROM rust:1.70-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev

WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache openssl

# Copy binary from builder stage
COPY --from=builder /app/target/release/rust-channel /usr/local/bin/

# Copy configuration files
COPY config/ /etc/rustchannel/

# Expose port
EXPOSE 8080

# Run the application
CMD ["rust-channel", "--fix-config", "/etc/rustchannel/fix-parser.yaml", "--policy-config", "/etc/rustchannel/policy-rules.yaml"]
```

---

## 🚀 Quick Start

1. **Start a Test Backend**
```bash
nc -l 8081
```

2. **Run RustCahnnel**
```bash
cargo run -- --listen-addr 127.0.0.1:8080 --backend-addr 127.0.0.1:8081
```

3. **Test the Channel**
```bash
echo -n "FIX4.4|9=100|35=D|49=SENDER|56=TARGET|34=1|52=20250101-10:00:00|11=12345|" | nc localhost 8080
```

---

## ⚙️ Configuration

### Command Line Options
```
Usage: rust-channel [OPTIONS]
  -l, --listen-addr ADDR    Listen address (default: 127.0.0.1:8080)
  -b, --backend-addr ADDR   Backend address (default: 127.0.0.1:8081)
  --tls                     Enable TLS
  --cert-file FILE          Certificate file (required for TLS)
  --key-file FILE           Key file (required for TLS)
  --fix-config FILE         FIX parser config file (default: config/fix-parser.yaml)
  --policy-config FILE      Policy rules config file (default: config/policy-rules.yaml)
  --log-level LEVEL         Log level: error, warn, info, debug, trace
  --log-file                Enable file logging
  --log-file-path FILE      Log file path (default: rustchannel.log)
  --log-json                Enable JSON logging format
  --no-color                Disable ANSI colors in console output
  -h, --help                Show this help message
```


#### Example with Custom Configs
```
cargo run -- \
  --listen-addr 127.0.0.1:8443 \
  --backend-addr 127.0.0.1:9443 \
  --tls \
  --cert-file certs/server.crt \
  --key-file certs/server.key \
  --fix-config my-fix-config.yaml \
  --policy-config my-policy-rules.yaml \
  --log-level debug
```

---
### 🧩 FIX Protocol Configuration
RustChannel provides extensive FIX protocol support with configurable parsing:
#### FIX Parser Configuration (YAML)
```
# config/fix-parser.yaml
enabled: true
inspect_tags:
  - 8    # BeginString
  - 9    # BodyLength
  - 35   # MsgType
  - 49   # SenderCompID
  - 56   # TargetCompID
  - 34   # MsgSeqNum
  - 52   # SendingTime
  - 10   # CheckSum
  - 11   # ClOrdID
  - 38   # OrderQty
  - 40   # OrdType
  - 44   # Price
  - 54   # Side
  - 55   # Symbol
required_tags:
  - 8
  - 9
  - 35
  - 49
  - 56
  - 34
  - 52
  - 10
validate_checksum: true
validate_structure: true
log_inspected_tags: true
max_message_length: 8192
min_message_length: 20
```
#### Configuration Options
- enabled: Enable/disable FIX parsing

- inspect_tags: List of FIX tags to extract and log

- required_tags: Mandatory tags for valid FIX messages

- validate_checksum: Enable FIX checksum validation

- validate_structure: Validate FIX message structure

- log_inspected_tags: Log extracted FIX tags for debugging

- max_message_length: Maximum allowed FIX message size

- min_message_length: Minimum allowed FIX message size

---

## 📝 Logging

RustChannel provides structured logging with multiple formats and severity levels.

### Environment Variables
```bash
RUST_LOG=debug cargo run
RUST_BACKTRACE=1 cargo run
RUST_LOG=rustchannel=info,tokio=warn cargo run --release
```
### Log Configuration
```bash
# Enable JSON logging to file
cargo run -- --log-level info --log-file --log-json --log-file-path /var/log/rustchannel.json

# Console logging with colors
cargo run -- --log-level debug --no-color
```

### Structured Log Fields

- client_addr: Client IP address and port

- connection_id: Unique connection identifier

- packet_length: Size of processed packet

- bytes_sent/received: Traffic volume metrics

- rule_name: Matched policy rule name

- action: Policy decision (Allow/Deny/RateLimit)


---

## 🛡️ Policy Rules

RustChannel uses a flexible policy engine with YAML/JSON configuration:

### Policy Rules Configuration (YAML)
```
# config/policy-rules.yaml
- name: "allow_fix_messages"
  match_pattern:
    msg_type: "FIX"
    min_length: 20
    max_length: 8192
  action: Allow

- name: "allow_local_binary"
  match_pattern:
    msg_type: "BINARY"
    source_ip: "127.0.0.1"
    min_length: 8
    max_length: 1024
  action: Allow

- name: "block_short_packets"
  match_pattern:
    min_length: 8
  action: Deny

- name: "rate_limit_protection"
  match_pattern: {}
  action: RateLimit(100)
```
### Policy Actions
- Allow: Permit the message to pass through

- Deny: Block the message and close connection

- RateLimit(n): Apply rate limiting of n messages per second

---

### Match Patterns
- msg_type: Match specific message types (FIX, BINARY, etc.)

- source_ip: Filter by source IP address

- min_length: Minimum packet length requirement

- max_length: Maximum packet length limit


## 🏗️ Architecture

```
Client       →            RustChannel       →     Backend

┌──────────┐ → ┌──────────────────────────┐ → ┌──────────┐
│  Client  │   │ RustChannel              │   │Backend   │
│          │   │   ┌─ Inspection Engine   │   │          │
│          │   │   ├─ Policy Engine       │   │          │
│          │   │   ├─ Connection Tracker  │   │          │
│          │   │   └─ Metrics Collector   │   │          │
│          │   │                          │   │          │
│          │   │                          │   │          │                   
└──────────┘   └──────────────────────────┘   └──────────┘
```

### Core components:
- Transaction Gateway: Handles incoming TCP/TLS connections with async I/O

- Packet Inspection: Multi-protocol parser (FIX, binary) with configurable validation

- Policy Engine: Rule-based filtering with YAML/JSON configuration

- Connection Tracker: Manages connection state, statistics, and rate limiting

- Backend Connector: Forwards traffic to backend services with load balancing

- Metrics Collector: Real-time performance and traffic metrics

---
### Protocol Support
- FIX Protocol: Full parsing, validation, and tag inspection

- Binary Protocols: Custom header/footer based parsing

- Custom Protocols: Extensible parser interface

---

## 📊 Performance

- Latency: microsecond-level
- Throughput target: 10,000+ concurrent connections
- Lock-free data structures and async I/O

### Performance Tips
```bash
# Release build with optimizations
cargo build --release

# Set optimal Tokio runtime
export TOKIO_WORKER_THREADS=num_cpus

# Monitor with built-in metrics
curl http://localhost:8081/metrics
```

---

## 🛠️ Development

```bash
cargo build
cargo test
cargo clippy --all-features -- -D warnings
cargo fmt --all
```

### Project structure:
```
src/
├── main.rs                 # Application entry point
├── config/
│   ├── mod.rs             # Configuration management
│   └── models.rs          # Configuration structures
├── gateway/
│   ├── mod.rs             # Transaction gateway
│   ├── tcp.rs             # TCP connection handler
│   ├── tls.rs             # TLS connection handler
│   └── backend.rs         # Backend connection management
├── inspection/
│   ├── mod.rs             # Packet inspection engine
│   ├── packet.rs          # Protocol parsers
│   └── rules.rs           # Inspection rules
├── policy/
│   ├── mod.rs             # Policy engine
│   └── engine.rs          # Rule evaluation
├── tracker/
│   ├── mod.rs             # Connection tracking
│   └── session.rs         # Session management
├── metrics/
│   ├── mod.rs             # Metrics collection
│   └── exporter.rs        # Metrics export
└── logger/
    └── mod.rs             # Structured logging system
```
### Configuration Files
```
config/
├── fix-parser.yaml        # FIX protocol configuration
├── policy-rules.yaml      # Traffic filtering rules
└── server-config.yaml     # Server settings (optional)
```
---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit and push changes
4. Open a Pull Request

Follow Rust conventions and include tests for new functionality.

---

## 📄 License

This project is licensed under the **MIT License**.

---

## 📈 Roadmap

- Web administration interface
- Prometheus metrics integration
- Dynamic rule reloading
- Cluster deployment support
- Machine learning-based anomaly detection

---

