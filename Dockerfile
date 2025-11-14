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
COPY --from=builder /app/target/release/rustwall /usr/local/bin/

# Expose port
EXPOSE 8080

# Run the application
CMD ["rustwall"]