# Use official Rust image
FROM rust:1.70 as builder

# Create app directory
WORKDIR /app

# Copy dependency files
COPY Cargo.toml Cargo.lock ./

# Create dummy lib.rs if needed (helps with Docker layer caching)
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs

# Fetch dependencies (with retry for network issues)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo fetch --locked || \
    (echo "Retrying cargo fetch..." && sleep 5 && cargo fetch --locked)

# Copy actual source code
COPY src ./src

# Build the application
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release

# Final stage
FROM debian:buster-slim

WORKDIR /app
COPY --from=builder /app/target/release/your-binary-name .

# Run the application
CMD ["./kharon-server"]