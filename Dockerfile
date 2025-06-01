# Use official Rust image
FROM rust:1.70 as builder

# Install system dependencies (CRITICAL for cc linker)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy dependency files
COPY Cargo.toml Cargo.lock ./

# Create dummy source files for caching dependencies
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs

# Fetch dependencies with proper cache mounting
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo_registry \
    cargo fetch --locked || \
    (echo "Retrying cargo fetch..." && sleep 5 && cargo fetch --locked)

# Copy actual source code
COPY src ./src

# Build with cache
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo_registry \
    --mount=type=cache,target=/app/target,id=cargo_target \
    cargo build --release

# Final stage
FROM debian:buster-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl1.1 \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/kharon-server ./kharon-server

# Run the application
CMD ["./kharon-server"]