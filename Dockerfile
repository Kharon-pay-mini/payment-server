# Use official Rust image
FROM rust:1.70 as builder

# Install system dependencies
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

# Build dependencies first (for Docker layer caching)
RUN cargo fetch --locked

# Copy actual source code
COPY src ./src

# Build the application
RUN cargo build --release

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