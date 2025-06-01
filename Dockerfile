FROM rust:1.75 as builder

# Install dependencies including CA certificates
RUN apt-get update && apt-get install -y \
    pkg-config libpq-dev build-essential libssl-dev curl \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create a clean cargo bin dir
RUN mkdir -p $CARGO_BIN_DIR
ENV PATH=$CARGO_BIN_DIR:$PATH
ENV CARGO_HOME=/cargo-home

# Install diesel CLI into $CARGO_BIN_DIR
RUN cargo install diesel_cli --no-default-features --features postgres --root $CARGO_BIN_DIR

WORKDIR /app

# Copy only Cargo.toml first
COPY Cargo.toml ./

# Copy source code
COPY src ./src

# Build without using the lock file (let Cargo resolve dependencies)
RUN cargo build --release

# Final stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    openssl \
    ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m appuser

COPY --from=builder /app/target/release/kharon-server-rs /usr/local/bin/app
COPY --from=builder /cargo-bin/bin/diesel /usr/local/bin/diesel
# Copy CA certificates from builder (redundant but ensures consistency)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY .env /app/.env

USER appuser
WORKDIR /app

ENV RUST_LOG=info

EXPOSE 8080

CMD ["app"]