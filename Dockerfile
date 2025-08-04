# === Build stage ===
FROM rust:1.87-slim AS builder

ENV CARGO_BIN_DIR=/cargo-bin

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

COPY . .

RUN cargo build --release


# === Runtime stage ===
FROM debian:bookworm-slim

# Install runtime dependencies including CA certificates and SSL
RUN apt-get update && apt-get install -y \
    libpq5 \
    libpq-dev \
    libssl-dev \
    openssl \
    ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/kharon-server /usr/local/bin/app
COPY --from=builder /cargo-bin/bin/diesel /usr/local/bin/diesel

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# script to check if .env exists and copy it
RUN if [ -f .env ]; then cp .env /app/.env; else echo ".env file not found, skipping copy."; fi

# COPY .env /app/.env

WORKDIR /app

ENV RUST_LOG=info

EXPOSE 8080

CMD ["app"]