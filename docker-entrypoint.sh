#!/bin/sh

# If .env doesn't exist but ENV vars are provided, create .env
if [ ! -f /app/.env ] && [ -n "$DATABASE_URL" ]; then
    echo "DATABASE_URL=$DATABASE_URL" > /app/.env
    # Add other variables as needed
    echo "RUST_LOG=info" >> /app/.env
fi

# If .env exists, use it (for local development)
if [ -f /app/.env ]; then
    export $(grep -v '^#' /app/.env | xargs)
fi

exec "$@"