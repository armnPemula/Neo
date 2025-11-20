#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR" || exit 1

source .env 2>/dev/null || true

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
else
    echo "Virtual environment not found. Please run setup first."
    exit 1
fi

echo "Initializing database..."
python3 main.py --init-db

if [ ! -f "server.crt" ] || [ ! -f "server.key" ]; then
    echo "Generating SSL certificates..."
    python3 main.py --generate-ssl
fi

echo "Starting NeoC2 server..."
exec python3 c2_service.py "$@"
