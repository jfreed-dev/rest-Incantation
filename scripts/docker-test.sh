#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== Building Docker image ==="
docker compose build

echo ""
echo "=== Running tests in Docker ==="
docker compose run --rm test

echo ""
echo "=== Tests completed successfully ==="
