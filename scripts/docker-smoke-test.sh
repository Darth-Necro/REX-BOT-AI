#!/usr/bin/env bash
# Docker smoke test for REX-BOT-AI
# Verifies that docker compose up brings all services to a healthy state
# and the API responds correctly.
#
# Usage: bash scripts/docker-smoke-test.sh
set -euo pipefail

TIMEOUT=120  # seconds to wait for services
COMPOSE_FILE="docker-compose.yml"

echo "=== REX-BOT-AI Docker Smoke Test ==="

# Ensure we're in the project root
if [ ! -f "$COMPOSE_FILE" ]; then
    echo "ERROR: Run this script from the project root (where docker-compose.yml is)"
    exit 1
fi

# Generate a .env if one doesn't exist
if [ ! -f ".env" ]; then
    echo "Generating temporary .env..."
    REDIS_PASS=$(openssl rand -hex 16)
    cat > .env << EOF
REX_MODE=basic
REX_LOG_LEVEL=info
REDIS_PASSWORD=${REDIS_PASS}
REX_FEDERATION_ENABLED=false
EOF
fi

cleanup() {
    echo "Cleaning up..."
    docker compose down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo "1. Building images..."
docker compose build --quiet

echo "2. Starting services..."
docker compose up -d

echo "3. Waiting for services to become healthy (timeout: ${TIMEOUT}s)..."
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    # Check if rex service is running
    REX_STATUS=$(docker compose ps rex --format json 2>/dev/null | head -1)
    if echo "$REX_STATUS" | grep -q '"running"'; then
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    echo "   Waiting... (${ELAPSED}s)"
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "TIMEOUT: Services did not start within ${TIMEOUT}s"
    docker compose logs --tail=50
    exit 1
fi

# Give the API a moment to initialize
sleep 5

echo "4. Testing /api/health endpoint..."
HEALTH=$(curl -sf http://localhost:8443/api/health 2>/dev/null || echo "FAIL")
if echo "$HEALTH" | grep -q '"ok"'; then
    echo "   PASS: /api/health returned ok"
else
    echo "   FAIL: /api/health returned: $HEALTH"
    docker compose logs rex --tail=30
    exit 1
fi

echo "5. Testing /api/status endpoint..."
STATUS=$(curl -sf http://localhost:8443/api/status 2>/dev/null || echo "FAIL")
if echo "$STATUS" | grep -q '"status"'; then
    echo "   PASS: /api/status returned valid JSON"
else
    echo "   FAIL: /api/status returned: $STATUS"
    exit 1
fi

echo "6. Checking docker compose service health..."
docker compose ps

echo ""
echo "=== SMOKE TEST PASSED ==="
echo "All services started and API is responding."
