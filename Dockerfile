# REX-BOT-AI Multi-Stage Dockerfile
# Stage 1: Python dependencies
# Stage 2: Node build (React dashboard)
# Stage 3: Runtime (minimal)

# ============================================================
# Stage 1: Python base with all dependencies
# ============================================================
FROM python:3.12-slim AS python-base

WORKDIR /app

# System deps for network tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    nmap \
    arp-scan \
    iproute2 \
    iptables \
    nftables \
    dnsutils \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY rex/ ./rex/
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# ============================================================
# Stage 2: Node build for React dashboard
# ============================================================
FROM node:20-alpine AS frontend-build

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --production=false 2>/dev/null || npm install
COPY frontend/ ./
RUN npm run build 2>/dev/null || mkdir -p dist

# ============================================================
# Stage 3: Runtime image
# ============================================================
FROM python:3.12-slim AS runtime

# Labels
LABEL org.opencontainers.image.title="REX-BOT-AI"
LABEL org.opencontainers.image.description="Open-source autonomous AI security agent"
LABEL org.opencontainers.image.source="https://github.com/rex-bot-ai/rex-bot-ai"
LABEL org.opencontainers.image.licenses="MIT"

# Create non-root user
RUN groupadd -r rex && useradd -r -g rex -d /etc/rex-bot-ai -s /bin/false rex

# System deps (runtime only)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    nmap \
    arp-scan \
    iproute2 \
    iptables \
    nftables \
    dnsutils \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python environment from builder
COPY --from=python-base /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=python-base /usr/local/bin /usr/local/bin
COPY --from=python-base /app /app

# Copy frontend build
COPY --from=frontend-build /app/dist /app/frontend/dist

# Create data directories
RUN mkdir -p /etc/rex-bot-ai /var/log/rex-bot-ai && \
    chown -R rex:rex /etc/rex-bot-ai /var/log/rex-bot-ai

# Environment
ENV REX_DATA_DIR=/etc/rex-bot-ai
ENV REX_LOG_LEVEL=info
ENV PYTHONUNBUFFERED=1
ENV OLLAMA_NOTELEMETRY=1

EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8443/api/health || exit 1

# Run as non-root for most operations
# Note: NET_ADMIN/NET_RAW capabilities granted via docker-compose
USER rex

ENTRYPOINT ["python", "-m", "rex.core"]
CMD []
