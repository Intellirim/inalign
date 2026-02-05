# In-A-Lign MCP Server - Production Dockerfile
# Multi-stage build for minimal image size

# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY pyproject.toml setup.py ./
COPY src/ src/

# Build wheel
RUN pip install --no-cache-dir build && \
    python -m build --wheel

# Production stage
FROM python:3.11-slim as production

WORKDIR /app

# Create non-root user
RUN groupadd -r inalign && useradd -r -g inalign inalign

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy wheel from builder
COPY --from=builder /app/dist/*.whl ./

# Install package with all extras
RUN pip install --no-cache-dir *.whl[neo4j,api] && rm *.whl

# Copy config
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Switch to non-root user
USER inalign

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    NEO4J_URI=bolt://neo4j:7687 \
    NEO4J_USERNAME=neo4j \
    NEO4J_PASSWORD=password \
    NEO4J_DATABASE=neo4j \
    LOG_LEVEL=INFO \
    API_PORT=8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import inalign_mcp; print('healthy')" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["mcp"]
