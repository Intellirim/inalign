#!/bin/bash
set -e

# In-A-Lign MCP Server Entrypoint
# Supports multiple run modes: mcp, api, worker

MODE=${1:-mcp}

echo "Starting In-A-Lign in ${MODE} mode..."

case "$MODE" in
    mcp)
        # Run MCP server (stdio mode for Claude/Cursor)
        exec python -m inalign_mcp.server
        ;;
    api)
        # Run REST API server
        exec python -c "from inalign_mcp.query_api import run_api; run_api(host='0.0.0.0', port=${API_PORT:-8080})"
        ;;
    worker)
        # Run background worker for analysis
        exec python -c "
import time
import logging
from inalign_mcp.graph_store import get_graph_store
from inalign_mcp.graph_rag import GraphRAGAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('inalign-worker')

store = get_graph_store()
analyzer = GraphRAGAnalyzer(store)

logger.info('Worker started. Running continuous analysis...')
while True:
    # Periodic analysis tasks would go here
    time.sleep(60)
"
        ;;
    shell)
        # Interactive shell for debugging
        exec /bin/bash
        ;;
    *)
        exec "$@"
        ;;
esac
