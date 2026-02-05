@echo off
echo ========================================
echo InALign - Starting Services
echo ========================================
echo.

cd /d "%~dp0"

echo [1/3] Starting Docker services...
docker compose up -d

echo.
echo [2/3] Waiting for services to be healthy...
timeout /t 30 /nobreak

echo.
echo [3/3] Checking service status...
docker compose ps

echo.
echo ========================================
echo Services started!
echo ========================================
echo.
echo Neo4j:      http://localhost:7474 (neo4j/inalign_dev)
echo Backend:    http://localhost:8000
echo Frontend:   http://localhost:3000
echo.
echo To run GraphRAG test:
echo   python tools/test_graphrag_integration.py
echo.
pause
