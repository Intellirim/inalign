@echo off
REM In-A-Lign Quick Scanner for Windows
REM Usage: scan.bat "text to scan"

python "%~dp0inalign_scanner.py" --hook-mode %*
