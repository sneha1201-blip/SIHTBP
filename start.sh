#!/usr/bin/env bash
# ==============================================================================
# AICTE Cyber Security Cell - One-Command Full-Stack Platform Launcher
# Smart India Hackathon (SIH Problem Statement ID: 26106)
# ==============================================================================

set -e

echo "=============================================================================="
echo "   AICTE CYBER SECURITY CELL | SMART INDIA HACKATHON 2026 (SIH ID: 26106)"
echo "   Starting Forensic Intelligence Platform (Backend + Frontend + Vault)..."
echo "=============================================================================="
echo ""

# Find Python 3
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    echo "[ERROR] Python 3 is not installed or not in PATH."
    exit 1
fi

# Run the cross-platform python orchestrator
exec "$PYTHON_CMD" run_platform.py

