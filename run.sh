#!/bin/bash
# PDF Malware Scanner - Setup & Run Script
set -e

echo "======================================"
echo "  Dillu Analyzer                      "
echo "======================================"

# Check Python
python3 --version || { echo "Python 3 required"; exit 1; }

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

# Install dependencies
echo "[+] Installing dependencies..."
pip install -q flask werkzeug requests

# Try installing yara-python (optional but recommended)
echo "[+] Attempting to install yara-python..."
pip install -q yara-python 2>/dev/null && echo "    yara-python installed successfully" || echo "    yara-python install failed - using built-in pattern matching"

# Set environment variables
export FLASK_APP=app/app.py
export FLASK_ENV=development

# Optional: set VirusTotal API key
# export VIRUSTOTAL_API_KEY="your_key_here"

echo ""
echo "[+] Starting Dillu Analyzer..."
echo "    URL: http://localhost:5000"
echo "    Press Ctrl+C to stop"
echo ""

cd app && python3 app.py
