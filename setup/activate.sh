#!/bin/bash
# Source this to activate the project venv.
# Usage: source setup/activate.sh
# Or add to ~/.zshrc: alias pcap='cd /path/to/pcap-engine && source setup/activate.sh'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PARENT_VENV="$(dirname "$PROJECT_ROOT")/.venv"

# Prefer the shared .venv in the parent NetworkAnalysis-Research dir
if [ -f "$PARENT_VENV/bin/activate" ]; then
  source "$PARENT_VENV/bin/activate"
  echo "Virtual environment activated: $(python --version)"
  echo "Run: python engine/main.py --pcap <path_to_pcap>"
elif [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
  source "$PROJECT_ROOT/venv/bin/activate"
  echo "Virtual environment activated: $(python --version)"
else
  echo "ERROR: No venv found. Run: python3 -m venv venv && pip install -r requirements.txt"
fi
