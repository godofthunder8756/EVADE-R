#!/bin/bash

VENV_DIR="evade_env"
PAYLOAD_PATH="$1"

if [ -z "$PAYLOAD_PATH" ]; then
    echo "Usage: ./run.sh <path_to_payload.exe>"
    exit 1
fi

# Check if venv exists
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Virtual environment not found. Running setup..."
    ./setup.sh
fi

# Activate virtual environment
source $VENV_DIR/bin/activate

# Run the Python main tool
echo "[*] Running EVADE-R on $PAYLOAD_PATH"
python main.py "$PAYLOAD_PATH"
