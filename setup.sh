#!/bin/bash

echo "[+] Setting up virtual environment..."
python3 -m venv evade_env
source evade_env/bin/activate

echo "[+] Installing requirements..."
pip install --upgrade pip
pip install lief capstone keystone-engine

echo "[+] Setup complete. To run:"
echo "source evade_env/bin/activate && python evade_r.py <your_exe>"
