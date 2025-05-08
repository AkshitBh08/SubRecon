#!/bin/bash

echo "[*] Installing SubRecon dependencies..."

# Create a virtual environment (optional but good practice)
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Check for required binaries
echo "[*] Checking for Subfinder and Sublist3r..."

if ! command -v subfinder &> /dev/null; then
    echo "[!] Subfinder not found. Please install it from: https://github.com/projectdiscovery/subfinder"
else
    echo "[+] Subfinder is installed."
fi

if ! command -v sublist3r &> /dev/null; then
    echo "[!] Sublist3r not found. Please install it from: https://github.com/aboul3la/Sublist3r"
else
    echo "[+] Sublist3r is installed."
fi

echo "[*] Setup complete. You can now run SubRecon with:"
echo "    python3 subrecon.py <domain>"
