
#!/bin/bash

# Update System
echo "[+] Updating System..."
sudo apt update && sudo apt upgrade -y

# Install Python & Pip
echo "[+] Installing Python..."
sudo apt install -y python3 python3-pip python3-venv

# Install Honeypot (Example: Cowrie) - SIMULATION ONLY
# In a real deployment, you would install Cowrie here.
# For this demo, we assume standard SSH logging.

# Setup Virtual Env for Log Collector
echo "[+] Setting up Log Collector Environment..."
python3 -m venv venv
source venv/bin/activate
pip install requests

echo "[+] Setup Complete. Update API_URL in log_collector.py and run:"
echo "    source venv/bin/activate"
echo "    sudo python3 log_collector.py"
