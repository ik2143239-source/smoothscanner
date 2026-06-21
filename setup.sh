#!/usr/bin/env bash
#
# Smooth Scanner installer for Kali Linux / Debian-based distros.
# Installs Python dependencies and makes `smoothscan` runnable from anywhere.
#
set -e

echo "[*] Smooth Scanner setup"

# 1. System packages (python3 + pip are usually already on Kali)
if command -v apt >/dev/null 2>&1; then
    echo "[*] Ensuring python3 + pip are present..."
    sudo apt update -y >/dev/null 2>&1 || true
    sudo apt install -y python3 python3-pip >/dev/null 2>&1 || true
fi

# 2. Python dependencies
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages

# 3. Pre-download the MAC vendor database (optional, makes first run faster)
echo "[*] Updating MAC vendor database (optional)..."
python3 -c "from mac_vendor_lookup import MacLookup; MacLookup().update_vendors()" 2>/dev/null || \
    echo "    (skipped - will fetch on first use)"

# 4. Make executable
chmod +x smoothscan.py

# 5. Optional: install a global 'smoothscan' command
read -r -p "[?] Install a global 'smoothscan' command into /usr/local/bin? [y/N] " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
    sudo ln -sf "$(pwd)/smoothscan.py" /usr/local/bin/smoothscan
    echo "[+] You can now run: sudo smoothscan -t 192.168.1.0/24 --full"
fi

echo
echo "[+] Done. Try:  sudo ./smoothscan.py -t 192.168.1.0/24 --full"
