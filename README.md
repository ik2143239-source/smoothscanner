# Smooth Scanner

A fast, beautiful network scanner for Kali Linux. Discovers live hosts on a LAN
(ARP), resolves MAC vendors, scans TCP ports across many hosts in parallel,
grabs service banners, takes a rough guess at the OS, and exports everything to
JSON or CSV — all wrapped in a clean, colorful terminal UI.

> Inspired by simple ARP scanners, rebuilt with a polished interface and a lot
> more capability.

```
   _____                       _   _      _____
  / ____|                     | | | |    / ____|
 | (___  _ __ ___   ___   ___ | |_| |__ | (___   ___ __ _ _ __
  \___ \| '_ ` _ \ / _ \ / _ \| __| '_ \ \___ \ / __/ _` | '_ \
  ____) | | | | | | (_) | (_) | |_| | | |____) | (_| (_| | | | |
 |_____/|_| |_| |_|\___/ \___/ \__|_| |_|_____/ \___\__,_|_| |_|
```

## Features

- **ARP host discovery** — finds every live device on a subnet, with IP + MAC.
- **MAC vendor lookup** — turns MAC addresses into manufacturer names (offline DB).
- **Multithreaded TCP port scanning** — hundreds of ports per second per host.
- **Service detection** — names common services (ssh, http, mysql, rdp, …).
- **Banner grabbing** — pulls service banners (e.g. server headers) where available.
- **OS guessing** — rough Linux/Windows guess from ping TTL.
- **Flexible targets** — single IP, CIDR (`192.168.1.0/24`), or range (`192.168.1.10-50`).
- **Flexible ports** — `top` (curated common ports), `1-1024`, `22,80,443`, or `all`.
- **Export** — save results to `.json` or `.csv`.
- **Beautiful terminal UI** — tables, panels, spinners, and progress bars via `rich`.

## Legal / Ethical Use

This tool is for **authorized testing and education only**. Only scan networks
and devices that you own or have **explicit written permission** to test.
Unauthorized scanning may be illegal in your jurisdiction. You are responsible
for how you use it.

## Requirements

- Kali Linux (or any Debian-based Linux) — works on most Linux distros
- Python 3.8+
- Root privileges **only** for ARP discovery (`--arp` / `--full`)

## Installation

```bash
git clone https://github.com/<your-username>/smooth-scanner.git
cd smooth-scanner
chmod +x setup.sh
./setup.sh
```

Or install dependencies manually:

```bash
pip3 install -r requirements.txt --break-system-packages
chmod +x smoothscan.py
```

## Usage

```bash
# ARP host discovery on your subnet (needs sudo)
sudo ./smoothscan.py -t 192.168.1.0/24 --arp

# Full scan: discover hosts, then port-scan each with banners + OS guess
sudo ./smoothscan.py -t 192.168.1.0/24 --full

# Port scan a single host (no root needed)
./smoothscan.py -t 192.168.1.10 -p 1-1024 -b

# Scan a range and export to JSON
sudo ./smoothscan.py -t 192.168.1.10-50 --full -o results.json

# Scan specific ports and export to CSV
./smoothscan.py -t 192.168.1.10 -p 22,80,443,8080 -b -o results.csv
```

If you installed the global command during setup:

```bash
sudo smoothscan -t 192.168.1.0/24 --full
```

## Options

| Flag | Description |
|------|-------------|
| `-t`, `--target` | IP, CIDR, or range to scan (**required**) |
| `-p`, `--ports` | `top` (default), `all`, `1-1024`, or `22,80,443` |
| `--arp` | ARP host discovery only (needs sudo) |
| `--full` | ARP discovery + port scan + banners + OS guess |
| `-b`, `--banner` | Grab service banners on open ports |
| `--threads` | Concurrent port-scan threads (default 200) |
| `--timeout` | Per-port connect timeout in seconds (default 0.6) |
| `-o`, `--output` | Export results to a `.json` or `.csv` file |
| `--no-banner-art` | Hide the ASCII banner |
| `-V`, `--version` | Show version |

## How it works

1. **Targets** are expanded into a list of IPs.
2. **ARP discovery** (when `--arp`/`--full`) sends ARP requests via scapy and
   listens for replies — fast and reliable on a local LAN. Found MACs are run
   through an offline vendor database.
3. **Port scanning** uses a thread pool of TCP connect scans. Open ports are
   matched to a service table; with `-b`/`--full` it reads the first banner line.
4. **OS guess** pings the host once and infers a family from the TTL.
5. **Output** is rendered as live tables and can be exported.

## Troubleshooting

- **"ARP discovery needs root"** — run with `sudo`. Port-only scans don't need root.
- **"Missing dependency 'rich'"** — run `pip3 install -r requirements.txt --break-system-packages`.
- **scapy import errors** — `sudo apt install python3-scapy` or reinstall via pip.
- **Vendor shows "Unknown"** — run once with internet so the OUI database can download,
  or run `python3 -c "from mac_vendor_lookup import MacLookup; MacLookup().update_vendors()"`.

## License

MIT — see [LICENSE](LICENSE).
