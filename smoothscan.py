#!/usr/bin/env python3
"""
Smooth Scanner - a fast, beautiful network scanner for Kali Linux.

Discovers live hosts (ARP), resolves MAC vendors, scans TCP ports,
grabs service banners, guesses the OS from TTL, and exports results.

For authorized use only. Scan only networks and devices you own or
have explicit written permission to test.
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ----------------------------------------------------------------------
# Optional / third-party imports with friendly errors
# ----------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        TimeElapsedColumn, MofNCompleteColumn,
    )
    from rich.text import Text
    from rich import box
except ImportError:
    sys.stderr.write(
        "\n[!] Missing dependency 'rich'. Install requirements first:\n"
        "    pip3 install -r requirements.txt --break-system-packages\n\n"
    )
    sys.exit(1)

console = Console()

# scapy is only needed for ARP discovery; import lazily so port-only
# scans still work without root / without scapy.
def _import_scapy():
    try:
        from scapy.all import ARP, Ether, srp, conf  # noqa
        conf.verb = 0
        return ARP, Ether, srp
    except ImportError:
        return None, None, None


__version__ = "1.0.0"

BANNER = r"""
   _____                       _   _      _____
  / ____|                     | | | |    / ____|
 | (___  _ __ ___   ___   ___ | |_| |__ | (___   ___ __ _ _ __
  \___ \| '_ ` _ \ / _ \ / _ \| __| '_ \ \___ \ / __/ _` | '_ \
  ____) | | | | | | (_) | (_) | |_| | | |____) | (_| (_| | | | |
 |_____/|_| |_| |_|\___/ \___/ \__|_| |_|_____/ \___\__,_|_| |_|
"""

# A small curated list of common, useful ports + service names.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s",
    1025: "nfs", 1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    2375: "docker", 3000: "node", 3306: "mysql", 3389: "rdp", 5000: "upnp",
    5060: "sip", 5432: "postgres", 5900: "vnc", 5985: "winrm", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9000: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
}

TOP_PORTS = list(COMMON_PORTS.keys())


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def banner():
    console.print(Text(BANNER, style="bold cyan"))
    sub = Text()
    sub.append("  Smooth Scanner ", style="bold white")
    sub.append(f"v{__version__}", style="bold magenta")
    sub.append("  •  fast • beautiful • authorized use only", style="dim")
    console.print(sub)
    console.print()


def is_root():
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def parse_targets(target):
    """Accept a single IP, CIDR (192.168.1.0/24) or range (192.168.1.10-50)."""
    target = target.strip()
    # range form a.b.c.x-y
    m = re.match(r"^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$", target)
    if m:
        base, start, end = m.group(1), int(m.group(2)), int(m.group(3))
        if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
            raise ValueError("Invalid range bounds.")
        return [f"{base}.{i}" for i in range(start, end + 1)]
    # CIDR
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        return [str(h) for h in net.hosts()]
    # single host (validates)
    ipaddress.ip_address(target)
    return [target]


def parse_ports(spec):
    """Accept '22,80,443', '1-1024', 'top', or 'all'."""
    if spec is None or spec == "top":
        return TOP_PORTS
    if spec == "all":
        return list(range(1, 65536))
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            lo, hi = int(lo), int(hi)
            ports.update(range(lo, hi + 1))
        elif chunk:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p < 65536)


# ----------------------------------------------------------------------
# Vendor lookup (offline-first, online fallback)
# ----------------------------------------------------------------------
class VendorResolver:
    def __init__(self):
        self._lib = None
        try:
            from mac_vendor_lookup import MacLookup
            self._lib = MacLookup()
        except Exception:
            self._lib = None

    def lookup(self, mac):
        if not mac:
            return "-"
        if self._lib:
            try:
                return self._lib.lookup(mac)
            except Exception:
                return "Unknown"
        return "Unknown"


# ----------------------------------------------------------------------
# ARP host discovery
# ----------------------------------------------------------------------
def arp_discover(hosts, timeout=2, vendor=None):
    ARP, Ether, srp = _import_scapy()
    if ARP is None:
        console.print("[yellow][!] scapy not available — skipping ARP discovery.[/yellow]")
        return []
    if not is_root():
        console.print("[yellow][!] ARP discovery needs root. Run with sudo for host discovery.[/yellow]")
        return []

    discovered = []
    # Build one request per /24 chunk for efficiency
    pdst = list(hosts)
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]ARP discovery"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("arp", total=len(pdst))
        # scapy can take a list of IPs directly
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=pdst)
        answered, _ = srp(pkt, timeout=timeout, retry=1)
        prog.update(task, completed=len(pdst))

    seen = {}
    for _, rcv in answered:
        ip = rcv.psrc
        mac = rcv.hwsrc.lower()
        if ip not in seen:
            seen[ip] = mac
    for ip, mac in seen.items():
        v = vendor.lookup(mac) if vendor else "Unknown"
        discovered.append({"ip": ip, "mac": mac, "vendor": v})
    discovered.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    return discovered


# ----------------------------------------------------------------------
# Port scanning + banner grab + TTL OS guess
# ----------------------------------------------------------------------
def grab_banner(ip, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # nudge HTTP services to talk
            if port in (80, 8080, 8000, 8888, 9000):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            text = data.decode(errors="ignore").strip()
            return text.splitlines()[0][:80] if text else ""
    except Exception:
        return ""


def scan_port(ip, port, timeout=0.6):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return port
    except Exception:
        pass
    return None


def ttl_os_guess(ip, timeout=1):
    """Rough OS family guess from ping TTL. Best-effort, non-fatal."""
    try:
        import subprocess
        out = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 1,
        ).stdout
        m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        if not m:
            return "-"
        ttl = int(m.group(1))
        if ttl <= 64:
            return "Linux/Unix"
        if ttl <= 128:
            return "Windows"
        return "Network/Other"
    except Exception:
        return "-"


def scan_host_ports(ip, ports, threads, timeout, do_banner):
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res is not None:
                open_ports.append(res)
    open_ports.sort()
    results = []
    for p in open_ports:
        svc = COMMON_PORTS.get(p, "unknown")
        bnr = grab_banner(ip, p) if do_banner else ""
        results.append({"port": p, "service": svc, "banner": bnr})
    return results


# ----------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------
def print_hosts_table(hosts):
    if not hosts:
        return
    t = Table(title="Live Hosts (ARP)", box=box.ROUNDED, header_style="bold cyan",
              title_style="bold white")
    t.add_column("IP Address", style="green")
    t.add_column("MAC Address", style="yellow")
    t.add_column("Vendor", style="magenta")
    for h in hosts:
        t.add_row(h["ip"], h["mac"], h.get("vendor", "-"))
    console.print(t)
    console.print()


def print_ports_table(ip, os_guess, ports):
    title = f"{ip}"
    if os_guess and os_guess != "-":
        title += f"   ·   OS guess: {os_guess}"
    t = Table(title=title, box=box.ROUNDED, header_style="bold cyan",
              title_style="bold white")
    t.add_column("Port", style="green", justify="right")
    t.add_column("State", style="bold green")
    t.add_column("Service", style="yellow")
    t.add_column("Banner", style="dim")
    if not ports:
        t.add_row("-", "no open ports", "-", "-")
    for p in ports:
        t.add_row(str(p["port"]), "open", p["service"], p["banner"] or "-")
    console.print(t)
    console.print()


def export_results(results, path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
    elif ext == ".csv":
        rows = []
        for host in results["hosts"]:
            ports = host.get("ports", [])
            if ports:
                for p in ports:
                    rows.append({
                        "ip": host["ip"], "mac": host.get("mac", "-"),
                        "vendor": host.get("vendor", "-"),
                        "os_guess": host.get("os_guess", "-"),
                        "port": p["port"], "service": p["service"],
                        "banner": p["banner"],
                    })
            else:
                rows.append({
                    "ip": host["ip"], "mac": host.get("mac", "-"),
                    "vendor": host.get("vendor", "-"),
                    "os_guess": host.get("os_guess", "-"),
                    "port": "", "service": "", "banner": "",
                })
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=[
                "ip", "mac", "vendor", "os_guess", "port", "service", "banner"])
            w.writeheader()
            w.writerows(rows)
    else:
        console.print(f"[yellow][!] Unknown export extension '{ext}'. Use .json or .csv[/yellow]")
        return
    console.print(f"[green][+] Results saved to[/green] [bold]{path}[/bold]")


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        prog="smoothscan",
        description="Smooth Scanner - fast, beautiful network scanner for Kali Linux.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  sudo ./smoothscan.py -t 192.168.1.0/24 --arp\n"
            "  sudo ./smoothscan.py -t 192.168.1.0/24 --full\n"
            "  ./smoothscan.py -t 192.168.1.10 -p 1-1024 -b\n"
            "  sudo ./smoothscan.py -t 192.168.1.0/24 --full -o results.json\n"
        ),
    )
    parser.add_argument("-t", "--target", required=True,
                        help="IP, CIDR (192.168.1.0/24) or range (192.168.1.10-50)")
    parser.add_argument("-p", "--ports", default="top",
                        help="Ports: '22,80,443', '1-1024', 'top' (default), or 'all'")
    parser.add_argument("--arp", action="store_true",
                        help="ARP host discovery only (needs sudo)")
    parser.add_argument("--full", action="store_true",
                        help="Full scan: ARP discovery + port scan + banners + OS guess")
    parser.add_argument("-b", "--banner", action="store_true",
                        help="Grab service banners on open ports")
    parser.add_argument("--threads", type=int, default=200,
                        help="Concurrent port-scan threads (default 200)")
    parser.add_argument("--timeout", type=float, default=0.6,
                        help="Per-port connect timeout in seconds (default 0.6)")
    parser.add_argument("-o", "--output",
                        help="Export results to a .json or .csv file")
    parser.add_argument("--no-banner-art", action="store_true",
                        help="Hide the ASCII banner")
    parser.add_argument("-V", "--version", action="version",
                        version=f"Smooth Scanner {__version__}")
    args = parser.parse_args()

    if not args.no_banner_art:
        banner()

    try:
        hosts = parse_targets(args.target)
    except Exception as e:
        console.print(f"[red][!] Invalid target:[/red] {e}")
        sys.exit(1)

    try:
        ports = parse_ports(args.ports)
    except Exception as e:
        console.print(f"[red][!] Invalid port spec:[/red] {e}")
        sys.exit(1)

    console.print(Panel.fit(
        f"[bold]Target[/bold]   {args.target}  ([cyan]{len(hosts)}[/cyan] host(s))\n"
        f"[bold]Ports[/bold]    {len(ports)} port(s)\n"
        f"[bold]Mode[/bold]     {'FULL' if args.full else ('ARP' if args.arp else 'PORT SCAN')}\n"
        f"[bold]Started[/bold]  {datetime.now():%Y-%m-%d %H:%M:%S}",
        border_style="cyan", title="[bold]Scan Configuration[/bold]",
    ))
    console.print()

    started = time.time()
    vendor = VendorResolver()
    results = {"target": args.target, "started": datetime.now().isoformat(), "hosts": []}

    # ---- Discovery phase ----
    discovered = []
    if args.arp or args.full:
        discovered = arp_discover(hosts, vendor=vendor)
        print_hosts_table(discovered)
        if args.arp and not args.full:
            for h in discovered:
                results["hosts"].append(h)
            if args.output:
                export_results(results, args.output)
            _summary(discovered, [], started)
            return

    # If full scan and ARP found hosts, scan only those (much faster).
    if args.full and discovered:
        scan_hosts = discovered
    else:
        # Port-scan everything in the target spec.
        scan_hosts = [{"ip": ip, "mac": "-", "vendor": "-"} for ip in hosts]

    # ---- Port scan phase ----
    do_banner = args.banner or args.full
    total_open = 0
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]Port scanning"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("scan", total=len(scan_hosts))
        for host in scan_hosts:
            ip = host["ip"]
            open_ports = scan_host_ports(ip, ports, args.threads, args.timeout, do_banner)
            os_guess = ttl_os_guess(ip) if args.full else "-"
            host_result = {
                "ip": ip, "mac": host.get("mac", "-"),
                "vendor": host.get("vendor", "-"),
                "os_guess": os_guess, "ports": open_ports,
            }
            results["hosts"].append(host_result)
            if open_ports:
                total_open += len(open_ports)
                prog.console.print()  # spacing above the table
                print_ports_table(ip, os_guess, open_ports)
            prog.advance(task)

    if args.output:
        export_results(results, args.output)

    _summary(discovered, results["hosts"], started, total_open)


def _summary(discovered, host_results, started, total_open=0):
    elapsed = time.time() - started
    hosts_with_ports = sum(1 for h in host_results if h.get("ports"))
    console.print(Panel.fit(
        f"[green]Live hosts found:[/green] {len(discovered) if discovered else hosts_with_ports}\n"
        f"[green]Open ports found:[/green] {total_open}\n"
        f"[green]Elapsed:[/green] {elapsed:.1f}s",
        border_style="green", title="[bold]Scan Complete[/bold]",
    ))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red][!] Interrupted by user.[/red]")
        sys.exit(130)
