"""
Full-featured single-file Port Scanner (Option B)
Features:
 - Loads ports from defaultport.json (fallback built-in list)
 - Multi-threaded scanning with banner grabbing
 - Range scanning support
 - Whois lookup (optional, requires 'whois' CLI)
 - Nmap mode (optional, requires 'nmap' CLI)
 - Save results to JSON/CSV
 - Colorized output via colorama (optional)
"""

from __future__ import annotations
import socket
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime
import csv
import sys
import shutil

# This will make the output colorful which is much easier to read. 
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except Exception:
    class _C:
        RESET = ""
        BRIGHT = ""
        DIM = ""
    class ForeClass:
        RED = ""
        GREEN = ""
        YELLOW = ""
        CYAN = ""
        MAGENTA = ""
        BLUE = ""
        RESET = ""
    Fore = ForeClass()
    Style = _C()


DEFAULT_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 135, 139, 143, 161, 162,
    389, 443, 445, 465, 587, 631, 636, 993, 995, 1433, 1521, 1723, 3389, 3306, 5432, 27017
]


def readable_time():
    #use for record the scan for scanning_results
    return datetime.now().strftime("%Y%m%d_%H%M%S")   


class PortScanner:
    def __init__(self, ports_file: Optional[str] = None, workers: int = 200, timeout: float = 0.6):
        """
        ports_file: optional path to default_ports.json
        workers: number of threads for scanning
        timeout: socket timeout for connect attempts
        """
        self.workers = max(10, int(workers))
        self.timeout = float(timeout)

        if ports_file:
            self.ports_path = Path(ports_file)
        else:
            # default: look for default_ports.json next to script in config/ or current dir
            candidate = Path(__file__).resolve().parent / "default_ports.json"
            candidate2 = Path(__file__).resolve().parents[1] / "config" / "default_ports.json"
            self.ports_path = candidate if candidate.exists() else (candidate2 if candidate2.exists() else None)

        self.ports = self.load_ports()
        # basic service name map (small)
        self.port_services = {
            20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            3306: "MySQL", 5432: "PostgreSQL", 3389: "RDP", 27017: "MongoDB"
        }

    def load_ports(self) -> List[int]:
        if not self.ports_path:
            return sorted(set(DEFAULT_PORTS))
        try:
            with self.ports_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            ports_raw = data.get("ports", [])
            cleaned = []
            for p in ports_raw:
                try:
                    cleaned.append(int(p))
                except Exception:
                    # if there's a range like "1-1024"
                    if isinstance(p, str) and "-" in p:
                        try:
                            lo, hi = p.split("-", 1)
                            lo_i = int(lo.strip()); hi_i = int(hi.strip())
                            cleaned.extend(range(lo_i, hi_i + 1))
                        except Exception:
                            continue
            if not cleaned:
                return sorted(set(DEFAULT_PORTS))
            return sorted(set(cleaned))
        except FileNotFoundError:
            print(f"{Fore.YELLOW}Port config not found; using built-in defaults.{Fore.RESET}")
            return sorted(set(DEFAULT_PORTS))
        except json.JSONDecodeError:
            print(f"{Fore.RED}Invalid JSON in port config; using built-in defaults.{Fore.RESET}")
            return sorted(set(DEFAULT_PORTS))
        except Exception as e:
            print(f"{Fore.RED}Error loading ports: {e}{Fore.RESET}")
            return sorted(set(DEFAULT_PORTS))

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        private_patterns = [
            r"^10\.", r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", r"^192\.168\.",
            r"^127\.", r"^169\.254\."
        ]
        return any(re.match(p, ip) for p in private_patterns)

    @staticmethod
    def resolve_target(target: str) -> Optional[str]:
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None

    def grab_banner(self, ip: str, port: int, timeout: float = None) -> Optional[str]:
        t = self.timeout if timeout is None else float(timeout)
        try:
            s = socket.socket()
            s.settimeout(t)
            s.connect((ip, port))
            try:
                # Try to receive a small banner (non-blocking-ish)
                s.settimeout(1.0)
                banner = s.recv(2048)
                if banner:
                    return banner.decode(errors="ignore").strip()
            except Exception:
                return None
            finally:
                s.close()
        except Exception:
            return None
        return None

    def scan_port(self, ip: str, port: int) -> Tuple[int, str, Optional[str]]:
        s = socket.socket()
        s.settimeout(self.timeout)
        try:
            s.connect((ip, port))
            s.close()
            banner = None
            try:
                banner = self.grab_banner(ip, port, timeout=0.8)
            except Exception:
                banner = None
            return port, "OPEN", banner
        except socket.timeout:
            return port, "FILTERED", None
        except ConnectionRefusedError:
            return port, "CLOSED", None
        except Exception:
            return port, "CLOSED", None

    def port_scan(self, ip: str, ports: Optional[List[int]] = None, show_progress: bool = True) -> List[Tuple[int, str, Optional[str]]]:
        if ports is None:
            ports = self.ports
        results: List[Tuple[int, str, Optional[str]]] = []
        total = len(ports)
        print(f"\nScanning {ip} with {self.workers} workers ({total} ports)...\n")
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(self.scan_port, ip, p): p for p in ports}
            completed = 0
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                    results.append(res)
                except Exception:
                    pass
                completed += 1
                if show_progress and completed % 50 == 0:
                    print(f"  Progress: {completed}/{total} ports scanned...")
        return sorted(results, key=lambda x: x[0])

    def nmap_scan(self, ip: str):
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            print(f"{Fore.YELLOW}Nmap not found on PATH. Install nmap or choose built-in scanner.{Fore.RESET}")
            return
        print(f"\nRunning Nmap (-sV) against {ip}...\n")
        try:
            output = subprocess.check_output(["nmap", "-sV", ip], stderr=subprocess.STDOUT)
            print(output.decode(errors="ignore"))
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Nmap returned error code {e.returncode}{Fore.RESET}")
            print(e.output.decode(errors="ignore"))
        except Exception as e:
            print(f"{Fore.RED}Nmap error: {e}{Fore.RESET}")

    def whois_lookup(self, ip_or_domain: str) -> Optional[str]:
        # try 'whois' command if available
        whois_path = shutil.which("whois")
        if not whois_path:
            return None
        try:
            out = subprocess.check_output([whois_path, ip_or_domain], stderr=subprocess.STDOUT, timeout=10)
            return out.decode(errors="ignore")
        except Exception:
            return None

    def pretty_print_results(self, results: List[Tuple[int, str, Optional[str]]], ip: str):
        print("\n--- Scan Results ---\n")
        for port, status, banner in results:
            service = self.port_services.get(port, "unknown")
            if status == "OPEN":
                print(f"{Fore.GREEN}[+] Port {port} OPEN{Fore.RESET} ({service})")
                if banner:
                    b = banner.replace("\n", " ").strip()
                    if len(b) > 200:
                        b = b[:200] + "..."
                    print(f"    Banner: {b}")
            elif status == "FILTERED":
                print(f"{Fore.YELLOW}[-] Port {port} FILTERED{Fore.RESET}")
            else:
                # closed - omit by default to keep output readable (uncomment if needed)
                # print(f"    Port {port}: {status}")
                pass

    def save_results(self, results: List[Tuple[int, str, Optional[str]]], ip: str, out_dir: Optional[str] = None):
        out_dir = Path(out_dir) if out_dir else Path.cwd() / "scanner_results"
        out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = readable_time()
        json_path = out_dir / f"scan_{ip}_{timestamp}.json"
        csv_path = out_dir / f"scan_{ip}_{timestamp}.csv"

        # JSON
        data = [{"port": p, "status": s, "banner": b or ""} for p, s, b in results]
        with json_path.open("w", encoding="utf-8") as jf:
            json.dump({"ip": ip, "timestamp": timestamp, "results": data}, jf, indent=2)

        # CSV
        with csv_path.open("w", newline="", encoding="utf-8") as cf:
            writer = csv.writer(cf)
            writer.writerow(["port", "status", "banner"])
            for p, s, b in results:
                writer.writerow([p, s, b or ""])

        print(f"\nResults saved to:\n  {json_path}\n  {csv_path}")

    def interactive(self):
        print(f"{Style.BRIGHT}== Simple Port Scanner (single-file, full-featured) =={Style.RESET_ALL}\n")
        user_input = input("Enter target (public IP or domain): ").strip()
        if not user_input:
            print("No target provided. Exiting.")
            return

        ip = self.resolve_target(user_input)
        if ip is None:
            print(f"{Fore.RED}Could not resolve target.{Fore.RESET}")
            return

        if self.is_private_ip(ip):
            print(f"{Fore.RED}Private IP detected ({ip}) - only public IP scans allowed.{Fore.RESET}")
            return

        print(f"Resolved target -> {ip}")

        # optional whois
        whois_info = self.whois_lookup(user_input)
        if whois_info:
            print(f"\n{Fore.CYAN}=== WHOIS (brief) ==={Fore.RESET}")
            print(whois_info.splitlines()[:10])
            print(f"{Fore.CYAN}=== END WHOIS ==={Fore.RESET}\n")

        # ask ports: use default, specify range, or custom list
        print("\nPort list options:")
        print("  1) Use default port list")
        print("  2) Enter port range (e.g. 1-1024)")
        print("  3) Enter custom comma-separated ports (e.g. 22,80,443)")
        choice = input("> ").strip()

        ports_to_scan: List[int] = []
        if choice == "2":
            rng = input("Enter range (lo-hi): ").strip()
            try:
                lo, hi = [int(x.strip()) for x in rng.split("-", 1)]
                ports_to_scan = list(range(max(1, lo), min(65535, hi) + 1))
            except Exception:
                print("Invalid range; using default ports.")
                ports_to_scan = self.ports
        elif choice == "3":
            raw = input("Ports: ").strip()
            try:
                parts = [p.strip() for p in raw.split(",") if p.strip()]
                ports_to_scan = [int(p) for p in parts]
            except Exception:
                print("Invalid input; using default ports.")
                ports_to_scan = self.ports
        else:
            ports_to_scan = self.ports

        # ask mode
        print("\nChoose scan mode:")
        print("  1) Built-in fast scanner (recommended)")
        print("  2) Nmap -sV (if nmap is installed)")
        mode = input("> ").strip()

        if mode == "2":
            self.nmap_scan(ip)
            return

        # run built-in scan
        results = self.port_scan(ip, ports_to_scan)
        self.pretty_print_results(results, ip)

        # option to save
        save = input("\nSave results to file? (y/N): ").strip().lower()
        if save == "y":
            self.save_results(results, ip)

        print("\nDone.")

# -----------------------------
# Run when executed directly
# -----------------------------
if __name__ == "__main__":
    # Example: pass optional ports file path via CLI: python scanner_full.py path/to/default_ports.json
    ports_file = None
    workers = 200
    timeout = 0.6

    if len(sys.argv) > 1:
        ports_file = sys.argv[1]
    scanner = PortScanner(ports_file=ports_file, workers=workers, timeout=timeout)
    try:
        scanner.interactive()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(0)

