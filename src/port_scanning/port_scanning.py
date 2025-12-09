import socket
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional


class PortScanner:
    def __init__(self, ports_file: Optional[str] = None, workers: int = 100):
        # Resolve default ports file relative to project root
        if ports_file:
            self.ports_path = Path(ports_file)
        else:
            # assume src/.. parent structure: Scan-Bondanh/src/port_scanning/...
            self.ports_path = Path(__file__).resolve().parents[2] / "config" / "default_ports.json"

        self.workers = workers
        self.ports = self.load_ports()

    def load_ports(self) -> List[int]:
        """Load ports from default_ports.json."""
        try:
            with self.ports_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            ports = data.get("ports", [])
            if not isinstance(ports, list):
                return []

            cleaned = []
            for p in ports:
                try:
                    cleaned.append(int(p))
                except Exception:
                    continue

            return sorted(set(cleaned))

        except FileNotFoundError:
            print(f"Error: config file not found: {self.ports_path}")
        except json.JSONDecodeError as e:
            print(f"JSON parsing error in {self.ports_path}: {e}")
        except Exception as e:
            print(f"Error loading ports from {self.ports_path}: {e}")

        return []

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Detect private IPv4 ranges."""
        private_patterns = [
            r"^10\.",
            r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
            r"^192\.168\.",
            r"^127\.",
            r"^169\.254\."
        ]
        return any(re.match(p, ip) for p in private_patterns)

    @staticmethod
    def resolve_target(target: str) -> Optional[str]:
        """Convert domain → IP or validate IP."""
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None

    @staticmethod
    def grab_banner(ip: str, port: int, timeout: float = 1.0) -> Optional[str]:
        """Try to grab service banner for the open port."""
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            return banner
        except Exception:
            return None

    def scan_port(self, ip: str, port: int):
        """Scan a single port."""
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect((ip, port))
            s.close()
            banner = self.grab_banner(ip, port)
            return port, "OPEN", banner
        except socket.timeout:
            return port, "FILTERED", None
        except Exception:
            return port, "CLOSED", None

    def port_scan(self, ip: str, ports: Optional[List[int]] = None):
        """Scan multiple ports using multithreading."""
        if ports is None:
            ports = self.ports

        results = []
        print(f"\nScanning {ip}...\n")

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = [executor.submit(self.scan_port, ip, port) for port in ports]
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception:
                    continue

        return sorted(results, key=lambda x: x[0])

    def nmap_scan(self, ip: str):
        """Run an nmap scan."""
        print("\nRunning Nmap scan...\n")
        try:
            output = subprocess.check_output(["nmap", "-sV", ip], stderr=subprocess.STDOUT)
            print(output.decode())
        except Exception as e:
            print("Nmap error:", e)

    def run_interactive(self):
        """Interactive mode for user input."""
        user_input = input("Enter target Public IP or Domain: ").strip()
        ip = self.resolve_target(user_input)

        if ip is None:
            print("❌ Invalid domain or IP.")
            return

        if self.is_private_ip(ip):
            print("❌ Private IP detected → Only public IP allowed.")
            return

        print(f"Resolved Target IP: {ip}")

        if not self.ports:
            print("❌ Port list empty. Check default_ports.json")
            return

        mode = input("\nChoose scan mode:\n1 = Built-in scanner\n2 = Nmap\n> ").strip()

        if mode == "2":
            self.nmap_scan(ip)
        else:
            results = self.port_scan(ip)
            print("\n--- Scan Results ---\n")
            for port, status, banner in results:
                if status == "OPEN":
                    print(f"[+] Port {port} OPEN")
                    if banner:
                        print(f"    Banner: {banner}")


# -------------------------------------------------
# ✅ MAIN PROGRAM (Creates the object and runs it)
# -------------------------------------------------
if __name__ == "__main__":
    scanner = PortScanner()
    scanner.run_interactive()
