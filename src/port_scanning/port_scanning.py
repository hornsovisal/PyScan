# --- Library Imports ---
from __future__ import annotations   # This will tell the hints to avoid error
import socket     # This one is for network communications
import re     # Check whether the IP is private or not 
import json   # use in scanner_result saving in JSON format(easy to read)
import csv    # use in scanner_result saving in CSV format
import sys    # use to exit the program safely(control how your program start and stop)
from pathlib import Path # use to handle file and directory paths in a clean, especially in cross-platform way
from datetime import datetime # use to get the current date
from concurrent.futures import ThreadPoolExecutor, as_completed #use to run port scans in parallel using multiple threads
from typing import List, Tuple   # this will return value is a list of (port, status)


# --- Color the output so that it's more readable ---
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except Exception:
    class _C:
        RESET = ""
        BRIGHT = ""
    class Fore:
        RED = GREEN = YELLOW = CYAN = RESET = ""
    Style = _C()



# --- These are common service ports used by many network services---
DEFAULT_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123,
    135, 139, 143, 161, 162, 389, 443, 445, 465, 587,
    631, 636, 993, 995, 1433, 1521, 1723, 3306, 3389,
    5432, 27017
]


# --- Show the current time in the scanner_result ---
def readable_time() -> str:
    return datetime.now().strftime("%b-%d-%Y_%I-%M-%S_%p")


# =====================================================
# BASE CLASS (PARENT CLASS)
# =====================================================
class BaseScanner:
    def __init__(self, workers: int, timeout: float):
        # Private attributes
        self.__workers = workers
        self.__timeout = timeout

        # Create a main output folder to store scan results
        self.__output_dir = Path.cwd() / "scanner_results"
        self.__output_dir.mkdir(parents=True, exist_ok=True)

# --- Methods ---
    def resolve_target(self, target: str) -> str | None:
        """
        It will convert a domain name (example: google.com) into an IP address.

        - If the domain is valid, return its IP address
        - If the domain cannot be resolved, return None

        This prevents the program from crashing when the user
        enters an invalid domain or IP.
        """
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None

    def is_private_ip(self, ip: str) -> bool:
        """
        Check whether the given IP address is private or not.

        Private IP addresses are blocked to prevent scanning
        local or internal networks.
        """
        patterns = [
            r"^10\.",
            r"^192\.168\.",
            r"^127\.",
            r"^169\.254\.",
            r"^172\.(1[6-9]|2[0-9]|3[0-1])\."
        ]
        return any(re.match(p, ip) for p in patterns)

    def save_results(self, results, ip):
        """
        Save scan results into a clean folder structure.

        Each scan has its own folder containing:
        - result.json
        - result.csv
        - summary.txt: this one will be faster if you want to only look for which ports are open. 
        """
        timestamp = readable_time()

        # Create one folder per scan using the timestamp
        scan_dir = self.__output_dir / f"scan_{timestamp}"
        scan_dir.mkdir(parents=True, exist_ok=True)

        json_path = scan_dir / "result.json"
        csv_path = scan_dir / "result.csv"
        summary_path = scan_dir / "summary.txt"

        # ---JSON ---
        # Save results in JSON format 
        with json_path.open("w", encoding="utf-8") as jf:
            json.dump(
                {
                    "ip": ip,
                    "timestamp": timestamp,
                    "results": [{"port": p, "status": s} for p, s in results]
                },
                jf,
                indent=2
            )

        # --- CSV ---
        # Save results in CSV format for spreadsheet usage
        with csv_path.open("w", newline="", encoding="utf-8") as cf:
            writer = csv.writer(cf)
            writer.writerow(["port", "status"])
            writer.writerows(results)

        # --- SUMMARY ---
        # Create a human-readable summary file
        open_ports = [str(p) for p, s in results if s == "OPEN"]

        with summary_path.open("w", encoding="utf-8") as sf:
            sf.write("Port Scan Summary\n")
            sf.write("=================\n\n")
            sf.write(f"Target IP   : {ip}\n")
            sf.write(f"Scan Time  : {timestamp}\n")
            sf.write(f"Total Ports: {len(results)}\n")
            sf.write(f"Open Ports : {', '.join(open_ports) if open_ports else 'None'}\n")

        print(f"\n✅ Results saved in folder:")
        print(f"   {scan_dir}")


    # using gettter to access to private attributes
    def get_workers(self):
        return self.__workers

    def get_timeout(self):
        return self.__timeout


# =====================================================
# CHILD CLASS (INHERITANCE)
# =====================================================
class PortScanner(BaseScanner):
    def __init__(self):
        # using super(). to call the parent class constructor 
        super().__init__(workers=200, timeout=0.6)

        # using private attribute to store the list of ports to scan
        self.__ports = DEFAULT_PORTS

# --- Methods ---
    def scan_single_port(self, ip: str, port: int) -> Tuple[int, str]:
        """
        Scan a single port on the target IP

        Returns:
        - (port, "OPEN") if connection succeeds
        - (port, "CLOSED") if refused
        - (port, "FILTERED") if timed out or protected by firewall
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.get_timeout())
        try:
            sock.connect((ip, port))
            return port, "OPEN"
        except socket.timeout:
            return port, "FILTERED"
        except ConnectionRefusedError:
            return port, "CLOSED"
        except Exception:
            return port, "CLOSED"
        finally:
            sock.close()

    def scan_ports(self, ip: str) -> List[Tuple[int, str]]:
        """
        Scan all ports using multithreading for faster performance
        """
        print(f"\nScanning {ip} ({len(self.__ports)} ports)...\n")
        results = []

        with ThreadPoolExecutor(max_workers=self.get_workers()) as executor:
            futures = [
                executor.submit(self.scan_single_port, ip, p)
                for p in self.__ports
            ]
            for future in as_completed(futures):
                results.append(future.result())

        return sorted(results, key=lambda x: x[0])

    # This is the main program flow 
    def run(self):
        """
        Main execution flow of the port scanner.
        """
        target = input("Enter target (public IP or domain): ").strip()
        ip = self.resolve_target(target)

        # Stop if the domain or IP cannot be resolved
        if not ip:
            print("❌ Cannot resolve target.")
            return

        # Block private IP addresses
        if self.is_private_ip(ip):
            print("❌ Private IP detected. Scan blocked.")
            return

        print(f"Resolved target → {ip}")

        results = self.scan_ports(ip)

        # Display results in the terminal
        print("\n--- Scan Results ---\n")
        for port, status in results:
            if status == "OPEN":
                print(f"{Fore.GREEN}[+] Port {port} OPEN{Fore.RESET}")
            else:
                print(f"{Fore.RED}[-] Port {port} {status}{Fore.RESET}")

        # Ask user whether to save results
        if input("\nSave results? (y/N): ").lower() == "y":
            self.save_results(results, ip)

        print("\nScan completed.")


# --- entry point program ---
if __name__ == "__main__":
    try:
        PortScanner().run()
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(0)
