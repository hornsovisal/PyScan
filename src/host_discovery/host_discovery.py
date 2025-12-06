"""Host discovery helpers with ICMP-first and ARP fallback."""
import json
import os
import platform
import socket
import subprocess
import sys
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import ARP, Ether, srp, conf  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    SCAPY_AVAILABLE = False


class BaseScanner(ABC):
    def __init__(self):
        self._ports = self._load_ports()
        self._hostname_cache = self._load_hostname_cache()
        if SCAPY_AVAILABLE:
            conf.verb = 0

    def _load_ports(self):
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(os.path.dirname(current_dir))
            config_path = os.path.join(project_root, "config/default_ports.json")
            with open(config_path, "r", encoding="utf-8") as f:
                lines = [line for line in f.read().splitlines() if not line.strip().startswith("/")]
            data = json.loads("\n".join(lines))
            return data.get("port_list_only", [80, 443])
        except Exception:
            return [80, 443]
    
    def _load_hostname_cache(self):
        """Load custom hostname mappings from config/hostnames.json"""
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(os.path.dirname(current_dir))
            config_path = os.path.join(project_root, "config/hostnames.json")
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _check_port(self, ip, port):
        try:
            socket.create_connection((ip, port), timeout=0.5).close()
            return port
        except Exception:
            return None

    def scan_ports(self, ip):
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._check_port, ip, p): p for p in self._ports}
            open_ports = [future.result() for future in as_completed(futures) if future.result()]
        return ",".join(map(str, sorted(open_ports))) if open_ports else "None"

    def resolve_identity(self, ip):
        """Resolve hostname using multiple methods like Angry IP Scanner."""
        # Method 0: Check custom hostname cache first (highest priority)
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]
        
        # Method 1: Check /etc/hosts (fast)
        try:
            with open('/etc/hosts', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == ip:
                            return parts[1].split('.')[0]
        except Exception:
            pass
        
        # Method 2: Try reverse DNS lookup
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            if hostname and hostname != ip:
                short_name = hostname.split('.')[0] if '.' in hostname else hostname
                return short_name if short_name else hostname
        except socket.herror:
            pass
        except socket.timeout:
            pass
        except Exception:
            pass

        # Method 3: Try using getfqdn as fallback
        try:
            fqdn = socket.getfqdn(ip)
            if fqdn and fqdn != ip and not fqdn.startswith(ip):
                short_name = fqdn.split('.')[0] if '.' in fqdn else fqdn
                return short_name if short_name else fqdn
        except Exception:
            pass

        # Method 4: Try NetBIOS lookup (Windows networks)
        try:
            result = subprocess.check_output(
                ["nmblookup", "-A", ip],
                stderr=subprocess.DEVNULL,
                timeout=3,
                text=True
            )
            for line in result.splitlines():
                if "<00>" in line and "GROUP" not in line:
                    parts = line.split()
                    if parts and parts[0] != ip:
                        return parts[0].strip()
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass
        except Exception:
            pass

        # Method 5: Try mDNS/Avahi (for .local domains)
        try:
            result = subprocess.check_output(
                ["avahi-resolve", "-a", ip],
                stderr=subprocess.DEVNULL,
                timeout=2,
                text=True
            )
            parts = result.strip().split()
            if len(parts) >= 2 and parts[1] != ip:
                hostname = parts[1].replace('.local', '')
                return hostname.split('.')[0] if '.' in hostname else hostname
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass
        except Exception:
            pass

        # If all methods fail, return the IP
        return ip

    def generate_ip_range(self, base_ip, start_host, end_host):
        return [f"{base_ip}.{i}" for i in range(start_host, end_host + 1)]

    @abstractmethod
    def ping(self, ip):
        pass


class ICMPScanner(BaseScanner):
    def ping(self, ip):
        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            subprocess.check_output(["ping", param, "1", ip], stderr=subprocess.STDOUT)
            return True
        except subprocess.CalledProcessError:
            return False
        except Exception:
            return False


class ARPScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self._icmp_fallback = ICMPScanner()

    def ping(self, ip):
        if not SCAPY_AVAILABLE:
            return self._icmp_fallback.ping(ip)
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered = srp(broadcast / arp_request, timeout=1, verbose=0)[0]
            return len(answered) > 0
        except Exception:
            return self._icmp_fallback.ping(ip)


class HostScanner:
    def __init__(self):
        self.icmp = ICMPScanner()
        self.arp = ARPScanner()

    def _build_result(self, ip, scanner, label):
        identity = scanner.resolve_identity(ip)
        ports = scanner.scan_ports(ip)
        return ip, f"Reachable ({label})", identity, ports

    def scan_host(self, ip, method="auto"):
        method = method.lower()
        if method not in ("auto", "icmp", "arp"):
            raise ValueError("method must be 'auto', 'icmp', or 'arp'")

        if method == "arp":
            primary = self.arp
            allow_fallback = False
        else:
            primary = self.icmp
            allow_fallback = method == "auto"

        if primary.ping(ip):
            label = "ICMP" if primary is self.icmp else "ARP"
            return self._build_result(ip, primary, label)

        if allow_fallback and self.arp.ping(ip):
            return self._build_result(ip, self.arp, "ARP fallback")

        return ip, "Unreachable", "N/A", "N/A"

    def scan_hosts(self, ip_range, method="auto", max_workers=50, show_progress=True):
        total = len(ip_range)
        if total == 0:
            return []

        progress = 0
        last_percent = -1

        def report(step):
            nonlocal last_percent
            if not show_progress:
                return
            percent = int(step * 100 / total)
            if percent != last_percent:
                sys.stdout.write(f"\rProgress: {percent}%")
                sys.stdout.flush()
                last_percent = percent

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_host, ip, method): ip for ip in ip_range}
            results = []
            for future in as_completed(futures):
                results.append(future.result())
                progress += 1
                report(progress)

        report(total)  # ensure 100%
        if show_progress:
            sys.stdout.write("\n")

        results.sort(key=lambda x: tuple(int(part) for part in x[0].split(".")))
        return results

    def display(self, ip_range, method="auto", max_workers=50):
        results = self.scan_hosts(ip_range, method, max_workers, show_progress=True)
        label = "ICMP->ARP Auto" if method == "auto" else method.upper()
        print(f"{label} Scan Results:")
        print(f"{'IP':<15} {'Status':<22} {'Identity':<32} {'Ports':<20}")
        print("-" * 100)
        for ip, status, identity, ports in results:
            print(f"{ip:<15} {status:<22} {identity:<32} {ports:<20}")


if __name__ == "__main__":
    scanner = HostScanner()
    sample_range = scanner.icmp.generate_ip_range("192.168.100", 1, 215)
    scanner.display(sample_range, method="auto")






