import socket
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------------------------
# LOAD PORT LIST FROM defaultport.json
# ----------------------------------------------
def load_ports():
    try:
        with open("defaultport.json", "r") as f:
            data = json.load(f)
            return data.get("ports", [])
    except Exception as e:
        print("Error loading defaultport.json:", e)
        return []


# ----------------------------------------------
# CHECK IF IP IS PRIVATE
# ----------------------------------------------
def is_private_ip(ip):
    private_patterns = [
        r"^10\.",            # 10.0.0.0 – 10.255.255.255
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",  # 172.16.0.0 – 172.31.255.255
        r"^192\.168\.",      # 192.168.0.0 – 192.168.255.255
        r"^127\.",           # Loopback
        r"^169\.254\."       # APIPA
    ]
    for p in private_patterns:
        if re.match(p, ip):
            return True
    return False


# ----------------------------------------------
# Resolve domain → IP (nslookup style)
# ----------------------------------------------
def resolve_target(target):
    try:
        # If target is domain → convert to IP
        return socket.gethostbyname(target)
    except:
        return None


# ----------------------------------------------
# Banner Grabbing
# ----------------------------------------------
def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner
    except:
        return None


# ----------------------------------------------
# Port Scan Worker
# ----------------------------------------------
def scan_port(ip, port):
    s = socket.socket()
    s.settimeout(0.5)

    try:
        s.connect((ip, port))
        s.close()
        banner = grab_banner(ip, port)
        return port, "OPEN", banner
    except socket.timeout:
        return port, "FILTERED", None
    except:
        return port, "CLOSED", None


# ----------------------------------------------
# Multi-thread port scan
# ----------------------------------------------
def port_scan(ip, ports, workers=100):
    results = []
    print(f"\nScanning {ip}...\n")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]

        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda x: x[0])


# ----------------------------------------------
# Optional: nmap scan
# ----------------------------------------------
def nmap_scan(ip):
    print("\nRunning Nmap scan...\n")
    try:
        output = subprocess.check_output(["nmap", "-sV", ip], stderr=subprocess.STDOUT)
        print(output.decode())
    except Exception as e:
        print("Nmap not installed or error:", e)


# ----------------------------------------------
# MAIN
# ----------------------------------------------
if __name__ == "__main__":
    user_input = input("Enter target Public IP or Domain: ").strip()

    # Convert domain → IP
    ip = resolve_target(user_input)

    if ip is None:
        print("❌ Invalid domain or IP.")
        exit()

    # Block private IPs
    if is_private_ip(ip):
        print("❌ Private IP detected → Ignoring. Only public IP allowed.")
        exit()

    print(f"Resolved Target IP: {ip}")

    # Load ports from defaultport.json
    ports = load_ports()
    if not ports:
        print("❌ Port list empty. Check defaultport.json")
        exit()

    # Ask user which scan mode
    mode = input("\nChoose scan mode:\n1 = Built-in scanner\n2 = Nmap\n> ")

    if mode == "2":
        nmap_scan(ip)
    else:
        results = port_scan(ip, ports)

        print("\n--- Scan Results ---\n")
        for port, status, banner in results:
            if status == "OPEN":
                print(f"[+] Port {port} OPEN")
                if banner:
                    print(f"    Banner: {banner}")


