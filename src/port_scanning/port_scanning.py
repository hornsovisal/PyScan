import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------------------------
# Common Ports → Services Mapping
# ----------------------------------------------
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy"
}

# ----------------------------------------------
# Banner Grabbing Function
# ----------------------------------------------
def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        try:
            banner = s.recv(1024).decode().strip()
            return banner
        except:
            return None
    except:
        return None

# ----------------------------------------------
# Port Scan Worker Function
# ----------------------------------------------
def scan_port(ip, port):
    """
    Returns: (port, status, service, banner)
    """
    s = socket.socket()
    s.settimeout(0.5)

    try:
        s.connect((ip, port))
        s.close()

<<<<<<< HEAD
# receive some data
response = client.recv(4096)
print(response.decode())  # decode from bytes to string
=======
        # If connection succeeds -> port is OPEN
        service = COMMON_SERVICES.get(port, "Unknown")
        banner = grab_banner(ip, port)

        return port, "OPEN", service, banner
    except socket.timeout:
        return port, "FILTERED", None, None
    except:
        return port, "CLOSED", None, None

# ----------------------------------------------
# Main Scanner with Concurrency
# ----------------------------------------------
def port_scan(ip, start_port, end_port, workers=100):
    results = []

    print(f"\nScanning {ip} from port {start_port} to {end_port}...")
    print(f"Using {workers} threads...\n")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_port, ip, port)
                   for port in range(start_port, end_port + 1)]

        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda x: x[0])

# ----------------------------------------------
# Run the Scanner
# ----------------------------------------------
if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    start = int(input("Start Port: "))
    end = int(input("End Port: "))

    results = port_scan(target_ip, start, end)

    print("\n--- Scan Results ---\n")
    for port, status, service, banner in results:
        if status == "OPEN":
            print(f"[+] Port {port} OPEN ({service})")
            if banner:
                print(f"    Banner: {banner}")
        # To show closed and filtered ports, uncomment:
        # else:
        #     print(f"Port {port}: {status}")

