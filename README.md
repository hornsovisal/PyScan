# Scan-Bondanh: Network Scanning & Security Assessment Tool

**Scan-Bondanh** is a lightweight, educational, and multi-threaded network scanning tool written in Python. It is designed to perform essential network reconnaissance, including host discovery, detailed port scanning, and service detection, providing clear reports for system administrators and cybersecurity students.

---

##  Key Features

* **Host Discovery:** Uses multiple methods to reliably detect active hosts: ICMP ping, ARP scanning (local subnet).
* **High-Speed Scanning:** Implements **multi-threading** for efficient and rapid port scanning across large ranges.
* **Service Detection:** Attempts **banner grabbing** to identify running services (e.g., SSH, HTTP) on open ports.
* **Customizable:** Scan behavior is controlled via external configuration files (`.json`, `.yaml`).
* **Reporting:** Generates structured, machine-readable **JSON** and human-readable **TXT** reports.
* **Modular Architecture:** Built using an Object-Oriented Programming (OOP) approach for easy testing and future expansion.
---

##  Project Setup

### Prerequisites

You must have Python 3.x installed. You may also need to run the tool with elevated privileges (`sudo` or Administrator) for low-level socket operations (like ARP or raw ICMP).

### Installation

1. **Clone the repository:**
   **Bash**

   ```
   git clone https://github.com/hornsovisal/Scan-Bondanh.git
   cd Scan-Bondanh

   ```
2. **Install Dependencies:**
   All necessary external libraries are listed in `requirements.txt`.
   **Bash**

   ```
   pip install -r requirements.txt
   ```

## 🧩 Basic Usage
  To start **Scan-Bondanh**, simply run the main script:
    ```
    python3 main.py
    ```
  Once executed, the tool displays an ASCII banner followed by the main menu:
    
    ```
    ======== Scan Bondanh ========
    [1] Host Discovery
    [2] Port Scanning
    [3] What is my IP?
    [4] Exit
    ==============================
    Choose an option (1, 2, 3):
    ```
    
  ### 🔎 1. Host Discovery
  Select this option to scan a network for active hosts.
  You will be prompted to enter an IP range (for example, `192.168.1.1-192.168.1.254`), and the tool will list all reachable devices on that network.
    
  ### 🚪 2. Port Scanning
  Use this option to check for open ports on a specific target.
  You will be asked to enter a target IP or domain (e.g., `cadt.edu.kh`), and the scanner will test common or specified ports to identify what services are running.
    
  ### 🌐 3. What is my IP?
  Displays your **IP address** and may also show additional local network information.
    
  ### ❌ 4. Exit
  Closes the program.


## 🧱 Project Structure

The project is organized as a professional Python package (`py_scan_tool`) to ensure modularity and clean separation of duties.

| Directory/File                        | Purpose                                                          | Key Files/Notes                                                            |
| ------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **📁`src/`**         | **The Core Python Package**(Source Code)                   | Contains all executable logic.                                             |
| ├── 📁`host_discovery/`          | Handles**Host Detection**using ICMP, ARP, and TCP methods. | `icmp_ping.py`,`arp_scan.py`                                           |
| ├── 📁`port_scanning/`           | Manages**Concurrency**and raw socket connections.          | `threaded_scanner.py`,`socket_handler.py`                              |
| ├── 📁`reporting/`               | Handles**Report Generation**and file output.               | `report_manager.py`,`json_writer.py`                                   |
| ├── 📄**`main.py`**    | **Primary Entry Point (CLI or GUI)**                              |  the entire scan process.                                      |
| **📁`config/`**               | **Tool Settings**                                          | External files to configure tool behavior.                                 |
| ├── 📄`default_ports.json`       | List of commonly scanned ports (e.g., 80, 443, 22).              |                                                                            |
| └── 📄`scanner_config.yaml`      | **Performance Settings**(thread count, timeouts, retries). |                                                                            |
| **📁`tests/`**                | **Automated Verification**                                 | Scripts to ensure the accuracy of host detection and port state logic.     |
| └── 📄`test_scanner.py`          | Unit and integration tests.                                      |                                                                            |
| **📁`reports/`**              | **Scan Output**                                            | Stores all generated scan reports.                                         |
| └── 📄`scan_results_YYMMDD.pdf` | Example output file.                                             |                                                                            |
| **📄`requirements.txt`**      | **Dependencies**                                           | List of all required Python libraries.                                     |
| **📄`__init__py`**      | **Python Package**                                           | Mark a directory as a Python package.                                     |

---

## 🤝 Contribution

**Prepared By:** Horn Sovisal; Kuyseng Marakat; Chhit Sovathana

**Course:** Python for Cyber Security 

**Course Info** : This course introduces Python programming. with a strong focus on Object-Oriented Programming (OOP) and its application in cybersecurity.

**Lecturer** : Mr. Han Leangsiv

**Department:** Telecom and Networking, Cyber Security, Cambodia Accademy of Digital Technology(CADT)

