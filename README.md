# Py-Scan: Network Scanning & Security Assessment Tool

**Py-Scan** is a lightweight, educational, and multi-threaded network scanning tool written in Python. It is designed to perform essential network reconnaissance, including host discovery, detailed port scanning, and service detection, providing clear reports for system administrators and cybersecurity students.

---

##  Key Features

* **Host Discovery:** Uses multiple methods to reliably detect active hosts: ICMP ping, ARP scanning (local subnet), and TCP SYN fallback checks.
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
   git clone [YOUR_REPOSITORY_URL]
   cd Py-Scan-Network-Tool
   ```
2. **Install Dependencies:**
   All necessary external libraries are listed in `requirements.txt`.
   **Bash**

   ```
   pip install -r requirements.txt
   ```

### Basic Usage



---

## 🧱 Project Structure

The project is organized as a professional Python package (`py_scan_tool`) to ensure modularity and clean separation of duties.

| Directory/File                        | Purpose                                                          | Key Files/Notes                                                            |
| ------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **📁`py_scan_tool/`**         | **The Core Python Package**(Source Code)                   | Contains all executable logic.                                             |
| ├── 📁`host_discovery/`          | Handles**Host Detection**using ICMP, ARP, and TCP methods. | `icmp_ping.py`,`arp_scan.py`                                           |
| ├── 📁`port_scanning/`           | Manages**Concurrency**and raw socket connections.          | `threaded_scanner.py`,`socket_handler.py`                              |
| ├── 📁`reporting/`               | Handles**Report Generation**and file output.               | `report_manager.py`,`json_writer.py`                                   |
| ├── 📄**`main_cli.py`**    | **Primary Entry Point (CLI)**                              | Orchestrates the entire scan process.                                      |
| **📁`config/`**               | **Tool Settings**                                          | External files to configure tool behavior.                                 |
| ├── 📄`default_ports.json`       | List of commonly scanned ports (e.g., 80, 443, 22).              |                                                                            |
| └── 📄`scanner_config.yaml`      | **Performance Settings**(thread count, timeouts, retries). |                                                                            |
| **📁`tests/`**                | **Automated Verification**                                 | Scripts to ensure the accuracy of host detection and port state logic.     |
| └── 📄`test_scanner.py`          | Unit and integration tests.                                      |                                                                            |
| **📁`reports/`**              | **Scan Output**                                            | Stores all generated scan reports.                                         |
| └── 📄`scan_results_YYMMDD.json` | Example output file.                                             |                                                                            |
| **📄`requirements.txt`**      | **Dependencies**                                           | List of all required Python libraries.                                     |
| **📄`.gitignore`**            | **Version Control**                                        | Ensures temporary files (`__pycache__`,`reports/`) are ignored by Git. |

---

## Contribution

**Prepared By:** Horn Sovisal, Kuyseng Marakat, Chhit Sovathana

**Course:** Python for Cyber Security

**Department:** Telecom and Networking, Cyber Security, CADT
