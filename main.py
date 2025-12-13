import sys
import os


# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
from src.host_discovery.host_discovery import HostScanner
from src.reportings.report_manager import HostReportManager
from src.IP_Finding.ip_find import IPConfig
from src.port_scanning.port_scanning import PortScanner



def clear_terminal():
    # Prompt the user explicitly and avoid silently defaulting to 'yes'.
    while True:
        try:
            # Print prompt and flush to ensure it appears before input()
            prompt = "Clear screen? (Y/N) [Y]: "
            choice = input(prompt).strip().lower()
        except EOFError:
            # If input is not available, do not clear.
            return

        if choice == '':
            choice = 'y'
        if choice in ('y', 'n'):
            break
        print("Please enter 'Y' or 'N'.")

    if choice == 'y':
        try:
            input("Press Enter to continue...")
        except EOFError:
            # If the terminal doesn't support input, just attempt to clear.
            pass

        # Prefer calling the system clear command which works reliably on most shells
        try:
            if os.name == 'nt':
                rc = os.system('cls')
            else:
                rc = os.system('clear')
            # If the system call failed (non-zero), fall back to ANSI sequence
            if rc != 0:
                print("\033c", end="", flush=True)
        except Exception:
            try:
                print("\033c", end="", flush=True)
            except Exception:
                pass

def main():
    banner = banner = r"""
███████╗ ██████╗ █████╗ ███╗   ██╗    ██████╗  ██████╗ ███╗   ██╗██████╗  █████╗ ███╗   ██╗██╗  ██╗
██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔══██╗████╗  ██║██║  ██║
███████╗██║     ███████║██╔██╗ ██║    ██████╔╝██║   ██║██╔██╗ ██║██║  ██║███████║██╔██╗ ██║███████║
╚════██║██║     ██╔══██║██║╚██╗██║    ██╔══██╗██║   ██║██║╚██╗██║██║  ██║██╔══██║██║╚██╗██║██╔══██║
███████║╚██████╗██║  ██║██║ ╚████║    ██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║██║ ╚████║██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
                                                                                                   

"""
    
    while True:
        print(banner)
        print("\n======== Scan Bondanh ========")
        print("[1] Host Discovery")
        print("[2] Port Scanning")
        print("[3] What is my IP?")
        print("[4] Exit")
        print("==============================")

        choice = input("Choose an option (1-4): ").strip()
        

        match choice:
            case "1":
                # Host Discovery Logic
                scanner = HostScanner()
                start_ip = input("Enter start IP (ex: 192.168.1.1): ").strip()
                end_ip = input("Enter end IP (ex: 192.168.1.254): ").strip()

                try:
                    # Validate IP format
                    for ip in [start_ip, end_ip]:
                        parts = ip.split('.')
                        if len(parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                            raise ValueError(f"Invalid IP format: {ip}")
                    
                    # generate full ip range list
                    ip_range_list = scanner.icmp.generate_ip_range(start_ip, end_ip) 
                    
                except ValueError as e:
                    print(f"Invalid IP format. Please use valid IP addresses (e.g., 192.168.1.1).")
                    print(f"Error: {e}")
                    # Continue the loop to show the menu again
                    continue 
                
                print(f"Scanning IP range: {start_ip} to {end_ip}...")
                scanner.display(ip_range_list, method="arp")

           
                print("\nScan complete.")
                save = input("Generate report? (Y/N): ").strip().lower()
                if save == 'y':
                    # Create report manager and load cached scan results
                    report_dir = os.path.join(os.path.dirname(__file__), 'src', 'reportings', 'reports')
                    report_manager = HostReportManager(output_dir=report_dir)
                    report_manager.scanner = scanner  # Use the same scanner with cached results
                    report_manager.load_from_cached_scan()  # Load results from cache without re-scanning
                    report_manager.display_summary()  # display the result
                    report_manager.generate_report()  # Generate report and save as docx
                    print("Report generated successfully.")
                else:
                    print("Report generation skipped.")
                clear_terminal()
            case "2":
                try:
                    scanner = PortScanner()
                    scanner.run()
                except KeyboardInterrupt:
                    print("\nPort scan interrupted.")
                except Exception as e:
                    print(f"Error running port scanner: {e}")
                clear_terminal()
            case "3":
                try:
                    ip_config = IPConfig()
                    ip_config.display_ipv4()
                except Exception as e:
                    print(f"Error displaying IP configuration: {e}")
            case "4":
                
                print(" Exiting Scan Bondanh. Goodbye!")
                return 
            
            case _:
                print(f"Invalid option: '{choice}'. Please choose 1, 2, 3, or 4.")
        
if __name__ == "__main__":
    main()