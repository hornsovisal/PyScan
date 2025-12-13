import sys
import os


# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
from src.host_discovery.host_discovery import HostScanner
from src.reportings.report_manager import HostReportManager
from src.IP_Finding.ip_find import IPConfig
from src.port_scanning.port_scanning import PortScanner



def main():
    banner = banner = r"""
███████╗ ██████╗ █████╗ ███╗   ██╗    ██████╗  ██████╗ ███╗   ██╗██████╗  █████╗ ███╗   ██╗██╗  ██╗
██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔══██╗████╗  ██║██║  ██║
███████╗██║     ███████║██╔██╗ ██║    ██████╔╝██║   ██║██╔██╗ ██║██║  ██║███████║██╔██╗ ██║███████║
╚════██║██║     ██╔══██║██║╚██╗██║    ██╔══██╗██║   ██║██║╚██╗██║██║  ██║██╔══██║██║╚██╗██║██╔══██║
███████║╚██████╗██║  ██║██║ ╚████║    ██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║██║ ╚████║██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
                                                                                                   

"""
    # print(banner)
    
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
                    # Get customer information
                    customer_name = input("Enter Customer/Client Name: ").strip()
                    if not customer_name:
                        customer_name = "Network Security Assessment"
                    
                    network_range = f"{start_ip} to {end_ip}"
                    # Create report manager and load cached scan results
                    report_dir = os.path.join(os.path.dirname(__file__), 'src', 'reportings', 'reports')
                    report_manager = HostReportManager(output_dir=report_dir)
                    report_manager.scanner = scanner  # Use the same scanner with cached results
                    report_manager.load_from_cached_scan()  # Load results from cache without re-scanning
                    report_manager.display_summary()  # display the result
                    
                    # Generate professional report with custom metadata
                    report_manager.generate_report(
                        customer_name=customer_name,
                        network_range=network_range,
                        project_by= "Scan Bondanh Team "
                    )
                    print("✓ Professional report generated successfully!")
                else:
                    print("Report generation skipped.")
                # Wait for user to press Enter (handle non-interactive runs)
                try:
                    input("Press Enter to continue...")
                except EOFError:
                    pass
                # Prefer ANSI clear for portability, fall back to os.system
                try:
                    print("\033c", end="")
                except Exception:
                    os.system('cls' if os.name == 'nt' else 'clear')
            case "2":
                try:
                    scanner = PortScanner()
                    result = scanner.run()
                    if result:
                        ip, results = result
                        # Save results to reports directory (JSON + summary) similar to host flow
                        try:
                            report_dir = os.path.join(os.path.dirname(__file__), 'src', 'reportings', 'reports')
                            os.makedirs(report_dir, exist_ok=True)
                            import json as _json
                            from datetime import datetime as _dt
                            ts = _dt.now().strftime('%Y%m%d_%H%M%S')
                            json_path = os.path.join(report_dir, f"port_scan_{ts}.json")
                            summary_path = os.path.join(report_dir, f"port_scan_{ts}_summary.txt")
                            with open(json_path, 'w', encoding='utf-8') as jf:
                                _json.dump({'ip': ip, 'timestamp': ts, 'results': [{'port': p, 'status': s} for p, s in results]}, jf, indent=2)
                            open_ports = [str(p) for p, s in results if s == 'OPEN']
                            with open(summary_path, 'w', encoding='utf-8') as sf:
                                sf.write('Port Scan Summary\n')
                                sf.write('=================\n\n')
                                sf.write(f"Target IP   : {ip}\n")
                                sf.write(f"Scan Time   : {ts}\n")
                                sf.write(f"Total Ports : {len(results)}\n")
                                sf.write(f"Open Ports  : {', '.join(open_ports) if open_ports else 'None'}\n")
                            print(f"\nReport saved to: {report_dir}")
                        except Exception as e:
                            print(f"Failed to save port scan report: {e}")
                except KeyboardInterrupt:
                    print("\nPort scan interrupted.")
                except Exception as e:
                    print(f"Error running port scanner: {e}")
                # Wait and clear like option 1
                try:
                    input("Press Enter to continue...")
                except EOFError:
                    pass
                try:
                    print("\033c", end="")
                except Exception:
                    os.system('cls' if os.name == 'nt' else 'clear')
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