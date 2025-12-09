from host_discovery.host_discovery import HostScanner

#initialize scanner
scanner = HostScanner()
banner = banner = r"""
███████╗ ██████╗ █████╗ ███╗   ██╗    ██████╗  ██████╗ ███╗   ██╗██████╗  █████╗ ███╗   ██╗██╗  ██╗
██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔══██╗████╗  ██║██║  ██║
███████╗██║     ███████║██╔██╗ ██║    ██████╔╝██║   ██║██╔██╗ ██║██║  ██║███████║██╔██╗ ██║███████║
╚════██║██║     ██╔══██║██║╚██╗██║    ██╔══██╗██║   ██║██║╚██╗██║██║  ██║██╔══██║██║╚██╗██║██╔══██║
███████║╚██████╗██║  ██║██║ ╚████║    ██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║██║ ╚████║██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
                                                                                                   
                                       
"""
def main():
    print(banner)
    print("======== Scan Bondanh ========")
    print("[1] Host Discovery")
    print("[2] Port Scanning")
    print("[3] Exit")
    print("==============================")

    choice = input("Choose an option (1, 2, 3): ").strip()
    hosts = []
    results = {}
    #Host Discovery
    
    if choice == "1":
        target = input("Enter target IP or network (ex:192.168.1.0-192.168.1.254): ")
        
        try:
            start_ip, end_ip = target.split('-')
            #generate full ip inside ICMPScanner
            ip_range_list = scanner.icmp.generate_ip_range(start_ip, end_ip)
            
        except ValueError:
            
            print(" Invalid range format. Please use 'START_IP-END_IP' (e.g., 10.0.0.1-10.0.0.10). Exiting.")
            return
        
        # This will print progress and return details for alive hosts
        raw_results = scanner.scan(ip_range_list, method="auto", alive_only=True, show_progress=True)
        hosts = [result[0] for result in raw_results]
        #function to display results
        scanner.display(ip_range=None, method="auto", alive_only=True)
        

    #Port Scanning

    elif choice == "2":
        pass
    elif choice == "3":
        print(" Exiting Scan Bondanh. Goodbye!")
        return
    else:
        print("Invalid option. Exiting.")
        return


    #report 

    print("\nScan complete.")
    save = input("Generate report? (Y/N): ").strip().lower()

    if save == "y":
        pass
    else:
        pass

if __name__ == "__main__":
    main()