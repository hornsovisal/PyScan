"""IP Configuration module that extends BaseScanner - get IPv4 addresses."""
import socket
import subprocess
import platform
import sys
from pathlib import Path


class IPConfig():
    """IP Configuration class that extends BaseScanner to display network interface information."""

    def get_interface_info(self):
        """Get detailed network interface information."""
        interfaces = []
        
        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                iface_info = {
                    'name': iface,
                    'mac': None,
                    'ipv4': None,
                    'netmask': None,
                    'gateway': None
                }
                
                # Get MAC address
                if netifaces.AF_LINK in addrs:
                    iface_info['mac'] = addrs[netifaces.AF_LINK][0].get('addr', '')
                
                # Get IPv4 address and netmask
                if netifaces.AF_INET in addrs:
                    iface_info['ipv4'] = addrs[netifaces.AF_INET][0].get('addr')
                    iface_info['netmask'] = addrs[netifaces.AF_INET][0].get('netmask')
                
                # Get default gateway for this interface
                gateways = netifaces.gateways()
                default_gw = gateways.get('default', {}).get(netifaces.AF_INET)
                if default_gw and default_gw[1] == iface:
                    iface_info['gateway'] = default_gw[0]
                
                interfaces.append(iface_info)
            
            return interfaces
        except ImportError:
            # Fallback without netifaces
            return self._get_interface_info_fallback()
    
    def _get_interface_info_fallback(self):
        """Fallback method to get interface info without netifaces."""
        interfaces = []
        
        try:
            # Get primary IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            s.close()
            
            interfaces.append({
                'name': 'primary',
                'mac': None,
                'ipv4': primary_ip,
                'netmask': '255.255.255.0',
                'gateway': None
            })
        except Exception:
            pass
        
        # Always add localhost
        interfaces.append({
            'name': 'lo',
            'mac': '00:00:00:00:00:00',
            'ipv4': '127.0.0.1',
            'netmask': '255.0.0.0',
            'gateway': None
        })
        
        return interfaces
    
    def display_ipv4(self):
        """Display network configuration in Windows ipconfig style."""
        interfaces = self.get_interface_info()
        
        print()
        for iface in interfaces:
            # Skip interfaces without IPv4
            if not iface['ipv4']:
                continue
            
            print(f"Ethernet adapter {iface['name']}:")
            
            # Physical Address (MAC)
            mac = iface['mac'] if iface['mac'] else ''
            print(f"   Physical Address: {mac}")
            
            # IPv4 Address
            print(f"   IPv4 Address: {iface['ipv4']}")
            
            # Subnet Mask
            netmask = iface['netmask'] if iface['netmask'] else 'N/A'
            print(f"   Subnet Mask: {netmask}")
            
            # Default Gateway
            gateway = iface['gateway'] if iface['gateway'] else 'N/A'
            print(f"   Default Gateway: {gateway}")
            
            print()
        print()



if __name__ == "__main__":
    config = IPConfig()
    config.display_ipv4()
