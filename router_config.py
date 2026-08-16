import os
import re
import winreg
import socket
import psutil

def get_home_ip():
    """Get the home network IP address"""
    try:
        # Get hostname
        hostname = socket.gethostname()
        # Get IP address
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        print(f"Error getting IP address: {e}")
        return None

def get_router_config():
    """Get router configuration information"""
    try:
        # Try to get router IP from Windows registry
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces')
        for i in range(0, winreg.QueryInfoKey(key)[0]):
            subkey_name = winreg.EnumKey(key, i)
            subkey = winreg.OpenKey(key, subkey_name)
            for j in range(0, winreg.QueryInfoKey(subkey)[1]):
                name, value, type = winreg.EnumValue(subkey, j)
                if name == 'DhcpDefaultGateway':
                    # Handle different types of values
                    if isinstance(value, str):
                        # If it's a string, try to convert to int
                        try:
                            value = int(value)
                        except ValueError:
                            continue
                    
                    if isinstance(value, (list, tuple)):
                        # If we got a list/tuple, take the first element
                        value = value[0]
                    
                    if isinstance(value, int):
                        # Convert DWORD to bytes
                        gateway_ip = socket.inet_ntoa(bytes([value & 0xFF,
                                                            (value >> 8) & 0xFF,
                                                            (value >> 16) & 0xFF,
                                                            (value >> 24) & 0xFF]))
                        return gateway_ip
    except Exception as e:
        print(f"Error getting router config: {e}")
    return None

def get_network_info():
    """Get basic network information"""
    try:
        # Get network interfaces
        ifaces = psutil.net_if_addrs()
        network_info = {}
        for iface_name, iface_addrs in ifaces.items():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET:
                    network_info[iface_name] = {
                        'ip': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
        return network_info
    except Exception as e:
        print(f"Error getting network info: {e}")
        return None

# Example usage
if __name__ == "__main__":
    print("Network Information:")
    print(f"Home IP: {get_home_ip()}")
    print(f"Router IP: {get_router_config()}")
    print("\nNetwork Interfaces:")
    network_info = get_network_info()
    if network_info:
        for iface, info in network_info.items():
            print(f"\nInterface: {iface}")
            print(f"IP: {info['ip']}")
            print(f"Netmask: {info['netmask']}")
            print(f"Broadcast: {info['broadcast']}")
