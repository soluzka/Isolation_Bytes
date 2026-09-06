"""Network device scanner — discovers all devices on the local network.

Does a ping sweep of the subnet to find all devices, then port-scans
each one to identify device type (Xbox, phone, smart TV, etc.).
Shows IP, hostname, device type, and open ports — no MAC address.
Works on Windows, macOS, and Linux.
"""
import socket
import sys
import re
import subprocess
import platform
import concurrent.futures
from utils.subprocess_safe import safe_run, safe_check_output

# Common ports to identify device types
_DEVICE_PORTS = {
    3074: 'Xbox Live',
    53: 'DNS Server',
    80: 'Web Server',
    443: 'HTTPS',
    1900: 'Smart TV / UPnP',
    3000: 'Smart TV (Samsung)',
    8009: 'Chromecast',
    8080: 'Web Admin',
    22: 'SSH',
    23: 'Telnet',
    3389: 'Remote Desktop',
    5900: 'VNC',
    631: 'Printer',
    9100: 'Printer (Raw)',
    5000: 'Smart TV (Samsung)',
    7000: 'AirPlay',
    49152: 'UPnP',
    49153: 'UPnP',
    49154: 'UPnP',
}

# Quick port set to scan per device (keeps it fast)
_SCAN_PORTS = [22, 23, 80, 443, 53, 1900, 3000, 3074, 3389, 5000, 5900, 631, 7000, 8009, 8080, 9100, 49152, 49153, 49154]

def _get_wifi_ip():
    """Get the IP address of the WiFi adapter only (Windows).
    Returns '' if not on WiFi or not Windows."""
    system = platform.system().lower()
    if system != 'windows':
        # On macOS/Linux, fall back to default route IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return ''
    try:
        # Use netsh to find the WiFi adapter IP
        result = safe_run(
            ['netsh', 'interface', 'ip', 'show', 'config'],
            capture_output=True, text=True, timeout=5,
            creationflags=0x08000000  # CREATE_NO_WINDOW
        )
        if result.returncode != 0:
            return ''
        output = result.stdout
        # Find WiFi adapter sections and extract IP
        lines = output.split('\n')
        in_wifi = False
        for line in lines:
            if 'Wi-Fi' in line or 'WiFi' in line or 'Wireless' in line:
                in_wifi = True
                continue
            if in_wifi and 'IP Address:' in line:
                # Extract IP from "IP Address:            192.168.1.133"
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    return ip_match.group(1)
            if in_wifi and line.strip() == '' and 'IP Address' not in output[max(0,output.find(line)-200):output.find(line)]:
                # Empty line might end the section, but keep scanning a bit
                pass
        # Fallback: try ipconfig
        result = safe_run(
            ['ipconfig'], capture_output=True, text=True, timeout=5,
            creationflags=0x08000000
        )
        lines = result.stdout.split('\n')
        in_wifi = False
        for line in lines:
            if 'Wi-Fi' in line or 'WiFi' in line or 'Wireless' in line:
                in_wifi = True
                continue
            if in_wifi and 'IPv4' in line:
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    return ip_match.group(1)
    except Exception:
        pass
    return ''

def _get_local_subnet():
    """Get the WiFi network base (e.g. 192.168.1)."""
    ip = _get_wifi_ip()
    if not ip:
        # Fallback to default route
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            return ''
    parts = ip.split('.')
    if len(parts) == 4:
        return f'{parts[0]}.{parts[1]}.{parts[2]}'
    return ''

def _is_local_ip(ip):
    if not ip:
        return False
    if ip.startswith('127.') or ip.startswith('169.254.'):
        return False
    if ip.startswith('192.168.') or ip.startswith('10.'):
        return True
    if ip.startswith('172.'):
        parts = ip.split('.')
        if len(parts) > 1:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            except ValueError:
                pass
    return False

def _resolve_hostname(ip):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ''

def _ping_ip(ip, timeout=1):
    """Ping a single IP. Returns True if it responds."""
    system = platform.system().lower()
    try:
        if system == 'windows':
            result = safe_run(
                ['ping', '-n', '1', '-w', str(timeout * 1000), ip],
                capture_output=True, timeout=timeout + 2,
                creationflags=0x08000000  # CREATE_NO_WINDOW
            )
        else:
            result = safe_run(
                ['ping', '-c', '1', '-W', str(timeout), ip],
                capture_output=True, timeout=timeout + 2
            )
        return result.returncode == 0
    except Exception:
        return False

def _tcp_probe(ip, timeout=0.3):
    """Try connecting to common ports to force ARP entry.
    Many devices (phones, IoT) block ping but still respond to TCP."""
    for port in [80, 443, 445, 1900, 5000, 7000, 8009, 8080]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                return True
        except Exception:
            pass
    return False

def _probe_ip(ip):
    """Check if an IP is alive using ping AND TCP probe."""
    if _ping_ip(ip, timeout=1):
        return True
    return _tcp_probe(ip, timeout=0.3)

def _ping_sweep_parallel(subnet):
    """Ping + TCP probe all 254 addresses in parallel for speed.
    Uses both ICMP ping and TCP connect to find devices that block ping."""
    if not subnet:
        return set()
    alive = set()
    ips = [f'{subnet}.{i}' for i in range(1, 255)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(_probe_ip, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    alive.add(ip)
            except Exception:
                pass
    return alive

def _scan_port(ip, port, timeout=0.3):
    """Check if a single port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return port if result == 0 else None
    except Exception:
        return None

def _scan_ports(ip, timeout=0.3):
    """Quick parallel port scan to identify device type."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=19) as executor:
        futures = {executor.submit(_scan_port, ip, p, timeout): p for p in _SCAN_PORTS}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
            except Exception:
                pass
    return sorted(open_ports)

def _guess_device_type(open_ports, hostname, ip='', is_gateway=False):
    """Guess device type from open ports, hostname, and IP info."""
    h = (hostname or '').lower()
    # Gateway/router
    if is_gateway or 53 in open_ports:
        return 'Router/Gateway'
    # Port-based detection
    if 3074 in open_ports:
        return 'Xbox'
    if 8009 in open_ports:
        return 'Chromecast'
    if 1900 in open_ports or 3000 in open_ports or 5000 in open_ports:
        return 'Smart TV'
    if 631 in open_ports or 9100 in open_ports:
        return 'Printer'
    if 3389 in open_ports:
        return 'Windows PC'
    if 5900 in open_ports:
        return 'VNC Device'
    if 22 in open_ports and 23 not in open_ports:
        return 'Linux/Mac PC'
    if 23 in open_ports:
        return 'IoT Device'
    if 7000 in open_ports:
        return 'Apple Device'
    if 80 in open_ports and 443 in open_ports:
        return 'Web Server'
    if 80 in open_ports or 443 in open_ports:
        return 'Network Device'
    # Hostname-based detection
    if 'android' in h or 'samsung' in h or 'pixel' in h or 'galaxy' in h:
        return 'Android Phone'
    if 'iphone' in h or 'ipad' in h or 'apple' in h or 'macbook' in h:
        return 'Apple Device'
    if 'xbox' in h:
        return 'Xbox'
    if 'desktop' in h or 'windows' in h or 'pc' in h or 'win-' in h:
        return 'Windows PC'
    if 'linux' in h or 'ubuntu' in h or 'debian' in h:
        return 'Linux PC'
    if 'printer' in h or 'hp' in h or 'canon' in h or 'epson' in h or 'brother' in h:
        return 'Printer'
    if 'roku' in h or 'fire' in h or 'apple-tv' in h or 'appletv' in h:
        return 'Streaming Device'
    if 'nest' in h or 'ring' in h or 'camera' in h or 'doorbell' in h:
        return 'Smart Home'
    if 'alexa' in h or 'echo' in h or 'google' in h or 'home' in h:
        return 'Smart Speaker'
    if 'light' in h or 'switch' in h or 'plug' in h or 'hue' in h:
        return 'Smart Home'
    if h and h != ip and not h.startswith('192.'):
        return 'Network Device'
    # No ports, no hostname — likely a phone or tablet (blocks incoming)
    if not open_ports and not h:
        return 'Phone/Tablet'
    if open_ports:
        return 'Network Device'
    return 'Unknown'

def _get_arp_entries():
    """Read the ARP table for all local network devices."""
    devices = {}
    cmds = []
    _no_window = 0x08000000 if sys.platform == 'win32' else 0
    if sys.platform != 'win32':
        cmds.append(['ip', 'neigh'])
    cmds.append(['arp', '-a'])
    for cmd in cmds:
        try:
            out = safe_check_output(
                cmd, text=True, encoding='utf-8',
                errors='ignore', timeout=5,
                creationflags=_no_window
            )
        except Exception:
            continue
        for line in out.splitlines():
            line = line.strip()
            if not line or 'incomplete' in line.lower():
                continue
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            if _is_local_ip(ip):
                devices[ip] = True
    return devices

def scan_network_devices():
    """Discover all devices on the local network.
    Ping sweeps the subnet, port-scans each device to identify type.
    Returns [{ip, hostname, device_type, open_ports, interface}]"""
    seen_ips = set()
    devices = []

    subnet = _get_local_subnet()

    # 1. Ping sweep in parallel (fast — ~5 seconds for 254 IPs)
    alive_ips = _ping_sweep_parallel(subnet)

    # 2. Also check ARP table for anything we missed
    arp_ips = _get_arp_entries()

    # Merge all discovered IPs
    all_ips = set(alive_ips) | set(arp_ips.keys())

    # Get gateway IP to identify router
    gateway_ip = ''
    try:
        import psutil
        stats = psutil.net_if_addrs()
        for iface, addrs in stats.items():
            for addr in addrs:
                if addr.family.name == 'AF_INET' and not addr.address.startswith('127.'):
                    # Gateway is usually .1 on the subnet
                    parts = addr.address.split('.')
                    if len(parts) == 4:
                        gateway_ip = f'{parts[0]}.{parts[1]}.{parts[2]}.1'
                        break
            if gateway_ip:
                break
    except Exception:
        pass

    # 3. For each device, resolve hostname and scan ports (in parallel)
    def _process_device(ip):
        hostname = _resolve_hostname(ip)
        open_ports = _scan_ports(ip)
        is_gateway = (ip == gateway_ip)
        device_type = _guess_device_type(open_ports, hostname, ip, is_gateway)
        port_labels = [_DEVICE_PORTS.get(p, f'Port {p}') for p in open_ports]
        return {
            'ip': ip,
            'hostname': hostname or '',
            'device_type': device_type,
            'open_ports': port_labels,
            'interface': '',
        }

    sorted_ips = sorted(all_ips)
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_process_device, ip): ip for ip in sorted_ips}
        for future in concurrent.futures.as_completed(futures):
            try:
                devices.append(future.result())
            except Exception:
                pass

    devices.sort(key=lambda x: x['ip'])

    return devices


if __name__ == '__main__':
    print(f"Scanning network on {platform.system()}...")
    devs = scan_network_devices()
    print(f"\nFound {len(devs)} device(s):\n")
    for d in devs:
        name = d['hostname'] or '(unknown)'
        ports = ', '.join(d['open_ports']) if d['open_ports'] else 'none'
        print(f"  {d['ip']:<16} {d['device_type']:<16} {name:<20} Ports: {ports}")
