"""Auto-forward ports on a UPnP-enabled router."""
import socket
import upnpclient


def _local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "192.168.1.133"
    finally:
        s.close()


def main():
    local_ip = _local_ip()
    print(f"Local IP: {local_ip}")
    print("Discovering UPnP devices...")
    devices = upnpclient.discover()
    print(f"Found {len(devices)} devices")
    for device in devices:
        print(f"Device: {device.friendly_name} ({device.location})")
        for service in device.services:
            if "WAN" in service.name and ("IPConn" in service.name or "PPPConn" in service.name):
                print(f"  Service: {service.name}")
                action = service.find_action("AddPortMapping")
                if not action:
                    print("  AddPortMapping not found")
                    continue
                for port in (8443, 80):
                    try:
                        action(
                            NewRemoteHost="",
                            NewExternalPort=port,
                            NewProtocol="TCP",
                            NewInternalPort=port,
                            NewInternalClient=local_ip,
                            NewEnabled="1",
                            NewPortMappingDescription=f"Antivirus Server {port}",
                            NewLeaseDuration=0,
                        )
                        print(f"  Forwarded port {port}")
                    except Exception as e:
                        print(f"  Port {port}: {e}")


if __name__ == "__main__":
    main()
