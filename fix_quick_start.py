import re

p = r'C:\Users\bpier\OneDrive\Documents\antivirus-yara-rules-c\antivirus-yara-rules-c\quick_start.py'
with open(p, 'r', encoding='utf-8') as f:
    text = f.read()

new_main = r'''if __name__ == '__main__':
    if '--install-startup' in sys.argv:
        install_startup()
        sys.exit(0)
    if sys.executable.lower().endswith('.exe') and not _is_startup_installed():
        install_startup()
    _single_instance_handle = _ensure_single_instance()
    print("Starting clean Windows Defender app instance...")
    print("Real-Time Protection: " + ('ENABLED' if folder_watcher_state['active'] else 'DISABLED'))
    print("Network Monitoring: " + ('ENABLED' if network_state['monitoring_enabled'] else 'DISABLED'))
    print("Auto-Block: " + ('ENABLED' if network_state['auto_block_enabled'] else 'DISABLED'))

    # Ensure desktop shortcuts exist
    try:
        import create_conditional_shortcut
    except Exception:
        pass
    try:
        import create_yara_scanner_shortcut
    except Exception:
        pass

    import threading
    import queue

    # Start the Flask server first so the dashboard is available immediately
    port_queue = queue.Queue()

    def start_server_and_report(default_port=5000):
        actual_port = start_server(default_port)
        if actual_port is not None:
            try:
                port_queue.put(actual_port, block=False)
            except queue.Full:
                pass
        return actual_port

    server_port = 5000
    server_thread = threading.Thread(target=lambda: start_server_and_report(server_port), daemon=True)
    server_thread.start()

    detected_port = None
    try:
        detected_port = port_queue.get(timeout=10)
        print(f"Server reported running on port {detected_port}")
    except queue.Empty:
        print("Server did not report its port. Attempting detection...")
        potential_ports = [5000, 5001, 8080, 8000, 3000]
        max_retries = 3
        for attempt in range(max_retries):
            time.sleep(1 + attempt)
            for port in potential_ports:
                try:
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.settimeout(1.0)
                    result = test_socket.connect_ex(('127.0.0.1', port))
                    test_socket.close()
                    if result == 0:
                        try:
                            import requests
                            if requests.get(f"http://127.0.0.1:{port}", timeout=2).status_code == 200:
                                detected_port = port
                                print(f"Verified server running on port {port} with HTTP request")
                                break
                        except Exception:
                            if detected_port is None:
                                detected_port = port
                except Exception:
                    pass
            if detected_port:
                break

    if detected_port is None:
        print("Trying one last attempt to find the server...")
        for port in [5000, 5001, 8080, 8000, 3000]:
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(0.3)
                result = test_socket.connect_ex(('127.0.0.1', port))
                test_socket.close()
                if result == 0:
                    detected_port = port
                    print(f"Found a service on port {port} - assuming it's our server")
                    break
            except Exception:
                pass

    if detected_port is not None:
        base_url = f"http://127.0.0.1:{detected_port}"
        browser_path = '/yara-scanner' if '--open-yara' in sys.argv else ''
        url = f"{base_url}{browser_path}"
        print(f"Server is ready at {url}")
        if sys.platform == 'win32':
            try:
                title = 'YARA Scanner' if browser_path else 'Antivirus Dashboard'
                result = ctypes.windll.user32.MessageBoxW(
                    0,
                    f"{title} is ready at {url}\n\n"
                    "Click OK to open it.",
                    title,
                    0x00000000
                )
                if result == 1:
                    import webbrowser
                    webbrowser.open(url, new=2)
            except Exception:
                print('Failed to open browser')
    else:
        print("\nCould not detect which port the server is running on.")
        print("The server is likely running on one of: 5000, 5001, 8080, 8000")
        print("Please try opening these URLs in your browser manually:")
        print("  - http://127.0.0.1:5000")
        print("  - http://127.0.0.1:5001")
        print("  - http://localhost:5000")
        print("  - http://localhost:5001")

    # Initialize DNS server (localhost only)
    try:
        dns_server, dns_resolver = start_dns_server(allow_network=False)
        logging.info("DNS server started automatically at application startup")
    except Exception as e:
        logging.error(f"Failed to start DNS server: {str(e)}. This is normal if not running as administrator.")

    # Start scheduled scanning thread for continuous YARA scanning
    scan_thread = threading.Thread(target=run_scheduled_scans, daemon=True)
    scan_thread.start()
    logger.info("Scheduled scanning thread started for continuous YARA scanning")

    # Auto-block monitor thread
    auto_block_thread = threading.Thread(target=run_auto_block_monitor, daemon=True)
    auto_block_thread.start()
    logger.info("Auto-block monitor thread started (active by default)")

    # Process hardening monitor thread
    process_hardening_thread = threading.Thread(target=run_process_hardening_monitor, daemon=True)
    process_hardening_thread.start()
    logger.info("Process hardening monitor thread started")

    # Start conditional startup scan in the background after the server is up
    with conditional_startup_lock:
        if not conditional_startup_state['running']:
            conditional_startup_state.update({
                'running': True,
                'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'last_updated': time.strftime('%Y-%m-%d %H:%M:%S'),
            })
            conditional_startup_thread = threading.Thread(target=run_conditional_startup_background, daemon=True)
            conditional_startup_thread.start()
            logger.info("Conditional startup scan auto-started")

    # Start automatic signature updates
    from auto_update_signatures import start_auto_update_thread
    auto_update_sig_thread = threading.Thread(target=start_auto_update_thread, daemon=True)
    auto_update_sig_thread.start()
    logger.info("Automatic signature update thread started")

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down server...")
    except Exception as e:
        print(f"Error in main thread: {e}")
        print("Server may still be running in background.")
        print("Close this console window to shut down completely.")
'''

pattern = r"if __name__ == '__main__':.*?$"
text = re.sub(pattern, new_main, text, flags=re.DOTALL, count=1)

with open(p, 'w', encoding='utf-8') as f:
    f.write(text)
print('quick_start.py updated')
