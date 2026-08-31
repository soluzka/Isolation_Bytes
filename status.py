def get_realtime_status(folder_watcher, network_monitor_running, safe_download_service, rtp_status_flag):
    """Get the current status of all real-time protection components
    
    Args:
        folder_watcher: The folder watcher process object
        network_monitor_running: Boolean indicating if network monitor is running
        safe_download_service: The safe download service object
        rtp_status_flag: Current status of real-time protection
    
    Returns:
        dict: Dictionary containing status information
    """
    return {
        'folder_watcher': folder_watcher is not None and folder_watcher.is_alive,
        'network_monitor': network_monitor_running,
        'safe_downloader': hasattr(safe_download_service, '_thread') and safe_download_service._thread.is_alive(),
        'rtp_status': rtp_status_flag
    }

if __name__ == '__main__':
    print("Status module loaded successfully")
