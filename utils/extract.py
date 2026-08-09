from utils.paths import get_resource_path
import os

import os
import zipfile
import tarfile

def extract_archive(path, destination=None):
    """
    Extracts a given archive file (ZIP or TAR) to a specified destination directory.
    If no destination is provided, the archive will be extracted in the same folder as the archive.
    
    Args:
        path (str): The path to the archive file (ZIP or TAR).
        destination (str): The path where the archive should be extracted. If None, extracted in the same folder.
        
    Returns:
        str: The path to the directory where the files were extracted.
    """
    
    # Get the file extension (e.g., .zip, .tar, .tar.gz, .tar.bz2)
    _, ext = os.path.splitext(path)
    
    # If no destination is provided, extract to the current directory of the archive
    if destination is None:
        destination = os.path.dirname(path)
    
    # Ensure destination exists
    os.makedirs(destination, exist_ok=True)
    
    # Extract based on the file type
    if ext == '.zip':
        with zipfile.ZipFile(path, 'r') as zip_ref:
            zip_ref.extractall(destination)
    elif ext in ('.tar', '.gz', '.bz2', '.tar.gz', '.tar.bz2'):
        with tarfile.open(get_resource_path(os.path.join(path)), 'r:*') as tar_ref:
            tar_ref.extractall(destination, filter="data")
    else:
        raise ValueError(f"Unsupported archive format: {ext}")

    return destination