import importlib.util
import zipfile
import tarfile
import os
import shutil

def import_module_from_path(module_name, file_path):
    """
    Dynamically import a module from a given file path.
    :param module_name: Name to assign to the module.
    :param file_path: Path to the module file.
    :return: Imported module object.
    """
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def extract_archive(filepath, extract_to):
    """
    Extract contents of an archive file to a specified directory.
    
    Args:
        filepath (str): Path to the archive file
        extract_to (str): Directory to extract the contents to
    
    Returns:
        bool: True if extraction was successful, False otherwise
    """
    try:
        if filepath.lower().endswith('.zip'):
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
        elif filepath.lower().endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tar.xz', '.txz')):
            with tarfile.open(filepath) as tar_ref:
                tar_ref.extractall(extract_to)
        elif filepath.lower().endswith(('.rar', '.7z')):
            # For .rar and .7z, you might need additional libraries
            # This is a placeholder for those formats
            raise NotImplementedError("RAR and 7z extraction not implemented")
        else:
            raise ValueError(f"Unsupported archive format: {os.path.basename(filepath)}")
        return True
    except Exception as e:
        print(f"Error extracting archive: {e}")
        return False
