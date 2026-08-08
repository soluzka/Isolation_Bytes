import os
import shutil

def cleanup(directory):
    for root, dirs, files in os.walk(directory):
        for dir_name in dirs:
            if dir_name == "__pycache__":
                shutil.rmtree(os.path.join(root, dir_name))
        for file_name in files:
            if file_name.endswith(".pyc"):
                os.remove(os.path.join(root, file_name))

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cleanup(base_dir)
    print("Cleanup completed.")
