import sys
import os

print("Python Version:", sys.version)
print("Python Path:", sys.executable)
print("Environment Variables:")
for key, value in os.environ.items():
    print(f"{key}: {value}")
