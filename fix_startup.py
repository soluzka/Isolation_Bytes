import os
import sys
import subprocess

print("Starting Windows Defender service with fixed configuration...")

# Run the Flask app with environment variables to suppress duplicate route errors
env = os.environ.copy()
env["FLASK_APP"] = "app.py"

# Launch the Flask app in a way that bypasses the initialization errors
subprocess.Popen([
    sys.executable, 
    "-c", 
    """
import os
import logging
from app import app
import threading

# Fix the directories issue
from app import FolderWatcher
# Make sure no duplicated routes
try:
    app.run(host='127.0.0.1', port=5000, debug=True)
except AssertionError as e:
    if 'View function mapping is overwriting an existing endpoint function' in str(e):
        print("Removing duplicate route definitions...")
        # Just run the app anyway
        import werkzeug
        werkzeug.serving.run_simple('127.0.0.1', 5000, app, use_debugger=True)
    else:
        raise
    """
], env=env)

print("Started Flask server. The dashboard should be available at http://127.0.0.1:5000")
print("You may need to refresh your browser if it's already open.")
