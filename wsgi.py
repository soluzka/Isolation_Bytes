"""WSGI entry point for production deployment (waitress / gunicorn / uwsgi).

The cloud server's `create_cloud_app()` builds and returns a configured Flask
app with the `cloud_bp` blueprint registered at the root URL prefix, so all
routes (including `/get_folder_watcher_paths`, `/folder-watcher-paths`,
`/get_network_monitored_directories`, `/dashboard`, etc.) are available at the
top level of the domain.

Usage with waitress (recommended on Windows/Linux for this project):
    waitress-serve --listen=127.0.0.1:5002 wsgi:application

Usage with gunicorn (Linux):
    gunicorn --bind 127.0.0.1:5002 --workers 4 wsgi:application

Usage with uwsgi (Linux):
    uwsgi --http 127.0.0.1:5002 --wsgi-file wsgi.py --callable application

The app is built once at import time (the first time a worker loads this
module), which is the correct behaviour for production WSGI servers -- routes
added after the process starts will NOT be picked up, so always restart the
service after pulling new code.
"""
from cloud.cloud_server import create_cloud_app

# Build the app once at module import. WSGI servers import this module and
# look up `application` (the conventional WSGI callable name).
application = create_cloud_app()


if __name__ == '__main__':
    # Allow `python wsgi.py` for quick local smoke-testing using Flask's dev
    # server. Production should use waitress/gunicorn/uwsgi against
    # `wsgi:application` instead.
    application.run(host='127.0.0.1', port=5002, debug=False)
