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
# Load the ctypes shim first so Windows-specific code doesn't crash on Linux
try:
    import ctypes_shim
except ImportError:
    pass

import logging
from flask import Flask, jsonify

logger = logging.getLogger("isolation_bytes_wsgi")

# Build the production application once at module import. If a newly deployed
# optional dependency or application import fails, keep Gunicorn alive with a
# minimal diagnostic application instead of allowing the upstream to disappear
# and Cloudflare to return a generic 502. The original exception is logged to
# stderr/journal and exposed only as a generic health status.
try:
    from cloud.cloud_server import create_cloud_app
    application = create_cloud_app()
    _startup_error = None
except Exception as exc:
    _startup_error = exc
    logger.exception("Isolation Bytes WSGI application failed to initialize")
    application = Flask("isolation_bytes_startup_fallback")

    @application.get("/healthz")
    def _startup_healthz():
        return jsonify({
            "status": "degraded",
            "application": "Isolation Bytes",
            "error": "Application startup failed; inspect antivirus-cloud journal.",
        }), 503

    @application.route("/", methods=["GET", "HEAD"])
    @application.route("/login", methods=["GET", "HEAD"])
    def _startup_unavailable():
        return (
            "Isolation Bytes is temporarily unavailable while the server "
            "application is recovering. Check the antivirus-cloud service log.",
            503,
            {"Content-Type": "text/plain; charset=utf-8"},
        )


if __name__ == '__main__':
    # Allow `python wsgi.py` for quick local smoke-testing using Flask's dev
    # server. Production should use waitress/gunicorn/uwsgi against
    # `wsgi:application` instead.
    application.run(host='127.0.0.1', port=5002, debug=False)
