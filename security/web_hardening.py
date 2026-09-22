"""Security controls shared by the Flask web applications.

The application serves both browser pages and machine-to-machine APIs.  This
module keeps controls that apply to both request types in one place while
allowing signed/API-key requests to bypass browser-only CSRF checks.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Iterable

from flask import Flask, jsonify, render_template, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

logger = logging.getLogger("web_security")

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_TOKEN_FIELDS = ("csrf_token", "csrfToken")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_networks(name: str) -> tuple[ipaddress._BaseNetwork, ...]:
    raw = os.environ.get(name, "")
    networks = []
    for value in (part.strip() for part in raw.split(",")):
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"{name} contains an invalid network: {value}") from exc
    return tuple(networks)


def sanitize_text(value: object, *, max_length: int = 512) -> str:
    """Trim untrusted text and remove control characters.

    This is intentionally not HTML escaping; Jinja and JSON serializers remain
    responsible for output encoding at their respective boundaries.
    """
    if value is None:
        return ""
    text = _CONTROL_CHARS.sub("", str(value)).strip()
    return text[:max_length]


def validate_upload(
    uploaded: FileStorage,
    *,
    allowed_extensions: Iterable[str] | None = None,
    max_bytes: int | None = None,
) -> tuple[bool, str, str]:
    """Validate an uploaded filename before it is persisted.

    Returns ``(valid, sanitized_filename, error_message)``.  The stream is
    never trusted for its client-provided MIME type.
    """
    original = sanitize_text(uploaded.filename, max_length=255)
    filename = secure_filename(original)
    if not filename or filename in {".", ".."}:
        return False, "", "A valid filename is required"
    if len(filename) > 180:
        return False, "", "Filename is too long"

    if allowed_extensions is not None:
        allowed = {ext.lower().lstrip(".") for ext in allowed_extensions}
        suffix = Path(filename).suffix.lower().lstrip(".")
        if suffix not in allowed:
            return False, "", "File type is not permitted"

    if max_bytes is not None:
        content_length = uploaded.content_length
        if content_length is not None and content_length > max_bytes:
            return False, "", "Uploaded file is too large"
    return True, filename, ""


def _request_ip() -> str:
    return request.remote_addr or "0.0.0.0"


def _csrf_value() -> str:
    if request.form:
        for field in _TOKEN_FIELDS:
            if request.form.get(field):
                return request.form[field]
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        if isinstance(payload, dict):
            for field in _TOKEN_FIELDS:
                if payload.get(field):
                    return str(payload[field])
    for header in ("X-CSRF-Token", "X-CSRFToken"):
        if request.headers.get(header):
            return request.headers[header]
    return ""


def _is_api_authenticated() -> bool:
    """Return true for requests using the service-to-service API key."""
    configured = os.environ.get("CLOUD_API_KEY", "").strip()
    supplied = request.headers.get("X-Api-Key", "").strip()
    return bool(configured and supplied and secrets.compare_digest(configured, supplied))


def constant_time_equal(expected: str, supplied: str) -> bool:
    """Compare secret values without leaking length/content timing."""
    if not expected or not supplied:
        return False
    return secrets.compare_digest(expected, supplied)


def init_web_security(
    app: Flask,
    *,
    csrf_exempt_paths: Iterable[str] = (),
    api_prefixes: Iterable[str] = ("/agent/",),
) -> None:
    """Install request validation, browser CSRF, session, and audit controls."""
    allowlist = _parse_networks("SECURITY_IP_ALLOWLIST")
    blocklist = _parse_networks("SECURITY_IP_BLOCKLIST")
    exempt_paths = set(csrf_exempt_paths)
    api_prefixes = tuple(api_prefixes)
    session_timeout = int(os.environ.get("SESSION_TIMEOUT_SECONDS", "3600"))
    max_json_bytes = int(os.environ.get("MAX_JSON_BYTES", "1048576"))

    app.config.setdefault("MAX_CONTENT_LENGTH", int(os.environ.get(
        "MAX_REQUEST_BYTES", str(100 * 1024 * 1024)
    )))
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=_env_bool("SESSION_COOKIE_SECURE", True),
        SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
        PERMANENT_SESSION_LIFETIME=session_timeout,
        SESSION_REFRESH_EACH_REQUEST=True,
    )
    if "web_rate_limiter" not in app.extensions:
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=[
                os.environ.get("RATE_LIMIT_15MIN", "10000 per 15 minutes"),
            ],
            storage_uri=os.environ.get("RATE_LIMIT_STORAGE_URI", "memory://"),
            strategy="fixed-window",
            key_prefix="isolation_bytes",
        )
        app.extensions["web_rate_limiter"] = limiter

    @app.errorhandler(429)
    def rate_limit_response(error):
        wants_json = request.path.startswith("/api/") or (
            request.accept_mimetypes.best == "application/json"
            and request.accept_mimetypes["text/html"] == 0
        )
        if not wants_json:
            return render_template("429.html"), 429
        retry_after = getattr(error, "retry_after", None) or 900
        response = jsonify(error="Rate limit exceeded", message="Please wait 15 minutes before trying again.", retry_after=retry_after)
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response

    @app.before_request
    def enforce_web_security():
        try:
            client_ip = ipaddress.ip_address(_request_ip())
        except ValueError:
            logger.warning("Rejected request with invalid client IP")
            return jsonify(error="Invalid client address"), 400

        if allowlist and not any(client_ip in network for network in allowlist):
            logger.warning("Blocked request outside IP allowlist: %s %s", client_ip, request.path)
            return jsonify(error="Access denied"), 403
        if any(client_ip in network for network in blocklist):
            logger.warning("Blocked request from denylisted IP: %s", client_ip)
            return jsonify(error="Access denied"), 403

        if request.content_length and request.content_length > app.config["MAX_CONTENT_LENGTH"]:
            return jsonify(error="Request body is too large"), 413
        if request.is_json and request.content_length and request.content_length > max_json_bytes:
            return jsonify(error="JSON request is too large"), 413
        if request.path.startswith("/api/") and request.data and request.is_json:
            try:
                json.loads(request.data)
            except (TypeError, ValueError):
                return jsonify(error="Malformed JSON request"), 400

        now = int(time.time())
        browser_authenticated = bool(session.get("logged_in") or session.get("user_logged_in"))
        if browser_authenticated:
            # Use an inactivity timeout, not an absolute-from-login timeout.
            # The dashboard polls APIs continuously, so an active user must
            # not lose authentication after one fixed hour while still using it.
            last_activity = int(session.get("last_seen_at") or session.get("session_created_at") or now)
            if now - last_activity > session_timeout:
                session.clear()
                browser_authenticated = False
            else:
                session["last_seen_at"] = now
                session.permanent = True
                # Keep the legacy creation field aligned for older deployments.
                if not session.get("session_created_at"):
                    session["session_created_at"] = now

        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            is_machine_api = _is_api_authenticated() or any(
                request.path.startswith(prefix) for prefix in api_prefixes
            )
            browser_session = bool(session.get("logged_in") or session.get("user_logged_in"))
            login_request = request.path == "/login"
            if not is_machine_api and (
                browser_session or login_request
            ) and request.path not in exempt_paths:
                token = _csrf_value()
                expected = session.get("csrf_token", "")
                if not token or not expected or not secrets.compare_digest(token, expected):
                    logger.warning("CSRF validation failed for %s %s", _request_ip(), request.path)
                    return jsonify(error="CSRF token missing or invalid"), 403

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        microphone_policy = "(self)" if request.path.rstrip("/") == "/voice-assistant" else "()"
        response.headers.setdefault(
            "Permissions-Policy", f"camera=(), microphone={microphone_policy}, geolocation=()"
        )
        # The UI uses a small, explicit set of third-party static assets. Keep
        # the policy restrictive while allowing those assets and Cloudflare's
        # optional Web Analytics beacon.  Do not use wildcard sources.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'self'; form-action 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://static.cloudflareinsights.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "connect-src 'self' https://cloudflareinsights.com https://static.cloudflareinsights.com;",
        )
        if request.is_secure or _env_bool("SECURITY_HSTS", False):
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        logger.info(
            "request method=%s path=%s status=%s ip=%s",
            request.method, request.path, response.status_code, _request_ip(),
        )
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        return jsonify(error="Request body is too large"), 413
