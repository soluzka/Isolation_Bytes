"""Security package startup hooks."""

# The cloud dashboard imports security modules during server startup. Start the
# cloud warning bridge there so suspicious agent-reported connections can be
# forwarded to the existing firewall command channel, including LAN endpoints.
try:
    from .cloud_warning_bridge import start as _start_cloud_warning_bridge
    _start_cloud_warning_bridge()
except Exception:
    # Security package imports must never prevent unrelated detector modules
    # from loading; the bridge will be retried by normal process startup code.
    pass
