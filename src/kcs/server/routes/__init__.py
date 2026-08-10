"""Lazy route exports for the mutually isolated V1 and V2 applications."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_ROUTE_EXPORTS = {
    "clusters_router": ("kcs.server.routes.clusters", "router"),
    "containers_router": ("kcs.server.routes.containers", "router"),
    "create_jobs_router": ("kcs.server.routes.jobs", "create_jobs_router"),
    "install_dev_session_websocket": (
        "kcs.server.routes.jobs",
        "install_dev_session_websocket",
    ),
    "install_project_dev_session_websocket": (
        "kcs.server.routes.jobs",
        "install_project_dev_session_websocket",
    ),
    "shell_proxy_router": ("kcs.server.routes.shell_proxy_routes", "router"),
    "shell_sessions_router": ("kcs.server.routes.shell_sessions", "router"),
    "system_router": ("kcs.server.routes.system", "router"),
}


def __getattr__(name: str) -> Any:
    """Import only the route family selected by the application mode."""
    try:
        module_name, attribute = _ROUTE_EXPORTS[name]
    except KeyError as error:
        raise AttributeError(name) from error
    value = getattr(import_module(module_name), attribute)
    globals()[name] = value
    return value


__all__ = [
    "containers_router",
    "clusters_router",
    "system_router",
    "shell_proxy_router",
    "shell_sessions_router",
    "create_jobs_router",
    "install_dev_session_websocket",
    "install_project_dev_session_websocket",
]
