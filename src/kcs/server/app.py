"""FastAPI application factory for kcs."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from kcs import __version__

if TYPE_CHECKING:
    from kcs.jobs.provider import V2JobProvider
    from kcs.jobs.settings import V2RuntimeSettings

log = logging.getLogger("kcs")
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])


def _get_api_key() -> str | None:
    """Read the configured API key from the cluster config (if any)."""
    from kcs.server.services import get_service

    svc = get_service()
    if svc.cluster_config and svc.cluster_config.api_key:
        return svc.cluster_config.api_key
    return None


def create_app(
    *,
    api_mode: str | None = None,
    v2_provider: V2JobProvider | None = None,
    v2_settings: V2RuntimeSettings | None = None,
    v2_service_token: str | None = None,
) -> FastAPI:
    """Create the legacy app or the isolated V2 attempt runtime."""
    has_v2_injection = any(
        value is not None for value in (v2_provider, v2_settings, v2_service_token)
    )
    selected_mode = (
        api_mode
        if api_mode is not None
        else ("v2" if has_v2_injection else os.environ.get("KCS_API_MODE", "v1"))
    )
    if selected_mode not in {"v1", "v2"}:
        raise ValueError("KCS_API_MODE must be 'v1' or 'v2'")
    if selected_mode == "v2":
        return _create_v2_app(
            provider=v2_provider,
            settings=v2_settings,
            service_token=v2_service_token,
        )
    if has_v2_injection:
        raise ValueError("V2 dependencies cannot be injected into the V1 application")

    from kcs.server.routes import (
        clusters_router,
        containers_router,
        shell_proxy_router,
        shell_sessions_router,
        system_router,
    )

    tags_metadata = [
        {
            "name": "Containers",
            "description": "Create, inspect, start, stop, scale, and remove containers. "
            "Also includes logs, exec, and interactive shell sessions.",
        },
        {
            "name": "System",
            "description": "Cluster health, aggregated dashboard status, node listing, and info.",
        },
        {
            "name": "Images",
            "description": "Build Docker images and push to the cluster registry.",
        },
        {
            "name": "Cluster",
            "description": "Apply declarative cluster configuration — join workers and prune "
            "stale nodes.",
        },
        {
            "name": "Shell Proxy",
            "description": "Start and stop shell proxies for CLAUDE_CODE_SHELL integration.",
        },
    ]

    app = FastAPI(
        title="kcs API",
        description="REST API for managing container workloads on a k3s cluster.",
        version=__version__,
        openapi_tags=tags_metadata,
    )

    app.state.limiter = limiter
    app.add_exception_handler(
        RateLimitExceeded,
        _rate_limit_exceeded_handler,  # type: ignore[arg-type]
    )

    # Static files
    static_dir = Path(__file__).resolve().parent.parent / "static"
    static_dir.mkdir(exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(str(static_dir / "index.html"))

    @app.middleware("http")
    async def log_requests(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        start = time.time()
        response = await call_next(request)
        duration = (time.time() - start) * 1000
        log.info(
            "%s %s → %s (%.0fms)",
            request.method,
            request.url.path,
            response.status_code,
            duration,
        )
        return response

    @app.middleware("http")
    async def auth(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        api_key = _get_api_key()
        # No auth configured — allow all
        if not api_key:
            return await call_next(request)

        # Allow static files and docs without auth
        path = request.url.path
        if (
            path == "/"
            or path.startswith("/static")
            or path in ("/docs", "/redoc", "/openapi.json")
        ):
            return await call_next(request)

        # Require Authorization header
        auth_header = request.headers.get("Authorization", "")
        if auth_header == f"Bearer {api_key}":
            return await call_next(request)

        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized — use Authorization: Bearer <key>"},
        )

    # Register routers
    app.include_router(system_router)
    app.include_router(containers_router)
    app.include_router(clusters_router)
    app.include_router(shell_proxy_router)
    app.include_router(shell_sessions_router)

    return app


def _create_v2_app(
    *,
    provider: V2JobProvider | None,
    settings: V2RuntimeSettings | None,
    service_token: str | None,
) -> FastAPI:
    """Create only the private health and authenticated V2 Job surfaces."""
    from kcs.jobs.settings import V2RuntimeSettings
    from kcs.server.routes import create_jobs_router

    if settings is None:
        settings_environ = dict(os.environ)
        settings_environ["KCS_API_MODE"] = "v2"
        if service_token is not None:
            settings_environ["KCS_V2_SERVICE_TOKEN"] = service_token
        settings = V2RuntimeSettings.from_env(settings_environ)
    elif settings.api_mode != "v2":
        raise ValueError("V2 settings must select api_mode='v2'")

    resolved_token = service_token if service_token is not None else settings.service_token
    if resolved_token is None:
        raise ValueError("KCS_V2_SERVICE_TOKEN is required for the V2 application")
    if provider is None:
        from kcs.server.services import get_v2_provider

        provider = get_v2_provider(settings)

    app = FastAPI(
        title="kcs V2 Attempt Runtime API",
        description="Isolated physical attempt runtime for ResearchCosmos.",
        version="2.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    reconcile_stop = asyncio.Event()

    async def reconcile_loop() -> None:
        while not reconcile_stop.is_set():
            try:
                await asyncio.to_thread(provider.reconcile_credentials)
            except Exception:
                log.warning("V2 credential reconciliation failed; retrying", exc_info=True)
            try:
                await asyncio.wait_for(reconcile_stop.wait(), timeout=30)
            except TimeoutError:
                pass

    @app.on_event("startup")
    async def start_reconciliation() -> None:
        await asyncio.to_thread(provider.reconcile_credentials)
        app.state.kcs_reconcile_task = asyncio.create_task(reconcile_loop())

    @app.on_event("shutdown")
    async def stop_reconciliation() -> None:
        reconcile_stop.set()
        await app.state.kcs_reconcile_task

    @app.get("/api/v1/health", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.middleware("http")
    async def log_v2_requests(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        start = time.time()
        response = await call_next(request)
        duration = (time.time() - start) * 1000
        log.info(
            "%s %s → %s (%.0fms)",
            request.method,
            request.url.path,
            response.status_code,
            duration,
        )
        return response

    app.include_router(create_jobs_router(provider, resolved_token))
    return app


app = create_app()
