"""Shell proxy management — start / stop / list Unix-socket proxies."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from kcs import shell_proxy
from kcs.legacy_guard import LegacyTargetForbiddenError

router = APIRouter(tags=["Shell Proxy"])


class ShellProxyStartRequest(BaseModel):
    container: str
    session: str = ""


@router.get("/api/v1/shell-proxy", summary="List running shell proxies")
def list_proxies():
    return {"proxies": shell_proxy.list_running()}


@router.post("/api/v1/shell-proxy/start", status_code=201, summary="Start a shell proxy")
def start_proxy(req: ShellProxyStartRequest):
    """Launch a Unix-socket proxy forwarding commands into a container."""
    try:
        return shell_proxy.start(container=req.container, session=req.session)
    except LegacyTargetForbiddenError as error:
        raise HTTPException(status_code=403, detail=str(error)) from None
    except RuntimeError as e:
        msg = str(e)
        if "already running" in msg.lower():
            raise HTTPException(status_code=409, detail=msg) from e
        raise HTTPException(status_code=500, detail=msg) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/api/v1/shell-proxy/stop", summary="Stop a shell proxy")
def stop_proxy(
    container: str = Query(..., description="Container name"),
    session: str = Query(default="", description="Session label"),
):
    """Shut down the shell proxy for the given container and session."""
    try:
        shell_proxy.stop(container, session)
    except RuntimeError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    label = f"{container}/{session}" if session else container
    return {"message": f"Shell proxy for {label} stopped"}
