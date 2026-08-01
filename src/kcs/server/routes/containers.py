"""Container routes — CRUD, lifecycle, logs, exec, and upload."""

from __future__ import annotations

import logging
import os
import re
import subprocess

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse, StreamingResponse

from kcs.legacy_guard import LegacyTargetForbiddenError
from kcs.server.models import ContainerCreate, ExecRequest, ScaleRequest
from kcs.server.services import get_service, resolve_image

log = logging.getLogger("kcs")
router = APIRouter(tags=["Containers"])


# ── CRUD ────────────────────────────────────────────────────────────────────


@router.get("/api/v1/containers", summary="List containers")
def list_containers(all: bool = Query(default=False, alias="all_namespaces")):
    client = get_service().get_client()
    try:
        containers = client.list(all_namespaces=all)
    except LegacyTargetForbiddenError as error:
        raise HTTPException(status_code=403, detail=str(error)) from None
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
    return {"containers": containers}


@router.post("/api/v1/containers", status_code=201, summary="Create a container")
def create_container(req: ContainerCreate):
    client = get_service().get_client()
    image = resolve_image(req.image)

    name = req.name
    if not name:
        name = image.rsplit("/", 1)[-1].split(":")[0]
        name = re.sub(r"[^a-zA-Z0-9.-]", "-", name).lower().strip("-.")

    env_dict = req.env or {}
    volumes = []
    for v in req.volumes or []:
        if ":" in v:
            parts = v.split(":", 1)
            volumes.append({"host": parts[0], "container": parts[1]})
        else:
            volumes.append({"path": v})

    try:
        result = client.create(
            name=name,
            image=image,
            ports=req.ports,
            env=env_dict,
            volumes=volumes,
            replicas=req.replicas,
            node=req.node,
            gpus=req.gpus,
            cpu=req.cpu,
            memory=req.memory,
        )
        return result
    except LegacyTargetForbiddenError as error:
        raise HTTPException(status_code=403, detail=str(error)) from None
    except Exception as e:
        msg = str(e)
        if "already exists" in msg:
            raise HTTPException(status_code=409, detail=msg) from e
        raise HTTPException(status_code=500, detail=msg) from e


@router.get("/api/v1/containers/{name}", summary="Inspect a container")
def inspect_container(name: str):
    client = get_service().get_client()
    detail = client.get(name)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Container '{name}' not found")
    return detail


@router.delete("/api/v1/containers/{name}", summary="Remove a container")
def remove_container(name: str, force: bool = Query(default=False)):
    client = get_service().get_client()
    if client.remove(name, force=force):
        from kcs import shell_proxy

        for p in shell_proxy.list_running():
            if p["container"] == name:
                try:
                    shell_proxy.stop(p["container"], p.get("session", ""))
                except Exception:
                    pass
        return {"message": f"Container '{name}' removed"}
    raise HTTPException(status_code=404, detail=f"Container '{name}' not found")


@router.post("/api/v1/containers/{name}/stop", summary="Stop a container")
def stop_container(name: str):
    client = get_service().get_client()
    if client.stop(name):
        return {"message": f"Container '{name}' stopped"}
    raise HTTPException(status_code=404, detail=f"Container '{name}' not found")


@router.post("/api/v1/containers/{name}/start", summary="Start a container")
def start_container(name: str):
    client = get_service().get_client()
    if client.start(name):
        return {"message": f"Container '{name}' started"}
    raise HTTPException(status_code=404, detail=f"Container '{name}' not found")


@router.post("/api/v1/containers/{name}/scale", summary="Scale replicas")
def scale_container(name: str, req: ScaleRequest):
    if req.replicas < 0:
        raise HTTPException(status_code=400, detail="Replicas must be >= 0")
    client = get_service().get_client()
    if client.scale(name, req.replicas):
        return {"message": f"Container '{name}' scaled to {req.replicas}"}
    raise HTTPException(status_code=404, detail=f"Container '{name}' not found")


# ── Logs, exec, upload ──────────────────────────────────────────────────────


@router.get("/api/v1/containers/{name}/logs", summary="Fetch container logs")
def container_logs(
    name: str,
    follow: bool = Query(default=False),
    tail: int = Query(default=100, ge=1, le=10000),
    pod: int | None = Query(default=None),
):
    client = get_service().get_client()
    try:
        if follow:
            resp = client.logs(name, follow=True, tail=tail, pod=pod)

            def stream():
                for line in resp:
                    yield line.decode("utf-8", errors="replace")

            return StreamingResponse(stream(), media_type="text/plain")
        else:
            output = client.logs(name, follow=False, tail=tail, pod=pod)
            return PlainTextResponse(output)
    except LegacyTargetForbiddenError as error:
        raise HTTPException(status_code=403, detail=str(error)) from None
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/api/v1/containers/{name}/exec", summary="Execute a command (non-interactive)")
def exec_container(name: str, req: ExecRequest, pod: int | None = Query(default=None)):
    client = get_service().get_client()
    result = client.exec(name, req.command, pod=pod, tty=False, stdin=False)
    if isinstance(result, str) and result.startswith("Error"):
        raise HTTPException(status_code=500, detail=result)
    return {"output": result}


@router.post("/api/v1/containers/{name}/upload", summary="Upload a file into a container")
def upload_file(
    name: str,
    path: str = Query(..., description="Target path inside the container"),
    file: UploadFile = File(..., description="File to upload"),  # noqa: B008
):
    client = get_service().get_client()
    svc = get_service()

    detail = client.get(name)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Container '{name}' not found")

    try:
        pod_name = client._get_target_pod(name)
    except LegacyTargetForbiddenError as error:
        raise HTTPException(status_code=403, detail=str(error)) from None
    if not pod_name:
        raise HTTPException(status_code=404, detail="No running pod found")

    # Try NFS direct write first
    parent_dir = os.path.dirname(path) or "/"
    try:
        nfs_base = client.resolve_volume_path(name, parent_dir)
    except LegacyTargetForbiddenError as error:
        raise HTTPException(status_code=403, detail=str(error)) from None
    if nfs_base:
        import shutil

        dest = os.path.join(nfs_base, os.path.basename(path) if os.path.basename(path) else "")
        if os.path.isdir(dest):
            dest = os.path.join(dest, file.filename or "upload")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            with open(dest, "wb") as f:
                shutil.copyfileobj(file.file, f)
            return {"path": path, "size": os.path.getsize(dest), "method": "nfs"}
        except OSError as e:
            raise HTTPException(status_code=500, detail=f"NFS write failed: {e}") from e

    # Fallback: kubectl cp
    import tempfile

    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            import shutil

            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name
        try:
            env = os.environ.copy()
            kubeconfig = svc.get_kubeconfig_path()
            if kubeconfig:
                env["KUBECONFIG"] = kubeconfig
            subprocess.run(
                ["kubectl", "cp", tmp_path, f"{client.namespace}/{pod_name}:{path}"],
                env=env,
                check=True,
                timeout=30,
            )
        finally:
            os.unlink(tmp_path)
        return {"path": path, "size": file.size or 0, "method": "kubectl-cp"}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"kubectl cp failed: {e}") from e


@router.get("/api/v1/containers/{name}/pods", summary="List pods for a container")
def list_container_pods(name: str):
    client = get_service().get_client()
    pods = client.list_pods(name)
    return {"name": name, "pods": pods}
