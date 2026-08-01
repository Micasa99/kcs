"""Pydantic request/response models for kcs API."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator

# RFC 1123: lowercase alphanumeric + '-' + '.', start/end alphanumeric, max 253 chars
_CONTAINER_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


class ContainerCreate(BaseModel):
    image: str
    name: str | None = None
    ports: list[int] | None = None
    env: dict[str, str] | None = None
    volumes: list[str] | None = None  # ["/data"] or ["./host:/container"]
    replicas: int = 1
    node: str | None = None  # pin to specific node (hostname)
    gpus: int | None = None  # number of GPUs (nvidia.com/gpu), exclusive
    cpu: str | None = None  # e.g. "1", "500m", "2"
    memory: str | None = None  # e.g. "512Mi", "1Gi"

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if len(v) > 253:
            raise ValueError("container name must be <= 253 characters")
        if not _CONTAINER_NAME_RE.match(v):
            raise ValueError(
                "container name must be RFC 1123 compliant: "
                "lowercase letters, digits, hyphens, dots; start and end with alphanumeric"
            )
        return v


class ScaleRequest(BaseModel):
    replicas: int


class ExecRequest(BaseModel):
    command: list[str]


class BuildRequest(BaseModel):
    tag: str
    path: str = "."
    no_push: bool = False


class ClusterJoin(BaseModel):
    node: str | None = None  # user@host or just host
    server: str | None = None
    token: str | None = None
    password: str | None = None


class WorkerNode(BaseModel):
    host: str
    user: str = "root"
    password: str | None = Field(default=None, repr=False)  # optional — prefer ssh_key
    ssh_key: str | None = Field(default=None, repr=False)  # e.g. ~/.ssh/id_ed25519


class ClusterConfig(BaseModel):
    backend: str = "k3s"  # k3s (host) or k3d
    api_key: str | None = None  # shared secret for API auth (env: KCS_API_KEY)
    sudo_password: str | None = None  # local sudo password (for reading token, etc.)
    nfs_path: str = "/srv/nfs/k3s"  # NFS export path, use data disk if system disk is small
    workers: list[WorkerNode] = []
