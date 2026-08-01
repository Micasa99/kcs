"""Narrow, non-secret RPC transport for the two fixed pod supervisors."""
# ruff: noqa: E501

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .errors import DependencyUnavailableError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class AgentRpcResponse:
    """The supervisor reply; it intentionally contains no credential material."""

    protocol_version: int
    generation: int
    agent_run_ref: str
    launch_bundle_digest: str
    state: str
    supervisor_alive: bool
    pid: int | None = None
    exit_code: int | None = None
    error: str | None = None
    credential_grant_ref: str | None = None
    audience: str | None = None
    credential_sha256: str | None = None
    credential_consumed: bool = False


class AgentRpcTransportProtocol(Protocol):
    def agent_rpc(
        self, binding: Mapping[str, str], request: Mapping[str, object]
    ) -> AgentRpcResponse: ...

    def stop_supervisor(self, binding: Mapping[str, str], container: str) -> AgentRpcResponse: ...


class ExecRpcTransport:
    """Run only fixed supervisor RPC commands through an injected pod-exec seam."""

    def __init__(
        self, execute: Callable[[Mapping[str, str], str, list[str], bytes], bytes]
    ) -> None:
        self._execute = execute

    def agent_rpc(
        self, binding: Mapping[str, str], request: Mapping[str, object]
    ) -> AgentRpcResponse:
        output = self._execute(
            binding,
            "agent",
            ["/opt/kcs/agent-supervisor", "rpc"],
            json.dumps(request, sort_keys=True, separators=(",", ":")).encode(),
        )
        return _response(output)

    def stop_supervisor(self, binding: Mapping[str, str], container: str) -> AgentRpcResponse:
        command = (
            ["/opt/kcs/agent-supervisor", "rpc"]
            if container == "agent"
            else ["/opt/kcs/workspace-sidecar", "rpc"]
        )
        output = self._execute(
            binding,
            container,
            command,
            b'{"protocolVersion":1,"action":"shutdown"}',
        )
        return _response(output)


def _response(output: bytes) -> AgentRpcResponse:
    try:
        value: Any = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DependencyUnavailableError("supervisor returned invalid RPC JSON") from exc
    if not isinstance(value, dict):
        raise DependencyUnavailableError("supervisor returned an invalid RPC response")
    required = (
        "protocolVersion",
        "generation",
        "agentRunRef",
        "launchBundleDigest",
        "state",
        "supervisorAlive",
    )
    if any(key not in value for key in required):
        raise DependencyUnavailableError("supervisor RPC response is missing required fields")
    protocol = value["protocolVersion"]
    generation = value["generation"]
    supervisor_alive = value["supervisorAlive"]
    if type(protocol) is not int or protocol != 1:
        raise DependencyUnavailableError("supervisor RPC protocol is invalid")
    if type(generation) is not int or generation < 0:
        raise DependencyUnavailableError("supervisor RPC generation is invalid")
    if type(supervisor_alive) is not bool:
        raise DependencyUnavailableError("supervisor RPC liveness is invalid")
    for field in ("agentRunRef", "launchBundleDigest", "state"):
        if not isinstance(value[field], str):
            raise DependencyUnavailableError("supervisor RPC field type is invalid")
    if generation > 0 and (
        not value["agentRunRef"] or not _DIGEST.fullmatch(value["launchBundleDigest"])
    ):
        raise DependencyUnavailableError("supervisor RPC start identity is invalid")
    for field in ("pid", "exitCode"):
        if value.get(field) is not None and type(value[field]) is not int:
            raise DependencyUnavailableError("supervisor RPC process observation is invalid")
    if "credentialConsumed" in value and type(value["credentialConsumed"]) is not bool:
        raise DependencyUnavailableError("supervisor RPC consumption proof is invalid")
    for field in ("credentialGrantRef", "audience", "credentialSha256", "error"):
        if value.get(field) is not None and not isinstance(value[field], str):
            raise DependencyUnavailableError("supervisor RPC optional field type is invalid")
    if value.get("credentialSha256") is not None and not _DIGEST.fullmatch(
        value["credentialSha256"]
    ):
        raise DependencyUnavailableError("supervisor RPC credential digest is invalid")
    return AgentRpcResponse(
        protocol_version=protocol,
        generation=generation,
        agent_run_ref=value["agentRunRef"],
        launch_bundle_digest=value["launchBundleDigest"],
        state=value["state"],
        supervisor_alive=supervisor_alive,
        credential_grant_ref=value["credentialGrantRef"]
        if value.get("credentialGrantRef") is not None
        else None,
        audience=value["audience"] if value.get("audience") is not None else None,
        credential_sha256=value["credentialSha256"]
        if value.get("credentialSha256") is not None
        else None,
        credential_consumed=value.get("credentialConsumed", False),
        pid=value["pid"] if value.get("pid") is not None else None,
        exit_code=value["exitCode"] if value.get("exitCode") is not None else None,
        error=value["error"] if value.get("error") is not None else None,
    )
