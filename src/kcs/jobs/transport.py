"""Narrow, non-secret RPC transport for the two fixed pod supervisors."""
# ruff: noqa: E501

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol


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


class AgentRpcTransportProtocol(Protocol):
    def agent_rpc(
        self, binding: Mapping[str, str], request: Mapping[str, object]
    ) -> AgentRpcResponse: ...

    def stop_supervisor(self, binding: Mapping[str, str], container: str) -> None: ...


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

    def stop_supervisor(self, binding: Mapping[str, str], container: str) -> None:
        command = (
            ["/opt/kcs/agent-supervisor", "rpc", "--shutdown"]
            if container == "agent"
            else ["/opt/kcs/workspace-sidecar", "rpc", "--shutdown"]
        )
        self._execute(binding, container, command, b"{}")


def _response(output: bytes) -> AgentRpcResponse:
    try:
        value: Any = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("supervisor returned invalid RPC JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("supervisor returned an invalid RPC response")
    required = (
        "protocolVersion",
        "generation",
        "agentRunRef",
        "launchBundleDigest",
        "state",
        "supervisorAlive",
    )
    if any(key not in value for key in required):
        raise ValueError("supervisor RPC response is missing required fields")
    return AgentRpcResponse(
        protocol_version=int(value["protocolVersion"]),
        generation=int(value["generation"]),
        agent_run_ref=str(value["agentRunRef"]),
        launch_bundle_digest=str(value["launchBundleDigest"]),
        state=str(value["state"]),
        supervisor_alive=bool(value["supervisorAlive"]),
        pid=int(value["pid"]) if value.get("pid") is not None else None,
        exit_code=int(value["exitCode"]) if value.get("exitCode") is not None else None,
        error=str(value["error"]) if value.get("error") is not None else None,
    )
