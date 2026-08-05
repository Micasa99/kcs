"""Narrow, non-secret RPC transport for the two fixed pod supervisors."""
# ruff: noqa: E501

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .errors import DependencyTimeoutError, DependencyUnavailableError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_RPC_HEADER = 4 * 1024 * 1024
_COPY_CHUNK = 1024 * 1024


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

    def inspect_supervisor(
        self, binding: Mapping[str, str], container: str
    ) -> AgentRpcResponse: ...

    def stop_supervisor(self, binding: Mapping[str, str], container: str) -> AgentRpcResponse: ...

    def pause_agent(self, binding: Mapping[str, str]) -> AgentRpcResponse: ...

    def resume_agent(self, binding: Mapping[str, str]) -> AgentRpcResponse: ...


@dataclass(frozen=True, slots=True)
class WorkspaceRpcReply:
    """A control header plus an optional private raw-content file."""

    header: Mapping[str, Any]
    content_path: Path | None


class WorkspaceRpcTransportProtocol(Protocol):
    def rpc(
        self,
        binding: Mapping[str, str],
        header: Mapping[str, object],
        body: Path | None = None,
    ) -> WorkspaceRpcReply: ...


class LocalWorkspaceRpcTransport:
    """Exercise binary framing against a local conformance-sidecar seam."""

    def __init__(
        self,
        dispatch: Callable[[bytes, Path | None, Path], None],
        *,
        temp_dir: Path | None = None,
    ) -> None:
        self._dispatch = dispatch
        self._temp_dir = temp_dir
        self.last_request_frame = b""
        self.last_response_frame = b""

    def rpc(
        self,
        binding: Mapping[str, str],
        header: Mapping[str, object],
        body: Path | None = None,
    ) -> WorkspaceRpcReply:
        del binding
        frame = workspace_header_frame(header, body)
        response_path = _private_temp_path(self._temp_dir, "kcs-rpc-response-")
        self.last_request_frame = frame
        try:
            self._dispatch(frame, body, response_path)
            reply = _decode_workspace_response(
                response_path, self._temp_dir, _response_body_bound(header)
            )
            self.last_response_frame = workspace_header_frame(reply.header, reply.content_path)
            return reply
        finally:
            response_path.unlink(missing_ok=True)


class ExecWorkspaceRpcTransport:
    """Stream the one fixed workspace command through Kubernetes exec."""

    def __init__(
        self,
        execute: Callable[[Mapping[str, str], bytes, Path | None, Path, int], None],
        *,
        temp_dir: Path | None = None,
    ) -> None:
        self._execute = execute
        self._temp_dir = temp_dir

    def rpc(
        self,
        binding: Mapping[str, str],
        header: Mapping[str, object],
        body: Path | None = None,
    ) -> WorkspaceRpcReply:
        frame = workspace_header_frame(header, body)
        response_path = _private_temp_path(self._temp_dir, "kcs-rpc-response-")
        try:
            self._execute(
                binding,
                frame,
                body,
                response_path,
                _response_body_bound(header) + _MAX_RPC_HEADER + 4,
            )
            return _decode_workspace_response(
                response_path, self._temp_dir, _response_body_bound(header)
            )
        finally:
            response_path.unlink(missing_ok=True)


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
        if container != "agent":
            raise DependencyUnavailableError(
                "workspace shutdown must use the framed workspace transport"
            )
        output = self._execute(
            binding,
            "agent",
            ["/opt/kcs/agent-supervisor", "rpc"],
            b'{"protocolVersion":1,"action":"shutdown"}',
        )
        return _response(output)

    def inspect_supervisor(self, binding: Mapping[str, str], container: str) -> AgentRpcResponse:
        if container != "agent":
            raise DependencyUnavailableError(
                "workspace inspection must use the framed workspace transport"
            )
        output = self._execute(
            binding,
            "agent",
            ["/opt/kcs/agent-supervisor", "rpc"],
            b'{"protocolVersion":1,"action":"inspect"}',
        )
        return _response(output)

    def pause_agent(self, binding: Mapping[str, str]) -> AgentRpcResponse:
        output = self._execute(
            binding,
            "agent",
            ["/opt/kcs/agent-supervisor", "rpc"],
            b'{"protocolVersion":1,"action":"pause"}',
        )
        return _response(output)

    def resume_agent(self, binding: Mapping[str, str]) -> AgentRpcResponse:
        output = self._execute(
            binding,
            "agent",
            ["/opt/kcs/agent-supervisor", "rpc"],
            b'{"protocolVersion":1,"action":"resume"}',
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
    retryable_error = value.get("error")
    if retryable_error in {"CREDENTIAL_PROJECTION_TIMEOUT", "SUPERVISOR_REQUEST_REJECTED"}:
        if (
            generation != 0
            or value["state"] != "retryable"
            or supervisor_alive is not True
            or value.get("credentialConsumed") is not False
        ):
            raise DependencyUnavailableError("supervisor retryable RPC response is invalid")
        if retryable_error == "CREDENTIAL_PROJECTION_TIMEOUT":
            raise DependencyTimeoutError("credential projection did not become ready")
        raise DependencyUnavailableError("supervisor rejected the fixed RPC")
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


def workspace_header_frame(header: Mapping[str, object], body: Path | None) -> bytes:
    """Encode the bounded JSON header; raw body bytes remain a binary stream."""
    body_size = body.stat().st_size if body is not None else 0
    value = dict(header)
    value["bodySize"] = body_size
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > _MAX_RPC_HEADER:
        raise DependencyUnavailableError("workspace RPC header exceeded its bound")
    return struct.pack(">I", len(encoded)) + encoded


def decode_workspace_header(frame: bytes) -> dict[str, Any]:
    if len(frame) < 4:
        raise DependencyUnavailableError("workspace RPC header was truncated")
    size = struct.unpack(">I", frame[:4])[0]
    if size > _MAX_RPC_HEADER or len(frame) != size + 4:
        raise DependencyUnavailableError("workspace RPC header length was invalid")
    try:
        value: Any = json.loads(frame[4:])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DependencyUnavailableError("workspace RPC header was invalid") from error
    if not isinstance(value, dict) or type(value.get("bodySize")) is not int:
        raise DependencyUnavailableError("workspace RPC header shape was invalid")
    if value["bodySize"] < 0:
        raise DependencyUnavailableError("workspace RPC body size was invalid")
    return value


def write_workspace_response(
    path: Path, header: Mapping[str, object], body: Path | None = None
) -> None:
    frame = workspace_header_frame(header, body)
    with path.open("wb") as output:
        os.chmod(path, 0o600)
        output.write(frame)
        if body is not None:
            with body.open("rb") as source:
                shutil.copyfileobj(source, output, length=_COPY_CHUNK)
        output.flush()
        os.fsync(output.fileno())


def _decode_workspace_response(
    path: Path, temp_dir: Path | None, maximum_body_size: int
) -> WorkspaceRpcReply:
    with path.open("rb") as source:
        prefix = source.read(4)
        if len(prefix) != 4:
            raise DependencyUnavailableError("workspace RPC response was truncated")
        header_size = struct.unpack(">I", prefix)[0]
        if header_size > _MAX_RPC_HEADER:
            raise DependencyUnavailableError("workspace RPC response header exceeded its bound")
        header = decode_workspace_header(prefix + source.read(header_size))
        body_size = header["bodySize"]
        if body_size > maximum_body_size:
            raise DependencyUnavailableError("workspace RPC response body exceeded its bound")
        content_path = _private_temp_path(temp_dir, "kcs-rpc-content-") if body_size else None
        try:
            if content_path is not None:
                remaining = body_size
                with content_path.open("wb") as output:
                    while remaining:
                        chunk = source.read(min(_COPY_CHUNK, remaining))
                        if not chunk:
                            raise DependencyUnavailableError(
                                "workspace RPC response body was truncated"
                            )
                        output.write(chunk)
                        remaining -= len(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            if source.read(1):
                raise DependencyUnavailableError("workspace RPC response had trailing bytes")
        except Exception:
            if content_path is not None:
                content_path.unlink(missing_ok=True)
            raise
    return WorkspaceRpcReply(header=header, content_path=content_path)


def _private_temp_path(directory: Path | None, prefix: str) -> Path:
    descriptor, raw_path = tempfile.mkstemp(
        prefix=prefix, dir=str(directory) if directory is not None else None
    )
    os.close(descriptor)
    os.chmod(raw_path, 0o600)
    return Path(raw_path)


def _response_body_bound(header: Mapping[str, object]) -> int:
    if header.get("action") == "collect":
        value = header.get("authorizedMaxSizeBytes", 0)
        if type(value) is int and 0 <= value <= 107374182400:
            return value
    return 0
