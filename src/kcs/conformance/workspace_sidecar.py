"""Fixed conformance probes layered over the production runtime control.

Production control behavior lives in :mod:`kcs.runtime_control.workspace_sidecar`.
This module only retains the historical fixed actions used by hosted/conformance
fixtures and the legacy console-script alias.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from kcs.conformance.actions import (
    observe_workspace_gpu,
    probe_runtime_url,
    shared_read,
    shared_write,
)
from kcs.runtime_control.workspace_sidecar import (
    RuntimeControlSidecar,
    _RpcRejectedError,
    main,
    rpc,
)
from kcs.runtime_control.workspace_sidecar import (
    serve as _serve,
)


class WorkspaceSidecar(RuntimeControlSidecar):
    """Test wrapper that adds only the frozen conformance actions."""

    def _handle(
        self, request: Mapping[str, Any], body: Path | None
    ) -> tuple[dict[str, object], Path | None]:
        if request.get("action") == "shutdown" and not os.environ.get("KCS_NATIVE_LAUNCHER_SOCKET"):
            self.shutdown_requested = True
            return {"ok": True, "state": "stopped", "supervisorAlive": False}, None
        return super()._handle(request, body)

    def _handle_extension(
        self, request: Mapping[str, Any], body: Path | None
    ) -> tuple[dict[str, object], Path | None]:
        del body
        action = request.get("action")
        if (
            request.get("protocolVersion") == 1
            and action == "sharedWrite"
            and set(request) == {"protocolVersion", "action"}
        ):
            return shared_write(self.workspace, "workspace"), None
        if (
            request.get("protocolVersion") == 1
            and action == "sharedRead"
            and set(request) == {"protocolVersion", "action", "sourceRole"}
        ):
            return shared_read(self.workspace, "workspace", request.get("sourceRole")), None
        if (
            request.get("protocolVersion") == 1
            and action == "observeGpu"
            and set(request) == {"protocolVersion", "action"}
        ):
            return observe_workspace_gpu(), None
        raise _RpcRejectedError("INVALID_REQUEST", "unsupported conformance RPC action")

    def _execute_workspace_action(self, frame: Mapping[str, Any]) -> dict[str, object]:
        action = frame.get("action")
        allowed_fields = {
            "sharedWrite": {"protocol", "action"},
            "sharedRead": {"protocol", "action", "sourceRole"},
            "observeGpu": {"protocol", "action"},
            "probeRuntimeUrl": {"protocol", "action"},
        }
        if (
            not isinstance(action, str)
            or action not in allowed_fields
            or set(frame) != allowed_fields[action]
        ):
            raise _RpcRejectedError(
                "INVALID_REQUEST", "workspace action is not a fixed conformance action"
            )
        if action == "sharedWrite":
            return shared_write(self.workspace, "workspace")
        if action == "sharedRead":
            return shared_read(self.workspace, "workspace", frame.get("sourceRole"))
        if action == "observeGpu":
            return observe_workspace_gpu()
        return probe_runtime_url(os.environ.get("RC_PUBLIC_RUNTIME_BASE_URL"))


def serve(socket_path: Path, workspace: Path) -> None:
    """Run the fixed conformance wrapper."""
    _serve(socket_path, workspace, WorkspaceSidecar)


def _main() -> None:
    """Keep the historical package console script for conformance images."""
    main(WorkspaceSidecar)


if __name__ == "__main__":
    _main()


__all__ = ["WorkspaceSidecar", "rpc", "serve"]
