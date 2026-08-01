"""Persistent /bin/sh sessions inside containers, accessed via HTTP."""

from __future__ import annotations

import logging
import os
import pty
import select
import shlex
import subprocess
import threading
import time
import uuid

from fastapi import APIRouter, HTTPException, Query

from kcs.legacy_guard import assert_legacy_target_allowed
from kcs.server.models import ExecRequest
from kcs.server.services import get_service

log = logging.getLogger("kcs")
router = APIRouter(tags=["Shell Sessions"])

# ── Session storage ─────────────────────────────────────────────────────────

_sessions: dict[str, ShellSession] = {}
_sessions_lock = threading.Lock()
_sessions_at: dict[str, float] = {}
_SESSION_TTL = 1800  # 30 min idle timeout


def _purge_stale_sessions() -> None:
    now = time.time()
    with _sessions_lock:
        stale = [sid for sid, ts in list(_sessions_at.items()) if now - ts > _SESSION_TTL]
        for sid in stale:
            sess = _sessions.pop(sid, None)
            if sess:
                try:
                    sess.close()
                except Exception:
                    pass
            _sessions_at.pop(sid, None)


# ── ShellSession ────────────────────────────────────────────────────────────


class ShellSession:
    """A persistent /bin/sh process inside a container, accessed via HTTP."""

    def __init__(self, pod_name: str, namespace: str, kubeconfig: str | None):
        assert_legacy_target_allowed({"namespace": namespace})
        self.pod_name = pod_name
        self.master_fd, slave_fd = pty.openpty()
        cmd = ["kubectl", "exec", "-it", pod_name, "-n", namespace, "--", "/bin/sh"]
        env = {**os.environ}
        if kubeconfig:
            env["KUBECONFIG"] = kubeconfig
        self.proc = subprocess.Popen(
            cmd,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            close_fds=True,
        )
        os.close(slave_fd)
        self._lock = threading.Lock()
        self._drain_output()
        self._setup_clean_env()

    def _setup_clean_env(self) -> None:
        with self._lock:
            os.write(self.master_fd, b"export PS1=''\n")
            time.sleep(0.1)
            os.write(self.master_fd, b"stty -echo 2>/dev/null; set +o histexpand 2>/dev/null\n")
            time.sleep(0.1)
            self._drain_output()

    def exec(self, command: str, timeout: float = 10) -> dict:
        with self._lock:
            if self.proc.poll() is not None:
                return {"stdout": "", "exit_code": -1}

            marker = f"__KCS_EXIT_{uuid.uuid4().hex[:8]}__"
            full_cmd = f"( {command} )\necho {marker}$?\n"
            os.write(self.master_fd, full_cmd.encode("utf-8"))
            output = self._read_until(marker, timeout)

            exit_code = 0
            if marker in output:
                idx = output.index(marker) + len(marker)
                try:
                    exit_code = int(output[idx : idx + 4].strip())
                except ValueError:
                    pass
                output = output[: output.index(marker)]

            output = self._clean_output(output, command)
            return {"stdout": output, "exit_code": exit_code}

    def _clean_output(self, raw: str, command: str) -> str:
        import re

        cleaned = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", raw)
        cleaned = re.sub(r"\x1b\][0-9;]*[^\x07]*\x07", "", cleaned)
        cleaned = cleaned.replace("\r", "")
        lines = cleaned.split("\n")
        if lines and command.strip() in lines[0]:
            lines = lines[1:]
        while lines and not lines[-1].strip():
            lines.pop()
        return "\n".join(lines)

    def _read_until(self, marker: str, timeout: float) -> str:
        result = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            ready, _, _ = select.select([self.master_fd], [], [], 0.1)
            if ready:
                try:
                    buf = os.read(self.master_fd, 4096)
                except OSError:
                    break
                if not buf:
                    break
                result += buf
                if marker.encode("utf-8") in result:
                    break
            if self.proc.poll() is not None:
                break
        return result.decode("utf-8", errors="replace")

    def _drain_output(self) -> None:
        try:
            ready, _, _ = select.select([self.master_fd], [], [], 0.5)
            if ready:
                os.read(self.master_fd, 4096)
        except Exception:
            pass

    def close(self) -> None:
        try:
            os.write(self.master_fd, b"exit\n")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()
        try:
            os.close(self.master_fd)
        except Exception:
            pass


# ── Routes ──────────────────────────────────────────────────────────────────


@router.post(
    "/api/v1/containers/{name}/shell/sessions", summary="Create a persistent shell session"
)
def shell_session_create(name: str, pod: int | None = Query(default=None)):
    """Open a persistent /bin/sh process inside a container."""
    client = get_service().get_client()
    pod_name = client._get_target_pod(name, pod)
    if not pod_name:
        raise HTTPException(status_code=404, detail="No pod found")

    session = ShellSession(pod_name, client.namespace, client._kubeconfig)
    sid = uuid.uuid4().hex[:12]

    with _sessions_lock:
        _purge_stale_sessions()
        _sessions[sid] = session
        _sessions_at[sid] = time.time()

    return {"session_id": sid, "pod": pod_name}


@router.post(
    "/api/v1/containers/{name}/shell/sessions/{sid}/exec",
    summary="Run a command in a shell session",
)
def shell_session_exec(name: str, sid: str, req: ExecRequest):
    """Execute a command inside an existing shell session."""
    with _sessions_lock:
        session = _sessions.get(sid)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    try:
        with _sessions_lock:
            _sessions_at[sid] = time.time()
        result = session.exec(shlex.join(req.command))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
    return result


@router.delete("/api/v1/containers/{name}/shell/sessions/{sid}", summary="Close a shell session")
def shell_session_close(name: str, sid: str):
    """Terminate the shell process and release the session."""
    with _sessions_lock:
        session = _sessions.pop(sid, None)
        _sessions_at.pop(sid, None)
    if session:
        session.close()
    return {"message": "Session closed"}


@router.get("/api/v1/containers/{name}/shell/sessions", summary="List active shell sessions")
def shell_session_list(name: str):
    """Return all active shell session IDs for a container."""
    with _sessions_lock:
        return {"sessions": list(_sessions.keys())}
