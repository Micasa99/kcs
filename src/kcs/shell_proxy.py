"""Shell proxy server — bridges Claude Code's CLAUDE_CODE_SHELL to a container.

Start:  kcs shell-proxy --container web
Then:   CLAUDE_CODE_SHELL=~/.local/bin/kcs-bash-web ccb

The proxy auto-creates the wrapper script on startup.  Each container gets its
own wrapper + port so multiple proxies can run side-by-side.
"""

from __future__ import annotations

import json
import logging
import os
import re
import select
import socket
import subprocess
import sys
import threading
import time
import uuid

from kcs.legacy_guard import (
    V2_EXCLUSION_SELECTOR,
    LegacyTargetForbiddenError,
    assert_legacy_target_allowed,
)

log = logging.getLogger("kcs.shell_proxy")


# ══════════════════════════════════════════════════════════════════════════════
# ShellSession — persistent /bin/sh via kubectl exec PTY
# ══════════════════════════════════════════════════════════════════════════════


class ShellSession:
    """A persistent /bin/sh process inside a container, accessed via PTY."""

    def __init__(self, pod_name: str, namespace: str, kubeconfig: str | None):
        import pty

        assert_legacy_target_allowed({"namespace": namespace})
        self.pod_name = pod_name
        self.master_fd, slave_fd = pty.openpty()
        cmd = [
            "kubectl",
            "exec",
            "-it",
            pod_name,
            "-n",
            namespace,
            "--",
            "/bin/sh",
        ]
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
            os.write(
                self.master_fd,
                b"stty -echo 2>/dev/null; set +o histexpand 2>/dev/null\n",
            )
            time.sleep(0.1)
            self._drain_output()

    def exec(self, command: str, timeout: float = 120) -> dict:
        with self._lock:
            if self.proc.poll() is not None:
                return {"stdout": "", "stderr": "", "exit_code": -1}

            marker = f"__KCS_EXIT_{uuid.uuid4().hex[:8]}__"
            # wrap in subshell so 'exit' only exits the subshell, not the pty
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
            return {"stdout": output, "stderr": "", "exit_code": exit_code}

    @staticmethod
    def _clean_output(raw: str, command: str) -> str:
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


# ══════════════════════════════════════════════════════════════════════════════
# TCP server
# ══════════════════════════════════════════════════════════════════════════════


def _get_target_pod(
    container_name: str,
    kubeconfig: str | None = None,
    namespace: str | None = None,
) -> str | None:
    """Find the first running pod for a container using kubectl.

    Waits up to 30 s for a pod to appear and enter Running phase.
    """
    env = {**os.environ}
    if kubeconfig:
        env["KUBECONFIG"] = kubeconfig
    namespace = namespace or _get_namespace(kubeconfig)
    assert_legacy_target_allowed({"namespace": namespace})
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            result = subprocess.run(
                [
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    namespace,
                    "-l",
                    f"app={container_name},{V2_EXCLUSION_SELECTOR}",
                    "-o",
                    "json",
                    "--field-selector=status.phase=Running",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            payload = json.loads(result.stdout or "{}")
            for pod in payload.get("items", []):
                metadata = pod.get("metadata", {})
                assert_legacy_target_allowed(metadata)
                name = metadata.get("name")
                if isinstance(name, str) and name:
                    return name
        except LegacyTargetForbiddenError:
            raise
        except Exception:
            pass
        time.sleep(1)
    return None


def _get_namespace(kubeconfig: str | None = None) -> str:
    """Get the current kubectl namespace."""
    env = {**os.environ}
    if kubeconfig:
        env["KUBECONFIG"] = kubeconfig
    try:
        result = subprocess.run(
            ["kubectl", "config", "view", "--minify", "-o", "jsonpath={..namespace}"],
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
        )
        ns = result.stdout.strip()
        return ns if ns else "default"
    except Exception:
        return "default"


# ══════════════════════════════════════════════════════════════════════════════
# Wrapper script (auto-created on startup)
# ══════════════════════════════════════════════════════════════════════════════

_WRAPPER_TEMPLATE = r"""#!/bin/bash
# kcs-bash-__CONTAINER__ — forwards Claude Code bash commands to kcs container.
# Auto-generated, socket __SOCK__, container __CONTAINER__.

case "$(basename "$0")" in
bash|kcs-bash-*)
    ;;
*)
    echo "kcs-bash-__CONTAINER__: this script must be invoked as 'bash'" \
      "or via a path containing 'bash'" >&2
    exit 1
    ;;
esac

cmd="${@: -1}"

exec python3 - "$@" << 'PYEOF'
import json, os, re, socket, subprocess, sys

_SOCK = "__SOCK__"


def _rpc(command):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(130)
    sock.connect(_SOCK)
    sock.sendall((command + "\n").encode("utf-8"))
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    sock.close()
    r = json.loads(data.decode("utf-8"))
    return r.get("stdout", ""), r.get("stderr", ""), r.get("exit_code", 0)


def main():
    args = sys.argv[1:]
    cmd = None
    i = 0
    while i < len(args):
        if args[i] == "-c" and i + 1 < len(args):
            i += 1
            if args[i] == "-l" and i + 1 < len(args):
                i += 1
            cmd = args[i]
            break
        i += 1
    if cmd is None:
        cmd = "exec /bin/sh"

    # snapshot generation must run locally to capture host environment
    if "SNAPSHOT_FILE" in cmd:
        result = subprocess.run(["/bin/bash", "-c", cmd])
        sys.exit(result.returncode)

    # Try to extract the actual command from eval wrappers
    m = re.search(r"\beval\s+(['\"])(.*?)\1\s*(?:<\s*/dev/null)?", cmd)
    actual = m.group(2) if m else cmd
    if m:
        actual = actual.replace("'\\''", "'")
    cwd_m = re.search(r"pwd\s+-P\s*>\|\s*(\S+)", cmd)
    cwd_file = cwd_m.group(1) if cwd_m else None
    try:
        stdout, stderr, exit_code = _rpc(actual)
        sys.stdout.write(stdout)
        sys.stderr.write(stderr)
        if cwd_file:
            pwd_out, _, pwd_rc = _rpc("pwd -P")
            if pwd_rc == 0:
                os.makedirs(os.path.dirname(cwd_file), exist_ok=True)
                with open(cwd_file, "w") as f:
                    f.write(pwd_out.strip() + "\n")
        sys.exit(exit_code)
    except Exception as e:
        sys.stderr.write("kcs-bash-__CONTAINER__: " + str(e) + "\n")
        sys.exit(1)


main()
PYEOF"""


def _wrapper_path(container: str, session: str = "") -> str:
    """Default path: ~/.local/bin/kcs-bash-<container>[-<session>]."""
    base = os.path.expanduser("~/.local/bin")
    os.makedirs(base, exist_ok=True)
    name = f"kcs-bash-{container}"
    if session:
        name += f"-{session}"
    return os.path.join(base, name)


def _socket_path(container: str, session: str = "") -> str:
    """Unix domain socket path: ~/.kcs/proxy-<container>[-<session>].sock."""
    base = os.path.expanduser("~/.kcs")
    os.makedirs(base, exist_ok=True)
    name = f"proxy-{container}"
    if session:
        name += f"-{session}"
    return os.path.join(base, f"{name}.sock")


def _ensure_wrapper(container: str, sock_path: str, session: str = "") -> str:
    """Create (or refresh) the self-contained bash wrapper.  Returns its path."""
    bash_path = _wrapper_path(container, session)
    label = f"{container}/{session}" if session else container
    content = _WRAPPER_TEMPLATE.replace("__CONTAINER__", label).replace("__SOCK__", sock_path)
    try:
        with open(bash_path) as f:
            if f.read() == content:
                return bash_path
    except FileNotFoundError:
        pass
    with open(bash_path, "w") as f:
        f.write(content)
    os.chmod(bash_path, 0o755)
    return bash_path


# ══════════════════════════════════════════════════════════════════════════════
# Server entry point
# ══════════════════════════════════════════════════════════════════════════════


def _try_register_with_api(
    container: str,
    sock_path: str,
    session: str,
    api_port: int = 8000,
) -> None:
    """Notify the local kcs API server about this proxy (best-effort)."""
    api_port = int(os.environ.get("KCS_PORT", str(api_port)))
    api_base = os.environ.get("KCS_API", f"http://localhost:{api_port}/api/v1")
    try:
        import requests

        requests.post(
            f"{api_base}/shell-proxy/start",
            json={"container": container, "session": session},
            timeout=2,
        )
    except Exception:
        pass


def _try_unregister_with_api(container: str, session: str, api_port: int = 8000) -> None:
    """Tell the local kcs API server this proxy is shutting down (best-effort)."""
    api_port = int(os.environ.get("KCS_PORT", str(api_port)))
    api_base = os.environ.get("KCS_API", f"http://localhost:{api_port}/api/v1")
    try:
        import requests

        requests.post(
            f"{api_base}/shell-proxy/stop?container={container}&session={session}",
            timeout=2,
        )
    except Exception:
        pass


def run_server(
    container: str,
    host: str = "127.0.0.1",
    port: int = 9876,
    verbose: bool = False,
    session: str = "",
    api_port: int = 8000,
) -> None:
    """Start the shell proxy Unix socket server (blocking — for CLI use).

    Registers with the API server at *api_port* so the dashboard discovers it.
    """
    kubeconfig = os.environ.get("KUBECONFIG") or os.path.expanduser("~/.kcs/k3s.yaml")
    if not os.path.exists(kubeconfig):
        kubeconfig = "/etc/rancher/k3s/k3s.yaml"

    namespace = _get_namespace(kubeconfig)
    assert_legacy_target_allowed({"namespace": namespace})
    pod = _get_target_pod(container, kubeconfig, namespace)
    if not pod:
        print(f"Error: no running pod for container '{container}'", file=sys.stderr)
        sys.exit(1)

    print(f"Opening shell to {container}/{pod} (ns={namespace})...", file=sys.stderr)

    sock_path = _socket_path(container, session)
    session_obj = ShellSession(pod, namespace, kubeconfig)
    wrapper = _ensure_wrapper(container, sock_path, session)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.unlink(sock_path)
    except OSError:
        pass
    try:
        server.bind(sock_path)
    except OSError:
        print(f"Error: cannot bind to {sock_path}", file=sys.stderr)
        sys.exit(1)
    os.chmod(sock_path, 0o600)
    server.listen(5)

    print(f"Shell proxy listening on {sock_path}", file=sys.stderr)
    print(f"Wrapper: {wrapper}", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"  CLAUDE_CODE_SHELL={wrapper} claude", file=sys.stderr)

    # Register with the local API server so the dashboard can discover this proxy
    _try_register_with_api(container, sock_path, session, api_port)

    if verbose:
        print("  [verbose] logging every command to stderr", file=sys.stderr)

    _cmd_count = 0

    def handle(conn: socket.socket) -> None:
        nonlocal _cmd_count
        try:
            conn.settimeout(130)
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
            command = data.decode("utf-8").strip()
            if command:
                _cmd_count += 1
                if verbose:
                    preview = command[:200].replace("\n", "\\n")
                    print(
                        f"\n[{_cmd_count}] CMD: {preview}{'...' if len(command) > 200 else ''}",
                        file=sys.stderr,
                        flush=True,
                    )
                result = session_obj.exec(command, timeout=120)
                if verbose:
                    out_preview = result.get("stdout", "")[:120]
                    print(
                        f"[{_cmd_count}] EXIT={result['exit_code']} OUT={out_preview!r}",
                        file=sys.stderr,
                        flush=True,
                    )
                resp = json.dumps(result) + "\n"
                conn.sendall(resp.encode("utf-8"))
        except Exception as e:
            log.error("handle error: %s", e)
        finally:
            conn.close()

    try:
        while True:
            conn, _addr = server.accept()
            t = threading.Thread(target=handle, args=(conn,), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        print("\nClosing shell session...", file=sys.stderr)
        _try_unregister_with_api(container, session, api_port)
        session_obj.close()
        server.close()
        try:
            os.unlink(sock_path)
        except OSError:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# In-process management
# ══════════════════════════════════════════════════════════════════════════════

_running: dict[tuple, dict] = {}


def start(
    container: str,
    host: str = "127.0.0.1",
    port: int = 9876,
    verbose: bool = False,
    session: str = "",
) -> dict:
    """Start a shell proxy in a background thread.  Returns {sock, wrapper}."""
    key = (container, session)
    if key in _running:
        raise RuntimeError(f"Shell proxy already running for {container}/{session}")

    kubeconfig = os.environ.get("KUBECONFIG") or os.path.expanduser("~/.kcs/k3s.yaml")
    if not os.path.exists(kubeconfig):
        kubeconfig = "/etc/rancher/k3s/k3s.yaml"

    namespace = _get_namespace(kubeconfig)
    assert_legacy_target_allowed({"namespace": namespace})
    pod = _get_target_pod(container, kubeconfig, namespace)
    if not pod:
        raise RuntimeError(f"No running pod for container '{container}'")

    sock_path = _socket_path(container, session)
    wrapper = _ensure_wrapper(container, sock_path, session)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.unlink(sock_path)
    except OSError:
        pass
    try:
        server.bind(sock_path)
    except OSError:
        raise RuntimeError(f"Cannot bind to {sock_path}") from None
    os.chmod(sock_path, 0o600)
    server.listen(5)
    shell_sess = ShellSession(pod, namespace, kubeconfig)

    if verbose:
        log.info(
            "[shell-proxy:%s] listening on %s, wrapper=%s",
            container,
            sock_path,
            wrapper,
        )

    def _serve():
        try:
            while True:
                conn, _addr = server.accept()
                threading.Thread(
                    target=_handle_conn,
                    args=(shell_sess, conn),
                    daemon=True,
                ).start()
        except OSError:
            pass  # server closed by stop()
        finally:
            shell_sess.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()

    # Wait until the socket is accepting connections
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(sock_path)
            s.close()
            break
        except (OSError, ConnectionRefusedError):
            time.sleep(0.2)

    _running[key] = {
        "container": container,
        "thread": t,
        "server": server,
        "session": session,
        "sock": sock_path,
    }
    return {"sock": sock_path, "wrapper": wrapper, "container": container}


def stop(container: str, session: str = "") -> None:
    """Stop a background shell proxy."""
    key = (container, session)
    entry = _running.pop(key, None)
    if entry is None:
        raise RuntimeError(f"No shell proxy for {container}/{session}")
    server = entry.get("server")
    thread = entry.get("thread")
    if server:
        server.close()
    if thread:
        thread.join(timeout=5)
    sock_path = entry.get("sock")
    if sock_path:
        # Give it a moment, then clean up the socket file
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(0.2)
                s.connect(sock_path)
                s.close()
            except (OSError, ConnectionRefusedError):
                break
            time.sleep(0.5)
        try:
            os.unlink(sock_path)
        except OSError:
            pass


def list_running() -> list[dict]:
    """Return info about all running shell proxies."""
    return [
        {
            "container": e["container"],
            "session": e.get("session", ""),
            "sock": e["sock"],
            "wrapper": _wrapper_path(e["container"], e.get("session", "")),
        }
        for _key, e in _running.items()
    ]


def _handle_conn(session: ShellSession, conn: socket.socket) -> None:
    """Handle one Unix socket client connection."""
    try:
        conn.settimeout(130)
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
        command = data.decode("utf-8").strip()
        if command:
            result = session.exec(command, timeout=120)
            resp = json.dumps(result) + "\n"
            conn.sendall(resp.encode("utf-8"))
    except Exception as exc:
        log.debug("shell-proxy handle error: %s", exc)
    finally:
        conn.close()
