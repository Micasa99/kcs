"""kcs CLI — HTTP client for kcs server."""

from __future__ import annotations

import os
import sys

import click
import requests
from rich.console import Console

from kcs import __version__

console = Console()


def _get_api_key() -> str | None:
    """Read API key from env var or cluster config."""
    key = os.environ.get("KCS_API_KEY")
    if key:
        return key
    # Try cluster config
    for path in (
        os.path.expanduser("~/.kcs/cluster.toml"),
        "cluster.toml",
        "local/cluster.toml",
    ):
        if os.path.exists(path):
            try:
                import tomllib
                with open(path, "rb") as f:
                    raw = tomllib.load(f)
                return raw.get("api_key")
            except Exception:
                pass
    return None


def _api(path: str, method: str = "GET", json_data=None, params=None, stream=False):
    ctx = click.get_current_context()
    port = ctx.obj.get("port", 8000)
    url = f"http://localhost:{port}/api/v1{path}"
    headers = {}
    api_key = _get_api_key()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        r = requests.request(
            method, url, json=json_data, params=params, headers=headers,
            stream=stream, timeout=120
        )
    except requests.ConnectionError:
        raise click.ClickException(
            f"Cannot connect to http://localhost:{port} — server running? (kcs serve)"
        ) from None
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", r.text[:200])
        except Exception:
            detail = r.text[:200]
        raise click.ClickException(f"Error {r.status_code}: {detail}")
    if stream:
        return r
    return r.json()


# ══════════════════════════════════════════════════════════════════════════════


@click.group()
@click.version_option(version=__version__, prog_name="kcs")
@click.option(
    "-P", "--port", envvar="KCS_PORT", default=8000, type=int, help="Server port"
)
@click.pass_context
def main(ctx: click.Context, port: int) -> None:
    """kcs — container controller made simpler than k3s."""
    ctx.ensure_object(dict)
    ctx.obj["port"] = port


# ══════════════════════════════════════════════════════════════════════════════
# kcs serve
# ══════════════════════════════════════════════════════════════════════════════


@main.command()
@click.option("--host", envvar="KCS_HOST", default="127.0.0.1")
@click.option("--port", envvar="KCS_PORT", default=8000, type=int)
@click.option(
    "-c",
    "--config",
    required=False,
    default=None,
    help="Cluster config file (.toml/.yaml); required for V1 mode",
)
@click.option("--log-file", default=None)
@click.option("-v", "--verbose", is_flag=True, help="Enable DEBUG-level logging")
@click.option("--no-nfs", is_flag=True, help="Skip NFS setup even when --config is provided")
@click.option("--api-key", envvar="KCS_API_KEY", default=None, help="API authentication key")
def serve(host: str, port: int, config: str | None, log_file: str | None,
          verbose: bool, no_nfs: bool, api_key: str | None) -> None:
    """Start API server + Dashboard."""
    from kcs.server.main import main as server_main

    sys.argv = ["kcs-server", "--host", host, "--port", str(port)]
    if config:
        sys.argv.extend(["--config", config])
    if log_file:
        sys.argv.extend(["--log-file", log_file])
    if verbose:
        sys.argv.append("--verbose")
    if no_nfs:
        sys.argv.append("--no-nfs")
    if api_key:
        sys.argv.extend(["--api-key", api_key])
    server_main()


# ══════════════════════════════════════════════════════════════════════════════
# kcs build
# ══════════════════════════════════════════════════════════════════════════════


@main.command()
@click.argument("path", default=".")
@click.option("-t", "--tag", required=True, help="Image name:tag")
@click.option("--no-push", is_flag=True, help="Build only, do not push")
def build(path: str, tag: str, no_push: bool) -> None:
    """Build Docker image and push to cluster registry.

    kcs build -t myapp:v1 .
    """
    data = _api(
        "/build",
        method="POST",
        json_data={"tag": tag, "path": path, "no_push": no_push},
    )
    console.print(f"[green]✓[/] {data['message']}")


# ══════════════════════════════════════════════════════════════════════════════
# kcs ssh
# ══════════════════════════════════════════════════════════════════════════════


@main.command()
@click.argument("name")
@click.option("--pod", default=None, type=int, help="Pod ordinal")
def ssh(name: str, pod: int | None) -> None:
    """Open a shell inside a container.  kcs ssh web"""
    pods_data = _api(f"/containers/{name}/pods")
    pods = pods_data.get("pods", [])
    if not pods:
        raise click.ClickException(f"No pods found for '{name}'")

    idx = pod if pod is not None else 0
    if idx >= len(pods):
        raise click.ClickException(f"Pod {idx} out of range (0-{len(pods) - 1})")

    kubeconfig = os.environ.get("KUBECONFIG") or os.path.expanduser("~/.kcs/k3s.yaml")
    if not os.path.exists(kubeconfig):
        kubeconfig = "/etc/rancher/k3s/k3s.yaml"

    env = os.environ.copy()
    env["KUBECONFIG"] = kubeconfig
    os.execvpe(
        "kubectl", ["kubectl", "exec", "-it", pods[idx]["name"], "--", "/bin/sh"], env
    )


if __name__ == "__main__":
    main()
