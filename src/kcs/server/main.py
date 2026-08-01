"""CLI entry point for kcs-server."""

from __future__ import annotations

import argparse
import logging
import os
import sys

import uvicorn

log = logging.getLogger("kcs")


def main() -> None:
    parser = argparse.ArgumentParser(description="kcs HTTP API server")
    parser.add_argument(
        "--host",
        default=os.environ.get("KCS_HOST", "127.0.0.1"),
        help="Listen address (env: KCS_HOST, default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("KCS_PORT", 8000)),
        help="Listen port (env: KCS_PORT, default: 8000)",
    )
    parser.add_argument(
        "--config",
        "-c",
        default=None,
        help="Cluster config file (.toml/.yaml), applied on startup",
    )
    parser.add_argument(
        "--log-file",
        default=os.environ.get("KCS_LOG_FILE"),
        help="Log file path (env: KCS_LOG_FILE)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Enable DEBUG-level logging",
    )
    parser.add_argument(
        "--no-nfs",
        action="store_true",
        default=False,
        help="Skip NFS setup even when --config is provided",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("KCS_API_KEY"),
        help="API authentication key (env: KCS_API_KEY)",
    )
    parser.add_argument(
        "--ssl-certfile",
        default=os.environ.get("KCS_SSL_CERT"),
        help="TLS certificate file (env: KCS_SSL_CERT)",
    )
    parser.add_argument(
        "--ssl-keyfile",
        default=os.environ.get("KCS_SSL_KEY"),
        help="TLS private key file (env: KCS_SSL_KEY)",
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.log_file:
        fh = logging.FileHandler(args.log_file)
        fh.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
        )
        logging.getLogger().addHandler(fh)
        log.info("Logging to %s", args.log_file)

    api_mode = os.environ.get("KCS_API_MODE", "v1")
    if api_mode not in {"v1", "v2"}:
        print("Error: KCS_API_MODE must be 'v1' or 'v2'", file=sys.stderr)
        sys.exit(1)

    if api_mode == "v2":
        from kcs.jobs.settings import V2RuntimeSettings

        try:
            V2RuntimeSettings.from_env(os.environ)
        except ValueError as error:
            log.error("  %s", error)
            sys.exit(1)
    else:
        from kcs.server.services import get_service, set_service_config

        if not args.config:
            print("Error: --config <file> is required", file=sys.stderr)
            print("  kcs serve --config cluster.toml", file=sys.stderr)
            sys.exit(1)

        log.info("Loading config: %s", args.config)
        try:
            svc = get_service()
            config = svc.load_config_file(args.config)

            # CLI flag / env var overrides config file
            if args.api_key:
                config.api_key = args.api_key

            if not config.api_key:
                print(
                    "Error: api_key is required. Set it in the config file or via "
                    "--api-key / KCS_API_KEY.",
                    file=sys.stderr,
                )
                sys.exit(1)

            if not config.sudo_password:
                print()
                print("  sudo access is needed on this machine to:")
                print("    • read the k3s server token (/var/lib/rancher/k3s/server/token)")
                print("    • configure the container registry (/etc/rancher/k3s/registries.yaml)")
                print("    • manage NFS (if enabled)")
                print()
                import getpass

                pw = getpass.getpass("  local sudo password: ")
                if pw:
                    config.sudo_password = pw
                print()

            set_service_config(config)
            results = svc.apply_config()
            for result in results:
                log.info("  %s", result)

            if not args.no_nfs:
                log.info("Setting up NFS...")
                try:
                    nfs_result = svc.setup_nfs()
                    log.info("NFS: %s", nfs_result.get("message"))
                    for result in nfs_result.get("results", []):
                        log.info("  %s", result)
                except Exception as error:
                    log.warning("NFS setup skipped: %s", error)

            # Wipe sudo password from memory — no longer needed
            config.sudo_password = None
        except Exception as error:
            log.error("  %s", error)
            sys.exit(1)

        log.info("Checking cluster health...")
        get_service().repair()

    uvicorn_kwargs = {"host": args.host, "port": args.port, "reload": False}
    if args.ssl_certfile and args.ssl_keyfile:
        uvicorn_kwargs["ssl_certfile"] = args.ssl_certfile
        uvicorn_kwargs["ssl_keyfile"] = args.ssl_keyfile
        log.info("TLS enabled: %s", args.ssl_certfile)
    uvicorn.run("kcs.server:app", **uvicorn_kwargs)
