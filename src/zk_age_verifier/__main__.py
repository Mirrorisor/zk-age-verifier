"""Command-line entry point for zk-age-verifier."""

import argparse
import os
import sys
from pathlib import Path

from granian import Granian
from granian.constants import Interfaces

from zk_age_verifier.app import CONFIG_ENV_VAR
from zk_age_verifier.config import ConfigError, load_config
from zk_age_verifier.core.trustlist import explain_certificate, load_anchors, read_certificate

APP_TARGET = "zk_age_verifier.app:app_factory"


def _serve(host: str, port: int) -> None:
    """Boot the ASGI app under granian in factory mode.

    Kept separate from ``main`` so tests can call ``main`` without starting a server.
    """
    Granian(APP_TARGET, address=host, port=port, interface=Interfaces.ASGI, factory=True).serve()


def _check_certificate(config_path: str, cert_path: str) -> int:
    """Report whether the configured trust anchors would accept a certificate.

    Returns:
        The exit status: 0 if it would be trusted, 1 if not, 2 if the check could
        not be made (bad configuration or unreadable certificate).
    """
    try:
        config = load_config(config_path)
        anchors = load_anchors(config.trust.sources)
        cert = read_certificate(cert_path)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    accepted, report = explain_certificate(anchors, cert)
    print("\n".join(report))
    return 0 if accepted else 1


def main(argv: list[str] | None = None) -> None:
    """Validate the configuration, then serve the verifier.

    Args:
        argv: Command-line arguments; defaults to ``sys.argv`` when ``None``.
    """
    parser = argparse.ArgumentParser(
        description="Verifier service for EU age-verification proofs "
        "(Longfellow ZK over mdoc, W3C Digital Credentials API)",
    )
    parser.add_argument("--config", required=True, help="Path to the TOML configuration file.")
    parser.add_argument("--host", default="127.0.0.1", help="Address to bind (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000).")
    parser.add_argument(
        "--check-cert",
        metavar="CERT",
        help="Do not serve. Check a PEM or DER certificate against the configured trust "
        "anchors, print why it is or is not trusted, and exit (0 trusted, 1 not trusted).",
    )
    args = parser.parse_args(argv)

    if args.check_cert is not None:
        raise SystemExit(_check_certificate(args.config, args.check_cert))

    try:
        load_config(args.config)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc

    os.environ[CONFIG_ENV_VAR] = str(Path(args.config).resolve())
    _serve(args.host, args.port)


if __name__ == "__main__":
    main()
