# zk-age-verifier

zk-age-verifier is a verifier service for EU age verification, accepting Longfellow
zero-knowledge proofs over mdoc through the W3C Digital Credentials API. It
runs as a sidecar HTTP service beside a consumer backend. A verified verdict contains one
boolean per requested check. The service has no authentication and is intended to be
reachable only from the consumer backend, not the browser or internet. It is experimental
and unstable.

> **Fork notice.** This is a fork of
> [pipe23-org/zk-age-verifier](https://github.com/pipe23-org/zk-age-verifier)
> (Apache-2.0, copyright Nathan Schepers), kept so that
> [Mirrorisor/age-gate](https://github.com/Mirrorisor/age-gate) can run a version it controls.
> Changes from upstream: an `untrusted_issuer` log line naming the refused certificate
> ([upstream issue #76](https://github.com/pipe23-org/zk-age-verifier/issues/76)), and a
> test that pins the clock so the expired real test certificate no longer fails CI, and an
> `etsi_xml` trust source that takes only active service certificates (not the list's signer)
> and can be pinned to a reviewed file's SHA-256.
> Everything else is upstream's work. Security fixes upstream must be merged here by hand.

[![CI](https://github.com/pipe23-org/zk-age-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/pipe23-org/zk-age-verifier/actions/workflows/ci.yml)
[![Docs](https://app.readthedocs.org/projects/zk-age-verifier/badge/?version=stable)](https://zk-age-verifier.readthedocs.io/en/stable/)
[![PyPI](https://img.shields.io/pypi/v/zk-age-verifier)](https://pypi.org/project/zk-age-verifier/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Installation

```
pip install zk-age-verifier
uv add zk-age-verifier
docker pull ghcr.io/pipe23-org/zk-age-verifier:latest
```

## Usage

The verifier needs a configured origin and at least one trust source.

```toml
[service]
expected_origin = "https://av.example"

[[trust.sources]]
pem = "/etc/zk-age-verifier/anchors"
```

```
python -m zk_age_verifier --config config.toml
```

`POST /sessions` opens a session and returns the `navigator.credentials.get()` argument
under `transports.dc`.

```
$ curl -X POST http://127.0.0.1:8000/sessions \
    -H 'content-type: application/json' -d '{"checks": ["age_over_18"]}'
{"session_id": "tmcdOPmo7oCgd4AmmMFyYg",
 "transports": {"dc": {"digital": {"requests": [{"protocol": "org-iso-mdoc",
   "data": {"deviceRequest": "omd2ZXJzaW9u…", "encryptionInfo": "gmVkY2FwaaJ…"}}]},
   "mediation": "required"}},
 "expires_at": "2026-07-20T09:34:22.089682Z"}
```

The consumer backend relays the wallet response to `POST /sessions/{session_id}/presentation`. A
verified and a failed verification both return 200.

```
POST /sessions/{session_id}/presentation
{"response": "<wallet response, base64url>"}

{"state": "verified", "result": {"age_over_18": true}, "verified_at": "<iso8601>"}
{"state": "failed", "reason": "decrypt-failed"}
```

`GET /health` returns `{"status": "ok", "zk_age_verifier": "0.4.0", "pylongfellow": "0.5.2",
"engine": "google-cpp", "ref": null}` while the process is up.

`GET /debug/transcript/{session_id}` returns the transcript inputs stored for a session — the
origin and the `encryptionInfo` string — with the handover hash and session-transcript bytes
reconstructed from them, hex-encoded. It is a development route, unauthenticated like the rest
of the service.

## Configuration

The verifier reads a TOML file with two tables, `[service]` and `[trust]`, passed with
`--config`. Scalar values can be overridden with environment variables.

### [service]

- `expected_origin` (required) — the origin the service accepts presentations for, a bare
  `scheme://host[:port]`. The origin is hashed into the presentation transcript, so it must
  correspond to the origin that the presentation asserts.
- `pylongfellow.backend` (default `google-cpp`) — the proof engine, see
  [Proof engine](#proof-engine).
- `session_ttl_seconds` (default `300`) — seconds a session stays usable after creation.
- `session_cap` (default `1000`) — maximum live sessions; session creation is rejected at
  the cap. Expired sessions are swept before the cap is enforced.
- `timestamp_skew_seconds` (default `300`) — allowed difference in either direction between
  the proof timestamp and the verifier clock.
- `cors_allowed_origins` (default empty) — origins granted cross-origin access to the API.
  An empty list sends no CORS headers.

### [trust]

`[[trust.sources]]` entries form a non-empty list. Each entry sets exactly one of:

- `pem` — a PEM file, or a directory whose `*.pem` files are all loaded.
- `etsi_xml` — an ETSI trusted list, path or URL; the certificates listed in each service's
  `ServiceDigitalIdentity` become anchors, but only for services whose status is `granted`
  or `recognisedatnationallevel` (others are skipped, with a log line). The list's own
  signature is not verified, and neither is its signer. The signer's certificate and the
  certificates of past service versions are not anchors. Add `etsi_xml_sha256` (the SHA-256
  of the file you reviewed, in hex) to refuse any other content; without it the service logs
  an `etsi_xml_not_pinned` warning that shows the digest to pin.

Every listed anchor is authorized to vouch for age credentials. Sources that resolve to
zero anchors fail startup.

### Environment variables

`ZK_AGE_VERIFIER_SECTION__KEY` overrides a scalar value: `ZK_AGE_VERIFIER_` is the prefix
and `__` separates nesting levels, so `ZK_AGE_VERIFIER_SERVICE__PYLONGFELLOW__BACKEND`
overrides `pylongfellow.backend` under `[service]`.

Lists and tables cannot be set from the environment and must be written in the TOML file.

`LOG_FORMAT=console` switches log output from JSON lines to console rendering. It is read
from the environment only and takes no prefix.

### Proof engine

The `pylongfellow.backend` key selects the proof engine the service verifies with.
Registry names: `google-cpp` (google/longfellow-zk), `isrg-rust`
(abetterinternet/zk-cred-longfellow). Both ship in the default pylongfellow install. An
unknown or unbuilt name fails startup.

Open issues on [pylongfellow](https://github.com/pipe23-org/pylongfellow) detail any known
problems with these backends.

## Documentation

Full documentation: https://zk-age-verifier.readthedocs.io/

## Development

```
uv sync
uv run pytest
uv run ruff check
uv run ruff format --check
uv run mypy
```

`make test-live` runs the suite against a running server over HTTP. `make test-container`
runs it against the built container image.

## Status

You should not rely on this code.

- No rate limiting.
- The session store is in-process.
- The proof is verified against an empty device-namespace map; the ZK response format carries
  no field holding the map the wallet signed.

## License

Apache-2.0.
