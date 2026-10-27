# Configuration

The verifier reads a TOML file with two tables, `[service]` and `[trust]`, passed with
`--config`. Scalar values can be overridden with environment variables.

## [service]

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

## [trust]

`[[trust.sources]]` entries form a non-empty list. Each entry sets exactly one of:

- `pem` — a PEM file, or a directory whose `*.pem` files are all loaded.
- `etsi_xml` — an ETSI trusted list, path or URL; the certificates listed in each service's
  `ServiceDigitalIdentity` become anchors. The list's own signature is not verified, and so
  neither is its signer, so load only a list you obtained and checked yourself. The
  signer's certificate and the certificates of past service versions are not anchors.

Every listed anchor is authorized to vouch for age credentials. Sources that resolve to
zero anchors fail startup.

## Environment variables

`ZK_AGE_VERIFIER_SECTION__KEY` overrides a scalar value: `ZK_AGE_VERIFIER_` is the prefix
and `__` separates nesting levels, so `ZK_AGE_VERIFIER_SERVICE__PYLONGFELLOW__BACKEND`
overrides `pylongfellow.backend` under `[service]`. 

Lists and tables cannot be set from the environment and must be written in the TOML file.

`LOG_FORMAT=console` switches log output from JSON lines to console rendering. It is read
from the environment only and takes no prefix.

## Proof engine

The `pylongfellow.backend` key selects the proof engine the service verifies with.
Registry names: `google-cpp` (google/longfellow-zk), `isrg-rust`
(abetterinternet/zk-cred-longfellow). Both ship in the default pylongfellow install. An
unknown or unbuilt name fails startup.

Open issues on [pylongfellow](https://github.com/pipe23-org/pylongfellow) detail any known problems
with these backends.
