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
- `log_level` (default `info`) — the threshold below which log events are dropped, one of
  `debug`, `info`, `warning`, `error`. Debug output includes the subject, issuer, validity
  dates, and SHA-256 fingerprint of the certificate a refused presentation supplied.

## [trust]

`[[trust.sources]]` entries form a non-empty list. Each entry sets exactly one of:

- `pem` — a PEM file, or a directory whose `*.pem` files are all loaded.
- `etsi_xml` — an ETSI trusted list, path or URL. The certificates in the
  `ServiceDigitalIdentity` of each active age-attestation service become anchors. An
  age-attestation service has the service type
  `http://trust.tech.ec.europa.eu/lists/age-verification/service-type/paa` (EU Age
  Verification Trusted List). Active statuses are `granted` and `recognisedatnationallevel`
  (ETSI TS 119 612) and `recognized` (EU Age Verification Trusted List). A service of any
  other type or status is skipped and logged as `etsi_service_skipped` with its service type
  and status. A list whose `NextUpdate` has passed is refused; one without a `NextUpdate`
  loads with an `etsi_xml_no_next_update` warning.
  - `etsi_xml_signers` (optional) — a PEM file, or a directory of `*.pem` files, holding
    the certificates authorised to sign the list. The list's XML signature must then verify
    against one of them, and anchors are read only from the signed content; otherwise
    startup stops. For the EU Age Verification Trusted List these are the EU/EEA list of
    trusted lists (LOTL) signing certificates, which the list also names in its
    `PointersToOtherTSL`. Get them from a source you trust rather than from the list itself.
    The acceptance (test) list is signed by a certificate outside that set, so a deployment
    that tests against it names that certificate. Without `etsi_xml_signers` the signature
    is not checked and `etsi_xml_signature_not_checked` is logged.

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
Registry names: `google-cpp` (the C++ implementation in longfellow-zk/longfellow-zk),
`isrg-rust` (abetterinternet/zk-cred-longfellow), `lf-rust` (the Rust implementation in
longfellow-zk/longfellow-zk). All three ship in the default pylongfellow install. An unknown
or unbuilt name fails startup.

Open issues on [pylongfellow](https://github.com/pipe23-org/pylongfellow) detail any known problems
with these backends.
