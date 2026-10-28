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
- `credential` (default `eu-av`) — the kind of credential this service accepts: `eu-av` for the
  EU age-verification credential (doctype `eu.europa.ec.av.1`), or `iso-mdl` for an ISO/IEC
  18013-5 mobile driving licence (doctype `org.iso.18013.5.1.mDL`, claims in the
  `org.iso.18013.5.1` namespace). One service accepts one kind; run a second service for the
  other. The check is still exactly `age_over_18`. A licence is only accepted if its issuer's
  certificate chains to a `[trust]` anchor you configured, so an `iso-mdl` service needs the
  licence issuer's root, not the EU one.

## [trust]

`[[trust.sources]]` entries form a non-empty list. Each entry sets exactly one of:

- `pem` — a PEM file, or a directory whose `*.pem` files are all loaded.
- `etsi_xml` — an ETSI trusted list, path or URL; the certificates listed in each service's
  `ServiceDigitalIdentity` become anchors, but only for services whose status is `granted`
  or `recognisedatnationallevel` (others are skipped, with a log line). The signer's
  certificate and the certificates of past service versions are not anchors. Protect the
  list in either or both of two ways:
  - `etsi_xml_signer` — a PEM file holding the certificate that signs the list. The list's
    XML signature must then verify against exactly that certificate, and the anchors are read
    only from the signed content. A missing, wrong or broken signature stops startup.
  - `etsi_xml_sha256` — the SHA-256 of the file you reviewed, in hex. Any other content is
    refused.

  With neither, the service logs an `etsi_xml_not_pinned` warning that shows the digest.
  The signer check does not look at the list's `NextUpdate` date, so an old but genuinely
  signed list is still accepted; pin the digest as well if that matters to you.

Every listed anchor is authorized to vouch for age credentials. Sources that resolve to
zero anchors fail startup.

### Checking why a certificate is not trusted

A failed check says `untrusted-issuer` and the service logs which certificate it refused,
including its subject, issuer, fingerprint and the whole certificate as `der_base64`. To test a
certificate without a phone or a running service, save it as a PEM, DER or base64-DER text
file (paste the `der_base64` value from the log into a file) and ask the configuration
directly:

```
zk-age-verifier --config config.toml --check-cert document-signer.pem
```

It prints the certificate's name, issuer and SHA-256 fingerprint, then each check in turn
(validity today, `keyUsage` `digitalSignature`, a P-256 key, whether it is a configured anchor
or which anchor signed it and whether that anchor may sign certificates) and ends with
`verdict: TRUSTED` or `verdict: NOT TRUSTED`. It never starts the service. The exit status is
0 if trusted, 1 if not, and 2 if the configuration or the file could not be read.

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
