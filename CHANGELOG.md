# Changelog

## Unreleased

- Fork only: an `etsi_xml` trust source now takes only certificates listed under a service's `ServiceDigitalIdentity`. Before, every certificate in the file became an anchor, including the list's own signer and past service versions. The list's signature is still not verified ([#76](https://github.com/pipe23-org/zk-age-verifier/issues/76)).
- Fork only: `test_real_document_signer_resolves_through_real_anchor` pins the clock, because the real document-signer test certificate expired on 2026-09-24. Added a fork notice to the README.
- An `untrusted-issuer` failure now logs an `untrusted_issuer` warning naming the presented certificate (subject, issuer, validity, SHA-256 fingerprint) and why it was refused. The verdict returned to the client is unchanged ([#76](https://github.com/pipe23-org/zk-age-verifier/issues/76)).
- Configuration file table and key names are matched case-sensitively; environment variable names are not. Previously the TOML source relied on pydantic-settings' default, which pydantic-settings 2.15 changed to case-insensitive for top-level tables.

## 0.4.0 - 2026-08-08

- Workaround for the malformed IACA and DS certificates, see
  [#35](https://github.com/pipe23-org/zk-age-verifier/issues/35).
- Bumped the demo compose's traefik to v3.7.
- Renamed the `[service]` key `backend` to `pylongfellow.backend`.
- Bumped pylongfellow to 0.5.1 (#47).
- Bumped pylongfellow to 0.5.2; the requirement is now the exact version `==0.5.2`,
  replacing the `>=0.5.1,<0.6` range (#48).
- add version strings to example page.

## 0.3.0 - 2026-08-03

Dependency and documentation release. The release carries the corrected README to the
PyPI project page.

- pylongfellow 0.5: the requirement is now `>=0.5.0,<0.6` and the service and test code
  use the 0.5 API. The service's HTTP surface is unchanged.
- The container image now installs fastapi 0.140.13, up from 0.139.2. The `fastapi`
  requirement is unconstrained, so this bump moves the locked build only
  ([#27](https://github.com/pipe23-org/zk-age-verifier/pull/27)).
- The `Documentation` project URL now points at
  `https://zk-age-verifier.readthedocs.io/en/stable/`, replacing the Read the Docs root, which
  serves the `latest` build of `main`
  ([#29](https://github.com/pipe23-org/zk-age-verifier/pull/29)).

## 0.2.0 - 2026-07-30

- pylongfellow 0.4.0: both verifier backends ship in the default install.
- `[service]` gains `backend` (default `google-cpp`; env
  `ZK_AGE_VERIFIER_SERVICE__BACKEND`), the pylongfellow backend the service verifies
  with. Unknown or unbuilt names fail startup. Per-backend scope: `docs/backends.md`.
- `ZkDocument` gains `device_name_spaces_bytes: bytes | None`; where `None`, the service
  supplies the empty device-namespace map to the verifier as a stated assumption
  ([pipe23-org/pylongfellow#29](https://github.com/pipe23-org/pylongfellow/issues/29)).
- In-process integration tests run against both verifier backends; the presenter's
  prover stays fixed. A new test verifies the vendored upstream example proof with both
  backends, isrg-rust under the assumed empty map; input provenance in
  `tests/data/README.md`.
- Ported to the pylongfellow 0.3 client API: one `Pylongfellow(backend="google-cpp")`
  binds the backend at startup, `load_circuit` returns a handle, and `prove`/`verify`
  are methods on the client. The module-level `mdoc.prove`/`mdoc.verify` calls and the
  `mdoc.ZkSpec` type are gone; the service imports no backend-specific symbols.
- The circuit ships as package data (`src/zk_age_verifier/circuits/v7-1attr.circuit`
  with a sidecar record) and is loaded at startup, replacing generate-on-first-run.
  The loader checks the blob against the sidecar `byte_sha256` and the sidecar spec
  against the pinned system, version, and attribute count; the backend re-validates the
  circuit hash at load.
- Removed `circuit_cache_dir` from `[service]` config, the `XDG_CACHE_HOME` default, the
  container cache directory and volume, and the Makefile cache-volume machinery. No
  writable cache directory is needed.

## 0.1.2 - 2026-07-24

- `scripts/generate_credentials.py` builds its constructed entries through
  `pylongfellow.mdoc.create_credential` and `create_certificate`, and validates the
  `DeviceAuthentication` encoding against the vendored credential through
  `verify_device_authentication`; the local COSE, certificate, and mdoc-assembly helpers
  moved to pylongfellow 0.2.3 and are deleted here
  ([#20](https://github.com/pipe23-org/zk-age-verifier/pull/20)).
- The presenter re-signs each session's transcript through
  `pylongfellow.mdoc.sign_device_authentication`
  ([#20](https://github.com/pipe23-org/zk-age-verifier/pull/20)).
- pylongfellow pin bumped to `>=0.2.3,<0.3`; credential fixtures regenerated
  ([#20](https://github.com/pipe23-org/zk-age-verifier/pull/20)).

## 0.1.1 - 2026-07-23

- The OpenAPI descriptions of `createSession` and `submitPresentation` now state the
  service contract only; wording that described the consumer's page was removed from the
  served schema, docstrings, README, and docs
  ([#18](https://github.com/pipe23-org/zk-age-verifier/pull/18)).
- A tagged release now creates a GitHub Release with this file's section as notes, after
  the published package is verified to install and import
  ([#19](https://github.com/pipe23-org/zk-age-verifier/pull/19)).

## 0.1.0 - 2026-07-23

Initial release. zk-age-verifier verifies Longfellow zero-knowledge proofs over mdoc,
presented through the W3C Digital Credentials API, and runs as a sidecar HTTP service
beside a consumer backend.

- **Fail-closed verification** — malformed presentation input produces a failed verdict,
  not an HTTP 500 ([#14](https://github.com/pipe23-org/zk-age-verifier/pull/14)).
- **Trust-source schemes** — ETSI trusted-list sources accept only https URLs or file
  paths ([#15](https://github.com/pipe23-org/zk-age-verifier/pull/15)).
- **Document Signer key usage** — the presented Document Signer certificate must carry
  keyUsage with digitalSignature; acceptance through a configured anchor requires
  keyCertSign on the anchor certificate
  ([#16](https://github.com/pipe23-org/zk-age-verifier/pull/16)).
- **Trust-source scope** — the README and configuration reference document that all
  configured trust sources merge into one anchor set, and that the source list must
  contain only anchors intended to vouch for age credentials
  ([#16](https://github.com/pipe23-org/zk-age-verifier/pull/16)).
