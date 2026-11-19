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
  `org.iso.18013.5.1` namespace). Two passport-based kinds are also known: `photo-id` (ISO/IEC
  23220 Photo ID) and `google-id-pass` (Google Wallet ID pass); see
  [Compatibility](compatibility.md). To accept several, give a list: `credential = ["eu-av",
  "iso-mdl", "photo-id"]`. The request then asks for any one of them (an ISO/IEC 18013-5 second-edition
  use case with one document set per kind), and the holder chooses which document to show
  from those they hold. The check is still
  exactly `age_over_18`. A licence is only accepted if its issuer's
  certificate chains to a `[trust]` anchor you configured, so an `iso-mdl` service needs the
  licence issuer's root, not the EU one.
- `log_level` (default `info`) — the threshold below which log events are dropped, one of
  `debug`, `info`, `warning`, `error`. Debug output includes the subject, issuer, validity
  dates, and SHA-256 fingerprint of the certificate a refused presentation supplied, and the whole
  certificate as `der_base64` (fork), for `--check-cert`.

## [trust]

`[[trust.sources]]` entries form a non-empty list. Each entry sets exactly one of `pem`, `etsi_xml`, `etsi_lotl`
or `vical`:

- `pem` — a PEM file, or a directory whose `*.pem` files are all loaded.
- `etsi_xml` — an ETSI trusted list, path or URL; the certificates listed in each service's
  `ServiceDigitalIdentity` become anchors, but only for services whose status is `granted`
  or `recognisedatnationallevel` (ETSI TS 119 612) or `recognized` (EU Age Verification
  Trusted List); others are skipped, with a log line. The signer's
  certificate and the certificates of past service versions are not anchors. Protect the
  list in either or both of two ways:
  - `etsi_xml_signer` — a PEM file holding the certificate that signs the list. The list's
    XML signature must then verify against exactly that certificate, and the anchors are read
    only from the signed content. A missing, wrong or broken signature stops startup.
  - `etsi_xml_sha256` — the SHA-256 of the file you reviewed, in hex. Any other content is
    refused.

  With neither, the service logs an `etsi_xml_not_pinned` warning that shows the digest.
  Whatever else you set, a list whose own `NextUpdate` time has passed is refused; a list
  with no usable `NextUpdate` loads with an `etsi_xml_no_next_update` warning.
- `etsi_lotl` — a signed ETSI list of trusted lists (path or URL), such as the EU's
  `https://ec.europa.eu/tools/lotl/eu-lotl.xml`. It needs two more keys:
  - `etsi_lotl_signer` — a PEM file holding the certificate that signs the list of trusted
    lists. Get it from a source you trust (the EU publishes the signing certificates in the
    Official Journal); the service logs the certificate's SHA-256 fingerprint when it
    verifies, so you can compare. The list's XML signature must verify against it.
  - `etsi_lotl_territories` — the two-letter country codes whose national lists to load,
    for example `["EE", "LV"]`. Only these are fetched.

  Each chosen national list is fetched (over https only) from the address in the signed
  pointer, and its signature must verify against one of the certificates in that same
  pointer. Its services become anchors under the same status rules as `etsi_xml`. If any
  chosen list is missing, unsigned, wrongly signed or past its `NextUpdate`, startup stops;
  nothing is loaded in part.
- `vical` — a VICAL (path or URL): the signed CBOR list of issuer root certificates (IACAs)
  that mobile driving licence programmes publish (ISO/IEC 18013-5 Annex C), such as AAMVA's
  for US states or, when available, the one Austroads is preparing for Australia. It needs:
  - `vical_signer` — a PEM file holding the VICAL signer's certificate, or the certificate
    that issued it (the provider's VICAL root). The list's COSE signature must come from the
    certificate in its `x5chain` header, and that certificate must be this one or be issued
    directly by it (then marked with the VICAL signer extended key usage `1.0.18013.5.1.8`),
    and be valid today. ES256, ES384 and ES512 are accepted, each only with
    its own curve (P-256, P-384, P-521).
  - `vical_doc_types` — the document types whose issuers to trust, for example
    `["org.iso.18013.5.1.mDL"]`. An issuer listed only for other types is not loaded.
  - `vical_countries` (optional) — two-letter `issuingCountry` codes, for example `["AU"]`.

  A VICAL past its `nextUpdate` or `notAfter` is refused, and so is one that lists no issuer
  for the chosen types and countries; one without a `nextUpdate` loads with a
  `vical_no_next_update` warning. An issuer entry whose certificate cannot be read is
  skipped with a `vical_bad_certificate` warning, and one whose certificate is not valid
  today with `vical_certificate_not_valid_now`. Loaded issuers vouch for every credential
  kind the service accepts, so give a VICAL source only the document types you mean to
  accept.

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
Registry names: `google-cpp` (the C++ implementation in longfellow-zk/longfellow-zk),
`isrg-rust` (abetterinternet/zk-cred-longfellow), `lf-rust` (the Rust implementation in
longfellow-zk/longfellow-zk). All three ship in the default pylongfellow install. An unknown
or unbuilt name fails startup.

Open issues on [pylongfellow](https://github.com/pipe23-org/pylongfellow) detail any known problems
with these backends.
