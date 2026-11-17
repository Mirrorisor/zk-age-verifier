# Test data

Bytes the tests read but did not produce.

- `upstream-verifier-service-request.json` — the example request body for google/longfellow-zk's
  reference verifier service. A JSON object with two base64 fields: `Transcript` (an
  OpenID4VP DC-API handover) and `ZKDeviceResponseCBOR` (a CBOR DeviceResponse carrying one
  `zkDocuments` entry). The ZK document is an `org.iso.18013.5.1.mDL` proof at circuit v6; its
  `zkSystemId` is a bare circuit hash, and its `documentData` has no `deviceSigned` key.
  Source: google/longfellow-zk `reference/verifier-service/server/examples/post1.json` at
  `fe83ec6c4efa5f98bc2439c8b06e5eccd153aca0` — pylongfellow's pinned submodule SHA, the SHA of
  record for all longfellow-zk-derived material here (byte-identical at upstream `90bb3c9`,
  the clone HEAD it was physically copied from). Captured 2026-07-14. Copied verbatim.
  google/longfellow-zk is Apache-2.0, the same licence as this repository.
- `v6-1attr.circuit`, `v6-1attr.json` — the circuit the request's proof was generated
  against, with its sidecar record. Copied verbatim from pipe23-org/pylongfellow
  `tests/differential/circuits/` at `5b3efdf98d7ce362a6e5862e48cb5bef002c6616` on
  2026-07-30; the sidecar's `origin` records the google/longfellow-zk artifact it was
  exported from.
- `mdl-age-over-18-presentation.json` — the request's verify input set as recorded in
  pylongfellow's differential corpus: transcript, issuer public key, timestamp, and
  requested attributes. Copied verbatim from pipe23-org/pylongfellow
  `tests/differential/presentations/mdl-age-over-18/presentation.json` at the same
  commit and date. Its transcript equals `upstream-verifier-service-request.json`'s
  `Transcript` field byte-for-byte; `tests/integration/test_mdl_specimen.py` asserts
  the equality.
- `av-issuer-ca-01.pem` — the Commission's Age Verification test IACA, "Age Verification
  Issuer CA 01": self-signed, `CA:TRUE`, keyUsage `keyCertSign` and `cRLSign`, valid to
  2034-09-27. Its non-critical `issuerAltName` (2.5.29.18) does not decode as `GeneralNames`:
  the extension value carries a second copy of the whole extension, whose inner URI is tagged
  `[2] dNSName` rather than `[6] uniformResourceIdentifier`. `cryptography` decodes every
  extension whose OID it recognises, so reading `Certificate.extensions` on this file raises
  `ValueError`. Source: eu-digital-identity-wallet/av-srv-web-issuing-avw-py
  `api_docs/test_tokens/IACA-token/AgeVerificationIssuer.IACA.01.EU.pem` (Apache-2.0).
  Captured 2026-07-08. Copied verbatim; byte-identical to
  `examples/site-dc-mdoc/anchors/eu-av-test.pem`.
- `av-document-signer-001.pem` — the document signer under that CA, "Age Verification DS -
  001": keyUsage `digitalSignature`, valid to 2026-09-24, and its signature verifies against
  `av-issuer-ca-01.pem`. Its `issuerAltName` value is byte-identical to the CA's, so reading
  `Certificate.extensions` raises the same `ValueError`. Implementations produce that by
  copying the issuer certificate's extension verbatim; multipaz does so in
  `multipaz-server/.../ServerIdentity.kt`, citing ISO 18013-5 table B.3. Source:
  eu-digital-identity-wallet/av-dc-api-backend
  `environment/trust-anchors/age-verification-testing-issuer.pem` (Apache-2.0) at clone HEAD
  `24180068`. Captured 2026-08-04. Copied verbatim.
- `av-tl-production-2026-11-15.xml` — the EU Age Verification Trusted List, an ETSI TS 119 612
  trusted list. Source: https://trust.tech.ec.europa.eu/lists/age-verification/av-tl.xml, the
  URL the eIDAS Dashboard page
  https://eidas.ec.europa.eu/efda/trust-services/browse/av-tl gives as the list's publication
  point. Sequence number 5, issued 2026-11-05. It lists one service, with status
  `recognized`. The file holds eight `X509Certificate` elements: one under that service's
  `ServiceDigitalIdentity`, six under `PointersToOtherTSL`, and one in the list's `Signature`.
  Captured 2026-11-15. Copied verbatim. SHA-256
  `d8cd20567a029c0fbc6b05e8f3a90fc3e6a172bd99869755095bbc82d0a81272`. © European Union. The
  Commission's legal notice (https://commission.europa.eu/legal-notice_en) licenses EU-owned
  content under CC BY 4.0.
- `av-tl-acceptance-2026-11-15.xml` — the test counterpart of that list. Source:
  https://acceptance.trust.tech.ec.europa.eu/lists/age-verification/av-tl.xml. The Age
  Verification project documentation (https://ageverification.dev/AV%20Trusted%20List/)
  describes it as a shared test list with test issuers from several Member States. Sequence
  number 19, issued 2026-10-08. It lists thirteen services: twelve with status `recognized`
  and one with status `deprecated`. The file holds 22 `X509Certificate` elements: thirteen
  under a `ServiceDigitalIdentity`, one under `ServiceHistory`, seven under
  `PointersToOtherTSL`, and one in the list's `Signature`. Captured 2026-11-15. Copied
  verbatim. SHA-256 `50efeb9b05fc68d4fc7e7797851a8a9ac480f2992b22b2a77e2134454019de69`. Same
  copyright and licence as the production list.
