# Troubleshooting

## A check ended in `untrusted-issuer`

The client only ever sees the bare reason `untrusted-issuer`. The server log says why.
Look for the `untrusted_issuer` warning:

```
untrusted_issuer  reason='no anchor accepts the presented certificate'
  subject='C=EU,...,CN=Some Document Signer'  issuer='C=EU,...,CN=Some Issuer CA'
  sha256='…'  not_before='…'  not_after='…'  der_base64='MIIB…'
```

- `subject` and `issuer` say who signed the credential and under which authority.
- `sha256` is the fingerprint to compare with your anchors.
- `der_base64` is the whole presented certificate. It is public information, shared by every
  credential that signer issued.

### Explain it offline

Paste the `der_base64` value into a text file (one line is fine) and run:

```
zk-age-verifier --config config.toml --check-cert presented.txt
```

`--check-cert` reads PEM, DER, or base64-DER text. In Docker the file has to be somewhere the
container can see, for example under the mounted config directory. It prints each check and
ends with `verdict: TRUSTED` or `verdict: NOT TRUSTED`, and never starts the service.

### Reading the result

| Line says | Meaning | What to do |
| --- | --- | --- |
| `valid … : NO, not valid today` | The certificate is expired or not yet valid. | The issuer must reissue it. Check the server clock first. |
| `keyUsage digitalSignature: NO (missing or not asserted)` | The certificate does not assert `digitalSignature`. | Usually the issuer's certificate is wrong. Nothing to change in the service. |
| `public key is P-256: NO` | The credential is signed with another curve. | The verifier only supports P-256 document-signer keys. |
| `is itself a configured anchor: no`, and every anchor line says `did not sign it` | None of your anchors issued this certificate. | You are missing the issuer's CA. Add the right certificate to a `pem` source, after checking it comes from the issuer you mean to trust. |
| an anchor `signed this certificate; keyCertSign NOT asserted` | The right CA is configured but does not assert `keyCertSign`, so it is not accepted as a CA. | The CA certificate is wrong or is being used as a leaf anchor. |

Adding an anchor trusts everything that anchor signs. Only add a certificate you have checked
against the issuer's own published source.

## Other log lines

| Log line | Meaning |
| --- | --- |
| `key_usage_der_fallback` | A certificate has malformed extensions that the normal parser rejects, so a fallback reader was used. Known issue with the Age Verification reference certificates ([#35](https://github.com/pipe23-org/zk-age-verifier/issues/35)). Harmless. |
| `key_usage_unreadable` | Even the fallback reader could not read the key usage, so the certificate is treated as not asserting it. |
| `etsi_xml_not_pinned` | An ETSI trusted list was loaded without `etsi_xml_sha256`. The line shows the digest; check the file, then set that digest to pin it. |
| `etsi_service_skipped` | A service in the trusted list was ignored because its status is not `granted` or `recognisedatnationallevel`. |
| `CryptographyDeprecationWarning … serial number which wasn't positive` | A configured anchor has serial number 0 or negative (the Multipaz TEST IACA does). It loads today; a future `cryptography` release will refuse it. The test suite has a test that fails when that happens. |

## The service will not start

- *"not the pinned"* — the ETSI list's SHA-256 differs from `etsi_xml_sha256`. Re-review the
  file, then update the pin.
- *"cannot read certificate file"* / *"does not contain a PEM, DER or base64-DER certificate"*
  (from `--check-cert`) — wrong path or format. Inside Docker, the path is the one in the
  container.
- *zero anchors* — a trust source resolved to no certificates. Check the paths and the
  `ServiceStatus` of the list entries.
