# Compatibility

What this service can verify today, and the limits of the proof system underneath it.
Everything here was measured on 28 October 2026 with pylongfellow 0.5.2, the `google-cpp`
backend, and the one vendored circuit (`longfellow-libzk-v1`, version 7, one attribute,
circuit id `8d079211…`). Test keys only. A different circuit or library version can change
every number on this page.

## Credential kinds

The credential kind is set by the `credential` key in the `[service]` table (see
[Configuration](configuration.md)).

| `credential` | Document type | Namespace | Notes |
| --- | --- | --- | --- |
| `eu-av` (default) | `eu.europa.ec.av.1` | `eu.europa.ec.av.1` | The EU age-verification credential. |
| `iso-mdl` | `org.iso.18013.5.1.mDL` | `org.iso.18013.5.1` | An ISO/IEC 18013-5 driving licence. |

A service accepts the kinds listed in `credential`; a list such as `["eu-av", "iso-mdl"]`
accepts either. Presenting a kind that is not listed ends in `claim-mismatch` (see
[Troubleshooting](troubleshooting.md)). With a list, one request carries a document
request per kind and a `deviceRequestInfo` use case saying any one of them will do;
Multipaz then lets the holder choose among the documents they hold that match.

## Limits of the pinned circuit

- **One attribute per presentation.** The circuit proves a single claim, for example
  `age_over_18`.
- **Size of the digest list.** The issuer-signed list of digests (the MSO) must fit the
  circuit. Measured: 62 plain data elements fit (2,522 bytes) and 63 do not (2,558 bytes).
  The prover then reports `MDOC_PROVER_TAGGED_MSO_TOO_BIG`. Each element costs about 36
  bytes and the fixed part about 270 bytes, so roughly 60 elements is the working limit. The
  newer Longfellow source documents a smaller limit (35 SHA blocks, 2,213 bytes), so the
  limit differs between circuit versions.
- **Nested element values.** A list or map as an element value makes the prover abort the
  whole process (`valueLength called on non-value type`). Every ISO driving licence carries
  one, `driving_privileges`. A wallet avoids the crash by handing the prover only the
  requested elements; removing the others does not affect the issuer's signature, because
  that signature covers only digests. Reported upstream as
  [pylongfellow#82](https://github.com/pipe23-org/pylongfellow/issues/82).
- **Issuer keys.** Document-signer keys must be P-256.

## What is tested

| Credential shape | Prover and verifier | Where |
| --- | --- | --- |
| EU age credential (age and `nym`) | Verifies | Integration suite |
| Licence with `age_over_18` only | Verifies | Integration suite |
| Licence with 28 plain elements and `driving_privileges`, only the requested element disclosed | Verifies | `tests/integration/test_licence_shape.py` |
| Licence with 63 or more plain elements | Not provable on this circuit | Probe, not in the suite |
| Any credential with a list or map element passed to the prover | Prover aborts | Probe, upstream issue above |

## Wallets

| Wallet | Credential | Result |
| --- | --- | --- |
| Multipaz Test App 0.102.0, Android | Sample driving licence | Fails in the wallet's prover: `MDOC_PROVER_TAGGED_MSO_TOO_BIG` |
| Multipaz Test App 0.102.0, Android | Sample "ZKP-friendly" driving licence | Fails in the wallet's prover: `MDOC_PROVER_GENERAL_FAILURE` (cause not confirmed) |

Both failures happen on the phone, before anything reaches the service, so the service logs
only `session_created`. The log shows the cause under the `org.multipaz.testapp` process
(`adb logcat`, search for `ProofGenerationException`).

## Adding a row

Each credential kind a country issues needs three facts before it can be called supported:
how many data elements it carries, how large its digest list is, and whether any element
value is a list or a map. The first two decide whether it fits the circuit, and the third
decides whether the prover can read it.
