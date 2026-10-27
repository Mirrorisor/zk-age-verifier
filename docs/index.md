# zk-age-verifier

Verifier service for EU age-verification proofs: Longfellow ZK over mdoc, presented through
the W3C Digital Credentials API.

The consumer's backend opens a session (`POST /sessions`) and receives a `transports.dc`
offer. The wallet's response is submitted (`POST /sessions/{session_id}/presentation`) and 
the verdict is returned.

The [Configuration](configuration.md) page documents the `[service]` and `[trust]` keys and
the environment-variable overrides. The [HTTP API](api.md) page documents the API. If a check
ends in `untrusted-issuer`, see [Troubleshooting](troubleshooting.md).
