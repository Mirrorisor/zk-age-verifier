"""An ISO driving licence verifies when the service is configured for one."""

from typing import Any, cast

import httpx
import pytest

from tests.integration.presenter import present

# Needs a verifier configured for licences, which the live server is not.
pytestmark = pytest.mark.inprocess_only


def _session(client: httpx.Client) -> dict[str, Any]:
    created = client.post("/sessions", json={"checks": ["age_over_18"]})
    assert created.status_code == 201
    return cast(dict[str, Any], created.json())


def test_licence_presentation_verifies(licence_client: httpx.Client, origin: str) -> None:
    session = _session(licence_client)
    data = present(session["transports"]["dc"], origin, credential="mdl")

    verdict = licence_client.post(f"/sessions/{session['session_id']}/presentation", json=data)
    assert verdict.status_code == 200
    body = verdict.json()
    assert body["state"] == "verified"
    assert body["result"] == {"age_over_18": True}


def test_eu_credential_is_refused_by_a_licence_service(
    licence_client: httpx.Client, origin: str
) -> None:
    session = _session(licence_client)
    data = present(session["transports"]["dc"], origin, credential="eu-av")

    verdict = licence_client.post(f"/sessions/{session['session_id']}/presentation", json=data)
    assert verdict.status_code == 200
    body = verdict.json()
    assert body["state"] == "failed"
    assert body["reason"] == "claim-mismatch"
