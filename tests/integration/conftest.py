from collections.abc import Iterator
from typing import Any, cast

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.conftest import ORIGIN, render_config
from zk_age_verifier.app import create_app
from zk_age_verifier.config import load_config


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--transport") != "live":
        return
    skip_live = pytest.mark.skip(reason="in-process-only: cannot cross a socket")
    for item in items:
        if item.get_closest_marker("inprocess_only"):
            item.add_marker(skip_live)


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Run every in-process integration test against each verifier backend.

    The presenter's prover stays fixed: a wallet's proving implementation is
    outside the service's knowledge, so only the verifier varies. The live
    transport runs the suite once, against the server as deployed.
    """
    if "verifier_backend" not in metafunc.fixturenames:
        return
    if metafunc.config.getoption("--transport") == "live":
        metafunc.parametrize("verifier_backend", ["as-deployed"], scope="session")
        return
    metafunc.parametrize("verifier_backend", ["google-cpp", "isrg-rust"], scope="session")


@pytest.fixture(scope="session")
def origin() -> str:
    return ORIGIN


@pytest.fixture(scope="session")
def client(
    request: pytest.FixtureRequest,
    tmp_path_factory: pytest.TempPathFactory,
    verifier_backend: str,
) -> Iterator[httpx.Client]:
    if request.config.getoption("--transport") == "live":
        base_url = request.config.getoption("--base-url")
        if not base_url:
            raise pytest.UsageError("--transport=live requires --base-url=<url>")
        with httpx.Client(base_url=str(base_url)) as live_client:
            yield live_client
        return
    config_file = tmp_path_factory.mktemp("config") / "config.toml"
    config_file.write_text(render_config(**{"pylongfellow.backend": verifier_backend}))
    with TestClient(create_app(load_config(config_file))) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def licence_client(
    tmp_path_factory: pytest.TempPathFactory, verifier_backend: str
) -> Iterator[httpx.Client]:
    """A verifier configured for ISO driving licences instead of the EU credential."""
    config_file = tmp_path_factory.mktemp("licence-config") / "config.toml"
    config_file.write_text(
        render_config(**{"pylongfellow.backend": verifier_backend, "credential": "iso-mdl"})
    )
    with TestClient(create_app(load_config(config_file))) as test_client:
        yield test_client


@pytest.fixture
def created_session(client: httpx.Client) -> dict[str, Any]:
    created = client.post("/sessions", json={"checks": ["age_over_18"]})
    assert created.status_code == 201
    return cast(dict[str, Any], created.json())
