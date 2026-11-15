from pathlib import Path

import pytest
from pylongfellow import Pylongfellow

from zk_age_verifier.core.engine.circuits import CircuitSpec, HeldCircuit, load_held_circuit


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--transport",
        choices=("inprocess", "live"),
        default="inprocess",
        help="How the integration suite reaches the app: inprocess (ASGI, default) or "
        "live (HTTP against a running server named by --base-url).",
    )
    parser.addoption(
        "--base-url",
        default=None,
        help="Base URL of the live server; required with --transport=live.",
    )


TEST_ANCHOR_PEM = Path(__file__).parent / "integration" / "credentials" / "test-anchor.pem"

ORIGIN = "https://chat.example.org"

# A stand-in HeldCircuit for tests that stub circuit loading: a fixed spec and a
# real Pylongfellow with no circuit loaded, so no artifact is read. Its zk_system_id
# is the identity the spec fields imply, not one resolved from the vendored artifact.
_STUB_SPEC = CircuitSpec(
    system="longfellow-libzk-v1",
    circuit_hash="abc123",
    num_attributes=1,
    version=7,
    block_enc_hash=1,
    block_enc_sig=1,
)
HELD_STUB = HeldCircuit(
    spec=_STUB_SPEC,
    longfellow=Pylongfellow(backend="google-cpp"),
    zk_system_id="longfellow-libzk-v1_7_1_1_1_abc123",
)


@pytest.fixture(scope="session")
def held() -> HeldCircuit:
    """Load the vendored circuit once for the whole session."""
    return load_held_circuit(backend="google-cpp")


def _toml_scalar(value: object) -> str:
    """Render a Python value as a TOML scalar: bools and ints bare, lists as an
    array of quoted strings, everything else quoted."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(f'"{item}"' for item in value) + "]"
    return f'"{value}"'


def render_config(
    *, origin: str = ORIGIN, pem: str | Path = TEST_ANCHOR_PEM, **service: object
) -> str:
    """Render a verifier ``config.toml`` body.

    ``[service]`` carries ``expected_origin`` plus any keyword in ``service``;
    ``[trust]`` carries one ``pem`` source. The default origin and anchor are the
    committed test CA, so a caller overrides only what its test varies.

    Args:
        origin: The service ``expected_origin``.
        pem: The trust ``pem`` source (a file or directory path).
        service: Extra ``[service]`` keys, e.g. ``session_cap=1``.

    Returns:
        The TOML body.
    """
    lines = ["[service]", f'expected_origin = "{origin}"']
    lines += [f"{key} = {_toml_scalar(value)}" for key, value in service.items()]
    lines += ["[trust]", f'sources = [{{ pem = "{pem}" }}]']
    return "\n".join(lines) + "\n"


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(render_config())
    return path
