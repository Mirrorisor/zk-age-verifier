"""Configuration loading: a TOML file with environment-variable overrides.

The verifier reads a TOML file with two tables, ``[service]`` and ``[trust]``.
Environment variables named ``ZK_AGE_VERIFIER_SECTION__KEY`` override scalar
values within a section; ``ZK_AGE_VERIFIER_`` is the prefix and ``__`` separates
nesting levels. Lists and tables cannot be set from the environment and must
be written in the TOML file.
Unprefixed environment variables are ignored. Table and key names in the TOML
file are case-sensitive; environment variable names are not. Unknown keys in
the TOML file are rejected, as is an unknown key nested under a known section in a prefixed
environment variable (``ZK_AGE_VERIFIER_SERVICE__BOGUS``). An unknown top-level
prefixed environment variable (``ZK_AGE_VERIFIER_BOGUS``) is silently ignored
by pydantic-settings.

Source priority, highest first: constructor arguments, environment variables,
the TOML file, then model defaults.
"""

import tomllib
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from zk_age_verifier.core.constants import EU_AV, PROFILES, CredentialProfile


class ConfigError(Exception):
    """Raised when a configuration file is missing, unparseable, or invalid."""


def validate_origin(value: str) -> str:
    """Require a bare ``scheme://host[:port]`` origin with no path.

    The origin is hashed into the presentation transcript, so it must equal
    the origin the presentation asserts.

    Args:
        value: The candidate origin.

    Returns:
        The value unchanged.

    Raises:
        ValueError: The scheme is not http(s), the host is missing, or a path,
            query, or fragment is present.
    """
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ValueError("expected_origin must use http or https")
    if not parts.hostname:
        raise ValueError("expected_origin must include a host")
    if parts.path or parts.query or parts.fragment:
        raise ValueError("expected_origin must be a bare origin with no path, query, or fragment")
    return value


class PylongfellowConfig(BaseModel):
    """The ``pylongfellow`` keys under ``[service]``: proof-engine selection."""

    model_config = ConfigDict(extra="forbid")

    backend: str = "google-cpp"


class ServiceConfig(BaseModel):
    """The ``[service]`` table: origin binding, proof-engine selection, and session hygiene."""

    model_config = ConfigDict(extra="forbid")

    expected_origin: str
    pylongfellow: PylongfellowConfig = Field(default_factory=PylongfellowConfig)
    session_ttl_seconds: int = 300
    session_cap: int = 1000
    timestamp_skew_seconds: int = 300
    cors_allowed_origins: list[str] = Field(default_factory=list)
    credential: str = EU_AV.name

    @field_validator("expected_origin")
    @classmethod
    def _validate_origin(cls, value: str) -> str:
        """Validate the configured origin against the shared rules."""
        return validate_origin(value)

    @field_validator("credential")
    @classmethod
    def _validate_credential(cls, value: str) -> str:
        """Accept only the name of a known credential profile."""
        if value not in PROFILES:
            raise ValueError(f"credential must be one of {sorted(PROFILES)}, not {value!r}")
        return value

    @property
    def profile(self) -> CredentialProfile:
        """The credential profile this service accepts."""
        return PROFILES[self.credential]


class TrustSource(BaseModel):
    """One ``[trust]`` source: exactly one of ``pem``, ``etsi_xml``."""

    model_config = ConfigDict(extra="forbid")

    pem: str | None = None
    etsi_xml: str | None = None
    # SHA-256 (hex) of the exact list file the operator reviewed. When set, a list
    # with any other content is refused at startup.
    etsi_xml_sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")

    @model_validator(mode="after")
    def _validate_single_source(self) -> "TrustSource":
        """Reject entries that set zero or several source keys, or a pin without a list."""
        if self.etsi_xml_sha256 is not None and self.etsi_xml is None:
            raise ValueError("etsi_xml_sha256 can only be used together with etsi_xml")
        set_keys = [
            key
            for key, value in (("pem", self.pem), ("etsi_xml", self.etsi_xml))
            if value is not None
        ]
        if len(set_keys) != 1:
            raise ValueError("each trust source must set exactly one of pem, etsi_xml")
        return self


class TrustConfig(BaseModel):
    """The ``[trust]`` table: a non-empty list of anchor sources.

    Every listed anchor is authorized to vouch for age credentials. A
    mixed-purpose or broad list authorizes every CA on it as an age-credential
    issuer.
    """

    model_config = ConfigDict(extra="forbid")

    sources: list[TrustSource] = Field(min_length=1)


class Config(BaseSettings):
    """The whole configuration file."""

    model_config = SettingsConfigDict(
        env_prefix="ZK_AGE_VERIFIER_",
        env_nested_delimiter="__",
        extra="forbid",
        case_sensitive=True,
    )

    service: ServiceConfig
    trust: TrustConfig


def load_config(path: str | Path) -> Config:
    """Load and validate a configuration file.

    Args:
        path: Path to the TOML file.

    Returns:
        The validated configuration.

    Raises:
        ConfigError: The file is missing, not valid TOML, or fails validation.
    """
    file = Path(path)
    if not file.is_file():
        raise ConfigError(f"config file not found: {path}")

    class _Config(Config):
        """Binds the TOML source to this call's path without shared class state."""

        @classmethod
        def settings_customise_sources(
            cls,
            settings_cls: type[BaseSettings],
            init_settings: PydanticBaseSettingsSource,
            env_settings: PydanticBaseSettingsSource,
            dotenv_settings: PydanticBaseSettingsSource,
            file_secret_settings: PydanticBaseSettingsSource,
        ) -> tuple[PydanticBaseSettingsSource, ...]:
            """Order the sources: init, env, then this call's TOML file.

            `case_sensitive=True` on the model keeps TOML table and key names
            exact; the environment source is built case-insensitive so the
            documented upper-case variable names keep matching.
            """
            return (
                init_settings,
                EnvSettingsSource(settings_cls, case_sensitive=False),
                TomlConfigSettingsSource(settings_cls, toml_file=file),
            )

    try:
        return _Config()
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration in {path}: {exc}") from exc
