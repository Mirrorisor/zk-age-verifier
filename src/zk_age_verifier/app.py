"""FastAPI application factory for zk-age-verifier."""

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from importlib.metadata import version
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware

from zk_age_verifier.config import Config, load_config
from zk_age_verifier.core.engine.circuits import load_held_circuit
from zk_age_verifier.core.transport.dc import DcTransport
from zk_age_verifier.core.trustlist import load_anchors
from zk_age_verifier.log import configure_logging
from zk_age_verifier.problem import install_problem_handlers
from zk_age_verifier.service.routes import router
from zk_age_verifier.service.sessions import SessionStore, sweep_loop

CONFIG_ENV_VAR = "ZK_AGE_VERIFIER_CONFIG"
"""Environment variable naming the config file for the granian factory target.

Shares the config loader's ``ZK_AGE_VERIFIER_`` env prefix; safe only because
pydantic-settings ignores unknown top-level prefixed variables.
"""

_SWEEP_INTERVAL_SECONDS = 60

_OPENAPI_TAGS = [
    {
        "name": "sessions",
        "description": "Session lifecycle, called server-to-server by the consumer's backend.",
    },
    {
        "name": "debug",
        "description": "Transcript reconstruction for diagnosing failed verifications.",
    },
    {"name": "health"},
]


class HealthStatus(BaseModel):
    """The ``/health`` 200 body."""

    status: Literal["ok"]
    zk_age_verifier: str
    pylongfellow: str
    engine: str
    ref: str | None


def create_app(config: Config) -> FastAPI:
    """Build the verifier ASGI application.

    Args:
        config: The validated service configuration.

    Returns:
        The configured application.
    """
    configure_logging()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Load the circuit and anchors, run the sweeper, and tear it down on shutdown."""
        held = load_held_circuit(backend=config.service.pylongfellow.backend)
        store = SessionStore(config, DcTransport(held, config.service.profiles))
        app.state.config = config
        app.state.held = held
        app.state.store = store
        app.state.anchors = load_anchors(config.trust.sources)
        sweeper = asyncio.create_task(sweep_loop(store, _SWEEP_INTERVAL_SECONDS))
        try:
            yield
        finally:
            sweeper.cancel()
            with suppress(asyncio.CancelledError):
                await sweeper

    app = FastAPI(
        title="zk-age-verifier",
        lifespan=lifespan,
        openapi_tags=_OPENAPI_TAGS,
        swagger_ui_parameters={"defaultModelExpandDepth": 3},
    )
    install_problem_handlers(app)
    if config.service.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.service.cors_allowed_origins,
            allow_methods=["POST"],
            allow_headers=["Content-Type"],
        )
    app.include_router(router)

    @app.get(
        "/health",
        tags=["health"],
        operation_id="health",
        summary="Liveness probe",
        response_description="Service is up",
    )
    async def health() -> HealthStatus:
        """Report that the service process is up, and what it is running."""
        return HealthStatus(
            status="ok",
            zk_age_verifier=version("zk-age-verifier"),
            pylongfellow=version("pylongfellow"),
            engine=config.service.pylongfellow.backend,
            ref=os.environ.get("ZK_AGE_VERIFIER_BUILD_REF"),
        )

    return app


def app_factory() -> FastAPI:
    """Load configuration from the environment and build the app (granian factory target)."""
    return create_app(load_config(os.environ[CONFIG_ENV_VAR]))
