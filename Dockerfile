# syntax=docker/dockerfile:1
# uv multi-stage build: deps resolved in a builder, only the venv + source ship.
FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
# install deps first (cached on a bind mount) without the project, for layer reuse
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev
RUN chmod +x /app/docker-entrypoint.sh

# Fork: pinned by digest (python 3.11.18, 2026-11-05), and pip, setuptools and wheel are removed:
# the service runs from /app/.venv and never installs anything, and their vendored packages
# carried known vulnerabilities (jaraco.context, wheel). The audit workflow scans this image.
FROM python:3.11-slim-bookworm@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39
RUN python -m pip uninstall --yes --quiet pip setuptools wheel
ARG GIT_REF=""
ENV ZK_AGE_VERIFIER_BUILD_REF=$GIT_REF
RUN useradd --create-home app
COPY --from=builder --chown=app:app /app /app
ENV PATH="/app/.venv/bin:$PATH"
USER app
WORKDIR /app
EXPOSE 8000
ENTRYPOINT ["/app/docker-entrypoint.sh"]
