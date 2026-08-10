# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 python:3.12.11-slim-bookworm@sha256:c00fc7b44d844b6da22861ec24af43968a5200eac4ec607b4725d585165d6b49 AS build
ARG PIP_INDEX_URL=https://pypi.org/simple
WORKDIR /build
COPY LICENSE README.md pyproject.toml ./
COPY src ./src
RUN python -m pip install --index-url "$PIP_INDEX_URL" --timeout 120 --disable-pip-version-check --no-cache-dir \
      setuptools==80.9.0 wheel==0.45.1 \
    && python -m pip wheel --index-url "$PIP_INDEX_URL" --timeout 120 --disable-pip-version-check \
      --wheel-dir=/wheels rfc8785==0.1.4 \
    && python -m pip wheel --index-url "$PIP_INDEX_URL" --timeout 120 --disable-pip-version-check --no-build-isolation \
      --no-deps --wheel-dir=/wheels .

FROM --platform=linux/amd64 python:3.12.11-slim-bookworm@sha256:c00fc7b44d844b6da22861ec24af43968a5200eac4ec607b4725d585165d6b49
ARG SOURCE_REVISION
RUN test -n "$SOURCE_REVISION"
LABEL org.opencontainers.image.source="https://github.com/TitiSkywalker/kcs" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="MIT" \
      io.researchcosmos.kcs.role="runtime-control"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KCS_CONTROL_STATE_DIR=/run/rc-control/control-state \
    KCS_NATIVE_FINALIZE_RECEIPT_PATH=/run/rc-control/finalize-receipt.json
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /wheels /tmp/wheels
RUN python -m pip install --disable-pip-version-check --no-cache-dir --no-deps \
      /tmp/wheels/rfc8785-*.whl /tmp/wheels/kcs-*.whl \
    && rm -rf /tmp/wheels \
    && install -d -m 0755 /opt/kcs /run/kcs /workspace
COPY --chmod=0555 src/kcs/runtime_control/entrypoint.py /opt/kcs/workspace-sidecar
ENTRYPOINT ["/opt/kcs/workspace-sidecar"]
