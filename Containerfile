# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 python:3.12.11-slim-bookworm@sha256:c00fc7b44d844b6da22861ec24af43968a5200eac4ec607b4725d585165d6b49 AS build
WORKDIR /build
COPY LICENSE README.md pyproject.toml ./
COPY src ./src
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
      setuptools==80.9.0 wheel==0.45.1 \
    && python -m pip wheel --disable-pip-version-check --no-build-isolation \
      --no-deps --wheel-dir=/wheels .

FROM --platform=linux/amd64 python:3.12.11-slim-bookworm@sha256:c00fc7b44d844b6da22861ec24af43968a5200eac4ec607b4725d585165d6b49
ARG SOURCE_REVISION
RUN test -n "$SOURCE_REVISION"
LABEL org.opencontainers.image.source="https://github.com/TitiSkywalker/kcs" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KCS_API_MODE=v2 \
    KCS_HOST=0.0.0.0 \
    KCS_PORT=8443 \
    TMPDIR=/tmp/kcs
COPY requirements.lock /tmp/requirements.lock
COPY --from=build /wheels /tmp/wheels
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
      --requirement /tmp/requirements.lock /tmp/wheels/kcs-*.whl \
    && rm -rf /tmp/requirements.lock /tmp/wheels \
    && install -d -o 65532 -g 65532 -m 0700 /tmp/kcs
USER 65532:65532
ENTRYPOINT ["kcs", "serve"]
CMD ["--host", "0.0.0.0", "--port", "8443"]
