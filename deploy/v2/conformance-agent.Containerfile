# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 python:3.12.11-slim-bookworm@sha256:c00fc7b44d844b6da22861ec24af43968a5200eac4ec607b4725d585165d6b49 AS build
WORKDIR /build
COPY LICENSE README.md pyproject.toml ./
COPY src ./src
RUN python -m pip wheel --disable-pip-version-check --no-deps --wheel-dir=/wheels .

FROM --platform=linux/amd64 python:3.12.11-slim-bookworm@sha256:c00fc7b44d844b6da22861ec24af43968a5200eac4ec607b4725d585165d6b49
ARG SOURCE_REVISION
RUN test -n "$SOURCE_REVISION"
LABEL org.opencontainers.image.source="https://github.com/TitiSkywalker/kcs" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /wheels /tmp/wheels
RUN python -m pip install --disable-pip-version-check --no-cache-dir --no-deps \
      /tmp/wheels/kcs-*.whl \
    && rm -rf /tmp/wheels \
    && install -d -m 0755 /opt/kcs /run/kcs /workspace \
    && ln -s /usr/local/bin/kcs-agent-supervisor /opt/kcs/agent-supervisor
ENTRYPOINT ["/opt/kcs/agent-supervisor"]
