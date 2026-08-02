# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 python:3.12.11-slim-bookworm@sha256:c00fc7b44d844b6da22861ec24af43968a5200eac4ec607b4725d585165d6b49 AS build
WORKDIR /build
COPY LICENSE README.md pyproject.toml ./
COPY src ./src
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
      setuptools==80.9.0 wheel==0.45.1 \
    && python -m pip wheel --disable-pip-version-check --no-build-isolation \
      --no-deps --wheel-dir=/wheels .

FROM --platform=linux/amd64 nvidia/cuda:12.8.1-runtime-ubuntu24.04@sha256:828c4d878adcaa4265d80c95d8ec877149b49bb2419a4cf3bb6aa889bbb7ca2e
ARG SOURCE_REVISION
RUN test -n "$SOURCE_REVISION"
LABEL org.opencontainers.image.source="https://github.com/TitiSkywalker/kcs" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="MIT"
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /wheels /tmp/wheels
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates python3-minimal python3-pip \
    && python3 -m pip install --break-system-packages --disable-pip-version-check \
      --no-cache-dir --no-deps /tmp/wheels/kcs-*.whl \
    && rm -rf /var/lib/apt/lists/* /tmp/wheels \
    && install -d -m 0755 /opt/kcs /run/kcs /workspace \
    && ln -s /usr/local/bin/kcs-workspace-sidecar /opt/kcs/workspace-sidecar
ENTRYPOINT ["/opt/kcs/workspace-sidecar"]
