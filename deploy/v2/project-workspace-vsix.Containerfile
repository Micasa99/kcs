# syntax=docker/dockerfile:1.7
FROM scratch
ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/TitiSkywalker/ResearchCosmos" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      io.researchcosmos.kcs.role="project-workspace-extension"
COPY aicosmos-workspace-0.1.0.vsix /opt/rc-workspace-extension/aicosmos-workspace.vsix
