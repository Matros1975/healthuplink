# Build from the repository root: docker build -f receiver/Dockerfile .
FROM python:3.12.12-slim-bookworm

LABEL org.opencontainers.image.source="https://github.com/Matros1975/healthuplink" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="healthuplink"

# Inside the image the store lives on the /data volume and the server listens on every interface of the
# container; the port mapping (HU_PUBLISH_ADDR) decides which host address is exposed.
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HU_DATA_DIR=/data \
    HU_BIND=0.0.0.0:8796

WORKDIR /app

COPY receiver/requirements.lock receiver/pyproject.toml receiver/README.md receiver/LICENSE receiver/NOTICE ./receiver/
RUN pip install -r receiver/requirements.lock

COPY receiver/src ./receiver/src
RUN pip install --no-deps ./receiver && rm -rf receiver/build

RUN groupadd --gid 1000 healthuplink \
 && useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin healthuplink \
 && mkdir /data && chown 1000:1000 /data

USER 1000:1000
VOLUME /data
EXPOSE 8796

# http or https by HU_TLS, on 127.0.0.1 at HU_BIND's port.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["healthuplink", "healthcheck"]

ENTRYPOINT ["healthuplink"]
CMD ["serve"]
