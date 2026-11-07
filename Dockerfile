FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PANEL_DATA_DIR=/data PANEL_AUDIT_DIR=/data/audit
ARG COMPOSE_VERSION=v2.39.4
RUN apt-get update && apt-get install -y --no-install-recommends docker.io ca-certificates curl \
    && mkdir -p /usr/local/lib/docker/cli-plugins \
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64|arm64) ;; *) echo "Unsupported architecture: $arch"; exit 1;; esac \
    && curl --fail --location --retry 3 --silent --show-error \
       "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-${arch}" \
       -o /usr/local/lib/docker/cli-plugins/docker-compose \
    && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose \
    && docker compose version \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/panel
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN mkdir -p /data
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9090/healthz', timeout=3)" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9090", "--workers", "1"]
