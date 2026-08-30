FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv/gateway
COPY pyproject.toml README.md ./
COPY push_gateway ./push_gateway
RUN pip install --no-cache-dir ".[gateway]"

RUN useradd --create-home --uid 10002 gateway \
    && mkdir -p /data \
    && chown -R gateway:gateway /data /srv/gateway
USER gateway

EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/healthz', timeout=3)"

CMD ["python", "-m", "push_gateway"]
