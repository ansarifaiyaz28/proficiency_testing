FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CTIA_DATA_DIR=/data \
    CTIA_PORT=8080

WORKDIR /app

RUN addgroup -S ctia && adduser -S -G ctia -h /app ctia

COPY requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt

COPY app/ ./

RUN mkdir -p /data && chown -R ctia:ctia /app /data

USER ctia

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('CTIA_PORT', '8080') + '/healthz', timeout=2)" || exit 1

CMD ["sh", "-c", "waitress-serve --listen=0.0.0.0:${CTIA_PORT:-8080} app:app"]
