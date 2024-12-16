FROM python:3.10-slim

RUN useradd -M -s /usr/sbin/nologin appuser

WORKDIR /app

COPY /private /app

RUN pip install --no-cache-dir flask gunicorn

EXPOSE 5000

USER appuser

CMD ["sh", "-c", "gunicorn -w 1 -b 0.0.0.0:${PORT:-5000} app:app"]
