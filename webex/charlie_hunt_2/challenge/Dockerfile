FROM python:3.10-slim

RUN useradd -m -s /usr/sbin/nologin -u 1001 ctfuser

WORKDIR /app

EXPOSE 5000

RUN apt update && \
    apt install -y --no-install-recommends nginx supervisor && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

COPY ./app/requirements.txt /app/app/

RUN pip install --no-cache-dir -r ./app/requirements.txt

COPY . /app

COPY ./app/nginx.conf /etc/nginx/nginx.conf

ENV FLASK_APP=./app/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000
ENV PYTHONUNBUFFERED 1

EXPOSE 5000

CMD ["supervisord", "-n", "-c", "/app/supervisord.conf"]
