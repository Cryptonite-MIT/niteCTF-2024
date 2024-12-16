FROM python:3.9-slim

RUN apt update && \
    apt install -y --no-install-recommends \
        nginx \
        curl \
        gnupg \
        supervisor && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/cache/nginx \
    /var/log/nginx \
    /var/lib/nginx \
    /var/lib/nginx/body \
    /run/nginx

WORKDIR /app

COPY frontend/requirements.txt frontend/requirements.txt
RUN pip install --no-cache-dir -r frontend/requirements.txt

COPY frontend frontend/
COPY backend backend/

RUN cd backend && npm install --omit=dev

COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /app/supervisord.conf

EXPOSE 80

RUN /usr/sbin/useradd --no-create-home -u 1000 user

CMD ["supervisord", "-n", "-c", "/app/supervisord.conf"]
