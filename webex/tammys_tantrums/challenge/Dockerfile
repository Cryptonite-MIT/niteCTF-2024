FROM node:20-slim

RUN apt update && apt install -y curl gnupg procps \
    && curl -fsSL https://pgp.mongodb.com/server-7.0.asc | gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor \
    && echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] http://repo.mongodb.org/apt/debian bookworm/mongodb-org/7.0 main" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list \
    && apt update \
    && apt install -y mongodb-org \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data/db

WORKDIR /app

COPY src/package*.json ./

RUN npm i --omit=dev --force

COPY src/ ./

RUN npx next telemetry disable && \
    npm run build

RUN useradd -M -s /usr/sbin/nologin user && \
    mkdir -p /data/db && \
    chmod -R o+w /data/db && \
    chmod +x start.sh && \
    echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.conf

USER user

EXPOSE 3000

ENV NODE_ENV=production
ENV RESET_INTERVAL=900
ENV JWT_SECRET=2dd71fac1db1476e9983300a82a5b4c9

CMD ["/app/start.sh"]
