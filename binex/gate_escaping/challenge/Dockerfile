FROM debian:bookworm-slim

RUN useradd --no-create-home -u 1001 user

RUN apt update && \
    apt install -y --no-install-recommends socat && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

COPY chall flag /

RUN chmod +x chall

USER user

CMD socat -T60 TCP-LISTEN:1337,reuseaddr,fork EXEC:"/chall"
