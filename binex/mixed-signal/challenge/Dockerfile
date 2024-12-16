FROM debian:bookworm-slim

RUN useradd --no-create-home -u 1000 user

RUN apt update && \
    apt install -y socat && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home/user

COPY chal flag.txt ./

RUN chmod +x chal

USER user

CMD socat -T60 TCP-LISTEN:1337,reuseaddr,fork EXEC:"./chal"
