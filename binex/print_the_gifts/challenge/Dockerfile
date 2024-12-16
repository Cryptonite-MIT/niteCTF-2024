FROM debian:bookworm-slim

RUN useradd --no-create-home -u 1000 user

RUN apt update && \
    apt install -y socat libc6 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home/user/

COPY chall flag.txt ./

RUN chmod +x ./chall && \
    chmod 444 ./flag.txt

USER user

CMD socat -T60 TCP-LISTEN:1337,reuseaddr,fork EXEC:"/home/user/chall"
