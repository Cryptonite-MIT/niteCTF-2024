FROM debian:bookworm-slim

RUN useradd --no-create-home -u 1001 user

RUN apt update && \
    apt install -y --no-install-recommends socat seabios && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home/user

COPY run.sh qemu-system-x86_64 bzImage rootfs.ext2 ./
COPY bios/* bios/
COPY libs_to_ship/* libs_to_ship/
COPY flag /

RUN chmod +x qemu-system-x86_64 && \
    chmod +x run.sh && \ 
    chmod 444 /flag

USER user

CMD socat -T600 TCP-LISTEN:1337,reuseaddr,fork EXEC:"/home/user/run.sh"
