FROM ubuntu@sha256:152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98 as chroot
RUN useradd --no-create-home -u 1000 user

RUN apt update && \
    apt install -y socat && \
    rm -rf /var/lib/apt/lists/*

COPY chall flag.txt /home/user/

WORKDIR /home/user/
RUN chmod +x ./chall 

USER user

CMD socat -T60 TCP-LISTEN:1337,reuseaddr,fork EXEC:"/home/user/chall"
