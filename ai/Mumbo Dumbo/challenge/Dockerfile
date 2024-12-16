FROM python:3.9-slim AS chroot

RUN /usr/sbin/useradd --no-create-home -u 1000 user

RUN apt update && \
    apt install -y socat && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home/user

COPY chall.py .

RUN chmod o+r chall.py && \
    pip install --no-cache-dir groq python-dotenv 
USER user
ENV GROQ_API_KEY='API KEY HERE'
ENV PERIOD=5
CMD socat -T300 TCP-LISTEN:1337,reuseaddr,fork EXEC:"/usr/local/bin/python3 /home/user/chall.py"
