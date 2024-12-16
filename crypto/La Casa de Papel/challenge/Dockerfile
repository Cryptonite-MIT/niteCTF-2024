FROM python:3.9-slim

RUN /usr/sbin/useradd --no-create-home -u 1000 user

RUN apt update && \
    apt install -y socat && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home/user

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY chall.py flag.txt secret.txt ./

RUN chmod 555 chall.py 

USER user

CMD socat -T60 TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 chall.py"
