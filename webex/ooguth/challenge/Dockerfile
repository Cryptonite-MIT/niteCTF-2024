FROM python:3.9-slim

RUN /usr/sbin/useradd --no-create-home -u 1000 user

RUN apt update && \
    apt install nginx supervisor -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home/user

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY init.sh stop.sh start.sh serverB.py serverC.py oauth.py supervisord.conf ./
COPY assets/ ./assets/ 
COPY templates/ ./templates/

COPY nginx.conf /etc/nginx/nginx.conf

RUN chmod +x init.sh start.sh

ENV SERVER_B_PORT=5001
ENV SERVER_C_PORT=5003
ENV OAUTH_PORT=5002
ENV USERNAME=adagessourdeline
ENV PASSWORD=&ONv+.ku@BPxFRIn

# ENV DOMAIN=b.com
# ENV OAUTH_URL=http://oauth.$DOMAIN
# ENV ISSUER_URL=http://oogle.$DOMAIN
# ENV SELF_HOST=http://yankdeal.$DOMAIN
ENV INTERNAL_OAUTH=http://127.0.0.1:5002
# ENV AUTHORIZATION_ENDPOINT=http://127.0.0.1:$OAUTH_PORT/authenticate
# ENV TOKEN_ENDPOINT=http://127.0.0.1:$OAUTH_PORT/verifyToken

CMD ["bash", "init.sh"]
