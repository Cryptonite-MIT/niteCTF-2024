FROM python:3.8-slim

RUN useradd -M -s /usr/sbin/nologin appuser

WORKDIR /app

COPY . .

RUN chown -R appuser:appuser /app
RUN chmod -R u+w /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

ENV FLASK_APP=main.py
ENV JWT_SECRET_KEY=H6jga21h1
ENV FDRP_JWT_SECRET_KEY=wEdAeLdjae

USER appuser

CMD ["sh", "-c", "gunicorn -w 1 -b 0.0.0.0:${PORT} main:app"]
