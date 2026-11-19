FROM python:3.13-slim
RUN pip install --no-cache-dir Flask==3.1.1 psycopg2-binary==2.9.10 redis==5.2.1 cryptography==46.0.5
