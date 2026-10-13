FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY config/ ./config/
COPY src/ ./src/

WORKDIR /app/src
CMD ["python", "-m", "detection.main"]
