FROM python:3.12-slim-bookworm
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
EXPOSE 5007
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "5007"]
