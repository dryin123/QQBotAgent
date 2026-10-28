FROM python:3.13-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    QQBOT_HOST=0.0.0.0

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

VOLUME ["/app/data", "/app/aux_data"]

EXPOSE 8000

CMD ["python", "main.py", "--serve"]
