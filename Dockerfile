FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    nmap \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/data

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY . .

# ✅ FIXED: Using shell form so $PORT expands correctly
CMD gunicorn -w 4 -b 0.0.0.0:$PORT app:app