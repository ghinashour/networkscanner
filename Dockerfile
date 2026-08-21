FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# ADDED "nmap" to the installation list below 👇
RUN apt-get update && apt-get install -y \
    build-essential \
    nmap \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/data   # <-- create database directory

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY . .

# Use $PORT, and ensure your app object is correctly named
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:$PORT", "app:app"]