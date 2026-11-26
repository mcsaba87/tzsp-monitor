FROM python:3.10-slim

# Install system dependencies needed for compiling NFStream C extensions
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY geoip.py main.py ./
CMD ["python", "-u", "main.py"]
