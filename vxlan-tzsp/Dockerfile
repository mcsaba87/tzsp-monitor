FROM python:3.12-alpine
WORKDIR /app
# Stdlib only, like tzsp-decap: sockets plus urllib for InfluxDB.
COPY convert.py ./
CMD ["python", "-u", "convert.py"]
