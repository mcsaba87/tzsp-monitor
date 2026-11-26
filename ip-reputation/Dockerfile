FROM python:3.12-alpine
WORKDIR /app
# Stdlib only, like the other sidecars: urllib for the feeds and InfluxDB,
# http.client for the kept-alive RouterOS connection, http.server for the
# control API Grafana calls.
COPY reputation.py selftest.py ./
EXPOSE 8070
CMD ["python", "-u", "reputation.py"]
