FROM python:3.12-alpine
WORKDIR /app
# Stdlib only, like the other sidecars: an HTTP server, a unix socket client for
# Suricata's command channel, and urllib for the InfluxDB audit write.
COPY control.py .
EXPOSE 8020
CMD ["python", "-u", "control.py"]
