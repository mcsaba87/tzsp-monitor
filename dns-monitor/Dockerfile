FROM python:3.12-alpine
WORKDIR /app
# Stdlib only, like the responder and dns-resolver: a unix socket server and
# urllib for the InfluxDB line-protocol writes, so there is nothing to install.
COPY monitor.py selftest.py ./
CMD ["python", "-u", "monitor.py"]
