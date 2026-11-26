FROM python:3.12-alpine
WORKDIR /app
# Stdlib only, like dns-resolver: the RouterOS REST calls and the InfluxDB
# line-protocol writes are both plain urllib, so there is nothing to install.
COPY responder.py selftest.py ./
CMD ["python", "-u", "responder.py"]
