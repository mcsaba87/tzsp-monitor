FROM python:3.12-alpine
WORKDIR /app
# Stdlib only, like dns-monitor: a UDP socket, struct-free byte indexing for
# the 802.11 headers, and urllib for the InfluxDB writes.
COPY wids.py selftest.py ./
CMD ["python", "-u", "wids.py"]
