FROM python:3.12-alpine
WORKDIR /app
# Stdlib only, like every other service here: an AF_PACKET socket with a
# classic-BPF filter, and urllib for the InfluxDB writes.
COPY oui.py arpwatch.py selftest.py ./
CMD ["python", "-u", "arpwatch.py"]
