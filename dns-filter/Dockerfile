FROM python:3.12-alpine
WORKDIR /app
# Stdlib only, like the other sidecars: an HTTP server for the control API and
# for the hosts files the router downloads, tarfile/gzip for the UT1 archives,
# and urllib for the RouterOS REST API and the InfluxDB writes.
COPY filter.py selftest.py ./
EXPOSE 8040 8041
CMD ["python", "-u", "filter.py"]
