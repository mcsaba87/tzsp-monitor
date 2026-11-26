FROM python:3.12-alpine
WORKDIR /app
# Stdlib only, like the other sidecars: statvfs for the disk reading, urllib for
# the InfluxDB API and the line-protocol writes, and a unix socket for
# Suricata's reopen-log-files. Nothing to pip-install.
COPY guard.py selftest.py ./
CMD ["python", "-u", "guard.py"]
