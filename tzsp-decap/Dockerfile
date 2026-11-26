FROM python:3.12-alpine
WORKDIR /app
# Stdlib only: the tap is driven with fcntl/ioctl and InfluxDB with urllib, so
# there is nothing to pip-install and no build toolchain in the image.
COPY decap.py selftest.py ./
CMD ["python", "-u", "decap.py"]
