FROM python:3.12-alpine
# tcpdump does the capturing, the BPF filter and the file rotation -- in C, in
# the kernel's filter engine, and without a Python loop per packet in front of
# the disk. Everything around it (budget, ceiling, control API, InfluxDB) is
# stdlib, like the other sidecars.
RUN apk add --no-cache tcpdump
WORKDIR /app
COPY dump.py selftest.py ./
EXPOSE 8050 8051
CMD ["python", "-u", "dump.py"]
