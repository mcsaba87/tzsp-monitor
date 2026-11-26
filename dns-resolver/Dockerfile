FROM python:3.12-alpine
WORKDIR /app
COPY geoip.py oui.py resolver.py ./
EXPOSE 8000
CMD ["python", "-u", "resolver.py"]
