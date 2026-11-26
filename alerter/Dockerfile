FROM python:3.12-alpine
# The service itself is stdlib only. curl, GNU wget and jq are for the alert
# commands: webhooks are the point, and jq is the safe way to build a JSON body
# from $ALERT_* without hand-quoting.
RUN apk add --no-cache curl wget jq ca-certificates
WORKDIR /app
COPY alerter.py selftest.py ./
CMD ["python", "-u", "alerter.py"]
