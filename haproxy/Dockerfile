# Dockerfile for HAProxy reverse proxy with TLS offload
# Build from latest official haproxy image
FROM haproxy:latest

# Copy HAProxy configuration
COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
COPY fullchain.pem /usr/local/etc/haproxy/fullchain.pem

# Run HAProxy in foreground with debugging enabled
CMD ["haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg", "-db"]