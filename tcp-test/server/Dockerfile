FROM martenseemann/quic-network-simulator-endpoint:latest

# Install nginx (Debian-based, use apt-get not apk)
RUN apt-get update && \
    apt-get install -y nginx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy configuration and script
COPY nginx.conf /etc/nginx/nginx.conf
COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]