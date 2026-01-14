FROM martenseemann/quic-network-simulator-endpoint:latest

# Install nginx and Python3 (Debian-based)
RUN apt-get update && \
    apt-get install -y nginx python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy configuration and scripts
COPY nginx.conf /etc/nginx/nginx.conf
COPY streaming_server.py /streaming_server.py
COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh /streaming_server.py

ENTRYPOINT ["/run_endpoint.sh"]