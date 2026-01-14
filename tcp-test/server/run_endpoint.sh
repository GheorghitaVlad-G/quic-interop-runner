#!/bin/bash
set -e
/setup.sh
mkdir -p /logs

# Increase max TCP buffer sizes to 64MB
# In run_endpoint.sh
sysctl -w net.core.rmem_max=67108864 || echo "Warning: Could not set rmem_max"
sysctl -w net.core.wmem_max=67108864 || echo "Warning: Could not set wmem_max"
sysctl -w net.ipv4.tcp_rmem="4096 87380 67108864" || echo "Warning: Could not set tcp_rmem"
sysctl -w net.ipv4.tcp_wmem="4096 65536 67108864" || echo "Warning: Could not set tcp_wmem"

/app/streaming-server
