#!/bin/bash

# Bypass version - NO simulator setup
# We're testing direct container-to-container throughput

# Default duration if not set
TRANSFER_DURATION=${TRANSFER_DURATION:-10}

# Export SSLKEYLOGFILE if set
if [ -n "$SSLKEYLOGFILE" ]; then
    export SSLKEYLOGFILE
fi

# Note: UDP buffer tuning should be done on the host, not in containers
# The Go QUIC library will use whatever buffers are available

if [ "$ROLE" == "server" ]; then
    echo "Server starting with TRANSFER_DURATION=${TRANSFER_DURATION}s"
    echo "Listening on :443"
    /app/streaming-server
    
elif [ "$ROLE" == "client" ]; then
    # Wait for server to be ready
    echo "Waiting for server to be ready..."
    sleep 3
    
    echo "Client starting with TRANSFER_DURATION=${TRANSFER_DURATION}s"
    echo "Connecting to server4:443"
    /app/streaming-client
fi