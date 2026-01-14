#!/bin/bash
mkdir -p /logs

# Configuration
PORT=443
TCP_PORT=4433
DURATION=${TRANSFER_DURATION:-10}
PATTERN_FILE="/tmp/pattern.bin"

# 1. Create the 0xaa pattern file if needed
if [ ! -f "$PATTERN_FILE" ]; then
    echo "Generating 0xaa pattern file..."
    head -c 100M /dev/zero | tr '\0' '\252' > "$PATTERN_FILE"
fi

if [ "$ROLE" == "server" ]; then
    echo "--- Starting Server Mode ---"
    
    if [ "$PROTOCOL" == "tcp" ]; then
        echo "Protocol: TCP + TLS (Go Binary)"
        /app/streaming-server
    else
        echo "Protocol: QUIC (Go Binary)"
        /app/streaming-server
    fi

elif [ "$ROLE" == "client" ]; then
    echo "--- Starting Client Mode ---"
    sleep 3 # Wait for server to bind
    
    if [ "$PROTOCOL" == "tcp" ]; then
        echo "Protocol: TCP + TLS (Go Binary)"
        /app/streaming-client
    else
        echo "Protocol: QUIC (Go Binary)"
        /app/streaming-client
    fi
fi