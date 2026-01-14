#!/bin/bash
mkdir -p /logs
# Configuration
PORT=443
TCP_PORT=4433
DURATION=${TRANSFER_DURATION:-10}
PATTERN_FILE="/tmp/pattern.bin"

# 1. Create the 0xaa pattern file (hex 0xaa is 170 decimal)
# We create a 100MB chunk to loop
if [ ! -f "$PATTERN_FILE" ]; then
    echo "Generating 0xaa pattern file..."
    head -c 100M /dev/zero | tr '\0' '\252' > "$PATTERN_FILE"
fi

if [ "$ROLE" == "server" ]; then
    echo "--- Starting Server Mode ---"
    
    if [ "$PROTOCOL" == "tcp" ]; then
        echo "Protocol: TCP (iPerf3)"
        iperf3 -s -p $TCP_PORT
    else
        echo "Protocol: QUIC (Go Optimized)"
        /app/streaming-server
    fi

elif [ "$ROLE" == "client" ]; then
    echo "--- Starting Client Mode ---"
    sleep 3 # Wait for server to bind
    
    if [ "$PROTOCOL" == "tcp" ]; then
        echo "Protocol: TCP (iPerf3)"
        # -P 8: 8 parallel streams (match your Go config)
        # -F: stream from our 0xaa file
        # -J: output JSON (perfect for your ML dataset)
        iperf3 -c server4 -p $TCP_PORT -t $DURATION -P 8 -F "$PATTERN_FILE" -J > /logs/tcp_results.json
        echo "TCP Test Complete. Results in /logs/tcp_results.json"
    else
        echo "Protocol: QUIC (Go Optimized)"
        /app/streaming-client
    fi
fi