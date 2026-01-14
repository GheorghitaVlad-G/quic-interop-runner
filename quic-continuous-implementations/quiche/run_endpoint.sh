#!/bin/bash

# Set up the routing needed for the simulation
/setup.sh

# List of supported test cases
SUPPORTED_TESTCASES=(
    "handshake"
    "transfer"
    "retry"
    "resumption"
    "zerortt"
    "chacha20"
    "keyupdate"
    "http3"
    "multiconnect"
    "versionnegotiation"
    "v2"
    "handshake_time"
    "goodput"
    "ttfb"
    "transfer_time"
    "throughput"
    "retransmission_rate"
    "recovery_time"
    "tail_latency"
    "memory"
    "cpu"
)

# Check if TESTCASE is set and if it's supported
if [ -n "$TESTCASE" ]; then
    TESTCASE_SUPPORTED=false
    for tc in "${SUPPORTED_TESTCASES[@]}"; do
        if [ "$TESTCASE" == "$tc" ]; then
            TESTCASE_SUPPORTED=true
            break
        fi
    done
    
    if [ "$TESTCASE_SUPPORTED" = false ]; then
        echo "Unsupported test case: $TESTCASE"
        exit 127
    fi
fi

# Default duration if not set
TRANSFER_DURATION=${TRANSFER_DURATION:-10}

# Export SSLKEYLOGFILE if set (quiche supports this natively)
if [ -n "$SSLKEYLOGFILE" ]; then
    export SSLKEYLOGFILE
fi

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up
    /wait-for-it.sh sim:57832 -s -t 30
    
    # Wait a bit more for server to be ready
    sleep 2
    
    echo "Client starting with TRANSFER_DURATION=${TRANSFER_DURATION}s"
    /app/streaming-client
    
elif [ "$ROLE" == "server" ]; then
    echo "Server starting with TRANSFER_DURATION=${TRANSFER_DURATION}s"
    /app/streaming-server
fi