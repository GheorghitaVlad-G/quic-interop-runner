#!/bin/bash
set -e

# CRITICAL: Must be first!
/setup.sh

mkdir -p /logs

# List of supported test cases (same as QUIC implementation)
SUPPORTED_TESTCASES=(
    "handshake"
    "transfer"
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

if [ "$ROLE" == "client" ]; then
    echo "=== TCP Client Starting ==="
    
    # Wait for simulator to be ready (REQUIRED!)
    /wait-for-it.sh sim:57832 -s -t 30

    if [ -n "$TRANSFER_DURATION" ]; then
        # Streaming mode - check port 8080
        CHECK_PORT=8080
    else
        # File mode - check port 80
        CHECK_PORT=80
    fi

    for i in {1..50}; do
        if curl -s --connect-timeout 1 http://193.167.100.100:${CHECK_PORT}/ >/dev/null 2>&1; then
            echo "Server reachable through sim on port ${CHECK_PORT}"
            reachable=true
            break
        fi
        sleep 0.1
    done

    if [ "$reachable" != "true" ]; then
        echo "Server never became reachable through sim on port ${CHECK_PORT}"
        exit 1
    fi
    
    echo "Simulator is ready!"
    
    cd /downloads
    
    # Check if TRANSFER_DURATION is set - if so, use streaming mode
    if [ -n "$TRANSFER_DURATION" ]; then
        # Streaming mode: download continuously for TRANSFER_DURATION seconds
        echo "Starting streaming download for ${TRANSFER_DURATION} seconds from port 8080"
        
        START=$(date +%s)
        BYTES_BEFORE=$(cat /proc/net/dev | grep eth0 | awk '{print $2}')
        
        # Download stream - use port 8080 where Python server is listening
        timeout $((TRANSFER_DURATION + 2))s curl -s --max-time $((TRANSFER_DURATION + 5)) \
            http://193.167.100.100:8080/stream -o /dev/null 2>&1 || true
        
        END=$(date +%s)
        BYTES_AFTER=$(cat /proc/net/dev | grep eth0 | awk '{print $2}')
        DURATION=$((END - START))
        BYTES_RECEIVED=$((BYTES_AFTER - BYTES_BEFORE))
        
        echo "Streaming complete: ${DURATION} seconds, received ${BYTES_RECEIVED} bytes"
    else
        # File mode: download actual files
        for url in $REQUESTS; do
            filename=$(basename "$url")
            echo "Downloading $filename from $url"
            
            START=$(date +%s%N)
            if curl -f --retry 10 --retry-delay 1 --retry-connrefused --connect-timeout 1 -o "$filename" "$url" >> /logs/client.log 2>&1; then
                END=$(date +%s%N)
                DURATION=$(( (END - START) / 1000000 ))
                echo "Downloaded $filename successfully in ${DURATION}ms"
            else
                echo "Failed to download $filename"
                exit 1
            fi
        done
    fi
    
    echo "Transfer completed successfully"
    exit 0
fi