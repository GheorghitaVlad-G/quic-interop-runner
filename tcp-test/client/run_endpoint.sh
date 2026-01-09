#!/bin/bash
set -e

# CRITICAL: Must be first!
/setup.sh

mkdir -p /logs

if [ "$ROLE" == "client" ]; then
    echo "=== TCP Client Starting ==="
    
    # Wait for simulator to be ready (REQUIRED!)
    /wait-for-it.sh sim:57832 -s -t 30

    for i in {1..50}; do
        if curl -s --connect-timeout 1 http://193.167.100.100/ >/dev/null; then
            echo "Server reachable through sim"
            reachable=true
            break
        fi
        sleep 0.1
    done

    if [ "$reachable" != "true" ]; then
        echo "Server never became reachable through sim"
        exit 1
    fi
    
    echo "Simulator is ready!"
    
    cd /downloads
    
    for url in $REQUESTS; do
        filename=$(basename "$url")
        echo "Downloading $filename from $url"
        
        START=$(date +%s%N)
        if curl -f --retry 10 --retry-delay 1 --retry-connrefused --connect-timeout 1 -o "$filename" "$url"  >> /logs/client.log 2>&1; then
            END=$(date +%s%N)
            DURATION=$(( (END - START) / 1000000 ))
            echo "Downloaded $filename successfully in ${DURATION}ms"
        else
            echo "Failed to download $filename"
            exit 1
        fi
    done
    
    echo "All downloads completed successfully"
    exit 0
fi