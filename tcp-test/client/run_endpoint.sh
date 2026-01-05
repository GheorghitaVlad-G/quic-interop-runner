#!/bin/bash
set -e

# CRITICAL: Must be first!
/setup.sh

mkdir -p /logs

if [ "$ROLE" == "client" ]; then
    echo "=== TCP Client Starting ==="
    
    # Wait for simulator to be ready (REQUIRED!)
    /wait-for-it.sh sim:57832 -s -t 30
    
    echo "Simulator is ready!"
    
    cd /downloads
    
    for url in $REQUESTS; do
        filename=$(basename "$url")
        echo "Downloading $filename from $url"
        
        START=$(date +%s%N)
        if curl -f -o "$filename" "$url" 2>&1 | tee -a /logs/client.log; then
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