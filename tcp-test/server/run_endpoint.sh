#!/bin/bash
set -e

# CRITICAL: Set up routing through the simulator
/setup.sh

mkdir -p /logs
chmod 755 /logs

if [ "$ROLE" == "server" ]; then
    echo "=== TCP Server Starting ==="
    
    # Fix permissions on www directory
    chmod -R 755 /www 2>/dev/null || true
    
    echo "Files to serve:"
    ls -lh /www/
    
    # Create www-data user if it doesn't exist (for Debian nginx)
    id -u www-data &>/dev/null || useradd -r -s /bin/false www-data
    
    # Start nginx in background
    nginx
    
    # Wait for nginx to be ready
    echo "Waiting for nginx to be ready..."
    for i in {1..30}; do
        if netcat -z localhost 80 2>/dev/null || nc -z localhost 80 2>/dev/null; then
            echo "Nginx is ready after ${i} attempts"
            break
        fi
        sleep 0.1
    done
    
    # Verify nginx is serving
    if wget -q -O /dev/null http://localhost:80/ 2>/dev/null || curl -f -s http://localhost:80/ >/dev/null 2>&1; then
        echo "Nginx is serving files successfully"
    fi
    
    # Show listening ports
    echo "Listening on:"
    netstat -tlnp 2>/dev/null | grep :80 || ss -tlnp 2>/dev/null | grep :80 || echo "Port 80 status check skipped"
    
    # Keep container running by tailing logs
    echo "Server ready, tailing logs..."
    tail -f /logs/access.log /logs/error.log 2>/dev/null || sleep infinity
    
elif [ "$ROLE" == "client" ]; then
    echo "ERROR: TCP server container shouldn't run in client mode"
    exit 1
fi