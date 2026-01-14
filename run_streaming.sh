#!/bin/bash
# run_bypass_test.sh - Complete setup and test script

set -e

echo "=== QUIC Throughput Bypass Test Setup ==="

# Step 1: Check if certs exist, if not generate them
CERT_DIR="./certs"
if [ ! -d "$CERT_DIR" ] || [ ! -f "$CERT_DIR/cert.pem" ]; then
    echo "Generating certificates..."
    mkdir -p "$CERT_DIR"
    
    # Generate certs (chain length 1 for simplicity)
    cat > "$CERT_DIR/cert_config.txt" << 'EOF'
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
dirstring_type = nobmp
[ req_distinguished_name ]
[ v3_ca ]
keyUsage=critical, keyCertSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints=critical,CA:TRUE,pathlen:100
EOF

    # Generate Root CA
    openssl ecparam -name prime256v1 -genkey -out "$CERT_DIR/ca.key"
    openssl req -x509 -sha256 -nodes -days 10 -key "$CERT_DIR/ca.key" \
        -out "$CERT_DIR/ca.pem" \
        -subj "/O=Test Root CA/" \
        -config "$CERT_DIR/cert_config.txt" \
        -extensions v3_ca 2>/dev/null

    # Generate server key and certificate
    openssl ecparam -name prime256v1 -genkey -out "$CERT_DIR/priv.key"
    openssl req -out "$CERT_DIR/cert.csr" -new -key "$CERT_DIR/priv.key" -nodes \
        -subj "/O=Test Server/" 2>/dev/null
    
    openssl x509 -req -sha256 -days 10 -in "$CERT_DIR/cert.csr" \
        -out "$CERT_DIR/cert.pem" \
        -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
        -extfile <(printf "subjectAltName=DNS:server,DNS:server4,DNS:server6,DNS:server46,IP:10.0.0.2") \
        2>/dev/null
    
    rm -f "$CERT_DIR/cert.csr" "$CERT_DIR"/*.srl
    
    echo "✓ Certificates generated in $CERT_DIR"
else
    echo "✓ Using existing certificates in $CERT_DIR"
fi

# Step 2: Set UDP buffers on host (for WSL2/Linux)
echo ""
echo "Configuring UDP buffers on host..."
if [ "$(uname -s)" = "Linux" ]; then
    # Try to set, may need sudo
    if sudo -n true 2>/dev/null; then
        sudo sysctl -w net.core.rmem_max=268435456 || echo "⚠ Could not set rmem_max (may need sudo)"
        sudo sysctl -w net.core.wmem_max=268435456 || echo "⚠ Could not set wmem_max (may need sudo)"
        sudo sysctl -w net.core.rmem_default=67108864 || echo "⚠ Could not set rmem_default"
        sudo sysctl -w net.core.wmem_default=67108864 || echo "⚠ Could not set wmem_default"
        echo "✓ UDP buffers configured"
    else
        echo "⚠ Cannot set UDP buffers without sudo. Performance may be limited."
        echo "  Run: sudo sysctl -w net.core.rmem_max=268435456"
        echo "       sudo sysctl -w net.core.wmem_max=268435456"
    fi
else
    echo "⚠ Not on Linux, skipping host UDP buffer config"
fi

# Step 3: Build optimized image if needed
IMAGE_NAME="quic-go-streaming-optimized:latest"
echo ""
echo "Checking for Docker image: $IMAGE_NAME"
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Building optimized QUIC streaming image..."
    
    # Create build directory
    BUILD_DIR="./build_optimized"
    mkdir -p "$BUILD_DIR"
    
    # Copy files (assuming they're in current directory or you'll need to adjust paths)
    cp client-optimized.go "$BUILD_DIR/client.go" 2>/dev/null || \
        echo "⚠ client-optimized.go not found, using client.go" && cp client.go "$BUILD_DIR/client.go"
    cp server-optimized.go "$BUILD_DIR/server.go" 2>/dev/null || \
        echo "⚠ server-optimized.go not found, using server.go" && cp server.go "$BUILD_DIR/server.go"
    cp run_endpoint_bypass.sh "$BUILD_DIR/run_endpoint.sh" 2>/dev/null || \
        cp run_endpoint.sh "$BUILD_DIR/run_endpoint.sh"
    
    # Copy or use existing Dockerfile
    if [ -f "Dockerfile" ]; then
        cp Dockerfile "$BUILD_DIR/"
    fi
    
    cd "$BUILD_DIR"
    docker build -t "$IMAGE_NAME" .
    cd ..
    echo "✓ Image built"
else
    echo "✓ Image already exists"
fi

# Step 4: Set environment variables
export CLIENT="$IMAGE_NAME"
export SERVER="$IMAGE_NAME"
export CERTS="$(pwd)/$CERT_DIR"
export TRANSFER_DURATION="${TRANSFER_DURATION:-10}"

echo ""
echo "=== Test Configuration ==="
echo "CLIENT: $CLIENT"
echo "SERVER: $SERVER"
echo "CERTS: $CERTS"
echo "DURATION: ${TRANSFER_DURATION}s"
echo ""

# Step 5: Run the test
echo "=== Starting Bypass Test (no simulator) ==="
echo "Press Ctrl+C to stop"
echo ""

# Save compose file if it doesn't exist
if [ ! -f "docker-compose.yml" ]; then
    cat > docker-compose.yml << 'EOFCOMPOSE'
services:
  server:
    image: ${SERVER}
    container_name: server_direct
    hostname: server
    stdin_open: true
    tty: true
    volumes:
      - ${CERTS}:/certs:ro
    environment:
      - ROLE=server
      - TRANSFER_DURATION=${TRANSFER_DURATION:-10}
      - SSLKEYLOGFILE=/logs/keys.log
    cap_add:
      - NET_ADMIN
    networks:
      directnet:
        ipv4_address: 10.0.0.2
    extra_hosts:
      - "server4:10.0.0.2"

  client:
    image: ${CLIENT}
    container_name: client_direct
    hostname: client
    stdin_open: true
    tty: true
    volumes:
      - ${CERTS}:/certs:ro
    environment:
      - ROLE=client
      - TRANSFER_DURATION=${TRANSFER_DURATION:-10}
      - SSLKEYLOGFILE=/logs/keys.log
    depends_on:
      - server
    cap_add:
      - NET_ADMIN
    networks:
      directnet:
        ipv4_address: 10.0.0.3
    extra_hosts:
      - "server4:10.0.0.2"

networks:
  directnet:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.enable_ip_masquerade: 'false'
    ipam:
      config:
        - subnet: 10.0.0.0/24
EOFCOMPOSE
fi

docker-compose -f docker-compose.yml up --remove-orphans

echo ""
echo "=== Test Complete ==="