FROM martenseemann/quic-network-simulator-endpoint:latest

# Install Rust and build dependencies
RUN apt-get update && \
    apt-get install -y \
        curl \
        git \
        build-essential \
        cmake \
        libssl-dev \
        pkg-config && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:${PATH}"

# Clone and build quiche
WORKDIR /quiche
RUN git clone --recursive --depth 1 --branch 0.20.1 https://github.com/cloudflare/quiche.git . && \
    cargo build --release --features ffi,pkg-config-meta,qlog

# Copy our streaming implementations
WORKDIR /app
COPY server.c .
COPY client.c .

# Build the streaming binaries
RUN gcc -o streaming-server server.c \
    -I/quiche/quiche/include \
    -L/quiche/target/release \
    -lquiche \
    -lpthread \
    -ldl \
    -lm && \
    gcc -o streaming-client client.c \
    -I/quiche/quiche/include \
    -L/quiche/target/release \
    -lquiche \
    -lpthread \
    -ldl \
    -lm

# Set library path
ENV LD_LIBRARY_PATH=/quiche/target/release

# Copy run script
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT ["./run_endpoint.sh"]