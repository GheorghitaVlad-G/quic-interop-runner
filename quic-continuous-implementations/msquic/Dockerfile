FROM martenseemann/quic-network-simulator-endpoint:latest

# Install dependencies for msquic
RUN apt-get update && \
    apt-get install -y \
        cmake \
        build-essential \
        git \
        libssl-dev \
        liblttng-ust-dev \
        lttng-tools \
        libnuma-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Clone and build msquic
WORKDIR /msquic
RUN git clone --recursive --depth 1 --branch v2.3.5 https://github.com/microsoft/msquic.git . && \
    mkdir build && \
    cd build && \
    cmake -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=Release .. && \
    cmake --build . --config Release

# Copy our streaming implementations
WORKDIR /app
COPY server.c .
COPY client.c .

# Build the streaming binaries
RUN gcc -o streaming-server server.c \
    -I/msquic/src/inc \
    -L/msquic/build/bin/Release \
    -lmsquic \
    -lpthread \
    -ldl \
    -lm && \
    gcc -o streaming-client client.c \
    -I/msquic/src/inc \
    -L/msquic/build/bin/Release \
    -lmsquic \
    -lpthread \
    -ldl \
    -lm

# Set library path
ENV LD_LIBRARY_PATH=/msquic/build/bin/Release

# Copy run script
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT ["./run_endpoint.sh"]