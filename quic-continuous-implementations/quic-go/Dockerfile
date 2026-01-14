FROM martenseemann/quic-network-simulator-endpoint:latest

# Install Go
RUN apt-get update && apt-get install -y wget git && \
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

ENV PATH="${PATH}:/usr/local/go/bin"
ENV GOPATH="/root/go"
ENV PATH="${PATH}:${GOPATH}/bin"

# Clone quic-go library (using latest stable version)
WORKDIR /quic-go-lib
RUN git clone --depth 1 --branch v0.40.1 https://github.com/quic-go/quic-go.git . && \
    go mod download

# Create our streaming app directory
WORKDIR /app
COPY server.go .
COPY client.go .

# Initialize go module for our streaming app
RUN go mod init streaming && \
    go mod edit -replace github.com/quic-go/quic-go=/quic-go-lib && \
    go mod tidy

# Build the streaming binaries
RUN go build -o streaming-server server.go && \
    go build -o streaming-client client.go

# Copy run script
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]