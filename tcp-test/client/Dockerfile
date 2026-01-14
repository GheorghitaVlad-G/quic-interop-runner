FROM martenseemann/quic-network-simulator-endpoint:latest

RUN apt-get update && apt-get install -y wget iperf3 && \
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

ENV PATH="${PATH}:/usr/local/go/bin"

WORKDIR /app
COPY client.go .
RUN go mod init streaming && go build -o streaming-client client.go

COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]