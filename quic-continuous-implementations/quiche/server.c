#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <quiche.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_DATAGRAM_SIZE 1350
#define BUFFER_SIZE (1024 * 1024)
#define LOCAL_CONN_ID_LEN 16

unsigned char data_buffer[BUFFER_SIZE];
int duration_seconds = 10;

int main(int argc, char** argv) {
    // Get duration from environment
    const char* duration_env = getenv("TRANSFER_DURATION");
    if (duration_env) {
        duration_seconds = atoi(duration_env);
        if (duration_seconds <= 0) duration_seconds = 10;
    }

    printf("Starting quiche streaming server on :443, duration: %ds\n",
           duration_seconds);

    // Initialize data buffer
    memset(data_buffer, 0xaa, BUFFER_SIZE);

    // Create socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    printf("Server listening on port 443\n");

    // Create quiche config
    quiche_config* config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (!config) {
        fprintf(stderr, "Failed to create config\n");
        return 1;
    }

    quiche_config_load_cert_chain_from_pem_file(config, "/certs/cert.pem");
    quiche_config_load_priv_key_from_pem_file(config, "/certs/priv.key");
    quiche_config_set_application_protos(config, (uint8_t*)"\x0fquic-streaming",
                                         16);
    quiche_config_set_max_idle_timeout(config, 30000);
    quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_cc_algorithm(config, QUICHE_CC_RENO);

    // Enable keylogging if SSLKEYLOGFILE is set
    const char* keylog_path = getenv("SSLKEYLOGFILE");
    if (keylog_path) {
        quiche_config_log_keys(config);
        printf("TLS key logging enabled\n");
    }

    // Main server loop
    uint8_t buf[65535];
    uint8_t out[MAX_DATAGRAM_SIZE];

    quiche_conn* conn = NULL;
    time_t start_time = 0;
    size_t bytes_sent = 0;
    uint64_t stream_id = 0;
    int stream_started = 0;
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len;

    while (1) {
        peer_addr_len = sizeof(peer_addr);

        ssize_t read = recvfrom(sock, buf, sizeof(buf), 0,
                                (struct sockaddr*)&peer_addr, &peer_addr_len);

        if (read < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                if (conn && stream_started) {
                    goto send_data;
                }
                continue;
            }
            perror("recvfrom");
            break;
        }

        uint8_t type;
        uint32_t version;
        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);
        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);
        uint8_t token[256];
        size_t token_len = sizeof(token);

        int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            fprintf(stderr, "Failed to parse header: %d\n", rc);
            continue;
        }

        if (!conn) {
            // New connection
            conn = quiche_accept(
                dcid, dcid_len, NULL, 0, (struct sockaddr*)&addr, sizeof(addr),
                (struct sockaddr*)&peer_addr, peer_addr_len, config);
            if (!conn) {
                fprintf(stderr, "Failed to create connection\n");
                continue;
            }

            printf("New connection from %s:%d\n", inet_ntoa(peer_addr.sin_addr),
                   ntohs(peer_addr.sin_port));
        }

        if (keylog_path) {
                quiche_conn_set_keylog_path(conn, keylog_path);
        }

        // Process packet
        quiche_recv_info recv_info = {
            .from = (struct sockaddr*)&peer_addr,
            .from_len = peer_addr_len,
            .to = (struct sockaddr*)&addr,
            .to_len = sizeof(addr),
        };

        ssize_t done = quiche_conn_recv(conn, buf, read, &recv_info);
        if (done < 0 && done != QUICHE_ERR_DONE) {
            fprintf(stderr, "Failed to process packet: %zd\n", done);
        }

        // Check if connection is established
        if (quiche_conn_is_established(conn) && !stream_started) {
            quiche_stream_iter* readable = quiche_conn_readable(conn);
            if (quiche_stream_iter_next(readable, &stream_id)) {
                uint8_t req_buf[1024];
                bool fin = false;
                ssize_t recv_len = quiche_conn_stream_recv(
                    conn, stream_id, req_buf, sizeof(req_buf), &fin);
                if (recv_len > 0) {
                    printf("Received client request, starting data transfer\n");
                    start_time = time(NULL);
                    bytes_sent = 0;
                    stream_started = 1;
                }
            }
            quiche_stream_iter_free(readable);
        }

    send_data:
        // Send data if stream is active
        if (stream_started &&
            difftime(time(NULL), start_time) < duration_seconds) {
            ssize_t sent = quiche_conn_stream_send(conn, stream_id, data_buffer,
                                                   BUFFER_SIZE, false);
            if (sent > 0) {
                bytes_sent += sent;
            }
        } else if (stream_started &&
                   difftime(time(NULL), start_time) >= duration_seconds) {
            // Done, close stream
            double elapsed = difftime(time(NULL), start_time);
            double mbps = (bytes_sent * 8.0) / (elapsed * 1000000.0);
            printf("Transfer complete: %zu bytes in %.2f s (%.2f Mbps)\n",
                   bytes_sent, elapsed, mbps);

            quiche_conn_stream_send(conn, stream_id, (uint8_t*)"", 0, true);
            stream_started = 0;
        }

        // Send packets
        quiche_send_info send_info;
        while (1) {
            ssize_t written =
                quiche_conn_send(conn, out, sizeof(out), &send_info);
            if (written == QUICHE_ERR_DONE) {
                break;
            }

            if (written < 0) {
                fprintf(stderr, "Failed to create packet: %zd\n", written);
                break;
            }

            ssize_t sent =
                sendto(sock, out, written, 0, (struct sockaddr*)&send_info.to,
                       send_info.to_len);
            if (sent != written) {
                perror("sendto");
                break;
            }
        }

        // Check if connection is closed
        if (quiche_conn_is_closed(conn)) {
            printf("Connection closed\n");
            quiche_conn_free(conn);
            conn = NULL;
            stream_started = 0;
        }
    }

    if (conn) quiche_conn_free(conn);
    quiche_config_free(config);
    close(sock);

    return 0;
}