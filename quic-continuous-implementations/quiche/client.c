#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <quiche.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MAX_DATAGRAM_SIZE 1350
#define BUFFER_SIZE (1024 * 1024)
#define CHUNK_SIZE (16 * 1024)
#define LOCAL_CONN_ID_LEN 16

unsigned char data_buffer[BUFFER_SIZE];
int duration_seconds = 10;

static uint64_t get_time_usec(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

int main(int argc, char** argv) {
    const char* duration_env = getenv("TRANSFER_DURATION");
    if (duration_env) {
        duration_seconds = atoi(duration_env);
        if (duration_seconds <= 0) duration_seconds = 10;
    }

    printf("Starting quiche streaming server on :443, duration: %ds\n",
           duration_seconds);

    memset(data_buffer, 0xaa, BUFFER_SIZE);

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
    quiche_config_enable_pacing(config, true);

    const char* keylog_path = getenv("SSLKEYLOGFILE");
    if (keylog_path) {
        quiche_config_log_keys(config);
        printf("TLS key logging enabled\n");
    }

    uint8_t buf[65535];
    uint8_t out[MAX_DATAGRAM_SIZE];

    quiche_conn* conn = NULL;
    uint64_t start_time_us = 0;
    size_t bytes_sent = 0;
    uint64_t stream_id = 0;
    int stream_started = 0;
    int fin_sent = 0;
    uint64_t next_send_us = 0;
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len;

    while (1) {
        peer_addr_len = sizeof(peer_addr);

        // Respect quiche's send timing
        uint64_t now_us = get_time_usec();
        if (conn) {
            uint64_t timeout_ns = quiche_conn_timeout_as_nanos(conn);
            if (timeout_ns > 0) {
                uint64_t timeout_us = timeout_ns / 1000;
                if (next_send_us == 0 || timeout_us < next_send_us) {
                    next_send_us = now_us + timeout_us;
                }
            }
        }

        // Non-blocking receive
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        struct timeval tv;
        if (next_send_us > 0 && next_send_us > now_us) {
            uint64_t wait_us = next_send_us - now_us;
            tv.tv_sec = wait_us / 1000000;
            tv.tv_usec = wait_us % 1000000;
        } else {
            tv.tv_sec = 0;
            tv.tv_usec = 1000;
        }

        int ret = select(sock + 1, &readfds, NULL, NULL, &tv);

        if (ret > 0) {
            ssize_t read = recvfrom(sock, buf, sizeof(buf), 0,
                                    (struct sockaddr*)&peer_addr, &peer_addr_len);

            if (read > 0) {
                uint8_t type;
                uint32_t version;
                uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
                size_t scid_len = sizeof(scid);
                uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
                size_t dcid_len = sizeof(dcid);
                uint8_t token[256];
                size_t token_len = sizeof(token);

                int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN,
                                            &version, &type, scid, &scid_len,
                                            dcid, &dcid_len, token, &token_len);
                if (rc < 0) {
                    fprintf(stderr, "Failed to parse header: %d\n", rc);
                    continue;
                }

                if (!conn) {
                    conn = quiche_accept(dcid, dcid_len, NULL, 0,
                                         (struct sockaddr*)&addr, sizeof(addr),
                                         (struct sockaddr*)&peer_addr,
                                         peer_addr_len, config);
                    if (!conn) {
                        fprintf(stderr, "Failed to create connection\n");
                        continue;
                    }

                    printf("New connection from %s:%d\n",
                           inet_ntoa(peer_addr.sin_addr),
                           ntohs(peer_addr.sin_port));

                    if (keylog_path) {
                        quiche_conn_set_keylog_path(conn, keylog_path);
                    }
                }

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

                // Check for client request
                if (quiche_conn_is_established(conn) && !stream_started) {
                    quiche_stream_iter* readable = quiche_conn_readable(conn);
                    if (quiche_stream_iter_next(readable, &stream_id)) {
                        uint8_t req_buf[1024];
                        bool fin = false;
                        ssize_t recv_len = quiche_conn_stream_recv(
                            conn, stream_id, req_buf, sizeof(req_buf), &fin);
                        if (recv_len > 0) {
                            printf("Received client request, starting data transfer\n");
                            start_time_us = get_time_usec();
                            bytes_sent = 0;
                            stream_started = 1;
                        }
                    }
                    quiche_stream_iter_free(readable);
                }
            }
        }

        if (!conn) continue;

        now_us = get_time_usec();

        // Send data: ONE chunk per send opportunity
        if (stream_started && !fin_sent) {
            uint64_t elapsed_us = now_us - start_time_us;
            double elapsed_sec = elapsed_us / 1000000.0;

            if (elapsed_sec < duration_seconds) {
                // Check connection-level send readiness
                if (quiche_conn_is_established(conn)) {
                    // Attempt to send packets first (drain any queued frames)
                    quiche_send_info send_info;
                    ssize_t written = quiche_conn_send(conn, out, sizeof(out), &send_info);
                    
                    // Only write more stream data if conn is ready
                    if (written != QUICHE_ERR_DONE) {
                        if (written > 0) {
                            sendto(sock, out, written, 0,
                                   (struct sockaddr*)&send_info.to, send_info.to_len);
                        }
                    } else if (quiche_conn_stream_writable(conn, stream_id, CHUNK_SIZE)) {
                        // Write ONE chunk, no loop
                        ssize_t sent = quiche_conn_stream_send(
                            conn, stream_id, data_buffer, CHUNK_SIZE, false);

                        if (sent > 0) {
                            bytes_sent += sent;
                        } else if (sent < 0 && sent != QUICHE_ERR_DONE) {
                            fprintf(stderr, "Stream send error: %zd\n", sent);
                        }
                    }
                }
            } else {
                // Duration expired: drain before FIN
                fin_sent = 1;
                printf("Duration expired, draining buffers before FIN\n");
            }
        }

        // If FIN requested, drain all packets first
        if (fin_sent && !quiche_conn_stream_finished(conn, stream_id)) {
            quiche_send_info send_info;
            int drained = 0;

            while (1) {
                ssize_t written = quiche_conn_send(conn, out, sizeof(out), &send_info);
                if (written == QUICHE_ERR_DONE) {
                    break;
                }
                if (written > 0) {
                    sendto(sock, out, written, 0,
                           (struct sockaddr*)&send_info.to, send_info.to_len);
                    drained = 1;
                }
            }

            // Only send FIN after drain attempt
            if (!drained && quiche_conn_stream_writable(conn, stream_id, 1)) {
                ssize_t fin_result = quiche_conn_stream_send(conn, stream_id, (uint8_t*)"", 0, true);
                if (fin_result >= 0 || fin_result == QUICHE_ERR_DONE) {
                    double elapsed = (now_us - start_time_us) / 1000000.0;
                    double mbps = (bytes_sent * 8.0) / (elapsed * 1000000.0);
                    printf("Transfer complete: %zu bytes in %.2f s (%.2f Mbps)\n",
                           bytes_sent, elapsed, mbps);
                }
            }
        }

        // Flush any remaining packets
        if (conn) {
            quiche_send_info send_info;
            while (1) {
                ssize_t written = quiche_conn_send(conn, out, sizeof(out), &send_info);
                if (written == QUICHE_ERR_DONE) {
                    break;
                }
                if (written < 0) {
                    break;
                }
                if (written > 0) {
                    sendto(sock, out, written, 0,
                           (struct sockaddr*)&send_info.to, send_info.to_len);
                }
            }
        }

        // Update next send time based on quiche timeout
        if (conn) {
            quiche_conn_on_timeout(conn);
        }

        // Exit if connection closed
        if (conn && quiche_conn_is_closed(conn)) {
            printf("Connection closed, exiting\n");
            break;
        }
    }

    if (conn) quiche_conn_free(conn);
    quiche_config_free(config);
    close(sock);

    return 0;
}