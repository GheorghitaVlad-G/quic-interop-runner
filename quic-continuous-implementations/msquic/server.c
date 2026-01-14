#include <arpa/inet.h>
#include <msquic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE (1024 * 1024)  // 1MB buffer

const QUIC_API_TABLE* MsQuic = NULL;
HQUIC Registration = NULL;
HQUIC Configuration = NULL;
unsigned char data_buffer[BUFFER_SIZE];
int duration_seconds = 10;

typedef struct {
    HQUIC Connection;
    HQUIC Stream;
    time_t start_time;
    size_t bytes_sent;
} STREAM_CONTEXT;

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ServerStreamCallback(_In_ HQUIC Stream, _In_opt_ void* Context,
                         _Inout_ QUIC_STREAM_EVENT* Event) {
    STREAM_CONTEXT* ctx = (STREAM_CONTEXT*)Context;

    switch (Event->Type) {
        case QUIC_STREAM_EVENT_START_COMPLETE:
            printf("Stream started\n");
            break;

        case QUIC_STREAM_EVENT_RECEIVE:
            // Client sent request, now we can start sending data
            printf("Received client request, starting data transfer\n");

            // Start sending data
            ctx->start_time = time(NULL);
            ctx->bytes_sent = 0;

            // Send first chunk
            QUIC_BUFFER Buffer;
            Buffer.Buffer = data_buffer;
            Buffer.Length = BUFFER_SIZE;

            MsQuic->StreamSend(Stream, &Buffer, 1, QUIC_SEND_FLAG_NONE, NULL);
            break;

        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            // Check if we should continue sending
            if (difftime(time(NULL), ctx->start_time) < duration_seconds) {
                QUIC_BUFFER Buffer;
                Buffer.Buffer = data_buffer;
                Buffer.Length = BUFFER_SIZE;

                ctx->bytes_sent += BUFFER_SIZE;
                MsQuic->StreamSend(Stream, &Buffer, 1, QUIC_SEND_FLAG_NONE,
                                   NULL);
            } else {
                // Done sending, close stream
                double elapsed = difftime(time(NULL), ctx->start_time);
                double mbps = (ctx->bytes_sent * 8.0) / (elapsed * 1000000.0);
                printf("Transfer complete: %zu bytes in %.2f s (%.2f Mbps)\n",
                       ctx->bytes_sent, elapsed, mbps);

                MsQuic->StreamShutdown(Stream,
                                       QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
            }
            break;

        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            MsQuic->StreamClose(Stream);
            free(ctx);
            break;

        default:
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    ServerConnectionCallback(_In_ HQUIC Connection, _In_opt_ void* Context,
                             _Inout_ QUIC_CONNECTION_EVENT* Event) {
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            printf("Connection established\n");
            MsQuic->ConnectionSendResumptionTicket(
                Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
            break;

        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            printf("Stream started by peer\n");

            STREAM_CONTEXT* ctx =
                (STREAM_CONTEXT*)malloc(sizeof(STREAM_CONTEXT));
            ctx->Connection = Connection;
            ctx->Stream = Event->PEER_STREAM_STARTED.Stream;
            ctx->bytes_sent = 0;

            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream,
                                       (void*)ServerStreamCallback, ctx);
            break;

        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            MsQuic->ConnectionClose(Connection);
            break;

        default:
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_LISTENER_CALLBACK) QUIC_STATUS QUIC_API
    ServerListenerCallback(_In_ HQUIC Listener, _In_opt_ void* Context,
                           _Inout_ QUIC_LISTENER_EVENT* Event) {
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection,
                                       (void*)ServerConnectionCallback, NULL);
            MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection,
                                               Configuration);
            break;

        default:
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

int main(int argc, char** argv) {
    // Get duration from environment
    const char* duration_env = getenv("TRANSFER_DURATION");
    if (duration_env) {
        duration_seconds = atoi(duration_env);
        if (duration_seconds <= 0) duration_seconds = 10;
    }

    printf("Starting msquic streaming server on :443, duration: %ds\n",
           duration_seconds);

    // Initialize data buffer with 0xaa pattern
    memset(data_buffer, 0xaa, BUFFER_SIZE);

    // Open MsQuic
    if (QUIC_FAILED(MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed\n");
        return 1;
    }

    // Create registration
    const QUIC_REGISTRATION_CONFIG RegConfig = {
        "quic-streaming", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    if (QUIC_FAILED(MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed\n");
        goto Error;
    }

    // Load certificate
    QUIC_CERTIFICATE_FILE CertFile = {"/certs/priv.key", "/certs/cert.pem"};

    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    CredConfig.CertificateFile = &CertFile;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    // Create configuration
    QUIC_SETTINGS Settings = {0};
    Settings.IdleTimeoutMs = 30000;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;

    uint8_t alpn_data[] = "quic-streaming";
    QUIC_BUFFER AlpnBuffer;
    AlpnBuffer.Buffer = alpn_data;
    AlpnBuffer.Length = sizeof(alpn_data) - 1;  // Exclude null terminator

    if (QUIC_FAILED(MsQuic->ConfigurationOpen(Registration, &AlpnBuffer, 1,
                                              &Settings, sizeof(Settings), NULL,
                                              &Configuration))) {
        printf("ConfigurationOpen failed\n");
        goto Error;
    }

    if (QUIC_FAILED(
            MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationLoadCredential failed\n");
        goto Error;
    }

    // Create listener
    HQUIC Listener = NULL;
    if (QUIC_FAILED(MsQuic->ListenerOpen(Registration, ServerListenerCallback,
                                         NULL, &Listener))) {
        printf("ListenerOpen failed\n");
        goto Error;
    }

    QUIC_ADDR Address = {0};
    Address.Ip.sa_family = AF_INET;
    Address.Ipv4.sin_port = htons(443);

    if (QUIC_FAILED(
            MsQuic->ListenerStart(Listener, &AlpnBuffer, 1, &Address))) {
        printf("ListenerStart failed\n");
        goto Error;
    }

    printf("Server listening on port 443\n");

    // Run indefinitely
    while (1) {
        sleep(1);
    }

Error:
    if (Configuration) MsQuic->ConfigurationClose(Configuration);
    if (Registration) MsQuic->RegistrationClose(Registration);
    if (MsQuic) MsQuicClose(MsQuic);

    return 1;
}