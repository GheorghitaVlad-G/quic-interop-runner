#include <arpa/inet.h>
#include <msquic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

const QUIC_API_TABLE* MsQuic = NULL;
HQUIC Registration = NULL;
HQUIC Configuration = NULL;

int duration_seconds = 10;
volatile int connection_complete = 0;
volatile int stream_complete = 0;

typedef struct {
    HQUIC Connection;
    HQUIC Stream;
    time_t start_time;
    size_t bytes_received;
} CLIENT_CONTEXT;

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ClientStreamCallback(_In_ HQUIC Stream, _In_opt_ void* Context,
                         _Inout_ QUIC_STREAM_EVENT* Event) {
    CLIENT_CONTEXT* ctx = (CLIENT_CONTEXT*)Context;

    switch (Event->Type) {
        case QUIC_STREAM_EVENT_START_COMPLETE:
            printf("Stream started\n");
            break;

        case QUIC_STREAM_EVENT_RECEIVE:
            // Receive and discard data
            ctx->bytes_received += Event->RECEIVE.TotalBufferLength;

            // Check if duration exceeded
            if (difftime(time(NULL), ctx->start_time) >= duration_seconds) {
                MsQuic->StreamShutdown(Stream,
                                       QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
            }
            break;

        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            printf("Server finished sending\n");
            break;

        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
            double elapsed = difftime(time(NULL), ctx->start_time);
            double mbps = (ctx->bytes_received * 8.0) / (elapsed * 1000000.0);
            printf(
                "Transfer complete: %zu bytes received in %.2f s (%.2f Mbps)\n",
                ctx->bytes_received, elapsed, mbps);

            MsQuic->StreamClose(Stream);
            stream_complete = 1;
        } break;

        default:
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    ClientConnectionCallback(_In_ HQUIC Connection, _In_opt_ void* Context,
                             _Inout_ QUIC_CONNECTION_EVENT* Event) {
    CLIENT_CONTEXT* ctx = (CLIENT_CONTEXT*)Context;

    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            printf("Connected to server\n");
            connection_complete = 1;

            // Open stream
            if (QUIC_FAILED(MsQuic->StreamOpen(
                    Connection, QUIC_STREAM_OPEN_FLAG_NONE,
                    ClientStreamCallback, ctx, &ctx->Stream))) {
                printf("StreamOpen failed\n");
                return QUIC_STATUS_INTERNAL_ERROR;
            }

            // Start stream
            if (QUIC_FAILED(MsQuic->StreamStart(ctx->Stream,
                                                QUIC_STREAM_START_FLAG_NONE))) {
                printf("StreamStart failed\n");
                return QUIC_STATUS_INTERNAL_ERROR;
            }

            // Send dummy request
            const char* request = "GET /\n";
            QUIC_BUFFER Buffer;
            Buffer.Buffer = (uint8_t*)request;
            Buffer.Length = strlen(request);

            ctx->start_time = time(NULL);
            ctx->bytes_received = 0;

            MsQuic->StreamSend(ctx->Stream, &Buffer, 1, QUIC_SEND_FLAG_NONE,
                               NULL);
            break;

        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            MsQuic->ConnectionClose(Connection);
            break;

        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            // Not expected in client
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

    printf(
        "Starting msquic streaming client, connecting to server4:443, "
        "duration: %ds\n",
        duration_seconds);

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

    // Create configuration
    QUIC_SETTINGS Settings = {0};
    Settings.IdleTimeoutMs = 30000;
    Settings.IsSet.IdleTimeoutMs = TRUE;

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

    // Load client credentials (insecure for testing)
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT |
                       QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    if (QUIC_FAILED(
            MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationLoadCredential failed\n");
        goto Error;
    }

    // Create client context
    CLIENT_CONTEXT ctx = {0};

    // Create connection
    if (QUIC_FAILED(MsQuic->ConnectionOpen(
            Registration, ClientConnectionCallback, &ctx, &ctx.Connection))) {
        printf("ConnectionOpen failed\n");
        goto Error;
    }

    // Start connection
    if (QUIC_FAILED(MsQuic->ConnectionStart(ctx.Connection, Configuration,
                                            QUIC_ADDRESS_FAMILY_INET, "server4",
                                            443))) {
        printf("ConnectionStart failed\n");
        goto Error;
    }

    // Wait for stream to complete
    while (!stream_complete) {
        sleep(1);
    }

    // Cleanup
    if (ctx.Connection) {
        MsQuic->ConnectionShutdown(ctx.Connection,
                                   QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        sleep(1);
    }

    if (Configuration) MsQuic->ConfigurationClose(Configuration);
    if (Registration) MsQuic->RegistrationClose(Registration);
    if (MsQuic) MsQuicClose(MsQuic);

    printf("Client exiting\n");
    return 0;

Error:
    if (Configuration) MsQuic->ConfigurationClose(Configuration);
    if (Registration) MsQuic->RegistrationClose(Registration);
    if (MsQuic) MsQuicClose(MsQuic);

    return 1;
}