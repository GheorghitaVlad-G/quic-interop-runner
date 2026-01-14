package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"os"
	"strconv"
	"time"
	"sync"

	"github.com/quic-go/quic-go"
)

const bufferSize = 1024 * 1024 // 1MB buffer of 0xaa

var dataBuffer []byte

func init() {
	// Pre-allocate buffer filled with 0xaa pattern
	dataBuffer = make([]byte, bufferSize)
	for i := range dataBuffer {
		dataBuffer[i] = 0xaa
	}
}

func main() {
	// Load TLS certificates
	cert, err := tls.LoadX509KeyPair("/certs/cert.pem", "/certs/priv.key")
	if err != nil {
		log.Fatal(err)
	}

	// Setup QUIC config
	quicConfig := &quic.Config{
		// You are not multiplexing requests, you are shoveling bytes
		MaxIncomingStreams:    1024,
		MaxIncomingUniStreams: 0,

		// Prevent the connection from idling out mid-test
		MaxIdleTimeout:       0,
		KeepAlivePeriod:      10 * time.Second,

		// Let QUIC discover MTU, don’t cripple it
		DisablePathMTUDiscovery: false,

		// Avoid tiny initial packets in the simulator

		// You don’t need QUIC datagrams
		EnableDatagrams:      false,

		// Don’t artificially throttle CPU scheduling
		HandshakeIdleTimeout: 30 * time.Second,
	}

	// Setup key logging if SSLKEYLOGFILE is set
	var keyLog io.Writer
	keyLogFile := os.Getenv("SSLKEYLOGFILE")
	if keyLogFile != "" {
		f, err := os.OpenFile(keyLogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Printf("Warning: Failed to open keylog file: %v", err)
		} else {
			keyLog = f
			defer f.Close()
			log.Printf("TLS keys will be logged to %s", keyLogFile)
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-streaming"},
		KeyLogWriter: keyLog,
	}

	// Get duration from environment (default to 10 seconds if not set)
	durationStr := os.Getenv("TRANSFER_DURATION")
	duration := 10 * time.Second
	if durationStr != "" {
		seconds, err := strconv.Atoi(durationStr)
		if err == nil && seconds > 0 {
			duration = time.Duration(seconds) * time.Second
		}
	}

	log.Printf("Starting QUIC streaming server on :443, duration: %v", duration)

	// Setup QUIC listener
	listener, err := quic.ListenAddr(":443", tlsConfig, quicConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleConnection(conn, duration)
	}
}

func handleConnection(conn quic.Connection, duration time.Duration) {
    defer conn.CloseWithError(0, "done")
    log.Printf("New connection from %s", conn.RemoteAddr())

    startTime := time.Now()
    totalBytes := int64(0)
    var totalBytesMutex sync.Mutex

    // Accept streams until the connection closes
    for {
        stream, err := conn.AcceptStream(context.Background())
        if err != nil {
            log.Printf("AcceptStream error: %v", err)
            break
        }

        go func(s quic.Stream) {
            defer s.Close()
            for time.Since(startTime) < duration {
                n, err := s.Write(dataBuffer)
                if err != nil {
                    break
                }
                totalBytesMutex.Lock()
                totalBytes += int64(n)
                totalBytesMutex.Unlock()
            }
        }(stream)
    }

    // Wait until duration is done
    for time.Since(startTime) < duration {
        time.Sleep(100 * time.Millisecond)
    }

    elapsed := time.Since(startTime)
    log.Printf("Transfer complete: %d bytes in %v (%.2f Mbps)",
        totalBytes, elapsed, float64(totalBytes*8)/(elapsed.Seconds()*1e6))
}
