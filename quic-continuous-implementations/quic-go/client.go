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

const readBufferSize = 1024 * 1024 // 1MB read buffer

func main() {
	// Get server address from REQUESTS environment variable
	// Format: https://server4:443/file (we only care about the host)
	serverAddr := "server4:443"

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

	// Get duration from environment (default to 10 seconds if not set)
	durationStr := os.Getenv("TRANSFER_DURATION")
	duration := 10 * time.Second
	if durationStr != "" {
		seconds, err := strconv.Atoi(durationStr)
		if err == nil && seconds > 0 {
			duration = time.Duration(seconds) * time.Second
		}
	}

	log.Printf("Starting QUIC streaming client, connecting to %s, duration: %v", serverAddr, duration)

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
		InsecureSkipVerify: true, // Accept self-signed certs from simulator
		NextProtos:         []string{"quic-streaming"},
		KeyLogWriter:       keyLog,
	}

	// Connect to server
	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, serverAddr, tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	log.Printf("Connected to server")

	log.Printf("Starting to receive data for %v", duration)

	numStreams := 4 // adjust to 4–8 or more depending on CPU/link
	var wg sync.WaitGroup
	totalBytes := int64(0)
	var totalBytesMutex sync.Mutex
	startTime := time.Now()

	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				log.Printf("Failed to open stream: %v", err)
				return
			}
			defer stream.Close()

			// Send dummy byte to signal ready
			stream.Write([]byte{0x01})

			buffer := make([]byte, readBufferSize)
			for time.Since(startTime) < duration {
				n, err := stream.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Printf("Read error: %v", err)
					}
					break
				}
				totalBytesMutex.Lock()
				totalBytes += int64(n)
				totalBytesMutex.Unlock()
			}
		}()
	}

	// Wait for all streams to finish
	wg.Wait()

	elapsed := time.Since(startTime)
	log.Printf("Transfer complete: %d bytes received in %v (%.2f Mbps)",
		totalBytes, elapsed, float64(totalBytes*8)/(elapsed.Seconds()*1e6))


	// Exit with success
	os.Exit(0)
}