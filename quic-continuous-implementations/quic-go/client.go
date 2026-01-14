package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	readBufferSize = 4 * 1024 * 1024 // 4MB buffer - larger for high BDP
)

func main() {
	serverAddr := "server4:443"

	// CRITICAL: Aggressive QUIC config for high throughput
	quicConfig := &quic.Config{
		MaxIncomingStreams:    1024,
		MaxIncomingUniStreams: 0,
		MaxIdleTimeout:        0,
		KeepAlivePeriod:       10 * time.Second,
		
		// CRITICAL: Large flow control windows for high BDP
		InitialStreamReceiveWindow:     10 * 1024 * 1024,  // 10MB per stream
		MaxStreamReceiveWindow:         100 * 1024 * 1024, // 100MB max per stream
		InitialConnectionReceiveWindow: 15 * 1024 * 1024,  // 15MB connection
		MaxConnectionReceiveWindow:     100 * 1024 * 1024, // 100MB max connection
		
		DisablePathMTUDiscovery: false,
		EnableDatagrams:         false,
		HandshakeIdleTimeout:    30 * time.Second,
	}

	durationStr := os.Getenv("TRANSFER_DURATION")
	duration := 10 * time.Second
	if durationStr != "" {
		if seconds, err := strconv.Atoi(durationStr); err == nil && seconds > 0 {
			duration = time.Duration(seconds) * time.Second
		}
	}

	log.Printf("Starting optimized QUIC client, connecting to %s, duration: %v", serverAddr, duration)

	var keyLog io.Writer
	if keyLogFile := os.Getenv("SSLKEYLOGFILE"); keyLogFile != "" {
		if f, err := os.OpenFile(keyLogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600); err == nil {
			keyLog = f
			defer f.Close()
		}
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-streaming"},
		KeyLogWriter:       keyLog,
	}

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, serverAddr, tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	log.Printf("Connected to server")

	// Use atomic operations instead of mutex - MUCH faster
	var totalBytes atomic.Int64
	
	// Optimal number of streams for high throughput
	numStreams := 8
	
	startTime := time.Now()
	done := make(chan struct{})
	
	// Timer goroutine
	go func() {
		time.Sleep(duration)
		close(done)
	}()

	// Stream workers
	streamsDone := make(chan struct{})
	for i := 0; i < numStreams; i++ {
		go func(id int) {
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				log.Printf("Stream %d: Failed to open: %v", id, err)
				return
			}
			defer stream.Close()

			// Signal ready
			stream.Write([]byte{0x01})

			// Per-goroutine buffer to avoid allocations
			buffer := make([]byte, readBufferSize)
			localBytes := int64(0)

			for {
				select {
				case <-done:
					totalBytes.Add(localBytes)
					return
				default:
					// Non-blocking read with deadline
					stream.SetReadDeadline(time.Now().Add(1 * time.Second))
					n, err := stream.Read(buffer)
					if n > 0 {
						localBytes += int64(n)
					}
					if err != nil {
						if err != io.EOF && !isTimeoutError(err) {
							log.Printf("Stream %d: Read error: %v", id, err)
						}
						totalBytes.Add(localBytes)
						return
					}
				}
			}
		}(i)
	}

	// Wait for timer
	<-done
	time.Sleep(100 * time.Millisecond) // Grace period for final accounting
	close(streamsDone)

	elapsed := time.Since(startTime)
	finalBytes := totalBytes.Load()
	throughputMbps := float64(finalBytes*8) / (elapsed.Seconds() * 1e6)

	log.Printf("Transfer complete: %d bytes in %v (%.2f Mbps)",
		finalBytes, elapsed, throughputMbps)

	os.Exit(0)
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	// Check if it's a timeout error
	return err.Error() == "deadline exceeded" || 
	       err.Error() == "i/o timeout"
}