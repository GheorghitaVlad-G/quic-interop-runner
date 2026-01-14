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
	bufferSize = 4 * 1024 * 1024 // 4MB buffer for writes
)

var dataBuffer []byte

func init() {
	dataBuffer = make([]byte, bufferSize)
	for i := range dataBuffer {
		dataBuffer[i] = 0xaa
	}
}

func main() {
	cert, err := tls.LoadX509KeyPair("/certs/cert.pem", "/certs/priv.key")
	if err != nil {
		log.Fatal(err)
	}

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

	var keyLog io.Writer
	if keyLogFile := os.Getenv("SSLKEYLOGFILE"); keyLogFile != "" {
		if f, err := os.OpenFile(keyLogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600); err == nil {
			keyLog = f
			defer f.Close()
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-streaming"},
		KeyLogWriter: keyLog,
	}

	durationStr := os.Getenv("TRANSFER_DURATION")
	duration := 10 * time.Second
	if durationStr != "" {
		if seconds, err := strconv.Atoi(durationStr); err == nil && seconds > 0 {
			duration = time.Duration(seconds) * time.Second
		}
	}

	log.Printf("Starting optimized QUIC server on :443, duration: %v", duration)

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

	var totalBytes atomic.Int64
	startTime := time.Now()
	
	// Global timer channel
	done := make(chan struct{})
	go func() {
		time.Sleep(duration)
		close(done)
	}()

	// Accept streams and spawn writers
	go func() {
		for {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}

			go func(s quic.Stream) {
				defer s.Close()
				
				// Wait for client ready signal
				readBuf := make([]byte, 1)
				s.Read(readBuf)
				
				localBytes := int64(0)
				
				// Tight write loop - check timer less frequently
				writeCount := 0
				for {
					select {
					case <-done:
						totalBytes.Add(localBytes)
						return
					default:
						n, err := s.Write(dataBuffer)
						if err != nil {
							totalBytes.Add(localBytes)
							return
						}
						localBytes += int64(n)
						writeCount++
						
						// Only check time every 100 writes (400MB) to reduce overhead
						if writeCount%100 == 0 {
							if time.Since(startTime) >= duration {
								totalBytes.Add(localBytes)
								return
							}
						}
					}
				}
			}(stream)
		}
	}()

	// Wait for duration
	<-done
	time.Sleep(200 * time.Millisecond) // Grace period

	elapsed := time.Since(startTime)
	finalBytes := totalBytes.Load()
	throughputMbps := float64(finalBytes*8) / (elapsed.Seconds() * 1e6)

	log.Printf("Transfer complete: %d bytes in %v (%.2f Mbps)",
		finalBytes, elapsed, throughputMbps)
}