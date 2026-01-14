package main

import (
	"crypto/tls"
	"log"
	"net" // Need this for net.Dial
	"os"
	"sync"
	"time"
)

func main() {
	serverAddr := "server4:443"
	durationStr := os.Getenv("TRANSFER_DURATION")
	duration, _ := time.ParseDuration(durationStr + "s")
	if duration == 0 {
		duration = 10 * time.Second
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
	}

	start := time.Now()
	var wg sync.WaitGroup

	log.Printf("Starting TCP+TLS client to %s for %v", serverAddr, duration)

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// 1. Create a raw TCP connection first
			rawConn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
			if err != nil {
				log.Printf("Dial error: %v", err)
				return
			}

			// 2. SET THE BUFFERS HERE
			// We cast the net.Conn to a *net.TCPConn to access socket options
			if tcpConn, ok := rawConn.(*net.TCPConn); ok {
				// 8MB is usually enough for a 1Gbps/30ms BDP
				tcpConn.SetReadBuffer(8 * 1024 * 1024)
				tcpConn.SetWriteBuffer(8 * 1024 * 1024)
				tcpConn.SetNoDelay(true) // Disable Nagle's algorithm for faster streaming
			}

			// 3. Wrap the raw connection in TLS
			conn := tls.Client(rawConn, tlsConf)
			err = conn.Handshake()
			if err != nil {
				log.Printf("TLS Handshake error: %v", err)
				rawConn.Close()
				return
			}
			defer conn.Close()

			// Ready signal
			conn.Write([]byte{0x01})

			buf := make([]byte, 1024*1024)
			for time.Since(start) < duration {
				_, err := conn.Read(buf)
				if err != nil {
					break
				}
			}
		}()
	}
	wg.Wait()
	log.Printf("Client finished transfer after %v", time.Since(start))
}