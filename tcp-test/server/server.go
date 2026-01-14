package main

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"time"
)

const bufferSize = 1024 * 1024 // 1MB chunks

func main() {
	cert, err := tls.LoadX509KeyPair("/certs/cert.pem", "/certs/priv.key")
	if err != nil {
		log.Fatal(err)
	}

	durationStr := os.Getenv("TRANSFER_DURATION")
	duration, _ := time.ParseDuration(durationStr + "s")
	if duration == 0 {
		duration = 10 * time.Second
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	log.Printf("Starting TCP+TLS server on :443")
	
	// We listen with a standard TCP listener first to control the socket
	innerListener, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}

	for {
		rawConn, err := innerListener.Accept()
		if err != nil {
			continue
		}

		// SET THE BUFFERS ON THE SERVER SIDE
		if tcpConn, ok := rawConn.(*net.TCPConn); ok {
			tcpConn.SetWriteBuffer(8 * 1024 * 1024) // Allow 8MB for sending
			tcpConn.SetReadBuffer(8 * 1024 * 1024)
			tcpConn.SetNoDelay(true)
		}

		// Wrap the optimized TCP connection in TLS
		tlsConn := tls.Server(rawConn, tlsConfig)
		go handleTLSConn(tlsConn, duration)
	}
}

func handleTLSConn(conn net.Conn, d time.Duration) {
	defer conn.Close()
	
	// Perform handshake explicitly to catch errors early
	if tc, ok := conn.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			log.Printf("TLS handshake error: %v", err)
			return
		}
	}

	data := make([]byte, bufferSize)
	for i := range data {
		data[i] = 0xaa
	}

	// Wait for client signal
	buf := make([]byte, 1)
	conn.Read(buf)

	start := time.Now()
	for time.Since(start) < d {
		_, err := conn.Write(data)
		if err != nil {
			return
		}
	}
}