package main

import (
	"crypto/tls"
	"log"
	"net"
)

func main() {
	cert, _ := tls.LoadX509KeyPair("/certs/cert.pem", "/certs/priv.key")
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	
	ln, _ := tls.Listen("tcp", ":4433", config)
	defer ln.Close()
	log.Println("TCP+TLS Server listening on :4433")

	data := make([]byte, 4*1024*1024)
	for i := range data { data[i] = 0xaa }

	for {
		conn, _ := ln.Accept()
		go func(c net.Conn) {
			defer c.Close()
			// Wait for client signal
			buf := make([]byte, 1)
			c.Read(buf)
			for {
				_, err := c.Write(data)
				if err != nil { return }
			}
		}(conn)
	}
}