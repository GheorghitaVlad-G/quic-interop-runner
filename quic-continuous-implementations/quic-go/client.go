package main

import (
	"crypto/tls"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	var totalBytes atomic.Int64
	var wg sync.WaitGroup
	duration := 10 * time.Second
	conf := &tls.Config{InsecureSkipVerify: true}

	startTime := time.Now()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, _ := tls.Dial("tcp", "server4:4433", conf)
			defer conn.Close()
			conn.Write([]byte{0x01}) // Ready signal

			buf := make([]byte, 4*1024*1024)
			for time.Since(startTime) < duration {
				n, err := conn.Read(buf)
				if n > 0 { totalBytes.Add(int64(n)) }
				if err != nil { break }
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(startTime)
	log.Printf("TCP+TLS Result: %.2f Mbps", float64(totalBytes.Load()*8)/(elapsed.Seconds()*1e6))
}