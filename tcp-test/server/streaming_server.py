#!/usr/bin/env python3
"""
Simple HTTP server that streams 0xaa pattern.
Runs on port 8080 for streaming.
"""

import http.server
import socketserver
import os
import time
import sys

PORT = 8080
BUFFER_SIZE = 1024 * 1024  # 1MB chunks

class StreamingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/stream':
            # Get duration from environment
            duration = int(os.environ.get('TRANSFER_DURATION', '10'))
            
            # Calculate total bytes to send (assume 10 Mbps target rate)
            # 10 Mbps = 1.25 MB/s, so total_bytes = 1.25 MB/s * duration
            total_bytes = int(1.25 * 1024 * 1024 * duration)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(total_bytes))  # Set content length!
            self.end_headers()
            
            # Generate 0xaa pattern
            data = bytes([0xaa] * BUFFER_SIZE)
            bytes_sent = 0
            start_time = time.time()
            
            try:
                while bytes_sent < total_bytes:
                    # Send as much as needed
                    remaining = total_bytes - bytes_sent
                    chunk_size = min(BUFFER_SIZE, remaining)
                    
                    if chunk_size < BUFFER_SIZE:
                        # Last chunk - trim it
                        self.wfile.write(data[:chunk_size])
                    else:
                        self.wfile.write(data)
                    
                    bytes_sent += chunk_size
                    
                    # Small sleep to avoid overwhelming (optional)
                    # time.sleep(0.001)
                    
            except (BrokenPipeError, ConnectionResetError):
                # Client disconnected
                pass
            
            elapsed = time.time() - start_time
            print(f"Streamed {bytes_sent} bytes in {elapsed:.2f}s ({bytes_sent*8/elapsed/1e6:.2f} Mbps)", 
                  file=sys.stderr)
        else:
            self.send_error(404, "Not Found")
    
    def log_message(self, format, *args):
        # Log to stderr so it appears in docker logs
        sys.stderr.write("%s - - [%s] %s\n" %
                        (self.address_string(),
                         self.log_date_time_string(),
                         format%args))

if __name__ == '__main__':
    # Allow reuse of address
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), StreamingHandler) as httpd:
        print(f"Streaming server listening on port {PORT}", file=sys.stderr)
        httpd.serve_forever()