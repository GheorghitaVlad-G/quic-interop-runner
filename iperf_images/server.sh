#!/bin/bash

# Disable offloading
ethtool -K eth0 tx off rx off tso off gso off gro off

# Add route
ip route add 193.167.0.0/24 via 193.167.100.2 dev eth0

# Verify configuration
echo "Server IP: 193.167.100.100"
echo "Routes:"
ip route show
echo "Listening on port 5201..."

# Start server with verbose output
exec iperf3 -s -p 5201 -B 193.167.100.100 -V