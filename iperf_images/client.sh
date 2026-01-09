#!/bin/bash

# Disable offloading
ethtool -K eth0 tx off rx off tso off gso off gro off

# Wait for simulator heartbeat
until nc -z sim 57832; do
  sleep 1
done

# Add route
ip route add 193.167.100.0/24 via 193.167.0.2 dev eth0

# Additional wait for sim to be fully ready
sleep 2

# Verify route
echo "Routes:"
ip route show

echo "Iperf3 Client connecting to 193.167.100.100..."
iperf3 -c 193.167.100.100 -u -b 10M -t 10 -p 5201 -V