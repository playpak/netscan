#!/bin/bash
# netscan.sh
# this script scans the local network for active devices by pinging each IP in the range

# get the local IP address and subnet mask
get_network_range() {
    ip addr show | awk '/inet / && !/127.0.0.1/ {print $2}' | head -n 1
}

# ping each IP in the network range and check for responses
scan_network() {
    local network_range="$1"
    echo "scanning network range: $network_range"
    
    # remove the last part of the IP to set the base for scanning
    ip_base="${network_range%.*}."
    
    for i in {1..254}; do
        ip="${ip_base}${i}"
        if ping -c 1 -W 1 "$ip" &> /dev/null; then
            echo "$ip is active"
        fi
    done
}

# main script execution
network_range=$(get_network_range)
scan_network "$network_range"
