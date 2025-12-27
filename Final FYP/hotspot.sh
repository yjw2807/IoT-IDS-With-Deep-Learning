#!/bin/bash

# Configuration Variables
INTERFACE="wlan0"          # The interface you want to turn into a hotspot
OUT_INTERFACE="eth0"       # The interface providing internet (eth0, wlan1, etc.)
SSID="Kali-Hotspot"        # The Hotspot Name
PASSWORD="password123"     # The Hotspot Password
GATEWAY_IP="192.168.50.1"  # Custom IP for the hotspot gateway
DHCP_RANGE="192.168.50.10,192.168.50.100,12h"

# 1. Check for Root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root." 1>&2
   exit 1
fi

echo "[*] Setting up Hotspot on $INTERFACE..."

# 2. Kill interfering processes
echo "[*] Killing interfering processes..."
nmcli device set $INTERFACE managed no 2>/dev/null
killall wpa_supplicant 2>/dev/null
killall hostapd 2>/dev/null
killall dnsmasq 2>/dev/null

# 3. Configure IP address
echo "[*] Configuring Interface IP..."
ip link set $INTERFACE down
ip addr flush dev $INTERFACE
ip link set $INTERFACE up
ip addr add $GATEWAY_IP/24 dev $INTERFACE

# 4. Configure Dnsmasq (DHCP)
echo "[*] Starting DHCP Server (dnsmasq)..."
cat > /tmp/dnsmasq_hotspot.conf <<EOF
interface=$INTERFACE
dhcp-range=$DHCP_RANGE
dhcp-option=3,$GATEWAY_IP
dhcp-option=6,8.8.8.8,8.8.4.4
server=8.8.8.8
log-queries
log-dhcp
listen-address=$GATEWAY_IP
bind-interfaces
EOF

dnsmasq -C /tmp/dnsmasq_hotspot.conf

# 5. Enable Internet Sharing (NAT)
echo "[*] Enabling Internet Sharing (NAT)..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null
iptables -t nat -A POSTROUTING -o $OUT_INTERFACE -j MASQUERADE
iptables -A FORWARD -i $INTERFACE -o $OUT_INTERFACE -j ACCEPT
iptables -A FORWARD -i $OUT_INTERFACE -o $INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

# 6. Configure and Start Hostapd (AP)
echo "[*] Starting Access Point (hostapd)..."
cat > /tmp/hostapd_hotspot.conf <<EOF
interface=$INTERFACE
ssid=$SSID
hw_mode=g
channel=6
wpa=2
wpa_passphrase=$PASSWORD
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
auth_algs=1
macaddr_acl=0
EOF

# Trap Ctrl+C to clean up
trap cleanup SIGINT

cleanup() {
    echo -e "\n[*] Stopping Hotspot and cleaning up..."
    killall hostapd
    killall dnsmasq
    iptables -t nat -D POSTROUTING -o $OUT_INTERFACE -j MASQUERADE
    iptables -D FORWARD -i $INTERFACE -o $OUT_INTERFACE -j ACCEPT
    sysctl -w net.ipv4.ip_forward=0 > /dev/null
    nmcli device set $INTERFACE managed yes 2>/dev/null
    ip link set $INTERFACE down
    rm /tmp/hostapd_hotspot.conf /tmp/dnsmasq_hotspot.conf
    echo "[*] Done."
    exit
}

# Start hostapd (this will block the terminal until you press Ctrl+C)
hostapd /tmp/hostapd_hotspot.conf

cleanup
