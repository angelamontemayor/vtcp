#!/bin/bash

# Simple TAP setup script based on smoltcp documentation
# Run with: sudo ./setup_tap.sh

echo "Setting up TAP interface for smoltcp..."

# Get the actual user (not root when using sudo)
ACTUAL_USER=${SUDO_USER:-$USER}
ACTUAL_UID=${SUDO_UID:-$(id -u)}

echo "Setting up TAP interface for user: $ACTUAL_USER (UID: $ACTUAL_UID)"

# Remove existing interface if it exists
if ip link show tap0 >/dev/null 2>&1; then
    echo "Removing existing tap0 interface..."
    sudo ip link delete tap0
fi

# Create persistent TAP interface with explicit user/group IDs
sudo ip tuntap add name tap0 mode tap user $ACTUAL_UID group $(id -g $ACTUAL_USER)

# Bring interface up
sudo ip link set tap0 up

# Add IPv4 address (from smoltcp docs)
sudo ip addr add 192.168.69.100/24 dev tap0

# Add IPv6 addresses (from smoltcp docs)
sudo ip -6 addr add fe80::100/64 dev tap0 2>/dev/null || echo "IPv6 address already exists"
sudo ip -6 addr add fdaa::100/64 dev tap0 2>/dev/null || echo "IPv6 address already exists"

# Add IPv6 routes (from smoltcp docs)
sudo ip -6 route add fe80::/64 dev tap0 2>/dev/null || echo "IPv6 route already exists"
sudo ip -6 route add fdaa::/64 dev tap0 2>/dev/null || echo "IPv6 route already exists"

# Verify setup
echo ""
echo "Verifying setup..."
echo "TAP interface ownership:"
sudo ip tuntap show | grep tap0

echo ""
echo "Interface status:"
ip addr show tap0

echo ""
echo "TAP interface setup complete!"
echo "Your smoltcp app can now use tap0 without root privileges"
echo "Host IP: 192.168.69.100"
echo "Your app should use: 192.168.69.1"
echo ""
echo "Note: Use TunTapInterface in smoltcp, not RawSocket (which requires root)"
