#!/bin/bash

# sysctl settings for network performance
sysctl -p

# Clean up residual processes
pkill -f supervisord || true
pkill -f nginx || true
pkill -f sshd || true

# Ensure directories exist with correct permissions
mkdir -p /var/log/supervisor /run/supervisor
chown root:root /var/log/supervisor /run/supervisor
chmod 755 /var/log/supervisor /run/supervisor
touch /var/log/supervisor/supervisord.log
chmod 644 /var/log/supervisor/supervisord.log

# Start Supervisor
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf