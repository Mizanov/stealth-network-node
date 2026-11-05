#!/usr/bin/env bash
set -euo pipefail

SWAP_SIZE_GB="${1:-2}"

if [ ! -f /swapfile ]; then
    echo "Creating ${SWAP_SIZE_GB}GB swapfile..."
    fallocate -l "${SWAP_SIZE_GB}G" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=$((SWAP_SIZE_GB * 1024))
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    echo "Swap created successfully."
else
    echo "Swapfile already exists."
fi
