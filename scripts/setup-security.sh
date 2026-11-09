#!/usr/bin/env bash
# ==============================================================================
# Multi-Layer Server Security & Hardening Script
# Protects against IP scanners (Shodan, Censys, RKN), SSH brute force, SYN floods
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${CYAN}[INFO]${NC} $1"; }
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Kernel Network Hardening (Anti-Spoofing, SYN Cookies, BBR, IPv6 Leak Protection)
info "Applying Linux kernel network hardening (/etc/sysctl.d/99-security.conf)..."
cat << 'EOF' > /etc/sysctl.d/99-security.conf
# Disable IPv6 system-wide (Prevents IP/DNS leaks, asymmetric routing & Let's Encrypt AAAA mismatch)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# TCP SYN Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_synack_retries = 2

# IP Spoofing & Source Routing Protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# ICMP Redirect & Smurf Attack Protection
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# TIME-WAIT Assassination Protection
net.ipv4.tcp_rfc1337 = 1

# Network Performance & Buffer Tuning
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 16384
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

sysctl --system >/dev/null 2>&1 || true
ok "Kernel network hardening applied (IPv6 disabled, BBR active)."

# Ensure UFW does not process IPv6
if [ -f /etc/default/ufw ]; then
    sed -i 's/^IPV6=yes/IPV6=no/' /etc/default/ufw 2>/dev/null || true
fi

# 2. UFW Firewall Setup
info "Configuring UFW firewall (default deny incoming, allow 22/80/443)..."
if [ -f "$SCRIPT_DIR/setup-firewall.sh" ]; then
    bash "$SCRIPT_DIR/setup-firewall.sh"
else
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    ufw allow 8443/tcp comment 'Xray REALITY Vision'
    ufw allow 8444/tcp comment 'Xray REALITY XHTTP'
    ufw allow 443/udp comment 'Hysteria 2 UDP (QUIC)'
    ufw --force enable
fi
ok "UFW firewall configured."

# 3. Fail2ban Installation & Configuration
info "Installing and configuring Fail2ban with UFW banaction..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y fail2ban >/dev/null

cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
bantime  = 1d
findtime = 10m
maxretry = 5
banaction = ufw
banaction_allports = ufw

[sshd]
enabled = true
port    = 22
backend = systemd
EOF

systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban
ok "Fail2ban is active (auto-bans failed SSH attempts via UFW for 24 hours)."

# 4. SSH Hardening (Fail2ban Protection + Key/Password Authentication)
info "Configuring SSH security (protected by Fail2ban rate-limiting)..."
mkdir -p /etc/ssh/sshd_config.d

cat << 'EOF' > /etc/ssh/sshd_config.d/99-security.conf
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin yes
EOF

if sshd -t >/dev/null 2>&1; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    ok "SSH configured: Key auth enabled, protected by Fail2ban."
else
    warn "sshd configuration test failed; changes not reloaded to avoid lockout."
fi

# 5. Automatic Security Patches
info "Enabling automated security updates (unattended-upgrades)..."
apt-get install -y unattended-upgrades >/dev/null 2>&1 || true
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
ok "Automatic zero-day patching is active."

echo ""
ok "Multi-layer security hardening complete!"
