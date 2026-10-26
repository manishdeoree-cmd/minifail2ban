#!/usr/bin/env bash
# Install (or remove) minifail2ban as a systemd service.
#
#   sudo ./install.sh              install and start
#   sudo ./install.sh --uninstall  stop, remove firewall rules and program files
#   sudo ./install.sh --uninstall --purge   ...and delete config and state too
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN=/usr/local/bin/minifail2ban
CONF_DIR=/etc/minifail2ban
CONF=$CONF_DIR/minifail2ban.conf
UNIT=/etc/systemd/system/minifail2ban.service
STATE_DIR=/var/lib/minifail2ban

die() { echo "error: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "please run as root (sudo $0 $*)"
command -v systemctl >/dev/null || die "systemd is required"

uninstall() {
    echo "Stopping service and removing firewall rules..."
    systemctl disable --now minifail2ban 2>/dev/null || true
    if [[ -x $BIN ]]; then
        "$BIN" flush --remove-rules -c "$CONF" 2>/dev/null || true
    fi
    rm -f "$UNIT" "$BIN"
    systemctl daemon-reload
    if [[ ${1:-} == "--purge" ]]; then
        rm -rf "$CONF_DIR" "$STATE_DIR"
        echo "Config and state deleted."
    else
        echo "Kept $CONF_DIR and $STATE_DIR (use --purge to delete them)."
    fi
    echo "minifail2ban removed."
}

if [[ ${1:-} == "--uninstall" ]]; then
    uninstall "${2:-}"
    exit 0
fi

command -v python3 >/dev/null || die "python3 is required"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || die "Python 3.8 or newer is required"
command -v nft >/dev/null || command -v iptables >/dev/null || die "install nftables or iptables first"

echo "Installing program..."
install -m 0755 "$SCRIPT_DIR/src/minifail2ban.py" "$BIN"

install -d -m 0755 "$CONF_DIR"
if [[ -f $CONF ]]; then
    echo "Keeping your existing config: $CONF"
else
    install -m 0644 "$SCRIPT_DIR/config/minifail2ban.conf" "$CONF"
    echo "Config installed: $CONF"
fi

# Debian 12+/Ubuntu 24.04 minimal installs may have no /var/log/auth.log (no rsyslog).
if ! [[ -f /var/log/auth.log || -f /var/log/secure ]]; then
    echo "note: no /var/log/auth.log or /var/log/secure found."
    echo "      Set 'source = journal' in $CONF to read from the systemd journal."
fi

install -m 0644 "$SCRIPT_DIR/systemd/minifail2ban.service" "$UNIT"
systemctl daemon-reload
systemctl enable --now minifail2ban

echo
echo "minifail2ban is running."
echo "  Add your own IP to 'whitelist' in $CONF, then: systemctl restart minifail2ban"
echo "  Live log:    journalctl -u minifail2ban -f"
echo "  Active bans: minifail2ban status"
echo "  Top attackers: minifail2ban report"
