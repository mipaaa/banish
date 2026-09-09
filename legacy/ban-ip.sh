#!/bin/sh
# ---------------------------------------------------------------------------
# ban-ip.sh <ip> -- block an IP at the firewall NOW and persist the block
# across reboots. Companion to flood-detector.sh: alert e-mails point here.
#
# Canonical: this file (legacy/ban-ip.sh in the banish repo), installed as
# /usr/local/bin/ban-ip.sh on the legacy server (postfix variant). The
# mainline root/usr/local/bin/ban-ip.sh on the new servers adds the expiry
# ladder, bans.state, and the ban-review.sh companion; this simple port
# only mirrors rules into /etc/rc.local. Run as root.
#
# Persistence model: /etc/rc.local carries a single loop line
#     for ip in <banned ips>; do iptables ... ; done
# ban-ip.sh extends that line; when the file exists without the loop it
# inserts one idempotent rule line per IP, and when there is no rc.local
# at all it creates the file with the loop. It then starts rc-local so
# nothing waits for a reboot. Idempotent: re-banning an IP is a no-op.
# ---------------------------------------------------------------------------
set -eu

ip="${1:-}"
case "$ip" in
    ""|*[!0-9.]*)
        echo "usage: $0 <ipv4>" >&2
        exit 1
        ;;
esac
[ "$(echo "$ip" | tr -cd '.' | wc -c)" -eq 3 ] || { echo "not an IPv4: $ip" >&2; exit 1; }

if iptables -C INPUT -s "$ip" -j DROP >/dev/null 2>&1; then
    echo "already blocked: $ip"
else
    iptables -I INPUT 1 -s "$ip" -j DROP
    echo "blocked now: $ip"
fi

RC=/etc/rc.local
if [ -f "$RC" ] && grep -q "^for ip in " "$RC"; then
    if grep -q " $ip " "$RC"; then
        echo "already persisted: $ip"
    else
        sed -i "s/^for ip in /for ip in $ip /" "$RC"
        echo "persisted in $RC: $ip"
    fi
elif [ -f "$RC" ]; then
    # rc.local exists but has no ban loop: insert before the exit line
    sed -i "\|^exit 0|i\\\tiptables -C INPUT -s $ip -j DROP 2>/dev/null || iptables -I INPUT 1 -s $ip -j DROP" "$RC"
    echo "persisted in $RC (single rule): $ip"
else
    umask 022
    cat > "$RC" <<EORC
#!/bin/sh
# Firewall blocks persisted by /usr/local/bin/ban-ip.sh.
for ip in $ip; do
    iptables -C INPUT -s "\$ip" -j DROP 2>/dev/null || iptables -I INPUT 1 -s "\$ip" -j DROP
done
exit 0
EORC
    chmod +x "$RC"
    echo "created $RC with ban loop: $ip"
fi

# Apply the file's rules now (no-op for rules already added above; matters
# for rules persisted earlier). rc-local is a static unit activated by the
# executable file -- starting it here never waits for a reboot.
systemctl start rc-local >/dev/null 2>&1 || true
echo "done: $ip"
