#!/bin/sh
# ---------------------------------------------------------------------------
# ban-ip.sh <ip> [--forever] [reason words...] -- block an IPv4 at the
# firewall NOW, persist via /etc/rc.local, and record the ban for the
# daily expiry review. Canonical: root/usr/local/bin/ban-ip.sh in the
# banish repo, installed by install.sh (legacy boxes may keep older
# manual-only copies).
# Full lifecycle docs: README.md, the "Ban lifecycle" section.
#
# Ladder (enforced by ban-review.sh): strike 1 -> 7 days, strike 2 -> 30
# days, strike 3+ or --forever -> permanent. Strikes climb from "hist"
# probation records; release additionally requires quietness (iptables
# DROP counter roughly flat), see ban-review.sh. /var/lib/bans.state is
# the source of truth ("ban <ip> <banned_at> <expires|perm> <strikes>
# <reason>"); /etc/rc.local is REGENERATED from it -- never hand-edit it.
# External reputation signals (AbuseIPDB, Spamhaus DROP, RDAP) deferred;
# IPv4-only. Test: STATE=/tmp/bans.state RCLOCAL=/tmp/rc.local $0 192.0.2.1
# (still inserts a REAL rule -- release with ban-review.sh or iptables -D).
# ---------------------------------------------------------------------------
set -eu

STATE=${STATE:-/var/lib/bans.state}
RCLOCAL=${RCLOCAL:-/etc/rc.local}
BAN_T1=${BAN_T1:-604800}     # strike 1: 7 days
BAN_T2=${BAN_T2:-2592000}    # strike 2: 30 days
case "$BAN_T1" in ''|*[!0-9]*) BAN_T1=604800 ;; esac
case "$BAN_T2" in ''|*[!0-9]*) BAN_T2=2592000 ;; esac

ip=""
forever=0
reason=""
for arg in "$@"; do
    case "$arg" in
        --forever) forever=1 ;;
        *)
            if [ -z "$ip" ]; then
                ip="$arg"
            else
                reason="$reason $arg"
            fi
            ;;
    esac
done
reason="${reason# }"
: "${reason:=manual}"

case "$ip" in
    ""|*[!0-9.]*)
        echo "usage: $0 <ipv4> [--forever] [reason words...]" >&2
        exit 1
        ;;
esac
[ "$(echo "$ip" | tr -cd '.' | wc -c)" -eq 3 ] || { echo "not an IPv4: $ip" >&2; exit 1; }

now=$(date +%s)
mkdir -p /var/lib
touch "$STATE" 2>/dev/null || exit 1

# state-changing scripts serialize on a directory lock next to the state
# file; ban-review.sh uses the same one
lock="${STATE}.lock"
if ! mkdir "$lock" 2>/dev/null; then
    echo "ban-ip: state busy (review running?), retry later" >&2
    exit 1
fi
trap 'rmdir "$lock" 2>/dev/null' EXIT

# already banned: idempotent no-op (the ladder advances only through the
# probation path, never by re-banning an active block)
if awk -v ip="$ip" '$1=="ban" && $2==ip {f=1} END {exit !f}' "$STATE"; then
    if iptables -C INPUT -s "$ip" -j DROP >/dev/null 2>&1; then
        echo "already banned: $ip"
    else
        iptables -I INPUT 1 -s "$ip" -j DROP
        echo "already banned (firewall rule was missing, re-added): $ip"
    fi
    exit 0
fi

# strikes climb from the probation history, if any
hist_strikes=$(awk -v ip="$ip" '$1=="hist" && $2==ip {print $4; exit}' "$STATE")
case "$hist_strikes" in
    ''|*[!0-9]*) strikes=1 ;;
    *) strikes=$((hist_strikes + 1)) ;;
esac

if [ "$forever" = "1" ] || [ "$strikes" -ge 3 ]; then
    expires="perm"
elif [ "$strikes" -eq 2 ]; then
    expires=$((now + BAN_T2))
else
    expires=$((now + BAN_T1))
fi

# firewall first: if this fails, the state stays untouched
if ! iptables -C INPUT -s "$ip" -j DROP >/dev/null 2>&1; then
    iptables -I INPUT 1 -s "$ip" -j DROP
fi

tmp="$STATE.tmp"
awk -v ip="$ip" '! (($1=="ban" || $1=="hist" || $1=="ctr") && $2==ip)' \
    "$STATE" > "$tmp"
echo "ban $ip $now $expires $strikes $reason" >> "$tmp"
mv "$tmp" "$STATE"

# /etc/rc.local is fully derived from the state file
ips=$(awk '$1=="ban" {print $2}' "$STATE" | sort -u | tr '\n' ' ')
umask 022
if [ -n "${ips%% }" ]; then
    cat > "$RCLOCAL" <<EORC
#!/bin/sh
# Managed by ban-ip.sh / ban-review.sh: banned-IP persistence, regenerated
# from $STATE -- do not edit by hand.
for ip in $ips; do
    iptables -C INPUT -s "\$ip" -j DROP 2>/dev/null || iptables -I INPUT 1 -s "\$ip" -j DROP
done
exit 0
EORC
else
    printf '#!/bin/sh\nexit 0\n' > "$RCLOCAL"
fi
chmod 755 "$RCLOCAL"

if [ "$RCLOCAL" = "/etc/rc.local" ]; then
    systemctl start rc-local >/dev/null 2>&1 || true
fi

if [ "$expires" = "perm" ]; then
    echo "banned: $ip strikes=$strikes expires=perm reason=$reason"
else
    echo "banned: $ip strikes=$strikes expires=$(date -d "@$expires" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "$expires") reason=$reason"
fi
