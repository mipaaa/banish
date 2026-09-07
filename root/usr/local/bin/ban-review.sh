#!/bin/sh
# ---------------------------------------------------------------------------
# ban-review.sh -- daily review of banned IPs (cron 06:12; canonical:
# root/usr/local/bin/ban-review.sh in the banish repo). Companion to
# ban-ip.sh and flood-detector.sh; full lifecycle docs: README.md, the
# "Ban lifecycle" section.
#
# Per "ban <ip> <banned_at> <expires|perm> <strikes>" in /var/lib/bans.state:
# releases expired non-permanent bans that were also QUIET for QUIET_SECS
# (default 3d; iptables DROP-counter growth under QUIET_PKTS/day, default
# 100; a reboot restarts the quiet clock), moves them to "hist" probation
# records, heals missing firewall rules, regenerates /etc/rc.local from
# the state file, and mails a report (msmtp via the env file, like the
# detector) only when something was released or healed.
# External reputation checks (AbuseIPDB, Spamhaus DROP, RDAP) deliberately
# deferred; IPv4-only. Fast-lane test: ban with BAN_T1=0, then review with
# QUIET_SECS=0.
# ---------------------------------------------------------------------------
set -eu

STATE=${STATE:-/var/lib/bans.state}
RCLOCAL=${RCLOCAL:-/etc/rc.local}
OUT=${OUT:-/var/log/ban-review.log}
ENV_FILE=${ENV_FILE:-/etc/banish/env}
# envval KEY -- first value of KEY=... from the env file
envval() {
    sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | head -n 1
}
# Report recipient: env var, else a MAIL_TO= line in the env file, else a
# placeholder that delivers nowhere -- set one of the first two.
MAIL_TO=${MAIL_TO:-$(envval MAIL_TO)}
MAIL_TO=${MAIL_TO:-alerts@example.com}
SERVER_TAG=${SERVER_TAG:-$(hostname -s 2>/dev/null || hostname)}
TESTMODE=${TESTMODE:-0}
QUIET_SECS=${QUIET_SECS:-259200}   # 3 days of counter flatness to release
QUIET_PKTS=${QUIET_PKTS:-100}      # tolerated packets per day while "quiet"
case "$QUIET_SECS" in ''|*[!0-9]*) QUIET_SECS=259200 ;; esac
case "$QUIET_PKTS" in ''|*[!0-9]*) QUIET_PKTS=100 ;; esac

mkdir -p /var/lib
touch "$STATE" "$OUT" 2>/dev/null || exit 1

now=$(date +%s)
stamp=$(date "+%Y-%m-%d %H:%M:%S")

# serialize with ban-ip.sh on the same directory lock
lock="${STATE}.lock"
if ! mkdir "$lock" 2>/dev/null; then
    echo "$stamp skipped: state busy (ban-ip running?)" >> "$OUT"
    exit 0
fi
trap 'rmdir "$lock" 2>/dev/null' EXIT

# one snapshot of the INPUT chain counters, taken before any change; the
# per-rule source address prints in column 8 of "iptables -L INPUT -v -n -x"
counters=$(iptables -L INPUT -v -n -x 2>/dev/null || true)

getpkts() {
    printf '%s\n' "$counters" | awk -v ip="$1" \
        '$8==ip || $8==ip"/32" {print $1; exit}'
}

new="$STATE.new"
: > "$new"
released=""       # ip:strikes pairs
healed=""         # ips whose rule was missing and got re-added
held_expired=""   # expired but still noisy: kept on purpose
kept=0
perm=0

while read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    set -- $line
    if [ "$1" != "ban" ]; then
        continue
    fi
    ip=$2
    banned_at=$3
    expires=$4
    strikes=$5
    shift 5
    reason="$*"

    pkts=$(getpkts "$ip")
    if [ -z "$pkts" ]; then
        iptables -I INPUT 1 -s "$ip" -j DROP
        pkts=0
        healed="$healed $ip"
        echo "$stamp healed missing firewall rule ip=$ip" >> "$OUT"
    fi

    # quietness bookkeeping against the previous ctr sample
    quiet_since=$now
    prev=$(awk -v ip="$ip" '$1=="ctr" && $2==ip {print $3, $4, $5; exit}' "$STATE")
    if [ -n "$prev" ]; then
        set -- $prev
        sat=$1
        spk=$2
        qs=$3
        quiet_since=$qs
        case "$sat" in ''|*[!0-9]*) sat=$now ;; esac
        case "$spk" in ''|*[!0-9]*) spk=0 ;; esac
        elapsed=$((now - sat))
        if [ "$elapsed" -lt 1 ]; then
            elapsed=1
        fi
        budget=$((QUIET_PKTS * elapsed / 86400 + 1))
        if [ "$pkts" -lt "$spk" ]; then
            quiet_since=$now          # counter reset (reboot): restart clock
        elif [ $((pkts - spk)) -gt "$budget" ]; then
            quiet_since=$now          # still probing: restart clock
        fi
    fi

    if [ "$expires" != "perm" ]; then
        case "$expires" in ''|*[!0-9]*) expires="perm" ;; esac
        quiet_ok=0
        if [ $((now - quiet_since)) -ge "$QUIET_SECS" ]; then
            quiet_ok=1
        fi
        if [ "$now" -ge "$expires" ] && [ "$quiet_ok" = "1" ]; then
            n=0
            while iptables -C INPUT -s "$ip" -j DROP >/dev/null 2>&1; do
                iptables -D INPUT -s "$ip" -j DROP
                n=$((n + 1))
                if [ "$n" -gt 10 ]; then
                    break
                fi
            done
            echo "hist $ip $now $strikes $reason" >> "$new"
            released="$released $ip:$strikes"
            echo "$stamp released ip=$ip strikes=$strikes reason=$reason" >> "$OUT"
            continue
        fi
        if [ "$now" -ge "$expires" ]; then
            held_expired="$held_expired $ip"
        fi
    else
        perm=$((perm + 1))
    fi

    echo "ban $ip $banned_at $expires $strikes $reason" >> "$new"
    echo "ctr $ip $now $pkts $quiet_since" >> "$new"
    kept=$((kept + 1))
done < "$STATE"

# carry the probation history over, then swap the state file in
grep '^hist ' "$STATE" >> "$new" 2>/dev/null || true
mv "$new" "$STATE"

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

# --- summary: always a log line, e-mail only when something was done -----
rel_count=0
for r in $released; do
    rel_count=$((rel_count + 1))
done
heal_count=0
for h in $healed; do
    heal_count=$((heal_count + 1))
done
echo "$stamp summary: kept=$kept perm=$perm released=$rel_count healed=$heal_count" \
    ${held_expired:+"held-expired-noisy:$held_expired"} >> "$OUT"

if [ "$rel_count" -eq 0 ] && [ "$heal_count" -eq 0 ]; then
    exit 0
fi

body="Banned-IP review on ${SERVER_TAG}
Time: $stamp

Released (moved to probation; a new detector alert re-bans them with a
longer ladder step):"
for r in $released; do
    body="$body
  ${r%%:*} (strike ${r##*:})"
done
body="$body

Healed (firewall rule was missing, re-added):"
for h in $healed; do
    body="$body
  $h"
done
body="$body

State file: $STATE
Kept bans: $kept ($perm permanent)

Manual unban of a still-listed IP:
  sudo iptables -D INPUT -s <ip> -j DROP
  sudo sed -i '/^ban <ip> /d;/^ctr <ip> /d' $STATE
  sudo /usr/local/bin/ban-review.sh   # regenerates /etc/rc.local"

smtp_host=$(envval SMTP_HOST)
if [ -z "$smtp_host" ] || [ "$smtp_host" = "CHANGE_ME" ]; then
    echo "$stamp mail: skipped (no SMTP_HOST in $ENV_FILE)" >> "$OUT"
    exit 0
fi
if ! command -v msmtp >/dev/null 2>&1; then
    echo "$stamp mail: skipped (msmtp not installed)" >> "$OUT"
    exit 0
fi
smtp_port=$(envval SMTP_PORT)
: "${smtp_port:=25}"
smtp_user=$(envval SMTP_USERNAME)
smtp_pass=$(envval SMTP_PASSWORD)
smtp_tls=$(envval SMTP_TLS)
smtp_from=$(envval SMTP_FROM)
: "${smtp_from:=no-reply@$(hostname -s)}"

cfg=$(mktemp /tmp/br-msmtp.XXXXXX) || exit 0
chmod 600 "$cfg"
{
    echo "account default"
    echo "host $smtp_host"
    echo "port $smtp_port"
    echo "from $smtp_from"
    echo "timeout 20"
    if [ -n "$smtp_user" ]; then
        echo "auth on"
        echo "user $smtp_user"
        echo "password $smtp_pass"
    else
        echo "auth off"
    fi
    if [ "$smtp_tls" = "never" ]; then
        echo "tls off"
    else
        echo "tls on"
        if [ "$smtp_port" = "465" ]; then
            echo "tls_starttls off"
        else
            echo "tls_starttls on"
        fi
        echo "tls_trust_file /etc/ssl/certs/ca-certificates.crt"
    fi
} > "$cfg"

subj="[${SERVER_TAG}] BAN-REVIEW released=$rel_count healed=$heal_count"
if [ "$TESTMODE" = "1" ]; then
    subj="$subj (forced test)"
fi
if printf "To: %s\nFrom: %s\nSubject: %s\nDate: %s\n\n%s" \
        "$MAIL_TO" "$smtp_from" "$subj" "$(date -R)" "$body" \
        | msmtp -C "$cfg" "$MAIL_TO" 2>>"$OUT"; then
    echo "$stamp mail: sent to $MAIL_TO" >> "$OUT"
else
    echo "$stamp mail: msmtp FAILED (see msmtp output above)" >> "$OUT"
fi
rm -f "$cfg"
