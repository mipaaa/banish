#!/bin/sh
# ---------------------------------------------------------------------------
# Flood and SQLi-probe detector, legacy postfix-mail variant.
#
# CANONICAL SOURCE: this file (legacy/flood-detector-postfix.sh in the
# banish repo), installed as /usr/local/bin/flood-detector.sh, cron every
# 5 minutes via /etc/cron.d/flood-detector (managed by hand on its box).
# The mainline canonical is root/usr/local/bin/flood-detector.sh (msmtp +
# env-file variant); this older port mails through the local postfix
# (sendmail) instead, and bans stay fully manual.
#
# Three signals, from the site access log (LOG= below):
#   FLOOD       one IP sustaining more than FLOOD_RPS requests/second,
#               measured as the log delta between consecutive runs (a true
#               rate, NOT a share of recent traffic -- a lone polite search
#               crawler on a visitor-less site never trips it)
#   SQLI-PROBE  requests dropped by the SQLi 444 rule (or 414: URI too
#               long); a handful of stray probes is internet background
#               radiation, so SQLI_THRESHOLD must be exceeded
#   RATE-LIMIT  one IP collecting many 429s -- our own limit_req zone is
#               actively shedding it (brute force or flood)
#
# Alerting: a line in /var/log/flood-detector.log plus an e-mail via the
# local postfix (sendmail). One alert per IP+reason per hour (COOLDOWN).
#
# Manual test (isolated files, one test-flagged e-mail per alert):
#   TESTMODE=1 LOG=/tmp/fd/fake STATE=/tmp/fd/s OUT=/tmp/fd/o \
#     /usr/local/bin/flood-detector.sh
#
# A confirmed hostile IP is banned by hand, never automatically -- carrier
# NAT can put many real customers behind one address. Persist bans in
# /etc/rc.local:
#   iptables -I INPUT 1 -s <ip> -j DROP
# ---------------------------------------------------------------------------

# Set LOG= to your vhost's access log (default: the nginx standard log)
LOG=${LOG:-/var/log/nginx/access.log}
OUT=${OUT:-/var/log/flood-detector.log}
STATE=${STATE:-/var/lib/flood-detector.state}
WINDOW=${WINDOW:-3000}
FLOOD_RPS=${FLOOD_RPS:-10}
SQLI_THRESHOLD=${SQLI_THRESHOLD:-3}
RATELIMIT_THRESHOLD=${RATELIMIT_THRESHOLD:-100}
COOLDOWN=${COOLDOWN:-3600}
MAIL_TO=${MAIL_TO:-root}   # local mailbox; set a real address via env or cron
MAIL_FROM=${MAIL_FROM:-root@$(hostname -s 2>/dev/null || hostname)}
SERVER_TAG=${SERVER_TAG:-$(hostname -s 2>/dev/null || hostname)}
TESTMODE=${TESTMODE:-0}

# FLOOD_RPS is an integer (requests/second). Validate defensively: a bad
# value would otherwise abort the script inside arithmetic expansion.
case "$FLOOD_RPS" in
    ''|*[!0-9]*) FLOOD_RPS=10 ;;
esac

mkdir -p /var/lib
touch "$STATE" "$OUT" 2>/dev/null || exit 1
[ -r "$LOG" ] || exit 0

now=$(date +%s)
stamp=$(date "+%Y-%m-%d %H:%M:%S")

# send_mail KIND DETAIL IP -- mail the alert through the local postfix
# (sendmail). Degrades to a log line; never breaks detection.
send_mail() {
    if [ ! -x /usr/sbin/sendmail ]; then
        echo "$stamp mail: skipped (no sendmail)" >> "$OUT"
        return
    fi
    subj="[${SERVER_TAG}] ALERT $1 ip=$3"
    [ "$TESTMODE" = "1" ] && subj="$subj (forced test)"
    body="Attack detector on ${SERVER_TAG}

Time:      $stamp
Reason:    $1
Detail:    $2
Source IP: $3

Log:  $OUT

Inspect (recent requests / claimed user agents):
  grep \"^$3 \" $LOG | tail -5
  grep \"^$3 \" $LOG | awk -F'\"' '{print \$6}' | sort | uniq -c | sort -rn | head -3

Ban until reboot only:
  sudo iptables -I INPUT 1 -s $3 -j DROP
Ban and persist across reboots:
  sudo /usr/local/bin/ban-ip.sh $3
"
    if printf "To: %s\nFrom: %s\nSubject: %s\nDate: %s\n\n%s" \
            "$MAIL_TO" "$MAIL_FROM" "$subj" "$(date -R)" "$body" \
            | /usr/sbin/sendmail -f "$MAIL_FROM" "$MAIL_TO" 2>>"$OUT"; then
        echo "$stamp mail: sent to $MAIL_TO" >> "$OUT"
    else
        echo "$stamp mail: sendmail FAILED" >> "$OUT"
    fi
}

# alert IP KIND DETAIL -- log + mail, throttled per IP+reason by COOLDOWN
alert() {
    aip=$1
    akind=$2
    adetail=$3
    key="$akind:$aip"
    alast=$(grep -F "$key " "$STATE" 2>/dev/null | tail -n 1 | cut -d" " -f 2)
    if [ -n "$alast" ] && [ $((now - alast)) -lt "$COOLDOWN" ]; then
        return
    fi
    echo "$key $now" >> "$STATE"
    echo "$stamp ALERT $akind $adetail ip=$aip" >> "$OUT"
    send_mail "$akind" "$adetail" "$aip"
}

# --- pick the analysis slice ----------------------------------------------
#
# Only NEW log lines are ever analyzed -- stale events must never re-alert
# after their cooldown expires (a quiet box would otherwise replay the
# last WINDOW lines once per hour, forever). Bookkeeping in the state file:
#   meta:lastrun <epoch>   -- when the previous run finished
#   meta:lastlines <n>     -- log line count at that time
#
#   baseline    first run ever: record state, analyze nothing
#   idle        no new lines since the previous run: nothing to see
#   delta:N     N new lines: SQLI/RATE-LIMIT analyze them; FLOOD also
#               requires a sane elapsed window (120-900s) for the rate math
#   rotation    line count went backwards (log rotated): analyze the new
#               file's tail, skip FLOOD (count vs elapsed is distorted)

prev_run=$(grep -F "meta:lastrun " "$STATE" 2>/dev/null | tail -n 1 | cut -d" " -f 2)
prev_lines=$(grep -F "meta:lastlines " "$STATE" 2>/dev/null | tail -n 1 | cut -d" " -f 2)
total=$(wc -l < "$LOG")

elapsed=""
slice=""
: > /tmp/flood-detector.recent

if [ -n "$prev_run" ] && [ -n "$prev_lines" ]; then
    if [ "$total" -lt "$prev_lines" ]; then
        tail -n "$WINDOW" "$LOG" > /tmp/flood-detector.recent
        slice="post-rotation"
    elif [ "$total" -gt "$prev_lines" ]; then
        new_lines=$((total - prev_lines))
        tail -n "$new_lines" "$LOG" > /tmp/flood-detector.recent
        slice="delta:$new_lines"
        elapsed=$((now - prev_run))
    fi
# else: baseline (first run) or idle (total == prev_lines): empty slice
fi

# FLOOD additionally needs a trustworthy elapsed window for rate division
if [ -n "$elapsed" ]; then
    if [ "$elapsed" -lt 120 ] || [ "$elapsed" -gt 900 ]; then
        elapsed=""
    fi
fi

# 1) FLOOD: sustained per-IP rate over the delta window
if [ -n "$elapsed" ]; then
    set -- $(cut -d" " -f 1 /tmp/flood-detector.recent | sort | uniq -c | sort -rn | head -n 1)
    if [ -n "$1" ] && [ "$1" -ge "$((FLOOD_RPS * elapsed))" ]; then
        rps=$(($1 / elapsed))
        alert "$2" FLOOD "$1 requests in ${elapsed}s (~${rps} r/s sustained, threshold ${FLOOD_RPS}/s)"
    fi
fi

# 2) SQLI-PROBE: URIs dropped by the SQLi 444 rule, or oversized (414)
set -- $(grep -cE '" (444|414) ' /tmp/flood-detector.recent | head -n 1)
if [ -n "$1" ] && [ "$1" -ge "$SQLI_THRESHOLD" ]; then
    set -- $(grep -E '" (444|414) ' /tmp/flood-detector.recent | cut -d" " -f 1 | sort | uniq -c | sort -rn | head -n 1)
    [ -n "$2" ] && alert "$2" SQLI-PROBE "$1 dropped or oversized URIs ($slice)"
fi

# 3) RATE-LIMIT: one IP piling up 429s shed by our limit_req zone
set -- $(grep -F '" 429 ' /tmp/flood-detector.recent | cut -d" " -f 1 | sort | uniq -c | sort -rn | head -n 1)
if [ -n "$1" ] && [ "$1" -gt "$RATELIMIT_THRESHOLD" ]; then
    alert "$2" RATE-LIMIT "$1 throttled requests ($slice)"
fi

# keep the state file small, then record this run's bookkeeping
tail -n 200 "$STATE" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
echo "meta:lastrun $now" >> "$STATE"
echo "meta:lastlines $total" >> "$STATE"

rm -f /tmp/flood-detector.recent
