#!/bin/sh
# ---------------------------------------------------------------------------
# Flood and SQLi-probe detector for an nginx access log.
#
# Installed by banish install.sh as /usr/local/bin/flood-detector.sh
# (canonical copy: root/usr/local/bin/flood-detector.sh in the banish repo)
# and run every 5 minutes from /etc/cron.d/flood-detector (canonical copy:
# root/etc/cron.d/flood-detector).
#
# The nginx side of the defense lives in the site nginx vhost
# (its limit_req zones + the SQLi 444 rule; see README, Site contract).
#
# Three signals, from the site vhost access log
# (/var/log/nginx/access-timed.log; static locations do not log there):
#   FLOOD       one IP sustaining more than FLOOD_RPS requests/second,
#               measured as the delta between consecutive runs (a true
#               rate, NOT a share of recent traffic -- a lone polite
#               search crawler on a visitor-less site never trips it)
#   SQLI-PROBE  requests dropped by the SQLi 444 rule (or 414: URI too
#               long); a handful of stray probes is internet background
#               radiation, so SQLI_THRESHOLD must be exceeded
#   RATE-LIMIT  one IP collecting many 429s -- our own limit_req zones
#               are actively shedding it (brute force or flood)
#
# Alerting: a line in /var/log/flood-detector.log plus an e-mail via msmtp.
# Mail settings come from an env file (SMTP_HOST, SMTP_PORT, SMTP_USERNAME,
# SMTP_PASSWORD, SMTP_TLS, SMTP_FROM, and optionally the alert recipient
# MAIL_TO) whose path is ENV_FILE (default
# /etc/banish/env) -- typically a symlink to the site's existing mailer
# env, so no separate credentials to maintain.
# One alert per IP+reason per hour (COOLDOWN) keeps the mailbox sane.
#
# Manual test (writes to /tmp, sends one test-flagged e-mail):
#   TESTMODE=1 FLOOD_RPS=1 OUT=/tmp/fd.log STATE=/tmp/fd.state \
#     /usr/local/bin/flood-detector.sh
# (two runs ~a minute apart; the second sees the delta and alerts)
#
# A confirmed hostile IP is banned by hand -- carrier NAT can put many
# real customers behind one address, so first bans are never automatic.
# The exception is probation: an IP released from the ban-ip.sh expiry
# ladder (see ban-review.sh) that trips a real alert again is re-banned
# automatically (AUTO_REBAN, default on), advancing its ladder strike
# (7d -> 30d -> permanent):
#   iptables -I INPUT -s <ip> -j DROP
# (Ubuntu 26.04 translates that into nftables automatically.)
# ---------------------------------------------------------------------------

LOG=${LOG:-/var/log/nginx/access-timed.log}
OUT=${OUT:-/var/log/flood-detector.log}
STATE=${STATE:-/var/lib/flood-detector.state}
ENV_FILE=${ENV_FILE:-/etc/banish/env}
WINDOW=${WINDOW:-3000}
FLOOD_RPS=${FLOOD_RPS:-10}
SQLI_THRESHOLD=${SQLI_THRESHOLD:-3}
RATELIMIT_THRESHOLD=${RATELIMIT_THRESHOLD:-100}
COOLDOWN=${COOLDOWN:-3600}
# envval KEY -- first value of KEY=... from the env file
envval() {
    sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | head -n 1
}
# Alert recipient: env var, else a MAIL_TO= line in the env file, else a
# placeholder that delivers nowhere -- set one of the first two.
MAIL_TO=${MAIL_TO:-$(envval MAIL_TO)}
MAIL_TO=${MAIL_TO:-alerts@example.com}
SERVER_TAG=${SERVER_TAG:-$(hostname -s 2>/dev/null || hostname)}
TESTMODE=${TESTMODE:-0}

# Probation auto-re-ban: "hist" records in BANS_STATE are released bans;
# an alerting IP found there is re-banned via BAN_CMD (AUTO_REBAN=0 to
# disable, BAN_CMD=stub for dry runs).
BANS_STATE=${BANS_STATE:-/var/lib/bans.state}
AUTO_REBAN=${AUTO_REBAN:-1}
BAN_CMD=${BAN_CMD:-/usr/local/bin/ban-ip.sh}

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

# send_mail KIND DETAIL IP -- build a one-shot msmtp config from the SMTP_*
# values in the env file and mail the alert. Degrades to a log line when msmtp
# is missing or mail is unconfigured; never breaks detection.
send_mail() {
    if ! command -v msmtp >/dev/null 2>&1; then
        echo "$stamp mail: skipped (msmtp not installed)" >> "$OUT"
        return
    fi
    smtp_host=$(envval SMTP_HOST)
    if [ -z "$smtp_host" ] || [ "$smtp_host" = "CHANGE_ME" ]; then
        echo "$stamp mail: skipped (no SMTP_HOST in $ENV_FILE)" >> "$OUT"
        return
    fi
    smtp_port=$(envval SMTP_PORT)
    : "${smtp_port:=25}"
    smtp_user=$(envval SMTP_USERNAME)
    smtp_pass=$(envval SMTP_PASSWORD)
    smtp_tls=$(envval SMTP_TLS)
    smtp_from=$(envval SMTP_FROM)
    : "${smtp_from:=no-reply@$(hostname -s)}"

    cfg=$(mktemp /tmp/fd-msmtp.XXXXXX) || return
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
            "$MAIL_TO" "$smtp_from" "$subj" "$(date -R)" "$body" \
            | msmtp -C "$cfg" "$MAIL_TO" 2>>"$OUT"; then
        echo "$stamp mail: sent to $MAIL_TO" >> "$OUT"
    else
        echo "$stamp mail: msmtp FAILED (see msmtp output above)" >> "$OUT"
    fi
    rm -f "$cfg"
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
    # Probation auto-re-ban (see ban-review.sh); failures never break the alert
    reban=""
    if [ "$AUTO_REBAN" = "1" ] && [ -x "$BAN_CMD" ]; then
        pstrikes=$(awk -v ip="$aip" '$1=="hist" && $2==ip {print $4; exit}' "$BANS_STATE" 2>/dev/null)
        if [ -n "$pstrikes" ]; then
            case "$pstrikes" in ''|*[!0-9]*) pstrikes=0 ;; esac
            if "$BAN_CMD" "$aip" probation-realert "$akind" >>"$OUT" 2>&1; then
                reban=" [auto-reban strike=$((pstrikes + 1))]"
                echo "$stamp auto-reban PROBATION ip=$aip strike=$((pstrikes + 1)) after $akind" >> "$OUT"
            else
                echo "$stamp auto-reban FAILED ip=$aip (ban-ip output above)" >> "$OUT"
            fi
        fi
    fi
    echo "$stamp ALERT $akind $adetail ip=$aip$reban" >> "$OUT"
    send_mail "$akind" "$adetail$reban" "$aip"
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

# 3) RATE-LIMIT: one IP piling up 429s shed by our limit_req zones
set -- $(grep -F '" 429 ' /tmp/flood-detector.recent | cut -d" " -f 1 | sort | uniq -c | sort -rn | head -n 1)
if [ -n "$1" ] && [ "$1" -gt "$RATELIMIT_THRESHOLD" ]; then
    alert "$2" RATE-LIMIT "$1 throttled requests ($slice)"
fi

# keep the state file small, then record this run's bookkeeping
tail -n 200 "$STATE" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
echo "meta:lastrun $now" >> "$STATE"
echo "meta:lastlines $total" >> "$STATE"

rm -f /tmp/flood-detector.recent
