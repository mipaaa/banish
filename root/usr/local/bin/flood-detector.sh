#!/bin/sh
# ---------------------------------------------------------------------------
# Bot-classifying attack detector for an nginx access log.
#
# Installed by banish install.sh as /usr/local/bin/flood-detector.sh
# (canonical copy: root/usr/local/bin/flood-detector.sh in the banish repo)
# and run every 5 minutes from /etc/cron.d/flood-detector (canonical copy:
# root/etc/cron.d/flood-detector).
#
# The same env file also carries the box's detection tuning (LOG,
# BADBOT_MIN, HEAVY_RPS, RATELIMIT_THRESHOLD, COOLDOWN, WINDOW, AUTO_REBAN,
# AUTO_BAN, AUTO_BAN_DAYS, PROBE_URL_REGEX, DIGEST): precedence is
# environment variable, then a KEY= line in the env file, then the
# built-in default.
#
# The nginx side of the defense lives in the site nginx vhost
# (its limit_req zones + the 444 drop rules; see README, Site contract).
#
# Visitor classes and what the detector does with them (humans and polite
# bots never match a class and are never touched):
#   bad bots     >= BADBOT_MIN probe hits in the analysis slice, at ANY
#                speed. A probe hit is a request dropped by the site's
#                444 scanner/SQLi rules (status 444), an oversized URI
#                (414), or any request whose URL matches PROBE_URL_REGEX
#                regardless of status. Auto-banned via ban-ip.sh
#                (AUTO_BAN, default on) with NO mail: no legit visitor,
#                NAT or not, pulls /wp-login.php or /.config/rclone.conf
#                five times in five minutes
#   heavy bots   one IP sustaining more than HEAVY_RPS requests/second,
#                measured as the delta between consecutive runs (a true
#                rate, NOT a share of recent traffic -- a lone polite
#                crawler on a visitor-less site never trips it).
#                Auto-banned the same way, no mail
#   possible     one IP collecting many 429s (RATELIMIT_THRESHOLD) shed
#   NAT / stuck  by the site's limit_req zones WITHOUT qualifying as a
#   client       bad bot -- could be real people behind a carrier NAT or
#                a broken client in a retry loop, so this is the one
#                signal that still mails a human (AUTO_REBAN applies to
#                probationers)
#
# Auto-bans go through ban-ip.sh with --days AUTO_BAN_DAYS (strike-1
# duration only; the ladder still escalates recidivists: 30 d, then
# permanent). Every auto-ban (and every failed or disabled one that had
# to fall back to mail) is appended as one line to the DIGEST file, which
# ban-review.sh rolls into its daily report -- that report is the admin's
# regular visibility into automatic bans. The AUTO-BAN log lines plus the
# offender's top probe requests in /var/log/flood-detector.log are the
# audit trail. If the ban command itself fails, the human alert mail is
# sent instead (auto-ban impossible -> notify).
#
# Alerting (NAT/stuck-client path and failures): a line in
# /var/log/flood-detector.log plus an e-mail via msmtp. Mail settings
# come from an env file (SMTP_HOST, SMTP_PORT, SMTP_USERNAME,
# SMTP_PASSWORD, SMTP_TLS, SMTP_FROM, and optionally the alert recipient
# MAIL_TO) whose path is ENV_FILE (default /etc/banish/env) -- typically
# a symlink to the site's existing mailer env, so no separate credentials
# to maintain. One alert per IP+reason per hour (COOLDOWN) keeps the
# mailbox sane. The mail embeds the alerting IP's footprint from the
# analysis slice (top requests, claimed user agents, statuses, raw tail)
# -- captured at alert time, because daily log rotation races the alert.
#
# Manual test (writes to /tmp, sends one test-flagged e-mail):
#   TESTMODE=1 BADBOT_MIN=2 OUT=/tmp/fd.log STATE=/tmp/fd.state \
#     RECENT=/tmp/fd.recent DIGEST=/tmp/fd.digest \
#     /usr/local/bin/flood-detector.sh
# (two runs ~a minute apart; the second sees the delta and acts; point
# MSMTP_BIN at a stub script to capture the mail without msmtp, and
# BAN_CMD at a stub to capture auto-bans without iptables)
#
# Site note: probes the site sheds with a logged 444 stay in the access
# log and are visible here; requests the site leaves unlogged (nginx
# access_log if= exclusions -- on this site: the i_wanna_buy legacy
# paths) are invisible to every banish signal, by the site's choice.
# ---------------------------------------------------------------------------

ENV_FILE=${ENV_FILE:-/etc/banish/env}
# envval KEY -- first value of KEY=... from the env file
envval() {
    sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | tr -d '\r' | head -n 1
}
# Access log to watch: env var, else a LOG= line in the env file, else
# the nginx default.
LOG=${LOG:-$(envval LOG)}
LOG=${LOG:-/var/log/nginx/access.log}
OUT=${OUT:-/var/log/flood-detector.log}
STATE=${STATE:-/var/lib/flood-detector.state}
# Analysis-slice temp file; override to run isolated tests in parallel
RECENT=${RECENT:-/tmp/flood-detector.recent}
# One line per detector auto-ban; ban-review.sh mails it daily
DIGEST=${DIGEST:-$(envval DIGEST)}
DIGEST=${DIGEST:-/var/lib/flood-digest}
# Detection knobs: environment variable, else a KEY= line in the env
# file, else the built-in default.
WINDOW=${WINDOW:-$(envval WINDOW)}
WINDOW=${WINDOW:-3000}
BADBOT_MIN=${BADBOT_MIN:-$(envval BADBOT_MIN)}
BADBOT_MIN=${BADBOT_MIN:-5}
case "$BADBOT_MIN" in ''|*[!0-9]*) BADBOT_MIN=5 ;; esac
HEAVY_RPS=${HEAVY_RPS:-$(envval HEAVY_RPS)}
HEAVY_RPS=${HEAVY_RPS:-15}
RATELIMIT_THRESHOLD=${RATELIMIT_THRESHOLD:-$(envval RATELIMIT_THRESHOLD)}
RATELIMIT_THRESHOLD=${RATELIMIT_THRESHOLD:-100}
case "$RATELIMIT_THRESHOLD" in ''|*[!0-9]*) RATELIMIT_THRESHOLD=100 ;; esac
COOLDOWN=${COOLDOWN:-$(envval COOLDOWN)}
COOLDOWN=${COOLDOWN:-3600}
# Alert recipient: env var, else a MAIL_TO= line in the env file, else a
# placeholder that delivers nowhere -- set one of the first two.
MAIL_TO=${MAIL_TO:-$(envval MAIL_TO)}
MAIL_TO=${MAIL_TO:-alerts@example.com}
SERVER_TAG=${SERVER_TAG:-$(hostname -s 2>/dev/null || hostname)}
TESTMODE=${TESTMODE:-0}
# Mail transport binary; override with a stub to capture mails in tests
MSMTP_BIN=${MSMTP_BIN:-msmtp}

# Probation auto-re-ban: "hist" records in BANS_STATE are released bans;
# an alerting IP found there is re-banned via BAN_CMD (AUTO_REBAN=0 to
# disable, BAN_CMD=stub for dry runs).
BANS_STATE=${BANS_STATE:-/var/lib/bans.state}
AUTO_REBAN=${AUTO_REBAN:-$(envval AUTO_REBAN)}
AUTO_REBAN=${AUTO_REBAN:-1}
BAN_CMD=${BAN_CMD:-/usr/local/bin/ban-ip.sh}

# Auto-ban master switch and strike-1 duration for auto-bans. AUTO_BAN=0
# rolls back to human-alert behavior for every class without a redeploy.
AUTO_BAN=${AUTO_BAN:-$(envval AUTO_BAN)}
AUTO_BAN=${AUTO_BAN:-1}
AUTO_BAN_DAYS=${AUTO_BAN_DAYS:-$(envval AUTO_BAN_DAYS)}
AUTO_BAN_DAYS=${AUTO_BAN_DAYS:-1}
case "$AUTO_BAN_DAYS" in ''|0|*[!0-9]*) AUTO_BAN_DAYS=1 ;; esac
# per-run caps: a bad day must not wedge the 5-minute cron slot (state
# lock serialization with ban-review.sh is the real constraint)
MAX_AUTO_BAN=${MAX_AUTO_BAN:-10}
MAX_ALERT=${MAX_ALERT:-5}

# Scanner probe URLs (lowercase; paths are matched lowercased). Keep in
# sync with the site's nginx $block_request scanner patterns -- nginx is
# the cheap first drop (444 before limit_req), this list additionally
# catches probe URLs that still slip through to a 404/429.
PROBE_URL_DEFAULT='(^|/)wp-(login|admin|content|includes|config|json)|(^|/)xmlrpc|(^|/)\.(git|svn|hg|env|config|htaccess|htpasswd|ds_store|aws|ssh|idea)(/|\.|\?|$)|%2e(env|git)|(^|/)(phpmyadmin|adminer|cgi-bin|vendor/phpunit|eval-stdin)|(^|/)actuator(/|\?|$)'
PROBE_URL_REGEX=${PROBE_URL_REGEX:-$(envval PROBE_URL_REGEX)}
PROBE_URL_REGEX=${PROBE_URL_REGEX:-$PROBE_URL_DEFAULT}
# a syntactically broken custom regex would silently kill the classifier
# (grep errors -> zero hits); fall back to the default instead
printf 'x\n' | grep -qE "$PROBE_URL_REGEX" >/dev/null 2>&1
[ "$?" -eq 2 ] && PROBE_URL_REGEX=$PROBE_URL_DEFAULT

# HEAVY_RPS is an integer (requests/second). Validate defensively: a bad
# value would otherwise abort the script inside arithmetic expansion.
case "$HEAVY_RPS" in
    ''|*[!0-9]*) HEAVY_RPS=15 ;;
esac

mkdir -p /var/lib
touch "$STATE" "$OUT" 2>/dev/null || exit 1
[ -r "$LOG" ] || exit 0

now=$(date +%s)
stamp=$(date "+%Y-%m-%d %H:%M:%S")
# IPs already acted on this run (auto-banned or mailed): later signals
# skip them, so one IP never yields two mails or a mail after a ban
handled=""
is_handled() {
    case " $handled " in *" $1 "*) return 0 ;; esac
    return 1
}

# digest LINE -- one line into the file ban-review.sh reports daily
digest() {
    echo "$stamp $1" >> "$DIGEST" 2>/dev/null
}

# evidence IP -- the alerting IP's footprint in this run's analysis slice:
# top request lines, claimed user agents, response statuses, raw tail.
# Embedded in the alert mail because daily log rotation races the alert;
# the slice file still exists at alert time, so this is the one copy of
# the evidence that rotation can never take away.
evidence() {
    eip=$1
    if [ ! -r "$RECENT" ]; then
        echo "  (analysis slice unavailable)"
        return
    fi
    eall=$(grep "^$eip " "$RECENT" 2>/dev/null)
    if [ -z "$eall" ]; then
        echo "  (no slice lines captured for this IP)"
        return
    fi
    echo "  top requests:"
    printf "%s\n" "$eall" | awk -F'"' '{print $2}' | sort | uniq -c | sort -rn | head -n 3 | sed "s/^/    /"
    echo "  claimed user agents:"
    printf "%s\n" "$eall" | awk -F'"' '{print $6}' | sort | uniq -c | sort -rn | head -n 3 | sed "s/^/    /"
    echo "  response statuses:"
    printf "%s\n" "$eall" | awk '{print $9}' | sort | uniq -c | sort -rn | sed "s/^/    /"
    echo "  last raw log lines:"
    printf "%s\n" "$eall" | tail -n 3 | sed "s/^/    /"
}

# send_mail KIND DETAIL IP -- build a one-shot msmtp config from the SMTP_*
# values in the env file and mail the alert. Degrades to a log line when msmtp
# is missing or mail is unconfigured; never breaks detection.
send_mail() {
    if ! command -v "$MSMTP_BIN" >/dev/null 2>&1; then
        echo "$stamp mail: skipped ($MSMTP_BIN not found)" >> "$OUT"
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
    ev=$(evidence "$3")
    # copy-pasteable subnet hint: the alerting IP's /24 (ban-ip.sh takes
    # CIDR since the subnet feature)
    s24=$(printf '%s' "$3" | awk -F. 'NF==4 {print $1"."$2"."$3".0/24"}')
    body="Attack detector on ${SERVER_TAG}

Time:      $stamp
Reason:    $1
Detail:    $2
Source IP: $3

Log:  $OUT

Evidence (captured at alert time from this run's analysis slice; log
rotation cannot erase it):
$ev

This mail is sent only for traffic the detector will NOT ban
automatically: possible people behind a shared address, or a failed
auto-ban. Scanner probes and floods are banned silently and appear in
the daily ban-review digest instead.

Dig deeper in the live log (may already have rotated):
  grep \"^$3 \" $LOG | tail -5
  grep \"^$3 \" $LOG | awk -F'\"' '{print \$6}' | sort | uniq -c | sort -rn | head -3

Ban until reboot only:
  sudo iptables -I INPUT 1 -s $3 -j DROP
Ban and persist across reboots:
  sudo /usr/local/bin/ban-ip.sh $3
Ban its whole /24 subnet (persists too):
  sudo /usr/local/bin/ban-ip.sh $s24
"
    if printf "To: %s\nFrom: %s\nSubject: %s\nDate: %s\n\n%s" \
            "$MAIL_TO" "$smtp_from" "$subj" "$(date -R)" "$body" \
            | "$MSMTP_BIN" -C "$cfg" "$MAIL_TO" 2>>"$OUT"; then
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
        return 1
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
                digest "AUTO-REBAN probation ip=$aip after $akind"
            else
                echo "$stamp auto-reban FAILED ip=$aip (ban-ip output above)" >> "$OUT"
            fi
        fi
    fi
    echo "$stamp ALERT $akind $adetail ip=$aip$reban" >> "$OUT"
    send_mail "$akind" "$adetail$reban" "$aip"
    return 0
}

# auto_ban IP CLASS DETAIL -- ban without mail. The AUTO-BAN log line
# plus the offender's top probe requests are the audit trail; one digest
# line feeds the daily ban-review report. Returns non-zero (and the
# caller falls back to the human alert) only when the ban was attempted
# and failed or auto-banning is disabled; an already-banned IP counts as
# handled without any noise.
auto_ban() {
    abip=$1
    abclass=$2
    abdetail=$3
    [ "$AUTO_BAN" = "1" ] && [ -x "$BAN_CMD" ] || return 1
    about=$("$BAN_CMD" "$abip" --days "$AUTO_BAN_DAYS" "auto-$abclass" 2>&1)
    case "$about" in
        banned:*)
            echo "$stamp AUTO-BAN $abclass ip=$abip $abdetail; ban-ip: $about; mail suppressed" >> "$OUT"
            abtop=$(grep "^$abip " "$RECENT" 2>/dev/null | awk -F'"' '{print $2}' \
                | grep -iE "$PROBE_URL_REGEX" | sort | uniq -c | sort -rn | head -n 3)
            if [ -n "$abtop" ]; then
                echo "  top probe requests:" >> "$OUT"
                printf "%s\n" "$abtop" | sed "s/^/    /" >> "$OUT"
            fi
            digest "AUTO-BAN $abclass ip=$abip $abdetail"
            return 0
            ;;
        already\ banned*)
            echo "$stamp AUTO-BAN $abclass ip=$abip skipped (already banned)" >> "$OUT"
            return 0
            ;;
        *)
            echo "$stamp auto-ban FAILED ip=$abip (ban-ip output above); alerting instead" >> "$OUT"
            digest "AUTO-BAN-FAILED $abclass ip=$abip"
            return 1
            ;;
    esac
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
#   delta:N     N new lines: classify them; the heavy-bot rate check
#               additionally requires a sane elapsed window (120-900s)
#   rotation    line count went backwards (log rotated): analyze the new
#               file's tail; heavy-bot rate math is skipped (elapsed
#               unknown), probe-hit classification still applies

prev_run=$(grep -F "meta:lastrun " "$STATE" 2>/dev/null | tail -n 1 | cut -d" " -f 2)
prev_lines=$(grep -F "meta:lastlines " "$STATE" 2>/dev/null | tail -n 1 | cut -d" " -f 2)
total=$(wc -l < "$LOG")

elapsed=""
slice=""
: > "$RECENT"

if [ -n "$prev_run" ] && [ -n "$prev_lines" ]; then
    if [ "$total" -lt "$prev_lines" ]; then
        tail -n "$WINDOW" "$LOG" > "$RECENT"
        slice="post-rotation"
    elif [ "$total" -gt "$prev_lines" ]; then
        new_lines=$((total - prev_lines))
        tail -n "$new_lines" "$LOG" > "$RECENT"
        slice="delta:$new_lines"
        elapsed=$((now - prev_run))
    fi
# else: baseline (first run) or idle (total == prev_lines): empty slice
fi

# heavy-bot rate division needs a trustworthy elapsed window
if [ -n "$elapsed" ]; then
    if [ "$elapsed" -lt 120 ] || [ "$elapsed" -gt 900 ]; then
        elapsed=""
    fi
fi

# --- classify every IP in the slice ---------------------------------------
#
# One awk pass -> "ip total probe_hits r429" per client. Probe hits: the
# site already dropped the request as scanner garbage (logged 444), the
# URI was oversized (414), or the URL matches PROBE_URL_REGEX at any
# status (probe paths that still slip through to a 404/429). The status
# is taken from the word after the second quote, so request lines with
# stray spaces cannot shift it. The regex travels via ENVIRON, not -v:
# awk -v processes backslash escapes in values and would corrupt \. or
# \? from the pattern into metacharacters.
statsfile="$RECENT.stats"
PROBE_RE="$PROBE_URL_REGEX" awk '
    BEGIN { re = ENVIRON["PROBE_RE"] }
    {
        ip = $1
        q = index($0, "\"")
        if (q == 0) next
        rest = substr($0, q + 1)
        e = index(rest, "\"")
        if (e == 0) next
        req = substr(rest, 1, e - 1)
        split(req, m, " ")
        path = tolower(m[2])
        split(substr(rest, e + 1), t, " ")
        st = t[1]
        tot[ip]++
        if (st == 444 || st == 414 || path ~ re) hits[ip]++
        if (st == 429) r429[ip]++
    }
    END { for (ip in tot) printf "%s %d %d %d\n", ip, tot[ip], hits[ip] + 0, r429[ip] + 0 }
' "$RECENT" > "$statsfile"

nban=0
nalert=0

# 1) bad bots: probe hits at ANY speed -- auto-ban, no mail. A slow
#    scanner rotating IPs is exactly this shape (it never reaches the
#    heavy-bot rate).
while read -r sip stot shits sr429; do
    [ -n "$sip" ] || continue
    is_handled "$sip" && continue
    [ "$shits" -ge "$BADBOT_MIN" ] || continue
    [ "$nban" -ge "$MAX_AUTO_BAN" ] && break
    if auto_ban "$sip" bad-bot "$shits/$stot requests match scanner probe patterns ($slice)"; then
        :
    else
        alert "$sip" BAD-BOT "auto-ban failed or disabled; $shits probe hits in $stot requests ($slice)" \
            || true
    fi
    handled="$handled $sip"
    nban=$((nban + 1))
done < "$statsfile"

# 2) heavy bots: sustained per-IP rate over the delta window
if [ -n "$elapsed" ]; then
    while read -r sip stot shits sr429; do
        [ -n "$sip" ] || continue
        is_handled "$sip" && continue
        [ "$stot" -ge "$((HEAVY_RPS * elapsed))" ] || continue
        [ "$nban" -ge "$MAX_AUTO_BAN" ] && break
        srps=$((stot / elapsed))
        if auto_ban "$sip" heavy-bot "$stot requests in ${elapsed}s (~${srps} r/s sustained, threshold ${HEAVY_RPS}/s)"; then
            :
        else
            alert "$sip" HEAVY-BOT "auto-ban failed or disabled; $stot requests in ${elapsed}s (~${srps} r/s sustained, threshold ${HEAVY_RPS}/s)" \
                || true
        fi
        handled="$handled $sip"
        nban=$((nban + 1))
    done < "$statsfile"
fi

# 3) possible NAT / stuck client: piling up 429s on ordinary URLs. The
#    one signal that still mails a human -- automatic bans are impossible
#    here without risking real people behind a shared address.
while read -r sip stot shits sr429; do
    [ -n "$sip" ] || continue
    is_handled "$sip" && continue
    [ "$sr429" -gt "$RATELIMIT_THRESHOLD" ] || continue
    [ "$nalert" -ge "$MAX_ALERT" ] && break
    if alert "$sip" RATE-LIMIT "$sr429 throttled requests of $stot total ($slice)"; then
        handled="$handled $sip"
        nalert=$((nalert + 1))
    fi
done < "$statsfile"

# keep the state file small, then record this run's bookkeeping
tail -n 200 "$STATE" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
echo "meta:lastrun $now" >> "$STATE"
echo "meta:lastlines $total" >> "$STATE"

rm -f "$RECENT" "$statsfile"
