# banish

Flood and abuse detection plus IP-ban lifecycle for nginx sites.
Three POSIX sh scripts, two cron entries, two logrotate snippets. No
daemon, no dependencies beyond a base userland, iptables, and (for mail
alerts) msmtp.

nginx sheds the bulk of attacks (SQLi drop rule, limit_req zones);
banish is the eyes and the memory: it watches the access log, alerts
a human, and keeps the ban list with an expiry ladder. Extracted
from its original app repo; the nginx side stays with each site.

## Layout

    root/                                  installs onto / via install.sh
      usr/local/bin/flood-detector.sh      detection + alerting (cron, 5 min)
      usr/local/bin/ban-ip.sh              ban now, persist, ladder state
      usr/local/bin/ban-review.sh          daily release/heal review (cron 06:12)
      etc/cron.d/flood-detector
      etc/cron.d/ban-review
      etc/logrotate.d/flood-detector.logrotate
      etc/logrotate.d/ban-review.logrotate
    legacy/flood-detector-postfix.sh       older port for the original
                                           server: postfix mail, box
                                           settings (LOG, MAIL_TO,
                                           MAIL_FROM) from the same
                                           ENV_FILE path as the mainline
    legacy/ban-ip.sh                       its simple ban companion
                                           (iptables + /etc/rc.local
                                           mirror; no ladder, no review)
    install.sh                             installer (--check, legacy)

## Detection signals (flood-detector.sh, every 5 minutes)

- FLOOD: one IP sustaining more than FLOOD_RPS requests/second,
  measured as the delta between consecutive runs (a true rate, not a
  share of traffic -- a lone polite crawler never trips it)
- SQLI-PROBE: requests dropped by the site SQLi rule (status 444) or
  oversized URIs (414), beyond SQLI_THRESHOLD per run
- RATE-LIMIT: one IP collecting many 429s shed by the site limit_req zones

Each alert lands in /var/log/flood-detector.log and in an e-mail (msmtp),
at most one per IP+reason per COOLDOWN (1 h). The mail embeds the
alerting IP's footprint (top requests, claimed user agents, statuses,
raw tail) captured from the run's analysis slice, so the evidence
survives the daily log rotation that can race the alert. First bans are
made by a human (carrier NAT can hide real customers behind one
address); only probationers that re-offend are re-banned automatically.

## Ban lifecycle (ban-ip.sh + ban-review.sh)

- ban-ip.sh <ip> [--forever] [reason words...] -- iptables DROP now,
  persistence via /etc/rc.local (regenerated from state; never
  hand-edit), recorded in /var/lib/bans.state with a ladder:
  strike 1 -> 7 days, strike 2 -> 30 days, strike 3+ (or --forever) ->
  permanent
- ban-review.sh (daily 06:12) releases a ban only when expired AND
  quiet for 3 days (iptables DROP counter roughly flat: under
  QUIET_PKTS/day; a reboot restarts the quiet clock), heals missing
  firewall rules, regenerates /etc/rc.local, and mails a report only
  when it released or healed something
- released IPs move to probation ("hist" records, kept forever); if the
  detector alerts on one again, ban-ip.sh re-bans it automatically with
  the next ladder strike (AUTO_REBAN)

Manual unban of a still-listed IP:

    sudo iptables -D INPUT -s <ip> -j DROP
    sudo sed -i '/^ban <ip> /d;/^ctr <ip> /d' /var/lib/bans.state
    sudo /usr/local/bin/ban-review.sh   # regenerates /etc/rc.local

## Site contract

banish only reads what the site produces. A site needs:

- an nginx access log whose first field is the client IP and whose
  status codes sit in the usual quoted position (any combined-format
  log). LOG: env var, a LOG= line in the env file, or the default
  /var/log/nginx/access.log
- the defensive rules themselves, in its own vhost: a SQLi drop rule
  (return 444) and limit_req zones producing 429 (414 is nginx
  built-in). banish never adds nginx config
- msmtp for alert mail (apt install msmtp)
- an env file with SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD,
  SMTP_TLS, SMTP_FROM; default ENV_FILE=/etc/banish/env -- typically a
  symlink to the site's existing mailer env (override per site), or plain
  env lines in the cron files
- MAIL_TO (env var, a MAIL_TO= line in the env file, or the placeholder
  default alerts@example.com that delivers nowhere)

Sketch of the rules the detector keys on -- the zone lives in http {},
the application in the vhost:

    # http {} -- one shared-memory counter bucket per client IP
    limit_req_zone $binary_remote_addr zone=site_perip:10m rate=15r/s;

    # vhost
    server {
        # Combined format is enough: client IP first, status right
        # after the quoted request -- that is what the greps expect.
        access_log /var/log/nginx/site-access.log combined;

        # SQLi scanner noise: dropped without a response (444). Tune the
        # token set to your threat picture; this one blunted a real
        # sqlmap-style probe flood.
        if ($request_uri ~* "(union.*select|information_schema|benchmark\(|sleep\(|waitfor.*delay|extractvalue\(|order(%20|\+|%2B|\s)*by)") {
            return 444;
        }

        location / {
            limit_req zone=site_perip burst=30 nodelay;
            limit_req_status 429;   # not 503: 429 says "nginx throttled
                                    # this client" -- the RATE-LIMIT signal
            # ... proxy or serve your site ...
        }
    }

## Install

From a checkout:

    sudo ./install.sh

From GitHub (bootstrap; pin a tag for reprovisioning):

    wget -qO- https://github.com/mipaaa/banish/archive/refs/heads/main.tar.gz | tar -xz -C /tmp
    bash /tmp/banish-main/install.sh && rm -rf /tmp/banish-main

Drift audit (installed files vs this checkout):

    sudo ./install.sh --check          # mainline boxes
    sudo ./install.sh legacy --check   # legacy box

Legacy variant (postfix mail, simple ban-ip; cron and the env file stay
hand-managed on that box):

    sudo ./install.sh legacy

Box settings for the legacy variant live in /etc/banish/env (LOG,
MAIL_TO, MAIL_FROM); postfix handles the relay, so no SMTP_* keys are
needed there.

Install is idempotent and never touches runtime state
(/var/lib/bans.state, /var/lib/flood-detector.state, the logs).

## Knobs (environment; full list in the script headers)

    flood-detector.sh  LOG OUT STATE RECENT ENV_FILE WINDOW FLOOD_RPS(10)
                       SQLI_THRESHOLD(3) RATELIMIT_THRESHOLD(100)
                       COOLDOWN(3600) MAIL_TO SERVER_TAG BANS_STATE
                       AUTO_REBAN(1) BAN_CMD MSMTP_BIN TESTMODE
    ban-ip.sh          STATE RCLOCAL BAN_T1(604800) BAN_T2(2592000)
    ban-review.sh      STATE RCLOCAL OUT ENV_FILE MAIL_TO SERVER_TAG
                       QUIET_SECS(259200) QUIET_PKTS(100) TESTMODE

Set them via env lines in the cron files (canonical: root/etc/cron.d/);
mail settings (SMTP_*, MAIL_TO) usually live in the env file instead.

## Testing

    # detector: two runs ~a minute apart; the second alerts + mails
    sudo TESTMODE=1 FLOOD_RPS=1 OUT=/tmp/fd.log STATE=/tmp/fd.state \
      RECENT=/tmp/fd.recent /usr/local/bin/flood-detector.sh

    # ban ladder fast lane (see ban-review.sh header)
    STATE=/tmp/bans.state RCLOCAL=/tmp/rc.local /usr/local/bin/ban-ip.sh 192.0.2.1

Careful: outside TESTMODE and /tmp paths, ban-ip.sh inserts a REAL
iptables rule even with STATE/RCLOCAL redirected.

## Updating the boxes

Edit, commit, push, then re-run the bootstrap snippet (or install.sh
from a checkout) on every box; cron and logrotate pick the changes up
on their next run. Use --check to audit drift during incident reviews.
