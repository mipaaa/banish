# banish

Flood and abuse detection plus IP-ban lifecycle for nginx sites.
Three POSIX sh scripts, two cron entries, two logrotate snippets. No
daemon, no dependencies beyond a base userland, iptables, and (for mail
alerts) msmtp.

nginx sheds the bulk of attacks (444 drop rules, limit_req zones);
banish is the eyes and the memory: it watches the access log, bans what
is safe to ban automatically, and keeps the ban list with an expiry
ladder. A human is mailed only when automatic action is impossible or
undesirable. Extracted from its original app repo; the nginx side stays
with each site.

## Layout

    root/                                  installs onto / via install.sh
      usr/local/bin/flood-detector.sh      detection + auto-ban (cron, 5 min)
      usr/local/bin/ban-ip.sh              ban now, persist, ladder state
      usr/local/bin/ban-review.sh          daily release/heal + digest report
                                           (cron 06:12)
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

## Visitor classes and actions (flood-detector.sh, every 5 minutes)

Humans and polite bots (search crawlers, well-behaved API clients)
match no class and are never touched; the rate thresholds sit an order
of magnitude above what a polite crawler sustains.

- bad bots: >= BADBOT_MIN probe hits in the analysis slice, at ANY
  speed. A probe hit is a request the site already dropped as scanner
  garbage (logged 444), an oversized URI (414), or any request whose
  URL matches PROBE_URL_REGEX regardless of status. Banned
  automatically with NO mail (AUTO_BAN): no legit visitor, carrier NAT
  or not, pulls /wp-login.php or /.config/rclone.conf five times in
  five minutes. This is the class that catches slow IP-rotating
  scanners -- they never reach the heavy-bot rate. The AUTO-BAN log
  lines plus top probe URLs in /var/log/flood-detector.log are the
  audit trail
- heavy bots: one IP sustaining more than HEAVY_RPS requests/second,
  measured as the delta between consecutive runs (a true rate, not a
  share of traffic -- a lone polite crawler never trips it). Banned
  automatically the same way, no mail
- possible NAT / stuck client: one IP collecting many 429s
  (RATELIMIT_THRESHOLD) shed by the site limit_req zones WITHOUT
  qualifying as a bad bot -- could be real people behind a shared
  address or a broken client in a retry loop. The one signal that
  still mails a human (at most one mail per IP+reason per COOLDOWN),
  since an automatic ban is undesirable here

Auto-bans call ban-ip.sh with --days AUTO_BAN_DAYS (strike-1 duration
only). Every auto-ban is also appended as one line to the DIGEST file;
ban-review.sh rolls those lines into its daily report -- the admin's
regular visibility into silent bans, without per-event mail. If the
ban command itself fails, the human alert mail is sent instead
(auto-ban impossible -> notify). AUTO_BAN=0 rolls every class back to
human alerts without a redeploy. An IP already acted on in a run
(banned or mailed) never triggers a second mail in the same run.

The alert mail embeds the alerting IP's footprint (top requests,
claimed user agents, statuses, raw tail) captured from the run's
analysis slice, so the evidence survives the daily log rotation that
can race the alert. The mail also carries copy-paste ban commands for
the alerting IP and its whole /24 subnet.

## Ban lifecycle (ban-ip.sh + ban-review.sh)

- ban-ip.sh <ipv4[/prefix]> [--forever] [--days N] [reason words...] --
  iptables DROP now, persistence via /etc/rc.local (regenerated from
  state; never hand-edit), recorded in /var/lib/bans.state with a
  ladder: strike 1 -> 7 days, strike 2 -> 30 days, strike 3+ (or
  --forever) -> permanent. --days N overrides the strike-1 duration
  only (the detector's auto-bans pass --days 1: their IPs are mostly
  single-use, so a short first ban keeps the firewall and state small,
  while genuine recidivists still climb the full ladder)
- ban-review.sh (daily 06:12) releases a ban only when expired AND
  quiet for 3 days (iptables DROP counter roughly flat: under
  QUIET_PKTS/day; a reboot restarts the quiet clock), heals missing
  firewall rules, regenerates /etc/rc.local, and mails a report when
  it released or healed something -- or when the detector's DIGEST
  file (auto-ban lines since the last review) is non-empty. The digest
  is cleared once reported, and kept for retry when msmtp fails
- released IPs move to probation ("hist" records, kept forever); if the
  detector acts on one again, ban-ip.sh re-bans it automatically with
  the next ladder strike (AUTO_REBAN)
- subnet bans: ban-ip.sh also takes IPv4 CIDR (ban-ip.sh 185.177.72.0/24)
  through the same ladder. The key is normalized to the network base
  (host bits masked), so the state file, "iptables -L" output and
  /etc/rc.local always agree. Two caveats: a broader rule shadows
  single-IP bans beneath it (their DROP counters look flat, so review
  may release those early -- harmless, the subnet rule still covers
  them), and probation auto-reban matches keys exactly -- members of a
  released subnet still alert but are never auto-re-banned; a human
  re-bans the subnet

Manual unban of a still-listed IP (works for CIDR subnet keys too; note
the | sed delimiters -- a CIDR key contains a slash):

    sudo iptables -D INPUT -s <ip> -j DROP
    sudo sed -i '\|^ban <ip> |d;\|^ctr <ip> |d' /var/lib/bans.state
    sudo /usr/local/bin/ban-review.sh   # regenerates /etc/rc.local

## Site contract

banish only reads what the site produces. A site needs:

- an nginx access log whose first field is the client IP and whose
  status codes sit right after the quoted request (any combined-format
  log). LOG: env var, a LOG= line in the env file, or the default
  /var/log/nginx/access.log
- the defensive rules themselves, in its own vhost: 444 drop rules for
  SQLi tokens and scanner probe paths, and limit_req zones producing
  429 (414 is nginx built-in). banish never adds nginx config
- logging of what it sheds: requests dropped with a logged status
  (444/414/429) stay visible to the detector, URLs included -- that is
  what feeds the bad-bot class (444/414/probe-URL hits) and the
  NAT/stuck-client signal (429s). Anything the site leaves unlogged
  (nginx access_log if= exclusions -- on this site: the i_wanna_buy
  legacy paths, pure noise not worth banning on) is invisible to every
  banish signal, by the site's choice
- msmtp for alert mail (apt install msmtp)
- an env file with SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD,
  SMTP_TLS, SMTP_FROM; default ENV_FILE=/etc/banish/env -- typically a
  symlink to the site's existing mailer env (override per site), or plain
  env lines in the cron files. The detector's tuning knobs (BADBOT_MIN,
  HEAVY_RPS, RATELIMIT_THRESHOLD, COOLDOWN, WINDOW, AUTO_REBAN,
  AUTO_BAN, AUTO_BAN_DAYS, PROBE_URL_REGEX, DIGEST)
  and LOG also read KEY= lines from this env file
- MAIL_TO (env var, a MAIL_TO= line in the env file, or the placeholder
  default alerts@example.com that delivers nowhere)

Sketch of the rules the detector keys on -- the zone lives in http {},
the application in the vhost:

    # http {} -- one shared-memory counter bucket per client IP
    limit_req_zone $binary_remote_addr zone=site_perip:10m rate=15r/s;

    # vhost
    server {
        # Combined format is enough: client IP first, status right
        # after the quoted request -- that is what the parser expects.
        access_log /var/log/nginx/site-access.log combined;

        # Scanner noise: dropped without a response (444), still LOGGED
        # so the detector can ban the source. Tune the token set to
        # your threat picture; this one blunted a real sqlmap-style
        # probe flood.
        if ($request_uri ~* "(union.*select|information_schema|benchmark\(|sleep\(|waitfor.*delay|extractvalue\(|order(%20|\+|%2B|\s)*by)") {
            return 444;
        }
        # Common scanner probe paths (WordPress, dotfiles incl.
        # .env/.config, admin panels, actuator) -- same treatment:
        # dropped before limit_req and the app, still logged.
        # Paths to drop UNLOGGED (pure-noise legacy URLs) belong in an
        # access_log if= map instead, and are then gone from every
        # banish signal by design.
        if ($request_uri ~* "^/(api/)?(actuator|\.git|\.env|\.config|wp-[a-z0-9.-]*|xmlrpc\.php|phpmyadmin|cgi-bin)(/|\?|$)") {
            return 444;
        }

        location / {
            limit_req zone=site_perip burst=30 nodelay;
            limit_req_status 429;   # not 503: 429 says "nginx throttled
                                    # this client" -- the NAT/stuck-client
                                    # signal
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
(/var/lib/bans.state, /var/lib/flood-detector.state, the logs, the
digest).

## Knobs (environment; full list in the script headers)

    flood-detector.sh  LOG OUT STATE RECENT DIGEST ENV_FILE WINDOW
                       BADBOT_MIN(5) HEAVY_RPS(15) RATELIMIT_THRESHOLD(100)
                       COOLDOWN(3600) MAIL_TO SERVER_TAG BANS_STATE
                       AUTO_REBAN(1) BAN_CMD MSMTP_BIN TESTMODE
                       AUTO_BAN(1) AUTO_BAN_DAYS(1) MAX_AUTO_BAN(10)
                       MAX_ALERT(5) PROBE_URL_REGEX(default list in the
                       script header)
    ban-ip.sh          STATE RCLOCAL BAN_T1(604800) BAN_T2(2592000)
    ban-review.sh      STATE RCLOCAL OUT ENV_FILE DIGEST MAIL_TO
                       SERVER_TAG QUIET_SECS(259200) QUIET_PKTS(100)
                       TESTMODE

Set them via env lines in the cron files (canonical: root/etc/cron.d/)
or KEY= lines in the env file (ENV_FILE, default /etc/banish/env); the
detector's tuning knobs (BADBOT_MIN, HEAVY_RPS, RATELIMIT_THRESHOLD,
COOLDOWN, WINDOW, AUTO_REBAN, AUTO_BAN, AUTO_BAN_DAYS, PROBE_URL_REGEX,
DIGEST) and LOG/MAIL_TO honor both. An environment variable beats the
env file, which beats the built-in default. Mail settings (SMTP_*) live
in the env file.

## Testing

    # detector: two runs ~a minute apart; the second classifies and acts
    sudo TESTMODE=1 BADBOT_MIN=2 OUT=/tmp/fd.log STATE=/tmp/fd.state \
      RECENT=/tmp/fd.recent DIGEST=/tmp/fd.digest \
      /usr/local/bin/flood-detector.sh

    # auto-ban dry run: point BAN_CMD and MSMTP_BIN at stub scripts to
    # capture the ban call and the mail without iptables/msmtp

    # ban ladder fast lane (see ban-review.sh header)
    STATE=/tmp/bans.state RCLOCAL=/tmp/rc.local /usr/local/bin/ban-ip.sh 192.0.2.1

Careful: outside TESTMODE and /tmp paths, ban-ip.sh inserts a REAL
iptables rule even with STATE/RCLOCAL redirected.

## Updating the boxes

Edit, commit, push, then re-run the bootstrap snippet (or install.sh
from a checkout) on every box; cron and logrotate pick the changes up
on their next run. Use --check to audit drift during incident reviews.

## License

MIT; see LICENSE.
