#!/bin/sh
# ---------------------------------------------------------------------------
# banish installer -- put the flood/ban defense tree onto this host.
#
# Usage (as root, from a checkout or the GitHub tarball):
#   sudo ./install.sh            install/update scripts + cron + logrotate
#   sudo ./install.sh --check    verify installed files match this checkout
#   sudo ./install.sh legacy     legacy variant (postfix mail, simple
#                                ban-ip; installs flood-detector.sh and
#                                ban-ip.sh; cron stays hand-managed)
#   sudo ./install.sh legacy --check
#                                 drift audit for a legacy box
#
# Idempotent: re-run on every update. Runtime state (/var/lib/bans.state,
# /var/lib/flood-detector.state, the logs) is never touched. cron and
# logrotate pick new files up automatically; no daemon reloads needed.
#
# Bootstrap on a new box (root or sudo; pin a tag for reprovisioning):
#   wget -qO- https://github.com/mipaaa/banish/archive/refs/heads/main.tar.gz \
#     | tar -xz -C /tmp
#   bash /tmp/banish-main/install.sh && rm -rf /tmp/banish-main
# ---------------------------------------------------------------------------
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/root"

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: must run as root (sudo)" >&2
    exit 1
fi

mode=${1:-install}
case "$mode" in
    install|--check|legacy) ;;
    *)
        echo "usage: $0 [--check | legacy [--check]]" >&2
        exit 1
        ;;
esac

check=0
if [ "$mode" = "--check" ] || [ "${2:-}" = "--check" ]; then
    check=1
    [ "$mode" = "--check" ] && mode=install
fi

fail=0

# do_file SRC DST PERM -- install, or compare when auditing drift
do_file() {
    src="$1"; dst="$2"; perm="$3"
    if [ "$check" = "1" ]; then
        if cmp -s "$src" "$dst"; then
            echo "ok:    $dst"
        else
            echo "DRIFT: $dst"
            fail=1
        fi
    else
        install -m "$perm" "$src" "$dst"
        echo "installed: $dst"
    fi
}

if [ "$mode" = "legacy" ]; then
    do_file "$ROOT/legacy/flood-detector-postfix.sh" \
        /usr/local/bin/flood-detector.sh 755
    do_file "$ROOT/legacy/ban-ip.sh" /usr/local/bin/ban-ip.sh 755
    if [ "$check" = "1" ]; then
        if [ "$fail" -eq 0 ]; then
            echo "all files match this checkout"
        fi
        exit "$fail"
    fi
    echo "note: /etc/cron.d/flood-detector on that box is managed by hand"
    echo "note: box settings (LOG, MAIL_TO, MAIL_FROM) are read from"
    echo "      /etc/banish/env -- create it if it does not exist yet"
    exit 0
fi

for f in flood-detector.sh ban-ip.sh ban-review.sh; do
    do_file "$SRC/usr/local/bin/$f" "/usr/local/bin/$f" 755
done
for f in flood-detector ban-review; do
    do_file "$SRC/etc/cron.d/$f" "/etc/cron.d/$f" 644
done
for f in flood-detector.logrotate ban-review.logrotate; do
    do_file "$SRC/etc/logrotate.d/$f" "/etc/logrotate.d/$f" 644
done

if [ "$check" = "1" ]; then
    if [ "$fail" -eq 0 ]; then
        echo "all files match this checkout"
    fi
    exit "$fail"
fi

command -v msmtp >/dev/null 2>&1 \
    || echo "note: msmtp missing -- alert mails will be skipped"
echo "done."
