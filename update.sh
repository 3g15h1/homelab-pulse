#!/usr/bin/env bash
# Update Homelab Pulse in place. Run as root INSIDE the Pulse container:
#   bash /opt/homelab-pulse/update.sh [ref]      (default ref: main; the settings page passes a release tag)
# Settings, token and overrides in /etc/homelab-pulse are untouched; the previous version is kept
# in /opt/homelab-pulse.prev. (Running install.sh again on the host does the same.)
set -euo pipefail
REF=${1:-main}
APP=/opt/homelab-pulse
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
python3 - "$REF" "$WORK/src.tgz" <<'PY'
import sys, urllib.request
urllib.request.urlretrieve(f"https://codeload.github.com/3g15h1/homelab-pulse/tar.gz/{sys.argv[1]}", sys.argv[2])
PY
tar -xzf "$WORK/src.tgz" -C "$WORK"
SRC=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -n1)
[ -f "$SRC/pulse/server.py" ] || { echo "download did not contain Pulse" >&2; exit 1; }
rm -rf "$APP.prev" "$APP.new"
mkdir -p "$APP.new"
cp -a "$SRC/pulse" "$SRC/README.md" "$SRC/LICENSE" "$SRC/update.sh" "$APP.new/"
[ -d "$APP" ] && mv "$APP" "$APP.prev"
mv "$APP.new" "$APP"
chown -R root:root "$APP" && chmod -R a+rX "$APP"
install -m 644 "$SRC/homelab-pulse.service" /etc/systemd/system/homelab-pulse.service
install -m 755 "$SRC/homelab-pulse-passwd" /usr/local/bin/homelab-pulse-passwd
if [ -f "$SRC/homelab-pulse-update" ]; then      # the upgrade button's root side (1.7+)
  install -m 755 "$SRC/homelab-pulse-update" /usr/local/sbin/homelab-pulse-update
  install -m 644 "$SRC/homelab-pulse-update.service" "$SRC/homelab-pulse-update.path" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable -q --now homelab-pulse-update.path
fi
systemctl daemon-reload
systemctl restart homelab-pulse
sleep 2
systemctl is-active homelab-pulse
