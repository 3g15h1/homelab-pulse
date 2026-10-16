#!/usr/bin/env bash
# Homelab Pulse installer. Run as root on a Proxmox VE host:
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/3g15h1/homelab-pulse/main/install.sh)"
#
# Creates an unprivileged Debian LXC, a read-only Proxmox user (pulse@pve, role PVEAuditor) with an
# API token, and installs Pulse as a systemd service. Run it again to upgrade: the container is
# found by its "homelab-pulse" tag, and its token, CA and settings are kept.
set -euo pipefail

REPO="3g15h1/homelab-pulse"
REF="main"
VMID="" STORAGE="" BRIDGE="vmbr0" IP="dhcp" GW="" SRC="" ROTATE=0 DRY=0 SHOW_PW=0 HEAL="" UPDATES=0
HOSTOP="" HOSTARG="" LABEL=""
APP=/opt/homelab-pulse
ETC=/etc/homelab-pulse
TAG=homelab-pulse
PVE_USER=pulse@pve

usage() {
  cat <<EOF
Usage: install.sh [options]

  --vmid N          container ID (default: next free; with an existing container: upgrade it)
  --storage NAME    storage for the container disk (default: first storage that holds containers)
  --bridge NAME     network bridge (default: vmbr0)
  --ip CIDR|dhcp    container address, e.g. 192.168.1.60/24 (default: dhcp)
  --gw IP           gateway, needed with a static --ip
  --ref REF         git branch or tag to install (default: main)
  --src DIR         install from a local checkout instead of downloading
  --rotate-token    create a new API token even if the container already has one
  --with-updates    also grant Sys.Modify (enables the Proxmox-update check)
  --show-password   print the existing admin password for the settings page
  --enable-heal     set up self-healing: the pulse-heal-gate on this host + a restricted SSH key for Pulse
  --disable-heal    remove self-healing (gate, key); keeps your recipes in /etc/pulse-heal/recipes.d

 More Proxmox hosts (ones that aren't in this host's cluster):
  --add-host IP     connect Pulse to another Proxmox host: logs in to root@IP over SSH once to
                    create a read-only token there. Without SSH, run --extra-host on that host and
                    pass the line it prints instead of the IP:  --add-host 'pulse-host:...'
  --label NAME      what Pulse calls that host (default: its node name); NAME/<vmid> in overrides.json
  --remove-host NAME   disconnect a host added with --add-host
  --list-hosts      list the hosts Pulse watches besides this one
  --extra-host      run on the *other* host: create the read-only token, print the line for --add-host
  --dry-run         print every change instead of making it
  -h, --help        this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --vmid) VMID=$2; shift 2 ;;
    --storage) STORAGE=$2; shift 2 ;;
    --bridge) BRIDGE=$2; shift 2 ;;
    --ip) IP=$2; shift 2 ;;
    --gw) GW=$2; shift 2 ;;
    --ref) REF=$2; shift 2 ;;
    --src) SRC=$2; shift 2 ;;
    --rotate-token) ROTATE=1; shift ;;
    --with-updates) UPDATES=1; shift ;;
    --show-password) SHOW_PW=1; shift ;;
    --enable-heal) [ "$HEAL" = disable ] && { echo "Choose --enable-heal or --disable-heal" >&2; exit 2; }; HEAL=enable; shift ;;
    --disable-heal) [ "$HEAL" = enable ] && { echo "Choose --enable-heal or --disable-heal" >&2; exit 2; }; HEAL=disable; shift ;;
    --add-host) HOSTOP=add; HOSTARG=${2:-}; shift 2 ;;
    --remove-host) HOSTOP=remove; HOSTARG=${2:-}; shift 2 ;;
    --list-hosts) HOSTOP=list; shift ;;
    --extra-host) HOSTOP=extra; shift ;;
    --label) LABEL=$2; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
# Every change goes through run(): printed in --dry-run, executed otherwise.
run() {
  if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi
}
# Same for a shell snippet executed inside the container.
in_ct() {
  if [ "$DRY" = 1 ]; then printf '+ pct exec %s -- sh -c %q\n' "$VMID" "$1"; else pct exec "$VMID" -- sh -c "$1"; fi
}

# ------------------------------------------------------------------ preflight
[ "$(id -u)" = 0 ] || [ "${PULSE_ASSUME_ROOT:-}" = 1 ] || die "run as root on the Proxmox host"
for c in pveversion pct pveum pvesh pveam pvesm; do
  command -v "$c" >/dev/null || die "'$c' not found: this must run on a Proxmox VE host"
done
PVE_VER=$(pveversion | sed -n 's|^pve-manager/\([0-9]*\)\..*|\1|p')
[ -n "$PVE_VER" ] && [ "$PVE_VER" -ge 8 ] || die "Proxmox VE 8 or newer is required"
if [ "$PVE_VER" -lt 9 ]; then
  say "Note: on Proxmox VE 8 a read-only token can't ask the QEMU guest agent for VM addresses."
  say "      Containers are fine; give VMs a static IP or a pulse-ip-a-b-c-d tag."
fi
if [ "$IP" != dhcp ] && [ -z "$GW" ]; then die "--ip needs --gw"; fi

json_get() {  # json_get <python expression on d> : reads JSON on stdin
  python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"
}
HOST_IP=$(pvesh get /cluster/status --output-format json |
  json_get 'next((e.get("ip") or "") for e in d if e.get("type") == "node" and e.get("local"))')
[ -n "$HOST_IP" ] || die "could not work out this node's IP from /cluster/status"

# ------------------------------------------------------------------ more Proxmox hosts
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
HOSTS_DIR=$ETC/hosts
has_tag() { pct config "$1" 2>/dev/null | grep -qE "^tags:.*\b$TAG\b"; }
find_pulse() {   # VMID of the Pulse container on this host (--vmid, or the tagged one)
  if [ -n "$VMID" ]; then pct config "$VMID" >/dev/null 2>&1 || die "CT $VMID doesn't exist"; return; fi
  for id in $(pct list | awk 'NR>1 {print $1}'); do
    if has_tag "$id"; then VMID=$id; return; fi
  done
  die "no Homelab Pulse container on this host (install Pulse first, or pass --vmid)"
}
# Runs on the other host (locally for --extra-host, over SSH for --add-host IP): a read-only
# pulse@pve user and token there, printed with that host's address, node name and CA as one line.
cat > "$WORK/extra-host.sh" <<'REMOTE'
set -eu
TID=$1 USER=pulse@pve
command -v pveum >/dev/null || { echo "Error: not a Proxmox VE host" >&2; exit 1; }
pveum user list --output-format json |
  python3 -c 'import json,sys; sys.exit(0 if any(u["userid"] == "pulse@pve" for u in json.load(sys.stdin)) else 1)' ||
  pveum user add "$USER" --comment "Homelab Pulse (read-only dashboard)" >&2
pveum acl modify / --users "$USER" --roles PVEAuditor >&2
if pveum user token list "$USER" --output-format json 2>/dev/null |
     python3 -c 'import json,sys; sys.exit(0 if any(t["tokenid"] == sys.argv[1] for t in json.load(sys.stdin)) else 1)' "$TID"; then
  pveum user token remove "$USER" "$TID" >&2
fi
umask 077
T=$(mktemp)
trap 'rm -f "$T"' EXIT
pveum user token add "$USER" "$TID" --privsep 0 --output-format json > "$T"
pvesh get /cluster/status --output-format json | python3 -c '
import base64, json, sys
tok = json.load(open(sys.argv[1]))
node = next(e for e in json.load(sys.stdin) if e.get("type") == "node" and e.get("local"))
d = {"host": node["ip"], "port": 8006, "node": node["name"], "token": "pulse@pve!" + sys.argv[2] + "=" + tok["value"],
     "ca": open("/etc/pve/pve-root-ca.pem").read()}
print("pulse-host:" + base64.urlsafe_b64encode(json.dumps(d).encode()).decode())' "$T" "$TID"
REMOTE

if [ "$HOSTOP" = extra ]; then
  TID=pulse-remote
  if [ "$DRY" = 1 ]; then
    echo "+ pveum user add $PVE_USER (if missing); pveum acl modify / --users $PVE_USER --roles PVEAuditor"
    echo "+ pveum user token add $PVE_USER $TID --privsep 0   (printed as a pulse-host: line)"
    say "Dry run: nothing was changed."; exit 0
  fi
  say "Creating a read-only token for Pulse on this host ($PVE_USER!$TID, role PVEAuditor)"
  LINE=$(bash "$WORK/extra-host.sh" "$TID")
  cat <<EOF

  On the Proxmox host that runs Pulse, run the installer with:

    --add-host '$LINE'

  (It contains the token's secret: don't paste it anywhere public.)
EOF
  exit 0
fi

if [ -n "$HOSTOP" ]; then
  find_pulse
  [ "$DRY" = 1 ] || [ "$(pct status "$VMID" | awk '{print $2}')" = running ] || die "CT $VMID isn't running"
  hosts_json() {   # the hosts Pulse has, one JSON object per line
    pct exec "$VMID" -- sh -c "for f in $HOSTS_DIR/*.json; do [ -f \"\$f\" ] && tr -d '\n' < \"\$f\" && echo; done; true"
  }
  case "$HOSTOP" in
  list)
    LIST=$(hosts_json)
    if [ -z "$LIST" ]; then say "Pulse in CT $VMID watches only this host's cluster."; exit 0; fi
    printf '%s\n' "$LIST" | python3 -c '
import json, sys
for line in sys.stdin:
    if line.strip():
        h = json.loads(line)
        print("  %-16s %-16s node %-12s slot %s" % (h["label"], h["host"], h.get("tls_name") or "?", h["slot"]))'
    exit 0 ;;
  remove)
    [ -n "$HOSTARG" ] || die "--remove-host needs the host's name (see --list-hosts)"
    H=$(hosts_json | python3 -c '
import json, sys
for line in sys.stdin:
    if line.strip() and json.loads(line)["label"] == sys.argv[1]:
        h = json.loads(line); print(h["host"], h["token"].split("=")[0].split("!")[1])' "$HOSTARG")
    [ -n "$H" ] || die "Pulse has no host called '$HOSTARG' (see --list-hosts)"
    say "Disconnecting $HOSTARG"
    in_ct "rm -f $HOSTS_DIR/$HOSTARG.json $HOSTS_DIR/$HOSTARG-ca.pem && systemctl restart homelab-pulse"
    say "Its read-only token still exists on ${H% *}; to delete it, run there:  pveum user token remove $PVE_USER ${H#* }"
    if [ "$DRY" = 1 ]; then say "Dry run: nothing was changed."; fi
    exit 0 ;;
  add)
    umask 077                          # the files below hold the other host's token
    [ -n "$HOSTARG" ] || die "--add-host needs the other host's IP, or the pulse-host: line from --extra-host there"
    case "$HOSTARG" in
    pulse-host:*) LINE=$HOSTARG ;;
    *)
      if [ "$DRY" = 1 ]; then
        echo "+ ssh root@$HOSTARG: pveum user add $PVE_USER; acl PVEAuditor; pveum user token add $PVE_USER pulse-ct$VMID --privsep 0"
        LINE=""
      else
        say "Creating a read-only token on $HOSTARG (you may be asked for its root password once)"
        LINE=$(ssh -o StrictHostKeyChecking=accept-new "root@$HOSTARG" bash -s -- "pulse-ct$VMID" < "$WORK/extra-host.sh") ||
          die "couldn't set up $HOSTARG over SSH; run 'install.sh --extra-host' there and pass the line it prints"
      fi ;;
    esac
    if [ -n "$LINE" ]; then
      printf '%s' "${LINE#pulse-host:}" | python3 -c '
import base64, json, sys
d = json.loads(base64.urlsafe_b64decode(sys.stdin.read().strip() + "=="))
for k in ("host", "node", "token", "ca"):
    assert d.get(k), k
json.dump(d, open(sys.argv[1], "w"))' "$WORK/new.json" 2>/dev/null || die "that pulse-host: line is damaged; copy it again"
    else      # dry run with an IP: nothing was created over there, so describe a placeholder
      printf '{"host": "%s", "port": 8006, "node": "pve", "token": "pulse@pve!pulse-ct%s=<secret>", "ca": "<ca>"}' \
        "$HOSTARG" "$VMID" > "$WORK/new.json"
    fi
    NEW_IP=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["host"])' "$WORK/new.json")
    if pvesh get /cluster/status --output-format json |
         json_get '"\n".join(e.get("ip") or "" for e in d if e.get("type") == "node")' | grep -qxF "$NEW_IP"; then
      die "$NEW_IP is a node of this cluster; Pulse already watches it"
    fi
    hosts_json > "$WORK/have.jsonl"
    python3 - "$WORK/new.json" "$WORK/have.jsonl" "$LABEL" "$WORK" <<'PY' || exit 1
import json, re, sys
new, have_file, label, work = sys.argv[1:5]
d = json.load(open(new))
have = [json.loads(line) for line in open(have_file) if line.strip()]
label = (label or re.sub(r"[^a-z0-9-]+", "-", d["node"].lower())).strip("-")[:31]
if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}", label):
    sys.exit(f"Error: --label must be lowercase letters, digits and dashes (got {label!r})")
same = next((h for h in have if h["label"] == label), None)
other = next((h for h in have if h["host"] == d["host"] and h["label"] != label), None)
if other:
    sys.exit(f"Error: {d['host']} is already connected as {other['label']!r} (--remove-host {other['label']} first)")
slot = same["slot"] if same else max([h["slot"] for h in have] + [0]) + 1     # re-adding keeps the slot
json.dump({"label": label, "slot": slot, "host": d["host"], "port": d.get("port", 8006), "token": d["token"],
           "tls_name": d["node"]}, open(f"{work}/host.json", "w"), indent=1)
open(f"{work}/host-ca.pem", "w").write(d["ca"])
PY
    read -r HLABEL HSLOT HNODE < <(python3 -c 'import json,sys; h=json.load(open(sys.argv[1])); print(h["label"], h["slot"], h["tls_name"])' "$WORK/host.json")
    say "Connecting $HLABEL ($NEW_IP, node $HNODE, slot $HSLOT) to Pulse in CT $VMID"
    in_ct "install -d -m 750 -o root -g pulse $HOSTS_DIR"
    run pct push "$VMID" "$WORK/host.json" "$HOSTS_DIR/$HLABEL.json" --perms 640 --group pulse
    run pct push "$VMID" "$WORK/host-ca.pem" "$HOSTS_DIR/$HLABEL-ca.pem" --perms 644
    in_ct "python3 -c 'import socket,sys; socket.create_connection((sys.argv[1], 8006), 5)' $NEW_IP" ||
      say "Warning: CT $VMID can't reach $NEW_IP:8006 right now; Pulse will keep trying"
    in_ct "systemctl restart homelab-pulse"
    if [ "$DRY" = 1 ]; then say "Dry run: nothing was changed."; exit 0; fi
    cat <<EOF

  $HLABEL is connected. Its node and guests show up on the dashboard within a minute.
  In overrides.json, refer to its guests as $HLABEL/<vmid> (e.g. "$HLABEL/100"): their VMIDs may repeat this host's.
  Self-healing stays limited to this host's guests.
  Disconnect:  install.sh --remove-host $HLABEL
EOF
    exit 0 ;;
  esac
fi

# ------------------------------------------------------------------ source
if [ -z "$SRC" ] && [ -f "$(dirname "$0")/pulse/server.py" ]; then SRC=$(cd "$(dirname "$0")" && pwd); fi
if [ -z "$SRC" ]; then
  say "Downloading $REPO@$REF"
  curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$REF" | tar -xz -C "$WORK"
  SRC=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -n1)
fi
[ -f "$SRC/pulse/server.py" ] || die "no Pulse source found in $SRC"

# ------------------------------------------------------------------ new or upgrade?
UPGRADE=0
if [ -n "$VMID" ] && pct config "$VMID" >/dev/null 2>&1; then
  UPGRADE=1
  has_tag "$VMID" || run pct set "$VMID" --tags "$( (pct config "$VMID" | sed -n 's/^tags: //p'; echo $TAG) | paste -sd';')"
elif [ -z "$VMID" ]; then
  for id in $(pct list | awk 'NR>1 {print $1}'); do
    if has_tag "$id"; then VMID=$id; UPGRADE=1; break; fi
  done
fi

if [ "$UPGRADE" = 1 ]; then
  say "Upgrading Homelab Pulse in CT $VMID"
else
  VMID=${VMID:-$(pvesh get /cluster/nextid)}
  STORAGE=${STORAGE:-$(pvesm status --content rootdir | awk 'NR>1 && $3=="active" {print $1; exit}')}
  [ -n "$STORAGE" ] || die "no active storage for containers; pass --storage"
  TEMPLATE=$(pveam list "$(pvesm status --content vztmpl | awk 'NR>1 && $3=="active" {print $1; exit}')" 2>/dev/null |
    awk '/debian-13-standard_.*_amd64/ {print $1}' | sort -V | tail -n1)
  if [ -z "$TEMPLATE" ]; then
    TSTORE=$(pvesm status --content vztmpl | awk 'NR>1 && $3=="active" {print $1; exit}')
    run pveam update >/dev/null
    TNAME=$(pveam available --section system | awk '/debian-13-standard_.*_amd64/ {print $2}' | sort -V | tail -n1)
    [ -n "$TNAME" ] || die "no Debian 13 template available from pveam"
    run pveam download "$TSTORE" "$TNAME"
    TEMPLATE="$TSTORE:vztmpl/$TNAME"
  fi
  NET="name=eth0,bridge=$BRIDGE,ip=$IP"
  [ "$IP" = dhcp ] || NET="$NET,gw=$GW"
  say "Creating CT $VMID from $TEMPLATE"
  run pct create "$VMID" "$TEMPLATE" --hostname pulse --cores 1 --memory 512 --swap 256 \
    --rootfs "$STORAGE:4" --net0 "$NET" --unprivileged 1 --features nesting=1 --onboot 1 \
    --tags "$TAG" --description "Homelab Pulse: https://github.com/$REPO"
  run pct start "$VMID"
  in_ct 'i=0; until ip -4 route | grep -q default && getent hosts deb.debian.org >/dev/null; do i=$((i+1)); [ $i -gt 60 ] && exit 1; sleep 1; done'
  in_ct 'command -v python3 >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3; }'
fi

if [ "$DRY" = 0 ] && [ "$(pct status "$VMID" | awk '{print $2}')" != running ]; then run pct start "$VMID"; fi

# ------------------------------------------------------------------ read-only Proxmox user + token
pveum user list --output-format json | json_get 'any(u["userid"] == "'$PVE_USER'" for u in d)' | grep -q True ||
  run pveum user add "$PVE_USER" --comment "Homelab Pulse (read-only dashboard)"
PVE_ROLES="PVEAuditor"
if [ "$UPDATES" = 1 ]; then
  pveum role list --output-format json | json_get 'any(r["roleid"] == "PulseUpdates" for r in d)' | grep -q True ||
    run pveum role add PulseUpdates --privs Sys.Modify
  PVE_ROLES="PVEAuditor,PulseUpdates"
  say "API token also gets Sys.Modify (enables the Proxmox update check)"
fi
run pveum acl modify / --users "$PVE_USER" --roles "$PVE_ROLES"

in_ct "id pulse >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin pulse; install -d -m 750 -o root -g pulse $ETC"
# Let the service user ping (unprivileged ICMP, for the gateway check) without raw-socket rights.
in_ct 'g=$(getent group pulse | cut -d: -f3); printf "net.ipv4.ping_group_range = %s %s\n" "$g" "$g" > /etc/sysctl.d/60-homelab-pulse-ping.conf; sysctl -q -p /etc/sysctl.d/60-homelab-pulse-ping.conf 2>/dev/null || true'

TOKEN_ID="ct$VMID"   # one token per container, so a second install never touches another's token
HAVE_TOKEN=0
if [ "$UPGRADE" = 1 ] && pct exec "$VMID" -- test -s "$ETC/pve-token"; then HAVE_TOKEN=1; fi
if [ "$HAVE_TOKEN" = 0 ] || [ "$ROTATE" = 1 ]; then
  say "Creating API token $PVE_USER!$TOKEN_ID (read-only)"
  if [ "$DRY" = 0 ] && pveum user token list "$PVE_USER" --output-format json 2>/dev/null |
       json_get 'any(t["tokenid"] == "'$TOKEN_ID'" for t in d)' | grep -q True; then
    run pveum user token remove "$PVE_USER" "$TOKEN_ID"
  fi
  if [ "$DRY" = 1 ]; then
    printf '+ pveum user token add %s %s --privsep 0 --output-format json  (value pushed to CT %s:%s)\n' \
      "$PVE_USER" "$TOKEN_ID" "$VMID" "$ETC/pve-token"
  else
    umask 077
    pveum user token add "$PVE_USER" "$TOKEN_ID" --privsep 0 --output-format json |
      json_get '"'$PVE_USER'!'$TOKEN_ID'=" + d["value"]' > "$WORK/token"
    pct push "$VMID" "$WORK/token" "$ETC/pve-token" --perms 640 --group pulse
    rm -f "$WORK/token"
  fi
fi
run pct push "$VMID" /etc/pve/pve-root-ca.pem "$ETC/pve-ca.pem" --perms 644

# Admin password for the settings page: made once, kept on upgrades, printed only when new.
ADMIN_PW="" NEW_PW=0
if [ "$UPGRADE" = 1 ] && pct exec "$VMID" -- test -s "$ETC/admin-password"; then
  if [ "$SHOW_PW" = 1 ]; then ADMIN_PW=$(pct exec "$VMID" -- cat "$ETC/admin-password"); fi
else
  ADMIN_PW=$(python3 -c 'import secrets; print(secrets.token_urlsafe(15))')
  NEW_PW=1
  (umask 077; printf '%s\n' "$ADMIN_PW" > "$WORK/admin")
  run pct push "$VMID" "$WORK/admin" "$ETC/admin-password" --perms 640 --group pulse
fi

# ------------------------------------------------------------------ app
tar -C "$SRC" -czf "$WORK/app.tgz" pulse README.md LICENSE update.sh
if [ "$UPGRADE" = 1 ]; then
  in_ct "rm -rf $APP.prev && if [ -d $APP ]; then cp -a $APP $APP.prev; fi"
fi
run pct push "$VMID" "$WORK/app.tgz" /tmp/homelab-pulse.tgz
in_ct "rm -rf $APP.new && mkdir -p $APP.new && tar -xzf /tmp/homelab-pulse.tgz -C $APP.new && rm /tmp/homelab-pulse.tgz && rm -rf $APP && mv $APP.new $APP && chown -R root:root $APP && chmod -R a+rX $APP"
run pct push "$VMID" "$SRC/homelab-pulse.service" /etc/systemd/system/homelab-pulse.service
run pct push "$VMID" "$SRC/homelab-pulse-passwd" /usr/local/bin/homelab-pulse-passwd --perms 755
# the settings page's "Upgrade" button: a root-only unit that runs update.sh for the requested release
run pct push "$VMID" "$SRC/homelab-pulse-update" /usr/local/sbin/homelab-pulse-update --perms 755
run pct push "$VMID" "$SRC/homelab-pulse-update.service" /etc/systemd/system/homelab-pulse-update.service --perms 644
run pct push "$VMID" "$SRC/homelab-pulse-update.path" /etc/systemd/system/homelab-pulse-update.path --perms 644
run pct push "$VMID" "$SRC/overrides.example.json" "$ETC/overrides.example.json" --perms 644

if [ "$UPGRADE" = 0 ] || ! pct exec "$VMID" -- test -s "$ETC/env"; then
  sed -e "s|^PULSE_PVE=.*|PULSE_PVE=live|" -e "s|^PULSE_PVE_HOST=.*|PULSE_PVE_HOST=$HOST_IP|" "$SRC/env.example" > "$WORK/env"
  [ "$DRY" = 1 ] && printf '+ env file with PULSE_PVE=live PULSE_PVE_HOST=%s\n' "$HOST_IP"
  run pct push "$VMID" "$WORK/env" "$ETC/env" --perms 640 --group pulse
elif ! pct exec "$VMID" -- grep -q PULSE_PVE_HOST "$ETC/env"; then
  in_ct "echo PULSE_PVE_HOST=$HOST_IP >> $ETC/env"   # older installs assumed the host's address
fi

# ------------------------------------------------------------------ self-healing (optional)
GATE=/usr/local/sbin/pulse-heal-gate HEAL_ETC=/etc/pulse-heal AUTH=/root/.ssh/authorized_keys KEYTAG="pulse-heal-ct$VMID"
install_gate_files() {   # the gate, its shared rules module and the built-in recipes (fresh install and upgrades)
  run install -d -m 755 /usr/local/lib/pulse-heal /usr/share/pulse-heal/recipes "$HEAL_ETC" "$HEAL_ETC/recipes.d"
  run install -d -m 700 /var/lib/pulse-heal
  run install -m 755 "$SRC/heal/pulse-heal-gate" "$GATE"
  run install -m 644 "$SRC/pulse/recipes.py" /usr/local/lib/pulse-heal/recipes.py
  run find /usr/share/pulse-heal/recipes -name '*.json' -delete
  for f in "$SRC"/recipes/*.json; do run install -m 644 "$f" /usr/share/pulse-heal/recipes/; done
}
if [ "$HEAL" = enable ]; then
  say "Setting up self-healing (gate on this host, restricted key for CT $VMID)"
  install_gate_files
  [ -e "$HEAL_ETC/enabled" ] || { [ "$DRY" = 1 ] && echo "+ echo 1 > $HEAL_ETC/enabled" || echo 1 > "$HEAL_ETC/enabled"; }
  [ -e "$HEAL_ETC/deny" ] || run touch "$HEAL_ETC/deny"
  [ -e "$HEAL_ETC/gate.conf" ] || { [ "$DRY" = 1 ] && echo "+ write $HEAL_ETC/gate.conf" || echo '{"budget_per_hour": 10}' > "$HEAL_ETC/gate.conf"; }
  if [ "$DRY" = 1 ]; then echo "+ echo $VMID > $HEAL_ETC/self"; else echo "$VMID" > "$HEAL_ETC/self"; fi
  [ -e "$HEAL_ETC/recipes.d/example-local-recipe.json.disabled" ] ||
    run install -m 644 "$SRC/recipes/example-local-recipe.json.disabled" "$HEAL_ETC/recipes.d/"
  if [ "$DRY" = 1 ]; then echo "+ write /etc/logrotate.d/pulse-heal-gate"; else
    printf '/var/log/pulse-heal-gate.log {\n  weekly\n  rotate 8\n  compress\n  missingok\n  notifempty\n}\n' > /etc/logrotate.d/pulse-heal-gate; fi
  in_ct "[ -f $ETC/heal_key ] || ssh-keygen -q -t ed25519 -N '' -C $KEYTAG -f $ETC/heal_key; chown pulse:pulse $ETC/heal_key $ETC/heal_key.pub; chmod 600 $ETC/heal_key"
  PUB=$(pct exec "$VMID" -- cat "$ETC/heal_key.pub" 2>/dev/null | head -n1 | awk '{print $1" "$2}')
  CTIP=$(pct exec "$VMID" -- sh -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1" 2>/dev/null | head -n1)
  [ -n "$PUB" ] || PUB="ssh-ed25519 <generated-key>"
  [ -n "$CTIP" ] || CTIP="<ct-ip>"
  LINE="restrict,command=\"$GATE\",from=\"$CTIP\" $PUB $KEYTAG"
  if [ "$DRY" = 1 ]; then echo "+ replace $KEYTAG in $AUTH with: $LINE"; else
    install -d -m 700 /root/.ssh; touch "$AUTH"; chmod 600 "$AUTH"
    grep -v " $KEYTAG\$" "$AUTH" > "$AUTH.pulse-tmp" || true
    printf '%s\n' "$LINE" >> "$AUTH.pulse-tmp" && mv "$AUTH.pulse-tmp" "$AUTH"
  fi
  in_ct "sed -i '/^PULSE_HEAL_GATE=/d; /^PULSE_HEAL_KEY=/d' $ETC/env; echo PULSE_HEAL_GATE=root@$HOST_IP >> $ETC/env; echo PULSE_HEAL_KEY=$ETC/heal_key >> $ETC/env"
  HEAL_NOTE="Self-healing: installed in dry-run mode (nothing runs until you choose Ask first or Automatic in Settings).
  The gate accepts Pulse's key only from $CTIP; give CT $VMID a fixed address (static or DHCP reservation)."
elif [ "$HEAL" = disable ]; then
  say "Removing self-healing"
  if [ "$DRY" = 1 ]; then echo "+ remove $KEYTAG from $AUTH"; else
    [ -f "$AUTH" ] && { grep -v " $KEYTAG\$" "$AUTH" > "$AUTH.pulse-tmp" || true; mv "$AUTH.pulse-tmp" "$AUTH"; chmod 600 "$AUTH"; }
  fi
  run rm -f "$GATE" /usr/local/lib/pulse-heal/recipes.py /etc/logrotate.d/pulse-heal-gate
  run rm -rf /usr/share/pulse-heal /usr/local/lib/pulse-heal
  in_ct "sed -i '/^PULSE_HEAL_GATE=/d; /^PULSE_HEAL_KEY=/d' $ETC/env; rm -f $ETC/heal_key $ETC/heal_key.pub /var/lib/homelab-pulse/heal_known_hosts"
  HEAL_NOTE="Self-healing removed (your recipes in $HEAL_ETC/recipes.d were kept)."
elif [ -x "$GATE" ]; then
  install_gate_files          # upgrade: refresh the gate and the built-in recipes
  HEAL_NOTE="Self-healing gate updated."
fi

in_ct "systemctl daemon-reload && systemctl enable -q homelab-pulse && systemctl enable -q --now homelab-pulse-update.path && systemctl restart homelab-pulse"

if [ "$DRY" = 1 ]; then
  if [ "$SHOW_PW" = 1 ] && [ "$NEW_PW" = 0 ] && [ -n "$ADMIN_PW" ]; then say "Admin password: $ADMIN_PW"; fi
  if [ -n "${HEAL_NOTE:-}" ]; then say "$HEAL_NOTE"; fi
  say "Dry run: nothing was changed."; exit 0
fi

# ------------------------------------------------------------------ verify + report
PORT=$(pct exec "$VMID" -- sh -c ". $ETC/env; echo \${PULSE_PORT:-80}")
ok=0
for _ in $(seq 1 20); do
  if pct exec "$VMID" -- python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$PORT/', timeout=2)" 2>/dev/null; then ok=1; break; fi
  sleep 1
done
CT_IP=$(pct exec "$VMID" -- sh -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1")
[ "$ok" = 1 ] || die "the service didn't answer; see: pct exec $VMID -- journalctl -u homelab-pulse -n 50"
URL="http://$CT_IP$( [ "$PORT" = 80 ] || echo ":$PORT")"
cat <<EOF

  Homelab Pulse is running in CT $VMID:  $URL

  It discovers your nodes, guests and their services by itself (first full scan within a minute).
  Fine-tune with Proxmox tags on a guest:  pulse-ignore  pulse-noscan  pulse-role-<text>  pulse-icon-<name>
  or with $ETC/overrides.json (example next to it).

  Alerts & settings:  $URL/settings
$(if [ -n "$ADMIN_PW" ]; then printf '  Admin password:     %s%s' "$ADMIN_PW" "$([ "$NEW_PW" = 1 ] && echo '   (new; keep it somewhere safe)')";
  else printf '  Admin password:     unchanged (show it with --show-password; reset with homelab-pulse-passwd)'; fi)

$(if [ -n "${HEAL_NOTE:-}" ]; then printf '\n  %s\n' "$HEAL_NOTE"; fi)
  Upgrade:    run this installer again
  Uninstall:  bash uninstall.sh   (from the repo; or: pct destroy $VMID && pveum user token remove $PVE_USER $TOKEN_ID)
EOF
