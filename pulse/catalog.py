"""What discovery knows about common homelab software: which ports to try, how to recognise what
answers, and which role + icon to give a guest. Pure data plus two lookups; edit freely.

The blob matched by the rules is lower-case text gathered by the fingerprinter, e.g.
"title: adguard home server: nginx location: /login body: ... cert: pve1 banner: ssh-2.0-openssh".
"""
import re

SCAN_PORTS = (21, 22, 53, 80, 81, 443, 1883, 3000, 3001, 5000, 5001, 5432, 6379, 7681, 8000, 8006, 8007,
              8080, 8081, 8088, 8096, 8123, 8443, 8888, 9000, 9090, 9443, 11434, 32400)
TLS_FIRST = {443, 5001, 8006, 8007, 8443, 9443}
# Never send these an HTTP request: Redis logs it as an attack, MQTT brokers as a protocol error.
NO_HTTP = {21, 22, 1883, 5432, 6379}
# Shown on the guest but not health-checked every 15 s (each check is a login-less connection that
# sshd logs; an explicit check in overrides.json still works).
QUIET = {"SSH"}

# Glyph names the UI knows (static/index.html GLYPH table).
ICONS = {"camera", "shield", "doc", "home", "globe", "spark", "flask", "key", "chat", "brain", "pulse", "box",
         "server", "router", "cloud", "film", "chart", "database", "terminal", "code", "lock", "flow", "radio",
         "sync", "disk", "cube", "photo"}

# (regex on blob, product, icon, ports it may match on or None). Order = specificity: first match wins
# and its index is the rank, so specific apps come first and generic servers last.
RULES = [
    (r"home assistant", "Home Assistant", "home", None),
    (r"adguard", "AdGuard Home", "shield", None),
    (r"pi-hole|pihole", "Pi-hole", "shield", None),
    (r"paperless", "Paperless-ngx", "doc", None),
    (r"nextcloud", "Nextcloud", "cloud", None),
    (r"jellyfin", "Jellyfin", "film", None),
    (r"\bemby\b", "Emby", "film", None),
    (r"plex", "Plex", "film", None),
    (r"", "Plex", "film", (32400,)),
    (r"immich", "Immich", "photo", None),
    (r"photoprism", "PhotoPrism", "photo", None),
    (r"grafana", "Grafana", "chart", None),
    (r"prometheus", "Prometheus", "chart", None),
    (r"uptime kuma", "Uptime Kuma", "pulse", None),
    (r"portainer", "Portainer", "cube", None),
    (r"nginx proxy manager", "Nginx Proxy Manager", "globe", None),
    (r"traefik", "Traefik", "globe", None),
    (r"vaultwarden|bitwarden", "Vaultwarden", "lock", None),
    (r"forgejo", "Forgejo", "code", None),
    (r"gitea", "Gitea", "code", None),
    (r"gitlab", "GitLab", "code", None),
    (r"frigate", "Frigate", "camera", None),
    (r"node-red", "Node-RED", "flow", None),
    (r"zigbee2mqtt", "Zigbee2MQTT", "radio", None),
    (r"ollama", "Ollama", "brain", None),
    (r"", "Ollama", "brain", (11434,)),
    (r"open webui", "Open WebUI", "chat", None),
    (r"syncthing", "Syncthing", "sync", None),
    (r"truenas", "TrueNAS", "disk", None),
    (r"openmediavault", "OpenMediaVault", "disk", None),
    (r"proxmox backup server", "Proxmox Backup Server", "disk", None),
    (r"", "Proxmox Backup Server", "disk", (8007,)),
    (r"proxmox virtual environment", "Proxmox VE", "server", None),
    (r"headscale", "Headscale", "globe", None),
    (r"ttyd", "Web terminal", "terminal", None),
    (r"", "Web terminal", "terminal", (7681,)),
    (r"homepage|homarr|dashy|heimdall", "Dashboard", "globe", None),
    (r"", "MQTT broker", "radio", (1883,)),
    (r"", "PostgreSQL", "database", (5432,)),
    (r"", "Redis", "database", (6379,)),
    (r"", "DNS server", "shield", (53,)),
    (r"", "FTP", "disk", (21,)),
    (r"caddy", "Caddy", "globe", None),
    (r"nginx", "nginx", "globe", None),
    (r"apache", "Apache", "globe", None),
    (r"banner: ssh-", "SSH", "terminal", None),
    (r"", "SSH", "terminal", (22,)),
]
_COMPILED = [(re.compile(rx) if rx else None, product, icon, ports) for rx, product, icon, ports in RULES]
GENERIC = {"SSH", "nginx", "Apache", "Caddy", "FTP"}   # never a guest's role on their own


def identify(blob, port):
    """-> (product, icon, rank) for the first rule matching this port's blob, or None."""
    for rank, (rx, product, icon, ports) in enumerate(_COMPILED):
        if ports is not None and port not in ports:
            continue
        if rx is None or rx.search(blob):
            return product, icon, rank
    return None


NAME_HINTS = [
    (r"dns|adguard|pihole|pi-hole", "DNS + ad blocking", "shield"),
    (r"proxy|nginx|traefik|caddy", "Reverse proxy", "globe"),
    (r"media|jellyfin|plex|emby|sonarr|radarr", "Media server", "film"),
    (r"home-?assistant|\bhass\b|\bhaos\b", "Home Assistant", "home"),
    (r"paperless|docs?\b", "Documents", "doc"),
    (r"ollama|llm|\bai\b", "Local AI", "brain"),
    (r"nas|truenas|omv|storage|backup|pbs", "Storage", "disk"),
    (r"camera|nvr|frigate|ring", "Cameras", "camera"),
    (r"git|forgejo|gitea", "Code hosting", "code"),
    (r"db|postgres|mysql|maria|redis", "Database", "database"),
    (r"vault|secret|bitwarden", "Secrets", "lock"),
    (r"docker|portainer|k3s|k8s|kube", "Containers", "cube"),
    (r"mqtt|mosquitto|zigbee", "IoT broker", "radio"),
    (r"monitor|grafana|prometheus|kuma|pulse", "Monitoring", "pulse"),
]
# whole words only, so "sandbox" isn't a database and "nascar" isn't a NAS
_NAME_COMPILED = [(re.compile(rf"(?<![a-z0-9])(?:{rx})(?![a-z0-9])"), role, icon) for rx, role, icon in NAME_HINTS]


def guess_from_name(name, ostype, kind):
    """Fallback (role, icon) when nothing recognisable answered on the network."""
    n = (name or "").lower()
    for rx, role, icon in _NAME_COMPILED:
        if rx.search(n):
            return role, icon
    return ("Virtual machine" if kind == "qemu" else "Container"), "box"
