# Changelog

## 1.4.0 — 2026-10-16

- **Separate Proxmox hosts:** watch a second server that isn't in your cluster. `install.sh --add-host <IP>`
  creates a read-only token there over SSH once. Without SSH, run `--extra-host` on that host and pass the
  `pulse-host:` line it prints. The host appears as one more node: map hub, panel, checks, backups, early
  warnings and history. Guests are keyed per host, so the same VMIDs on both are fine. The dashboard shows
  each guest's real VMID, and `overrides.json` names them `<host>/<vmid>`. A taken node name becomes
  `name@host`. If the host is unreachable, its node shows offline and dependent alerts are held. A host
  never reached since Pulse started raises "Pulse can't reach Proxmox host …". Each host's own CA is used
  for its Proxmox UI check. Self-healing stays on the gate's host. Also `--list-hosts` and `--remove-host`.
- **Fix: false "Gateway is not answering" alert.** In unprivileged containers the service user may not be
  allowed to ping, so every ping failed. The installer now allows unprivileged ICMP for Pulse's group, and the
  gateway check falls back to a TCP probe (a refused connection proves the host is up) wherever ping is denied.
- **Fix: `http_contains` in overrides.json** was documented in 1.3.0 but rejected by the validator, which then
  ignored the whole file.
- Self-healing no longer asks the gate about Pulse's own guest (or anything else it refused) on every
  discovery pass. A refusal is remembered for an hour, which keeps the gate log quiet.
- Discovery scans port 2283, so Immich is recognised on its default port.
- Demo mode adds a separate host (`mini`) whose VMIDs repeat the cluster's.

## 1.3.0 — 2026-10-14

- **Expanded alerting.** New alert kinds: Internet unreachable, gateway not answering, and lab DNS
  not resolving (new built-in ping/DNS probes, so an ISP outage no longer looks like every service
  dying at once); guest flapping (3 unexplained restarts in an hour → one summary); new service
  appeared (new open port); guest IP changed. New early warnings: ZFS pool health, backup-storage
  fill forecasting (separate thresholds from regular storage), and opt-in Proxmox update checks
  (`install.sh --with-updates` grants the token `Sys.Modify` for this; default token unchanged).
  HTTP checks can now require a page keyword via `overrides.json` (`http_contains`).
- **Dependency suppression:** when a node goes offline, its guests' and services' alerts are held
  (not dropped, not sent) until the node recovers — one message per incident.
- **Internet down:** ntfy is skipped while the internet is unreachable (it can't deliver); the alert
  notes this and the local webhook still fires.
- Docs: `docs/alerting.md` describes every check, its generic mechanism, and its setting.

## 1.2.2 — 2026-10-14

- **Installable app (PWA):** PNG icons (180/192/512 px plus a maskable 512 px) generated from the Pulse
  icon, wired into the web manifest and the iOS touch icon; the server now serves  with the right
  content type. Add the dashboard to the home screen from Safari/Chrome for a fullscreen app experience.

## 1.2.1 — 2026-10-14

- **Settings page redesigned:** a "Right now" status strip; Notifications with per-channel health, last-delivery
  info and test buttons; "When Pulse speaks up" in plain language (kinds, timing, quiet hours); Early warnings
  with tunable rules; Silenced with search-based muting and mute-from-attention; Self-healing with mode cards,
  pending-fix approvals, recipes and inline target overrides; a merged Activity log; collapsed Advanced section.
  Changes auto-save with a "Saved" confirmation instead of per-section save buttons.

## 1.2.0 — 2026-10-14

- **Self-healing (opt-in):** first-response fixes run through a narrow, audited gate on the Proxmox host
  (`install.sh --enable-heal`). Modes Off / Dry run (default) / Ask first ("Run fix" button in Home Assistant
  and ntfy notifications) / Automatic. A fix that works sends one message ("…was down; restarted X; back
  after 40 s"); one that doesn't adds "tried: …" to the alert.
- **Recipes:** JSON files that match on what Pulse discovers (alert, product, port, tags, warning rule), so they
  work in any lab. Built-ins: restart the service or Docker container behind a check, container disk cleanup,
  nginx/Caddy reload, Home Assistant Core check-and-restart (HAOS), Pi-hole DNS, Jellyfin, Plex. Your own go in
  `/etc/pulse-heal/recipes.d/`. Safety lint, per-recipe hourly limits, lab-wide budget, kill switch, deny list.
- Settings page: self-healing section with recipe tests (dry run), learned targets and overrides, history.
- Docs: `docs/recipes.md` (schema, matching, trust model, writing and contributing recipes).

## 1.1.0 — 2026-10-13

- **Alerts** to a generic webhook (e.g. Home Assistant) and/or ntfy: service down, node offline, Proxmox
  unreachable, guest stopped unexpectedly, backup failed, early warnings. Recovery messages, grouping
  (one message per incident), quiet hours with a morning summary, mutes, optional reminders. Restart-safe.
- **Early warnings** with an Attention strip: storage forecast from Proxmox RRD history, certificate
  expiry, SSD wear/SMART, guests without a recent backup, node memory, container disks.
- **History that lasts:** Day/Week/Month/Year graphs from Proxmox RRD; uptime per check (24 h / 7 d / 30 d);
  activity feed, alert state and settings kept in SQLite (`/var/lib/homelab-pulse/pulse.db`).
- **Settings page** (`/settings`) behind an admin password (PBKDF2, signed 30-day session, rate-limited,
  CSRF header). Installer generates and prints the password; `homelab-pulse-passwd` resets it.

## 1.0.0 — 2026-10-12

First public release.

- Discovers nodes, guests, IPs (LXC interfaces, QEMU guest agent, static/cloud-init config) and
  services (port scan + HTTP/TLS/DNS/banner fingerprinting) by itself; new guests appear within a minute.
- Multi-node clusters: one hub per node on the map, per-node host panels and backups, shared storage.
- Health checks are planned from discovery; tags (`pulse-*`) and `overrides.json` steer it.
- One-command installer for Proxmox hosts (LXC + read-only PVEAuditor token), upgrade in place.
- Demo mode simulates a two-node cluster through the same code paths.
