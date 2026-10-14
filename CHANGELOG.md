# Changelog

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
