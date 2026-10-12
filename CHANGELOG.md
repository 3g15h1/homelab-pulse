# Changelog

## 1.0.0 — 2026-10-12

First public release.

- Discovers nodes, guests, IPs (LXC interfaces, QEMU guest agent, static/cloud-init config) and
  services (port scan + HTTP/TLS/DNS/banner fingerprinting) by itself; new guests appear within a minute.
- Multi-node clusters: one hub per node on the map, per-node host panels and backups, shared storage.
- Health checks are planned from discovery; tags (`pulse-*`) and `overrides.json` steer it.
- One-command installer for Proxmox hosts (LXC + read-only PVEAuditor token), upgrade in place.
- Demo mode simulates a two-node cluster through the same code paths.
