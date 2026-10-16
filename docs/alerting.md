# Alerting

Pulse watches your lab and speaks up through two channels: **alerts** (something is wrong
right now) and **early warnings** (something will go wrong soon). Everything below works in
any lab — Pulse discovers what to watch from the Proxmox API and its own port scans, and
every check is toggleable in the settings page.

## Alert kinds

| Kind | What it watches | How it works |
|---|---|---|
| Internet unreachable | The lab's path to the internet | Built-in TCP probe to 1.1.1.1:443 |
| Gateway not answering | Your router | Built-in ping probe to the discovered gateway IP (a TCP probe where the container may not ping) |
| Lab DNS not resolving | Your lab's DNS server | Built-in DNS probe asking the gateway to resolve a real name |
| A service stops answering | Every discovered TCP/HTTP/TLS service | Probes, debounced (2 failed rounds) |
| A Proxmox node goes offline | Each cluster node, and each separate host added with `--add-host` | Node status from the Proxmox API; for a separate host, its API not answering |
| Pulse can't reach Proxmox | The Proxmox API itself (and a separate host never reached since Pulse started) | API health |
| A guest stops unexpectedly | Every VM/container | Stops correlated against the Proxmox task list, so your own shutdowns don't alert |
| Guest keeps restarting | Flapping guests | 3 unexplained stops within an hour → one summary alert instead of stop/start pairs |
| New service appeared | New open ports | Discovery baseline; the first scan seeds silently |
| Guest IP changed | DHCP churn | IP baseline per guest; first sight seeds silently |
| A backup job fails | vzdump jobs | Failed backup tasks |
| Early warnings | See below | Evaluated every alert poll |

**Dependency suppression.** When a node goes offline, Pulse holds that node's guest and
service alerts instead of sending them — the dead node already explains them. They fire
normally once the node is back if they're still broken. Nothing is dropped.

**Internet down.** While the internet is unreachable, ntfy notifications are skipped
(they can't be delivered) and the alert notes this. The local webhook still fires.

## Early warnings

| Rule | What it watches | Setting |
|---|---|---|
| Storage filling up | Disk usage + fill forecast per storage | warn/critical % and days |
| Backup storage filling up | Same, for storages holding backups | separate thresholds |
| Certificates expiring | Every discovered TLS service | warn/critical days |
| ZFS pool unhealthy | `health != ONLINE` on any pool | on/off |
| SSD wear | Wear-out indicator | warn/critical % |
| SMART health | Disk health | on/off |
| Guest without a recent backup | Last successful backup per guest | stale after (hours) |
| Node memory high | Sustained memory pressure | % for (minutes) |
| Container disk filling up | LXC rootfs usage | warn/critical % |
| Proxmox updates pending | Package updates per node | on/off, **off by default** |

The Proxmox-update check needs the API token to have `Sys.Modify`, which the default
read-only token lacks. Install with `install.sh --with-updates` to grant it (it creates
a `PulseUpdates` role with just that privilege). With the default token the rule stays
silent.

## HTTP keyword checks

For any discovered HTTP check you can require the page to contain a keyword (e.g. make
sure the login page actually renders, not just that the port answers). This is configured
in `overrides.json`, not the UI:

```json
{
  "http_contains": {
    "101:80": "Dashboard"
  }
}
```

The key is the check id (`<vmid>:<port>`). A mismatch marks the check down.
