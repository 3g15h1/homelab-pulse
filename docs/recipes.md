# Self-healing recipes

When a check fails, Pulse can try a **first-response fix** before (or instead of) bothering you. Fixes are
**recipes**: small JSON files that say *when* they apply, *what* they run and *how careful* to be.

This page covers what a recipe looks like, how Pulse picks one, the safety rules, and how to write
and share your own.

## How it fits together

```
Pulse (container, read-only)  ──ssh, forced command──▶  pulse-heal-gate (Proxmox host, root)
  decides when a fix applies                              checks the request, the recipe and the limits
  waits for the check to recover                          runs it in the guest: pct exec / qm guest exec
```

- **Pulse never gets a shell.** Its SSH key can only run the gate, and only from Pulse's IP. The gate
  accepts four verbs (`version`, `list-recipes`, `inspect`, `run`), validates every word, and never uses a
  shell.
- **Only recipes stored on the host can run.** The settings page can switch recipes on and off and pick
  their mode, but it can't create or change commands.
- **Every request is logged** in `/var/log/pulse-heal-gate.log` on the host.

## Modes

Set on **Settings → Self-healing**:

| Mode | What happens when an alert fires |
|---|---|
| **Off** | Nothing. |
| **Dry run** (default for new installs) | Pulse logs what it *would* run. Nothing changes. |
| **Ask first** | The alert arrives with a **Run fix** button (Home Assistant / ntfy) and on the settings page. |
| **Automatic** | The fix runs. If the check recovers you get one message ("…was down; restarted X; back after 40 s"); if it doesn't, the normal alert says what was tried. |

Each recipe can override the global mode: **default**, **auto**, **ask** or **off**. The global mode is a
ceiling: in *Ask first* nothing runs on its own, and in *Dry run* nothing runs at all.

## A recipe

```json
{
  "schema": 1,
  "id": "nginx-reload",
  "name": "Check and reload nginx",
  "description": "Tests the nginx configuration and, only if it is valid, reloads nginx.",
  "when": {"alert": "service_down", "product": ["nginx"]},
  "do": {"exec": [["nginx", "-t"], ["systemctl", "reload-or-restart", "nginx"]]},
  "guest": ["lxc", "qemu"],
  "safety": {"max_per_hour": 2, "verify_s": 60, "timeout_s": 60, "default_mode": "auto"}
}
```

### `when`: when it applies

All the keys you give must match. Everything here is something Pulse already knows about any lab, so a
recipe written for one lab works in another.

| Key | Meaning |
|---|---|
| `alert` | `service_down` (a health check failed) or `warning` (an early warning fired). Required. |
| `product` | The product discovery recognised, e.g. `"Jellyfin"`, `"Home Assistant"` (see `pulse/catalog.py`). Case-insensitive. |
| `port` | The failed check's port. |
| `rule` | For warnings: the warning rule, e.g. `ct_disk`, `storage_full`, `cert_expiry`. Required when `alert` is `warning`. |
| `tags` | Proxmox tags the guest must all have, e.g. `["media"]`. |
| `vmids` | Only these guests. |

`guest` limits it to `lxc` and/or `qemu` (default: both). VMs need the QEMU guest agent.

### `do`: what it runs

Exactly one of:

- `{"restart": "unit"}` restarts the systemd service (or OpenRC service) that owns the check's port.
  Pulse learns which service that is while the check is healthy, because a dead service no longer
  owns its port. The settings page shows what was learned and lets you override it.
- `{"restart": "container"}` restarts the Docker container that publishes the check's port.
- `{"exec": [[...], [...]]}` runs up to 8 commands in order and stops at the first one that fails.
  Each command is an **argument list**, never a shell string. Placeholders are allowed only as a whole
  argument: `{unit}`, `{container}`, `{port}`. The gate fills them with values it checked itself.

### `safety`: how careful to be

| Key | Default | Range | Meaning |
|---|---|---|---|
| `max_per_hour` | 2 | 1–6 | Tries per guest per hour; after that, you get the alert. |
| `verify_s` | 90 | 10–600 | How long to wait for the check to recover after the fix. |
| `timeout_s` | 60 | 5–300 | Per-command timeout. |
| `default_mode` | `auto` | `auto`, `ask` | Used when the recipe's mode is "default". Use `ask` for anything disruptive. |

The gate also enforces a total of 10 fixes per hour for the whole lab (`/etc/pulse-heal/gate.conf`,
up to 30).

## Which recipe wins

If several recipes match, Pulse picks the most specific one:
1. product-specific;
2. port, tag, vmid or warning-rule specific;
3. generic.

Your own recipe beats a built-in one at the same level, and a local recipe with the same `id` as a
built-in replaces it. Restart recipes only count when Pulse has learned a service or container for that
check.

## What is never allowed

The gate refuses a recipe, built-in or yours, that uses any of the following:

- **Shells and interpreters:** `sh`, `bash`, `python`, `perl`, `env`, `xargs`, `awk`, `find`, `sudo`,
  `su`, `nsenter`, `chroot`, …
- **Recursive deletes, disk tools and power commands:** `rm -r`, `dd`, `mkfs`, `fdisk`, `parted`,
  `shutdown`, `reboot`, `init`, …
- **Removing things:** packages (`apt remove/purge/autoremove`, `dnf/yum remove`, …); Docker
  containers, images, volumes and networks (`docker rm`, `rmi`, `system prune`, `volume rm`,
  `compose down`, …).
- **Stopping services:** `systemctl stop/disable/mask/kill/isolate/edit`. Restart, reload and start are
  fine.
- **Writing under `/etc`:** `tee`, `cp`, `mv`, `sed -i`, `chmod`, `chown`, … aimed at `/etc`.
- **Proxmox's own tools:** `pct`, `qm`, `pvesh`, plus network and firewall tools (`ip`, `iptables`,
  `nft`) and `kill`/`pkill`.

Recipes that fail these checks are listed on the settings page with the reason and never run.

It also never touches Pulse's own guest, guests listed in `/etc/pulse-heal/deny`, or anything at all
while `/etc/pulse-heal/enabled` isn't `1`.

## Writing your own

1. On the Proxmox host, create `/etc/pulse-heal/recipes.d/<id>.json`. There's an example in the repo
   at `recipes/example-local-recipe.json.disabled`. The file must be owned by root and not writable
   by anyone else (`chmod 644`).
2. Check it: `pulse-heal-gate --check /etc/pulse-heal/recipes.d/<id>.json`
3. Open **Settings → Self-healing**. The recipe appears as "yours" and shows which checks it matches
   right now.
4. Press **Test** to see exactly what it would run (a dry run), then pick a mode.

Good first-response fixes are:
- **non-breaking:** they don't lose data or change configuration;
- **idempotent:** running them twice does no harm;
- **quick:** they finish within the timeout;
- **specific:** a reload before a restart, a restart before anything bigger.

## Sharing a recipe

Recipes in this repo's `recipes/` folder ship with Pulse as built-ins. To contribute one, open a pull
request with a single JSON file. CI validates and lints it, and the review checks this list:

- [ ] It fixes a common, specific failure of a widely used app.
- [ ] Non-breaking: no data loss, no config changes, no package or container removal.
- [ ] Idempotent and safe to run when the app is actually fine.
- [ ] Matches narrowly (product and/or port), not "every service".
- [ ] `default_mode` is `ask` if it interrupts users (e.g. a full app restart).
- [ ] The description says what it does and what it doesn't.
- [ ] Tested on a real install: describe how in the PR.
