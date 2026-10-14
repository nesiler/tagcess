# tagcess installer: install and roll back

This document is the single user guide for the installer (`deploy/install.sh` + `deploy/ansible/`). A test lab (`fresh`)
and an existing installation (`adopt`) are installed with the same roles and the same phases; the difference is the
environment variables and the mode (§3, §9). Architecture context: `docs/architecture.md` §8.

Note: the prompts and messages printed by `deploy/install.sh` are currently in Turkish. This guide describes
what each prompt asks; the answers `evet` (yes), `fresh` and `adopt` are typed literally.

**Rules.**
- The repository contains no secrets. The installer asks for a secret only as a **file path**; it checks that the file exists and its mode
  (`0600`/`0640`/`0400`), and does not read or show its content. Ansible copies the secret to the host byte for byte with `no_log`.
- Environment settings live outside the repository: `${XDG_CONFIG_HOME:-~/.config}/tagcess-install/<env>/` (`inventory.yml`,
  `vars.yml`, `state`, `preflight.json`, `guide/`, reports). A path inside the repository is rejected.
- Before every phase that writes to the host, a backup is taken (`/var/backups/tagcess-install/<id>/`) and the installer waits for `evet` to be typed.
- tagcess does not create users and does not grant roles (Zitadel is the only user/role store). Headplane, WireGuard and the
  existing certbot are not changed in any phase.

Step labels: `read (target)` only reads; `write (target)` writes to the install target (a lab or the VPN host of an existing
installation). Whether the target is production is decided by the environment the developer chooses, not by the label.

## 1. What it does and does not do

| Does | Does not |
|---|---|
| Scans the target read-only (preflight), suggests a mode, stops an installation that has a blocker | Does not choose the mode: the developer confirms `fresh`/`adopt` by typing it |
| Installs missing components (`fresh`) or adopts what exists (`adopt`; a missing component is added only with confirmation) | Does not overwrite an existing Headscale/Caddy/certbot |
| Installs the tagcess layer: host directories, hshelper, oauth2-proxy, the Caddy UI block, the tagcess container | Does not touch Caddy site files or the role snippet (after the first import Caddy belongs to tagcess) |
| Finds or creates the vpn project, roles and applications in Zitadel (`zitadel_seed`) | Does not create users in Zitadel, grant roles or delete anything; does not enable the groups execution on an existing installation |
| Does Headscale tags, the hook ACL rule, the DNS path and the G-02 switch with separate confirmation gates | Does not write to the Kubernetes cluster: it generates the RBAC manifest and commands (`k8s_access`); applying them is up to the developer |
| After each phase writes the remaining manual steps as `guide/<phase>.md` | Does not do the manual steps itself; DNS A records and console work are in the `guide` |
| Checks parity and health with `verify`; rolls back with `rollback.yml`/`restore.yml` | Does not remove packages it installed on fresh during rollback (shutting down the host = deleting) |

## 2. Prerequisites

- Control machine: `ansible-playbook` (ansible-core 2.17+), `bash` 3.2+, key login to the target over `ssh` (root or sudo),
  the Go toolchain (the Zitadel adopt tool and `-import-preview` are built from the repository) and Docker (the tagcess image; `app_image_source`).
- Target: Ubuntu 24.04, `python3`, `sqlite3` (for the Headscale backup; preflight stops if it is missing), at least 500 MB under `/var/lib`.
- Secret files on the control machine, outside the repository, mode `0600`: the webhook signing key, (if used) the groups signing key,
  the tagcess service user key (`zitadel-key.json`, ADR 0009; created in the console), the Zitadel admin key (adopt) or
  the PAT (fresh lab: `zitadel_install` produces it), and on fresh a Cloudflare DNS-01 token.
- Site seed file (`site_seed_file`): kept outside the repository; the format is the example seed file under `deploy/ansible/examples/`.

## 3. Modes

| | `fresh` | `adopt` |
|---|---|---|
| When | Headscale and Caddy are absent on the target (lab) | Headscale or Caddy exists on the target (an existing installation) |
| Component phases | Installs | Leaves existing ones alone ("adopted"); if one is missing it asks by name and adds it with `confirm_add_missing=<component>` |
| Zitadel | If `zitadel_install_enabled: true`, installs on the lab cluster with helm | Does not install; uses the existing one |
| Gate | Does not overwrite an existing core component (preflight blocker) | Asks for `confirm_adopt_empty=yes` on an empty target |

Preflight counts the components: if Headscale or Caddy exists it suggests `adopt`, if neither exists it suggests `fresh`. The choice is written to
`vars.yml` as `install_mode`, and the preflight of every call re-checks the mode gate.

## 4. The install.sh flow

#### Step 1: Prepare the secret files outside the repository [write (target)]

The files are created only on the control machine; their content is not written to this document or to the terminal.

```bash
mkdir -p ~/.config/tagcess-install/lab/secrets && chmod 700 ~/.config/tagcess-install/lab/secrets
openssl rand -hex 32 > ~/.config/tagcess-install/lab/secrets/webhook-signing-key
chmod 600 ~/.config/tagcess-install/lab/secrets/webhook-signing-key
```

#### Step 2: See the plan first [read (target)]

The first run asks for the settings (environment name, ssh target, domain, certificate names, tailnet IPs, Traefik entrypoint name/port, Caddy
site directory, oauth2-proxy form, seed file and optionally the path of the Zitadel admin key) and writes `inventory.yml` and
`vars.yml`. tagcess's own secret files (webhook and groups signing keys, the service user key) are not asked here: they are
asked when the `host` phase starts. On a fresh install Zitadel does not exist yet; the service user is created in the console after the `zitadel_seed` guide;
the signing key produced by `zitadel_seed` itself (`<env>/zitadel.json`) or the file recorded in `vars.yml` is not asked again. `--dry-run` runs
every call with `--check --diff`, asks for no confirmation and writes nothing.

```bash
deploy/install.sh --env lab --dry-run
deploy/install.sh --env lab --plan
```

#### Step 3: Start the installation [write (target)]

Flow: preflight (read-only; if there is a blocker no writing phase is called) -> mode suggestion and reason -> confirmation by typing `fresh`/`adopt` ->
phase plan -> `evet` for every writing phase -> the phase's `guide` steps ("done / will do later"; the answer is written to `state` and does not
stop the flow). Any answer other than `evet` skips the phase and stops (exit code 3).

```bash
deploy/install.sh --env lab
```

Separate in-phase questions: on adopt a missing component (`confirm_add_missing`), the `oauth2_proxy` cookie switch (`confirm_oauth2_cookie`),
`zitadel_seed` plan first (`zitadel_seed_apply=false`) then apply, on an existing installation the Actions targets are a separate question; before `g02`
preflight runs again and shows the policy sha256 (`expected_policy_sha256`). Confirmation variables are passed only to the call of their own phase.

#### Step 4: Resume or run a single phase [write (target)]

```bash
deploy/install.sh --env lab --resume
deploy/install.sh --env lab --phase verify
```

Options: `--env <name>` environment name; `--plan` shows the phase plan of the selected mode and runs nothing; `--resume` skips completed phases
and continues from the next; `--phase <name>` runs only this phase after preflight; `--dry-run` runs every call with `--check --diff`.
Exit codes: 0 finished, 1 error or blocker, 3 stopped because the developer did not confirm. For an existing installation the environment is conventionally named `prod`.

## 5. Phases

The order is in `deploy/ansible/group_vars/all/phases.yml` (single source; `site.yml` and `rollback.yml` are generated from it). The read/write
column shows where the phase writes, the confirmation column shows the phase's own gate variable.

| Phase | Mode | Read/write | Confirmation |
|---|---|---|---|
| `preflight` | fresh, adopt | read | |
| `certbot` | fresh, adopt | write (host) | |
| `headscale_install` | fresh, adopt | write (host) | |
| `caddy_install` | fresh, adopt | write (host) | |
| `tailscale_join` | fresh, adopt | write (host) | |
| `zitadel_install` | fresh | write (cluster) | |
| `zitadel_seed` | fresh, adopt | write (Zitadel) | |
| `headscale_oidc` | fresh, adopt | write (host) | |
| `backup` | fresh, adopt | write (backup) | |
| `host` | fresh, adopt | write (host) | |
| `host_system` | fresh, adopt | write (host) | `confirm_host_system` |
| `hshelper` | fresh, adopt | write (host) | |
| `oauth2_proxy` | fresh, adopt | write (host) | |
| `caddy_ui` | fresh, adopt | write (host) | |
| `app` | fresh, adopt | write (host) | |
| `verify` | fresh, adopt | read | |
| `hs_tags` | fresh, adopt | write (host) | `confirm_hs_tags` |
| `hs_hook_acl` | fresh, adopt | write (host) | `confirm_hs_hook_acl` |
| `hs_dns_path` | fresh, adopt | write (host) | `confirm_hs_dns_path` |
| `g02` | fresh, adopt | write (host) | `confirm_g02` |
| `k8s_access` | fresh, adopt | write (control machine) | |
| `verify_final` | fresh, adopt | read | |

### 5.1 `preflight`
- **What it does:** Headscale (version, `configtest`, gRPC socket, policy mode and sha256), Caddy (`validate`, disk/running config
  equality, site directory), certificates, hook port, Zitadel discovery, oauth2-proxy, Docker, tailscale, disk, components that will not be touched.
  Writes the report `preflight.md`/`preflight.json` and the suggested mode.
- **Verification:** blocker count is 0; the report is on the control machine.
- **guide:** `preflight-vpn-tailnet-ip`, `preflight-secret-files`.

### 5.2 `certbot`
- **What changes:** fresh: `certbot` + the Cloudflare plugin, token `/root/.secrets/certbot/cloudflare.ini` (`0600`), a wildcard certificate for each
  `cert_names` entry, a `systemctl reload caddy` deploy hook. Adopt: nothing if certbot exists; only an expiry report.
- **Verification:** `/etc/letsencrypt/live/<name>/{fullchain,privkey}.pem` exist; no preflight certificate warning.
- **Rollback:** packages and certificates are not removed (report: "not removed, shut down the host").
- **guide:** `certbot-dns-records`.

### 5.3 `headscale_install`
- **What changes:** fresh: a pinned `.deb` (sha256 verified), `/etc/headscale/config.yaml`, an initial `policy.hujson`. Adopt:
  nothing if Headscale exists ("adopted").
- **Verification:** `headscale configtest`, `headscale policy check`, `/health` 200.
- **Rollback:** the package and config are not removed (report).

### 5.4 `caddy_install`
- **What changes:** fresh: the official Caddy package, an initial Caddyfile with the system sites (`import sites/*.caddy`). Adopt: no file if
  Caddy exists.
- **Verification:** `caddy validate`, the service runs; `-import-preview` parity with the seed is 0.
- **Rollback:** the package is not removed (report).

### 5.5 `tailscale_join`
- **What changes:** fresh: the tailscale package, joining with a single-use 10-minute pre-auth key per node (`tag:vpn-server`,
  `tag:k8s`), the `vpn_host` private network route and its approval. The key is not written to any file or output.
- **Verification:** `headscale nodes list` shows the nodes with their tags; the route is approved.
- **Rollback:** tailnet membership stays (report).
- **guide:** `tailscale-k8s-join` (if there is no `k8s` group in the inventory, the Kubernetes node joins by hand).

### 5.6 `zitadel_install`
- **What changes:** only fresh, `zitadel_install_enabled: true` and Zitadel discovery unreachable: a helm install on the lab cluster with the `test/lab` files;
  the admin PAT goes to a `0600` file on the control machine. It stops if the context is empty or matches a production pattern.
- **Verification:** discovery 200.
- **Rollback:** Zitadel on the cluster is not removed (report).
- **guide:** `zitadel-admin-pat`.

### 5.7 `zitadel_seed`
- **What changes:** in Zitadel the vpn project, roles (`devops`, `developer`, `standart`), the oauth2-proxy and Headscale applications
  (find or create); Actions v2 targets if confirmed. Output on the control machine is `zitadel.json` (ids, secret file paths).
  Plan first (writes nothing), then apply with confirmation.
- **Verification:** the second run says "no changes"; the report shows the number of users without roles (informational).
- **Rollback:** the tool deletes nothing; created objects are listed in the report and can be deleted by hand from the console if needed.
- **guide:** `zitadel-service-user`, `zitadel-webhook-target`, `zitadel-groups-v1-to-v2`.

### 5.8 `headscale_oidc`
- **What changes:** fresh: the OIDC block in the Headscale config (`client_secret_path` file), `configtest` -> restart -> `/health`.
  Adopt: nothing if the OIDC block exists.
- **Verification:** `/health` 200, the OIDC login page opens.
- **Rollback:** `rollback.yml --tags headscale_oidc` puts the config back from the phase's backup.
- **guide:** `headscale-oidc-client`.

### 5.9 `backup`
- **What changes:** a consistent copy of all managed paths and of the Headscale and tagcess databases; `manifest.json` (sha256, mode,
  owner). Every writing phase also takes its own backup.
- **Verification:** `/var/backups/tagcess-install/<id>/manifest.json`.
- **Rollback:** `restore.yml -e backup_id=<id>` (§7).

### 5.10 `host`
- **What changes:** the `tagcess` user, `/etc/tagcess`, `/var/lib/tagcess`, `/run/tagcess` (tmpfiles), secret files
  (`/etc/tagcess/secrets`), the tagcess DNS file seeded with today's records. On adopt, Docker is added only with confirmation.
- **Verification:** directory ownership/modes; Headscale can read the DNS file.
- **Rollback:** `rollback.yml --tags host`; data directories are set aside only with `confirm_remove_data=yes`.
- **guide:** `host-optional-secrets`, `host-docker-missing`.

### 5.11 `host_system`
- **What changes:** with `confirm_host_system=yes`, the Headscale systemd drop-in (`headscale-preserve.conf`) and the Caddy secret paths.
  Without confirmation only a plan.
- **Verification:** `systemctl cat headscale` shows the drop-in; services run.
- **Rollback:** `rollback.yml --tags host_system`.
- **guide:** `host-system-confirm`.

### 5.12 `hshelper`
- **What changes:** `/usr/local/bin/tagcess-hshelper`, `tagcess-hshelper.{path,service}`, the boot unit, the request directory.
- **Verification:** the path unit is active; a sample request is processed.
- **Rollback:** `rollback.yml --tags hshelper`.

### 5.13 `oauth2_proxy`
- **What changes:** the oauth2-proxy config (systemd or container), secret files `0640`; the candidate config is first
  tried on an empty port, and if `/ping` is not 200 after the restart the old config and service state are put back. On adopt the cookie changes only with confirmation.
- **Verification:** `/ping` 200; Caddy files do not change.
- **Rollback:** `rollback.yml --tags oauth2_proxy`.
- **guide:** `oauth2-proxy-cookie-switch`.

### 5.14 `caddy_ui`
- **What changes:** the `deploy/caddy/tagcess.caddy` block as `sites/tagcess.caddy`; `caddy validate` -> reload.
- **Verification:** `https://tagcess.<domain>` redirects to the gate.
- **Rollback:** `rollback.yml --tags caddy_ui` (refuses if tagcess already did the first import: Caddy now belongs to tagcess).
- **guide:** `caddy-ui-oauth2-proxy`.

### 5.15 `app`
- **What changes:** the tagcess image, `/etc/tagcess/config.yaml`, `compose.yaml`; the `-check` gate; the container starts.
- **Verification:** `/healthz` 200; the config passes tagcess's own validation.
- **Rollback:** `rollback.yml --tags app` (previous image and config).

### 5.16 `verify`
- **What it does:** first-import parity (`tagcess -import-preview`), service health, number of users without roles, guide state.
  If parity is not 0 it stops with "not ready to apply"; the only exception is the `s06_open_start` class (developer decision 2026-10-07,
  ADR 0010): this class is accepted but written as a WARNING at the top of the report and the guide. Read-only.
- **guide:** `verify-s06-open-start` (if there is an accepted difference), `verify-unroled-users`.

### 5.17 `hs_tags`
- **What changes:** with `confirm_hs_tags=yes`, the Headscale node tags (`tag:vpn-server`, `tag:k8s`).
- **Verification:** `headscale nodes list` shows the tags.
- **Rollback:** `rollback.yml --tags hs_tags` (previous tags).
- **guide:** `hs-tags-missing`.

### 5.18 `hs_hook_acl`
- **What changes:** with `confirm_hs_hook_acl=yes`, the rule `tag:k8s -> tag:vpn-server:<hook>` in the policy file; it is not written until the candidate passes
  `policy check`.
- **Verification:** `headscale policy get` shows the rule.
- **Rollback:** `rollback.yml --tags hs_hook_acl`.
- **guide:** `hs-hook-acl-confirm`.

### 5.19 `hs_dns_path`
- **What changes:** with `confirm_hs_dns_path=yes`, `dns.extra_records_path` points to tagcess's file; the records of the two files must be
  the same and the candidate must pass `configtest`; if Headscale is not healthy the old config is put back.
- **Rollback:** `rollback.yml --tags hs_dns_path`.
- **guide:** `hs-dns-path-confirm`.

### 5.20 `g02`
- **What changes:** with `confirm_g02=yes` and `expected_policy_sha256`, from policy file mode to database mode (G-02,
  `policy-database-migration.md`).
- **Verification:** `headscale policy get` is semantically the same as the policy in the file.
- **Rollback:** `rollback.yml --tags g02` (returns to file mode).
- **guide:** `g02-confirm`, `g02-headplane`.

### 5.21 `k8s_access`
- **What changes:** control machine only: tagcess's Kubernetes monitoring ServiceAccount/RBAC manifest and the commands to apply. The cluster
  does not change.
- **Rollback:** delete the files on the control machine; if applied to the cluster, `kubectl delete -f` with the manifest.
- **guide:** `k8s-apply-rbac`, `k8s-token-ca`, `k8s-profile`.

### 5.22 `verify_final`
- **What it does:** the same checks as `verify`, after all phases. Read-only.

## 6. Manual or UI steps (`guide`)

Every phase writes its remaining manual steps to `guide/<phase>.md`; `install.sh` shows them and `verify` collects their states. The ids are stable.

| Id | Phase | What to do |
|---|---|---|
| `preflight-vpn-tailnet-ip` | preflight | Pin the host's tailnet IP in `vars.yml` as `vpn_tailnet_ip` |
| `preflight-secret-files` | preflight | Prepare the missing secret files with mode `0600` |
| `certbot-dns-records` | certbot | In Cloudflare, point the `hs`, `auth`, `tagcess` A records to the VPN host; check with `dig +short` |
| `tailscale-k8s-join` | tailscale_join | If there is no `k8s` group in the inventory, join the Kubernetes node by hand with `tag:k8s` |
| `zitadel-admin-pat` | zitadel_install | Note where the admin PAT file is; do not move it out of the lab |
| `zitadel-service-user` | zitadel_seed | Finish the tagcess service user in the console, download the key file (ADR 0009) |
| `zitadel-webhook-target` | zitadel_seed | Confirm the Actions v2 webhook target in the console |
| `zitadel-groups-v1-to-v2` | zitadel_seed | Move the groups claim from Actions v1 to v2 by hand |
| `zitadel-secret-missing` | zitadel_seed | The secret file of an object the tool created in Zitadel is missing; put the file back or give it under secret_files |
| `headscale-oidc-client` | headscale_oidc | If the Headscale OIDC client id or secret file is missing, complete `zitadel_seed` |
| `host-optional-secrets` | host | If the optional secret files (groups signing key) are absent, the feature stays off |
| `host-docker-missing` | host | No Docker on adopt: confirm to add it |
| `host-system-confirm` | host_system | Confirmation for the systemd drop-in |
| `oauth2-proxy-cookie-switch` | oauth2_proxy | Confirmation and an announcement for switching to the shared `_tagcess_gate` cookie |
| `caddy-ui-oauth2-proxy` | caddy_ui | The UI block depends on oauth2-proxy: run the `oauth2_proxy` phase first |
| `verify-s06-open-start` | verify | WARNING: S-06 starts on, internal sites are reachable from the internet too; when WireGuard is shut down, turn it off in the UI under Settings -> Site settings -> "Turn the switch off" -> "Confirm and apply" |
| `verify-unroled-users` | verify | Give roles to users without roles in Zitadel (tagcess does not grant roles) |
| `hs-tags-missing` | hs_tags | Confirmation for missing node tags |
| `hs-hook-acl-confirm` | hs_hook_acl | Confirmation for the hook ACL rule (an access widening) |
| `hs-dns-path-confirm` | hs_dns_path | Confirmation for the DNS path switch |
| `g02-confirm` | g02 | Confirmation for the G-02 policy DB switch and the policy sha256 |
| `g02-headplane` | g02 | Turn off Headplane policy editing (the policy now belongs to tagcess) |
| `k8s-apply-rbac` | k8s_access | Apply the RBAC manifest with your own kubectl context |
| `k8s-token-ca` | k8s_access | Put the ServiceAccount token and CA into tagcess's secret files |
| `k8s-profile` | k8s_access | Enable the Kubernetes monitoring profile in the UI |

## 7. Rollback: `rollback.yml` and `restore.yml`

`rollback.yml` rolls the phases back in the reverse order of `phases.yml`; each phase returns to its own backup recorded in the install state on the host
(`/var/lib/tagcess-install/state.json`). Paths that did not exist before the install are set aside. Packages installed on fresh, Zitadel
objects, Headplane and WireGuard are never removed; they are listed in the report.

#### Step 5: Roll back a single phase [write (target)]

```bash
cd deploy/ansible
ansible-playbook -i ~/.config/tagcess-install/lab/inventory.yml -i ~/.config/tagcess-install/lab/vars.yml rollback.yml --tags hs_hook_acl
```

#### Step 6: Return everything to before the install [write (target)]

tagcess's data directories (`/var/lib/tagcess`) are moved into the backup directory only with `confirm_remove_data=yes`.

```bash
cd deploy/ansible
ansible-playbook -i ~/.config/tagcess-install/lab/inventory.yml -i ~/.config/tagcess-install/lab/vars.yml rollback.yml -e confirm_remove_data=yes
```

#### Step 7: Restore a specific backup [write (target)]

First a backup of the current state is taken (`pre-restore`); the service is not reloaded until validation (Caddy `validate`, Headscale `configtest`)
passes. Databases are restored only with an explicit flag.

```bash
cd deploy/ansible
ansible-playbook -i ~/.config/tagcess-install/lab/inventory.yml -i ~/.config/tagcess-install/lab/vars.yml restore.yml -e backup_id=20261007T101500Z-host
ansible-playbook -i ~/.config/tagcess-install/lab/inventory.yml -i ~/.config/tagcess-install/lab/vars.yml restore.yml -e backup_id=20261007T101500Z-host -e restore_headscale_db=yes
```

## 8. Remaining manual steps

Of the 25 `guide` items in §6, the ones that apply to every installation (unconditional): `certbot-dns-records` (fresh), `zitadel-service-user`,
`verify-s06-open-start` (if there is an accepted difference), `verify-unroled-users` (if there are users without roles), `k8s-apply-rbac`, `k8s-token-ca`, `k8s-profile`, `g02-headplane` (if
Headplane exists). The others are conditional (a missing file, a gate waiting for confirmation). A lab rehearsal measures the real count.

## 9. Variable differences between a lab (fresh) and an existing installation (adopt)

| Variable | Lab (`fresh`) | Existing installation (`adopt`, env `prod`) |
|---|---|---|
| `install_mode` | `fresh` | `adopt` |
| `tagcess_domain` / `cert_names` | `lab.example.com` / `[lab.example.com]` | your domain / site certificate groups |
| `traefik_entrypoint` / `traefik_port` | `websecure` / `443` | `internal` / `8443` |
| `k8s_target_addr` | `https://100.64.0.5` | `https://<k8s tailnet IP>:8443` (tagcess `sites.k8s_upstream`: the upstream of the `(k8s)` snippet; parity and every apply use it) |
| `caddy_sites_dir` | `""` (a single Caddyfile + its own import line) | `/etc/caddy/sites` |
| `oauth2_proxy_runtime` | `container` | `systemd` |
| `oauth2_proxy_cookie_profile` | `tagcess` | `existing` (switch with separate confirmation) |
| `zitadel_install_enabled` | `true` (lab cluster, `zitadel_kube_context`) | `false` |
| `zitadel_seed_create_actions` / `zitadel_groups_execution` | `true` / `true` | separate question / never |
| Zitadel admin identity | `zitadel_admin_pat_file` (`zitadel_install` produces it) | `zitadel_admin_key_file` |
| `secret_files.cloudflare_token` | present (DNS-01) | absent (the existing certbot) |
| Inventory `k8s` group | present (tailscale_join) | absent (Ansible does not connect to the Kubernetes host) |
