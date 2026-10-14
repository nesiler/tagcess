# Runbook: Kubernetes monitoring: first setup and manual renewal

Status: **[Proposed]**. This document describes steps the developer runs. Until a production connection is explicitly
allowed, all steps are tried in a lab ([ADR 0030](adr/0030-read-only-k8s-discovery-and-site-draft.md)).

## Credential directory
- The credential (token + CA) lives in the directory `/var/lib/tagcess-credentials`, separate from the SQLite/git tree
  (`k8s_auth_dir`; see `deploy/compose.yaml` and `deploy/config.example.yaml`).
- Create the directory before the first start, owned by tagcess's UID and with mode `0700`; files are written with `0600`.
  Because the directory is not under `/var/lib/tagcess`, it is not part of the SQLite/git backup; do not add it to the backup scope either.
- If `k8s_auth_dir` is left empty, tagcess stores no credential and does not create a default directory under `data_dir`; the connection screen
  shows the setup error "k8s_auth_dir is not set". No upload can be done until the directory is set and tagcess is restarted.
- The existing read-only `/etc/tagcess/secrets` does not change. The token value does not enter the repository, the config file, logs or audit.

## First setup
1. **UI manifest:** get the narrow read-only ServiceAccount/RBAC manifest and the selected namespaces from the UI.
2. **Authorized installer:** an authorized cluster admin applies the manifest in the cluster and issues a time-limited token. tagcess carries no admin
   or TokenRequest identity.
3. **UI CA/token:** the endpoint, CA and token are uploaded in the UI; the upload is atomic and the value is not shown in the response.
4. **Proof of selected permissions:** the UI shows the permission proof (SSAR) for the selected namespaces. If a permission is missing,
   the full read is not counted as successful; no site draft is produced before the proof is complete.

## Manual renewal
- When the expiry warning appears, the installer issues a new token; it is uploaded with the same UI flow. The old token counts as replaced once a new read
  succeeds.
- Automatic renewal is out of scope for this first trial.

## Failure: a resource or the token cannot be read
- If a read/measurement fails, the **last complete snapshot** is kept; the UI shows the old time, the error and a freshness warning.
  A missing inventory does not produce a "does not exist" result, no site is deleted, and access is not widened.
- Fix: upload the token/CA with the manual renewal flow above and wait for a successful full read.

## After an emergency manual change
- After an emergency manual change in the cluster or in Caddy, tagcess only shows **read-only drift**; it does not write to the cluster.
- To make the change permanent, use the existing preview and approval flow (S-04); drift is not applied by itself.

## Production gate
- Connecting to a production cluster is forbidden until a separate full acceptance test has passed
  ([ADR 0032](adr/0032-dashboard-health-tls-and-alerts.md), [ADR 0031](adr/0031-two-gate-evidence-and-uncertainty.md)).
