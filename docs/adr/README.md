# Architecture decision records

Each ADR records one decision, its context, consequences and the alternatives that were considered.
Status is one of Proposed, Accepted, Rejected or Superseded. Numbers are stable; gaps are intentional.

| # | Title | Status |
|---|---|---|
| [0001](0001-headscale-policy-database-mode.md) | Headscale policy is stored in database mode | Accepted |
| [0002](0002-identity-matching-by-sub.md) | Zitadel and Headscale users are matched by OIDC provider identifier | Accepted |
| [0003](0003-webhook-over-tailscale.md) | The Zitadel webhook reaches tagcess over Tailscale | Accepted |
| [0004](0004-docker-host-network.md) | tagcess runs in Docker on the VPN host, on the host network, bound to 127.0.0.1 only | Accepted |
| [0005](0005-caddyfile-generation.md) | Caddy config is generated as a Caddyfile | Accepted |
| [0006](0006-sqlite-and-migrations.md) | SQLite driver, migrations and query layer | Accepted |
| [0007](0007-ui-stack.md) | UI stack: templ + htmx + own component package | Accepted |
| [0008](0008-headscale-restart-helper.md) | Headscale config changes are applied by a systemd helper on the host | Accepted |
| [0009](0009-zitadel-service-user.md) | Zitadel service user, authentication and client library | Accepted |
| [0010](0010-site-data-model-and-rendering.md) | Site data model and Caddyfile rendering rules | Accepted |
| [0011](0011-api-exemption-rules.md) | API exemption rules are defined only with structured rules | Accepted |
| [0012](0012-zitadel-redirect-uri-update.md) | Zitadel redirect URIs are updated by read-merge-write with an ownership set | Accepted |
| [0013](0013-magicdns-records-file.md) | MagicDNS extra records are written atomically to a separate directory and verified from the resolver | Accepted |
| [0014](0014-lab-zitadel-on-k3s.md) | The test stack's Zitadel runs in a remote k3s lab; Headscale stays in local compose | Accepted |
| [0015](0015-production-zitadel-webhook-deny-list.md) | Production Zitadel allows the Tailscale range for the webhook | Proposed |
| [0016](0016-local-git-history.md) | Generated artifacts are committed to a local git history | Accepted |
| [0017](0017-rollback-from-the-ui.md) | Rolling back to an earlier version from the UI is a new, validated change | Accepted |
| [0020](0020-headscale-policy-editor.md) | The Headscale policy editor uses a lossless document and a validated version flow | Accepted |
| [0021](0021-headscale-host-operation-protocol.md) | The Headscale host helper works with a maintenance flag and a journal | Accepted |
| [0030](0030-read-only-k8s-discovery-and-site-draft.md) | Read-only Kubernetes discovery and a site draft | Accepted |
| [0031](0031-two-gate-evidence-and-uncertainty.md) | The two-gate check is reported with evidence and uncertainty | Accepted |
| [0032](0032-dashboard-health-tls-and-alerts.md) | Dashboard health, presented TLS and the alert lifecycle | Accepted |
