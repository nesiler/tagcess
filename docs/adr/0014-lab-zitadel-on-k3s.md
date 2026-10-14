# 0014: The test stack's Zitadel runs in a remote k3s lab; Headscale stays in local compose

- Status: Accepted
- Date: 2026-09-29
- Decided by: the developer (source: 2026-09-29 approval; RAM is tight on the laptop and Zitadel is the heavy part of the stack). The developer
  explicitly accepted that the lab needs no access restriction.
- Related: NFR-08, ADR 0009

## Context
The compose stack ran Zitadel v4.16.0 + Postgres + Headscale on the developer's laptop. Zitadel is the heaviest part
in memory. The developer has a remote k3s cluster (a single node, 4 CPU, 7.9 GiB), but the same node also carries live
sites and other services. An overflow here could take others down.

## Decision
1. The test stack's **Zitadel** (and Postgres) move to k3s; **Headscale stays in local compose** and uses the lab
   Zitadel as its OIDC issuer. The local compose Zitadel was kept as a fallback; it was removed on 2026-09-29 (see the note below).
2. Same node, **separate namespace `tagcess-lab`**. A `ResourceQuota` and a `LimitRange` are put on the namespace (about 768Mi limit
   for Zitadel, 256Mi for Postgres). Nothing is written to any other namespace; they are only read.
3. **No access restriction:** Zitadel and Postgres are on the server only to save RAM on the laptop; since this is a lab
   the Ingress is plain (with TLS) and may be public. No IP allow list and no NetworkPolicy (developer decision).
4. **Address and TLS:** `tagcess-zitadel.lab.example.com` (the wildcard domain already resolves to the node's public IP; DNS
   is not touched). Certificate: a new `Certificate` is not requested on every setup (see the 2026-09-29 TLS note); the existing wildcard Secret is copied.
   Zitadel: `ExternalDomain=tagcess-zitadel.lab.example.com`, `ExternalPort=443`, `ExternalSecure=true`, TLS off inside
   (TLS terminates at Traefik).
5. **Installation:** the official `zitadel/zitadel` chart **10.0.6** (app v4.15.3) is kept; the image tag is given
   explicitly as **v4.16.0** (the pinned production version). Chart 10.1.0 (v4.19.2) is not used. Postgres is not the bitnami chart but
   our own small StatefulSet (`postgres:16.13-alpine`, same pin as compose).
6. No manual UI step remains: installation, obtaining the PAT, the seed and the Headscale connection are done with `make lab-up`.
   Only manifests and values are in the repository; the masterkey and passwords are generated at run time.

## Consequences
- Pro: RAM is freed on the laptop; Zitadel is tested with real TLS and a real domain (closer to production).
- Con: the test depends on a shared node and the internet; quotas are mandatory.
- Follow-up: it was verified that the Headscale container reaches the issuer.

## Alternatives considered
- Keep the whole stack local: does not solve the RAM problem (the developer rejected it).
- Bitnami postgres chart: the old images were removed.
- Chart 10.1.0: app v4.19.2, differs from the pinned production version.

## Update (2026-09-29): the local compose Zitadel was removed
On the developer's order ("REMOVE IT COMPLETELY") the local Docker Compose Zitadel and Postgres were deleted from the repository: **Accepted** (developer decision).
Zitadel exists only in this lab; local compose keeps only Headscale and the socat relay. Test and seed defaults
point to the lab (`tagcess-zitadel.lab.example.com:443`, TLS, `.secrets/lab`); `make compose-up/compose-down/integration` no longer exist,
replaced by `make lab-up`, `make lab-integration`, `make lab-down`.

## Update (2026-09-29): the wildcard Secret is copied for TLS, no Certificate is requested
Developer decision, **Accepted**. `make lab-up` copies the existing wildcard TLS Secret covering the lab domain
(namespace `default`) into `tagcess-lab` as `tagcess-zitadel-tls`; the Ingress uses it. The cert-manager
`Certificate` (and `test/lab/certificate.yaml`) was removed. Reason: every clean `lab-down`/`lab-up` consumed a new Let's Encrypt
certificate and hit the limit of 5 certificates per week for the same host (429). The source Secret is only read and is never
modified; the copy is written only to `tagcess-lab`; key material does not enter the repository, logs or files (it is passed through a pipe).
