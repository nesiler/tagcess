# 0003: The Zitadel webhook reaches tagcess over Tailscale

- Status: Accepted
- Date: 2026-09-28
- Decided by: the developer ("the other proposals are fine")
- Related: Y-01, Y-02

## Context
Zitadel runs inside Kubernetes on one host, tagcess runs on the VPN host. For instant sync, the Zitadel Actions v2
webhook has to reach tagcess.

## Decision
- The webhook target is an endpoint on the VPN host's Tailscale address. No webhook endpoint is exposed to the
  public internet.
- Signature verification is mandatory in every case.

## Consequences
- Pro: small attack surface.
- Con: if Tailscale breaks on the Kubernetes host, the webhook does not arrive. The periodic full comparison (Y-02) covers this case.
- **Not verified:** whether the Zitadel pod can reach the VPN host's Tailscale IP. To be checked read-only.
  If it cannot, this ADR is reopened.
- Follow-up: add a `tag:k8s -> tag:vpn-server:<webhook port>` rule to the Headscale ACL.
- The endpoint listens directly on the Tailscale IP; Caddy is not used ([ADR 0004](0004-docker-host-network.md)).
- Verified: `tailscale ping 100.64.0.4` works from the Kubernetes host. TCP is closed at the moment because of the
  ACL, which is expected (2026-09-28, production read-only).

## Alternatives considered
- Public endpoint (for example a path under `hs.*`): an internet-facing surface even with a signature. Not needed.
