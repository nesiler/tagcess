# 0009: Zitadel service user, authentication and client library

- Status: Accepted
- Decided by: the developer. Approved the role first ("A ok"), then the method and library ("approved") (2026-09-28).
- Date: 2026-09-28
- Related: Y-01..Y-05, S-03, security.md §7 and §10

## Context
tagcess has three jobs in Zitadel:
- read role grants in the `vpn` project
- read user state
- update the URIs of the oauth2-proxy app

This needs a non-human account. In Zitadel it is called a "service user" (machine user).

## Decision
1. **Account:** a service user named `tagcess` is created in Zitadel. It is added to the `vpn` project as a
   member (administrator) with the `PROJECT_OWNER` role. At organization level it only has the read-only
   `ORG_OWNER_VIEWER` role (change below); it has no write permission there.
2. **Authentication:** JWT profile key (`key.json`).
   - Zitadel hands out the key file **once**, at creation time.
   - tagcess uses this key to request a short-lived access token (OAuth2 JWT Profile Grant, RFC 7523) and renews the
     token automatically.
   - On the VPN host the key is the file `/etc/tagcess/secrets/zitadel-key.json`: mode 0400, owned by tagcess's UID,
     mounted read-only into the container.
   - The key is given a 1-year expiry date.
3. **Client library:** `github.com/zitadel/zitadel-go/v3`, Zitadel's official Go SDK.
   - Facts (2026-09-28, `gh api`): Apache-2.0; latest release v3.30.0 (2026-09-28); actively maintained.
   - Authentication is done with `client.DefaultServiceUserAuthentication(keyPath, oidc.ScopeOpenID, client.ScopeZitadelAPI())`.
     The SDK ships the v2 service clients ready-made (`authorization/v2`, `application/v2`, user v2).
   - Reason for the dependency: gRPC and protobuf are needed for the Headscale client anyway. The SDK provides token
     acquisition, renewal and typed clients. Writing the same by hand means JWT signing and API definitions.
   - tagcess wraps the SDK in its own `internal/zitadel` package. This package exposes only three operations:
     grant list, user state, app URI update. There is no function that assigns or removes roles
     (security.md §10); a test checks this.

## Change (2026-09-29)
Verified in the lab (Zitadel v4.16.0): when the service user is `PROJECT_OWNER` only at project level,
`UserService.ListUsers` returns only the user itself; other users are silently filtered out and `totalResult` does not
count them (so comparing `totalResult` cannot detect this), and `GetUserByID` returns PermissionDenied.
After adding `ORG_OWNER_VIEWER` at organization level, `ListUsers` returns all users and the correct `totalResult`.
Decision: the account gets `ORG_OWNER_VIEWER` at organization level (developer approval, 2026-09-29).
Added to setup step 3: Organization -> Members -> `tagcess` -> `ORG_OWNER_VIEWER`.

## Setup (done by the developer)
1. Zitadel console -> organization -> Users -> **Service Users** -> New.
   - Username `tagcess`.
   - Access token type **JWT**.
2. The user's **Keys** tab -> New -> type JSON, expiry 1 year -> download the file. It cannot be downloaded again.
3. Projects -> `vpn` -> Members/Administrators -> add `tagcess` -> role `PROJECT_OWNER`.
   Also give the `tagcess` user the `ORG_OWNER_VIEWER` role in the organization (to read user states).
4. Put the file on the VPN host as `/etc/tagcess/secrets/zitadel-key.json` (0400). Do not paste it into the repository,
   documents or chat.
5. To rotate the key: create a new key, replace the file, restart tagcess, delete the old key.

The same setup is done on the lab Zitadel (Kubernetes lab, ADR 0014) with the seed tool, so tests run against a real Zitadel.

## Consequences
- Pro: no password or long-lived token; the access token is short-lived. The v2 clients of the official SDK are ready.
- Con: the SDK brings zitadel/oidc and gRPC dependencies. Accepted, reason above.
- **To verify:**
  - The SDK connects to `auth.example.com:443` over gRPC. If this traffic goes from the VPN host through Caddy -> the
    Kubernetes ingress controller, it must be tested that the chain carries HTTP/2 end to end and that the API paths
    are reachable from the VPN.
  - Which IP the VPN host resolves the `auth.*` address to must also be checked (read-only).

## Alternatives considered
- Personal Access Token (PAT): simpler, a single static token. But long-lived, and if leaked from the file it stays valid
  until its expiry date.
- Client credentials (client id/secret): simple, but the secret is long-lived.
- Hand-written REST client without the SDK: fewer dependencies. But JWT signing, token renewal and API types stay with us.
