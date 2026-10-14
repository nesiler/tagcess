# 0002: Zitadel and Headscale users are matched by OIDC provider identifier

- Status: Accepted
- Date: 2026-09-28
- Decided by: the developer ("the other proposals are fine")
- Related: Y-03, Y-04, H-02

## Context
Policy groups name users by e-mail. The Headscale documentation warns that e-mail and username can change and can
be taken over to gain more privileges. It recommends the OIDC provider identifier instead
(https://headscale.net/stable/ref/oidc/).

## Decision
- The matching key is the Zitadel user ID. This ID is the `sub` claim in the token and the last segment of the
  Headscale user's provider identifier.
- Policy groups name users in provider-identifier form.
- E-mail is used for display only.

## Consequences
- Pro: changing an e-mail address neither breaks nor transfers privileges.
- Con: reading the policy does not show directly who is who. The UI shows the name and e-mail next to the provider identifier.
- Follow-up: the policy notation of the provider identifier and its support in Headscale v0.29.4 were to be verified
  (`researcher` + compose test). **Verified (2026-09-29):** see "Notation in the policy" below.
- Verified: the `sub` claim is the Zitadel user ID. Headscale first looks for an exact `ProviderIdentifier` match.
  Referencing a user who has never logged in passes validation (stack-notes, 2026-09-28).

## Notation in the policy (finding of 2026-09-29, Accepted: developer approval 2026-09-29)
Tested on a Compose Headscale (v0.29.4, OIDC users have `provider_identifier=<issuer>/<id>`; at test time the issuer
was a local Zitadel, a path since removed; Zitadel now runs only in the lab, ADR 0014). The result does not depend on the issuer address:
- `"<issuer>/<id>"` (without `@`) is **rejected**: `username must contain @`.
- `"<issuer>/<id>@"` (identifier plus a trailing `@`) is **accepted** and resolves to the right user
  (`resolveUser` drops the trailing `@` and matches `ProviderIdentifier` exactly). Real ACL test: `group:a` = alice,
  single rule `group:a -> group:b`; alice->bob passed, bob->alice and a third user carol->bob were blocked.
- **Decision:** users are written in the policy as `<provider identifier>@`. There is no other transformation that avoids `@`.
  Identifiers in production look like `https://auth.example.com/<id>`, so the generated value is
  `https://auth.example.com/<id>@`; the policy generator and the policy sync use this format.
- Note: if `ProviderIdentifier` does not match, `resolveUser` also matches by `Email`/`Name`. The generator must verify that
  the generated value carries the `<issuer>/` prefix and contains no other `@`; then an identifier cannot collide with a username.
- If the user has never logged in, validation still passes (known behaviour), so a `CheckPolicy` acceptance alone is not
  proof that "the user was resolved"; tests must look the user up in Headscale and verify the real resolution separately.

## Alternatives considered
- E-mail: the current method. It can change and can be taken over.
