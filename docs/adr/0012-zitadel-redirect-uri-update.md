# 0012: Zitadel redirect URIs are updated by read-merge-write with an ownership set

- Status: Accepted
- Date: 2026-09-28
- Decided by: the developer ("the proposals are fine for all ADRs"); the Codex review confirmed the proposal on all
  items. Two sub-decisions are the developer's: foreign URIs are left alone and shown with a warning
  ("Foreign URI: don't touch, warn"); post-logout URIs are not written ("Don't write for now").
- Related: S-03, P-02, ADR 0009

## Context
- The oauth2-proxy app has 17 redirect URIs. 16 belong to role-checked sites, 1 (`hs`) is not managed by tagcess.
- Zitadel v4.16 has no add/remove of a single URI; only the full list can be written. There is no optimistic
  concurrency; the last writer wins.
- In v2 `UpdateApplication`, some fields that are absent from the request return to defaults: `responseTypes`,
  `grantTypes`, `clockSkew` and `loginVersion`. `loginVersion` would really change today (`loginV1` -> `UNSPECIFIED`).
- A production write test (add -> verify -> revert) succeeded with this method; the app returned exactly to its old state.

## Decision
1. The desired set is `D`: for every host of every block that uses `forward_auth`, `https://<host>/oauth2/callback`. These are
   the role-checked sites and the `tagcess` system template (ADR 0010 item 2).
2. tagcess stores the URIs it wrote last as its own set `O`. At the first import, `O` = the intersection of the current list
   and `D`. The remaining URIs are foreign; tagcess does not touch them and shows them in the UI with a warning.
3. The new list:
   - URIs in the current list are taken in their existing order and `O \ D` is removed.
   - URIs that are in `D` but not in the list are appended in sorted order.
   - If the result equals the current list, nothing is written.
4. Writing:
   - `GetApplication` is called right before.
   - `UpdateApplication` is sent `redirectUris` together with the `responseTypes`, `grantTypes`, `clockSkew` and
     `loginVersion` that were read; other fields are not sent.
   - After writing, the app is read again. If the list differs from expected, an error and a drift warning are raised. On success `O`
     is updated.
5. Post-logout URIs are not written. If backend logout is enabled, the same algorithm applies to that list too.
6. The periodic comparison (Y-02 loop) checks `D ⊆ list` and `O ∩ list`. A manual change becomes a P-02
   drift warning.

## Consequences
- Pro: foreign URIs and ones added by hand in the console are preserved (S-03.3). No unnecessary writes.
- Pro: the trap of fields returning to defaults is turned into a rule; a golden test checks that the request contains these four fields.
- Con: a concurrent edit from the console can be lost if it falls into the read-write interval. The interval is kept short;
  the read after writing and the periodic comparison show it as drift.
- Follow-up: the same flow through the SDK (gRPC) is tested against the lab Zitadel (ADR 0014) with an integration test. The production test
  was done with `PROJECT_OWNER_GLOBAL`; it must be verified in the lab that it works with the project-member `PROJECT_OWNER` role of ADR 0009.
- Follow-up: if it is verified that the `project.application.config.oidc.changed` event arrives through Actions v2, drift
  can be detected instantly.

## Alternatives considered
- Replacing the list entirely with `D`: simple, but deletes foreign URIs such as `hs` (violates S-03.3).
- "Add only" without an ownership set: the URIs of deleted sites pile up in the list.
- v1 `UpdateOIDCAppConfig`: works with full-replace semantics for all fields, and v1 is in maintenance mode.
