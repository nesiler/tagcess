# 0017: Rolling back to an earlier version from the UI is a new, validated change

- Status: Accepted
- Date: 2026-09-30
- Decided by: the developer
- Related: A-03, A-02, ADR 0016, S-05, S-06

## Context
When artifacts have a git history (ADR 0016), devops should be able to go back to an earlier version from the UI.
If a rollback skipped today's validation and approval flow and just loaded an old file as it is, it could leave the system
without locks or with wide access. The developer approved A-03: a rollback is a new validated, approved and
audited change. The developer's wording: "UI rollback as a new validated, approved, audited change".

## Decision
Rolling back from the UI is not a blind load of an old artifact version; only loading the old file is not enough, because the
next render would undo the rollback. The durable **site source snapshot** of the selected version is re-applied:
- **Durable source versions:** on every successfully applied site change (normal or rollback), the site's source model
  (hosts, kind, roles, API rules, redirects, headers, certificate, target, magicdns, maintenance, owner) is stored as a
  durable version record and tied to the Git revision of that change. Versions are selected in the UI and the
  source model is rebuilt exactly (round-trip) from the selected version; this is the source of the history
  (git holds the content history of verified artifacts).
- **Preview is read-only:** today's site field validation + Caddy `/adapt` + diff; `/load` and other writes do not
  run in this step. The preview records the live base hash at that moment (current site source + the state of the
  related live artifacts).
- **After approval:** at approval the live base is re-read fresh and compared with the hash recorded at preview. If they do not match (another
  change/race in between), the apply stops and a warning is shown;
  if they match, the existing site change chain runs (Caddy `/load`, DNS, owned Zitadel URI). The durable site
  source version and the linked artifacts are updated in **a single new Change** (the version is tied to the Git revision of that
  change); the selected version is audited with actor/time/result and it is proven that the next render preserves the rollback.
- **Scope:** this covers only the site source snapshot and its Caddyfile/MagicDNS/owned Zitadel URI
  artifacts. Git may record policy versions; but the UI disables policy Apply for rollback and states that policy
  rollback comes later, as a separate item after the policy writer; no manual config step
  is suggested. The full scope of A-03 is completed with the policy rollback.
- **Access:** uncertainty or automatic error recovery without explicit approval never widens access (NFR-05).
  An explicitly approved rollback may widen access only under current and complete reads, role checks and the S-05/S-06 locks.

The system site locks (S-05) and the WireGuard switch (S-06) also apply to rollback; a rollback that would break them
is rejected. It comes after ADR 0016 and does not block the main acceptance path.

## Consequences
- Pro: a rollback is at least as safe and traceable as a normal change; the next render does not undo it.
- Con: re-validating old versions and re-applying the source snapshot add work and error surface. Mitigation: the existing
  site change chain is reused, and the rollback is subject to the locks and the preview/approval base-hash check.

## Alternatives considered
- Writing the old version straight into the file and reloading Caddy: skips validation and audit, may widen access.
- Only running git `revert`/`checkout`: changes the system without UI approval and validation, ignores the locks.
