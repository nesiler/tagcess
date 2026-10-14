# 0020: The Headscale policy editor uses a lossless document and a validated version flow

- Status: Accepted
- Date: 2026-09-29
- Decided by: the developer (2026-09-29, final decision round 3: "YES"; an explicit answer accepting ADR 0020)
- Related: H-04, H-05, Y-03, A-01, A-03

## Context
ADR 0001 sets the Headscale database as the policy source. v0.29.4 supports grants, SSH and test fields;
CheckPolicy returns an empty success response or a text error. If neither ACL nor grants exists, allow-all results. A failure in the
SetPolicy steps gives no atomic rollback guarantee. Sources: the Headscale research notes.

## Decision
**[Decided]** (2026-09-29) The raw HuJSON and the AST are kept as a single document; the form and the raw editor change the same draft. Role groups stay
owned only by the Zitadel sync. The shared writer lock is taken first; fresh policy/user/node/Zitadel reads, building the candidate groups and
the base hash check are done under the lock. The lock is held until CheckPolicy, the persistent intent, SetPolicy, read-back and the result record
are complete. An empty document, or removing both the ACL and grants fields, is blocked. Rollback builds a new candidate with today's role
groups and validates it again; an old version is not restored directly.

**[Decided]** (2026-09-29) The shared writer also obeys the persistent maintenance barrier in ADR 0021; the policy is not
written during a config restart/recovery. While there is a SetPolicy with an uncertain result or a pending role revocation, a normal config restart is not done. So
a restart re-enabling the old DB policy is not treated as ordinary recovery; a separate verified policy recovery is needed.

## Consequences
- **[Decided]** (2026-09-29, developer: "1,2,3 proposals ok.", second detail round 3) The first version offers a form for everyday access rules,
  tag owners and route autoApprovers; for complex advanced fields it offers a raw HuJSON editor on the same page.
  Comments and other fields are preserved. The first answer accepted the UI scope; the final decision round 3 accepted the ADR as a whole.
- Comments, grants and tests are not lost; CodeMirror shows a text error panel if there is no exact position.
- Because Headscale offers no CAS, there is no full guarantee against a race with an external writer; single-writer operation and drift checks are needed.
- On error an uncertain state is shown; live/DB consistency cannot be proven by GetPolicy alone.
- Partial-failure recovery, behaviour that does not widen access, and round-trip tests must be proven.

## Additional decisions (2026-10-01)
**[Decided]** (developer, 2026-10-01: "everything is APPROVED apart from these"; status stays Accepted)
- Locked, mandatory policy tests: `devops -> tag:vpn-server:443` (the tagcess UI), `tag:k8s ->` the vpn-server webhook port, the SSH access rule. tagcess keeps them; an edit that breaks them is rejected (like S-05 for sites).
- While Zitadel cannot be read, ACL editing is blocked (current roles cannot be verified); the CLI emergency path in security §11 remains.
- The editor first ships as a plain textarea + server-side error panel; CodeMirror comes later (the CodeMirror position/diagnostic notes above belong to that stage; see the ADR 0007 note).
- Headplane is ignored: a Headplane ACL race is out of scope.

## Alternatives considered
- Full JSON marshal: loses comments and metadata.
- Trusting only a CheckPolicy success: does not prevent an empty policy or a semantic widening of access.
- Writing an old revision unconditionally: may re-open current role revocations.
