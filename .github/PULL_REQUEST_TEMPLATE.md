Closes #

## Summary
<!-- What changed and why, in a few lines. -->

## Acceptance criteria → tests
| Criterion | Test (package) | Result |
|---|---|---|
| AC1 | `TestXxx` (`./internal/...`) | pass |

## Gate
```
$ make check
<short summary of the output>
```
<!-- Also list the integration/e2e targets you ran, if any. -->

## Risk
- [ ] normal
- [ ] auth (`risk:auth`: authn/authz, webhooks, policy/ACL writes, generated config, node expiry or secrets).
      Needs `security-reviewer` and the developer's approval before merge.

## Checklist
- [ ] Docs or ADR updated if behaviour or a decision changed.
- [ ] Generated code committed (`make generate`); golden files changed on purpose only.
- [ ] No secrets, real hostnames, IPs or personal data in code, fixtures or logs.
- [ ] No `Co-Authored-By` or "Generated with" lines in commits.

## Follow-ups
<!-- Out-of-scope findings; the coordinator turns them into issues. -->
