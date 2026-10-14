---
name: stack-notes
description: Verified facts about tagcess's external systems (Headscale, Caddy, oauth2-proxy, Zitadel, Headplane, k8s) — versions, file paths, API behaviour, event names. Read before designing or coding any integration; append new verified facts with date and source.
---

# stack-notes

Facts here are verified, each with a date and a source. Anything else is a guess and must be checked
(context7, official docs, source code, `researcher` agent) before code depends on it.
Production versions are pinned below. Always check behaviour for **these** versions.

Details: [reference.md](reference.md)

## Adding facts
- Format: `- <fact> (YYYY-MM-DD, <source URL or "observed on a production installation">)`.
- Put them under the right section in `reference.md`. When something is superseded, strike it through;
  do not delete it.
- No secrets and no personal data (e-mails, device names) from production.
