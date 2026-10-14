---
name: adr
description: Record an architectural or technical decision for tagcess as docs/adr/NNNN-slug.md. Use when a design choice is made or proposed (library, data model, integration method, deployment), or when an open point [Open] is resolved.
---

# adr

1. Pick the next number: `ls docs/adr/`, then 4 digits (`0001`, `0002`, …). Name the file
   `docs/adr/NNNN-kebab-slug.md`.
2. Copy `.agents/templates/adr.md`. Write it in English, short: one page or less.
3. Set the status honestly:
   - `Accepted` only when the developer decided it, in this conversation, in an issue or in the docs. Quote them.
   - Otherwise `Proposed`, and ask the developer to accept or reject it.
4. Link the ADR from the places that depend on it: the **[Open]** point in `docs/overview.md`, the related
   docs, and the GitHub issue or PR (`Refs docs/adr/NNNN-…`).
5. Superseding: set the old ADR to `Superseded by NNNN`. Do not delete it.
6. An ADR reaches `main` through a `type:docs` PR like any other change.
