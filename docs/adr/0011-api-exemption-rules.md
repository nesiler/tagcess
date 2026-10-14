# 0011: API exemption rules are defined only with structured rules

- Status: Accepted
- Date: 2026-09-28
- Decided by: the developer ("the proposals are fine for all ADRs", then "/onasor... settle everything by asking
  codex"). The Codex review removed the free-form expression on YAGNI grounds; the developer approved this separately
  ("the three items Codex changed ...: ok").
- Related: S-02, S-03, ADR 0010, security.md §5

## Context
Typical sites exempt API requests from the role check:
- `git`, `k8s-dashboard`: `header Authorization *`
- `errors`: Authorization header or `path_regexp`
- `tickets`, `wiki`: Authorization or a second header such as `X-API-Key`

All of them are an OR of "header present" and "path regex" rules. Because user input enters the Caddyfile text,
there is an injection risk (ADR 0005). In Caddy, `header X *` matches even when the header is present with an empty value
(caddy v2.8.4 `matchers.go:963-993`).

## Decision
1. There are only two rule types, combined with OR:
   - `header_present`: the header name is an RFC 7230 token, `^[A-Za-z0-9-]{1,64}$`. Ready-made patterns: `Authorization`,
     `X-Api-Key`, `PRIVATE-TOKEN`.
   - `path_regex`: must compile with Go `regexp` (RE2, the same engine as Caddy), at most 200 characters. Backtick, `{`, `}`,
     `'`, line breaks and control characters are forbidden (security.md §5). `\` is written as `\\` in the CEL string (a single `\` gives a CEL error; local caddy v2.8.4 test).
2. There is **no** free-form expression. Every current use is covered by the two types. If a need appears, a new rule
   type is added (for example `path_prefix`); a free-form expression can only come with a new ADR.
3. Render:
   - If there is a single rule and it is `header_present`: `@api header <Name> *`.
   - Otherwise: `@api expression` + the rules joined with `||` in record order. A `header` rule becomes
     `header({'<Name>': '*'})`, a `path_regex` rule becomes `path_regexp('<pattern>')`.
   - These rules produce exactly the same text as the current 5 expressions.
4. Validation: the field rules first, then Caddy `/load` provisioning (second line of defence). `/adapt` does not compile CEL or
   regex; a `/load` error returns 400 and does not break the running config (local test).
5. The exemption applies from every source (developer: "From every source"). The UI shows that the header rule does not
   look at the value and that even an empty header bypasses the check.

## Consequences
- Pro: no parser, no dependency; the injection surface is two strictly validated fields.
- Pro: an expression that opens the site completely, like `true`, cannot be written.
- Con: an unforeseen API pattern needs a code change. There is no such pattern today.
- Follow-up: the "free-form expression" items in S-02 and security.md §5 are updated to this decision.
- Follow-up: the security reviewer examines the render function with golden and bad-input tests.

## Alternatives considered
- Restricted free-form expression + our own parser (first proposal): flexible, but unused today (YAGNI) and the parser
  adds security surface.
- Parsing with `cel-go`: a heavy dependency, same YAGNI reasoning.
- Validating raw CEL only with `/load`: violates security.md §5; allows opening the site completely.
- Always the `expression` form: the code gets a little simpler, but departs from the current text; for a single header
  Caddy's native matcher is the narrowest solution.
- Also checking the header value (for example a `Bearer ` prefix): differs from today's behaviour and may break applications.
