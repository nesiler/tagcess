# 0010: Site data model and Caddyfile rendering rules

- Status: Accepted
- Date: 2026-09-28
- Decided by: the developer ("the proposals are fine for all ADRs", then "/onasor... settle everything by asking
  codex"). Two items changed after the Codex review: the exact-equivalence test (item 6) and the import (item 8);
  the developer approved them separately ("the three items Codex changed ...: ok"). On the scope of `open` sites in item 5:
  "YES. With the switch off, 'outside the tailnet -> 403' also applies to open blocks; @api rules stay valid from every
  source".
- Related: S-01..S-06, G-01, ADR 0005

## Context
Per ADR 0005 the Caddyfile is generated from the site records in SQLite, and the first version must produce an exact
equivalent of the current Caddyfile. The current file has 21 blocks and 23 hosts:
- role-checked sites with `vpn_site`
- role-checked, API-exempt sites with `vpn_site_api` (one has an extra `redir`)
- multi-host blocks without roles
- three special blocks: `auth` (Zitadel gate), `hs` (Headscale + Headplane), `vpn` (wireguard-ui)

## Decision
1. A site record carries these fields: `hosts` (ordered, at least 1), `kind` (`role` | `open` | `system`), `open_reason`
   (`intentional` | `transition`), `target_roles`, `roles` (ordered), `cert` (`le:<name>` | `auto`), `target`
   (`k8s` | `url`), `api_rules` (ADR 0011), `redirects`, `magicdns`, `note`/`owner`/`maintenance`,
   `system_template`, `headers`. The field rules are in security.md §5. In particular the host of a `url` target must be
   on an allow list; loopback and unix sockets are forbidden on user sites.
2. Special blocks are of kind `system` and are generated from fixed templates in code: `zitadel`, `headscale`,
   `wireguard_ui`, `tagcess`. They cannot be deleted and their role check cannot be broken (S-05). Only the fields the template
   exposes are editable: the `wireguard_ui` template has an `enabled` switch (turned off from the UI when WireGuard is
   shut down); the `headscale` template's `headplane` switch turns the `/admin*` path on and off (turned off from the UI).
   `zitadel` and `tagcess` cannot be turned off. None of them needs a code change or a manual step. Loopback and
   socket targets (Headscale, Headplane, wireguard-ui, `ui.sock`) exist only in these templates, fixed in code.
   The content of the `tagcess` template is: 403 outside the tailnet, deletion of `X-Auth-Request-*`, fixed `devops` role. Because this template
   also uses `forward_auth`, its callback URI belongs to set `D` in ADR 0012.
3. The snippets (`k8s`, `vpn_site`, `vpn_site_api`) are fixed in code and keep the current text.
4. Render: `role` -> `import vpn_site` or (if `api_rules` exist) `@api` + `import vpn_site_api`; `redirects` before the import
   line; `open` -> `tls` + `import k8s` (or a `url` target). Blocks are ordered by their first host name,
   system blocks come last in a fixed order.
5. When the S-06 switch is off, requests from outside the tailnet get 403:
   - On role-checked sites the outside-tailnet branch in the snippets becomes `respond 403`.
   - A `@tailnet remote_ip 100.64.0.0/10` branch is added to `open` blocks: tailnet -> `import k8s` (or the `url`
     target), everything else `respond 403`. With the switch on, `open` blocks are generated as they are today.
   - This closes both WireGuard and access from the public IP.
   - The `@api` branch stays valid from every source (developer: "From every source"; "@api rules stay valid from every
     source").
   - System templates (`zitadel`, `headscale`, `wireguard_ui`, `tagcess`) keep their own source rules.
   On import the switch starts on (today's behaviour).
6. There are two tests, catching different errors:
   - **Text golden test:** the generated Caddyfile must equal the expected text (determinism).
   - **Adapt-JSON equality:** the current and generated Caddyfiles are converted to JSON with `caddy adapt`; after sorting
     the host lists in multi-host blocks they must be equal (semantic equivalence with the current config).
   - **[Proposed] Known intentional difference (2026-10-06):** the only accepted difference between the generated Caddyfile and the current one is the friendly "No access" 403 page. `CheckSeedParity` drops it only from the generated adapt-JSON, with a narrowly matching allow list (`internal/render/parity.go` `dropKnownAdditions`: inside the reverse_proxy `handle_response`, `status_code [403]` + HTML `Content-Type` header + a 403 `static_response` with exactly the `caddyForbiddenPage` body; if there is no counterpart on the current side). Every other deviation is reported as a difference; the fixture (`test/fixtures/caddyfile-current.caddy`) does not change. The developer approved this as an exception to the S-03.2/G-01.1 equality.
   - **[Decided] Named difference class `s06_open_start` (developer, 2026-10-07):** takeover starts with S-06 on. If the current block of an `open` site restricts sources (a tailnet branch + other `remote_ip` branches to the same target, the last branch 403) and the generated block sends every source to the same target, and the routes before the source gate are the same on both sides, this block is accepted. It is not dropped silently: `render.SeedParity` lists each block in the `accepted` list (`-import-preview` `parity: accepted`, verify/guide warning). A difference that narrows access is named separately as `narrower` and fails the gate; every other difference fails it too. Covering `open/intentional` sites is **[Proposed]**.
7. Apply (same as architecture §4, S-04.1): generate -> `/adapt` -> `/load` -> if successful, write the file atomically.
   If `/load` fails the file is not touched; because systemd reads the Caddyfile on disk at restart, no file that can
   never be loaded may remain on disk. ADR 0005 was corrected to this order.
8. Import (G-01): a one-time seed file. The current 23 hosts are written once by hand into a structured file (JSON)
   and loaded into tagcess. The Caddyfile generated from the records is not applied until it passes the adapt-JSON
   equality in item 6. No Caddyfile reader is written.

## Consequences
- Pro: all current blocks fit the model; there is no free-text block. Locked system sites prevent locking oneself out.
- Pro: a single switch (S-06) closes the public exposure on both role-checked and `open` sites.
- Con: a new special block kind needs new template code. There is no such need today.
- Follow-up: in the golden test the current Caddyfile becomes the fixture. The ACME e-mail and the server IPs in the `auth` block
  are replaced with placeholders; in the adapt-JSON test the same values are supplied from settings.
- Follow-up: `deploy/caddy/tagcess.caddy` and the output of the `tagcess` template must be identical; this file becomes
  the template's golden.

## Alternatives considered
- Free "raw block" field: flexible, but a large injection surface, and it can break the S-05 lock.
- A generic "list of handle rules" model: can express every block, but needlessly complex for today's 4 patterns and
  makes the form UI harder.
- Text equality with the current file: never holds because of comments and the inline k8s block; so the comparison with
  the current file is done with adapt-JSON.
- A Caddyfile reader for known patterns (first proposal): maintenance load and fragility for a one-time 23 hosts;
  seed + equality test gives the same assurance more simply.
- Caddy's own Caddyfile parser: pulls the `caddy` module in as a dependency.

## Change notes
- 2026-09-30: the content of the `tagcess` template contains two more lines than the list given in the research notes:
  the `/oauth2/*` path goes to oauth2-proxy, and if `forward_auth` returns 401 the browser is redirected to
  `/oauth2/start?rd=<uri>`. These are infrastructure needed for the login flow of every `forward_auth` site (the
  vpn_site snippet does the same). The reference text is `deploy/caddy/tagcess.caddy`; the template must produce text
  identical to this file.
