# UI glossary

The UI is available in English and Turkish. This table fixes the term used in each language so that screens stay consistent.
Technical names that Headscale, Caddy, Zitadel and k8s use for themselves stay in English in the Turkish UI too. Turkish suffixes are attached
with an apostrophe: `tag'ler`, `policy'de`, `route'u`. Menu and column names start with a capital letter.

Terms that stay English in Turkish (the technical set) are marked with "(kept)" in the Turkish column.

| English term | Turkish term | Meaning |
|---|---|---|
| tag, tagged | tag, tag'li (kept) | Headscale label on a node; tagged nodes are owned by the tag, not a user |
| node | node (kept) | A device registered in Headscale |
| exit node | exit node (kept) | A node that routes internet traffic for other nodes |
| route | route (kept) | A subnet route advertised by a node |
| redirect | redirect (kept) | A Caddy redirect in the site form; not to be confused with route |
| dry run | dry-run (kept) | A mode in which differences are computed and shown but not applied |
| sync | sync (kept) | Carrying Zitadel role assignments into Headscale groups |
| policy | policy (kept) | The Headscale access policy document |
| approvers (autoApprovers) | autoApprovers / approvers (kept) | Headscale policy field |
| owners (tagOwners) | tagOwners / owners (kept) | Headscale policy field |
| cluster | cluster (kept) | The k8s cluster |
| discovery | discovery (kept) | Finding internal Ingresses that are not yet sites |
| scope | scope (kept) | The set of namespaces read from the cluster |
| parity | parity (kept) | Equality between generated and existing configuration |
| artifact | artifact (kept) | A generated file (Caddyfile, policy, DNS records) |
| freshness | freshness (kept) | How recent an observation is |
| check, probe | check / probe (kept) | A health measurement; "check" appears only in settings and technical names |
| gate | gate (kept) | The access entry point (the two-gate audit) |
| API bypass | API bypass (kept) | The API exemption rule of a site (header or path) |
| import | import (kept) | Importing an existing installation |
| listener | listener (kept) | A network listener of the ingress controller |
| actor | actor (kept) | The audit column that says who made a change |
| threshold | threshold (kept) | A limit that triggers a warning or an approval |
| read-only | read-only (kept) | Single spelling for "cannot be changed" |
| credential | credential (kept) | A secret used to connect to a system |
| key: auth key, API key | key: auth key, API key (kept) | A Headscale pre-auth key or API key |
| switch | switch (kept) | An on/off setting, for example the WireGuard switch; distinct from "key" |
| preview | preview (kept) | The read-only step that shows validation and diff before applying |
| apply | apply (kept) | Putting a confirmed change into effect; button label `Apply` |
| revision | revision (kept) | A stored version of the policy |
| draft | draft (kept) | A saved, not yet applied suggestion |
| config | config (kept) | Configuration |
| recovery | recovery (kept) | Controlled recovery after an uncertain policy write |
| rollback | rollback (kept) | Returning to an earlier site version as a new change |
| audit | audit (kept) | The audit log |
| device | cihaz | A machine connected to the VPN |
| user | kullanıcı | A person known to the identity provider |
| role | rol | A role in the Zitadel `vpn` project |
| group | grup | A Headscale group built from a role |
| rule | kural | An access or exemption rule |
| alert | uyarı | A dashboard alert |
| maintenance | bakım | A mode that mutes a site's monitoring alarm, or the Headscale config maintenance state |
| health | sağlık | Whether a target responds as expected |
| certificate | sertifika | A TLS certificate |
| history | geçmiş | Past changes |
| record | kayıt | For example a DNS record |
| server | sunucu | A server |
| request | istek | An HTTP or API request |
| permission | yetki | A granted capability |
| network | ağ | The network |
| last seen | son görülme | When a device was last connected |
| event | olay | An event, for example a webhook event |
| owner | sahip | The owner of a device |
| check (noun, health or network) | kontrol | A health check or network check; the Turkish UI does not use half-translated forms such as "ağ check'i" |
| source outside the tailnet | tailnet dışı kaynak | Wording used instead of presenting WireGuard as a separate component |
| transition source | geçiş kaynağı | Same as above |

## Rules
- Sentences, button verbs, warnings and explanations are written in the language of the UI; technical terms follow the table.
- A new term is added to this table and to the glossary test list together. `TestUITextUsesGlossaryTerms` (`internal/web/ui_rules_test.go`) prevents old
  or inconsistent wording from re-entering page text.
