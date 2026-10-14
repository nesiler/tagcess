# Security policy

tagcess decides who can reach internal services over a VPN, so we take security reports seriously.

## Reporting a vulnerability
- Report privately through a **GitHub security advisory**:
  [Report a vulnerability](https://github.com/nesiler/tagcess/security/advisories/new).
- Do **not** open a public issue, pull request or discussion for a vulnerability.
- Include what you found, how to reproduce it, the affected version or commit, and the impact you expect.
- Remove secrets and real hostnames, IPs or user data from what you send.

## What to expect
tagcess is pre-release and maintained by a small team. We do not promise a response or fix time (SLA) yet. We will
acknowledge the report in the advisory, keep you informed there, and credit you in the advisory unless you prefer
otherwise.

## Supported versions
There is no stable release yet. Fixes go into the latest `0.1.x` development line only.

## Scope
In scope: the tagcess code in this repository, its generated configuration (Caddy, Headscale policy, DNS) and its
install scripts. Vulnerabilities in Headscale, Caddy, oauth2-proxy or the identity provider themselves should go to
those projects; tell us too if tagcess makes them reachable.
