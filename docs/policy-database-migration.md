# Runbook: Moving the Headscale policy from file mode to database mode (G-02)

Status: verified with a compose Headscale (Headscale v0.29.4, 2026-09-29; OIDC users came from a local Zitadel at that time, now Zitadel is only in the lab, ADR 0014). On an existing installation the
developer runs it. This document is a command proposal; it is not applied to production by itself.

## Why a special method is needed
- With `policy.mode: file`, `SetPolicy` (gRPC and `headscale policy set`) is rejected. So to write the policy to the DB first, you would
  have to switch the mode.
- When the mode is switched, the policy is **not copied**. If there is no policy in the DB, Headscale treats it as "no policy" and **allows everything to everyone**.
  Tested: starting with an empty DB, all connections between newly registered/reconnected nodes opened
  (including alice->carol and bob->alice, 6/6 OK). So the "switch first, then `policy set`" method opens a window in which access is widened.
- In the configuration the mode value is `database`. If `db` is written, Headscale starts but cannot read the policy
  (`no supported policy mode found in configuration, policy.mode: "db"`).

## Safe method: write to the DB first, then switch the mode
While the server runs in file mode, the policy is written to the DB with a one-off Headscale command that looks at the same data directory.
By the time the mode is switched the same policy is already in the DB, so the policy is never empty.

1. Precondition: verify that the policy file is valid (`headscale policy check -f policy.hujson`, while the server runs).
   Take a backup: the policy file and `db.sqlite`.
2. Prepare a copy of the config with `mode: database` (only `policy.mode` differs; `policy.path` may stay).
3. Write the policy to the DB. For this command Headscale says "do not run while the server is running", so the **main path is to stop the
   server** (connected clients keep the last ACL they received; while stopped the ACL does not loosen, but no new ACL is distributed):
   ```
   systemctl stop headscale
   headscale -c <database-mode-config> policy set --bypass-grpc-and-access-database-directly -f <policy.hujson>
   headscale -c <database-mode-config> policy get --bypass-grpc-and-access-database-directly > /tmp/db-policy.hujson
   diff <policy.hujson> /tmp/db-policy.hujson    # must be empty; if it differs, do not go on to step 4
   ```
   The command must run with the **same** Headscale binary as the server version (the bypass path may run DB migrations).
   **`--force`:** even with Headscale stopped, `policy set --bypass-grpc-and-access-database-directly`
   asks for an interactive confirmation; in scripts and when running by hand add `--force` to the command:
   `headscale -c <database-mode-config> policy set --bypass-grpc-and-access-database-directly --force -f <policy.hujson>`
   (verified in a lab switch, 2026-10-05). After the switch the gRPC socket is recreated; thanks to the directory mount and the client
   reconnecting, tagcess does not need a restart.
   In the compose test the command also ran without problems in a one-off container (with `--force`) while the server was running in file mode
   (same image, WAL SQLite); this path is for the lab only and is not recommended in production.
4. In the real config set `policy.mode: database` and start/restart Headscale.
5. Verify: `headscale policy get` returns the policy from the file; the leak test (below) passes.
6. From now on the policy changes only through `SetPolicy` (tagcess). The old policy file is no longer read; keep a copy of it.

## Going back
`policy.mode: file` + the file + a restart. **Careful:** if tagcess changed the policy after the switch, the file is stale
and on going back the old (possibly broader) policy is loaded. Before going back, write the current DB policy to the file with `headscale policy get > policy.hujson`
and review it. The row in the DB is not read in file mode and is harmless.

## Connectivity test (a connection that violates the ACL must fail throughout the switch)
The clients are `tailscale/tailscale` containers (`TS_USERSPACE=false`, `/dev/net/tun`), each running `nc -l -p 8000`.
Policy: `group:a`=alice, `group:b`=bob (provider identifier + `@`), a single rule `group:a -> group:b:*`. carol is in no group.
Throughout the switch, every 2 s: `bob->alice` and `carol->bob` must be **BLOCKED**, `alice->bob` must stay OK.
In the test, `bob->alice` and `carol->bob` were always BLOCKED before, during (including the restart) and after the switch;
nodes registered from scratch after the mode switch got the same ACL; the `carol->bob` rule added with `policy set` (gRPC)
was applied within a few seconds.

## Notation of the provider identifier in the policy
The user is written as `<provider identifier>@`: an `@` is appended to the end of the identifier, with no other transformation.
Example: `"group:a": ["https://auth.example.com/100000000000000002@"]`. When resolving, Headscale drops the trailing `@` and matches
`ProviderIdentifier` exactly. A notation without `@` is rejected by Headscale.
