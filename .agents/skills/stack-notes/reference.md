# Stack reference (verified facts)

## Pinned versions (2026)
- Headscale v0.29.4; Caddy v2.8.4; oauth2-proxy v7.15.4; Headplane 0.7.1; Zitadel v4.16.0.

## Headscale
- Config: `/etc/headscale/config.yaml`.
  - `server_url: https://hs.example.com`
  - Database: SQLite at `/var/lib/headscale/db.sqlite`.
  - `policy.mode: file`, path `/etc/headscale/policy.hujson`.
  - DNS: `magic_dns: true`, `base_domain: ts.example.com`,
    `extra_records_path: /etc/headscale/extra-records.json`.
  - OIDC issuer `https://auth.example.com`, scopes `openid profile email`, PKCE S256;
    `allowed_groups` is not set.
- A policy typically uses e-mail addresses as user identifiers in `groups`, and defines tags for servers (for example `tag:vpn-server`).
- OIDC groups cannot be used in policy rules. Issue #2366 is open; PR #3216 is open and unmerged.
  (2026-09-28, https://github.com/juanfont/headscale/issues/2366)
- The unix socket at `/var/run/headscale/headscale.sock` (mode `0770`) serves **unauthenticated, full admin** gRPC.
  The REST gateway `/api/v1/*` needs an API key. (2026-09-28, headscale v0.29.4 `hscontrol/app.go:707-730`)
- RPCs include:
  - `SetPolicy`, `GetPolicy`, **`CheckPolicy`** (validates without applying)
  - `ListNodes`, `ExpireNode`, `RenameNode`, `DeleteNode`, `SetTags`, **`SetApprovedRoutes`**
  - `ListUsers`: returns `id`, `name`, `display_name`, `email`, `provider_id`, `provider`
  - `Create`/`ExpirePreAuthKey`, `Create`/`ExpireApiKey`

  (2026-09-28, headscale v0.29.4 `proto/headscale/v1/headscale.proto`)
- Policy user resolution: first an exact `ProviderIdentifier` match, then e-mail or name.
  A policy that references a user who never logged in **passes** validation; only an ambiguous match fails.
  (2026-09-28, headscale v0.29.4 `hscontrol/policy/v2/types.go:411-439`, `policy.go:105-121`)
- Switching `policy.mode` from file to db does **not** copy the policy. An empty DB policy means
  "no policy configured", which is valid. `headscale policy set -f` works only in db mode. `headscale policy check`
  exists. (2026-09-28, headscale v0.29.4 `hscontrol/db/policy.go:56-92`, `cmd/headscale/cli/policy.go`)
- A tagged node's owner is its tag. `SetTags` on a **personal** node (database-mode v0.29.4, disposable hsstack,
  disposable-stack observation): the node becomes tagged with exactly the given set; its `UserID` is **not left on the old user**
  but moves to Headscale's built-in `tagged-devices` user (id `2147455555`); its **expiry is left unchanged** (a future
  expiry keeps the same timestamp, a node without one stays without). Expiry code must skip tagged nodes explicitly by
  looking at the tags, never at `UserID`; a converted node stays tagged for the reconcile's Y-04 rule (`len(Tags) > 0`).
  (2026-10-01, headscale v0.29.4 `TestTags_Integration_OwnershipAfterSetTags`, `hscontrol/types/node.go:283-287`,
  `state.go:960`; corrects both the 2026-09-28 "keeps its UserID" note and the "clears UserID" reading)
- Extra records file (`dns.extra_records_path`): watched with fsnotify (file, not dir); atomic rename works (watch
  re-added with backoff). Invalid JSON → error logged, **old records kept**; empty file ignored. A successful load
  pushes to clients without restart. Only A/AAAA in practice; duplicate names with different values are not
  checked. No gRPC/REST API for extra records. (2026-09-28, headscale v0.29.4 `hscontrol/dns/extrarecords.go:73-253`,
  `hscontrol/app.go:298-385`)
- A typical installation keeps `/etc/headscale/extra-records.json` as `root:root 0644`; Headscale runs as `headscale` with `ProtectSystem=strict`, `ReadWritePaths=/var/lib/headscale`.
  `dig @100.100.100.100 <name>` on the VPN host answers from MagicDNS.
- Local test stack on a macOS container runtime: a unix socket bind-mounted from the container to the macOS host is visible as a file but
  `connect()` gets ECONNREFUSED, so Go tests cannot dial it. The compose Headscale shares the socket through a named volume
  with a `socat` relay container that publishes it on `127.0.0.1:50444`. Distroless Headscale image has no shell or
  socat. (2026-09-29, local test)
- `CheckPolicy` returns gRPC `InvalidArgument` with Headscale's message for a bad policy (e.g. an undefined group);
  `RegisterNode`/`DebugCreateNode` (auth id `hskey-authreq-` + 24 chars) can create a test node without a tailscale client.
  (2026-09-29, headscale v0.29.4 `hscontrol/grpcv1.go`, verified against the compose stack)
- Node write RPCs (v0.29.4, hsstack integration): `RenameNode` changes the node's `given_name`; the
  `name` field stays the machine-registered name, so "renamed" shows up only in `given_name` of the response and
  `ListNodes`. `ExpireNode` accepts an arbitrary `expiry` timestamp (a future time schedules the cutoff) and a
  `disable_expiry` boolean that clears the expiry (node never expires); both answer with the node. `SetTags`
  replaces the full tag list and rejects an empty list with `InvalidArgument`; `SetApprovedRoutes` replaces the
  full approved-CIDR list, an empty list withdraws all. `DeleteNode` answers empty and leaves users and keys alone.
  (2026-10-01, hsstack v0.29.4 integration, internal/headscale/admin)
- Pre-auth keys (v0.29.4, hsstack integration): the plaintext secret exists only in the `CreatePreAuthKey`
  response; `ListPreAuthKeys` returns later-created keys with the `key` field masked, and `ExpirePreAuthKey`/
  `DeletePreAuthKey` address keys by `id`. Deleting a pre-auth or API key never deletes the node that registered
  with it. `ExpireApiKey`/`DeleteApiKey` accept `prefix` or `id`; calling them by `id` with the `prefix` field
  unset works. `CreateApiKey`'s response is the full secret string, not a message. (2026-10-01, hsstack v0.29.4
  integration, internal/headscale/admin)
- Tagged pre-auth key user/tag combination (v0.29.4, hsstack integration, `TestTagKey_Integration_AcceptedCombination`):
  `CreatePreAuthKey` accepts `user = 0` together with `acl_tags` (the key lists with user id 0 and empty user name; the nodes
  it registers are owned by their tags) and also a real user together with tags. User 0 without tags is refused
  (`auth-key must be either tagged or owned by user`). Headscale does **not** check the tags against the policy's
  `tagOwners` (an unknown tag is accepted), so tagcess does that check itself. tagcess makes shared-device keys with user 0;
  the admin client therefore allows user 0 only when tags are given. (2026-10-01, hsstack v0.29.4 integration)
- `#`-named policy members are **version dependent** (2026-10-05, source read of the tags): `stripMetadataMembers`
  (removes every `#`-named member recursively, array elements included, before `Standardize`; v0.29.4
  `hscontrol/policy/v2/types.go:3206-3257`) exists **only from v0.29.4** (cherry-pick aa4c952b of main 5401edb6,
  2026-09-14, PR https://github.com/juanfont/headscale/pull/3481, fixes #3479; v0.29.4 CHANGELOG.md:23). v0.27.0-v0.29.3
  strip `#` keys only inside `acls[]` elements (`ACL.UnmarshalJSON`, v0.29.3 `types.go:1941-1960`); a `#` member in
  `tests`, `grants`, `ssh` or `nodeAttrs` fails json v2 `RejectUnknownMembers` (`types.go:28-32`) with
  `unknown field: "#x"` (`types.go:149, 3263-3296`); the lab 0.29.3 showed `parsing policy: unknown field: "#tagcess"`.
  v0.26.0 strips none. HuJSON comments (`//`, `/* */`) are removed by `hujson.Parse` + `Standardize` in the single
  entry point `unmarshalPolicy` on every version, so tagcess marks locked tests with a `/* tagcess:locked */` comment
  instead (the old `"#tagcess": "locked"` member is migrated away on the next save). Database mode stores the raw text
  (`db.SetPolicy` `Data: policy`, v0.29.3 `grpcv1.go:723-760`, `db/policy.go:14-45`; v0.29.4 `state.go:1226-1228`), so
  comments survive `GetPolicy` (also checked by the writer integration test on 0.29.4). Not run: a commented `tests`
  entry against a real 0.29.3 (code reading only).
- Historical (v0.29.4 compose): policy `tests` entries with a `"#tagcess": "locked"` member were accepted there. A failing test makes CheckPolicy return `InvalidArgument` with one
  line per failure: `<src> -> <dst>: expected ALLOWED, got DENIED` (a `(proto)` suffix after dst when set), or
  `<src>: error testing "<dst>": ...`. A `tests` entry whose src or dst resolves to **no IP** (a group or tag without
  nodes) is a **failure**, not a skip. (2026-10-01, v0.29.4 `policy/v2/test.go` + compose; host aliases in `hosts`
  stand in for groups/tags in the compose test, real groups/tags with nodes need a separate lab)
- Policy v2 fields (, 2026-10-01, v0.29.4 `hscontrol/policy/v2/types.go`): `groups`, `tagOwners`, `hosts`, `acls`,
  `grants` (`src`, `dst`, `ip`, `app`, `via`), `ssh` (`action`, `src`, `dst`, `users`, `checkPeriod`, `acceptEnv`),
  `autoApprovers` (`routes`, `exitNode`), `nodeAttrs` (`target`, `attr`, `ipPool`; `ipPool` is parsed and validated but
  the compiler does not consume it), `tests`, `sshTests`, `randomizeClientPort`. Unknown ordinary fields are rejected;
  `postures` and IP sets are unsupported. Neither `acls` nor `grants` = allow-all; `grants: []` = deny-all.
- `CheckPolicy` success is an **empty response** (no line/column or structured diagnostic); a bad policy is
  `InvalidArgument`, a user-read failure is `Internal`. It builds a separate manager and changes neither the live
  manager nor the DB. An unresolved user reference alone may not fail it. (2026-10-01, v0.29.4 `grpcv1.go:791-826`;
  )
- `SetPolicy` (db mode) is several steps (state change, SSH check for the first node, DB write, ReloadPolicy,
  distribution), not one atomic operation: a later error does not undo earlier steps (**partial failure**). Writing the
  same policy again can re-evaluate `autoApprovers` routes, so "same text" is not "no side effect".
  (2026-10-01, v0.29.4 `grpcv1.go:730-786`)
- `ListPreAuthKeys` has no filter and returns all keys. New (hashed) keys come back masked as `hskey-auth-<prefix>-***`;
  **legacy plaintext keys may return the full secret**, so an admin DTO must strip the secret from both kinds.
  Only the create response holds the full key. (2026-10-01, v0.29.4 `hscontrol/types/preauth_key.go:84-111`)
- `CreatePreAuthKey` without `expiration` does **not** make a never-expiring key: the handler passes a pointer to the
  zero `time.Time`, the DB stores it, and `PreAuthKey.Validate` rejects it as `authkey expired` (zero time is before
  now). There is no "never expires" pre-auth key in the API; always send an explicit future time. A long expiry (years)
  is accepted. (2026-10-06, v0.29.4 `hscontrol/grpcv1.go:147-186`, `hscontrol/db/preauth_keys.go`,
  `hscontrol/types/preauth_key.go:120-133`; read from the module source)
- `SetTags` rejects an empty tag list. `ExpireNode` takes `expiry` and `disable_expiry` (note above).
  (2026-10-01, v0.29.4 `hscontrol/grpcv1.go`, `state.go`)
- OIDC restrictions (`doOIDCAuthorization`): a non-empty `allowed_groups` is checked first; defined `allowed_domains` and
  `allowed_users` must **also** pass (AND, not alternatives). `allowed_users` is an **e-mail list**, not user IDs.
  With e-mail filters set and `email_verified_required=true`, an unverified e-mail is rejected. If `allowed_groups` is
  empty the group check is skipped. Source behaviour only; a real login flow was not verified.
  (2026-10-01, v0.29.4 `hscontrol/oidc.go:525-617`)
- Pinned sources for the policy findings: Headscale v0.29.4 commit `8106636c7f8d0cf8c9d4fb0beae94415069b768b`; Headplane
  v0.7.1 commit `30c842ed8dbf011e78596e3a474133ec4069ba79` (historical only, Headplane is ignored). (2026-10-01,
  )
- `headscale configtest` exists. `/health` is served at the root path. (2026-09-28, headscale v0.29.4)
- `SetPolicy` through the API is rejected in file mode. File mode needs a SIGHUP or reload after a change.
  (2026-09-28, https://headscale.net/stable/ref/policy/) Migration steps verified below.
- Policy user written as the OIDC provider identifier (2026-09-29, compose v0.29.4 + real tailscale clients):
  `"https://issuer/<id>@"` (identifier + trailing `@`) passes `CheckPolicy` and resolves to that user (`resolveUser`
  strips one trailing `@`, exact-matches `ProviderIdentifier`, then falls back to Email/Name); without the `@` it fails with
  `username must contain @`. Users created by `headscale users create` have no provider id; the test set
  `provider='oidc'` and `provider_identifier` in sqlite (a real OIDC login is a later task).
- Policy mode value in `config.yaml` is `database` (not `db`). With `db` Headscale still starts but `policy get`
  fails with `no supported policy mode found`. (2026-09-29, `hscontrol/types/config.go:57`, compose)
- Empty DB policy after file→database switch = allow-all: freshly registered nodes could reach each other with no
  ACL (6/6 connects OK), while already-connected clients kept their old filter. (2026-09-29, compose)
- Safe file→database switch: `headscale -c <db-mode config> policy set --force --bypass-grpc-and-access-database-directly -f policy.hujson`
  (one-off container on the same data volume, server still in file mode; needs the OIDC env vars because config validation
  runs), then set `policy.mode: database` and restart. `--force` skips the "is headscale running" prompt. Policy was never
  empty; bob→alice and carol→bob stayed blocked throughout. Runbook: `docs/policy-database-migration.md`. (2026-09-29, compose)
- Docs: storing the policy in the database "is typically only required in case a web interface is used". (2026-09-28, https://headscale.net/stable/ref/policy/)
- Policy user identifiers must contain a single `@`: an e-mail, `username@`, or the OIDC provider identifier. The docs recommend the provider identifier, because e-mail and username can change or be hijacked. (2026-09-28, https://headscale.net/stable/ref/oidc/)
- Host lab (OrbStack arm64, ubuntu:24.04 + systemd PID 1, `--privileged --network host`): the v0.29.4 `.deb`
  (release `checksums.txt` sha256: amd64 `1f653647…0841`, arm64 `021a4aeb…f816`) creates user/group `headscale` (uid 997 in
  the image), installs `/usr/lib/systemd/system/headscale.service` (`User=headscale`, `ProtectSystem=strict`,
  `ReadWritePaths=/var/lib/headscale`, `RuntimeDirectory=headscale` mode 0750, `UMask=0077`, `Restart=always`; the lab image runs `systemctl disable`
  on it and hostlab.sh enables it once the config is written), a default `/etc/headscale/config.yaml` (root:root 0644, not usable as is: it lacks
  `noise.private_key_path`, `server_url`) and `/var/lib/headscale` (created by the unit's `StateDirectory`, headscale:headscale
  0750; db/key files 0600). `headscale version` prints `headscale version v0.29.4` plus commit/build lines. systemd comes up
  with only `--privileged` plus tmpfs on `/run`, `/run/lock`, `/tmp`; no cgroup flags needed. A file created by the container
  in a bind-mounted Mac directory appears on the Mac as the Mac user (uid 501, root is mapped); inside the container the
  mount shows as root. OrbStack (virtiofs) shows a Mac directory that was deleted and recreated at the same path unreliably
  (one of two bind mounts missing in the container about every second run), so the lab uses a fresh `mktemp -d` per start.
  (2026-10-02, live `make hostlab-up`; amd64 image not built)
- Host lab bind mount, measured (`TestHostLab_PathTriggerOnBindMount`, OrbStack arm64, virtiofs, 2026-10-02): a file the Mac user
  (uid:gid 501:20) writes into `requests/` is seen in the container as **uid:gid 0:0** with the Mac mode kept (0640 → 640); the mount's
  directories show as `0:0 755`, a file the container creates in `results/` shows `0:0 644` in the container and as 501:20 on the Mac
  (the directory and `results/` values were measured by hand with `stat` in the container; the test logs only the `requests/` file).
  So in the lab the helper's expected request owner is **uid 0** (root; in production it is the tagcess container's uid). A trial `.path`
  unit (`PathExists=` on a not-yet-existing file in the bind-mounted `requests/`) triggered its oneshot service every time, 30–380 ms after
  the Mac wrote the file, both for an in-place write and for the ADR 0021 b temp-file + atomic-rename publish (5 runs of each): inotify
  events do reach the container, so no lab fallback is needed. Note: a `.path` unit reports `ActiveState=active` while waiting; its
  `SubState` is `waiting`. (2026-10-02, live lab)
- `headscale configtest -c <file>` is not a pure check (researcher, v0.29.4 source at commit `8106636c`, read not run, 2026-10-02):
  it calls `NewHeadscale` (`cli/configtest.go:17`, `utils.go:53-68`), which creates or reads the noise private key (`app.go:131`,
  `readOrCreatePrivateKey` makes the dir and file if missing; the DERP key too when `derp.server.enabled`), opens the SQLite DB at
  `database.sqlite.path` (creates the dir, WAL on by default so `-wal`/`-shm` can appear), runs pending migrations and writes
  `database_versions.updated_at` on every run (`db/db.go:867-883`, `versioncheck.go:118-125`). It does not start the listeners or the unix
  socket. It does OIDC discovery when `oidc.issuer` is set (30 s; a failure fails configtest while `only_start_if_oidc_is_available` is true,
  the default; `app.go:182-201`). It reads `oidc.client_secret_path` and, in file mode, `policy.path`. `-c` is a persistent root flag; a
  bad config exits 1 (`cli/root.go:25,49,144-150`); `HEADSCALE_CONFIG` replaces `-c`. So run as root against the live state it can
  create root-owned files; run as the service user it writes with the right owner but into the live DB/key. The open question,
  concurrent SQLite access with the running service (`SQLITE_BUSY`), is resolved by the single lab
  observation below (2026-10-02): none was seen.
- The config type is inferred from the candidate file's **extension** (viper): `headscale configtest -c <file>` on a name viper
  cannot map (e.g. `.config.yaml.tagcess-new`) fails with `Unsupported Config Type "<ext>"`, exit 1. The
  helper's candidate temp file therefore keeps a `.yaml` suffix (`.config.tagcess-new.yaml`). (live lab, 2026-10-02; fixed in)
- Host lab concurrent `configtest` (live lab, 2026-10-02): `configtest` as the `headscale` service user while
  `headscale.service` is running succeeds (no `SQLITE_BUSY` observed); `/var/lib/headscale` stays `750 headscale:headscale`, the file
  list (db.sqlite, `-wal`, `-shm`, noise_private.key) and their owner/mode are unchanged, the service stays `active`.
- Host lab failure injections (OrbStack arm64, live lab, 2026-10-04; `TestHostLab_Failure_*`):
  - configtest error: moving `oidc.client_secret_path` (`/etc/headscale/oidc_client_secret`) aside makes
    `headscale configtest -c /etc/headscale/config.yaml` exit 1 with `configuration error: loading configuration: open
    /etc/headscale/oidc_client_secret: no such file or directory`; the running Headscale is unaffected (no restart). This confirms the
    v0.29.4 source note above: configtest reads the secret file.
  - post-replace health error: a `[Service]\nExecStartPre=/bin/false` drop-in on `headscale.service` makes
    `systemctl restart headscale.service` exit 1; `systemctl is-active` then reports `activating` (not `failed`) because the packaged unit
    has `Restart=always`/`RestartSec=5`, and `/health` is unreachable. The helper's restart step sees the non-zero restart and reports
    `failed`/`restart_failed` with `config_changed=true`, leaving the new config in place (no rollback).
  - `TimeoutStartSec` overrun: a `TimeoutStartSec=20` drop-in on `tagcess-hshelper.service` plus an
    `ExecStartPre=/bin/sleep 30` drop-in on `headscale.service` makes systemd SIGTERM the oneshot mid-restart; `ExecStopPost`
    (finalize) publishes `interrupted` with `phase=restart` and `config_changed=null` (unknown).
- Host lab Headscale policy (live lab, 2026-10-04): the v0.29.4 database-mode server starts with **no policy row**; `GetPolicy`
  then fails with `rpc error: ... loading ACL from database: acl policy not found`. tagcess's H-07 apply reads the live policy through
  `policywriter.Live` while the maintenance is off, so against a fresh lab it is refused with `ErrUnknownOutcome`
  ("Headscale unreadable"). The lab must seed a policy (`SetPolicy`, a fixture policy) before tagcess starts. Clearing the
  maintenance after a failure does not remove the config; a recovery patch applies the new list and the hand-over reconcile closes the flag.
- Real OIDC `groups` consumption, verified (host lab + lab Zitadel v4.16.0, browser-less logins, 2026-10-04):
  with `oidc.allowed_groups: ["devops"]` a fresh devops login (`lab-devops@tagcess.test`) completes and Headscale creates the node; a
  developer-only login (`lab-developer@tagcess.test`) is refused at `/oidc/callback` with HTTP **401** and **no node** is created. After the
  interface applies `["devops","developer"]`, developer is accepted and the standart-only account is refused with 401 / no node. So a real
  login consumes the `preuserinfo` `groups` claim (source note above upgraded from "not verified"). The accepted node's Headscale `user`
  name is the Zitadel login username (`lab-devops@tagcess.test`). (2026-10-04, live lab)
- Lab `allowed_groups` AND `allowed_domains` (2026-10-04): the host lab config carries `oidc.allowed_domains: ["tagcess.test"]`;
  every lab account (e-mail domain `tagcess.test`) passes the domain check together with its `groups`, so the AND branch of
  `doOIDCAuthorization` is exercised. `allowed_users` is left empty (the production inventory was pending).
- Headscale OIDC registration has an interactive confirm step (browser-less login, 2026-10-04): `/oidc/callback` answers 302 to
  `/register/confirm/<nodekey>`; that GET needs the state cookie set when `/register/<nodekey>` was opened (without it `/oidc/callback` is
  400 `state not found error="http: named cookie not present"`), and the node is created only after **POSTing** the confirm form
  (hidden input `headscale_register_confirm`) with that cookie. A browser-less client must follow the register → authorize → login chain,
  finish the Zitadel session, then POST the confirm form.
- Zitadel `authorizationRequired` (lab, 2026-10-04): a user without a `vpn` grant (`lab-norole@tagcess.test`) is refused by Zitadel
  itself at OIDC v2 `CreateCallback` with `PermissionDenied ... Errors.User.GrantRequired (OIDC-...)`; Headscale never sees the login, so no
  node is created. The `vpn` project keeps `authorizationRequired=true` (not changed).

- `headscale policy check -f <file>` talks to the running server over gRPC (0.29.4); with Headscale stopped it fails
  (`connecting to /var/run/headscale/headscale.sock: context deadline exceeded`). Offline check:
  `runuser -u headscale -- headscale -c <config> policy check -f <file> --bypass-grpc-and-access-database-directly --force`
  (as the headscale user, so the database gets no root-owned `-wal`/`-shm`). (2026-10-07, local 0.29.4 test target)
- `headscale configtest` loads the policy file too (`init state: loading policy: open ...: no such file`) and creates the
  database and the noise/DERP keys when missing; an invalid prefix fails it (`netip.ParsePrefix("300.64.0.0/10")`). The config
  file needs a `.yaml` extension (viper picks the format by extension). (2026-10-07, local 0.29.4)
- In file mode the policy Headscale serves (`headscale policy get`) has its comments blanked: compare by meaning (parsed
  HuJSON), not bytes. (2026-10-07, local 0.29.4)
- The 0.29.4 `.deb` ships `/etc/headscale/config.yaml`, enables `headscale.service` without starting it, leaves
  `/var/lib/headscale` root-owned until the first start (`StateDirectory=headscale`); commands run as the headscale user
  before that need the directory chowned. `preauthkeys create -o json` returns `key` (`hskey-auth-...`); `preauthkeys list`
  shows it masked (`hskey-auth-<prefix>-***`), omits `reusable`/`used` when false. (2026-10-07, local 0.29.4)

## Caddy
- Default path `/etc/caddy/Caddyfile`. Certificates are commonly issued by certbot under `/etc/letsencrypt/live/<name>/`;
  Caddy DNS-01 is the alternative.
- Admin API `POST /load` accepts `Content-Type: text/caddyfile`. The new config is fully provisioned in an isolated
  context first; if that fails, the running config is untouched and the call returns 400. `POST /adapt` only
  converts and validates. (2026-09-28, caddy v2.8.4 `caddyconfig/load.go:73-168`, `caddy.go:317-346`)
- `reverse_proxy unix//path/to.sock` is supported. (2026-09-28, caddy v2.8.4 `listeners.go:296-407`)
- systemd runs `caddy run --environ --config /etc/caddy/Caddyfile` without `--resume`: a restart reads the Caddyfile
  on disk, not `autosave.json`. `caddy reload --force` = `POST /load`. So write the file only after a successful
  `/load`. (2026-09-28, local observation + caddy v2.8.4 `caddy.go:342-380`, `cmd/commandfuncs.go:191-213,306-339`)
- `/adapt` only converts. CEL expressions and `path_regexp` compile at provisioning: an invalid CEL or regex passes
  `adapt` and fails `validate` / `/load` (400, running config unchanged). Inside a CEL string, `\d` must be written
  as `\\d`. (2026-09-28, local caddy v2.8.4)
- `handle` blocks: named-matcher blocks sort before matcher-less ones, source order kept among them, so
  `@api` → `@tailnet` → catch-all works. (`caddyconfig/httpcaddyfile/directives.go:451-527`)
- `header X *` and CEL `header({'X': '*'})` match when the header exists, even empty. `remote_ip` uses the TCP peer,
  not `X-Forwarded-For`. (`modules/caddyhttp/matchers.go:963-993`, `ip_matchers.go:145-157`)
- `caddy adapt` output is not byte-deterministic for multi-host blocks (host order from a Go map); sort host lists
  before comparing. (`directives.go:550-579`)
- Admin listen address under a loaded Caddyfile: a Caddyfile without an `admin` global option resets the admin
  listener to `localhost:2019` on `/load`, which locks a published container port out. The `CADDY_ADMIN` env var
  (`0.0.0.0:2019`) survives `/load`, so a throwaway test container retains its published admin port.
  (2026-10-01, local caddy v2.8.4 container)
- With the `tls <cert> <key>` files mounted and matching a host (a `*.<name>` certificate counts), Caddy logs
  "skipping automatic certificate management" and starts no ACME for it; a host with neither a `tls` line nor a
  matching loaded certificate would. A container started with `--dns 127.0.0.1` cannot reach an ACME server at all.
  (2026-10-01, local caddy v2.8.4 container)
- A `/load` whose `tls` files do not exist passes `/adapt` and fails `/load` with
  `loading certificates: open ...: no such file or directory` (400, running config untouched).
  (2026-10-01, local caddy v2.8.4)

- `POST /adapt` resolves a relative `import` against Caddy's working directory (`/` under systemd), not the Caddyfile's
  directory: `import sites/*.caddy` matches nothing there, so the adapted JSON holds only the main file's sites (a split layout adapts without its 20 site files). `caddy validate --config /etc/caddy/Caddyfile` resolves it
  against the file's directory. (2026-10-07, local caddy v2.8.4 adopt test target)
  An unmatched import glob is only a `warn` log line ("No files matching import glob pattern"), never an error; a
  missing non-glob file is an error. tagcess's parity adapter therefore rewrites relative file imports to absolute
  paths under the Caddyfile's directory before `/adapt` (`caddy.AbsImports`, snippet names untouched); with it the real-world fixture adapts with all 23 hosts (`TestAbsImports_RealCaddySeesSiteFiles`). (2026-10-07, caddy:2.8.4)

## oauth2-proxy
- Default config path `/etc/oauth2-proxy/oauth2-proxy.cfg`; it listens on `127.0.0.1:4180` in the usual Caddy `forward_auth` setup.
  - OIDC against Zitadel; `oidc_groups_claim = "groups"`.
  - `upstreams = static://202`, `set_xauthrequest = true`.
  - `whitelist_domains` must cover every site domain.

## Zitadel
- Project `vpn`, roles `devops`, `developer`, `standart`. An Action writes the roles into the `groups` claim.
  (2026-09-28, developer)
- The `vpn` project has an oauth2-proxy application with `projectRoleAssertion=true`, `authorizationRequired=true`.
  Its redirect URIs are `https://<host>/oauth2/callback`, one per role-checked site. Without `backend_logout_url` in
  `oauth2-proxy.cfg`, tagcess does not write post-logout URIs (decision). `allowedOrigins` equals the redirect URI origins.
- Actions v2 execution events:
  - Grants: `user.grant.added`, `.changed`, `.removed`, `.deactivated`, `.reactivated`, `.cascade.changed`,
    `.cascade.removed`
  - Users: `user.deactivated`, `user.locked`, `user.removed`, `user.reactivated`
  - Payload fields: `aggregateID`, `aggregateType`, `resourceOwner`, `instanceID`, `sequence`,
    `event_type`, `created_at`, `userID`, `event_payload`
  - The payload is signed with an HMAC signature header.

  (2026-09-28, zitadel source `internal/repository/usergrant/user_grant.go` and docs `actions/usage.mdx`.)
- The signature header is `ZITADEL-Signature` in code (`Zitadel-Signature` on the wire). The proto comment says
  `X-ZITADEL-Signature`, which is wrong. (2026-09-28, zitadel v4.16.0 `pkg/actions/signing.go:16-45`)
  - Scheme: `HMAC-SHA256(key, "<unix_ts>." + rawBody)`.
  - Header format: `t=<unix_ts>,v1=<hex>`. There can be several `v1=` values, for key rotation.
- Target types (2026-09-28, zitadel v4.16.0 `internal/execution/execution.go:101-118`, `internal/execution/worker.go:38-57`):
  - `rest_webhook`: synchronous; the response is ignored.
  - `rest_call`: synchronous; the response is used.
  - `rest_async`: fire-and-forget.
  - None of them retries automatically. A failed event execution cancels its River job.
  - **So a missed webhook is lost, and the periodic reconcile is required.**
- Execution conditions can only be `event`, `group` or `all`. There is no per-project filter.
  The payloads of `user.grant.changed` and the `cascade.*` events do not contain `projectId`.
  (2026-09-28, zitadel v4.16.0 `proto/zitadel/action/v2/execution.proto:133-164`,
  `internal/repository/usergrant/user_grant.go:84-92`)
- Also verified: `user.unlocked`. The payload also contains `version`. The payload has no event id; use
  `aggregateID` + `sequence` as the replay key. (2026-09-28, zitadel v4.16.0 `internal/repository/execution/queue.go`)
- The `sub` claim is the Zitadel user ID. (2026-09-28, zitadel v4.16.0 `internal/api/oidc/auth_request_converter.go:90-92`)
- Permissions: `PROJECT_OWNER`, scoped to one project through a project member entry, covers `user.read`,
  `user.global.read`, `user.grant.read/write/delete` and `project.app.read/write/delete`. `PROJECT_OWNER_VIEWER`
  lacks `project.app.write`. (2026-09-28, zitadel v4.16.0 `cmd/defaults.yaml:1997-2037`)
  Not verified live: whether the list APIs are auto-limited to the project. Always filter by `project_id`.
- v2 list endpoints **silently filter** records the caller may not see: `totalResult` counts all, the list holds
  only the visible ones (unauthorized `ListAuthorizations`: 1 of 12). "Complete read" must check
  collected == `totalResult`. `project.v2.ListProjectRoles` returned an empty list with `totalResult: 3` even with
  `PROJECT_OWNER_GLOBAL`; v1 `management/v1/projects/{id}/roles/_search` returned the roles.
- App OIDC config: only full-list replacement of redirect URIs; no optimistic concurrency (last writer wins).
  v2 `UpdateApplication` resets fields missing from the request: empty `responseTypes`/`grantTypes` → defaults,
  missing `clockSkew` → 0, missing `loginVersion` → `UNSPECIFIED` (today `loginV1`, so it really changes). Always
  send the read values of these four. Other optional fields stay. Redirect URI compliance problems are
  informational only. (2026-09-28, zitadel v4.16.0 `internal/command/project_application_oidc.go:277-355`,
  `internal/api/grpc/application/v2/convert/oidc_app.go`)
- APIs, all stable v2: `AuthorizationService.ListAuthorizations` (filter `project_id` / `role_key`),
  `UserService.ListUsers` / `GetUserByID`, and `ApplicationService.UpdateApplication` with
  `oidc_configuration{redirect_uris, post_logout_redirect_uris}` (tagcess writes only `redirect_uris`). The v1 `ManagementService.UpdateOIDCAppConfig`
  also exists. (2026-09-28, zitadel v4.16.0 protos)
- Headscale OIDC users have a `provider_id` of the form `https://auth.example.com/<zitadel-id>`.
  - The provider id has no `@`, while the docs say a policy user identifier must contain exactly one `@`.
    Verified on the compose Headscale (2026-09-29): write `<provider_id>@` (append `@`); see the Headscale section.
- Helm chart `zitadel/zitadel` 10.0.6 is app v4.15.3 (also the Login v2 image default); set `image.tag` and
  `login.image.tag` to pin v4.16.0. It writes the machine user's PAT to Secret `<machine username>-pat` (`tagcess-seed-pat`
  for username `tagcess-seed`). DB passwords can come from `envVarsSecret` (ZITADEL_DATABASE_POSTGRES_{USER,ADMIN}_PASSWORD).
  The chart's Service already carries `traefik.ingress.kubernetes.io/service.serversscheme: h2c`, so gRPC works through
  Traefik with TLS ending there. (2026-09-29, `helm template` of chart 10.0.6 and a live install in the lab)
- Lab: `tagcess-zitadel.lab.example.com:443` speaks gRPC over TLS through Traefik; `zitadel-go` needs
  `zitadel.WithPort(443)` there instead of `WithInsecure`. The lab ingress is a plain Ingress with TLS, no access restriction. Headscale v0.29.4 in Docker (OrbStack, host network) reaches the lab issuer and starts with
  `only_start_if_oidc_is_available: true`. (2026-09-29, live)
- **Actions v2 target HTTP client denies CGNAT/private ranges by default.** Zitadel v4.16.0
  `HTTPClient.DenyList` (system default, `cmd/defaults.yaml`) includes `100.64.0.0/10` (Tailscale),
  all RFC1918, `127.0.0.0/8`, `169.254.0.0/16`, `::1/128`, `fc00::/7`, `fe80::/10`. A `CreateTarget`
  whose endpoint resolves into it fails with `Errors.Target.DeniedURL` (COMMAND). To let the lab
  Zitadel (or production, ADR 0003) call a Tailscale webhook, the `HTTPClient.DenyList` system default
  must be overridden to drop `100.64.0.0/10` (keep the rest). Verified live 2026-09-30
  `CreateTarget` denied before the override, delivered after.
- **Actions v2 target facts (v4.16.0, live 2026-09-30):** `CreateTarget` requires a `timeout`
  (max 270s). The signing key is returned only in `CreateTargetResponse.SigningKey` (36 chars, shown
  once) and is HMAC-SHA256 over `"<unix_ts>.<rawBody>"`; the wire header is `Zitadel-Signature` with
  `t=<unix_ts>,v1=<hex>` (the proto comment's `X-ZITADEL-Signature` is wrong). Target type `rest_async`
  delivers a POST to the endpoint and ignores the response. An execution condition
  `EventExecution_Event{Event: "user.grant.added"}` fires on that event; `SetExecution` is an upsert
  keyed by condition. Grant events (`user.grant.added/changed/removed/deactivated/reactivated/
  cascade.changed/cascade.removed`) and user events (`user.deactivated/locked/removed/reactivated`) are
  the execution events tagcess subscribes to.
- **v1 Actions are not usable in the pinned lab v4.16 in practice:** `ManagementService.ListFlowTriggerTypes`
  returned `NotFound` in a lab call. Source review (2026-09-30, zitadel v4.16.0
  `internal/api/grpc/management/flow.go:26-34`, `internal/domain/flow.go:52-78`) shows v1 flow triggers are
  still present in v4.16.0 (deprecated, sunset planned for V5); the NotFound likely came from an
  unrecognized flow `type` string (CustomiseToken is `"2"`). Either way a custom `groups` claim should use
  the v2 `rest_call` path, not a v1 JS action. The v2 `ListExecutionFunctions` are `preuserinfo`,
  `preaccesstoken`, `presamlresponse`. (2026-09-30, live lab + zitadel v4.16.0 source)
- **Actions v2 function execution payload (`preuserinfo`/`preaccesstoken`, v4.16.0 source, 2026-09-30):**
  a `rest_call` target receives `oidc.ContextInfo` as JSON, not the event payload. Top-level fields:
  `function` (`"function/preuserinfo"`), `userinfo` (OIDC UserInfo), `user`, `user_metadata`, `org`,
  `user_grants`, `application`, `response`. There is **no** top-level `projectID`/`userID`/`roles`/`grants`.
  Project grants are in `user_grants[]` (`project_id`, `project_name`, `roles[]`); the user id is
  `user.id` / `userinfo.sub`. `user_grants` is filled only for projects in `roleAudience` with `state=1`;
  the `vpn` app has `project_role_assertion=true`, so its grant is expected (not yet verified live).
  `preuserinfo` (ID token/userinfo/introspect) and `preaccesstoken` (JWT access token) share the same
  `user_grants`; they differ only in the trigger. `rest_webhook`/`rest_async` ignore the response; only
  `rest_call` applies it. (`internal/api/oidc/userinfo.go:474-515`, `internal/query/userinfo_by_id.sql:35-45`,
  `internal/execution/execution.go:101-118,234-249`, `proto/zitadel/action/v2/execution.proto:128-131`)
- **Actions v2 `rest_call` response contract (v4.16.0):** return
  `{"append_claims":[{"key":"groups","value":["devops"]}]}`, **not** `{"groups":[...]}`. Keys are copied to
  the token verbatim; `urn:zitadel:iam`-prefixed keys are skipped and a key that already exists is not
  overwritten. Also supported: `set_user_metadata[]` and `append_log_claims[]`. A non-2xx or invalid-JSON
  response applies nothing. (`internal/api/oidc/userinfo.go:456-515`; docs
  `apps/docs/content/guides/integrate/actions/usage.mdx:145-165`)
- **Actions v2 function requests are HMAC-signed like the event webhook (v4.16.0):**
  `Zitadel-Signature: t=<unix_ts>,v1=<hex>`, `HMAC-SHA256(key, "<unix_ts>."+rawBody)`, using the target's
  key returned once by `CreateTarget` (the same field for `rest_call` and `rest_webhook`).
  (`internal/execution/execution.go:234-249`, `pkg/actions/signing.go:21-45`)

- **Persistent PROJECT_OWNER can write app URIs (lab-verified).** The seeded `tagcess` service
  user — project member with `PROJECT_OWNER` (+ org `ORG_OWNER_VIEWER`) — can `ListApplications`,
  `GetApplication` and `UpdateApplication` (redirect URI replacement, with the read
  `response_types`/`grant_types`/`clock_skew`/`login_version` sent back) on the lab v4.16.0. An earlier test had only proven this with a temporary `PROJECT_OWNER_GLOBAL`. (2026-10-01, live
  lab)
- **Missing-entitlement denial shape:** a call the identity holds no membership for answers either
  gRPC `PermissionDenied` or `NotFound` with Zitadel's authz code in the message, e.g.
  `membership not found (AUTHZ-cdgFk)`; an ordinary missing object (unknown app) carries a
  different subsystem's code. tagcess maps both denial shapes to one typed error and leaves plain
  `NotFound` alone. (2026-10-01, live lab)
- `UpdateApplicationResponse` returns only the change date (no application body); proving a URI
  write needs a fresh `GetApplication`. (2026-09-28, zitadel-go v3.30.0 protos)
- `PROJECT_OWNER_VIEWER` (project member role): every read keeps working (app, roles) and `UpdateApplication` is
  denied with the same `PermissionDenied`/`NotFound: membership not found` shapes as an unauthorised identity.
  `InternalPermissionService.UpdateAdministrator` switches a member's roles in place and takes effect within a few
  seconds; the e2e probes with a write of the already-live list. Zitadel checks permission before it checks for
  changes, so an allowed no-op write answers `FailedPrecondition: No changes (COMMAND-1m88i)` while a denied one
  answers the permission error. (2026-10-01, live lab v4.16.0)

## Kubernetes host networking
- Pod-to-tailnet traffic leaves the node with the node's tailnet address as source, so the policy needs an explicit rule
  (tag to tag) for the webhook port; ICMP and TCP are denied without one while `tailscale ping` still works.

## Headplane
- Headplane 0.7.1 in Docker. It mounts `/etc/headplane/config.yaml` (ro) and `/var/lib/headplane`.
  All integrations (docker, kubernetes, proc, agent) are disabled.
- In file mode its ACL page is read-only. It has no IdP group sync. (2026-09-28, headplane source)
- With only project-level `PROJECT_OWNER`, `UserService.ListUsers` returns just the caller; other users are silently
  hidden and `totalResult` does not count them (`GetUserByID`: PermissionDenied). Adding org-level `ORG_OWNER_VIEWER`
  makes `ListUsers` return all users with the right `totalResult`. Removed users are simply absent from `ListUsers`.
  (2026-09-29, lab Zitadel v4.16.0)
