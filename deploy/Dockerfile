# tagcess production image (architecture.md §8): non-root, with git for the artifact history.
# Build from the repo root: docker build -f deploy/Dockerfile -t tagcess:latest .

# golang:1.27 matches go.mod (go 1.27.1). modernc.org/sqlite is pure Go, so CGO is off and the binary
# is static; the runtime image needs no libc.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=0.1.0-dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/nesiler/tagcess/internal/version.Version=${VERSION} -X github.com/nesiler/tagcess/internal/version.Commit=${COMMIT}" \
    -o /out/tagcess ./cmd/tagcess

# Alpine runtime: git (artifact commits) and CA certificates. Runs as an unprivileged UID.
FROM alpine:3.22
# The process chgrps ui.sock to ui.socket_group (name `caddy` in the example config) and must reach
# the headscale socket (mode 0770, group `headscale`). Both groups must exist with the host's GIDs;
# the runbook (F1-022) passes them: `docker build --build-arg CADDY_GID=$(getent group caddy | cut -d: -f3) ...`.
ARG CADDY_GID
ARG HEADSCALE_GID
# Append the group lines directly: `addgroup -g` refuses a GID already used by an Alpine system group
# (e.g. ping is 999), while a duplicate GID entry is harmless and keeps the numeric group id exact.
RUN test -n "${CADDY_GID}" && test -n "${HEADSCALE_GID}" \
 && apk add --no-cache ca-certificates git \
 && addgroup -S -g 10001 tagcess \
 && adduser -S -D -H -u 10001 -G tagcess tagcess \
 && printf 'caddy:x:%s:\nheadscale:x:%s:\n' "${CADDY_GID}" "${HEADSCALE_GID}" >> /etc/group \
 && adduser tagcess caddy \
 && adduser tagcess headscale \
 && mkdir -p /var/lib/tagcess /run/tagcess \
 && chown tagcess:tagcess /var/lib/tagcess /run/tagcess \
 && chmod 0750 /var/lib/tagcess /run/tagcess
COPY --from=build /out/tagcess /usr/local/bin/tagcess
USER tagcess
ENTRYPOINT ["/usr/local/bin/tagcess"]
CMD ["-config", "/etc/tagcess/config.yaml"]
