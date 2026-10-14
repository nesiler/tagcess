# tagcess developer and agent gates. The Go steps run only once go.mod exists.
SHELL := /bin/bash
HAS_GO := $(wildcard go.mod)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION_PKG := github.com/nesiler/tagcess/internal/version
LDFLAGS := -s -w -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(COMMIT)

.PHONY: build version agents agents-check guard-test coord-test check-fast check go-fast go-full generate generate-check generate-test image-test lab-up lab-down lab-integration hostlab-up hostlab-down hostlab-ui hostlab-e2e e2e ui ui-down k8s-lab f4-e2e installer-lint installer-test adopt-target-up adopt-target-down

build:         ## Build every cmd binary into bin/ with the version stamped in
	@mkdir -p bin
	@for c in $$(ls cmd); do CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$$c ./cmd/$$c || exit 1; done

version:       ## Print the version stamped into builds
	@echo $(VERSION)


agents:        ## Regenerate .codex/agents and .opencode/agent from .agents/agents
	@scripts/gen-codex-agents.sh
	@scripts/gen-opencode-agents.sh

agents-check:  ## Fail if .codex/agents or .opencode/agent is stale
	@tmp=$$(mktemp -d) && scripts/gen-codex-agents.sh "$$tmp/codex" >/dev/null && \
	  scripts/gen-opencode-agents.sh "$$tmp/opencode" >/dev/null && \
	  diff -r "$$tmp/codex" .codex/agents >/dev/null && diff -r "$$tmp/opencode" .opencode/agent >/dev/null || \
	  { echo "agents: generated agent files are stale, run 'make agents'" >&2; exit 1; }; \
	  echo "agents: ok"

guard-test:    ## Regression tests for the prod guard hook
	@scripts/test-guard.sh

coord-test:    ## End-to-end test for scripts/coord (fake agent, private tmux socket)
	@scripts/coord/test.sh

generate:      ## Run the pinned code generators (templ, sqlc)
	go tool templ generate -log-level warn
ifneq ($(wildcard sqlc.yaml),)
	go tool sqlc generate
else
	@echo "sqlc: no sqlc.yaml yet, skipped"
endif

generate-check: ## Fail if generated code is stale
	@scripts/generate-check.sh

generate-test: ## TestGenerate_UpToDate: generate + generate-check on fixtures in a temp copy
	@scripts/test-generate.sh

image-test:    ## Build deploy/Dockerfile and check it runs non-root with git (needs Docker)
	go test -tags=image -count=1 -run TestImage ./deploy/...

lab-up:        ## Zitadel on the developer's k3s lab (tagcess-lab; lab settings: ~/.config/tagcess/lab.env, test/lab/lib.sh) + local Headscale (ADR 0014)
	@test/lab/up.sh

lab-down:      ## Remove the lab namespace, stop local Headscale, delete lab secrets
	@test/lab/down.sh

lab-integration: ## Run the integration tests against the lab Zitadel and the local Headscale
	go test -tags=integration -count=1 ./test/compose/... ./internal/...

hostlab-up:    ## Linux/systemd host lab in a container: Headscale v0.29.4 under systemd, ADR 0021 b layout (needs `make lab-up`)
	@test/hostlab/hostlab.sh up

hostlab-down:  ## Remove the host lab container and its temporary directory (the lab Zitadel is not touched)
	@test/hostlab/hostlab.sh down

hostlab-ui:    ## Run tagcess against the host lab: helper install, shared dirs, gRPC relay (requires `make lab-up`)
	@test/ui/hostlab-up.sh

e2e:           ## End-to-end scenarios (lab Zitadel + local compose + disposable Headscale; requires `make lab-up`; skips the host-lab tests, use `make hostlab-e2e`)
	go test -tags=integration -count=1 -v -skip 'TestHostLab|TestF3b_E2E|TestF4_E2E' ./test/e2e/...

hostlab-e2e:   ## Host-lab scenarios: real tagcess against the containerised systemd lab (ADR 0021 b; requires `make lab-up`, starts the host lab itself)
	go test -tags=integration -count=1 -v -timeout 20m -run 'TestHostLab|TestF3b_E2E' ./test/e2e/...

ui:            ## Run tagcess against the local compose and print the URL/login for the web UI (requires `make lab-up`)
	@test/ui/up.sh

ui-down:       ## Stop the stack `make ui` started
	@test/ui/down.sh

check-fast: go-fast   ## Quick gate (Stop hook): gofmt, vet, go test

check: agents-check guard-test coord-test installer-lint go-full   ## Full gate (before a PR; CI runs the pieces that need no local-only tools)

go-fast:
ifneq ($(HAS_GO),)
	@files=$$(git ls-files --cached --others --exclude-standard '*.go' 2>/dev/null || find . -name '*.go'); \
	  bad=$$([ -z "$$files" ] || gofmt -l $$files </dev/null); \
	  test -z "$$bad" || { echo "$$bad"; echo "gofmt: files above need formatting" >&2; exit 1; }
	go vet ./...
	go test ./...
else
	@echo "go: no go.mod yet, skipped"
endif

go-full: go-fast
ifneq ($(HAS_GO),)
	golangci-lint run ./...
	go test -race ./...
	@scripts/generate-check.sh
	@scripts/test-generate.sh
endif

k8s-lab:       ## Opt-in k3s contract fixture and read-only acceptance: needs TAGCESS_K8S_LAB=1, TAGCESS_K8S_LAB_KUBECONFIG and TAGCESS_K8S_LAB_CONTEXT; a skip fails the target (never a PASS)
	@out="$$(go test -tags=integration -count=1 -v -timeout 30m -run 'TestK8sLabIntegration|TestK8sLab_|TestReadOnlyCredentialRotation|TestK8sSelected|TestK8sLabConflict' ./test/k8s/ 2>&1)"; st=$$?; \
	printf '%s\n' "$$out"; \
	if [ $$st -ne 0 ]; then exit $$st; fi; \
	if printf '%s\n' "$$out" | grep -q -e '--- SKIP'; then echo "k8s-lab: the test was skipped, which is not a PASS (set TAGCESS_K8S_LAB=1, TAGCESS_K8S_LAB_KUBECONFIG and TAGCESS_K8S_LAB_CONTEXT)"; exit 1; fi

f4-e2e:        ## Kubernetes e2e: real tagcess UI + a k3s cluster + local compose stack; needs `make lab-up` and TAGCESS_K8S_LAB=1, TAGCESS_K8S_LAB_KUBECONFIG, TAGCESS_K8S_LAB_CONTEXT; a skip fails the target (never a PASS)
	@test "$$TAGCESS_K8S_LAB" = 1 && test -n "$$TAGCESS_K8S_LAB_KUBECONFIG" && test -n "$$TAGCESS_K8S_LAB_CONTEXT" || { echo "f4-e2e: set TAGCESS_K8S_LAB=1, TAGCESS_K8S_LAB_KUBECONFIG and TAGCESS_K8S_LAB_CONTEXT (the k3s cluster); nothing was run"; exit 1; }
	@out="$$(go test -tags=integration -count=1 -v -timeout 20m -run '^TestF4_E2E_' ./test/e2e 2>&1)"; st=$$?; \
	printf '%s\n' "$$out"; \
	if [ $$st -ne 0 ]; then exit $$st; fi; \
	echo "f4-e2e report: PASS = $$(printf '%s\n' "$$out" | grep -c -e '^--- PASS')  SKIP = $$(printf '%s\n' "$$out" | grep -c -e '--- SKIP')  FAIL = $$(printf '%s\n' "$$out" | grep -c -e '--- FAIL')"; \
	printf '%s\n' "$$out" | grep -e '^--- PASS' -e '--- SKIP' | sed 's/^/f4-e2e report: /'; \
	if printf '%s\n' "$$out" | grep -q -e '--- SKIP'; then echo "f4-e2e: a test was skipped, which is not a PASS"; exit 1; fi

installer-lint: ## Installer: ansible-lint (deploy/ansible) + shellcheck (deploy, test/adopttarget) when installed; a missing tool prints "skipped" (never a PASS)
	@scripts/installer-lint.sh

installer-test: ## Installer role tests against the local systemd targets (installer tag; needs Docker + ansible); a skip fails the target (never a PASS)
	@out="$$(go test -tags=installer -count=1 -v -timeout 120m -p 1 $${INSTALLER_RUN:+-run "$$INSTALLER_RUN"} ./deploy/... ./test/adopttarget/... ./cmd/tagcess/... 2>&1)"; st=$$?; \
	printf '%s\n' "$$out"; \
	echo "installer-test report: PASS = $$(printf '%s\n' "$$out" | grep -c -e '^--- PASS' -e '^    --- PASS')  SKIP = $$(printf '%s\n' "$$out" | grep -c -e '--- SKIP')  FAIL = $$(printf '%s\n' "$$out" | grep -c -e '--- FAIL')"; \
	if [ $$st -ne 0 ]; then exit $$st; fi; \
	if printf '%s\n' "$$out" | grep -q -e '--- SKIP'; then echo "installer-test: a test was skipped, which is not a PASS"; exit 1; fi

adopt-target-up: ## Installer test target: SHAPE=adopt (an existing vpn-host installation) or SHAPE=bare (empty Ubuntu 24.04); prints the env file with the ssh details
	@SHAPE=$(SHAPE) test/adopttarget/adopttarget.sh up

adopt-target-down: ## Remove the Installer test target(s) (SHAPE=adopt|bare, both when empty), their volumes, temp dirs and ssh keys
	@SHAPE=$(SHAPE) test/adopttarget/adopttarget.sh down
