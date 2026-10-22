MISE ?= mise
MISE_PRESENT := $(shell command -v $(MISE) >/dev/null 2>&1 && printf yes)
ifeq ($(MISE_PRESENT),yes)
GO ?= $(MISE) exec -- go
GOFMT ?= $(MISE) exec -- gofmt
else
GO ?= go
GOFMT ?= gofmt
endif
CONFIG ?= config.json
APP := ./cmd/terrascale-orchestrator
BUILD_FLAGS := -trimpath -buildvcs=true -ldflags="-s -w"
# Test tier (CONTRIBUTING.md): pr runs the fast tier with -short; full also
# runs the integration tier and checks the fixturetest build.
TS_TEST_TIER ?= full
export TS_TEST_TIER

.PHONY: verify ci-check ci-lint ci-verify retired-host-check format-check generate generate-check test test-fast vet fixturetest-check race-test nats-identity-check terrabase-walkthrough-process terrabase-release-process netbird-backup-check netbird-podman-test shellcheck build build-linux release-linux release-check image run host check clean

verify: format-check generate-check vet race-test nats-identity-check netbird-backup-check

# Every revision runs checks; CI separately builds a changed release candidate.
ci-verify: ci-check release-check

CI_LINT = format-check generate-check vet shellcheck nats-identity-check netbird-backup-check retired-host-check \
	$(if $(filter pr,$(TS_TEST_TIER)),,fixturetest-check)

ci-check:
	$(MAKE) --jobs --keep-going --output-sync=none $(CI_LINT) race-test

# Every check except the race suite, which CI splits across machines.
ci-lint:
	$(MAKE) --jobs --keep-going --output-sync=none $(CI_LINT)

format-check:
	@unformatted="$$(find . -type f -name '*.go' -not -path './.git/*' -not -path './third_party/*' -not -path './docs/*' -print0 | xargs -0 $(GOFMT) -l)"; \
	if [ -n "$$unformatted" ]; then \
		printf 'Go files need gofmt:\n%s\n' "$$unformatted" >&2; \
		exit 1; \
	fi

# Regenerate the committed templ Go files with the generator pinned by the
# go.mod tool directive, so a plain go build never needs the templ tool.
# Formats exactly the sources generate-check discovers (no third_party).
TEMPL_SOURCES = $(shell find . -type f -name '*.templ' -not -path './.git/*' -not -path './third_party/*' -not -path './docs/*')

generate:
	$(if $(TEMPL_SOURCES),$(GO) tool templ fmt $(TEMPL_SOURCES))
	$(GO) tool templ generate

# Fail when a committed *_templ.go file differs from its .templ source or a
# source is not templ-formatted. It generates into a scratch copy, so it is
# safe beside the other ci-verify jobs.
generate-check:
	GO="$(GO)" bash scripts/ci/check-templ.sh

test:
	$(GO) test ./...

# The fast tier without the race detector, for local iteration.
test-fast:
	$(GO) test -short ./...

vet:
	$(GO) vet ./...

# The fixturetest tag swaps in fixture observers that no default build
# compiles; vet and test them so they cannot rot.
fixturetest-check:
	$(GO) vet -tags fixturetest ./...
	$(GO) test -tags fixturetest ./tests/firecracker/production/fixturegen

race-test:
	GO="$(GO)" bash scripts/ci/racetest/race-test.sh

# This regression lives in the separate vendored NATS module.
nats-identity-check:
	$(GO) -C third_party/nats-server test -race ./server -run '^TestTerraScaleSystemAdvertisesActualRaftIdentity$$'

# Walk through two local tb-server members built from the paired TerraBase
# revision, in a finite memory cgroup as tb-server requires:
# make terrabase-walkthrough-process TERRABASE_SERVER=<tb-server>
terrabase-walkthrough-process:
	@test -n "$(TERRABASE_SERVER)" || { echo 'usage: make terrabase-walkthrough-process TERRABASE_SERVER=<tb-server>' >&2; exit 2; }
	systemd-run --user --scope --quiet -p MemoryMax=10G env TS_TERRABASE_SERVER="$(abspath $(TERRABASE_SERVER))" \
		$(GO) test ./internal/app -run '^TestTerraBaseWalkthroughAgainstRealMembers$$' -count=1 -v

# Deploy, upgrade and roll back the real C# TerraBase release binary, check
# its peer mesh and bootstrap ts-auth's tenant on it; its .sha256 release
# asset must sit beside it:
# make terrabase-release-process TERRABASE_BINARY=<terrabase-linux-amd64>
terrabase-release-process:
	@test -n "$(TERRABASE_BINARY)" || { echo 'usage: make terrabase-release-process TERRABASE_BINARY=<terrabase-linux-amd64>' >&2; exit 2; }
	TS_TERRABASE_BINARY="$(abspath $(TERRABASE_BINARY))" $(GO) test ./internal/terrabase ./internal/app ./internal/tsauth \
		-run '^(TestTerraBaseBinaryPeerMesh|TestTerraBaseReleaseDeployUpgradeRollback|TestBootstrapAgainstTerraBaseRelease)$$' -count=1 -v

# Lint the tracked shell scripts (needs shellcheck >= 0.11 on PATH; the
# ts-builder image ships it).
shellcheck:
	git ls-files -z -- 'scripts/*.sh' 'deploy/*.sh' scripts/check-dashboard-netbird deploy/netbird/manager/netbird-firewall | xargs -0 shellcheck -S warning

# No tracked file may mention the retired Fly.io hosting.
retired-host-check:
	bash scripts/ci/retired-host-check.sh

# The ts-ops NetBird store backup script carries its own self-check.
netbird-backup-check:
	python3 deploy/netbird/manager/netbird-backup --self-check

# Sync and prune a disposable NetBird 0.80 manager and real client peers in
# rootless Podman (pulls the netbird-server and netbird images). Nested Podman
# in a CI job container also needs TS_NESTED_PODMAN=1.
netbird-podman-test:
	TS_NETBIRD_PODMAN=1 $(GO) test ./internal/netbird/manager -run '^TestPodmanManagerSyncAndPrune$$' -count=1 -v -timeout 15m

build:
	mkdir -p dist
	CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o dist/ts-orch $(APP)

build-linux: release-linux

release-linux: dist/terrascale-orchestrator-linux-amd64 dist/terrascale-orchestrator-linux-arm64

# Phony build targets always embed this checkout's VCS metadata. CI's make
# jobserver builds both architectures together instead of serially.
.PHONY: dist/terrascale-orchestrator-linux-amd64 dist/terrascale-orchestrator-linux-arm64
dist/terrascale-orchestrator-linux-amd64:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o dist/terrascale-orchestrator-linux-amd64 $(APP)

dist/terrascale-orchestrator-linux-arm64:
	mkdir -p dist
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o dist/terrascale-orchestrator-linux-arm64 $(APP)

release-check: release-linux
	GO="$(GO)" bash scripts/ci/check-release-binaries.sh

# Build the host image for a CI-qualified main revision on this machine:
# make image SOURCE=<full sha> [IMAGE_OUT=<directory>]
image:
	@test -n "$(SOURCE)" || { echo 'usage: make image SOURCE=<full sha> [IMAGE_OUT=<directory>]' >&2; exit 2; }
	bash scripts/ci/build-image-local.sh $(SOURCE) $(IMAGE_OUT)

run:
	$(GO) run $(APP) run --config $(CONFIG)

host:
	$(GO) run $(APP) host --config $(CONFIG)

check:
	$(GO) run $(APP) check --config $(CONFIG)

clean:
	rm -rf dist
