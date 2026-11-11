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
# Keep the symbol table so govulncheck can inspect the actual release bytes.
BUILD_FLAGS := -trimpath -buildvcs=true -ldflags="-w"
CHANGE_BASE ?= $(shell git merge-base origin/main HEAD)
LINT_CHECKS := format-check generate-check vet shellcheck netbird-backup-check retired-host-check zero-config-check observability-check

.PHONY: lint retired-host-check zero-config-check format-check generate generate-check vet netbird-backup-check shellcheck observability-check build build-linux release-linux release-check image run host check clean

lint:
	$(MAKE) --jobs --keep-going $(LINT_CHECKS)

zero-config-check:
	python3 scripts/ci/zero-config-check.py "$(CHANGE_BASE)" HEAD

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

generate-check:
	GO="$(GO)" bash scripts/ci/check-templ.sh

vet:
	CGO_ENABLED=0 GOFLAGS=-trimpath $(GO) vet ./... # zero-config: Go toolchain variable; vets the CGO-free release build

# Lint the tracked shell scripts (needs shellcheck >= 0.11 on PATH; the
# ts-builder image ships it).
shellcheck:
	git ls-files -z -- 'scripts/*.sh' 'deploy/*.sh' scripts/check-dashboard-netbird deploy/netbird/manager/netbird-firewall | xargs -0 shellcheck -S warning

# No tracked file may mention the retired hosting provider (see the script).
retired-host-check:
	bash scripts/ci/retired-host-check.sh

# The ts-ops NetBird store backup script carries its own self-check.
netbird-backup-check:
	python3 deploy/netbird/manager/netbird-backup --self-check

observability-check:
	bash deploy/observability/production/install.sh --check

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
