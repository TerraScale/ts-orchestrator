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

.PHONY: verify ci-verify format-check test vet race-test build build-linux release-linux release-check image run host check clean

verify: format-check vet race-test

# CI runs the independent checks and the release build at once. The race
# scheduler prints complete shard logs; stream them as each shard finishes.
ci-verify:
	$(MAKE) --jobs --keep-going --output-sync=none format-check vet race-test release-check

format-check:
	@unformatted="$$(find . -type f -name '*.go' -not -path './.git/*' -not -path './third_party/*' -print0 | xargs -0 $(GOFMT) -l)"; \
	if [ -n "$$unformatted" ]; then \
		printf 'Go files need gofmt:\n%s\n' "$$unformatted" >&2; \
		exit 1; \
	fi

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

race-test:
	GO="$(GO)" bash scripts/ci/race-test.sh

build:
	mkdir -p dist
	CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o dist/ts-orch $(APP)
	ln -sf ts-orch dist/terrascale-orchestrator

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
