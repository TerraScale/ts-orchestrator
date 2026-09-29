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

.PHONY: verify format-check python-test test vet race-test build build-linux release-linux run host check clean

verify: format-check python-test vet race-test

format-check:
	@unformatted="$$(find . -type f -name '*.go' -not -path './.git/*' -not -path './third_party/*' -print0 | xargs -0 $(GOFMT) -l)"; \
	if [ -n "$$unformatted" ]; then \
		printf 'Go files need gofmt:\n%s\n' "$$unformatted" >&2; \
		exit 1; \
	fi

PYTHON_SUITES := tests/deploy deploy/oci-region tests/ci tests/runtime_priority \
	tests/firecracker:test_qualify.py tests/firecracker/memberstatus:test_qualify.py \
	tests/firecracker/managedmember:test_qualify.py

python-test:
	python3 scripts/ci/run-python-tests.py $(PYTHON_SUITES)

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

race-test:
	$(GO) test -race ./...

build:
	mkdir -p dist
	CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o dist/terrascale-orchestrator $(APP)

build-linux: release-linux

release-linux:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o dist/terrascale-orchestrator-linux-amd64 $(APP)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o dist/terrascale-orchestrator-linux-arm64 $(APP)

run:
	$(GO) run $(APP) run --config $(CONFIG)

host:
	$(GO) run $(APP) host --config $(CONFIG)

check:
	$(GO) run $(APP) check --config $(CONFIG)

clean:
	rm -rf dist
