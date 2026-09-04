.PHONY: check vm-doctor vm-image vm-smoke vm-stack vm-test vm-clean

# I-12 is intentionally an explicit build-tagged command. The tag binds the
# coordinator to the official Firecracker Go SDK; no normal production build
# can accidentally import or launch a local VMM.
VM_QUALIFY ?= go run -tags sandboxvm ./cmd/vm-qualify
# Keep every generated VM artifact below the checkout. This is absolute even
# when make is invoked from a subdirectory and remains overrideable for CI.
VM_ROOT ?= $(if $(TS_VM_ROOT),$(TS_VM_ROOT),$(CURDIR)/tmp/vmqual)
VM_PINS ?= $(CURDIR)/src/orchestrator/vmimage/pins-$(shell go env GOARCH).json
VM_IMAGE_MANIFEST ?= $(CURDIR)/src/orchestrator/vmimage/ubuntu-24.04.3-$(shell go env GOARCH).json
VM_ENV = TS_VM_ROOT="$(abspath $(VM_ROOT))" TS_VM_PINS="$(abspath $(VM_PINS))" TS_VM_IMAGE_MANIFEST="$(abspath $(VM_IMAGE_MANIFEST))"
# The production-composition gates boot the exact locally built static
# binaries. vm-artifacts gives those binaries a qualification-only Ed25519
# trust root, passes the complete signed triplets to vm-qualify, and removes
# only its private per-invocation directory after vm-qualify has stopped.
VM_ARTIFACTS ?= go run ./cmd/vm-artifacts
VM_TERRABASE_REPO ?= $(CURDIR)/../terrabase
VM_TERRABASE_BINARY ?=
VM_ARTIFACT_ARGS = --root "$(abspath $(VM_ROOT))" --repo "$(abspath $(CURDIR))" --terrabase-repo "$(abspath $(VM_TERRABASE_REPO))" $(if $(strip $(VM_TERRABASE_BINARY)),--terrabase-binary "$(abspath $(VM_TERRABASE_BINARY))")
VM_WITH_ARTIFACTS = $(VM_ARTIFACTS) $(VM_ARTIFACT_ARGS) -- $(VM_QUALIFY)

vm-doctor:
	$(VM_ENV) $(VM_QUALIFY) doctor

vm-image:
	$(VM_ENV) $(VM_QUALIFY) image

vm-smoke:
	$(VM_ENV) $(VM_WITH_ARTIFACTS) smoke

vm-stack:
	$(VM_ENV) $(VM_WITH_ARTIFACTS) stack

vm-test:
	$(VM_ENV) $(VM_WITH_ARTIFACTS) test

vm-clean:
	$(VM_ENV) $(VM_QUALIFY) clean

# check is the repository verification set (workspace GOAL.md section 5).
check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go build ./...
	go test -race -count=1 ./...
