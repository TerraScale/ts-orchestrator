.PHONY: check vm-doctor vm-image vm-smoke vm-stack vm-test vm-clean

# I-12 is intentionally an explicit build-tagged command. The tag binds the
# coordinator to the official Firecracker Go SDK; no normal production build
# can accidentally import or launch a local VMM.
VM_QUALIFY ?= go run -tags sandboxvm ./cmd/vm-qualify

vm-doctor:
	$(VM_QUALIFY) doctor

vm-image:
	$(VM_QUALIFY) image

vm-smoke:
	$(VM_QUALIFY) smoke

vm-stack:
	$(VM_QUALIFY) stack

vm-test:
	$(VM_QUALIFY) test

vm-clean:
	$(VM_QUALIFY) clean

# check is the repository verification set (workspace GOAL.md section 5).
check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go build ./...
	go test -race -count=1 ./...
