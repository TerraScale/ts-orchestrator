package vmguest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeRequestAcceptsOnlyBoundedTypedOperations(t *testing.T) {
	tests := []Request{
		{SchemaVersion: SchemaVersion, Operation: OperationProbe},
		{SchemaVersion: SchemaVersion, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"is-system-running"}},
		{SchemaVersion: SchemaVersion, Operation: OperationPut, Path: "terrabase/v1/artifact", Data: []byte("release"), Mode: 0o600},
		{SchemaVersion: SchemaVersion, Operation: OperationDataWrite, Path: "persistence/check", Data: []byte("value")},
		{SchemaVersion: SchemaVersion, Operation: OperationDataRead, Path: "persistence/check"},
	}
	for _, request := range tests {
		data, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeRequest(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("decode %s: %v", request.Operation, err)
		}
		if got.Operation != request.Operation || got.Path != request.Path {
			t.Fatalf("decoded request = %+v", got)
		}
	}
}

func TestDecodeRequestRejectsAmbiguousOrUnsafeInput(t *testing.T) {
	tests := []string{
		``,
		`{"schemaVersion":1,"operation":"probe","unknown":true}`,
		`{"schemaVersion":1,"operation":"probe"}{}`,
		`{"schemaVersion":2,"operation":"probe"}`,
		`{"schemaVersion":1,"operation":"execute","path":"/bin/sh","args":["-c","id"]}`,
		`{"schemaVersion":1,"operation":"put","path":"../escape","data":"YQ==","mode":384}`,
		`{"schemaVersion":1,"operation":"data-read","path":"/absolute"}`,
	}
	for _, input := range tests {
		if _, err := DecodeRequest(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted unsafe request %q", input)
		}
	}
}

func TestDiagnosticAdmissionHasNoMutationCommands(t *testing.T) {
	accepted := []Request{
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/readlink", Args: []string{"/proc/1/exe"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/stat", Args: []string{"-fc", "%T", "/sys/fs/cgroup"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/findmnt", Args: []string{"-n", "-o", "SOURCE,FSTYPE,TARGET", "/var/lib/terrascale"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"is-active", "ts-node.service"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"show", "terrabase.service", "--property=MainPID,ActiveState,SubState"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/sha256sum", Args: []string{"/opt/terrascale/terrabase/v1/terrabase"}},
	}
	for _, request := range accepted {
		if err := request.Validate(); err != nil {
			t.Fatalf("rejected admitted diagnostic %+v: %v", request, err)
		}
	}
	rejected := []Request{
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"restart", "ts-node.service"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"is-active", "ssh.service"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/sha256sum", Args: []string{"/etc/shadow"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/sha256sum", Args: []string{"/opt/terrascale/../etc/shadow"}},
	}
	for _, request := range rejected {
		if err := request.Validate(); err == nil {
			t.Fatalf("accepted mutating or unsafe diagnostic %+v", request)
		}
	}
}

func TestRelativePathValidation(t *testing.T) {
	for _, value := range []string{"file", "component/v1/artifact", "data/check.json"} {
		if !validRelativePath(value) {
			t.Fatalf("rejected safe path %q", value)
		}
	}
	for _, value := range []string{"", ".", "..", "../file", "a/../../file", "/absolute", "a//b", "a/b/c/d/e", "bad name"} {
		if validRelativePath(value) {
			t.Fatalf("accepted unsafe path %q", value)
		}
	}
}
