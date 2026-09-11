package vmguest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		{SchemaVersion: SchemaVersion, Operation: OperationNetwork, Path: "10.77.0.1:4100", Data: []byte("challenge")},
		{SchemaVersion: SchemaVersion, Operation: OperationStorage, Action: StorageActionObserve},
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
		`null`,
		`[]`,
		`{"schemaVersion":1,"operation":"probe","unknown":true}`,
		`{"SchemaVersion":1,"operation":"probe"}`,
		`{"schemaVersion":1,"operation":"probe","operation":"probe"}`,
		`{"schemaVersion":1,"operation":"probe"}{}`,
		`{"schemaVersion":1,"operation":"probe",}`,
		`{"schemaVersion":2,"operation":"probe"}`,
		`{"schemaVersion":1.0,"operation":"probe"}`,
		`{"schemaVersion":1,"operation":"execute","path":"/bin/sh","args":["-c","id"]}`,
		`{"schemaVersion":1,"operation":"put","path":"../escape","data":"YQ==","mode":384}`,
		`{"schemaVersion":1,"operation":"put","path":"artifact","data":"YQ\n==","mode":384}`,
		`{"schemaVersion":1,"operation":"put","path":"artifact","data":"YR==","mode":384}`,
		`{"schemaVersion":1,"operation":"data-read","path":"/absolute"}`,
	}
	for _, input := range tests {
		if _, err := DecodeRequest(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted unsafe request %q", input)
		}
	}
}

func TestDecodeRequestRejectsNullForEveryField(t *testing.T) {
	tests := []string{
		`{"schemaVersion":null,"operation":"probe"}`,
		`{"schemaVersion":1,"operation":null}`,
		`{"schemaVersion":1,"operation":"probe","path":null}`,
		`{"schemaVersion":1,"operation":"probe","args":null}`,
		`{"schemaVersion":1,"operation":"probe","data":null}`,
		`{"schemaVersion":1,"operation":"probe","mode":null}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic","action":null}`,
		`{"schemaVersion":1,"operation":"execute","path":"/usr/bin/systemctl","args":[null]}`,
	}
	for _, input := range tests {
		if _, err := DecodeRequest(strings.NewReader(input)); !errors.Is(err, errRequestNull) {
			t.Fatalf("null request %q error = %v, want %v", input, err, errRequestNull)
		}
	}
}

func TestDecodeRequestRequiresExactUniqueFieldNames(t *testing.T) {
	caseVariants := []string{
		`{"SchemaVersion":1,"operation":"probe"}`,
		`{"schemaVersion":1,"Operation":"probe"}`,
		`{"schemaVersion":1,"operation":"probe","Path":""}`,
		`{"schemaVersion":1,"operation":"probe","Args":[]}`,
		`{"schemaVersion":1,"operation":"probe","Data":""}`,
		`{"schemaVersion":1,"operation":"probe","Mode":0}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic","Action":"observe"}`,
	}
	for _, input := range caseVariants {
		if _, err := DecodeRequest(strings.NewReader(input)); !errors.Is(err, errRequestUnknown) {
			t.Fatalf("case-variant request %q error = %v, want %v", input, err, errRequestUnknown)
		}
	}

	duplicates := []string{
		`{"schemaVersion":1,"schemaVersion":1,"operation":"probe"}`,
		`{"schemaVersion":1,"operation":"probe","operation":"probe"}`,
		`{"schemaVersion":1,"operation":"probe","path":"","path":""}`,
		`{"schemaVersion":1,"operation":"probe","args":[],"args":[]}`,
		`{"schemaVersion":1,"operation":"probe","data":"","data":""}`,
		`{"schemaVersion":1,"operation":"probe","mode":0,"mode":0}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic","action":"observe","action":"observe"}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic","action":"observe","acti\u006fn":"observe"}`,
		`{"schemaVersion":1,"operation":"probe","oper\u0061tion":"probe"}`,
	}
	for _, input := range duplicates {
		if _, err := DecodeRequest(strings.NewReader(input)); !errors.Is(err, errRequestFields) {
			t.Fatalf("duplicate request %q error = %v, want %v", input, err, errRequestFields)
		}
	}
}

func TestDecodeRequestHandlesStrictJSONStringEncoding(t *testing.T) {
	request, err := DecodeRequest(strings.NewReader(`{"schemaVersi\u006fn":1,"\u006fperation":"put","path":"artifact","data":"YQ\u003d\u003d","mode":384}`))
	if err != nil {
		t.Fatalf("decode escaped request: %v", err)
	}
	if !bytes.Equal(request.Data, []byte("a")) {
		t.Fatalf("decoded data = %q", request.Data)
	}

	invalidSurrogate := `{"schemaVersion":1,"operation":"pr\ud800obe"}`
	if _, err := DecodeRequest(strings.NewReader(invalidSurrogate)); err == nil {
		t.Fatal("accepted an unpaired UTF-16 surrogate")
	}
	invalidUTF8 := append([]byte(`{"schemaVersion":1,"operation":"pro`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`be"}`)...)
	if _, err := DecodeRequest(bytes.NewReader(invalidUTF8)); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
}

func TestDecodeRequestCapsScalarsAndListsBeforeReadingTheirTails(t *testing.T) {
	tests := map[string]string{
		"field name": `{"` + strings.Repeat("x", maxFieldNameBytes+1),
		"operation":  `{"schemaVersion":1,"operation":"` + strings.Repeat("x", maxOperationBytes+1),
		"path":       `{"schemaVersion":1,"operation":"data-read","path":"` + strings.Repeat("x", maxPathBytes+1),
		"argument":   `{"schemaVersion":1,"operation":"execute","path":"/usr/bin/systemctl","args":["` + strings.Repeat("x", maxArgumentBytes+1),
		"arguments":  `{"schemaVersion":1,"operation":"execute","path":"/usr/bin/findmnt","args":[` + strings.Repeat(`"a",`, maxRequestArgs),
		"integer":    `{"schemaVersion":` + strings.Repeat("1", maxIntegerBytes+1),
		"action":     `{"schemaVersion":1,"operation":"storage-diagnostic","action":"` + strings.Repeat("x", maxActionBytes+1),
	}
	for name, prefix := range tests {
		t.Run(name, func(t *testing.T) {
			reader := &stagedReader{first: []byte(prefix)}
			if _, err := DecodeRequest(reader); err == nil {
				t.Fatal("accepted an over-limit field")
			}
			if reader.readPastFirst {
				t.Fatal("decoder read the rejected field's tail")
			}
		})
	}
}

func TestDecodeRequestRejectsNestedValuesWithoutReadingTheirTails(t *testing.T) {
	tests := map[string]string{
		"operation object": `{"schemaVersion":1,"operation":{"nested":`,
		"path array":       `{"schemaVersion":1,"operation":"data-read","path":[`,
		"nested argument":  `{"schemaVersion":1,"operation":"execute","path":"/usr/bin/systemctl","args":[[`,
		"data object":      `{"schemaVersion":1,"operation":"put","path":"artifact","data":{"nested":`,
		"mode array":       `{"schemaVersion":1,"operation":"put","path":"artifact","data":"YQ==","mode":[`,
		"action object":    `{"schemaVersion":1,"operation":"storage-diagnostic","action":{"nested":`,
		"unknown field":    `{"schemaVersion":1,"operation":"probe","unknown"`,
	}
	for name, prefix := range tests {
		t.Run(name, func(t *testing.T) {
			reader := &stagedReader{first: []byte(prefix)}
			if _, err := DecodeRequest(reader); err == nil {
				t.Fatal("accepted a recursively typed JSON value")
			}
			if reader.readPastFirst {
				t.Fatal("decoder read the rejected nested value's tail")
			}
		})
	}
}

func TestDecodeRequestRejectsExplicitUnrelatedAndMissingFields(t *testing.T) {
	tests := []string{
		`{"schemaVersion":1,"operation":"probe","path":""}`,
		`{"schemaVersion":1,"operation":"probe","args":[]}`,
		`{"schemaVersion":1,"operation":"probe","data":""}`,
		`{"schemaVersion":1,"operation":"probe","mode":0}`,
		`{"schemaVersion":1,"operation":"execute","path":"/usr/bin/systemctl","args":["is-system-running"],"mode":0}`,
		`{"schemaVersion":1,"operation":"put","path":"artifact","data":"YQ=="}`,
		`{"schemaVersion":1,"operation":"data-write","path":"proof","data":"YQ==","mode":0}`,
		`{"schemaVersion":1,"operation":"data-read","path":"proof","args":[]}`,
		`{"schemaVersion":1,"operation":"network-exchange","path":"10.77.0.1:4100","data":"YQ==","mode":0}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic"}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic","action":"observe","path":""}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic","action":"observe","args":[]}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic","action":"observe","data":""}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic","action":"observe","mode":0}`,
	}
	for _, input := range tests {
		if _, err := DecodeRequest(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted non-canonical request %q", input)
		}
	}
}

func TestDecodeRequestAcceptsEveryStorageDiagnosticAction(t *testing.T) {
	actions := []StorageAction{
		StorageActionObserve,
		StorageActionProbeWrite,
		StorageActionFillENOSPC,
		StorageActionClearFill,
		StorageActionFSCKRepair,
		StorageActionFSCKCheck,
		StorageActionGrow,
	}
	for _, action := range actions {
		t.Run(string(action), func(t *testing.T) {
			input := fmt.Sprintf(`{"schemaVersion":1,"operation":"storage-diagnostic","action":%q}`, action)
			request, err := DecodeRequest(strings.NewReader(input))
			if err != nil {
				t.Fatalf("decode storage action: %v", err)
			}
			if request.Operation != OperationStorage || request.Action != action {
				t.Fatalf("decoded request = %+v", request)
			}
		})
	}
}

func TestDecodeRequestRejectsInvalidStorageDiagnosticActions(t *testing.T) {
	tests := []string{
		`{"schemaVersion":1,"operation":"storage-diagnostic","action":""}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic","action":"Observe"}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic","action":"unknown"}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic","action":1}`,
		`{"schemaVersion":1,"operation":"storage-diagnostic","action":[]}`,
	}
	for _, input := range tests {
		if _, err := DecodeRequest(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted invalid storage action %q", input)
		}
	}
}

func TestOtherOperationsRejectProgrammaticStorageAction(t *testing.T) {
	requests := []Request{
		{SchemaVersion: SchemaVersion, Operation: OperationProbe},
		{SchemaVersion: SchemaVersion, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"is-system-running"}},
		{SchemaVersion: SchemaVersion, Operation: OperationPut, Path: "artifact", Data: []byte("value"), Mode: 0o600},
		{SchemaVersion: SchemaVersion, Operation: OperationDataWrite, Path: "proof", Data: []byte("value")},
		{SchemaVersion: SchemaVersion, Operation: OperationDataRead, Path: "proof"},
		{SchemaVersion: SchemaVersion, Operation: OperationNetwork, Path: "10.77.0.1:4100", Data: []byte("value")},
	}
	for _, request := range requests {
		request.Action = StorageActionObserve
		if err := request.Validate(); err == nil {
			t.Fatalf("%s accepted a storage action", request.Operation)
		}
	}
}

func TestNetworkExchangeRequestValidation(t *testing.T) {
	valid := []string{
		"10.0.0.1:1",
		"10.255.255.254:65535",
		"172.16.0.1:4100",
		"172.31.255.254:4100",
		"192.168.1.1:4100",
	}
	for _, endpoint := range valid {
		request := Request{SchemaVersion: SchemaVersion, Operation: OperationNetwork, Path: endpoint, Data: []byte("challenge")}
		if err := request.Validate(); err != nil {
			t.Fatalf("rejected private endpoint %q: %v", endpoint, err)
		}
	}
	invalid := []string{
		"",
		"10.0.0.1",
		"10.0.0.1:0",
		"10.0.0.1:04100",
		"010.0.0.1:4100",
		"0.0.0.0:4100",
		"127.0.0.1:4100",
		"169.254.1.1:4100",
		"224.0.0.1:4100",
		"1.1.1.1:4100",
		"[fd00::1]:4100",
		"controller.internal:4100",
		" 10.0.0.1:4100",
	}
	for _, endpoint := range invalid {
		request := Request{SchemaVersion: SchemaVersion, Operation: OperationNetwork, Path: endpoint, Data: []byte("challenge")}
		if err := request.Validate(); err == nil {
			t.Fatalf("accepted unsafe endpoint %q", endpoint)
		}
	}
	for _, data := range [][]byte{nil, bytes.Repeat([]byte("x"), MaxNetworkBytes+1)} {
		request := Request{SchemaVersion: SchemaVersion, Operation: OperationNetwork, Path: "10.77.0.1:4100", Data: data}
		if err := request.Validate(); err == nil {
			t.Fatalf("accepted network challenge with %d bytes", len(data))
		}
	}
}

func TestDecodeRequestRejectsDecodedDataPastTransferLimit(t *testing.T) {
	encodedLength := base64.StdEncoding.EncodedLen(MaxTransferBytes)
	reader := io.MultiReader(
		strings.NewReader(`{"schemaVersion":1,"operation":"put","path":"artifact","data":"`),
		&repeatedByteReader{value: 'A', remaining: encodedLength},
		strings.NewReader(`","mode":384}`),
	)
	if _, err := DecodeRequest(reader); !errors.Is(err, errRequestFields) {
		t.Fatalf("oversized decoded data error = %v, want %v", err, errRequestFields)
	}
}

func TestDecodeRequestRejectsInputPastWireLimit(t *testing.T) {
	prefix := `{"schemaVersion":1,"operation":"probe"}`
	reader := io.MultiReader(
		strings.NewReader(prefix),
		&repeatedByteReader{value: ' ', remaining: MaxRequestBytes - len(prefix) + 1},
	)
	if _, err := DecodeRequest(reader); !errors.Is(err, errRequestSizeInvalid) {
		t.Fatalf("oversized request error = %v, want %v", err, errRequestSizeInvalid)
	}
}

type stagedReader struct {
	first         []byte
	readPastFirst bool
}

func (reader *stagedReader) Read(target []byte) (int, error) {
	if len(reader.first) != 0 {
		count := copy(target, reader.first)
		reader.first = reader.first[count:]
		return count, nil
	}
	reader.readPastFirst = true
	return 0, errors.New("unexpected read past bounded value")
}

type repeatedByteReader struct {
	value     byte
	remaining int
}

func (reader *repeatedByteReader) Read(target []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	count := min(len(target), reader.remaining)
	for index := range count {
		target[index] = reader.value
	}
	reader.remaining -= count
	return count, nil
}

func TestDiagnosticAdmissionHasNoMutationCommands(t *testing.T) {
	accepted := []Request{
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/readlink", Args: []string{"/proc/1/exe"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/stat", Args: []string{"-fc", "%T", "/sys/fs/cgroup"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/findmnt", Args: []string{"-no", "SOURCE,FSTYPE,TARGET", "/var/lib/terrascale"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"is-active", "terrascale-ts-node.service"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"show", "terrascale-terrabase.service", "--property=MainPID,ActiveState,SubState"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/sha256sum", Args: []string{"/opt/terrascale/terrabase/v1/terrabase"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/test", Args: []string{"-s", "/opt/terrascale/terrabase/current/terrabase.config"}},
	}
	for _, request := range accepted {
		if err := request.Validate(); err != nil {
			t.Fatalf("rejected admitted diagnostic %+v: %v", request, err)
		}
	}
	rejected := []Request{
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/findmnt", Args: []string{"-n", "-o", "SOURCE,FSTYPE,TARGET", "/var/lib/terrascale"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"restart", "terrascale-ts-node.service"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"is-active", "ts-node.service"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"is-active", "ssh.service"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/sha256sum", Args: []string{"/etc/shadow"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/test", Args: []string{"-s", "/etc/shadow"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/test", Args: []string{"-s", "/opt/terrascale/terrabase/current/../../etc/shadow"}},
		{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/test", Args: []string{"-e", "/opt/terrascale/terrabase/current/terrabase.config"}},
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
