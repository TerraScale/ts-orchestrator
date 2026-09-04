package vmguest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type executorCall struct {
	path string
	args []string
}

type fakeExecutor struct {
	calls  []executorCall
	stdout []byte
	stderr []byte
	err    error
}

func (executor *fakeExecutor) Run(_ context.Context, path string, args []string, stdout, stderr io.Writer) error {
	executor.calls = append(executor.calls, executorCall{path: path, args: append([]string(nil), args...)})
	_, _ = stdout.Write(executor.stdout)
	_, _ = stderr.Write(executor.stderr)
	return executor.err
}

func TestServeForcedExecutesOnlyTheValidatedArgv(t *testing.T) {
	executor := &fakeExecutor{stdout: []byte("running\n")}
	config := testConfig(t, executor)
	response := serveRequest(t, config, Request{SchemaVersion: 1, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"is-system-running"}}, "")
	if response.Error != "" || response.Command == nil || response.Command.ExitCode != 0 || string(response.Command.Stdout) != "running\n" {
		t.Fatalf("response = %+v", response)
	}
	if len(executor.calls) != 1 || executor.calls[0].path != "/usr/bin/systemctl" || strings.Join(executor.calls[0].args, " ") != "is-system-running" {
		t.Fatalf("executor calls = %+v", executor.calls)
	}

	response = serveRequest(t, config, Request{SchemaVersion: 1, Operation: OperationProbe}, "uname -a")
	if !strings.Contains(response.Error, "original command") || len(executor.calls) != 1 {
		t.Fatalf("SSH_ORIGINAL_COMMAND was not rejected: %+v", response)
	}
}

func TestServeForcedReturnsBoundedProbeFacts(t *testing.T) {
	executor := &fakeExecutor{stdout: bytes.Repeat([]byte("x"), MaxOutputBytes+128)}
	response := serveRequest(t, testConfig(t, executor), Request{SchemaVersion: 1, Operation: OperationProbe}, "")
	if response.Error != "" || response.Probe == nil || len(executor.calls) != 7 {
		t.Fatalf("probe response=%+v calls=%d", response, len(executor.calls))
	}
	for _, result := range []CommandResult{response.Probe.Systemd, response.Probe.PID1, response.Probe.CgroupV2, response.Probe.DataMount, response.Probe.Network, response.Probe.Time, response.Probe.SeedDigest} {
		if len(result.Stdout) != MaxOutputBytes || !result.StdoutTruncated {
			t.Fatalf("probe output was not bounded: bytes=%d truncated=%v", len(result.Stdout), result.StdoutTruncated)
		}
	}
}

func TestServeForcedPersistsAndReadsOnlyOwnedFiles(t *testing.T) {
	config := testConfig(t, &fakeExecutor{})
	payload := []byte("survives reboot")
	write := serveRequest(t, config, Request{SchemaVersion: 1, Operation: OperationDataWrite, Path: "proof/value", Data: payload}, "")
	if write.Error != "" {
		t.Fatal(write.Error)
	}
	read := serveRequest(t, config, Request{SchemaVersion: 1, Operation: OperationDataRead, Path: "proof/value"}, "")
	if read.Error != "" || !bytes.Equal(read.Data, payload) {
		t.Fatalf("read response = %+v", read)
	}
	info, err := os.Stat(filepath.Join(config.DataRoot, "proof", "value"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("persistent file mode = %v, %v", info, err)
	}

	artifact := serveRequest(t, config, Request{SchemaVersion: 1, Operation: OperationPut, Path: "terrabase/v1/artifact", Data: []byte("binary"), Mode: 0o644}, "")
	if artifact.Error != "" {
		t.Fatal(artifact.Error)
	}
	info, err = os.Stat(filepath.Join(config.InboxRoot, "terrabase", "v1", "artifact"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("artifact file mode = %v, %v", info, err)
	}
}

func TestStorageRejectsSymlinkEscapeAndOversizeRead(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	if err := os.Symlink(external, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(root, "link/file", []byte("escape"), 0o600); err == nil {
		t.Fatal("write followed a symlink directory")
	}
	if err := os.WriteFile(filepath.Join(root, "large"), bytes.Repeat([]byte("x"), 17), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := boundedRead(root, "large", 16); err == nil {
		t.Fatal("oversized file was read")
	}
	if err := os.Symlink(filepath.Join(root, "large"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := boundedRead(root, "alias", 32); err == nil {
		t.Fatal("read followed a symlink")
	}
}

func TestServeForcedEncodesProtocolErrors(t *testing.T) {
	var output bytes.Buffer
	if err := ServeForced(context.Background(), strings.NewReader(`{"schemaVersion":1,"operation":"execute","path":"/bin/sh"}`), &output, "", testConfig(t, &fakeExecutor{})); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != SchemaVersion || response.Error == "" {
		t.Fatalf("protocol error response = %+v", response)
	}
	if err := ServeForced(context.Background(), strings.NewReader(`{}`), nil, "", Config{}); err == nil {
		t.Fatal("accepted nil response writer")
	}
}

func TestRunCommandRecordsExecutorFailure(t *testing.T) {
	executor := &fakeExecutor{stderr: []byte("failed"), err: errors.New("spawn failed")}
	config := testConfig(t, executor)
	result := runCommand(context.Background(), config, "/usr/bin/systemctl", []string{"is-system-running"})
	if result.ExitCode != -1 || result.Error == "" || string(result.Stderr) != "failed" {
		t.Fatalf("command result = %+v", result)
	}
}

func serveRequest(t *testing.T, config Config, request Request, original string) Response {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := ServeForced(context.Background(), bytes.NewReader(data), &output, original, config); err != nil {
		t.Fatal(err)
	}
	var response Response
	decoder := json.NewDecoder(&output)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	return response
}

func testConfig(t *testing.T, executor Executor) Config {
	t.Helper()
	root := t.TempDir()
	return Config{
		InboxRoot: filepath.Join(root, "inbox"),
		DataRoot:  filepath.Join(root, "data"),
		SeedPath:  filepath.Join(root, "seed.json"),
		Executor:  executor,
	}
}
