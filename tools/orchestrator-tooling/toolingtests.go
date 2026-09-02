package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type toolingTests struct{}

var ToolingTests = toolingTests{}

type toolingTest struct {
	Name string
	Body func()
}

func (toolingTests) Run(arguments []string) (int, error) {
	if len(arguments) != 0 && !(len(arguments) == 1 && arguments[0] == "--repository-only") {
		return 0, newToolValidationException([]string{"test accepts only --repository-only"})
	}

	var failures []string
	for _, test := range toolingTestSuite() {
		if err := runToolingTestBody(test.Body); err != nil {
			failures = append(failures, fmt.Sprintf("FAIL %s: %s", test.Name, err.Error()))
		} else {
			fmt.Printf("PASS %s\n", test.Name)
		}
	}

	if len(failures) != 0 {
		return 0, newToolValidationException(failures)
	}
	fmt.Printf("Passed %d Go tooling tests.\n", len(toolingTestSuite()))
	return 0, nil
}

func runToolingTestBody(body func()) (failure error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if err, ok := recovered.(error); ok {
				failure = err
				return
			}
			failure = fmt.Errorf("%v", recovered)
		}
	}()
	body()
	return nil
}

func toolingTestSuite() []toolingTest {
	return []toolingTest{
		{"git bytes preserve non UTF-8 blob", gitBytesPreserveNonUtf8Blob},
		{"no python sources", noPythonSources},
		{"workspace topology lease", developmentWorkspaceTopologyLease},
	}
}

func gitBytesPreserveNonUtf8Blob() {
	root := filepath.Join(os.TempDir(), "tooling-git-bytes-"+randomTestToken())
	if err := os.MkdirAll(root, 0o755); err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	path := filepath.Join(root, "blob.bin")
	expected := []byte{0xff, 0x00, 0x80, 0x0a}
	if err := os.WriteFile(path, expected, 0o644); err != nil {
		panic(err)
	}
	result, err := ToolingSupport.RunProcess("git", []string{"init", "--quiet", root}, "", 0)
	if err != nil {
		panic(err)
	}
	assertEqualValue(0, result.ExitCode)
	hash := strings.TrimSpace(mustGit(ToolingSupport.Git(root, "hash-object", "-w", path)))
	actual := mustBytes(ToolingSupport.GitBytes(root, "cat-file", "blob", hash))
	if !bytes.Equal(actual, expected) {
		panic(errors.New("git raw bytes changed a non-UTF-8 blob"))
	}
	assertEqualValue(ToolingSupport.Sha256Bytes(expected), ToolingSupport.Sha256Bytes(actual))
}

func noPythonSources() {
	var python []string
	_ = filepath.WalkDir(ToolingSupport.Root(), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := entry.Name()
		if entry.IsDir() {
			if name == "bin" || name == "obj" || name == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(name, ".py") {
			python = append(python, path)
		}
		return nil
	})
	if len(python) != 0 {
		panic(fmt.Errorf("Python sources remain: %s", strings.Join(python, ",")))
	}
}

type leaseHolderProcess struct {
	command    *exec.Cmd
	stdin      io.WriteCloser
	stdoutLine chan string
	stderrDone chan string
}

func developmentWorkspaceTopologyLease() {
	previousNamespace, hadPrevious := os.LookupEnv(workspaceTopologyNamespaceVariable)
	leaseNamespace := "tooling-" + randomTestToken()
	defer func() {
		if hadPrevious {
			os.Setenv(workspaceTopologyNamespaceVariable, previousNamespace)
		} else {
			os.Unsetenv(workspaceTopologyNamespaceVariable)
		}
	}()

	os.Unsetenv(workspaceTopologyNamespaceVariable)
	name, err := workspaceTopologyMutexName()
	if err != nil {
		panic(err)
	}
	assertEqualValue("terrascale-workspace-topology-"+envUserName(), name)
	os.Setenv(workspaceTopologyNamespaceVariable, leaseNamespace)
	name, err = workspaceTopologyMutexName()
	if err != nil {
		panic(err)
	}
	assertEqualValue("terrascale-workspace-topology-"+leaseNamespace, name)
	os.Setenv(workspaceTopologyNamespaceVariable, "invalid namespace")
	if _, err := workspaceTopologyMutexName(); err == nil {
		panic(errors.New("expected an invalid namespace error"))
	}
	os.Setenv(workspaceTopologyNamespaceVariable, leaseNamespace)

	first, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 2*time.Second)
	if err != nil {
		panic(err)
	}
	func() {
		defer func() {
			if closeErr := first.Close(); closeErr != nil {
				panic(closeErr)
			}
		}()
		_, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 50*time.Millisecond)
		if err == nil || err.Error() != "Timed out acquiring the workspace topology lease." {
			panic(fmt.Errorf("expected a lease timeout, observed %v", err))
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancelled := make(chan error, 1)
		go func() {
			_, cancelErr := AcquireWorkspaceTopologyLease(ctx, "development-lab", 2*time.Second)
			cancelled <- cancelErr
		}()
		cancel()
		if cancelErr := <-cancelled; !errors.Is(cancelErr, context.Canceled) {
			panic(fmt.Errorf("expected context cancellation, observed %v", cancelErr))
		}
	}()

	second, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 2*time.Second)
	if err != nil {
		panic(err)
	}
	if err := second.Close(); err != nil {
		panic(err)
	}

	holder := startWorkspaceTopologyLeaseHolder(leaseNamespace, false, false)
	tryReadHolderReady(holder)
	if _, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 50*time.Millisecond); err == nil {
		panic(errors.New("The child process did not hold the workspace topology lease."))
	} else if err.Error() != "Timed out acquiring the workspace topology lease." {
		panic(err)
	}
	stopWorkspaceTopologyLeaseHolder(holder, 5*time.Second)
	assertEqualValue(0, holder.command.ProcessState.ExitCode())

	hostile := startWorkspaceTopologyLeaseHolder(leaseNamespace, true, true)
	tryReadHolderReady(hostile)
	stopWorkspaceTopologyLeaseHolder(hostile, 50*time.Millisecond)
	assertEqualValue(256, len(readHolderBoundedStderr(hostile)))

	afterChildExit, err := AcquireWorkspaceTopologyLease(context.Background(), "development-lab", 2*time.Second)
	if err != nil {
		panic(err)
	}
	if err := afterChildExit.Close(); err != nil {
		panic(err)
	}
}

func startWorkspaceTopologyLeaseHolder(leaseNamespace string, noisyStderr bool, ignoreStandardInput bool) *leaseHolderProcess {
	processPath, err := os.Executable()
	if err != nil {
		panic(errors.New("The tooling test host path is unavailable."))
	}
	arguments := []string{"-test.run=^TestWorkspaceTopologyLeaseHolderProcess$"}
	command := exec.Command(processPath, arguments...)
	command.Dir = ToolingSupport.Root()
	command.Env = append(os.Environ(),
		"TERRASCALE_TOOLING_LEASE_HOLDER=1",
		"TERRASCALE_TOOLING_LEASE_NAMESPACE="+leaseNamespace,
		fmt.Sprintf("TERRASCALE_TOOLING_LEASE_NOISY=%t", noisyStderr),
		fmt.Sprintf("TERRASCALE_TOOLING_LEASE_IGNORE_STDIN=%t", ignoreStandardInput),
	)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := command.StdinPipe()
	if err != nil {
		panic(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		panic(err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		panic(err)
	}
	if err := command.Start(); err != nil {
		panic(err)
	}
	holder := &leaseHolderProcess{
		command:    command,
		stdin:      stdin,
		stdoutLine: make(chan string, 1),
		stderrDone: make(chan string, 1),
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			holder.stdoutLine <- scanner.Text()
		} else {
			holder.stdoutLine <- ""
		}
	}()
	go func() { holder.stderrDone <- captureBoundedStderr(stderr, 256) }()
	return holder
}

func tryReadHolderReady(holder *leaseHolderProcess) string {
	select {
	case text := <-holder.stdoutLine:
		if text == "" {
			panic(errors.New("The workspace topology lease holder exited before admission."))
		}
		return text
	case <-time.After(5 * time.Second):
		stopWorkspaceTopologyLeaseHolder(holder, 5*time.Second)
		exitCode := -1
		if holder.command.ProcessState != nil {
			exitCode = holder.command.ProcessState.ExitCode()
		}
		panic(fmt.Errorf("The workspace topology lease holder did not become ready (exit %d): %s",
			exitCode, readHolderBoundedStderr(holder)))
	}
}

func stopWorkspaceTopologyLeaseHolder(holder *leaseHolderProcess, gracefulTimeout time.Duration) {
	if holder.command.ProcessState != nil {
		return
	}
	_ = holder.stdin.Close()
	done := make(chan error, 1)
	go func() { done <- holder.command.Wait() }()
	select {
	case <-done:
	case <-time.After(gracefulTimeout):
		killProcessTree(holder.command.Process.Pid)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			panic(fmt.Errorf("The workspace topology lease holder did not exit after termination: %s",
				readHolderBoundedStderr(holder)))
		}
	}
}

func captureBoundedStderr(reader io.Reader, maximumLength int) string {
	captured := make([]byte, 0, maximumLength)
	buffer := make([]byte, maximumLength)
	for {
		read, err := reader.Read(buffer)
		if read > 0 && len(captured) < maximumLength {
			remaining := maximumLength - len(captured)
			amount := read
			if remaining < amount {
				amount = remaining
			}
			captured = append(captured, buffer[:amount]...)
		}
		if err != nil {
			break
		}
	}
	return string(captured)
}

func readHolderBoundedStderr(holder *leaseHolderProcess) string {
	select {
	case text := <-holder.stderrDone:
		return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", " "), "\n", " "))
	case <-time.After(1 * time.Second):
		return "stderr unavailable"
	}
}

func assertEqualValue(expected any, actual any) {
	if expected != actual {
		panic(fmt.Errorf("expected %v, observed %v", expected, actual))
	}
}

func mustGit(value string, err error) string {
	if err != nil {
		panic(err)
	}
	return value
}

func mustBytes(value []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return value
}

func randomTestToken() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buffer)
}
