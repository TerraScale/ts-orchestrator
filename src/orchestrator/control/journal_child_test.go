package control

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestJournalChildFilesystemCASAndTamperRejection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses Unix advisory file locks")
	}
	moduleRoot := journalChildModuleRoot(t)
	buildDir := t.TempDir()
	childPath := filepath.Join(buildDir, "journalchild")
	build := exec.Command("go", "build", "-o", childPath, "./tests/journalchild")
	build.Dir = moduleRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build journalchild: %v\n%s", err, output)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyText := base64.StdEncoding.EncodeToString(key)
	root := filepath.Join(t.TempDir(), "contention")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	barrier := filepath.Join(root, "release")
	one := filepath.Join(root, "one")
	two := filepath.Join(root, "two")
	first := startJournalChild(t, childPath, root, keyText, barrier, one, "one")
	second := startJournalChild(t, childPath, root, keyText, barrier, two, "two")
	waitForJournalFiles(t, one+".ready", two+".ready")
	if err := os.WriteFile(barrier, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	firstExit := waitJournalChild(t, first)
	secondExit := waitJournalChild(t, second)
	if !((firstExit == 0 && secondExit == 1) || (firstExit == 1 && secondExit == 0)) {
		t.Fatalf("children exited %d and %d; one output=%q; two output=%q", firstExit, secondExit, first.output(), second.output())
	}
	results := []string{readJournalResult(t, one), readJournalResult(t, two)}
	if countJournalVerdict(results, "|true|1|op-contention") != 1 || countJournalVerdict(results, "|false|1|op-contention") != 1 {
		t.Fatalf("unexpected CAS results: %q", results)
	}
	if strings.Contains(first.output()+second.output(), keyText) {
		t.Fatal("child output exposed key material")
	}

	// A malformed or tampered authenticated record must fail closed. The child
	// writes its ready marker, but must not publish a verdict or leave a private
	// temporary file behind after rejecting the record.
	tamperRoot := filepath.Join(t.TempDir(), "tamper")
	if err := os.Mkdir(tamperRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256Hex(operationJournalIDForTest())
	if err := os.WriteFile(filepath.Join(tamperRoot, digest+".json"), []byte(`{"algorithm":"HMAC-SHA256","keyId":"test","payload":"dGFtcGVy","tag":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tamperBarrier := filepath.Join(tamperRoot, "release")
	if err := os.WriteFile(tamperBarrier, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	tampered := startJournalChild(t, childPath, tamperRoot, keyText, tamperBarrier, filepath.Join(tamperRoot, "tampered"), "tampered")
	if exit := waitJournalChild(t, tampered); exit == 0 || exit == 1 {
		t.Fatalf("tampered record unexpectedly returned CAS verdict, exit=%d output=%q", exit, tampered.output())
	}
	if _, err := os.Stat(filepath.Join(tamperRoot, "tampered")); !os.IsNotExist(err) {
		t.Fatalf("tampered child wrote result: %v", err)
	}
	if temporary, err := filepath.Glob(filepath.Join(tamperRoot, ".journalchild-*.tmp")); err != nil {
		t.Fatal(err)
	} else if len(temporary) != 0 {
		t.Fatalf("tampered child left temporary files: %v", temporary)
	}
}

type journalChildProcess struct {
	cmd    *exec.Cmd
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func (process *journalChildProcess) output() string {
	return strings.TrimSpace(process.stdout.String() + " " + process.stderr.String())
}

func startJournalChild(t *testing.T, executable string, args ...string) *journalChildProcess {
	t.Helper()
	process := &journalChildProcess{cmd: exec.Command(executable, args...)}
	process.cmd.Stdout = &process.stdout
	process.cmd.Stderr = &process.stderr
	if err := process.cmd.Start(); err != nil {
		t.Fatalf("start journalchild: %v", err)
	}
	return process
}

func waitJournalChild(t *testing.T, process *journalChildProcess) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- process.cmd.Wait() }()
	select {
	case err := <-done:
		if process.cmd.ProcessState == nil {
			t.Fatalf("journalchild has no process state after wait: %v", err)
		}
		return process.cmd.ProcessState.ExitCode()
	case <-time.After(30 * time.Second):
		_ = process.cmd.Process.Kill()
		t.Fatalf("journalchild did not exit within 30 seconds")
		return -1
	}
}

func waitForJournalFiles(t *testing.T, paths ...string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		ready := true
		for _, path := range paths {
			if _, err := os.Stat(path); err != nil {
				ready = false
				break
			}
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("journalchild readiness timeout: %v", paths)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readJournalResult(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func countJournalVerdict(results []string, verdict string) int {
	count := 0
	for _, result := range results {
		if strings.Contains(strings.ToLower(result), verdict) {
			count++
		}
	}
	return count
}

func journalChildModuleRoot(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			return root
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("could not find Go module root")
		}
		root = parent
	}
}

func operationJournalIDForTest() string { return "op-contention" }

func sha256Hex(value string) string {
	// Keep this helper local to the parent test so the fixture remains a
	// standalone executable and production packages cannot import it.
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
