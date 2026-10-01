package deploy_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// The command fakes (TestOfflineCommand, TestPromotionCommand) run hundreds
// of times per image build and contain no production code. Under -race they
// run from this package rebuilt once without race instrumentation, whose
// startup otherwise dominated the suite; the native commands under test
// (TestDeployTool) keep running from the race-instrumented binary.
var fakeBinary struct {
	once      sync.Once
	directory string
	path      string
	err       error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if fakeBinary.directory != "" {
		os.RemoveAll(fakeBinary.directory)
	}
	os.Exit(code)
}

func fakeToolBinary(t *testing.T) string {
	t.Helper()
	if !raceEnabled {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		return exe
	}
	fakeBinary.once.Do(func() {
		fakeBinary.directory, fakeBinary.err = os.MkdirTemp("", "ts-deploy-fakes-")
		if fakeBinary.err != nil {
			return
		}
		path := filepath.Join(fakeBinary.directory, "deploy.test")
		cmd := exec.Command("go", "test", "-c", "-o", path, ".")
		if output, err := cmd.CombinedOutput(); err != nil {
			fakeBinary.err = &buildError{err: err, output: output}
			return
		}
		fakeBinary.path = path
	})
	if fakeBinary.err != nil {
		t.Fatalf("build command fakes without -race: %v", fakeBinary.err)
	}
	return fakeBinary.path
}

type buildError struct {
	err    error
	output []byte
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + string(e.output) }
