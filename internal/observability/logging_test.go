package observability

import (
	"os"
	"path/filepath"
	"testing"
)

// The tests parse unprefixed output, so they run as if outside journald even
// when the test runner is a systemd service.
func TestMain(m *testing.M) {
	journalStream = func() bool { return false }
	os.Exit(m.Run())
}

// logOutput observes the same file boundary as the process log sink.
type logOutput struct {
	*os.File
	t *testing.T
}

func newLogOutput(t *testing.T) *logOutput {
	t.Helper()
	file, err := os.Create(filepath.Join(t.TempDir(), "process.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	return &logOutput{File: file, t: t}
}

func (output *logOutput) Bytes() []byte {
	output.t.Helper()
	data, err := os.ReadFile(output.Name())
	if err != nil {
		output.t.Fatal(err)
	}
	return data
}
func (output *logOutput) String() string { return string(output.Bytes()) }
func (output *logOutput) Len() int       { return len(output.Bytes()) }
func (output *logOutput) Reset() {
	output.t.Helper()
	if err := output.Truncate(0); err != nil {
		output.t.Fatal(err)
	}
	if _, err := output.Seek(0, 0); err != nil {
		output.t.Fatal(err)
	}
}
