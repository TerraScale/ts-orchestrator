package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparedSuiteExecutesCurrentSourceAndRefusesChangedSource(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if output, err := exec.Command("git", "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	for name, data := range map[string]string{
		"go.mod":        "module fast.example/proof\n\ngo 1.27\n",
		"proof_test.go": "package proof\nimport \"testing\"\nfunc TestHappy(t *testing.T) { t.Log(\"actual test executed\") }\n",
	} {
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	directory := filepath.Join(t.TempDir(), "prepared")
	if err := prepare(t.Context(), []string{"go"}, directory); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runPrepared(t.Context(), []string{"go"}, nil, directory, &output); err != nil {
		t.Fatalf("prepared execution: %v: %s", err, output.String())
	}
	receipts, err := os.ReadFile(filepath.Join(directory, "receipts.json"))
	if err != nil || !bytes.Contains(receipts, []byte(`"Test":"TestHappy"`)) {
		t.Fatalf("missing actual test receipt: %s, %v", receipts, err)
	}
	if err := os.WriteFile("proof_test.go", []byte("package proof\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runPrepared(t.Context(), []string{"go"}, nil, directory, &output); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("changed source admitted: %v", err)
	}
}
