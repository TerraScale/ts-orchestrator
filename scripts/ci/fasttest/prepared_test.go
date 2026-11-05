package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
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
	files := map[string]string{
		"go.mod":        "module fast.example/proof\n\ngo 1.27\n",
		"proof_test.go": "package proof\nimport \"testing\"\nfunc TestHappy(t *testing.T) { t.Log(\"actual test executed\") }\n",
	}
	for name, data := range files {
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
	// A fresh checkout must reuse identical compiled bytes, while retaining its
	// own source stamp, executable paths and original package working directory.
	otherRoot := t.TempDir()
	t.Chdir(otherRoot)
	if output, err := exec.Command("git", "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("second git init: %v: %s", err, output)
	}
	for name, data := range files {
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	otherDirectory := filepath.Join(t.TempDir(), "prepared")
	if err := prepare(t.Context(), []string{"go"}, otherDirectory); err != nil {
		t.Fatal(err)
	}
	compiled := func(directory string) ([]byte, testBinary) {
		data, err := os.ReadFile(filepath.Join(directory, "suite.json"))
		if err != nil {
			t.Fatal(err)
		}
		var suite preparedSuite
		if err := json.Unmarshal(data, &suite); err != nil {
			t.Fatal(err)
		}
		binary := suite.Binaries["fast.example/proof"]
		data, err = os.ReadFile(binary.Path)
		if err != nil {
			t.Fatal(err)
		}
		return data, binary
	}
	firstBytes, first := compiled(directory)
	otherBytes, other := compiled(otherDirectory)
	if sha256.Sum256(firstBytes) != sha256.Sum256(otherBytes) || first.Path == other.Path || first.Dir != root || other.Dir != otherRoot {
		t.Fatalf("checkout reuse changed compiled bytes or runtime location: %+v, %+v", first, other)
	}
	if err := runPrepared(t.Context(), []string{"go"}, nil, otherDirectory, &output); err != nil {
		t.Fatalf("second checkout execution: %v: %s", err, output.String())
	}
	t.Chdir(root)
	if err := os.WriteFile("proof_test.go", []byte("package proof\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runPrepared(t.Context(), []string{"go"}, nil, directory, &output); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("changed source admitted: %v", err)
	}
}
