package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestParseOptionsRequiresExplicitCleanInputs(t *testing.T) {
	repository := t.TempDir()
	root := filepath.Join(repository, "vm")
	terraBase := filepath.Join(repository, "terrabase")
	config, err := parseOptions([]string{
		"--root", root,
		"--repo", repository,
		"--terrabase-repo", terraBase,
		"--", "go", "run", "./cmd/vm-qualify", "smoke",
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.root != root || config.repo != repository || config.terraBaseRepo != terraBase || strings.Join(config.command, " ") != "go run ./cmd/vm-qualify smoke" {
		t.Fatalf("unexpected parsed options: %+v", config)
	}
	for _, arguments := range [][]string{
		{"--root", "relative", "--repo", repository, "--terrabase-repo", terraBase, "--", "true"},
		{"--root", root, "--repo", repository, "--terrabase-repo", terraBase},
		{"--root", root + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "vm", "--repo", repository, "--terrabase-repo", terraBase, "--", "true"},
	} {
		if _, err := parseOptions(arguments); err == nil {
			t.Fatalf("parseOptions accepted invalid arguments %#v", arguments)
		}
	}
}

func TestValidateAndSignExactStaticArtifacts(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("qualification ELF validation is native Linux only")
	}
	directory := t.TempDir()
	inputs := []artifact{
		{component: "ts-node", environment: "TS_VM_TS_NODE", path: buildTestELF(t, directory, "ts-node", "node")},
		{component: "orchestrator", environment: "TS_VM_ORCHESTRATOR", path: buildTestELF(t, directory, "orchestrator", "control")},
		{component: "terrabase", environment: "TS_VM_TERRABASE", path: buildTestELF(t, directory, "terrabase", "data")},
	}
	validated, err := validateArtifacts(inputs)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroArtifacts(validated)
	prepared, err := signArtifacts(directory, validated, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	publicText, err := os.ReadFile(prepared.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := hex.DecodeString(strings.TrimSuffix(string(publicText), "\n"))
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		t.Fatalf("invalid public key: length=%d err=%v", len(publicBytes), err)
	}
	seenVersions := map[string]bool{}
	for _, item := range prepared.artifacts {
		signature, err := os.ReadFile(item.signaturePath)
		if err != nil {
			t.Fatal(err)
		}
		if len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(publicBytes), item.data, signature) {
			t.Fatalf("%s signature did not verify: %v", item.component, err)
		}
		wantVersion := "vmqual." + hex.EncodeToString(item.digest[:8])
		if item.version != wantVersion || seenVersions[item.version] {
			t.Fatalf("%s version = %q, want unique %q", item.component, item.version, wantVersion)
		}
		seenVersions[item.version] = true
		assertMode(t, item.path, 0o755)
		assertMode(t, item.signaturePath, 0o444)
	}
	assertMode(t, prepared.publicKey, 0o444)

	environment := bundleEnvironment([]string{
		"PATH=/bin",
		"TS_VM_TS_NODE=untrusted",
		"TS_VM_TS_NODE_VERSION=old",
		"TS_VM_TERRABASE_DECLARATION_FILE=/protected/member.json",
		"TS_VM_RUN_DECLARATION_FILE=/protected/run.json",
		"TS_VM_CONTROL_DECLARATION_FILE=/protected/control.json",
	}, prepared)
	for _, name := range artifactEnvironment {
		count := 0
		for _, value := range environment {
			if strings.HasPrefix(value, name+"=") {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s occurs %d times in %#v", name, count, environment)
		}
	}
	for _, want := range []string{
		"TS_VM_TERRABASE_DECLARATION_FILE=/protected/member.json",
		"TS_VM_RUN_DECLARATION_FILE=/protected/run.json",
		"TS_VM_CONTROL_DECLARATION_FILE=/protected/control.json",
	} {
		if !containsEnvironment(environment, want) {
			t.Fatalf("declaration input %q was not forwarded: %#v", want, environment)
		}
	}
}

func TestBundleEnvironmentPreservesMissingDeclarationInputs(t *testing.T) {
	prepared := bundle{}
	environment := bundleEnvironment([]string{"PATH=/bin", "TS_VM_RUN_DECLARATION_FILE=/missing/run.json"}, prepared)
	if !containsEnvironment(environment, "TS_VM_RUN_DECLARATION_FILE=/missing/run.json") {
		t.Fatalf("missing declaration path was not forwarded: %#v", environment)
	}
}

func TestValidateArtifactsRejectsAliasesAndDuplicateBytes(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("qualification ELF validation is native Linux only")
	}
	directory := t.TempDir()
	path := buildTestELF(t, directory, "one", "same")
	if _, err := validateArtifacts([]artifact{{component: "one", path: path}, {component: "two", path: path}}); err == nil || !strings.Contains(err.Error(), "aliases") {
		t.Fatalf("alias validation error = %v", err)
	}
	copyPath := filepath.Join(directory, "copy")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := validateArtifacts([]artifact{{component: "one", path: path}, {component: "two", path: copyPath}}); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("duplicate validation error = %v", err)
	}
}

func TestServiceArtifactCanExceedDiagnosticTransferLimit(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("qualification ELF validation is native Linux only")
	}
	directory := t.TempDir()
	source := buildTestELF(t, directory, "service", "large-native-service")
	// ELF permits trailing bytes. Preserve the real ELF headers while covering
	// the size reached by the static TerraBase release, above diagnostic limits.
	const size = 17 << 20
	if err := os.Truncate(source, size); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "installed")
	if err := copyArtifact(source, target); err != nil {
		t.Fatal(err)
	}
	artifacts, err := validateArtifacts([]artifact{{component: "terrabase", path: target}})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroArtifacts(artifacts)
	if len(artifacts[0].data) != size {
		t.Fatalf("artifact bytes = %d, want %d", len(artifacts[0].data), size)
	}
	if err := os.Truncate(source, artifactLimit+1); err != nil {
		t.Fatal(err)
	}
	if err := copyArtifact(source, filepath.Join(directory, "oversized")); err == nil {
		t.Fatal("accepted an artifact larger than the service limit")
	}
}

func TestCleanupOwnedDirectoryIsNarrow(t *testing.T) {
	root := t.TempDir()
	owned, err := os.MkdirTemp(root, artifactPrefix)
	if err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(root, "keep")
	if err := os.Mkdir(keep, 0o700); err != nil {
		t.Fatal(err)
	}
	ownedInfo, err := os.Lstat(owned)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanupOwnedDirectory(root, owned, ownedInfo); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatalf("owned directory still exists: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("unowned sibling was changed: %v", err)
	}
	if err := cleanupOwnedDirectory(root, keep, ownedInfo); err == nil {
		t.Fatal("cleanup accepted an unowned sibling")
	}
	if err := cleanupOwnedDirectory(root, root, ownedInfo); err == nil {
		t.Fatal("cleanup accepted the qualification root")
	}
	replacement, err := os.MkdirTemp(root, artifactPrefix)
	if err != nil {
		t.Fatal(err)
	}
	otherInfo, err := os.Lstat(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanupOwnedDirectory(root, replacement, ownedInfo); err == nil {
		t.Fatal("cleanup accepted a different directory identity")
	}
	if _, err := os.Stat(replacement); err != nil {
		t.Fatalf("identity-mismatched directory was changed: %v", err)
	}
	if err := cleanupOwnedDirectory(root, replacement, otherInfo); err != nil {
		t.Fatal(err)
	}
}

func buildTestELF(t *testing.T, directory, name, identity string) string {
	t.Helper()
	source := filepath.Join(directory, name+".go")
	program := "package main\nimport \"os\"\nfunc main() { _, _ = os.Stdout.WriteString(" + strconv.Quote(identity) + ") }\n"
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, name)
	command := exec.CommandContext(context.Background(), "go", "build", "-trimpath", "-ldflags=-s -w", "-o", output, source)
	command.Env = replaceEnvironment(os.Environ(), map[string]string{"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": runtime.GOARCH})
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build static fixture: %v: %s", err, combined)
	}
	if err := os.Chmod(output, 0o755); err != nil {
		t.Fatal(err)
	}
	return output
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %04o, want %04o", path, info.Mode().Perm(), want)
	}
}

func containsEnvironment(environment []string, want string) bool {
	for _, item := range environment {
		if item == want {
			return true
		}
	}
	return false
}
