package release

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSourceTreeDigestIgnoresLocalGitSettings hashes one commit under the
// default settings and under settings that change git archive's output.
func TestSourceTreeDigestIgnoresLocalGitSettings(t *testing.T) {
	checkout := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", checkout}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	if err := os.WriteFile(filepath.Join(checkout, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, "secret.txt"), []byte("kept\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("-c", "user.name=ci", "-c", "user.email=ci@example.com", "commit", "-q", "-m", "fixture")
	commit := git("rev-parse", "HEAD")
	want, err := SourceTreeDigest(t.Context(), checkout, commit)
	if err != nil {
		t.Fatal(err)
	}
	attributes := filepath.Join(t.TempDir(), "attributes")
	if err := os.WriteFile(attributes, []byte("secret.txt export-ignore\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, ".git", "info", "attributes"), []byte("main.go export-ignore\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("config", "tar.umask", "0000")
	git("config", "core.attributesFile", attributes)
	// A global init.templateDir whose template carries info/attributes.
	home, template := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(template, "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(template, "info", "attributes"), []byte("* export-ignore\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[init]\n\ttemplateDir = "+template+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	// Inherited git variables: another repository and command-line config.
	other := t.TempDir()
	git("init", "-q", other)
	t.Setenv("GIT_DIR", filepath.Join(other, ".git"))
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.attributesFile")
	t.Setenv("GIT_CONFIG_VALUE_0", attributes)
	got, err := SourceTreeDigest(t.Context(), checkout, commit)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("local Git settings changed the source tree digest: %s, want %s", got, want)
	}
	// Without the pins those settings do change git archive's bytes.
	for _, variable := range []string{"GIT_DIR", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"} {
		os.Unsetenv(variable)
	}
	plain := exec.Command("sh", "-c", "git -C '"+checkout+"' archive --format=tar "+commit+" | sha256sum")
	out, err := plain.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Fields(string(out))[0] == want {
		t.Fatal("the fixture's settings do not change git archive's output")
	}
}
