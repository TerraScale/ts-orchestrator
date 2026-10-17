package dns

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestOperatorDNSPermissionsWithPrivateUmask(t *testing.T) {
	if filepath.Dir(subscriber) != "/etc" {
		t.Fatal("operator DNS must not create a runtime config directory")
	}
	root := t.TempDir()
	previous := syscall.Umask(0077)
	defer syscall.Umask(previous)
	owned := filepath.Join(root, "owned")
	if err := mkdir(owned); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(owned, "subscriber")
	if err := write(file, []byte("nameserver 127.0.0.53\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{owned: 0755, file: 0644} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s must have permissions %o despite umask077", path, mode)
		}
	}
	private := filepath.Join(root, "existing")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err := mkdir(private); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(private)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("installer changed an existing private directory")
	}
}

func TestPlanAndRejectUnsafeDNSSetup(t *testing.T) {
	var out bytes.Buffer
	if err := Run(t.Context(), []string{"--split-resolver", "--upstream", "100.100.100.100", "--netbird", "sudo -n netbird-wt0"}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"100.100.100.100", "~nb.ts.internal", "127.0.0.53"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %s in reviewed plan: %s", want, out.String())
		}
	}
	directory := t.TempDir()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(directory, "netbird")
	if err := os.WriteFile(script, []byte(`printf '%s\n' "$*" >> "$(dirname "$0")/commands"`), 0600); err != nil {
		t.Fatal(err)
	}
	argv := []string{os.Args[0], "-test.run=^TestNativeDNSInstallProcess$", "--", directory, shell + " " + script}
	if os.Geteuid() != 0 {
		argv = append([]string{"unshare", "--user", "--map-root-user"}, argv...)
	}
	if output, err := exec.CommandContext(t.Context(), argv[0], argv[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("isolated native DNS process: %v: %s", err, output)
	}
	commands, err := os.ReadFile(filepath.Join(directory, "commands"))
	if err != nil || string(commands) != "down\nup --disable-dns=false\n" {
		t.Fatalf("native process commands=%q error=%v", commands, err)
	}
	override, err := os.ReadFile(filepath.Join(directory, "90-ts-orchestrator-dns.json"))
	if err != nil || string(override) != "{\"DisableDNS\":false}\n" {
		t.Fatalf("native DNS override=%q error=%v", override, err)
	}
	for _, args := range [][]string{
		{"--netbird", "netbird\nExecStart=/bad"},
		{"--netbird", "netbird %n"},
		{"--upstream", "not-an-ip"},
		{"--config-dir", "relative"},
		{"--config-dir", "/etc/netbird/config.d", "--split-resolver"},
	} {
		if err := Run(context.Background(), args, &out); err == nil {
			t.Fatalf("accepted unsafe setup %q", args)
		}
	}
}

func TestNativeDNSInstallProcess(t *testing.T) {
	index := slices.Index(os.Args, "--")
	if index < 0 {
		return
	}
	args := os.Args[index+1:]
	var out bytes.Buffer
	if err := Run(t.Context(), []string{"--apply", "--config-dir", args[0], "--netbird", args[1]}, &out); err != nil {
		t.Fatal(err)
	}
}
