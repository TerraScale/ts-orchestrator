package tsauth

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

// TestReadOwnerOnlyRefusesFIFO refuses a FIFO at once instead of blocking
// until a writer appears.
func TestReadOwnerOnlyRefusesFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "credential")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readOwnerOnly(fifo, 4096); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read a FIFO as a credential file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}

func writeFile(t *testing.T, content string, mode os.FileMode) string {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunRejectsIncompleteCommands(t *testing.T) {
	var output bytes.Buffer
	if err := Run(t.Context(), nil, &output, nil); err != nil || !strings.HasPrefix(output.String(), "Usage: ts-orch ts-auth") {
		t.Fatalf("usage %q: %v", output.String(), err)
	}
	for _, args := range [][]string{
		{"rotate"},
		{"env-file"},
		{"secrets"},
		{"terrabase-bootstrap", "--plan", "plan.json"},
		{"secrets", "--plan", "plan.json", "extra"},
	} {
		if err := Run(t.Context(), args, &bytes.Buffer{}, nil); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestRenderedMetadataRulesReserveMetadataForRootAndController(t *testing.T) {
	var rules bytes.Buffer
	if err := Run(t.Context(), []string{"metadata-rules"}, &rules, nil); err != nil {
		t.Fatal(err)
	}
	if want := "destroy table inet terrascale_metadata\ndestroy table bridge terrascale_metadata\ntable inet terrascale_metadata {\n" +
		"    chain prerouting {\n        type filter hook prerouting priority -300; policy accept;\n" +
		"        ip daddr 169.254.169.254 counter drop\n    }\n" +
		"    chain output {\n        type filter hook output priority 0; policy accept;\n" +
		"        ip daddr 169.254.169.254 meta skuid \"systemd-timesync\" udp dport 123 accept\n" +
		"        ip daddr 169.254.169.254 meta skuid \"systemd-resolve\" meta l4proto { tcp, udp } th dport 53 accept\n" +
		"        ip daddr 169.254.169.254 meta skuid 0 accept\n" +
		"        ip daddr 169.254.169.254 counter drop\n    }\n" +
		"    chain forward {\n        type filter hook forward priority 0; policy accept;\n" +
		"        ip daddr 169.254.169.254 counter drop\n    }\n}\n" +
		"table bridge terrascale_metadata {\n    chain forward {\n" +
		"        type filter hook forward priority 0; policy accept;\n" +
		"        ip daddr 169.254.169.254 counter drop\n    }\n}\n"; rules.String() != want {
		t.Fatalf("metadata rules:\n%s", rules.String())
	}
	unit, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "terrascale-ts-auth-metadata.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, directive := range []string{"DefaultDependencies=no\n", "Before=network-pre.target shutdown.target\n", "Type=oneshot\n",
		"ExecStartPre=/bin/sh -c '/usr/sbin/nft list table inet terrascale_metadata >/dev/null 2>&1 || /usr/sbin/nft add table inet terrascale_metadata'\n",
		"ExecStart=/usr/sbin/nft -f /etc/terrascale-orchestrator/ts-auth-metadata.nft\n",
		"ExecStartPre=/bin/sh -c '/usr/sbin/nft list table bridge terrascale_metadata >/dev/null 2>&1 || /usr/sbin/nft add table bridge terrascale_metadata'\n",
		"RemainAfterExit=no\n"} {
		if !strings.Contains(string(unit), directive) {
			t.Fatalf("metadata unit missing %q", directive)
		}
	}
	for _, name := range []string{"network-pre.target", "containerd.service", "terrascale-orchestrator-managed-host-start.service", "terrascale-orchestrator-controller-install.service", "terrascale-orchestrator-bootstrap.service", "terrascale-orchestrator-managed-runtime.service", "terrascale-orchestrator-controller.service", "terrascale-orchestrator-host-setup.service", "terrascale-orchestrator-host.service"} {
		for _, relationship := range []string{"Before", "RequiredBy"} {
			found := false
			for line := range strings.SplitSeq(string(unit), "\n") {
				if value, ok := strings.CutPrefix(line, relationship+"="); ok && slices.Contains(strings.Fields(value), name) {
					found = true
				}
			}
			if !found {
				t.Fatalf("metadata unit lacks %s=%s", relationship, name)
			}
		}
	}
	if strings.Contains(string(unit), "ExecStop=") {
		t.Fatal("stopping the firewall unit must leave its rules installed")
	}
}

func TestRunRejectsPlanBeforeVaultAccess(t *testing.T) {
	want := errors.New("plan rejected")
	loadPlan := func(path string) (map[string]any, error) {
		if path != "reviewed-plan.json" {
			t.Fatalf("plan path %q", path)
		}
		return nil, want
	}
	err := Run(t.Context(), []string{"secrets", "--plan", "reviewed-plan.json"}, &bytes.Buffer{}, loadPlan)
	if !errors.Is(err, want) {
		t.Fatalf("plan validation error: %v", err)
	}
}

// TestMemberClientRefusesUnsafeInputs checks memberClient's local inputs; its
// TLS checks run against the real TerraBase in TestBootstrapAgainstTerraBaseRelease.
func TestMemberClientRefusesUnsafeInputs(t *testing.T) {
	ca := writeFile(t, "no certificate", 0o644)
	credential := writeFile(t, "dashboard-credential-SENTINEL-0123456789\n", 0o600)
	if _, err := memberClient("https://127.0.0.1:1", "http://127.0.0.1:2", "gru-1-db-1", ca, credential); err == nil {
		t.Fatal("accepted a member CA without a certificate")
	}
	certificate, _, err := terrabase.NewCA("gru-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client, err := memberClient("https://127.0.0.1:1", "http://127.0.0.1:2", "gru-1-db-1", writeFile(t, string(certificate), 0o644), credential)
	if err != nil || client.HTTP.Timeout != terraBaseRequestTimeout || terraBaseRequestTimeout <= 0 || client.HTTP.CheckRedirect == nil {
		t.Fatalf("member client %v without a request timeout: %v", client.HTTP, err)
	}
	if redirectErr := client.HTTP.CheckRedirect(&http.Request{}, nil); !errors.Is(redirectErr, http.ErrUseLastResponse) {
		t.Fatalf("member client follows redirects: %v", redirectErr)
	}
}
