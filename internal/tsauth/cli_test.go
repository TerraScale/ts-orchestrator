package tsauth

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

func TestWriteEnvFile(t *testing.T) {
	secrets := testSecrets()
	vault := newVault(t).withSecrets("gru-1", secrets)
	root := filepath.Join(t.TempDir(), "ts-auth")
	host := HostConfig{Cell: "gru-1", Root: root, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	path, err := WriteEnvFile(t.Context(), vault, testTarget.VaultID, host)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(root, "ts-auth.env") {
		t.Fatalf("path %s", path)
	}
	check := func() os.FileInfo {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Uid != host.UID {
			t.Fatalf("env file %v uid %d", info.Mode(), info.Sys().(*syscall.Stat_t).Uid)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseEnvFile(data)
		if err != nil || !maps.Equal(parsed, secrets) {
			t.Fatalf("env file holds other secrets: %v", err)
		}
		return info
	}
	before := check()
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode().Perm() != 0o750 {
		t.Fatalf("root %v: %v", info.Mode(), err)
	}

	if _, err := WriteEnvFile(t.Context(), vault, testTarget.VaultID, host); err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, check()) {
		t.Fatal("rerun rewrote the file in place")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("root holds %v: %v", entries, err)
	}
}

func TestWriteEnvFileRefusesRoot(t *testing.T) {
	vault := newVault(t).withSecrets("gru-1", testSecrets())
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "ts-auth")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{link, "ts-auth", "/", "/srv/../ts-auth"} {
		host := HostConfig{Cell: "gru-1", Root: root, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
		if _, err := WriteEnvFile(t.Context(), vault, testTarget.VaultID, host); err == nil {
			t.Errorf("root %s accepted", root)
		}
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("wrote through the symlink: %v", entries)
	}
	// A symlinked ancestor, and an ancestor another user can add entries to,
	// are refused before anything is created or changed below them.
	ancestor := filepath.Join(t.TempDir(), "srv")
	if err := os.Symlink(target, ancestor); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{filepath.Join(ancestor, "ts-auth"), filepath.Join(open, "ts-auth")} {
		host := HostConfig{Cell: "gru-1", Root: root, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
		if _, err := WriteEnvFile(t.Context(), vault, testTarget.VaultID, host); err == nil {
			t.Errorf("root %s below an unsafe ancestor accepted", root)
		}
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("wrote through the symlinked ancestor: %v", entries)
	}
	if entries, _ := os.ReadDir(open); len(entries) != 0 {
		t.Fatalf("created the root below a writable ancestor: %v", entries)
	}
}

// TestWriteEnvFileRefusesSubstitutableRoot refuses a root in a sticky parent
// such as /tmp, where another user could create or swap it first, and a root
// another user owns, before anything changes it.
func TestWriteEnvFileRefusesSubstitutableRoot(t *testing.T) {
	vault := newVault(t).withSecrets("gru-1", testSecrets())
	sticky := filepath.Join(t.TempDir(), "tmp")
	if err := os.Mkdir(sticky, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	host := HostConfig{Cell: "gru-1", Root: filepath.Join(sticky, "ts-auth"), UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	if _, err := WriteEnvFile(t.Context(), vault, testTarget.VaultID, host); err == nil {
		t.Fatal("accepted a root in a sticky parent")
	}
	if entries, _ := os.ReadDir(sticky); len(entries) != 0 {
		t.Fatalf("created the root in a sticky parent: %v", entries)
	}
	// A root another user owns; only root can create one, as CI runs.
	if os.Geteuid() != 0 {
		return
	}
	foreign := filepath.Join(t.TempDir(), "ts-auth")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(foreign, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	host.Root = foreign
	if _, err := WriteEnvFile(t.Context(), vault, testTarget.VaultID, host); err == nil {
		t.Fatal("accepted a root another user owns")
	}
	if info, err := os.Stat(foreign); err != nil || info.Sys().(*syscall.Stat_t).Uid != 65534 {
		t.Fatalf("changed the owner of another user's root: %v", err)
	}
}

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

func TestReadHostConfig(t *testing.T) {
	valid := `{"nats":{"cell":"GRU"},"host":{"ts_auth_root":"/srv/ts-managed/ts-auth","install_root":"/srv/ts-managed/install","state_root":"/var/lib/host","terrabase_root":"/srv/ts-managed/terrabase","managed_runtime_root":"/srv/ts-managed/runtime","workload_uid":2000,"workload_gid":2000}}`
	host, err := readHostConfig(writeFile(t, valid, 0o600))
	if want := (HostConfig{Cell: "gru-1", Root: "/srv/ts-managed/ts-auth", InstallRoot: "/srv/ts-managed/install", StateRoot: "/var/lib/host",
		TerraBaseRoot: "/srv/ts-managed/terrabase", UID: 2000, GID: 2000}); err != nil || host != want {
		t.Fatalf("host %+v: %v", host, err)
	}
	if _, err := readHostConfig(writeFile(t, valid, 0o644)); err == nil {
		t.Fatal("accepted a world-readable host config")
	}
	if _, err := readHostConfig(writeFile(t, `{"nats":{"cell":"GRU"},"host":{"workload_uid":2000,"workload_gid":2000}}`, 0o600)); err == nil {
		t.Fatal("accepted a host config without ts_auth_root")
	}
}

func TestEnvFileRefusesOverlappingHostRootsBeforeMutation(t *testing.T) {
	for _, field := range []string{"install_root", "state_root", "terrabase_root"} {
		for _, relation := range []string{"equal", "ancestor", "descendant"} {
			t.Run(field+"/"+relation, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "private")
				if err := os.Mkdir(root, 0o700); err != nil {
					t.Fatal(err)
				}
				before, err := os.Stat(root)
				if err != nil {
					t.Fatal(err)
				}
				other := root
				if relation == "ancestor" {
					other = filepath.Join(root, "other")
				} else if relation == "descendant" {
					other = filepath.Dir(root)
				}
				config := map[string]any{"nats": map[string]string{"cell": "gru"}, "host": map[string]any{
					"ts_auth_root": root, "install_root": "/srv/install", "state_root": "/var/lib/state",
					"workload_uid": 2000, "workload_gid": 2000, field: other}}
				data, err := json.Marshal(config)
				if err != nil {
					t.Fatal(err)
				}
				path := writeFile(t, string(data), 0o600)
				if err := Run(t.Context(), []string{"env-file", "--host-config", path, "--vault-id", testTarget.VaultID}, &bytes.Buffer{}, nil); err == nil || !strings.Contains(err.Error(), "separate") {
					t.Fatalf("overlapping roots reached OCI: %v", err)
				}
				// Direct callers must also reject before fetching secrets or chmod.
				var decoded struct {
					Host HostConfig `json:"host"`
				}
				if err := json.Unmarshal(data, &decoded); err != nil {
					t.Fatal(err)
				}
				if _, err := WriteEnvFile(t.Context(), nil, testTarget.VaultID, decoded.Host); err == nil || !strings.Contains(err.Error(), "separate") {
					t.Fatalf("direct call accepted overlap: %v", err)
				}
				after, err := os.Stat(root)
				if err != nil || after.Mode() != before.Mode() || after.Sys().(*syscall.Stat_t).Uid != before.Sys().(*syscall.Stat_t).Uid || after.Sys().(*syscall.Stat_t).Gid != before.Sys().(*syscall.Stat_t).Gid {
					t.Fatalf("changed private root: %v", err)
				}
				if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
					t.Fatalf("wrote into private root: %v, %v", entries, err)
				}
			})
		}
	}
}

func TestRunRejectsIncompleteCommands(t *testing.T) {
	var output bytes.Buffer
	if err := Run(t.Context(), nil, &output, nil); err != nil || !strings.HasPrefix(output.String(), "Usage: ts-orch ts-auth") {
		t.Fatalf("usage %q: %v", output.String(), err)
	}
	for _, args := range [][]string{
		{"rotate"},
		{"env-file"},
		{"env-file", "--host-config", "/nonexistent"},
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
	if want := "destroy table inet terrascale_metadata\ntable inet terrascale_metadata {\n" +
		"    chain output {\n        type filter hook output priority 0; policy accept;\n" +
		"        ip daddr 169.254.169.254 meta skuid \"systemd-timesync\" udp dport 123 accept\n" +
		"        ip daddr 169.254.169.254 meta skuid != { 0, \"terrascale-orchestrator\" } counter drop\n    }\n}\n"; rules.String() != want {
		t.Fatalf("metadata rules:\n%s", rules.String())
	}
	unit, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "terrascale-ts-auth-metadata.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, directive := range []string{"Before=terrascale-orchestrator-host.service\n", "Type=oneshot\n",
		"ExecStartPre=/bin/sh -c '/usr/sbin/nft list table inet terrascale_metadata >/dev/null 2>&1 || /usr/sbin/nft add table inet terrascale_metadata'\n",
		"ExecStart=/usr/sbin/nft -f /etc/terrascale-orchestrator/ts-auth-metadata.nft\n",
		"RemainAfterExit=no\n", "RequiredBy=terrascale-orchestrator-host.service\n"} {
		if !strings.Contains(string(unit), directive) {
			t.Fatalf("metadata unit missing %q", directive)
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
