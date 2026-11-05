package managedmember_test

import (
	"context"
	"crypto/sha256"

	"encoding/hex"

	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"slices"
	"strings"

	"testing"
	"time"

	fc "github.com/TerraScale/ts-orchestrator/internal/qualification/firecracker"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
)

func mmSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

var mmMaterials = [][2]string{{"authority_tbca", "authority.tbca"}, {"trusted_public_key", "trusted-public-key"}, {"server_crt", "server.crt"}, {"server_key", "server.key"}, {"client_ca_pem", "client-ca.pem"}, {"server_ca_pem", "server-ca.pem"}, {"client_managed_manifest", "client-managed-manifest.json"}, {"client_config", "client-config.json"}, {"client_chain", "client-chain.pem"}, {"client_private_key", "client-private-key.pem"}, {"client_api_keys", "client-api-keys.json"}, {"signed_v2_s3_config", "signed-v2-s3-config.json"}}

func mmSudo(t *testing.T, commands ...string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("requires a nonroot host user and passwordless sudo")
	}
	for _, name := range append([]string{"sudo"}, commands...) {
		if _, e := exec.LookPath(name); e != nil {
			t.Skip("requires " + name)
		}
	}
	if out := script.Exec(t, "", nil, "sudo", "-n", "true"); out.Code != 0 {
		t.Skip("passwordless sudo unavailable")
	}
}
func mmCleanupSudo(t *testing.T, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
	defer cancel()
	if out, e := exec.CommandContext(ctx, "sudo", "-n", "rm", "-rf", "--", path).CombinedOutput(); e != nil {
		t.Errorf("sudo cleanup: %v %s", e, out)
	}
}

func TestManagedMemberRealProtectedMaterialStaging(t *testing.T) {
	if testing.Short() {
		t.Skip("heavy provisioning, recovery or multi-node integration runs in Slow")
	}
	mmSudo(t)
	base := t.TempDir()
	mount := filepath.Join(base, "guest-root")
	logs := filepath.Join(base, "logs")
	for _, dir := range []string{mount, logs} {
		if e := os.Mkdir(dir, 0o755); e != nil {
			t.Fatal(e)
		}
	}
	inputs := map[string]fc.ManagedInput{}
	for _, pair := range mmMaterials {
		payload := []byte("pinned-" + pair[0])
		path := filepath.Join(base, pair[0])
		script.Write(t, path, payload, 0o600)
		inputs[pair[0]] = fc.ManagedInput{Path: path, SHA256: mmSHA(payload), Size: int64(len(payload))}
	}
	t.Cleanup(func() { mmCleanupSudo(t, mount) })
	lab := &fc.ManagedLab{Ctx: t.Context(), Commands: logs}
	if e := lab.StageManagedMaterial(mount, "a", inputs); e != nil {
		t.Fatal(e)
	}
	commands := []string{}
	for _, event := range lab.Events {
		if event["kind"] == "command" {
			commands = append(commands, event["label"].(string))
		}
	}
	names := []string{"install-dir-ts-managed", "install-dir-" + filepath.Base(fc.ManagedMemberDirs["a"]), "install-dir-material", "install-dir-control", "install-dir-volume"}
	want := slices.Clone(names)
	for _, pair := range mmMaterials {
		want = append(want, "install-"+pair[1], "hash-"+pair[1])
	}
	slices.Reverse(names)
	want = append(want, names...)
	want = append(want, "verify-a-managed-layout")
	if !slices.Equal(commands, want) {
		t.Fatal(commands)
	}
	protected := filepath.Join(mount, "srv/ts-managed")
	info, e := os.Stat(protected)
	if e != nil || info.Mode().Perm() != 0o750 {
		t.Fatal(info, e)
	}
	if _, e = os.Stat(filepath.Join(mount, strings.TrimPrefix(fc.ManagedMemberDirs["a"], "/"), "material", mmMaterials[0][1])); !os.IsPermission(e) {
		t.Fatal("want permission rejection", e)
	}
	argv := []string{"-n", "stat", "-c", "%u:%g:%f", "--"}
	records := []string{}
	for _, d := range fc.ManagedDirectories("a") {
		argv = append(argv, filepath.Join(mount, strings.TrimPrefix(d[0].(string), "/")))
		records = append(records, fmt.Sprintf("0:65534:%x", 0o40000|d[1].(int)))
	}
	for _, pair := range mmMaterials {
		argv = append(argv, filepath.Join(mount, strings.TrimPrefix(fc.ManagedMemberDirs["a"], "/"), "material", pair[1]))
		records = append(records, "0:65534:8120")
	}
	stat := script.Exec(t, "", nil, "sudo", argv...)
	if stat.Code != 0 || strings.TrimSpace(stat.Stdout) != strings.Join(records, "\n") {
		t.Fatal(stat)
	}
}
