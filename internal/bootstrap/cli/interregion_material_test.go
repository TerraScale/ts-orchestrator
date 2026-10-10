package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

func TestGenerateInterRegionMaterialWritesThePublicInventory(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	material := filepath.Join(root, "material")
	if _, err := bootstrapmaterial.Generate(material, bootstrapmaterial.Config{Environment: "production",
		Region: "sa-saopaulo-1", Cell: "gru", DeploymentID: "0000000000XXVM2FA4QBBHZBKD", ClusterID: "00000000000C2KQX35BT9P1FFG",
		SubnetCIDR: "10.251.0.0/24", ValidityHours: 48, Slots: []bootstrapmaterial.Slot{
			{Name: "controller-a", PrivateIP: "10.251.0.10"}, {Name: "controller-b", PrivateIP: "10.251.0.11"},
			{Name: "controller-c", PrivateIP: "10.251.0.12"}}}, now); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(bootstrapmaterial.InterRegionConfig{
		Topology: natscell.HubAndSpoke("gru", []string{"sfo"}), ListenPort: 7422})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "interregion-config.json")
	if err := os.WriteFile(configPath, wire, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	out := filepath.Join(root, "interregion-public.json")
	var output bytes.Buffer
	run := func(digest string, extra ...string) error {
		return (command{ctx: context.Background(), output: &output}).generateInterRegionMaterialAt(append([]string{
			"--material-directory", material, "--config", configPath, "--config-sha256", digest,
			"--directory", filepath.Join(root, "interregion"), "--out", out}, extra...), now)
	}
	// The reissued cell claim must be newer than the material's.
	time.Sleep(time.Until(time.Unix(time.Now().Unix()+1, 0)))
	if err := run(strings.Repeat("0", 64)); err == nil {
		t.Fatal("unreviewed configuration accepted")
	}
	if err := run(hex.EncodeToString(sum[:]), "--cell-jwt", filepath.Join(material, "system.jwt")); err == nil {
		t.Fatal("another account's claim accepted as the cell claim")
	}
	if err := run(hex.EncodeToString(sum[:]), "--cell-jwt", filepath.Join(material, "cell.jwt")); err != nil {
		t.Fatal(err)
	}
	public, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var record bootstrapmaterial.InterRegionRecord
	if err := json.Unmarshal(public, &record); err != nil || len(record.LedgerDigest) != 64 ||
		!strings.Contains(output.String(), record.LedgerDigest) {
		t.Fatalf("public inventory = %s, %v", public, err)
	}
	for _, name := range []string{"child-sfo.seed", "interregion-ca.key"} {
		secret, err := os.ReadFile(filepath.Join(root, "interregion", name))
		if err != nil || bytes.Contains(public, secret) {
			t.Fatalf("public inventory carries %s (%v)", name, err)
		}
	}
	base, err := bootstrapmaterial.Load(material)
	if err != nil {
		t.Fatal(err)
	}
	credentialsOut := filepath.Join(root, "controller-a-observability.creds")
	for _, test := range []struct {
		name, directory, want string
		now                   time.Time
		cause                 error
	}{
		{"incomplete", filepath.Join(root, "missing"), "load interregion material", now, bootstrapmaterial.ErrMaterial},
		{"future", filepath.Join(root, "interregion"), "not yet valid", record.IssuedAt.Add(-time.Nanosecond), nil},
		{"expired", filepath.Join(root, "interregion"), "has expired", record.ExpiresAt, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := (command{ctx: t.Context(), output: &output}).runAt([]string{"issue-observability-credentials",
				"--credentials", filepath.Join(material, "controller-a.creds"), "--account-seed", filepath.Join(material, "issuer-cell.seed"),
				"--interregion-directory", test.directory, "--slot", "controller-a", "--cell-account", base.Public.CellAccountNKey,
				"--out", credentialsOut}, test.now)
			if err == nil || !strings.Contains(err.Error(), test.want) || test.cause != nil && !errors.Is(err, test.cause) {
				t.Fatalf("want %q with cause %v, got %v", test.want, test.cause, err)
			}
			if _, err := os.Stat(credentialsOut); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid interregion material created credentials: %v", err)
			}
		})
	}
	issueAt := func(slot, account, outputPath string, at time.Time) error {
		return (command{ctx: t.Context(), output: &output}).runAt([]string{"issue-observability-credentials", "--credentials", filepath.Join(material, "controller-a.creds"),
			"--account-seed", filepath.Join(material, "issuer-cell.seed"), "--interregion-directory", filepath.Join(root, "interregion"),
			"--slot", slot, "--cell-account", account, "--out", outputPath}, at)
	}
	issue := func(slot, account string) error {
		return issueAt(slot, account, credentialsOut, record.IssuedAt)
	}
	immutableOutput := filepath.Join(root, "interregion", "controller-a-observability.creds")
	if err := issueAt("controller-a", base.Public.CellAccountNKey, immutableOutput, record.IssuedAt); err == nil {
		t.Fatal("credential output inside immutable interregion material accepted")
	}
	if _, err := os.Stat(immutableOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("immutable interregion directory changed: %v", err)
	}
	if issue("controller-d", base.Public.CellAccountNKey) == nil {
		t.Fatal("unknown slot accepted")
	}
	if issue("controller-a", base.Public.SystemAccountNKey) == nil {
		t.Fatal("wrong cell account accepted")
	}
	if err := issue("controller-a", base.Public.CellAccountNKey); err != nil {
		t.Fatal(err)
	}
	creds, err := os.ReadFile(credentialsOut)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrapmaterial.CheckControllerObservabilityCredentials(creds, "gru", "controller-a", base.Public.CellAccountNKey, []string{"sfo"}, true); err != nil {
		t.Fatal(err)
	}
	if issue("controller-a", base.Public.CellAccountNKey) == nil {
		t.Fatal("existing credentials overwritten")
	}
	if bytes.Contains(output.Bytes(), creds) {
		t.Fatal("private credentials printed")
	}

	// The hub's block for one slot, at the installed paths.
	block := filepath.Join(root, "interregion-controller-b.json")
	render := func(extra ...string) error {
		return (command{ctx: context.Background(), output: &output}).renderInterRegionConfigAt(append([]string{
			"--material", out, "--slot", "controller-b", "--out", block}, extra...), now)
	}
	if err := render("--receipt", configPath); err == nil {
		t.Fatal("a receipt without the parent's inventory was accepted")
	}
	if err := render(); err != nil {
		t.Fatal(err)
	}
	rendered, err := os.ReadFile(block)
	if err != nil {
		t.Fatal(err)
	}
	var interregion natscell.InterRegion
	if err := json.Unmarshal(rendered, &interregion, json.RejectUnknownMembers(true)); err != nil ||
		interregion.Validate("gru") != nil || interregion.Listen == nil ||
		interregion.Listen.TLS.CertFile != "/var/lib/terrascale-orchestrator-secrets/interregion-tls-controller-b-cert.pem" {
		t.Fatalf("rendered block %s: %v", rendered, err)
	}
	digest := sha256.Sum256(rendered)
	if !strings.Contains(output.String(), hex.EncodeToString(digest[:])) {
		t.Fatalf("output %q lacks the block digest", output.String())
	}
}
