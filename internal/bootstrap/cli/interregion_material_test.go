package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
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
		Region: "sa-saopaulo-1", Cell: "gru", DeploymentID: "alpha-20260927", ClusterID: "alpha-gru",
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
	run := func(digest string) error {
		return (command{ctx: context.Background(), output: &output}).generateInterRegionMaterialAt([]string{
			"--material-directory", material, "--config", configPath, "--config-sha256", digest,
			"--directory", filepath.Join(root, "interregion"), "--out", out}, now)
	}
	if err := run(strings.Repeat("0", 64)); err == nil {
		t.Fatal("unreviewed configuration accepted")
	}
	if err := run(hex.EncodeToString(sum[:])); err != nil {
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
	seed, err := os.ReadFile(filepath.Join(root, "interregion", "child-sfo.seed"))
	if err != nil || bytes.Contains(public, seed) {
		t.Fatalf("public inventory carries the child signing seed (%v)", err)
	}
}
