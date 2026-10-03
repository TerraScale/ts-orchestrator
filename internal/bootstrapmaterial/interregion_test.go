package bootstrapmaterial

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/jwt/v2"
)

func interRegionFixture(t *testing.T) (string, string, InterRegionConfig, time.Time) {
	t.Helper()
	root := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	material := filepath.Join(root, "material")
	if _, err := Generate(material, testConfig(), now); err != nil {
		t.Fatal(err)
	}
	topology := natscell.HubAndSpoke("gru", []string{"sfo", "fra"}).WithSpokeParent("fra", "sfo")
	return material, filepath.Join(root, "interregion"), InterRegionConfig{Topology: topology, ListenPort: 7422}, now
}

func TestInterRegionMaterialMatchesTheContract(t *testing.T) {
	material, directory, cfg, now := interRegionFixture(t)
	record, err := GenerateInterRegion(material, directory, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadInterRegion(directory)
	if err != nil || loaded.LedgerDigest != record.LedgerDigest || len(loaded.LedgerDigest) != 64 {
		t.Fatalf("load = %+v, %v", loaded, err)
	}
	names := make([]string, 0, len(record.Files))
	for _, file := range record.Files {
		names = append(names, file.Name)
	}
	if !slices.Equal(names, []string{"cell-interregion.jwt", "child-sfo.seed", "interregion.jwt", "leaf-sfo.creds",
		"system-interregion.jwt"}) {
		t.Fatalf("files = %v", names)
	}
	base, err := Load(material)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) *jwt.AccountClaims {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		claim, err := jwt.DecodeAccountClaims(string(raw))
		if err != nil || claim.Issuer != base.Public.OperatorNKey {
			t.Fatalf("%s = %+v, %v", name, claim, err)
		}
		return claim
	}
	interregion, cell, system := read("interregion.jwt"), read("cell-interregion.jwt"), read("system-interregion.jwt")
	contract := natscell.InterRegionContract{Cell: "gru", Peers: []string{"fra", "sfo"}, GlobalHome: "gru",
		Subtrees: map[string][]string{"sfo": {"fra", "sfo"}}}
	if err := contract.VerifyClaims(system, cell, interregion, 1); err != nil {
		t.Fatalf("issued claims fail the startup check: %v", err)
	}
	if !interregion.Limits.DisallowBearer || cell.Limits.LeafNodeConn != 0 || system.Limits.LeafNodeConn != 0 ||
		cell.Subject != base.Public.CellAccountNKey || len(cell.SigningKeys) != 1 ||
		interregion.Subject != record.InterRegionAccountNKey || interregion.Expires != base.ExpiresAt.Unix() {
		t.Fatalf("claims: interregion %+v cell %+v", interregion.Limits, cell.Limits)
	}
	if err := natscell.ValidateLeafCredentials(filepath.Join(directory, "leaf-sfo.creds"),
		record.InterRegionAccountNKey); err != nil {
		t.Fatal(err)
	}

	// Immutable: the same request returns the same material; any other is refused.
	again, err := GenerateInterRegion(material, directory, cfg, now.Add(time.Minute))
	if err != nil || again.LedgerDigest != record.LedgerDigest {
		t.Fatalf("regenerate = %v", err)
	}
	other := cfg
	other.Topology = natscell.HubAndSpoke("gru", []string{"sfo", "fra"})
	if _, err := GenerateInterRegion(material, directory, other, now); err == nil {
		t.Fatal("material for another topology replaced existing material")
	}

	// Any changed byte fails loading.
	path := filepath.Join(directory, "leaf-sfo.creds")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body[:len(body)-1], 'x'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadInterRegion(directory); err == nil {
		t.Fatal("tampered interregion material loaded")
	}
}

func TestInterRegionConfigNeedsAPortExactlyWithChildren(t *testing.T) {
	material, directory, cfg, now := interRegionFixture(t)
	for name, mutate := range map[string]func(*InterRegionConfig){
		"no port with children": func(c *InterRegionConfig) { c.ListenPort = 0 },
		"port out of range":     func(c *InterRegionConfig) { c.ListenPort = 70000 },
		"region not in tree":    func(c *InterRegionConfig) { c.Topology = natscell.HubAndSpoke("sfo", []string{"fra"}) },
		"cyclic tree": func(c *InterRegionConfig) {
			c.Topology = natscell.LeafTopology{Hub: "gru", Parents: map[string]string{"sfo": "fra", "fra": "sfo"}}
		},
		"port on a leaf region": func(c *InterRegionConfig) {
			c.Topology = natscell.HubAndSpoke("sfo", []string{"gru"})
		},
	} {
		candidate := cfg
		mutate(&candidate)
		if _, err := GenerateInterRegion(material, directory+"-"+strings.ReplaceAll(name, " ", "-"), candidate, now); err == nil {
			t.Errorf("%s: interregion material issued", name)
		}
	}
}

// TestWideTreeMaterialIsRefusedBeforeWriting pins the 64 KiB JWT limit: a
// hub with 63 direct children needs a larger interregion account than the
// server reads, so nothing is written, while a narrower tree still fits.
func TestWideTreeMaterialIsRefusedBeforeWriting(t *testing.T) {
	material, directory, cfg, now := interRegionFixture(t)
	spokes := make([]string, 0, 63)
	for index := range 63 {
		spokes = append(spokes, "r"+strings.Repeat("x", index/26)+string(rune('a'+index%26)))
	}
	cfg.Topology = natscell.HubAndSpoke("gru", spokes)
	if _, err := GenerateInterRegion(material, directory, cfg, now); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("wide tree = %v", err)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("refused material left a directory: %v", err)
	}
	cfg.Topology = natscell.HubAndSpoke("gru", spokes[:8])
	if _, err := GenerateInterRegion(material, directory, cfg, now); err != nil {
		t.Fatalf("eight children = %v", err)
	}
	if _, err := LoadInterRegion(directory); err != nil {
		t.Fatal(err)
	}
}

func receipt(t *testing.T, mutate func(map[string]any)) ([]byte, string) {
	t.Helper()
	document := map[string]any{
		"schema_version": 1, "kind": PrivatePeerReceiptKind, "status": PrivatePeerReceiptPass,
		"readback_expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		"allowed_tcp_ports":   []int{4222, 7422},
		"cells": map[string]any{"gru": map[string]any{"subnet_cidr": "10.251.0.0/24", "vcn_id": "x"},
			"sfo": map[string]any{"subnet_cidr": "10.252.0.0/24"}},
		"dataplane_reachability": "not_tested",
	}
	if mutate != nil {
		mutate(document)
	}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	return wire, hex.EncodeToString(sum[:])
}

func TestLeafRemoteURLsComeOnlyFromTheReviewedReceipt(t *testing.T) {
	material, directory, cfg, now := interRegionFixture(t)
	parent, err := GenerateInterRegion(material, directory, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	// The child's private copy of its credentials.
	body, err := os.ReadFile(filepath.Join(directory, "leaf-sfo.creds"))
	if err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(t.TempDir(), "gru-leaf.creds")
	if err := os.WriteFile(creds, body, 0o600); err != nil {
		t.Fatal(err)
	}
	tls := natscell.TLSFiles{CAFile: "ca.pem", CertFile: "cert.pem", KeyFile: "key.pem"}
	wire, reviewed := receipt(t, nil)
	remote, err := LeafRemote(parent, "sfo", wire, reviewed, creds, tls, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if remote.Peer != "gru" || remote.PeerAccount != parent.InterRegionAccountNKey || !slices.Equal(remote.URLs,
		[]string{"nats-leaf://10.251.0.10:7422", "nats-leaf://10.251.0.11:7422", "nats-leaf://10.251.0.12:7422"}) {
		t.Fatalf("remote = %+v", remote)
	}
	cases := map[string]func() ([]byte, string, string, string){
		"unreviewed receipt": func() ([]byte, string, string, string) {
			other, _ := receipt(t, func(d map[string]any) { d["dataplane_reachability"] = "ok" })
			return other, reviewed, "sfo", creds
		},
		"failed readback": func() ([]byte, string, string, string) {
			w, d := receipt(t, func(d map[string]any) { d["status"] = "configuration_readback_fail" })
			return w, d, "sfo", creds
		},
		"expired readback": func() ([]byte, string, string, string) {
			w, d := receipt(t, func(d map[string]any) {
				d["readback_expires_at"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
			})
			return w, d, "sfo", creds
		},
		"leaf port not allowed": func() ([]byte, string, string, string) {
			w, d := receipt(t, func(d map[string]any) { d["allowed_tcp_ports"] = []int{4222} })
			return w, d, "sfo", creds
		},
		"controllers outside the peered subnet": func() ([]byte, string, string, string) {
			w, d := receipt(t, func(d map[string]any) {
				d["cells"].(map[string]any)["gru"] = map[string]any{"subnet_cidr": "10.9.0.0/24"}
			})
			return w, d, "sfo", creds
		},
		"another peering": func() ([]byte, string, string, string) {
			w, d := receipt(t, func(d map[string]any) {
				cells := d["cells"].(map[string]any)
				cells["fra"] = cells["sfo"]
				delete(cells, "sfo")
			})
			return w, d, "sfo", creds
		},
		"child that does not dial the parent": func() ([]byte, string, string, string) {
			return wire, reviewed, "fra", creds
		},
		"credentials not issued by the parent": func() ([]byte, string, string, string) {
			forged := filepath.Join(t.TempDir(), "forged.creds")
			if err := os.WriteFile(forged, append(body[:len(body)-2], 'x', '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			return wire, reviewed, "sfo", forged
		},
	}
	for name, input := range cases {
		document, digest, child, path := input()
		if _, err := LeafRemote(parent, child, document, digest, path, tls, time.Now()); err == nil {
			t.Errorf("%s: leaf remote accepted", name)
		}
	}
}
