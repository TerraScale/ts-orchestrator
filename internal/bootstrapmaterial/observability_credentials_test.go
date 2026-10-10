package bootstrapmaterial

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func TestOfflineObservabilityCredentialsPreserveControllerIdentity(t *testing.T) {
	now := time.Now()
	directory := filepath.Join(t.TempDir(), "material")
	cfg := testConfig()
	record, err := Generate(directory, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(filepath.Join(directory, "controller-a.creds"))
	signerSeed, _ := os.ReadFile(filepath.Join(directory, "issuer-cell.seed"))
	decode := func(creds []byte) *jwt.UserClaims {
		t.Helper()
		raw, err := jwt.ParseDecoratedJWT(creds)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := jwt.DecodeUserClaims(raw)
		if err != nil {
			t.Fatal(err)
		}
		return claim
	}
	before := decode(current)
	if CheckControllerObservabilityCredentials(current, "gru", "controller-a", record.Public.CellAccountNKey, []string{"sfo"}, true) == nil {
		t.Fatal("founding credentials unexpectedly admit peer telemetry")
	}
	creds, err := IssueControllerObservabilityCredentials(current, signerSeed, "gru", "controller-a", record.Public.CellAccountNKey, []string{"sfo"}, true)
	if err != nil {
		t.Fatal(err)
	}
	after := decode(creds)
	for _, peers := range [][]string{nil, {"fra"}} {
		narrowed, err := IssueControllerObservabilityCredentials(creds, signerSeed, "gru", "controller-a", record.Public.CellAccountNKey, peers, true)
		if err != nil {
			t.Fatalf("replace existing peers with %v: %v", peers, err)
		}
		claim := decode(narrowed)
		if claim.Subject != before.Subject || claim.Expires != before.Expires ||
			slices.Contains(claim.Pub.Allow, "ts.orch.v1.sfo.obs.region") ||
			slices.Contains(claim.Pub.Allow, "ts.orch.v1.sfo.obs.decisions") {
			t.Fatal("peer replacement retained removed grants or changed the controller identity")
		}
	}
	if err := CheckControllerObservabilityCredentials(creds, "gru", "controller-a", record.Public.CellAccountNKey, []string{"sfo"}, false); err == nil {
		t.Fatal("home-region global publish grants accepted for a non-home region")
	}
	if issued, err := IssueControllerObservabilityCredentials(current, signerSeed, "gru", "controller-a", record.Public.CellAccountNKey, []string{"sfo"}, false); err != nil {
		t.Fatalf("topology change to non-home: %v", err)
	} else if err := CheckControllerObservabilityCredentials(issued, "gru", "controller-a", record.Public.CellAccountNKey, []string{"sfo"}, false); err != nil {
		t.Fatalf("non-home grants were not narrowed to its topology: %v", err)
	}
	if after.Subject != before.Subject || after.Expires != before.Expires || !reflect.DeepEqual(after.Resp, before.Resp) ||
		!slices.Contains(after.Sub.Allow, protocol.ObservabilityGrant("gru")) {
		t.Fatal("credential rotation changed user, expiry or bounded response grant")
	}
	for _, grant := range before.Pub.Allow {
		if !slices.Contains(after.Pub.Allow, grant) {
			t.Fatalf("lost publish %s", grant)
		}
	}
	for _, grant := range before.Sub.Allow {
		if !slices.Contains(after.Sub.Allow, grant) {
			t.Fatalf("lost subscription %s", grant)
		}
	}
	if len(after.Pub.Allow) != len(before.Pub.Allow)+2 || len(after.Sub.Allow) != len(before.Sub.Allow) {
		t.Fatal("credential rotation added unrelated grants")
	}
	for name, change := range map[string]func(*jwt.UserClaims){
		"wildcard peer":       func(c *jwt.UserClaims) { c.Pub.Allow.Add("ts.orch.v1.sfo.obs.>") },
		"remote snapshot":     func(c *jwt.UserClaims) { c.Pub.Allow.Add("ts.orch.v1.sfo.obs.snapshot") },
		"remote mutation":     func(c *jwt.UserClaims) { c.Pub.Allow.Add(protocol.PlacementApplySubject("sfo")) },
		"missing local grant": func(c *jwt.UserClaims) { c.Sub.Allow.Remove(protocol.ObservabilityGrant("gru")) },
		"missing peer":        func(c *jwt.UserClaims) { c.Pub.Allow.Remove("ts.orch.v1.sfo.obs.region") },
		"wrong account":       func(c *jwt.UserClaims) { c.IssuerAccount = record.Public.SystemAccountNKey },
		"infinite expiry":     func(c *jwt.UserClaims) { c.Expires = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			claim := decode(creds)
			change(claim)
			signer, _ := nkeys.FromSeed(bytes.TrimSpace(signerSeed))
			defer signer.Wipe()
			raw, err := claim.Encode(signer)
			if err != nil {
				t.Fatal(err)
			}
			user, _ := jwt.ParseDecoratedUserNKey(creds)
			defer user.Wipe()
			seed, _ := user.Seed()
			defer clear(seed)
			changed, _ := jwt.FormatUserConfig(raw, seed)
			if CheckControllerObservabilityCredentials(changed, "gru", "controller-a", record.Public.CellAccountNKey, []string{"sfo"}, true) == nil {
				t.Fatal("invalid controller telemetry credentials accepted")
			}
		})
	}
	for _, peer := range []string{"global", "sfo-", "sfo--north"} {
		if issued, err := IssueControllerObservabilityCredentials(current, signerSeed, "gru", "controller-a", record.Public.CellAccountNKey, []string{peer}, true); err == nil || len(issued) != 0 {
			t.Fatalf("invalid peer %q issued credentials: %v", peer, err)
		}
	}
	for _, peers := range [][]string{{"*"}, {"global"}, {"sfo-"}, {"sfo--north"}, {"sfo", "sfo"}, {"gru"}, {"fra"}} {
		if CheckControllerObservabilityCredentials(creds, "gru", "controller-a", record.Public.CellAccountNKey, peers, true) == nil {
			t.Fatalf("unreviewed peers %v accepted", peers)
		}
	}
	if CheckControllerObservabilityCredentials(creds, "gru", "controller-b", record.Public.CellAccountNKey, []string{"sfo"}, true) == nil {
		t.Fatal("another slot's credentials accepted")
	}
	output := filepath.Join(t.TempDir(), "controller-a.creds")
	write := func() error {
		return WriteControllerObservabilityCredentials(filepath.Join(directory, "controller-a.creds"), filepath.Join(directory, "issuer-cell.seed"), output, "gru", "controller-a", record.Public.CellAccountNKey, []string{"sfo"}, true)
	}
	if err := write(); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(output)
	if info.Mode().Perm() != 0o600 {
		t.Fatal("output is not owner-only")
	}
	if write() == nil {
		t.Fatal("existing credentials replaced")
	}
	unchanged, _ := os.ReadFile(filepath.Join(directory, "controller-a.creds"))
	if !bytes.Equal(current, unchanged) {
		t.Fatal("founding material changed")
	}
}
