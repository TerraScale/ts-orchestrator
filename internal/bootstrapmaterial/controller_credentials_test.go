package bootstrapmaterial

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestCheckControllerCredentialsRequiresExactRoleGrants(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	record, err := Generate(directory, testConfig(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(filepath.Join(directory, "controller-a.creds"))
	if err != nil {
		t.Fatal(err)
	}
	signerSeed, err := os.ReadFile(filepath.Join(directory, "issuer-cell.seed"))
	if err != nil {
		t.Fatal(err)
	}
	account := record.Public.CellAccountNKey
	if err := CheckControllerCredentials(current, "gru", "controller-a", account); err != nil {
		t.Fatalf("founding credentials refused: %v", err)
	}
	reissue := func(change func(*jwt.UserClaims)) []byte {
		t.Helper()
		raw, err := jwt.ParseDecoratedJWT(current)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := jwt.DecodeUserClaims(raw)
		if err != nil {
			t.Fatal(err)
		}
		change(claim)
		signer, err := nkeys.FromSeed(bytes.TrimSpace(signerSeed))
		if err != nil {
			t.Fatal(err)
		}
		defer signer.Wipe()
		user, err := jwt.ParseDecoratedUserNKey(current)
		if err != nil {
			t.Fatal(err)
		}
		defer user.Wipe()
		creds, err := credentials(claim, signer, user)
		if err != nil {
			t.Fatal(err)
		}
		return creds
	}
	for name, change := range map[string]func(*jwt.UserClaims){
		"extra publish grant": func(c *jwt.UserClaims) { c.Pub.Allow.Add("ts.orch.v1.sfo.obs.region") },
		"missing pattern grant": func(c *jwt.UserClaims) {
			c.Pub.Allow.Remove(protocol.AnyRegionObservabilitySubject(protocol.ObservabilityRegionLeaf))
		},
		"wrong account": func(c *jwt.UserClaims) { c.IssuerAccount = record.Public.SystemAccountNKey },
	} {
		t.Run(name, func(t *testing.T) {
			if CheckControllerCredentials(reissue(change), "gru", "controller-a", account) == nil {
				t.Fatal("invalid controller credentials accepted")
			}
		})
	}
}
