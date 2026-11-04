package bootstrap_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

var generationNow = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func generationExpectation() bootstrap.MaterialGenerationExpectation {
	return bootstrap.MaterialGenerationExpectation{DeploymentID: "0000000000YY15F5R431V5JPJ9", Environment: "production",
		ClusterID: "00000000006GRRF84JEVN9TX7M", Cell: "GRU", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}
}

func signGeneration(t *testing.T, generation bootstrap.MaterialGeneration, key ed25519.PrivateKey) trust.Envelope {
	t.Helper()
	envelope, err := bootstrap.SignMaterialGeneration(generation, generationNow, generationNow.AddDate(0, 6, 0), key)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func keyring(t *testing.T, keys ...ed25519.PublicKey) trust.Keyring {
	t.Helper()
	roots, err := trust.ParseKeyring(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return roots
}

// After a root rotation the chain is extended under the new root alone,
// and a retired root can no longer extend it.
func TestMaterialGenerationChainAcrossRootRotation(t *testing.T) {
	oldPublic, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	newPublic, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	expected := generationExpectation()
	material := generationtest.New(t, generationNow)
	first := signGeneration(t, material.Generation(expected, 1, ""), oldPrivate)
	verified, err := bootstrap.VerifyMaterialGenerationChain([]trust.Envelope{first}, keyring(t, oldPublic), expected, generationNow)
	if err != nil {
		t.Fatal(err)
	}
	next := generationtest.Rollover(t, generationNow, material).Generation(expected, 2, verified[0].Fingerprint())
	current := keyring(t, newPublic)
	if _, err := bootstrap.VerifyMaterialGenerationChain([]trust.Envelope{first, signGeneration(t, next, newPrivate)}, current,
		expected, generationNow); err != nil {
		t.Fatalf("the new root extends a chain the old root began: %v", err)
	}
	retired := []trust.Envelope{first, signGeneration(t, next, oldPrivate)}
	if _, err := bootstrap.VerifyMaterialGenerationChain(retired, current, expected, generationNow); err == nil {
		t.Fatal("a retired root extended the chain")
	}
}
