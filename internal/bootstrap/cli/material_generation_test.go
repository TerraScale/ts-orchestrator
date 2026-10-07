package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// The owner signs generation 1, then a CA rollover as generation 2 on the
// chain it wrote; material that differs from its pins, a missing or wrong
// chain and a mismatched root key are refused, and no output is written.
func TestSignMaterialGeneration(t *testing.T) {
	// The fixture's NATS JWTs are always issued now (jwt.Encode stamps iat
	// itself), so the check runs on the real clock.
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	publicDER, _ := x509.MarshalPKIXPublicKey(rootPublic)
	privateDER, _ := x509.MarshalPKCS8PrivateKey(rootPrivate)
	rootPath, keyPath := filepath.Join(directory, "root.pub"), filepath.Join(directory, "root.key")
	writeFixture(t, rootPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)
	writeFixture(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600)
	expected := bootstrap.MaterialGenerationExpectation{DeploymentID: "gru-1-deployment", Environment: "production",
		ClusterID: "gru-1", Cell: "GRU", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}
	stage := func(name string, material generationtest.Material, generation bootstrap.MaterialGeneration) (string, string) {
		t.Helper()
		materialDir := filepath.Join(directory, name)
		if err := os.Mkdir(materialDir, 0o700); err != nil {
			t.Fatal(err)
		}
		for file, data := range material.Files {
			writeFixture(t, filepath.Join(materialDir, file), data, 0o600)
		}
		candidate, err := trust.EncodePayload(generation)
		if err != nil {
			t.Fatal(err)
		}
		candidatePath := filepath.Join(directory, name+".json")
		writeFixture(t, candidatePath, candidate, 0o600)
		return candidatePath, materialDir
	}
	var output bytes.Buffer
	sign := func(candidate, material, chain, out string, key string) error {
		args := []string{"sign-material-generation", "--candidate", candidate, "--material", material,
			"--root-key", rootPath, "--signing-key", key, "--out", out}
		if chain != "" {
			args = append(args, "--chain", chain)
		}
		return (command{ctx: context.Background(), output: &output}).runAt(args, now)
	}

	first := generationtest.New(t, now)
	firstCandidate, firstDir := stage("g1", first, first.Generation(expected, 1, ""))
	chainOne := filepath.Join(directory, "chain-1.json")
	if err := sign(firstCandidate, firstDir, "", chainOne, keyPath); err != nil {
		t.Fatal(err)
	}
	wire, _ := os.ReadFile(chainOne)
	chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
	if err != nil {
		t.Fatal(err)
	}
	roots, _ := trust.ParseKeyring(rootPublic)
	verified, err := bootstrap.VerifyMaterialGenerationChain(chain, roots, expected, now)
	if err != nil || !strings.Contains(output.String(), "signed material generation 1 cell=GRU fingerprint="+verified[0].Fingerprint()) {
		t.Fatalf("generation 1: %v\n%s", err, output.String())
	}
	if want := now.AddDate(1, 0, 0).Add(-time.Hour); !verified[0].ExpiresAt().Equal(want) {
		t.Fatalf("generation 1 expires %s, want the first pinned expiry %s", verified[0].ExpiresAt(), want)
	}

	rollover := generationtest.Rollover(t, now, first)
	secondCandidate, secondDir := stage("g2", rollover, rollover.Generation(expected, 2, verified[0].Fingerprint()))
	tamperedDir := filepath.Join(directory, "g2-tampered")
	if err := os.CopyFS(tamperedDir, os.DirFS(secondDir)); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(tamperedDir, "cell.jwt"), first.Files["cell.jwt"], 0o600)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	otherDER, _ := x509.MarshalPKCS8PrivateKey(otherKey)
	otherKeyPath := filepath.Join(directory, "other.key")
	writeFixture(t, otherKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}), 0o600)
	refused := filepath.Join(directory, "refused.json")
	for name, args := range map[string][5]string{
		"generation 2 without its chain":      {secondCandidate, secondDir, "", refused, keyPath},
		"material that differs from its pins": {secondCandidate, tamperedDir, chainOne, refused, keyPath},
		"a key that is not the root":          {secondCandidate, secondDir, chainOne, refused, otherKeyPath},
		"generation 1 on a chain":             {firstCandidate, firstDir, chainOne, refused, keyPath},
	} {
		if err := sign(args[0], args[1], args[2], args[3], args[4]); err == nil {
			t.Errorf("signed %s", name)
		}
		if _, err := os.Stat(refused); err == nil {
			t.Fatalf("%s left output behind", name)
		}
	}
	chainTwo := filepath.Join(directory, "chain-2.json")
	if err := sign(secondCandidate, secondDir, chainOne, chainTwo, keyPath); err != nil {
		t.Fatal(err)
	}
	wire, _ = os.ReadFile(chainTwo)
	if chain, err = bootstrap.DecodeMaterialGenerationChain(wire); err != nil {
		t.Fatal(err)
	}
	if verified, err := bootstrap.VerifyMaterialGenerationChain(chain, roots, expected, now); err != nil || len(verified) != 2 {
		t.Fatalf("the rollover extends the chain: %v", err)
	}
	if err := sign(secondCandidate, secondDir, chainOne, chainTwo, keyPath); err == nil {
		t.Fatal("an existing chain file was overwritten")
	}

	// Schema 2 (TS-668) extends the chain; every controller config the
	// candidate pins must be in the material directory.
	upgraded := rollover.SchemaTwo(t).WithoutIssuers(t).InterRegion(t, now, expected.ControllerSlots)
	previous, _ := trust.Fingerprint(chain[1])
	thirdCandidate, thirdDir := stage("g3", upgraded, upgraded.Generation(expected, 3, previous))
	unconfiguredDir := filepath.Join(directory, "g3-unconfigured")
	if err := os.CopyFS(unconfiguredDir, os.DirFS(thirdDir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(unconfiguredDir, "controller-controller-b.json")); err != nil {
		t.Fatal(err)
	}
	if err := sign(thirdCandidate, unconfiguredDir, chainTwo, refused, keyPath); err == nil {
		t.Fatal("signed without a pinned controller config")
	}
	chainThree := filepath.Join(directory, "chain-3.json")
	if err := sign(thirdCandidate, thirdDir, chainTwo, chainThree, keyPath); err != nil {
		t.Fatal(err)
	}
	wire, _ = os.ReadFile(chainThree)
	if chain, err = bootstrap.DecodeMaterialGenerationChain(wire); err != nil {
		t.Fatal(err)
	}
	if verified, err := bootstrap.VerifyMaterialGenerationChain(chain, roots, expected, now); err != nil || len(verified) != 3 {
		t.Fatalf("schema 2 extends the chain: %v", err)
	}
}
