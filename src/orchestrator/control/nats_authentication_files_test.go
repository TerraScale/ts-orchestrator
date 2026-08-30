package control

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"
)

func TestNatsAuthenticationFilesFromNKeyFileUsesNKeyIdentity(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	firstSeed := writeNatsAuthenticationTestSeed(t, filepath.Join(directory, "first.seed"))
	secondSeed := writeNatsAuthenticationTestSeed(t, filepath.Join(directory, "second.seed"))

	first, err := NatsAuthenticationFilesFromNKeyFile(firstSeed)
	if err != nil {
		t.Fatalf("first authentication: %v", err)
	}
	second, err := NatsAuthenticationFilesFromNKeyFile(secondSeed)
	if err != nil {
		t.Fatalf("second authentication: %v", err)
	}

	if first.PublicKey == *first.NKeyFile {
		t.Fatal("public key must not be the seed file path")
	}
	if first.PublicKey == second.PublicKey {
		t.Fatal("different NKey seed files must have different public identities")
	}

	copyPath := filepath.Join(directory, "copy.seed")
	seedBytes, err := os.ReadFile(firstSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seedBytes)
	if err := os.WriteFile(copyPath, seedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	copyAuth, err := NatsAuthenticationFilesFromNKeyFile(copyPath)
	if err != nil {
		t.Fatalf("copied authentication: %v", err)
	}
	if copyAuth.PublicKey != first.PublicKey {
		t.Fatal("copied NKey seed files must have the same public identity")
	}
	if same, err := NatsCredentialFile.SameIdentity(*first.NKeyFile, *copyAuth.NKeyFile); err != nil || !same {
		t.Fatalf("same identity = %v, err = %v", same, err)
	}
	if same, err := NatsCredentialFile.SameIdentity(*first.NKeyFile, *second.NKeyFile); err != nil || same {
		t.Fatalf("different identity = %v, err = %v", same, err)
	}
}

func writeNatsAuthenticationTestSeed(t *testing.T, path string) string {
	t.Helper()
	pair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pair.Wipe)
	seed, err := pair.Seed()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(seed) })
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
