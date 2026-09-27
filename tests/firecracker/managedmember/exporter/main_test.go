package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthoritySeedRequiresProtectedFileAndIndependentPin(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	private := ed25519.NewKeyFromSeed(seed)
	publicHash := sha256.Sum256(private.Public().(ed25519.PublicKey))
	path := filepath.Join(t.TempDir(), "authority.seed")
	if err := os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := options{authoritySeedFile: path, authorityPublicSHA256: hex.EncodeToString(publicHash[:])}
	loaded, err := loadAuthoritySigner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Equal(private) {
		t.Fatal("loaded authority key differs from pinned seed")
	}
	clear(loaded)
	clear(private)

	badPin := cfg
	badPin.authorityPublicSHA256 = hex.EncodeToString(make([]byte, sha256.Size))
	if _, err := loadAuthoritySigner(badPin); err == nil {
		t.Fatal("accepted authority seed with mismatched public key pin")
	}

	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthoritySigner(cfg); err == nil {
		t.Fatal("accepted group-readable authority seed")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "authority.link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	cfg.authoritySeedFile = link
	if _, err := loadAuthoritySigner(cfg); err == nil {
		t.Fatal("accepted symlinked authority seed")
	}
}

func TestEmptyCatalogSchemaDigest(t *testing.T) {
	_, digest, err := emptyCatalog()
	if err != nil {
		t.Fatal(err)
	}
	const expected = "b659dc901eba8b60728633fc4cbd0d532e179f2307784ba518b5a1baffb9fdbb"
	if got := hex.EncodeToString(digest[:]); got != expected {
		t.Fatalf("empty schema digest = %s, want %s", got, expected)
	}
}
