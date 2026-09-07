package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteLifecycleRestoreGrantFixture(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	now := time.UnixMilli(1800000000000).UTC()
	lease := now.Add(time.Minute)
	g := lifecycleOperationGrant{Version: 1, Domain: lifecycleGrantDomain, Environment: "production", Tenant: "tenant", Project: "project", Database: "database", Region: "GRU", Member: "member", Action: "restore_to_target", OperationID: "restore-op-member", AcceptedProofDigest: hex.EncodeToString(make([]byte, 32)), AcceptedPlacementRevision: 9, AuthorityEpoch: 7, AuthorityLease: "lease-7", IssuedAtUnixMillis: now.UnixMilli(), ExpiresAtUnixMillis: now.Add(10 * time.Second).UnixMilli(), AcceptedRestoreRequestDigest: restoreRequestDigest("source-owner", "source-database", "recovery-point", "recovery-digest", "target-owner", "target-database", "journal-cut", 7, 1)}
	signed, err := issueLifecycleOperationGrant("proof", key, func() error { return nil }, g, now, lease, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("testdata")
	fixture := filepath.Join(dir, "lifecycle-restore-grant.json")
	if os.Getenv("UPDATE_LIFECYCLE_FIXTURES") == "1" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture, b, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "lifecycle-restore-grant-public.key"), []byte(hex.EncodeToString(key.Public().(ed25519.PublicKey))), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, b) {
		t.Fatal("lifecycle grant fixture differs from producer output; set UPDATE_LIFECYCLE_FIXTURES=1 to regenerate")
	}
}
