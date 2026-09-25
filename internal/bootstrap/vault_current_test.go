package bootstrap

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type advancingSecretReader struct {
	bundle    SecretBundle
	afterRead func()
	calls     int
}

func (reader *advancingSecretReader) GetSecretBundle(context.Context, string, int64) (SecretBundle, error) {
	reader.calls++
	if reader.afterRead != nil {
		reader.afterRead()
	}
	return reader.bundle, nil
}

func TestVaultRechecksCurrentProofBeforeFetchAndInstall(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	manifest := authority.verifyManifest(t, "seed-a", authority.manifest)
	facts := authority.facts(manifest, "seed-a")
	envelope, err := SignSeedReceipt(manifest, facts, authority.now.Add(-time.Minute),
		authority.now.Add(5*time.Minute), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := VerifySeedReceipt(envelope, manifest, authority.roots, facts, authority.now, authority.policy)
	if err != nil {
		t.Fatal(err)
	}
	reference := authority.manifest.Secrets[0]
	reader := &advancingSecretReader{bundle: SecretBundle{
		SecretOCID: reference.SecretOCID, VersionNumber: reference.VersionNumber,
		ContentType: "BASE64", ContentBase64: base64.StdEncoding.EncodeToString(authority.regionalData),
	}}
	now := authority.now
	vault := &Vault{reader: reader, now: func() time.Time { return now }}
	expired := errors.New("current bootstrap proof expired")
	checks := 0
	verifyCurrent := func(at time.Time) error {
		checks++
		if !at.Before(authority.now.Add(time.Minute)) {
			return expired
		}
		return nil
	}

	now = authority.now.Add(2 * time.Hour)
	if err := vault.MaterializeCurrent(t.Context(), manifest, receipt, reference, t.TempDir(), verifyCurrent); !errors.Is(err, expired) || reader.calls != 0 {
		t.Fatalf("expired proof fetched Vault secret: calls=%d err=%v", reader.calls, err)
	}

	now = authority.now
	reader.afterRead = func() { now = authority.now.Add(2 * time.Hour) }
	directory := t.TempDir()
	if err := vault.MaterializeCurrent(t.Context(), manifest, receipt, reference, directory, verifyCurrent); !errors.Is(err, expired) || reader.calls != 1 {
		t.Fatalf("proof expired during fetch was installed: calls=%d err=%v", reader.calls, err)
	}
	if _, err := os.Stat(filepath.Join(directory, reference.TargetFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired proof left installed secret: %v", err)
	}

	now = authority.now
	reader.afterRead = nil
	if err := vault.MaterializeCurrent(t.Context(), manifest, receipt, reference, directory, verifyCurrent); err != nil {
		t.Fatalf("current proof denied exact secret: %v", err)
	}
	if checks != 5 || reader.calls != 2 {
		t.Fatalf("current proof was not checked at both effect boundaries: checks=%d reads=%d", checks, reader.calls)
	}
}
