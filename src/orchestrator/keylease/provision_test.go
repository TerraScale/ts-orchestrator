package keylease

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProvisionCommitsAllRegionsAndRetryPreservesKey(t *testing.T) {
	config, catalog := fixture(t)
	if err := WriteCatalog(config.CatalogPath, Catalog{Version: 1}); err != nil {
		t.Fatal(err)
	}
	e := catalog.Entries[0]
	target := ProvisionTarget{Binding: e.Binding, CryptoEndpoint: e.CryptoEndpoint, KEKID: e.KEKID, KEKVersionID: e.KEKVersionID, LeaseSeconds: e.LeaseSeconds, NotAfter: e.NotAfter}
	second := target
	second.Binding.Region = "FRA"
	second.CryptoEndpoint = "https://fixture-crypto.kms.eu-frankfurt-1.oraclecloud.com"
	targets := []ProvisionTarget{target, second}
	calls := 0
	var first []byte
	wrap := func(_ context.Context, target ProvisionTarget, key []byte) (string, error) {
		calls++
		if first == nil {
			first = bytes.Clone(key)
		} else if !bytes.Equal(first, key) {
			t.Error("selected regions received different DEKs")
		}
		return "wrapped-" + target.Binding.Region, nil
	}
	if err := provision(t.Context(), config.CatalogPath, targets, wrap); err != nil {
		t.Fatal(err)
	}
	clear(first)
	if calls != 2 {
		t.Fatal("not every selected region wrapped")
	}
	stored, err := ReadCatalog(config.CatalogPath)
	if err != nil || len(stored.Entries) != 2 {
		t.Fatal("not every selected region persisted")
	}
	if err := provision(t.Context(), config.CatalogPath, targets, wrap); err != nil || calls != 2 {
		t.Fatal("retry generated new keys")
	}
	if err := provision(t.Context(), config.CatalogPath, targets[:1], wrap); err == nil {
		t.Fatal("retry narrowed immutable region set")
	}
	// A partial new region cannot turn a historical version into another key.
	third := target
	third.Binding.Region = "SFO"
	third.CryptoEndpoint = "https://fixture-crypto.kms.us-sanjose-1.oraclecloud.com"
	if err := provision(t.Context(), config.CatalogPath, []ProvisionTarget{third}, wrap); err == nil {
		t.Fatal("version reused with changed regional policy")
	}
}
func TestProvisionFailurePublishesNoPartialKey(t *testing.T) {
	config, catalog := fixture(t)
	if err := WriteCatalog(config.CatalogPath, Catalog{Version: 1}); err != nil {
		t.Fatal(err)
	}
	e := catalog.Entries[0]
	targets := []ProvisionTarget{{Binding: e.Binding, CryptoEndpoint: e.CryptoEndpoint, KEKID: e.KEKID, KEKVersionID: e.KEKVersionID, LeaseSeconds: e.LeaseSeconds, NotAfter: e.NotAfter}}
	err := provision(t.Context(), config.CatalogPath, targets, func(context.Context, ProvisionTarget, []byte) (string, error) {
		return "", errors.New("SECRET RESPONSE")
	})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("provider failure exposed")
	}
	stored, err := ReadCatalog(config.CatalogPath)
	if err != nil || len(stored.Entries) != 0 {
		t.Fatal("failed issuance published partial state")
	}
}

func TestCatalogDeliveryPreservesRevocationAndInitialization(t *testing.T) {
	config, catalog := fixture(t)
	if err := InitializeCatalog(config.CatalogPath); err != nil {
		t.Fatal(err)
	}
	if err := MergeEntries(config.CatalogPath, catalog.Entries); err != nil {
		t.Fatal("exact delivery retry rejected")
	}
	conflict := catalog.Entries[0]
	conflict.Ciphertext = "different-wrapped-key"
	if err := MergeEntries(config.CatalogPath, []Entry{conflict}); err == nil {
		t.Fatal("conflicting wrapped key overwrote admitted version")
	}
	catalog.Entries[0].Revoked = true
	if err := WriteCatalog(config.CatalogPath, catalog); err != nil {
		t.Fatal(err)
	}
	if err := MergeEntries(config.CatalogPath, []Entry{conflict}); err == nil {
		t.Fatal("delivery revived revoked version")
	}
	if err := InitializeCatalog(config.CatalogPath); err != nil {
		t.Fatal(err)
	}
	persisted, err := ReadCatalog(config.CatalogPath)
	if err != nil || len(persisted.Entries) != 1 || !persisted.Entries[0].Revoked {
		t.Fatal("initialization overwrote catalog")
	}
}
