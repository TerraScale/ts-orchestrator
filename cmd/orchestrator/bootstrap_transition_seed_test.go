package main

import (
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

func TestReceiptSeedCannotReuseAnotherHostKey(t *testing.T) {
	path := hostsecrets.StorageTransitionReceiptKeyPath
	seed := hostsecrets.Seed{Entries: []hostsecrets.Entry{{Destination: path}}}
	identities := map[string]string{path: "verified-public-id"}
	hosts := map[string]string{}
	if err := validateBootstrapStorageTransitionSeed(path, seed, identities, nil, hosts, "sfo-one"); err != nil {
		t.Fatal(err)
	}
	if err := validateBootstrapStorageTransitionSeed(path, seed, identities, nil, hosts, "fra-one"); err == nil {
		t.Fatal("two hosts shared a receipt signer")
	}
	if err := validateBootstrapStorageTransitionSeed("", seed, identities, nil, hosts, "sfo-one"); err == nil {
		t.Fatal("unconfigured host accepted receipt seed")
	}
}
