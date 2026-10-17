package natscell

import (
	"strings"
	"testing"
	"time"
)

func TestBrokerStorageMarkerRejectsUnknownHistory(t *testing.T) {
	node := strings.Repeat("a", 64)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	valid := stamp + "\n" + node + "\n"
	if _, err := parseBrokerStorageMarker([]byte(valid), node); err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{"", stamp + "\n", stamp + "\n" + node, valid + "extra", stamp + "\n" + strings.Repeat("b", 64) + "\n", "2026-10-17T00:00:00+00:00\n" + node + "\n"} {
		if _, err := parseBrokerStorageMarker([]byte(wire), node); err == nil {
			t.Fatalf("malformed origin accepted: %q", wire)
		}
	}
	if err := (VerifiedBrokerStorage{}).Revalidate(t.Context()); err == nil {
		t.Fatal("zero read-only proof accepted")
	}
}

func TestBrokerStorageObservationRefusesMissingOriginalMarker(t *testing.T) {
	cfg := installationIdentityFixture(t)
	existingInstallationPins(t, cfg)
	r := &Runtime{}
	defer r.Close()
	if err := r.lockBrokerStore(t.Context(), cfg, false); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ObserveBrokerStorage(t.Context()); err == nil {
		t.Fatal("legacy runtime received original storage credit")
	}
}

func TestBrokerProofRuntimeBindingRejectsZeroAndOtherTargets(t *testing.T) {
	first, second := &Runtime{}, &Runtime{}
	for _, target := range []*Runtime{nil, first, second} {
		if err := (VerifiedBrokerGenesis{}).RevalidateRuntime(t.Context(), target); err == nil {
			t.Fatal("zero genesis accepted runtime")
		}
		if err := (VerifiedBrokerStorage{}).RevalidateRuntime(t.Context(), target); err == nil {
			t.Fatal("zero storage accepted runtime")
		}
	}
	if err := (VerifiedBrokerGenesis{runtime: first}).RevalidateRuntime(t.Context(), second); err == nil {
		t.Fatal("genesis accepted other target")
	}
	if err := (VerifiedBrokerStorage{runtime: first}).RevalidateRuntime(t.Context(), second); err == nil {
		t.Fatal("storage accepted other target")
	}
}
