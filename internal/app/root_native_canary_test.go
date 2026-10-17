//go:build linux

package app

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/nats-io/nats.go/jetstream"
)

func TestNativeCanaryRejectsUnsealedAuthority(t *testing.T) {
	if (*rootNativeCanaryAdmission)(nil).guard(t.Context()) == nil {
		t.Fatal("nil native canary seal accepted")
	}
	if new(rootNativeCanaryAdmission).guard(t.Context()) == nil {
		t.Fatal("zero native canary seal accepted")
	}
	service := new(rootWorkloadCredentials)
	receipt, err := service.MaterializeNativeCanary(t.Context(), rootoci.Call{}, rootoci.NativeCanaryRequest{})
	if err == nil || receipt.Value != "" || !receipt.ExpiresAt.IsZero() {
		t.Fatal("unadmitted native operation returned material", err)
	}
}

func TestNativeCanaryRootPinRejectsReplacementAndRemoval(t *testing.T) {
	js := testRolloutJetStream(t)
	kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: rootChainBucket, History: 4})
	if err != nil {
		t.Fatal(err)
	}
	wire := []byte(`{"version":1,"rotations":[]}`)
	if _, err := kv.Put(t.Context(), rootChainKey, wire); err != nil {
		t.Fatal(err)
	}
	original, err := kv.Get(t.Context(), rootChainKey)
	if err != nil || rootTrustChainCurrent(t.Context(), js, original) != nil {
		t.Fatal("current original root record rejected", err)
	}
	if _, err := kv.Put(t.Context(), rootChainKey, wire); err != nil {
		t.Fatal(err)
	}
	if rootTrustChainCurrent(t.Context(), js, original) == nil {
		t.Fatal("new root revision with identical bytes retained original authority")
	}
	replacement, err := kv.Get(t.Context(), rootChainKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := kv.Delete(t.Context(), rootChainKey); err != nil {
		t.Fatal(err)
	}
	if rootTrustChainCurrent(t.Context(), js, replacement) == nil {
		t.Fatal("removed root record retained authority")
	}
}
