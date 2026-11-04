package foundationbinding

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func pinnedStartupScenario(t *testing.T) *bindingScenario {
	t.Helper()
	s := newBindingScenario(t)
	pins := s.intent.Plan["resource_ids"].(map[string]any)
	for _, role := range []string{"control_compartment", "vault", "key"} {
		pins[role] = s.record.ResourceIDs[role]
		delete(s.record.ResourceProvenance, role)
	}
	// Host slot maps remain inside the original signed intent, never scalar IDs.
	pins["instances"] = map[string]any{"controller-a": ""}
	pins["boot_volumes"] = map[string]any{"controller-a": ""}
	pins["data_volumes"] = map[string]any{"controller-a": ""}
	s.publish()
	return s
}

func TestStartupVaultObservesExactPinsWithoutCreatingLogicalBirth(t *testing.T) {
	for _, schema := range []int{
		3,
	} {
		t.Run(fmt.Sprintf("schema%d", schema), func(t *testing.T) {
			s := pinnedStartupScenario(t)
			if schema == 3 {
				s.transportSchemaThree()
			}
			deadline := time.Now().Add(30 * time.Second)
			verified, err := VerifyStartupVault(t.Context(), s.factory, s.authority, s.wire, deadline)
			if err != nil {
				t.Fatal(err)
			}
			if verified.CompartmentOCID() != s.record.ResourceIDs["control_compartment"] || verified.VaultOCID() != s.record.ResourceIDs["vault"] || verified.KMSKeyOCID() != s.record.ResourceIDs["key"] || !verified.ExpiresAt().Equal(deadline) {
				t.Fatal("startup witness lost exact signed destination or original deadline")
			}
			for _, path := range []string{"/20160918/compartments/" + verified.CompartmentOCID(), "/20180608/vaults/" + verified.VaultOCID(), "/20180608/keys/" + verified.KMSKeyOCID()} {
				if s.reads[path] != 1 {
					t.Fatalf("startup target was not freshly observed: %s reads=%d", path, s.reads[path])
				}
			}
			if s.reads["/20160918/subnets/"+s.record.ResourceIDs["subnet"]] != 0 {
				t.Fatal("finite witness observed unrelated network")
			}
			if err := verified.Revalidate(t.Context()); err != nil {
				t.Fatal(err)
			}
			if s.reads["/20180608/keys/"+verified.KMSKeyOCID()] != 2 {
				t.Fatal("revalidation reused stale SDK key observation")
			}
			if _, err := Verify(t.Context(), s.factory, s.authority, s.wire); err == nil || !strings.Contains(err.Error(), "persisted create provenance") {
				t.Fatalf("generic worker reference gained logical authority: %v", err)
			}
			s.authority.Keys = []string{"subnet", "network_security_group"}
			logical, err := Verify(t.Context(), s.factory, s.authority, s.wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := logical.Resolve("foundation:SJC:key"); err == nil {
				t.Fatal("finite startup projection exposed pinned key")
			}
			if _, err := logical.ForCell(t.Context(), "SJC"); err == nil {
				t.Fatal("generic ForCell lost full missing-birth refusal")
			}
			for _, role := range []string{"control_compartment", "vault", "key"} {
				if _, exists := s.record.ResourceProvenance[role]; exists {
					t.Fatalf("observation fabricated %s creation provenance", role)
				}
			}
		})
	}
}
