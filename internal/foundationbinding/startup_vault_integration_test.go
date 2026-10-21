package foundationbinding

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
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
	for _, schema := range []int{2, 3} {
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

func TestStartupVaultRefusesAuthorityRecordAndLiveDrift(t *testing.T) {
	for _, schema := range []int{2, 3} {
		for _, scenario := range []struct {
			name   string
			mutate func(*bindingScenario)
		}{
			{"schema one", func(s *bindingScenario) { s.grant.SchemaVersion = 1; s.publish() }},
			{"unknown schema", func(s *bindingScenario) { s.grant.SchemaVersion = 4; s.publish() }},
			{"unrelated grant member", func(s *bindingScenario) {
				payload, err := trust.EncodePayload(s.grant)
				if err != nil {
					s.t.Fatal(err)
				}
				s.publishPayload([]byte(strings.TrimSuffix(string(payload), "}") + `,"unrelatedAuthority":true}`))
			}},
			{"unrelated record member", func(s *bindingScenario) {
				wire, err := json.Marshal(s.record, json.Deterministic(true))
				if err != nil {
					s.t.Fatal(err)
				}
				s.recordWire = []byte(strings.TrimSuffix(string(wire), "}") + `,"unrelatedAuthority":true}`)
			}},
			{"protected grant replacement", func(s *bindingScenario) { s.activeWire = []byte(`{}`) }},
			{"root removal", func(s *bindingScenario) { s.authority.Roots = trust.Keyring{} }},
			{"wrong exact wire", func(s *bindingScenario) { s.authority.GrantSHA256 = strings.Repeat("c", 64) }},
			{"foreign installation", func(s *bindingScenario) { s.authority.InstallationID = entityid.New() }},
			{"foreign tenancy", func(s *bindingScenario) { s.authority.TenancyID = "ocid1.tenancy.oc1..foreign" }},
			{"foreign operation", func(s *bindingScenario) { s.record.OperationID = entityid.New() }},
			{"foreign generation", func(s *bindingScenario) { s.record.Generation++ }},
			{"foreign intent", func(s *bindingScenario) { s.record.IntentDigest = strings.Repeat("c", 64) }},
			{"missing protected ETag", func(s *bindingScenario) { s.etag = "" }},
			{"wrong signed pin", func(s *bindingScenario) {
				s.intent.Plan["resource_ids"].(map[string]any)["vault"] = "ocid1.vault.oc1.us-sanjose-1.other"
				s.publish()
			}},
			{"pending exact pin", func(s *bindingScenario) {
				s.record.PendingCreates = map[string]pendingCreate{"vault": {OperationID: s.record.OperationID}}
			}},
			{"compartment moved", func(s *bindingScenario) {
				s.live["/20160918/compartments/"+s.record.ResourceIDs["control_compartment"]]["compartmentId"] = "ocid1.compartment.oc1..foreign"
			}},
			{"compartment deleted", func(s *bindingScenario) {
				s.live["/20160918/compartments/"+s.record.ResourceIDs["control_compartment"]]["lifecycleState"] = "DELETED"
			}},
			{"vault moved", func(s *bindingScenario) {
				s.live["/20180608/vaults/"+s.record.ResourceIDs["vault"]]["compartmentId"] = "ocid1.compartment.oc1..foreign"
			}},
			{"vault inactive", func(s *bindingScenario) {
				s.live["/20180608/vaults/"+s.record.ResourceIDs["vault"]]["lifecycleState"] = "DELETED"
			}},
			{"vault type changed", func(s *bindingScenario) {
				s.live["/20180608/vaults/"+s.record.ResourceIDs["vault"]]["vaultType"] = "VIRTUAL_PRIVATE"
			}},
			{"untrusted management endpoint", func(s *bindingScenario) {
				s.live["/20180608/vaults/"+s.record.ResourceIDs["vault"]]["managementEndpoint"] = "https://kms.invalid"
			}},
			{"key moved", func(s *bindingScenario) {
				s.live["/20180608/keys/"+s.record.ResourceIDs["key"]]["vaultId"] = "ocid1.vault.oc1.us-sanjose-1.foreign"
			}},
			{"key disabled", func(s *bindingScenario) {
				s.live["/20180608/keys/"+s.record.ResourceIDs["key"]]["lifecycleState"] = "DISABLED"
			}},
			{"software key", func(s *bindingScenario) {
				s.live["/20180608/keys/"+s.record.ResourceIDs["key"]]["protectionMode"] = "SOFTWARE"
			}},
			{"key shape changed", func(s *bindingScenario) {
				s.live["/20180608/keys/"+s.record.ResourceIDs["key"]]["keyShape"] = map[string]any{"algorithm": "AES", "length": 16}
			}},
			{"logical target lacks birth", func(s *bindingScenario) { delete(s.intent.Plan["resource_ids"].(map[string]any), "key"); s.publish() }},
			{"wrong logical target role", func(s *bindingScenario) {
				s.intent.Plan["resource_ids"].(map[string]any)["key"] = "foundation:SJC:vault"
				s.publish()
			}},
			{"cross-cell logical target", func(s *bindingScenario) {
				s.intent.Plan["resource_ids"].(map[string]any)["key"] = "foundation:GRU:key"
				s.publish()
			}},
			{"noncanonical logical target", func(s *bindingScenario) {
				s.intent.Plan["resource_ids"].(map[string]any)["key"] = "foundation:sjc:key"
				s.publish()
			}},
		} {
			t.Run(fmt.Sprintf("schema%d/%s", schema, scenario.name), func(t *testing.T) {
				s := pinnedStartupScenario(t)
				if schema == 3 {
					s.transportSchemaThree()
				}
				scenario.mutate(s)
				_, err := VerifyStartupVault(t.Context(), s.factory, s.authority, s.wire, time.Now().Add(time.Minute))
				if err == nil {
					t.Fatal("startup target accepted changed authority, record or live facts")
				}
				if strings.HasPrefix(scenario.name, "unrelated ") && !strings.Contains(err.Error(), "unrelatedAuthority") {
					t.Fatalf("unrelated member did not reach strict decoding: %v", err)
				}
			})
		}
	}
}

func TestStartupVaultRetainsOriginalLeaseEpochAndDeadline(t *testing.T) {
	for _, schema := range []int{2, 3} {
		t.Run(fmt.Sprintf("schema%d", schema), func(t *testing.T) {
			for _, scenario := range []string{"epoch", "lease", "lease deadline", "expired lease", "operation", "grant", "live key"} {
				t.Run(scenario, func(t *testing.T) {
					s := pinnedStartupScenario(t)
					if schema == 3 {
						s.transportSchemaThree()
					}
					s.record.Stage = "foundation"
					s.record.CompletedAt = time.Time{}
					s.record.LeaseID = entityid.New()
					s.record.ExpiresAt = time.Now().Add(time.Minute)
					verified, err := VerifyStartupVault(t.Context(), s.factory, s.authority, s.wire, time.Now().Add(2*time.Minute))
					if err != nil {
						t.Fatal(err)
					}
					if !verified.ExpiresAt().Equal(s.record.ExpiresAt) {
						t.Fatal("witness extended retained lease")
					}
					switch scenario {
					case "epoch":
						s.record.Epoch++
					case "lease":
						s.record.LeaseID = entityid.New()
					case "lease deadline":
						s.record.ExpiresAt = s.record.ExpiresAt.Add(time.Minute)
					case "expired lease":
						s.record.ExpiresAt = time.Now().Add(-time.Second)
					case "operation":
						s.record.OperationID = entityid.New()
					case "grant":
						s.activeWire = []byte(`{}`)
					case "live key":
						s.live["/20180608/keys/"+s.record.ResourceIDs["key"]]["protectionMode"] = "SOFTWARE"
					}
					if err := verified.Revalidate(t.Context()); err == nil {
						t.Fatal("revalidation renewed or replaced original authority")
					}
				})
			}
			s := pinnedStartupScenario(t)
			if schema == 3 {
				s.transportSchemaThree()
			}
			before := len(s.reads)
			if _, err := VerifyStartupVault(t.Context(), s.factory, s.authority, s.wire, time.Now().Add(-time.Second)); err == nil {
				t.Fatal("expired anchor cap accepted")
			}
			if len(s.reads) != before {
				t.Fatal("expired cap made SDK requests")
			}
		})
	}
}

func TestStartupVaultDynamicTargetStillRequiresOriginalBirth(t *testing.T) {
	for _, schema := range []int{2, 3} {
		t.Run(fmt.Sprintf("schema%d", schema), func(t *testing.T) {
			s := newBindingScenario(t)
			if schema == 3 {
				s.transportSchemaThree()
			}
			for _, logical := range []bool{false, true} {
				if logical {
					s.intent.Plan["resource_ids"].(map[string]any)["key"] = "foundation:SJC:key"
					s.publish()
				}
				if _, err := VerifyStartupVault(t.Context(), s.factory, s.authority, s.wire, time.Now().Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
			delete(s.record.ResourceProvenance, "key")
			if _, err := VerifyStartupVault(t.Context(), s.factory, s.authority, s.wire, time.Now().Add(time.Minute)); err == nil {
				t.Fatal("dynamic publication target accepted without original birth")
			}
		})
	}
}

func TestStartupVaultDoesNotSealAuthorityRotatedDuringSDKRead(t *testing.T) {
	for _, schema := range []int{2, 3} {
		for _, scenario := range []string{"grant replacement", "epoch replacement", "request canceled"} {
			t.Run(fmt.Sprintf("schema%d/%s", schema, scenario), func(t *testing.T) {
				s := pinnedStartupScenario(t)
				if schema == 3 {
					s.transportSchemaThree()
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				s.resourceRead = func(path string) {
					if path != "/20180608/keys/"+s.record.ResourceIDs["key"] {
						return
					}
					switch scenario {
					case "grant replacement":
						s.activeWire = []byte(`{}`)
					case "epoch replacement":
						s.record.Epoch++
					case "request canceled":
						cancel()
					}
				}
				if _, err := VerifyStartupVault(ctx, s.factory, s.authority, s.wire, time.Now().Add(time.Minute)); err == nil {
					t.Fatal("SDK observation sealed superseded or canceled authority")
				}
			})
		}
	}
}

func TestStartupVaultConsumedExactPinRequiresAndRetainsBirth(t *testing.T) {
	for _, schema := range []int{2, 3} {
		t.Run(fmt.Sprintf("schema%d", schema), func(t *testing.T) {
			s := pinnedStartupScenario(t)
			if schema == 3 {
				s.transportSchemaThree()
			}
			s.authority.Keys = []string{"key"}
			if _, err := VerifyStartupVault(t.Context(), s.factory, s.authority, s.wire, time.Now().Add(time.Minute)); err == nil {
				t.Fatal("template-consumed exact pin gained logical authority without birth")
			}
			born := newBindingScenario(t)
			if schema == 3 {
				born.transportSchemaThree()
			}
			for _, role := range []string{"control_compartment", "vault", "key"} {
				born.intent.Plan["resource_ids"].(map[string]any)[role] = born.record.ResourceIDs[role]
			}
			born.authority.Keys = []string{"key"}
			born.publish()
			verified, err := VerifyStartupVault(t.Context(), born.factory, born.authority, born.wire, time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			born.authority.Keys[0] = "subnet"
			delete(born.record.ResourceProvenance, "key")
			if err := verified.Revalidate(t.Context()); err == nil {
				t.Fatal("caller mutation erased original consumed target birth requirement")
			}
		})
	}
}
