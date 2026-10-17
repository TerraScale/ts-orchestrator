package region

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

type originalVaultDispatch struct {
	cell, kind, host, vaultID, endpoint string
	body                                []byte
	pending                             PendingFoundationCreate
}

type originalVaultSDKFixture struct {
	*originalNetworkSDKFixture
	vaultMu       sync.Mutex
	vaultFault    string
	failSlot      int
	vaultFaulted  bool
	vaultPosts    []originalVaultDispatch
	vaultReturned map[string]bool
	vaultGets     map[string]int
	vaultUpstream []byte
}

func newOriginalVaultSDKFixture(t *testing.T, fault string, slot int) *originalVaultSDKFixture {
	t.Helper()
	base := newOriginalNetworkSDKFixture(t, "")
	f := &originalVaultSDKFixture{originalNetworkSDKFixture: base, vaultFault: fault, failSlot: slot, vaultReturned: map[string]bool{}, vaultGets: map[string]int{}}
	// Public version identity is returned by OCI; the inherited provider omits it.
	f.cloud.mu.Lock()
	for id, collection := range f.cloud.collections {
		if collection == "keys" {
			f.cloud.rows[id]["currentKeyVersion"] = strings.Replace(id, ".key.", ".keyversion.", 1) + ".version1"
		}
	}
	f.cloud.mu.Unlock()
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("original Vault fixture requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("fixture refuses network %q", network)
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	return f
}

func (f *originalVaultSDKFixture) run(t *testing.T) error {
	t.Helper()
	return provisionOriginalFoundationCompartments(t.Context(), f.factoryFor(), f.roots, f.bundle)
}

func originalVaultUpstream(record FoundationRecord) ([]byte, error) {
	section := *record.OriginalFoundationCompartments
	for index := range section.Regions {
		section.Regions[index].Vault = nil
	}
	return json.Marshal(struct {
		Material     *NetBirdMaterialJournal
		Births       *[3]OriginalSourceProducerBirth
		Compartments OriginalFoundationCompartments
	}{record.NetBirdMaterial, record.OriginalSourceProducers, section}, json.Deterministic(true))
}

func (f *originalVaultSDKFixture) checkVaultPrerequisites(record FoundationRecord) {
	f.checkNetworkPrerequisites(record)
	for _, region := range record.OriginalFoundationCompartments.Regions {
		v := region.Vault
		wire, err := json.Marshal(region.Network, json.Deterministic(true))
		if v == nil || region.Network == nil || !region.Network.Complete || len(region.Network.Rules.ReturnedRules) != 9 || region.Network.Rules.VerifiedAt.IsZero() || err != nil || v.NetworkProofSHA256 != preparationDigest(wire) || v.ControlCompartmentID != originalCompartmentID(region.Compartments[0]) {
			f.cloud.test.Error("Vault effect preceded all three exact control compartments and acknowledged complete original network scopes")
		}
	}
	pins, err := originalVaultUpstream(record)
	if err != nil {
		f.cloud.test.Error(err)
		return
	}
	if f.vaultUpstream == nil {
		f.vaultUpstream = pins
	} else if !bytes.Equal(pins, f.vaultUpstream) {
		f.cloud.test.Error("Vault progress changed original material, producer, compartment or complete network pins")
	}
}

func (f *originalVaultSDKFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.vaultMu.Lock()
	defer f.vaultMu.Unlock()
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json") && !f.vaultFaulted {
		body, _, err := originalNetworkBody(r)
		if err != nil {
			f.cloud.test.Error(err)
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		wire, err := json.Marshal(body)
		var record FoundationRecord
		if err == nil && json.Unmarshal(wire, &record) == nil && record.OriginalFoundationCompartments != nil {
			for _, region := range record.OriginalFoundationCompartments.Regions {
				v := region.Vault
				if v == nil {
					continue
				}
				entry := originalVaultEntry(v, f.failSlot)
				accepted := entry.Provenance != nil && entry.VerifiedAt.IsZero()
				if f.vaultFault == "uninitialized scope" || (f.vaultFault == "lost accepted checkpoint" || f.vaultFault == "response before CAS") && accepted {
					f.vaultFaulted = true
					if f.vaultFault == "lost accepted checkpoint" {
						recorder := httptest.NewRecorder()
						f.originalNetworkSDKFixture.serveHTTP(recorder, r)
						if recorder.Code >= 300 {
							f.cloud.test.Errorf("Vault checkpoint fault preceded accepted CAS: %d", recorder.Code)
						}
					}
					originalCompartmentFailure(w, 503, "InternalError")
					return
				}
			}
		}
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[1] != "vaults" && parts[1] != "keys" {
		f.originalNetworkSDKFixture.serveHTTP(w, r)
		return
	}
	if parts[0] != "20180608" || r.URL.RawQuery != "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") || r.Method != http.MethodGet && r.Method != http.MethodPost || r.Method == http.MethodGet && len(parts) != 3 || r.Method == http.MethodPost && len(parts) != 2 {
		f.cloud.test.Errorf("unexpected original KMS endpoint/mutation: %s %s %s", r.Method, r.Host, r.URL.String())
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	slot := 0
	if parts[1] == "keys" {
		slot = 1
	}
	kind := [2]string{"vault", "key"}[slot]
	var record FoundationRecord
	wire, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		f.cloud.test.Error(err)
	}
	if err == nil && json.Unmarshal(wire, &record) != nil {
		f.cloud.test.Error("fixture could not read original KMS journal")
	}
	// The genuine material operator independently reads these exact GRU parents
	// before any compartment/network stage and on every subsequent invocation.
	preflight := r.Method == http.MethodGet && (parts[2] == f.approval.SourceVaultTarget.VaultOCID || parts[2] == f.approval.SourceVaultTarget.KMSKeyOCID || parts[2] == f.approval.HomeStorageDomain.LedgerKMSKeyOCID)
	if preflight {
		host := "kms." + foundationHomeRegion + ".oraclecloud.com"
		if slot == 1 {
			host = "prerequisite-management.kms." + foundationHomeRegion + ".oraclecloud.com"
		}
		if r.Host != host {
			f.cloud.test.Error("inherited original material observation escaped exact GRU KMS origin")
		}
		if record.OriginalFoundationCompartments != nil && record.OriginalFoundationCompartments.Regions[0].Vault != nil && parts[2] != f.approval.HomeStorageDomain.LedgerKMSKeyOCID {
			f.checkVaultPrerequisites(record)
			entry := originalVaultEntry(record.OriginalFoundationCompartments.Regions[0].Vault, slot)
			if entry.SelectedID != parts[2] || entry.Pending != nil || entry.Provenance != nil {
				f.cloud.test.Error("original selected GRU KMS read invented create provenance or changed selection")
			}
			if f.vaultFault == "selected nonready" && slot == f.failSlot && !f.vaultFaulted {
				f.vaultFaulted = true
				f.cloud.mu.Lock()
				f.cloud.rows[parts[2]]["lifecycleState"] = "CREATING"
				f.cloud.mu.Unlock()
			}
		}
		f.vaultGets[parts[2]]++
		f.originalNetworkSDKFixture.serveHTTP(w, r)
		return
	}
	if record.OriginalFoundationCompartments == nil {
		f.cloud.test.Error("KMS effect preceded retained original prerequisites")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	f.checkVaultPrerequisites(record)
	index := -1
	for candidate, region := range record.OriginalFoundationCompartments.Regions {
		if region.Vault == nil {
			continue
		}
		host := "kms." + region.OCIRegion + ".oraclecloud.com"
		if slot == 1 {
			host = strings.TrimPrefix(region.Vault.Key.ManagementEndpoint, "https://")
		}
		if r.Host == host {
			index = candidate
		}
	}
	if index < 0 {
		f.cloud.test.Error("KMS request escaped accepted regional management origin")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	region := record.OriginalFoundationCompartments.Regions[index]
	v := region.Vault
	entry := originalVaultEntry(v, slot)
	if r.Method == http.MethodGet {
		id := parts[2]
		if originalVaultID(*entry) != id || entry.SelectedID != "" && (entry.Pending != nil || entry.Provenance != nil) || entry.SelectedID == "" && (!f.vaultReturned[id] || entry.Provenance == nil) {
			f.cloud.test.Error("KMS exact-ID GET preceded durable actual response provenance or invented selected create provenance")
		}
		f.vaultGets[id]++
		if f.vaultFault == "nonready" && slot == f.failSlot && index == 1 && !f.vaultFaulted {
			f.vaultFaulted = true
			f.cloud.mu.Lock()
			f.cloud.rows[id]["lifecycleState"] = "CREATING"
			f.cloud.mu.Unlock()
		}
		f.originalNetworkSDKFixture.serveHTTP(w, r)
		return
	}
	body, canonical, err := originalNetworkBody(r)
	digest, digestErr := originalVaultRequestSHA(v, slot)
	pending := entry.Pending
	if err != nil || digestErr != nil || pending == nil || digest != preparationDigest(canonical) || pending.Request.RequestDigest != digest || pending.Request.RetryToken != r.Header.Get("opc-retry-token") || pending.Request.RetryToken != BootstrapRetryToken(region.OperationID, digest) || pending.Request.Key != kind || pending.Request.Region != region.OCIRegion || pending.OperationID != region.OperationID || pending.IntentDigest != region.IntentSHA256 || pending.FirstAttemptAt.IsZero() || entry.SelectedID != "" || entry.Provenance != nil || index == 0 {
		f.cloud.test.Error("KMS create preceded exact durable original body/token/time/scope or attempted GRU selected creation")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	wanted := map[string]any{"compartmentId": v.ControlCompartmentID, "displayName": strings.ToLower(region.Cell) + "-1-" + kind}
	if slot == 0 {
		wanted["vaultType"] = "DEFAULT"
	} else {
		wanted["protectionMode"] = "HSM"
		wanted["keyShape"] = map[string]any{"algorithm": "AES", "length": 32}
		f.cloud.mu.Lock()
		endpoint := f.cloud.rows[originalVaultID(v.Vault.OriginalFoundationKMSCreate)]["managementEndpoint"]
		f.cloud.mu.Unlock()
		if v.Vault.VerifiedAt.IsZero() || v.Key.VaultID != originalVaultID(v.Vault.OriginalFoundationKMSCreate) || v.Key.ManagementEndpoint != v.Vault.ManagementEndpoint || v.Key.ManagementEndpoint != endpoint {
			f.cloud.test.Error("key create preceded durable accepted Vault and independent management-endpoint dependency")
		}
	}
	if !sameOriginalSourceValue(originalNetworkPrune(body), wanted) {
		f.cloud.test.Error("KMS body widened exact signed DEFAULT Vault or AES256 HSM key semantics")
	}
	f.vaultPosts = append(f.vaultPosts, originalVaultDispatch{cell: region.Cell, kind: kind, host: r.Host, vaultID: v.Key.VaultID, endpoint: v.Key.ManagementEndpoint, body: canonical, pending: *pending})
	if slot == f.failSlot && !f.vaultFaulted {
		switch f.vaultFault {
		case "unknown create":
			f.vaultFaulted = true
			originalCompartmentFailure(w, 503, "InternalError")
			return
		case "conflict", "invalid token":
			f.vaultFaulted = true
			status, code := 409, "Conflict"
			if f.vaultFault == "invalid token" {
				status, code = 400, "InvalidRetryToken"
			}
			originalCompartmentFailure(w, status, code)
			return
		}
	}
	recorder := httptest.NewRecorder()
	f.originalNetworkSDKFixture.serveHTTP(recorder, r)
	var row map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &row); err != nil || row["id"] == nil {
		f.cloud.test.Errorf("KMS SDK create lacked actual returned ID: %v", err)
		originalCompartmentFailure(w, 500, "InternalError")
		return
	}
	id := row["id"].(string)
	f.vaultReturned[id] = true
	if slot == 1 {
		version := strings.Replace(id, ".key.", ".keyversion.", 1) + ".version1"
		row["currentKeyVersion"] = version
		f.cloud.mu.Lock()
		f.cloud.rows[id]["currentKeyVersion"] = version
		f.cloud.mu.Unlock()
		recorder.Body.Reset()
		json.MarshalWrite(recorder.Body, row)
	}
	if f.vaultFault == "lost create response" && slot == f.failSlot && !f.vaultFaulted {
		f.vaultFaulted = true
		originalCompartmentFailure(w, 503, "InternalError")
		return
	}
	originalNetworkCopyResponse(w, recorder)
}

func (f *originalVaultSDKFixture) kmsDispatches() []originalVaultDispatch {
	f.vaultMu.Lock()
	defer f.vaultMu.Unlock()
	return slices.Clone(f.vaultPosts)
}

func (f *originalVaultSDKFixture) assertVaultState(t *testing.T) {
	t.Helper()
	f.assertNetworkState(t, true)
	record := f.record(t)
	if err := record.validate(); err != nil {
		t.Fatal(err)
	}
	pins, err := originalVaultUpstream(record)
	if err != nil || !bytes.Equal(pins, f.vaultUpstream) {
		t.Fatalf("Vault progress replaced complete original network/upstream pins: %v", err)
	}
	for index, region := range record.OriginalFoundationCompartments.Regions {
		v := region.Vault
		if v == nil || v.Vault.ManagementEndpoint == "" || v.Key.VaultID != originalVaultID(v.Vault.OriginalFoundationKMSCreate) || v.Key.ManagementEndpoint != v.Vault.ManagementEndpoint || v.Key.CurrentKeyVersion == "" {
			t.Fatal("complete original KMS prerequisites lack exact accepted Vault/endpoint/version dependencies")
		}
		for slot := range 2 {
			entry := originalVaultEntry(v, slot)
			if entry.VerifiedAt.IsZero() || entry.ReadbackSHA256 == "" || entry.HoldReason != "" || index == 0 && (entry.SelectedID == "" || entry.Pending != nil || entry.Provenance != nil) || index != 0 && (entry.SelectedID != "" || entry.Pending == nil || entry.Provenance == nil || !sameOriginalSourceValue(entry.Pending, entry.Provenance.Create)) {
				t.Fatalf("%s KMS%d lost exact selected/returned/readback provenance", region.Cell, slot)
			}
			f.vaultMu.Lock()
			gets := f.vaultGets[originalVaultID(*entry)]
			f.vaultMu.Unlock()
			if gets == 0 {
				t.Fatal("complete KMS prerequisite never received an actual exact-ID GET")
			}
		}
	}
}

func TestOriginalFoundationVaultSDK(t *testing.T) {
	t.Run("four original KMS creates and selected GRU Get only", func(t *testing.T) {
		f := newOriginalVaultSDKFixture(t, "", 0)
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationVaultPending) {
			t.Fatalf("automatic original path did not reach explicit actor/material HOLD: %v", err)
		}
		posts := f.kmsDispatches()
		network, sends := f.effects()
		if len(posts) != 4 || len(network) != 18 || sends != 3 || len(f.dispatches()) != 5 || f.cloud.creates != 27 {
			t.Fatal("normal original path did not make exactly5 compartment+18 network+4 KMS creates and3 rule sends")
		}
		seen := map[string]bool{}
		for _, post := range posts {
			key := post.cell + "/" + post.kind
			if seen[key] || post.cell == "GRU" {
				t.Fatal("selected GRU or repeated KMS create")
			}
			seen[key] = true
		}
		f.assertVaultState(t)
		before, material := f.wire(t), f.cloud.materialPosts
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationVaultPending) {
			t.Fatal(err)
		}
		if len(f.kmsDispatches()) != 4 || f.cloud.creates != 27 || f.cloud.materialPosts != material || !bytes.Equal(before, f.wire(t)) {
			t.Fatal("completed original KMS replay changed effects, provenance or actor HOLD")
		}
	})

	t.Run("unknown creates and accepted IDs keep exact recovery identity", func(t *testing.T) {
		for slot := range 2 {
			for _, fault := range []string{"lost create response", "lost accepted checkpoint", "response before CAS", "nonready"} {
				t.Run(fmt.Sprintf("%d/%s", slot, fault), func(t *testing.T) {
					f := newOriginalVaultSDKFixture(t, fault, slot)
					if err := f.run(t); err == nil {
						t.Fatal("interrupted KMS operation claimed complete provisioning")
					}
					before := f.kmsDispatches()
					if len(before) != slot+1 || f.cloud.creates != 24+slot {
						t.Fatal("KMS recovery fault did not follow actual accepted SFO create")
					}
					v := f.record(t).OriginalFoundationCompartments.Regions[1].Vault
					entry := originalVaultEntry(v, slot)
					if fault == "response before CAS" && (entry.Pending == nil || entry.Provenance != nil) {
						t.Fatal("rejected accepted-ID checkpoint lost pending identity or invented durable response provenance")
					}
					if fault == "nonready" {
						if entry.Provenance == nil || !entry.VerifiedAt.IsZero() {
							t.Fatal("nonready KMS readback lost accepted ID or fabricated readiness")
						}
						f.cloud.mu.Lock()
						f.cloud.rows[entry.Provenance.ResourceID]["lifecycleState"] = [2]string{"ACTIVE", "ENABLED"}[slot]
						f.cloud.mu.Unlock()
					}
					if err := f.run(t); !errors.Is(err, ErrOriginalFoundationVaultPending) {
						t.Fatalf("retained original KMS did not recover: %v", err)
					}
					after := f.kmsDispatches()
					want := 4
					if fault == "lost create response" || fault == "response before CAS" {
						want = 5
						if len(after) <= slot+1 {
							t.Fatal("unknown KMS identity did not replay the original request")
						}
						first, next := before[slot], after[slot+1]
						if !bytes.Equal(first.body, next.body) || !sameOriginalSourceValue(first.pending, next.pending) || first.cell != next.cell || first.kind != next.kind || first.host != next.host || first.vaultID != next.vaultID || first.endpoint != next.endpoint {
							t.Fatal("unknown KMS request changed body/token/time/Vault/endpoint instead of exact replay")
						}
					}
					if len(after) != want || f.cloud.creates != 27 {
						t.Fatal("accepted original KMS ID was recreated instead of GET-only recovery")
					}
					f.assertVaultState(t)
				})
			}
		}
		for slot := range 2 {
			t.Run(fmt.Sprintf("%d/selected nonready", slot), func(t *testing.T) {
				f := newOriginalVaultSDKFixture(t, "selected nonready", slot)
				if err := f.run(t); err == nil || f.cloud.creates != 23 || len(f.kmsDispatches()) != 0 {
					t.Fatal("nonready selected GRU KMS parent was replaced or authorized regional creates")
				}
				entry := originalVaultEntry(f.record(t).OriginalFoundationCompartments.Regions[0].Vault, slot)
				if entry.SelectedID == "" || entry.Pending != nil || entry.Provenance != nil || !entry.VerifiedAt.IsZero() {
					t.Fatal("selected nonready GRU KMS parent acquired create provenance or readiness")
				}
				f.cloud.mu.Lock()
				f.cloud.rows[entry.SelectedID]["lifecycleState"] = [2]string{"ACTIVE", "ENABLED"}[slot]
				f.cloud.mu.Unlock()
				if err := f.run(t); !errors.Is(err, ErrOriginalFoundationVaultPending) {
					t.Fatal(err)
				}
				if len(f.kmsDispatches()) != 4 || f.cloud.creates != 27 {
					t.Fatal("selected nonready recovery recreated selected parent")
				}
				f.assertVaultState(t)
			})
		}
	})

	t.Run("terminal refusal and genuine23h expiry retain original HOLD", func(t *testing.T) {
		for slot := range 2 {
			for _, fault := range []string{"conflict", "invalid token"} {
				t.Run(fmt.Sprintf("%d/%s", slot, fault), func(t *testing.T) {
					f := newOriginalVaultSDKFixture(t, fault, slot)
					if err := f.run(t); err == nil {
						t.Fatal("terminal KMS refusal claimed success")
					}
					entry := *originalVaultEntry(f.record(t).OriginalFoundationCompartments.Regions[1].Vault, slot)
					if entry.Pending == nil || entry.Provenance != nil || entry.HoldReason == "" {
						t.Fatal("terminal KMS failure lacks original pending HOLD")
					}
					wire := f.wire(t)
					if err := f.run(t); err == nil || !bytes.Equal(wire, f.wire(t)) || len(f.kmsDispatches()) != slot+1 || f.cloud.creates != 23+slot {
						t.Fatal("terminal KMS HOLD reset or resent original identity")
					}
					store := f.store(t)
					record, etag, err := store.Load(t.Context(), "GRU")
					if err != nil {
						t.Fatal(err)
					}
					originalVaultEntry(record.OriginalFoundationCompartments.Regions[1].Vault, slot).HoldReason = ""
					if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(wire, f.wire(t)) {
						t.Fatal("protected CAS erased terminal KMS HOLD")
					}
				})
			}
		}
		for slot := range 2 {
			t.Run(fmt.Sprintf("%d/valid expired original", slot), func(t *testing.T) {
				f := newOriginalVaultSDKFixture(t, "unknown create", slot)
				f.bundle = signHistoricalOriginalCompartmentBundle(t, f.foundationProvisionFixture)
				f.cloud.bundle = f.bundle.clone()
				if err := VerifyFoundationProvisionBundle(t.Context(), f.roots, f.bundle); err != nil {
					t.Fatal(err)
				}
				if err := f.run(t); err == nil {
					t.Fatal("unknown KMS create lost original reservation")
				}
				record := f.record(t)
				originalVaultAgeTimeline(t, &record)
				if err := record.validate(); err != nil {
					t.Fatalf("historical coherent KMS timeline is invalid: %v", err)
				}
				pending := originalVaultEntry(record.OriginalFoundationCompartments.Regions[1].Vault, slot).Pending
				if pending == nil || !pending.FirstAttemptAt.Before(time.Now().Add(-23*time.Hour)) {
					t.Fatal("historical original KMS request is not actually expired")
				}
				wire, err := json.Marshal(record, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				f.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", wire)
				// The fixture now models yesterday's same signed original; observers
				// pin that coherent timeline before any resumed provider observation.
				f.upstream, err = originalNetworkUpstream(record)
				if err != nil {
					t.Fatal(err)
				}
				f.vaultUpstream, err = originalVaultUpstream(record)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.run(t); !errors.Is(err, ErrOriginalSourceProducerHold) {
					t.Fatalf("valid expired KMS request did not retain HOLD: %v", err)
				}
				retained := f.record(t)
				originalVaultEntry(record.OriginalFoundationCompartments.Regions[1].Vault, slot).HoldReason = "retry-expired"
				record.UpdatedAt = retained.UpdatedAt
				if !sameOriginalSourceValue(record, retained) {
					t.Fatal("KMS expiry changed original network/material/body/token/time/dependency pins")
				}
				hold := f.wire(t)
				if err := f.run(t); !errors.Is(err, ErrOriginalSourceProducerHold) || !bytes.Equal(hold, f.wire(t)) || len(f.kmsDispatches()) != slot+1 || f.cloud.creates != 23+slot {
					t.Fatal("expired KMS identity reset or dispatched replacement")
				}
			})
		}
	})

	t.Run("exact parent network and KMS readbacks refuse drift", func(t *testing.T) {
		for _, fault := range []string{"unknown rule response", "reservation before send", "extra listed rule"} {
			t.Run("network/"+fault, func(t *testing.T) {
				f := newOriginalVaultSDKFixture(t, "", 0)
				f.networkFault = fault
				if err := f.run(t); err == nil || len(f.kmsDispatches()) != 0 || f.cloud.creates != 11 {
					t.Fatal("unknown or drifted network authorized regional KMS creates")
				}
				for _, region := range f.record(t).OriginalFoundationCompartments.Regions {
					if region.Vault != nil {
						t.Fatal("unknown network acquired Vault original scope")
					}
				}
			})
		}
		for _, drift := range []string{"missing selected Vault", "selected key shape", "missing accepted Vault", "missing accepted key", "Vault name", "Vault compartment", "Vault type", "key Vault", "key shape", "key protection", "key version", "endpoint", "external endpoint", "wrong user", "wrong tenancy", "expired original"} {
			t.Run(drift, func(t *testing.T) {
				f := newOriginalVaultSDKFixture(t, "", 0)
				if err := f.run(t); !errors.Is(err, ErrOriginalFoundationVaultPending) {
					t.Fatal(err)
				}
				before := f.wire(t)
				region := f.record(t).OriginalFoundationCompartments.Regions[1]
				v := region.Vault
				vaultID, keyID := originalVaultID(v.Vault.OriginalFoundationKMSCreate), originalVaultID(v.Key.OriginalFoundationKMSCreate)
				f.cloud.mu.Lock()
				switch drift {
				case "missing selected Vault":
					delete(f.cloud.rows, f.approval.SourceVaultTarget.VaultOCID)
				case "selected key shape":
					f.cloud.rows[f.approval.SourceVaultTarget.KMSKeyOCID]["keyShape"] = map[string]any{"algorithm": "AES", "length": 16}
				case "missing accepted Vault":
					delete(f.cloud.rows, vaultID)
				case "missing accepted key":
					delete(f.cloud.rows, keyID)
				case "Vault name":
					f.cloud.rows[vaultID]["displayName"] = "foreign"
				case "Vault compartment":
					f.cloud.rows[vaultID]["compartmentId"] = f.approval.SharedCompartmentID
				case "Vault type":
					f.cloud.rows[vaultID]["vaultType"] = "VIRTUAL_PRIVATE"
				case "key Vault":
					f.cloud.rows[keyID]["vaultId"] = f.approval.SourceVaultTarget.VaultOCID
				case "key shape":
					f.cloud.rows[keyID]["keyShape"] = map[string]any{"algorithm": "AES", "length": 16}
				case "key protection":
					f.cloud.rows[keyID]["protectionMode"] = "SOFTWARE"
				case "key version":
					f.cloud.rows[keyID]["currentKeyVersion"] = strings.Replace(keyID, ".key.", ".keyversion.", 1) + ".version2"
				case "endpoint":
					f.cloud.rows[vaultID]["managementEndpoint"] = "https://foreign-management.kms." + region.OCIRegion + ".oraclecloud.com"
				case "external endpoint":
					f.cloud.rows[vaultID]["managementEndpoint"] = "https://foreign.invalid"
				}
				f.cloud.mu.Unlock()
				var err error
				if drift == "wrong user" || drift == "wrong tenancy" {
					provider := originalCompartmentProvider{ConfigurationProvider: f.provider, user: "ocid1.user.oc1..test", tenancy: f.approval.TenancyID}
					if drift == "wrong user" {
						provider.user = "ocid1.user.oc1..foreign"
					} else {
						provider.tenancy = "ocid1.tenancy.oc1..foreign"
					}
					factory, factoryErr := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
					if factoryErr != nil {
						t.Fatal(factoryErr)
					}
					err = provisionOriginalFoundationCompartments(t.Context(), factory, f.roots, f.bundle)
				} else {
					if drift == "expired original" {
						f.bundle = signProvisionFoundation(t, f.prepared, f.bundle.RootChainWire, f.root, f.now.Add(-24*time.Hour))
					}
					err = f.run(t)
				}
				if err == nil || len(f.kmsDispatches()) != 4 || f.cloud.creates != 27 || !bytes.Equal(before, f.wire(t)) {
					t.Fatalf("KMS drift/revocation/deadline reset accepted originals or dispatched replacements: %v", err)
				}
			})
		}
	})

	t.Run("protected CAS retains original KMS scopes dependencies and proof", func(t *testing.T) {
		f := newOriginalVaultSDKFixture(t, "", 0)
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationVaultPending) {
			t.Fatal(err)
		}
		store, wire := f.store(t), f.wire(t)
		for name, mutate := range map[string]func(*FoundationRecord){
			"remove scope": func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[1].Vault = nil },
			"replace control": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.ControlCompartmentID = r.SharedCompartmentID
			},
			"replace network proof": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.NetworkProofSHA256 = strings.Repeat("a", 64)
			},
			"replace selected ID": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Vault.Vault.SelectedID = "ocid1.vault.oc1.sa-saopaulo-1.foreign"
			},
			"erase Vault body": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.Vault.Request = keymanagement.CreateVaultDetails{}
			},
			"replace key body": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.Key.Request.ProtectionMode = keymanagement.CreateKeyDetailsProtectionModeSoftware
			},
			"erase pending": func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[1].Vault.Vault.Pending = nil },
			"replace digest": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.Vault.Pending.Request.RequestDigest = strings.Repeat("a", 64)
			},
			"replace token": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.Key.Pending.Request.RetryToken = strings.Repeat("a", 64)
			},
			"replace first time": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.Key.Pending.FirstAttemptAt = r.OriginalFoundationCompartments.Regions[1].Vault.Key.Pending.FirstAttemptAt.Add(time.Second)
			},
			"erase provenance": func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[1].Vault.Vault.Provenance = nil },
			"replace accepted ID": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.Key.Provenance.ResourceID = "ocid1.key.oc1.us-sanjose-1.foreign"
			},
			"erase Vault endpoint": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.Vault.ManagementEndpoint = ""
			},
			"replace key endpoint": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.Key.ManagementEndpoint = "https://foreign-management.kms.us-sanjose-1.oraclecloud.com"
			},
			"replace key Vault": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.Key.VaultID = r.OriginalFoundationCompartments.Regions[0].Vault.Vault.SelectedID
			},
			"replace key version": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.Key.CurrentKeyVersion += "foreign"
			},
			"erase readback": func(r *FoundationRecord) {
				v := &r.OriginalFoundationCompartments.Regions[1].Vault.Key
				v.VerifiedAt = time.Time{}
				v.ReadbackSHA256 = ""
				v.CurrentKeyVersion = ""
			},
			"replace verification time": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].Vault.Key.VerifiedAt = r.OriginalFoundationCompartments.Regions[1].Vault.Key.VerifiedAt.Add(time.Second)
			},
			"runtime binding": func(r *FoundationRecord) {
				r.ResourceIDs["vault"] = r.OriginalFoundationCompartments.Regions[1].Vault.Vault.Provenance.ResourceID
			},
		} {
			record, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(wire, f.wire(t)) {
				t.Fatalf("protected original KMS CAS accepted %s: %v", name, err)
			}
		}
		f.assertVaultState(t)
		t.Run("first scope cannot import populated progress", func(t *testing.T) {
			f := newOriginalVaultSDKFixture(t, "uninitialized scope", 0)
			if err := f.run(t); err == nil || f.cloud.creates != 23 || len(f.kmsDispatches()) != 0 {
				t.Fatal("scope-initialization fault failed to stop before regional KMS effects")
			}
			store, wire := f.store(t), f.wire(t)
			record, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			for index := range record.OriginalFoundationCompartments.Regions {
				scope, err := originalVaultScope(record, index)
				if err != nil {
					t.Fatal(err)
				}
				record.OriginalFoundationCompartments.Regions[index].Vault = &scope
			}
			v := record.OriginalFoundationCompartments.Regions[0].Vault
			v.Vault.ManagementEndpoint = "https://prerequisite-management.kms." + foundationHomeRegion + ".oraclecloud.com"
			v.Vault.VerifiedAt = time.Now().UTC()
			record.UpdatedAt = v.Vault.VerifiedAt
			v.Vault.ReadbackSHA256, err = originalVaultReadback(v, 0, v.Vault.SelectedID)
			if err != nil {
				t.Fatal(err)
			}
			if err := record.validate(); err != nil {
				t.Fatalf("populated initial-scope refusal lacks otherwise coherent candidate: %v", err)
			}
			if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(wire, f.wire(t)) {
				t.Fatal("first Vault scope attachment imported progress instead of exact zero-progress original scope")
			}
		})
	})
}

func originalVaultAgeTimeline(t *testing.T, record *FoundationRecord) {
	t.Helper()
	age := func(value *time.Time) {
		if !value.IsZero() {
			*value = value.Add(-24 * time.Hour)
		}
	}
	age(&record.StartedAt)
	age(&record.NetBirdMaterial.BornAt)
	for index := range record.NetBirdMaterial.Creates {
		age(&record.NetBirdMaterial.Creates[index].FirstDispatchedAt)
	}
	for index := range record.OriginalSourceProducers {
		age(&record.OriginalSourceProducers[index].BornAt)
	}
	section := record.OriginalFoundationCompartments
	age(&section.BornAt)
	for index := range section.Regions {
		region := &section.Regions[index]
		for slot := range region.Compartments {
			entry := &region.Compartments[slot]
			if entry.Pending != nil {
				age(&entry.Pending.FirstAttemptAt)
			}
			if entry.Provenance != nil {
				entry.Provenance.Create = *entry.Pending
			}
			age(&entry.VerifiedAt)
		}
		for slot := range region.Network.Creates {
			entry := &region.Network.Creates[slot]
			if entry.Pending != nil {
				age(&entry.Pending.FirstAttemptAt)
			}
			if entry.Provenance != nil {
				entry.Provenance.Create = *entry.Pending
			}
			age(&entry.VerifiedAt)
		}
		age(&region.Network.Rules.ReservedAt)
		age(&region.Network.Rules.VerifiedAt)
		wire, err := json.Marshal(region.Network, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		region.Vault.NetworkProofSHA256 = preparationDigest(wire)
		for slot := range 2 {
			entry := originalVaultEntry(region.Vault, slot)
			if entry.Pending != nil {
				age(&entry.Pending.FirstAttemptAt)
			}
			if entry.Provenance != nil {
				entry.Provenance.Create = *entry.Pending
			}
			age(&entry.VerifiedAt)
		}
	}
}
