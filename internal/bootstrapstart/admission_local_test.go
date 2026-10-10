package bootstrapstart

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/identityrekey"
)

func TestLocalRestartAdmissionNeedsNoInitialInputsOCIOrClock(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
		t.Fatal(err)
	}
	accepted, err := fixture.gate.Markers.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(fixture.gate.Markers.directory, initialFormationName)); err != nil {
		t.Fatal(err)
	}
	local := fixture.gate
	local.Roots, local.AnchorWire, local.Expected = nil, nil, bootstrap.BootstrapAnchorExpectation{}
	local.Instances, local.Ledgers, local.InitialIdentity = nil, nil, nil
	local.ClockCheck = func() error { t.Fatal("local routes checked NTP"); return nil }
	fixture.ledger.state = bootstrap.SlotState{}
	calls, published := fixture.ledger.currentCalls, len(fixture.ledger.published)
	admitted, err := local.AdmitRestartLocal(t.Context())
	if err != nil || admitted.OperationID != accepted.OperationID {
		t.Fatalf("local restart without initial files/history = %+v, %v", admitted, err)
	}
	if fixture.ledger.currentCalls != calls || fixture.ledger.historyCalls != 0 || len(fixture.ledger.published) != published {
		t.Fatal("local admission touched the ledger")
	}
	if fixture.material.restartCalls != 1 || fixture.credentials.calls != 2 {
		t.Fatal("local admission skipped installed material or live credentials")
	}
	for name, mutate := range map[string]func(*Gate){
		"another instance": func(g *Gate) {
			g.Descriptor = fixedDescriptor{slot: accepted.Slot, instance: "ocid1.instance.oc1.sa-saopaulo-1.other"}
		},
		"another slot":         func(g *Gate) { g.Descriptor = fixedDescriptor{slot: "controller-a", instance: accepted.InstanceOCID} },
		"another config":       func(g *Gate) { g.LoadedControllerConfigSHA256 = digest([]byte("unsigned config")) },
		"no material verifier": func(g *Gate) { g.Material = nil },
		"no identity observer": func(g *Gate) { g.ObserveIdentity = nil },
	} {
		t.Run(name, func(t *testing.T) {
			gate := local
			mutate(&gate)
			if _, err := gate.AdmitRestartLocal(t.Context()); !errors.Is(err, ErrAdmission) {
				t.Fatalf("accepted invalid local boundary: %v", err)
			}
		})
	}
	fixture.credentials.err = ErrLiveCredentials
	if _, err := local.AdmitRestartLocal(t.Context()); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("invalid live credentials admitted: %v", err)
	}
}

func TestAcceptedRestartRequiresExactInstalledBrokerAndStore(t *testing.T) {
	for _, name := range []string{"absent store", "changed store file", "changed observed broker", "changed observed store"} {
		t.Run(name, func(t *testing.T) {
			fixture := newAdmissionFlowFixture(t)
			if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
				t.Fatal(err)
			}
			accepted, err := fixture.gate.Markers.ReadIdentity()
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "absent store":
				if err := os.Remove(filepath.Join(accepted.Store.Directory, "server-name")); err != nil {
					t.Fatal(err)
				}
			case "changed store file":
				if err := os.WriteFile(filepath.Join(accepted.Store.Directory, "server-name"), []byte("another-server\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				fixture.gate.ObserveIdentity = func(AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
					broker, store := accepted.Broker, accepted.Store
					if name == "changed observed broker" {
						broker.HostSigner = accepted.Broker.CellAccount
					} else {
						store.RaftNodeID = "CHANGED1"
					}
					return broker, store, nil
				}
			}
			if _, err := fixture.gate.AdmitRestartLocal(t.Context()); err == nil {
				t.Fatal("changed installed identity admitted")
			}
			if fixture.material.restartCalls != 0 || fixture.credentials.calls != 1 {
				t.Fatal("changed store reached later verification")
			}
		})
	}
}

func TestAcceptedRestartDetectsSnapshotChangesAndCancellation(t *testing.T) {
	for _, name := range []string{"snapshot changed", "canceled"} {
		t.Run(name, func(t *testing.T) {
			fixture := newAdmissionFlowFixture(t)
			if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fixture.credentials.onVerify = func() {
				if name == "canceled" {
					cancel()
					return
				}
				accepted, err := fixture.gate.Markers.ReadIdentity()
				if err != nil {
					t.Fatal(err)
				}
				accepted.OperationID = "0000000000T9P5D5DS78CYMC9A"
				wire, err := EncodeAcceptedIdentity(accepted)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fixture.gate.Markers.directory, markerName), wire, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			_, err := fixture.gate.AdmitRestartLocal(ctx)
			if name == "snapshot changed" && !errors.Is(err, ErrAdmission) || name == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("late boundary change admitted: %v", err)
			}
		})
	}
}

func TestRestartAdmissionRequiresExactAuthenticatedOCIObservation(t *testing.T) {
	for name, mutate := range map[string]func(*InstanceObservation){
		"instance":     func(o *InstanceObservation) { o.InstanceOCID += "-other" },
		"image":        func(o *InstanceObservation) { o.ImageOCID += "-other" },
		"VNIC":         func(o *InstanceObservation) { o.PrimaryVNICOCID += "-other" },
		"private IP":   func(o *InstanceObservation) { o.PrimaryPrivateIP = "10.0.0.4" },
		"primary flag": func(o *InstanceObservation) { o.PrimaryVNIC = false },
		"lifecycle":    func(o *InstanceObservation) { o.LifecycleState = "STOPPED" },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newAdmissionFlowFixture(t)
			if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
				t.Fatal(err)
			}
			observer := fixture.gate.Instances.(fakeInstanceObserver)
			mutate(&observer.observation)
			fixture.gate.Instances = observer
			if _, err := fixture.gate.AdmitRestart(t.Context()); !errors.Is(err, ErrAdmission) {
				t.Fatalf("OCI mismatch admitted: %v", err)
			}
		})
	}
}

func TestRestartAdmissionChecksNTPBeforeAndAfterOCI(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			fixture := newAdmissionFlowFixture(t)
			if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
				t.Fatal(err)
			}
			checks, observations := 0, 0
			fixture.gate.ClockCheck = func() error {
				checks++
				if checks == failAt {
					return errors.New("NTP unsynchronized")
				}
				return nil
			}
			original := fixture.gate.Instances
			fixture.gate.Instances = instanceObserverFunc(func(ctx context.Context, id string) (InstanceObservation, error) {
				observations++
				return original.ObserveInstance(ctx, id)
			})
			if _, err := fixture.gate.AdmitRestart(t.Context()); !errors.Is(err, ErrAdmission) {
				t.Fatalf("NTP failure admitted: %v", err)
			}
			if checks != failAt || observations != failAt-1 {
				t.Fatalf("NTP/OCI ordering: checks=%d OCI=%d", checks, observations)
			}
		})
	}
}

type instanceObserverFunc func(context.Context, string) (InstanceObservation, error)

func (observe instanceObserverFunc) ObserveInstance(ctx context.Context, id string) (InstanceObservation, error) {
	return observe(ctx, id)
}

func TestAdmissionRefusesRekeyJournalBeforeInitialOrRestartEffects(t *testing.T) {
	for _, initial := range []bool{true, false} {
		t.Run(map[bool]string{true: "initial", false: "restart"}[initial], func(t *testing.T) {
			fixture := newAdmissionFlowFixture(t)
			if !initial {
				if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(fixture.gate.Markers.directory, identityRekeyJournalName), []byte(`{}`), 0o644); err != nil {
				t.Fatal(err)
			}
			calls := fixture.ledger.currentCalls
			var err error
			if initial {
				_, err = fixture.gate.AdmitInitial(t.Context())
			} else {
				_, err = fixture.gate.AdmitRestartLocal(t.Context())
			}
			if err == nil {
				t.Fatal("malformed rekey journal admitted")
			}
			if fixture.ledger.currentCalls != calls || fixture.material.restartCalls != 0 || initial && fixture.material.initialCalls != 0 {
				t.Fatal("journal failure reached effects")
			}
		})
	}
}

func TestAcceptedRestartRefusesMaterialVerificationFailure(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
		t.Fatal(err)
	}
	fixture.material.restartErr = ErrMaterial
	if _, err := fixture.gate.AdmitRestartLocal(t.Context()); !errors.Is(err, ErrMaterial) {
		t.Fatalf("material failure admitted: %v", err)
	}
	if fixture.credentials.calls != 1 {
		t.Fatal("invalid material reached live credential verification")
	}
}

func TestAcceptedRestartRejectsPendingRootedJournalBeforeAdapters(t *testing.T) {
	journal, inputs, target := identityRekeyJournalFixture(t)
	fixture := newAdmissionFlowFixture(t)
	store := admissionTrustStore(t, inputs.Genesis)
	fixture.gate.trustStore = &store
	predecessor := target.Clone()
	predecessor.OperationID = "0000000000T9P5D5DS78CYMC9A"
	wire, err := EncodeAcceptedIdentity(predecessor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.gate.Markers.directory, markerName), wire, 0o644); err != nil {
		t.Fatal(err)
	}
	journalWire, err := encodeIdentityRekeyJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.gate.Markers.directory, identityRekeyJournalName), journalWire, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.gate.AdmitRestartLocal(t.Context()); !errors.Is(err, ErrIdentityRekeyLocalPending) {
		t.Fatalf("pending root plan admitted: %v", err)
	}
	if fixture.material.restartCalls != 0 || fixture.credentials.calls != 0 {
		t.Fatal("pending plan reached restart adapters")
	}
}
