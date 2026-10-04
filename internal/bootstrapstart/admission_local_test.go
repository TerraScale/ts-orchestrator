package bootstrapstart

import (
	"errors"
	"testing"
)

func TestLocalRestartAdmissionNeedsNoOCIOrClock(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	marker, err := fixture.gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatalf("initial admission: %v", err)
	}
	manifestWire := fixture.ledger.state.ManifestRecord.Bytes
	historyCalls, currentCalls := fixture.ledger.historyCalls, fixture.ledger.currentCalls
	published := len(fixture.ledger.published)
	local := fixture.gate
	local.Instances, local.Ledgers = nil, nil
	local.ClockCheck = func() error { return errors.New("NTP unsynchronized") }
	admitted, err := local.AdmitRestartLocal(t.Context(), manifestWire)
	if err != nil || admitted.InstanceOCID != marker.InstanceOCID || admitted.AnchorSHA256 != marker.AnchorSHA256 {
		t.Fatalf("offline local restart admission = %+v, %v", admitted, err)
	}
	if fixture.ledger.historyCalls != historyCalls || fixture.ledger.currentCalls != currentCalls ||
		len(fixture.ledger.published) != published {
		t.Fatal("local restart admission touched the OCI ledger")
	}
	if fixture.material.restartCalls != 1 || fixture.credentials.calls != 2 {
		t.Fatalf("local restart admission skipped installed material checks: material=%d credentials=%d",
			fixture.material.restartCalls, fixture.credentials.calls)
	}

	other := local
	other.Descriptor = fixedDescriptor{slot: "controller-b", instance: "ocid1.instance.oc1.sa-saopaulo-1.other"}
	if _, err := other.AdmitRestartLocal(t.Context(), manifestWire); !errors.Is(err, ErrAdmission) {
		t.Fatalf("a different VM passed local restart admission: %v", err)
	}
	moved := local
	moved.Descriptor = fixedDescriptor{slot: "broker-b", instance: marker.InstanceOCID}
	if _, err := moved.AdmitRestartLocal(t.Context(), manifestWire); !errors.Is(err, ErrAdmission) {
		t.Fatalf("a different slot passed local restart admission: %v", err)
	}
	tampered := append([]byte(nil), manifestWire...)
	tampered[len(tampered)/2] ^= 1
	if _, err := local.AdmitRestartLocal(t.Context(), tampered); !errors.Is(err, ErrAdmission) {
		t.Fatalf("a tampered installed manifest passed local restart admission: %v", err)
	}
	reconfigured := local
	reconfigured.LoadedControllerConfigSHA256 = digest([]byte("unsigned controller config"))
	if _, err := reconfigured.AdmitRestartLocal(t.Context(), manifestWire); !errors.Is(err, ErrAdmission) {
		t.Fatalf("an unsigned controller config passed local restart admission: %v", err)
	}
	fixture.credentials.err = ErrLiveCredentials
	if _, err := local.AdmitRestartLocal(t.Context(), manifestWire); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("invalid live credentials passed local restart admission: %v", err)
	}
	fixture.credentials.err = nil
	missing := local
	missing.Material = nil
	if _, err := missing.AdmitRestartLocal(t.Context(), manifestWire); !errors.Is(err, ErrAdmission) {
		t.Fatalf("local restart admission ran without a material verifier: %v", err)
	}
}
