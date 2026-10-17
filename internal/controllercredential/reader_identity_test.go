package controllercredential

import (
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

// These inputs check descriptive identity retention, not credential authority.
func TestControllerReaderSourceIdentityPinsOriginalMaterial(t *testing.T) {
	expires := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	fixture := func() (controllerReaderSnapshot, []controllerReaderMaterial) {
		return controllerReaderSnapshot{
			accepted: bootstrapstart.AcceptedIdentity{Cell: "gru", Slot: "controller-a", ConfigSHA256: map[string]string{"b": "two", "a": "one"}},
			chain:    []byte("retained-signed-chain"), config: []byte("retained-exact-config"),
		}, []controllerReaderMaterial{{Reference: bootstrap.SecretReference{
			SecretOCID: "original-secret", VersionNumber: 7, SHA256: "original-signed-digest", TargetFile: "controller.creds",
		}, SHA256: "original-verified-bytes-digest", ExpiresAt: expires}}
	}
	snapshot, material := fixture()
	original, err := controllerReaderSourceIdentity(snapshot, material, expires)
	if err != nil || len(original) != 64 {
		t.Fatalf("original identity = %q, %v", original, err)
	}
	snapshot.accepted.ConfigSHA256 = map[string]string{"a": "one", "b": "two"}
	stable, err := controllerReaderSourceIdentity(snapshot, material, expires)
	if err != nil || stable != original {
		t.Fatalf("map insertion order changed original identity: %q, %v", stable, err)
	}
	for name, change := range map[string]func(*controllerReaderSnapshot, []controllerReaderMaterial, *time.Time){
		"accepted scope": func(s *controllerReaderSnapshot, _ []controllerReaderMaterial, _ *time.Time) {
			s.accepted.Slot = "controller-b"
		},
		"signed chain": func(s *controllerReaderSnapshot, _ []controllerReaderMaterial, _ *time.Time) { s.chain[0]++ },
		"exact config": func(s *controllerReaderSnapshot, _ []controllerReaderMaterial, _ *time.Time) { s.config[0]++ },
		"secret version": func(_ *controllerReaderSnapshot, m []controllerReaderMaterial, _ *time.Time) {
			m[0].Reference.VersionNumber++
		},
		"actual bytes": func(_ *controllerReaderSnapshot, m []controllerReaderMaterial, _ *time.Time) {
			m[0].SHA256 = "different-bytes"
		},
		"bundle cap": func(_ *controllerReaderSnapshot, m []controllerReaderMaterial, _ *time.Time) {
			m[0].ExpiresAt = expires.Add(time.Second)
		},
		"source cap": func(_ *controllerReaderSnapshot, _ []controllerReaderMaterial, cap *time.Time) {
			*cap = cap.Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			snapshot, material := fixture()
			cap := expires
			change(&snapshot, material, &cap)
			changed, err := controllerReaderSourceIdentity(snapshot, material, cap)
			if err != nil || changed == original {
				t.Fatalf("changed original material retained identity: %q, %v", changed, err)
			}
		})
	}
}

func TestControllerReaderSourceIdentityRejectsUnopenedReader(t *testing.T) {
	for _, reader := range []*ControllerReader{nil, {}} {
		identity, expires, err := reader.SourceIdentity(t.Context())
		if !errors.Is(err, ErrDelivery) || identity != "" || !expires.IsZero() {
			t.Fatalf("unopened reader returned source identity %q, %s, %v", identity, expires, err)
		}
	}
}
