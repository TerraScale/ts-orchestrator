package selfupdate

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestReceiptPolicyProjectsIndependentQualificationExpiry(t *testing.T) {
	for _, delegated := range []bool{false, true} {
		name := "root qualification"
		if delegated {
			name = "delegated qualification"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			data := []byte("qualified candidate")
			wire, grant := f.signed(data)
			envelope, err := trust.DecodeEnvelope(wire)
			if err != nil {
				t.Fatal(err)
			}
			var receipt release.BinaryUpdateReceipt
			if err := protocol.DecodeStrict(envelope.Payload, &receipt, trust.MaxPayloadBytes); err != nil {
				t.Fatal(err)
			}
			qualification, err := trust.DecodeEnvelope(receipt.Production.Qualification)
			if err != nil {
				t.Fatal(err)
			}
			expires := f.now.Add(time.Minute)
			private := f.rootPrivate
			if delegated {
				private = f.nodePrivate
				keyID, err := trust.KeyID(f.nodePublic)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := trust.EncodeDelegatedPublicKey(f.nodePublic)
				if err != nil {
					t.Fatal(err)
				}
				scope := qualification.Scope
				delegation, err := trust.SignDelegation(trust.Delegation{
					SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
					Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID,
						Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role,
						Slots: []string{scope.Slot}, Actions: []string{"sign"}}},
				}, f.now.Add(-time.Minute), expires, f.rootPrivate)
				if err != nil {
					t.Fatal(err)
				}
				receipt.Production.Delegation = f.encode(delegation)
			}
			qualification, err = trust.Sign(qualification.Payload, qualification.Scope, f.now, expires, private)
			if err != nil {
				t.Fatal(err)
			}
			receipt.Production.Qualification = f.encode(qualification)
			payload, err := trust.EncodePayload(receipt)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err = trust.Sign(payload, envelope.Scope, envelope.IssuedAt, envelope.ExpiresAt, f.leafPrivate)
			if err != nil {
				t.Fatal(err)
			}
			wire = f.encode(envelope)
			policy := f.policy()
			verified, err := policy.Verify(wire, grant, expires.Add(-time.Nanosecond))
			if err != nil || !verified.IsVerified() || !verified.ExpiresAt().Equal(expires) {
				t.Fatalf("consumer proof expiry = %s, %v; want %s", verified.ExpiresAt(), err, expires)
			}
			if !envelope.ExpiresAt.After(verified.ExpiresAt()) {
				t.Fatal("fixture must retain a longer-lived release signature")
			}
			if _, err := release.VerifyBinaryUpdateCurrent(wire, grant, f.roots,
				release.UpdateExpectation{Environment: "canary", Cell: "GRU", Architecture: runtime.GOARCH}, expires); err != nil {
				t.Fatalf("release authority must remain current at qualification expiry: %v", err)
			}
			if _, err := Stage(f.layout, bytes.NewReader(data), wire, grant, policy, expires); !errors.Is(err, trust.ErrExpired) {
				t.Fatalf("stage at qualification expiry = %v; want expired", err)
			}
			if _, err := os.Stat(f.layout.Root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expired qualification created staging effects: %v", err)
			}
		})
	}
}
