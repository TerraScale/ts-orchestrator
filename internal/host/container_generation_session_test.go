//go:build linux

package host

import (
	"context"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestContainerGenerationObservationRejectsSessionReplacement(t *testing.T) {
	c, _, original, _ := reportedTestHost(t)
	admitted, err := (&Reader{controller: c}).AdmitContainerGenerationSession(t.Context(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if !admitted.Deadline().Equal(original.ExpiresAt) {
		t.Fatal("generation observation did not preserve its original host session deadline")
	}
	current, revision, _, err := c.sessionSnapshot(t.Context(), sessionKey(c.cell, "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	current.SessionID, current.Epoch = entityid.New(), current.Epoch+1
	if _, err := c.cas(t.Context(), sessionKey(c.cell, "node-a"), current, revision); err != nil {
		t.Fatal(err)
	}
	if err := admitted.Guard(t.Context()); err == nil {
		t.Fatal("generation observation followed a successor host session")
	}
}

func TestRootCredentialFloorPinsCurrentSessionDuringRead(t *testing.T) {
	for _, operation := range []string{"container-material", "generation"} {
		t.Run(operation, func(t *testing.T) {
			controller, _, _, _, _ := testControllerWithVerifier(t,
				managedRegistrationVerifierFunc(func(context.Context, Registration) error { return nil }))
			registration, _, key := managedContractFixture()
			registration.ManagedPlacement = &ManagedPlacementBinding{
				DatabaseID: "0000000000WVSMBJNMAWCDJBSK", PartitionID: "0000000000Z3WK359G2W66CVT8", SeatID: "000000000077F1R6E1XPKAC2D4",
				IntentGeneration: 1, IntentPayloadDigest: strings.Repeat("a", 64),
				CanonicalRosterDigest: strings.Repeat("b", 64), ManagedHostProfileDigest: strings.Repeat("c", 64),
			}
			if _, err := controller.Register(t.Context(), registration); err != nil {
				t.Fatal(err)
			}
			controller.credentialFloor = func(context.Context, Registration) (uint64, error) { return 1, nil }
			acquire := signedHostRequest(t, key, "session", entityid.New(), 0, struct {
				Kind string `json:"kind"`
			}{"acquire"})
			result, err := controller.handleSession(t.Context(), acquire)
			if err != nil {
				t.Fatal(err)
			}
			current := result.(session)
			reads := 0
			controller.credentialFloor = func(ctx context.Context, _ Registration) (uint64, error) {
				reads++
				if GuardCredentialFloorSession(ctx) != nil {
					t.Fatal("actual original floor session was not retained")
				}
				deadline, ok := ctx.Deadline()
				if !ok || deadline.After(current.ExpiresAt) {
					t.Fatal("credential read exceeded the original current session expiry")
				}
				_, revision, _, err := controller.sessionSnapshot(ctx, sessionKey(controller.cell, registration.Node))
				if err != nil {
					t.Fatal(err)
				}
				successor := current
				successor.SessionID, successor.Epoch = entityid.New(), current.Epoch+1
				if _, err := controller.cas(ctx, sessionKey(controller.cell, registration.Node), successor, revision); err != nil {
					t.Fatal(err)
				}
				if GuardCredentialFloorSession(ctx) == nil {
					t.Fatal("per-wire floor guard accepted a replacement session")
				}
				return 1, nil
			}
			reader := &Reader{controller: controller}
			if operation == "generation" {
				_, err = reader.AdmitContainerGenerationSession(t.Context(), registration.Node)
			} else {
				req := signedHostRequest(t, key, operation, current.SessionID, current.Epoch, struct{}{})
				_, _, err = reader.currentContainerMaterialSession(t.Context(), req)
			}
			if err == nil || reads != 1 {
				t.Fatal("credential floor accepted a replacement session during its read", err, reads)
			}
		})
	}
}

func TestCredentialFloorGuardRejectsMissingOriginalSession(t *testing.T) {
	if GuardCredentialFloorSession(t.Context()) == nil || GuardCredentialFloorSession(nil) == nil {
		t.Fatal("floor guard accepted a caller context without the actual original session")
	}
}
