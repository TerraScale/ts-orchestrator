package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestIdentityRekeyAbortRequiresPermanentFenceAndExactUnaffectedFiles(t *testing.T) {
	for _, fault := range []string{"renewal", "empty slot", "committed barrier", "changed acceptance", "changed journal", "cancelled", "changed store", "wrong digest", "archive collision"} {
		t.Run(fault, func(t *testing.T) {
			markers, baked, journal, inputs, accepted := rootInstallerFixture(t)
			journal.Replicas = 1
			if err := markers.WriteIdentityRekeyJournal(journal, inputs, acceptedObservation, accepted.AcceptedAt); err != nil {
				t.Fatal(err)
			}
			wire, err := encodeIdentityRekeyJournal(journal)
			if err != nil {
				t.Fatal(err)
			}
			expected := digest(wire)
			js := completionJetStream(t)
			for i := range 10 {
				subject, data := protocol.ControlRoot+".gru.host.audit", []byte("retained audit")
				if i == 8 {
					subject, data = protocol.ControlRoot+".gru.lease", []byte("obsolete identity bytes are opaque")
				}
				if _, err := js.Publish(t.Context(), subject, data); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "committed barrier" {
				verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, false)
				if err != nil {
					t.Fatal(err)
				}
				envelope, _ := verified.ResetEnvelope()
				if _, err := authority.ResetIdentityLease(t.Context(), js, envelope, verified.AcceptedRoots(), verified.ResetTarget(), accepted.AcceptedAt); err != nil {
					t.Fatal(err)
				}
			} else if fault != "empty slot" {
				if _, err := js.Publish(t.Context(), protocol.ControlRoot+".gru.lease", []byte("ordinary renewed opaque lease")); err != nil {
					t.Fatal(err)
				}
			}
			ctx := t.Context()
			observe := IdentityObservation(acceptedObservation)
			switch fault {
			case "changed acceptance":
				if err := os.WriteFile(filepath.Join(markers.directory, markerName), journal.AcceptedWire, 0o644); err != nil {
					t.Fatal(err)
				}
			case "changed journal":
				if err := os.WriteFile(filepath.Join(markers.directory, identityRekeyJournalName), append(wire, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "changed store":
				observe = func(a AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
					broker, store, err := acceptedObservation(a)
					store.RaftNodeID = "OTHER000"
					return broker, store, err
				}
			case "wrong digest":
				expected = strings.Repeat("a", 64)
			case "archive collision":
				if err := os.WriteFile(filepath.Join(markers.directory, "identity-rekey.aborted."+expected+".json"), []byte("existing evidence"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(filepath.Join(markers.directory, markerName))
			if err != nil {
				t.Fatal(err)
			}
			err = markers.abortIdentityRekeyJournal(ctx, expected, js, observe, baked)
			if (err == nil) != (fault == "renewal") {
				t.Fatalf("abort %s = %v", fault, err)
			}
			after, readErr := os.ReadFile(filepath.Join(markers.directory, markerName))
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatal("abort changed accepted installation")
			}
			if fault == "renewal" {
				archived, err := os.ReadFile(filepath.Join(markers.directory, "identity-rekey.aborted."+expected+".json"))
				if err != nil || !bytes.Equal(archived, wire) {
					t.Fatal("exact aborted evidence was not retained")
				}
				if _, err := os.Stat(filepath.Join(markers.directory, identityRekeyJournalName)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("aborted journal remained active")
				}
			} else if _, err := os.Stat(filepath.Join(markers.directory, identityRekeyJournalName)); err != nil {
				t.Fatal("refused abort removed active evidence")
			}
		})
	}
}
