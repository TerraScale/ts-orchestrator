//go:build fixturetest

package bootstrapmaterial

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// This qualifies local durable publication against an actual root call;
// signed source and foundation authorization remain the backend's checks.
func TestJournalPublicationRetainsOriginalRootCall(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("this actual root-call filesystem boundary requires a root QA process")
	}
	for _, stage := range []string{"rename", "checkpoint"} {
		for _, loss := range []string{"cancel", "deadline"} {
			t.Run(stage+"/"+loss, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				directory := filepath.Join(t.TempDir(), "source")
				record, err := Generate(directory, testConfig(), time.Now().UTC().Add(-time.Second))
				if err != nil {
					t.Fatal(err)
				}
				metadata, err := os.ReadFile(filepath.Join(directory, metadataName))
				if err != nil {
					t.Fatal(err)
				}
				initial, err := rootoci.RootCall(ctx)
				if err != nil {
					t.Fatal(err)
				}
				target := VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..control",
					VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.vault", KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.key"}
				original, err := loadJournal(WithPublicationGuard(ctx, initial.Guard), directory, record, target, digest(metadata), nil)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(directory, journalName)
				prior, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				next := original
				next.Entries = slices.Clone(original.Entries)
				next.Entries[0].SentAt = time.Now().UTC()
				next.Entries[0].SecretOCID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.original"
				next.Entries[0].Verified = true
				nextWire, err := json.Marshal(next)
				if err != nil {
					t.Fatal(err)
				}
				callCtx, stopCall := context.WithCancel(ctx)
				if loss == "deadline" {
					stopCall()
					callCtx, stopCall = context.WithTimeout(ctx, time.Second)
				}
				defer stopCall()
				call, err := rootoci.RootCall(callCtx)
				if err != nil {
					t.Fatal(err)
				}
				reached, resume := make(chan struct{}), make(chan struct{})
				paused := false
				guarded := WithPublicationGuard(ctx, func(check context.Context) error {
					temporary, temporaryErr := os.ReadFile(filepath.Join(directory, journalTempName))
					published, publishedErr := os.ReadFile(path)
					atStage := stage == "rename" && temporaryErr == nil && bytes.Equal(temporary, nextWire) ||
						stage == "checkpoint" && errors.Is(temporaryErr, os.ErrNotExist) && publishedErr == nil && bytes.Equal(published, nextWire)
					if !paused && atStage {
						paused = true
						close(reached)
						select {
						case <-resume:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					return call.Guard(check)
				})
				checkpoints := 0
				finished := make(chan error, 1)
				go func() {
					finished <- checkpointJournal(guarded, directory, next, func([]byte) error {
						checkpoints++
						return nil
					})
				}()
				select {
				case <-reached:
				case err := <-finished:
					t.Fatalf("publication did not pause at %s after real filesystem Sync: %v", stage, err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if loss == "cancel" {
					stopCall()
				} else {
					select {
					case <-callCtx.Done():
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				close(resume)
				select {
				case err := <-finished:
					if !errors.Is(err, rootoci.ErrUnauthorized) {
						t.Fatalf("expired original call did not stop %s: %v", stage, err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if checkpoints != 0 {
					t.Fatal("lost original call reached the source checkpoint")
				}
				want := prior
				if stage == "checkpoint" {
					want = nextWire
				}
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, want) {
					t.Fatal("failed publication changed the durable journal outside its authorized stage", err)
				}
				recovery, err := rootoci.RootCall(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := checkpointJournal(WithPublicationGuard(ctx, recovery.Guard), directory, next, func(wire []byte) error {
					checkpoints++
					if !bytes.Equal(wire, nextWire) {
						return fmt.Errorf("recovery changed the original retry token or sent time")
					}
					return nil
				}); err != nil || checkpoints != 1 {
					t.Fatal("fresh original-scope call could not recover the exact journal", err)
				}
			})
		}
	}
}
