package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// Returning the public DTO or its zero proof cannot authorize an OCI mutation.
type unverifiedWorkerAuthority struct{}

func (unverifiedWorkerAuthority) WorkerRecipes(context.Context, string, string, []byte) ([]region.VerifiedWorkerRecipe, error) {
	return []region.VerifiedWorkerRecipe{{}}, nil
}

func (unverifiedWorkerAuthority) AuthorizeWorkerRecipe(context.Context, region.WorkerRecipe) (region.VerifiedWorkerRecipe, error) {
	return region.VerifiedWorkerRecipe{}, nil
}

func TestCapacityRequiresIndependentWorkerProof(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte("public CA fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		authority capacityWorkerAuthority
	}{
		{"absent producer", nil},
		{"unverified producer result", unverifiedWorkerAuthority{}},
		{"concrete resolver without signed source", region.FoundationResolver{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reservations := &capacityReservations{cell: "gru", environment: "production", workers: test.authority, caFile: caFile}
			recipe := nodescale.Recipe{Cell: "gru", Capacity: nodescale.Capacity{Role: nodescale.RoleContainer, Architecture: "arm64", Shape: "VM.Standard.A1.Flex"}}
			if _, err := reservations.authorizeWorker(t.Context(), recipe, "ocid1.compartment.worker"); !errors.Is(err, nodescale.ErrCapacityPending) {
				t.Fatalf("worker without independent proof reached admission: %v", err)
			}
			if _, _, err := reservations.workerBase(t.Context(), nodescale.RoleContainer, "arm64"); err == nil {
				t.Fatal("worker without independent proof supplied a launch base")
			}
			if _, err := reservations.prepare(t.Context(), "operation", recipe, "ocid1.compartment.worker"); !errors.Is(err, nodescale.ErrCapacityPending) {
				t.Fatalf("worker without independent proof reached OCI inventory discovery: %v", err)
			}
		})
	}
}
