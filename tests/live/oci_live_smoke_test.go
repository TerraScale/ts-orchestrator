//go:build live_oci

package live

import (
	"context"
	"os"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

// TestOCIEstateLiveSmoke performs only signed GET requests. It proves the
// reviewed estate and instance-principal policy bindings without creating or
// changing cloud resources.
func TestOCIEstateLiveSmoke(t *testing.T) {
	if os.Getenv("TS_ORCH_OCI_LIVE") != "1" {
		t.Skip("set TS_ORCH_OCI_LIVE=1 and build with -tags live_oci to run")
	}
	estateFile := os.Getenv("TS_ORCH_OCI_ESTATE_FILE")
	if estateFile == "" {
		t.Fatal("TS_ORCH_OCI_ESTATE_FILE is required on an OCI compute instance")
	}
	spec, err := provider.LoadOCIEstateSpec(estateFile)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := provider.NewOCIEstateHTTPReader(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := provider.VerifyOCIEstate(ctx, spec, reader); err != nil {
		t.Fatal(err)
	}
}
