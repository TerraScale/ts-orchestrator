//go:build linux

package app

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootfoundation"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func TestTrafficFoundationRecheckRetainsEffectCapAndExactIdentity(t *testing.T) {
	deadline := time.Now().Add(time.Second)
	original := rootfoundation.TaskTrafficScope{Foundation: rootoci.FoundationReceipt{Cell: "GRU", GrantDigest: "grant", OperationID: "foundation", Generation: 3, Epoch: 7, Stage: "reconciled"},
		OCIRegion: "sa-saopaulo-1", CompartmentID: "network", ExpiresAt: deadline.Add(time.Minute)}
	current := original
	current.ExpiresAt = deadline
	if !rootTrafficFoundationCurrent(original, current, deadline) {
		t.Fatal("same scope shortened to the retained effect deadline was rejected")
	}
	for _, field := range []string{"expiry", "foundation", "region", "compartment"} {
		t.Run(field, func(t *testing.T) {
			changed := current
			switch field {
			case "expiry":
				changed.ExpiresAt = deadline.Add(-time.Nanosecond)
			case "foundation":
				changed.Foundation.Epoch++
			case "region":
				changed.OCIRegion = "us-ashburn-1"
			case "compartment":
				changed.CompartmentID = "replacement"
			}
			if rootTrafficFoundationCurrent(original, changed, deadline) {
				t.Fatalf("changed %s passed the retained scope", field)
			}
		})
	}
	current.ExpiresAt = deadline.Add(time.Hour)
	if !rootTrafficFoundationCurrent(original, current, deadline) || !original.ExpiresAt.Equal(deadline.Add(time.Minute)) {
		t.Fatal("later writer expiry changed the original scope cap")
	}
}
