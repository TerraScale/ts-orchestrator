package regionops

import (
	"errors"
	"slices"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/identity"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

// OCI's own key subscribes a region, even one outside the product catalog.
func TestSubscriptionUsesOCIsRegionKeyOutsideTheCatalog(t *testing.T) {
	t.Parallel()

	tenancy := &fakeIdentity{status: map[string]identity.RegionSubscriptionStatusEnum{}}
	subscription := Subscription{API: tenancy, TenancyID: "ocid1.tenancy.oc1..test"}
	record := regionlifecycle.Record{Cell: "lhr", Proposal: regionlifecycle.Proposal{OCIRegion: "uk-london-1"}}
	_, err := subscription.Execute(t.Context(), record, regionlifecycle.StepIntent{Step: regionlifecycle.StepSubscribe,
		CreateKey: "token"})
	if !errors.Is(err, ErrSubscriptionInProgress) || !slices.Equal(tenancy.creates, []string{"LHR"}) {
		t.Fatalf("Execute = %v, creates %v; want an in-progress subscription under LHR", err, tenancy.creates)
	}
}

// A region must be listed by OCI, and its OCI key must name the record's cell.
func TestSubscriptionRefusesARegionOCIDoesNotListForTheCell(t *testing.T) {
	t.Parallel()

	tenancy := &fakeIdentity{status: map[string]identity.RegionSubscriptionStatusEnum{}}
	subscription := Subscription{API: tenancy, TenancyID: "ocid1.tenancy.oc1..test"}
	for _, record := range []regionlifecycle.Record{
		{Cell: "lhr", Proposal: regionlifecycle.Proposal{OCIRegion: "xx-nowhere-1"}},
		{Cell: "gru", Proposal: regionlifecycle.Proposal{OCIRegion: "us-sanjose-1"}},
	} {
		if _, err := subscription.Execute(t.Context(), record, regionlifecycle.StepIntent{}); err == nil {
			t.Fatalf("subscribed %s to %s", record.Cell, record.Proposal.OCIRegion)
		}
	}
	if len(tenancy.creates) != 0 {
		t.Fatalf("refused regions still created subscriptions: %v", tenancy.creates)
	}
}
