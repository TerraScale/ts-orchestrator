package fleet

import (
	"context"
	"fmt"
	"slices"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func regionalVCN(ctx context.Context, region Region, client core.VirtualNetworkClient) (string, error) {
	vcns, err := list("regional VCN", func(page *string) ([]core.Vcn, *string, error) {
		r, err := client.ListVcns(ctx, core.ListVcnsRequest{CompartmentId: common.String(region.CompartmentID), Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return "", err
	}
	return ownedRegionalVCN(region, vcns)
}

func ownedRegionalVCN(region Region, vcns []core.Vcn) (string, error) {
	owned := slices.DeleteFunc(slices.Clone(vcns), func(v core.Vcn) bool {
		return gone(string(v.LifecycleState)) || !region.owns("vcn", "vcn", v.FreeformTags)
	})
	if len(owned) != 1 {
		return "", fmt.Errorf("region %s needs exactly one document-made VCN, found %d", region.Label, len(owned))
	}
	vcn := owned[0]
	if vcn.LifecycleState != core.VcnLifecycleStateAvailable || deref(vcn.CompartmentId) != region.CompartmentID ||
		deref(vcn.Id) == "" || !slices.Equal(vcn.CidrBlocks, []string{region.VCNCIDR}) {
		return "", fmt.Errorf("region %s owned VCN %s must be AVAILABLE in compartment %s with CIDR %s", region.Label, deref(vcn.Id), region.CompartmentID, region.VCNCIDR)
	}
	return deref(vcn.Id), nil
}
