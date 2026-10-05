package oci

import (
	"context"
	"fmt"
	"slices"
)

// StaticHostObserver reads one operator-launched C# TerraBase host, which
// the fleet neither launched nor journaled. See fleet.ObserveStaticHost.
type StaticHostObserver interface {
	ObserveStaticHost(ctx context.Context, instanceID, node string) (CloudInstance, error)
}

// ObserveStaticHost returns a RUNNING instance in the fleet's compartment,
// availability domain and fault domains, booted from the pinned image with
// the fleet's boot size, subnet and NSGs (the provider verifies those and
// its primary private IP), tagged with node and no managed launch identity. The
// caller still binds the instance to its own enrollment claim.
func (f *fleet) ObserveStaticHost(ctx context.Context, instanceID, node string) (CloudInstance, error) {
	cloud, err := f.provider.GetInstance(ctx, instanceID)
	if err != nil {
		return CloudInstance{}, err
	}
	tags := cloud.FreeformTags
	if cloud.ID != instanceID || cloud.CompartmentID != f.config.CompartmentID ||
		cloud.AvailabilityDomain != f.config.AvailabilityDomain || !slices.Contains(f.config.FaultDomains, cloud.FaultDomain) ||
		cloud.LifecycleState != "RUNNING" || cloud.PrivateIP == "" ||
		tags[tagManagedBy] != "" || tags[tagCreateKey] != "" || node == "" || tags[tagHostNode] != node {
		return CloudInstance{}, fmt.Errorf("%w: instance %s is not a running static host of this regional fleet", ErrForeignResource, instanceID)
	}
	return cloud, nil
}
