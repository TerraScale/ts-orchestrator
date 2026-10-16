package region

import (
	"context"
	"errors"
	"maps"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
)

// FoundationResourceReference names one immutable resource role in the signed
// foundation grant; observations and caller-selected OCIDs cannot authorize it.
func FoundationResourceReference(cell, key string) (string, error) {
	return foundationbinding.Reference(cell, key)
}

// ResourceBindings independently verifies the grant, protected creation journal
// and exact current SDK resources before exposing any logical authorization.
func (r FoundationResolver) ResourceBindings(ctx context.Context, cell string) (foundationbinding.VerifiedBindings, error) {
	return r.ResourceBindingsFor(ctx, cell)
}

// ResourceBindingsFor narrows observation to already-created signed roles when
// a finite bootstrap allocation is needed before the whole region exists.
func (r FoundationResolver) ResourceBindingsFor(ctx context.Context, cell string, keys ...string) (foundationbinding.VerifiedBindings, error) {
	reader, ok := r.Footprint.(*SignedFootprint)
	if !ok {
		return foundationbinding.VerifiedBindings{}, errors.New("logical resource bindings require an independently authenticated signed foundation")
	}
	wire, err := reader.readGrant(ctx)
	if err != nil {
		return foundationbinding.VerifiedBindings{}, err
	}
	return reader.resourceBindingsFor(ctx, cell, wire, keys...)
}

func (r FoundationResolver) ResolveResource(ctx context.Context, reference string) (string, error) {
	cell, _, err := foundationbinding.Parse(reference)
	if err != nil {
		return "", err
	}
	bindings, err := r.ResourceBindings(ctx, cell)
	if err != nil {
		return "", err
	}
	return bindings.Resolve(reference)
}

func (s *SignedFootprint) resourceBindings(ctx context.Context, cell string, wire []byte) (foundationbinding.VerifiedBindings, error) {
	return s.resourceBindingsFor(ctx, cell, wire)
}

func (s *SignedFootprint) resourceBindingsFor(ctx context.Context, cell string, wire []byte, keys ...string) (foundationbinding.VerifiedBindings, error) {
	if s.factory == nil {
		return foundationbinding.VerifiedBindings{}, errors.New("logical resource binding requires the authenticated production OCI factory")
	}
	if _, _, err := s.verifyGrant(wire); err != nil {
		return foundationbinding.VerifiedBindings{}, err
	}
	return foundationbinding.Verify(ctx, s.factory, foundationbinding.Authority{Scope: s.scope, Roots: s.roots,
		Policy: bootstrap.BootstrapAnchorTrustPolicy(), GrantSHA256: s.home.GrantSHA256, Generation: s.home.GrantGeneration,
		InstallationID: s.home.InstallationID, TenancyID: s.tenancy, Namespace: s.storage.Namespace,
		Bucket: s.storage.HeadBucket, Prefix: s.storage.Prefix, Cell: cell, Keys: keys}, wire)
}

func (s *SignedFootprint) boundStartup(ctx context.Context, startup BootstrapStartupIntent, plan map[string]any, wire []byte) (BootstrapStartupIntent, map[string]any, error) {
	if !hasFoundationReference(startup) {
		return startup, plan, nil
	}
	cell, _ := plan["cell"].(string)
	bindings, err := s.resourceBindings(ctx, cell, wire)
	if err != nil {
		return BootstrapStartupIntent{}, nil, err
	}
	projected, err := bootstrap.ProjectFoundationStartup(startup, bindings)
	if err != nil {
		return BootstrapStartupIntent{}, nil, err
	}
	bound := maps.Clone(plan)
	ids, _ := plan["resource_ids"].(map[string]any)
	ids = maps.Clone(ids)
	for _, key := range []string{"control_compartment", "network_compartment", "workload_compartment", "subnet", "network_security_group", "workload_network_security_group", "vault", "key"} {
		if pinned, _ := ids[key].(string); pinned != "" {
			continue
		}
		ref, _ := FoundationResourceReference(cell, key)
		if id, err := bindings.Resolve(ref); err == nil {
			ids[key] = id
		}
	}
	bound["resource_ids"] = ids
	return projected, bound, nil
}

func hasFoundationReference(startup BootstrapStartupIntent) bool {
	for _, profile := range startup.Profiles {
		if strings.HasPrefix(profile.CompartmentOCID, "foundation:") || strings.HasPrefix(profile.SubnetOCID, "foundation:") {
			return true
		}
		for _, id := range profile.NetworkSecurityGroupOCIDs {
			if strings.HasPrefix(id, "foundation:") {
				return true
			}
		}
	}
	for _, file := range startup.ControllerFiles {
		if strings.Contains(string(file.Bytes), "foundation:") {
			return true
		}
	}
	if startup.FounderResources != nil {
		for _, slot := range startup.FounderResources.Slots {
			if strings.HasPrefix(slot.ImageCompartmentOCID, "foundation:") {
				return true
			}
		}
	}
	if startup.ManagedMaterial != nil {
		domain := startup.ManagedMaterial
		return strings.HasPrefix(domain.KMSKeyOCID, "foundation:") || strings.HasPrefix(domain.MemberCompartmentOCID, "foundation:") || strings.HasPrefix(domain.MemberSubnetOCID, "foundation:")
	}
	return false
}
