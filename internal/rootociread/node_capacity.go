package rootociread

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/limits"
)

// ObserveNodeCapacity derives the worker scope locally; the caller supplies no IDs.
func (b *Backend) ObserveNodeCapacity(ctx context.Context, call rootoci.Call) (rootoci.NodeCapacityObservation, error) {
	ctx, cancel, scope, err := b.begin(ctx, call, rootoci.OperationObserveNodeCapacity)
	defer cancel()
	if err != nil {
		return rootoci.NodeCapacityObservation{}, err
	}
	bindings, compartment, err := nodeWorkerBindings(ctx, scope)
	if err != nil {
		return rootoci.NodeCapacityObservation{}, err
	}
	observed := rootoci.NodeCapacityObservation{Cell: scope.cell, OCIRegion: b.factory.Region(), GrantSHA256: scope.grant, Generation: bindings.Generation(), WorkerCompartmentID: compartment, ObservedAt: time.Now().UTC(), ExpiresAt: bindings.ExpiresAt()}
	if deadline := observed.ObservedAt.Add(2 * time.Minute); deadline.Before(observed.ExpiresAt) {
		observed.ExpiresAt = deadline
	}
	state, err := nodescale.ReadNodePoolCapacity(ctx, b.factory, strings.ToLower(scope.cell), compartment)
	if err != nil {
		return rootoci.NodeCapacityObservation{}, err
	}
	observed.Pools = state.Pools
	retained := map[string][]region.VerifiedWorkerProfile{}
	for _, role := range []string{nodescale.RoleContainer, nodescale.RoleWasm} {
		profiles, err := scope.resolver.WorkerProfiles(ctx, scope.cell, role)
		if err != nil {
			observed.Pending = append(observed.Pending, fmt.Sprintf("%s worker profiles: %v", role, err))
			continue
		}
		for _, profile := range profiles {
			if !profile.IsVerified() || profile.GrantDigest() != scope.grant || profile.Generation() != bindings.Generation() || !time.Now().Before(profile.ExpiresAt()) {
				return rootoci.NodeCapacityObservation{}, errors.New("worker capacity profile differs from current finite authority")
			}
			if profile.ExpiresAt().Before(observed.ExpiresAt) {
				observed.ExpiresAt = profile.ExpiresAt()
			}
		}
		retained[role] = profiles
	}
	if len(retained) > 0 {
		candidates, pending, err := b.nodeCandidates(ctx, scope, compartment, retained, observed.ExpiresAt)
		if err != nil {
			return rootoci.NodeCapacityObservation{}, err
		}
		observed.Candidates, observed.Pending = candidates, append(observed.Pending, pending...)
	}
	if err := bindings.Revalidate(ctx); err != nil {
		return rootoci.NodeCapacityObservation{}, err
	}
	for role, original := range retained {
		current, err := scope.resolver.WorkerProfiles(ctx, scope.cell, role)
		if err != nil || !sameNodeProfiles(original, current) {
			return rootoci.NodeCapacityObservation{}, errors.Join(err, errors.New("current worker image or profile changed during capacity observation"))
		}
	}
	if !time.Now().Before(observed.ExpiresAt) {
		return rootoci.NodeCapacityObservation{}, ErrPending
	}
	if err := b.finish(ctx, call, scope); err != nil {
		return rootoci.NodeCapacityObservation{}, err
	}
	if !time.Now().Before(observed.ExpiresAt) {
		return rootoci.NodeCapacityObservation{}, ErrPending
	}
	return observed, nil
}

func nodeWorkerBindings(ctx context.Context, scope scope) (foundationbinding.VerifiedBindings, string, error) {
	bindings, err := scope.resolver.ResourceBindingsFor(ctx, scope.cell, "workload_compartment")
	if err != nil {
		return foundationbinding.VerifiedBindings{}, "", err
	}
	if bindings.GrantSHA256() != scope.grant || bindings.Generation() == 0 || !time.Now().Before(bindings.ExpiresAt()) {
		return foundationbinding.VerifiedBindings{}, "", ErrPending
	}
	reference, err := region.FoundationResourceReference(scope.cell, "workload_compartment")
	if err != nil {
		return foundationbinding.VerifiedBindings{}, "", err
	}
	compartment, err := bindings.Resolve(reference)
	return bindings, compartment, err
}

func sameNodeProfiles(before, after []region.VerifiedWorkerProfile) bool {
	if len(before) != len(after) {
		return false
	}
	for i, original := range before {
		current := after[i]
		originalID, originalSHA, originalEnvelope := original.CurrentImage()
		currentID, currentSHA, currentEnvelope := current.CurrentImage()
		if !current.IsVerified() || !time.Now().Before(original.ExpiresAt()) || !time.Now().Before(current.ExpiresAt()) || original.GrantDigest() != current.GrantDigest() || original.Generation() != current.Generation() || originalID != currentID || originalSHA != currentSHA || originalEnvelope != currentEnvelope || !reflect.DeepEqual(original.Profile(), current.Profile()) {
			return false
		}
	}
	return true
}

func (b *Backend) nodeCandidates(ctx context.Context, scope scope, compartment string, profiles map[string][]region.VerifiedWorkerProfile, expires time.Time) ([]rootoci.NodeCandidateObservation, []string, error) {
	approved, err := scope.footprint.AuthorizedRegions(ctx)
	if err != nil || approved.TenancyID == "" || approved.GrantSHA256 != scope.grant {
		return nil, nil, errors.Join(err, ErrPending)
	}
	compute, err := b.factory.Compute()
	if err != nil {
		return nil, nil, err
	}
	quotas, err := b.factory.Limits()
	if err != nil {
		return nil, nil, err
	}
	definitions, err := nodePages(func(page *string) ([]limits.LimitDefinitionSummary, *string, error) {
		response, err := quotas.ListLimitDefinitions(ctx, limits.ListLimitDefinitionsRequest{CompartmentId: new(approved.TenancyID), ServiceName: new("compute"), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return nil, []string{fmt.Sprintf("compute quota definitions: %v", err)}, nil
	}
	var candidates []rootoci.NodeCandidateObservation
	var pending []string
	attempts := 0
	for _, role := range []string{nodescale.RoleContainer, nodescale.RoleWasm} {
		for _, verified := range profiles[role] {
			profile := verified.Profile()
			imageID, imageSHA, _ := verified.CurrentImage()
			for _, domain := range profile.AvailabilityDomains {
				attempts++
				if attempts > 512 {
					return nil, nil, errors.New("worker capacity observation exceeds its candidate bound")
				}
				shapes, err := nodePages(func(page *string) ([]core.Shape, *string, error) {
					response, err := compute.ListShapes(ctx, core.ListShapesRequest{CompartmentId: new(compartment), AvailabilityDomain: new(domain), ImageId: new(imageID), Page: page})
					return response.Items, response.OpcNextPage, err
				})
				if err != nil {
					pending = append(pending, fmt.Sprintf("%s %s compatibility: %v", profile.Shape, domain, err))
					continue
				}
				matches := 0
				for _, shape := range shapes {
					if shape.Shape == nil || *shape.Shape != profile.Shape {
						continue
					}
					matches++
					if matches > 1 {
						return nil, nil, errors.New("provider returned ambiguous exact worker shape")
					}
					if len(shape.QuotaNames) > 32 {
						return nil, nil, errors.New("worker shape exceeds whole-quota observation bound")
					}
					candidate := nodescale.CapacityCandidate{Capacity: nodescale.Capacity{Role: role, Architecture: profile.Architecture, Shape: profile.Shape}, ImageID: imageID, RuntimeManifestDigest: imageSHA, AvailabilityDomain: domain}
					request := nodescale.CapacityRequest{TenancyID: approved.TenancyID, CompartmentID: compartment, OCPUs: float32(profile.OCPUs), MemoryGB: float32(profile.MemoryGB), BootGB: int(profile.BootGB), FactsExpireAt: expires}
					if float64(request.OCPUs) != profile.OCPUs || float64(request.MemoryGB) != profile.MemoryGB {
						pending = append(pending, "signed worker geometry is not exactly representable by OCI")
						continue
					}
					fact, err := nodescale.ObserveNativeCapacity(ctx, compute, quotas, request, candidate, shape, definitions)
					if err != nil {
						pending = append(pending, fmt.Sprintf("%s %s: %v", profile.Shape, domain, err))
						continue
					}
					candidates = append(candidates, fact)
				}
				if matches == 0 {
					pending = append(pending, fmt.Sprintf("%s image %s has no compatible signed shape in %s", profile.Shape, imageID, domain))
				}
			}
		}
	}
	return candidates, pending, nil
}

func nodePages[T any](fetch func(*string) ([]T, *string, error)) ([]T, error) {
	var all []T
	var page *string
	seen := map[string]bool{}
	for range 32 {
		items, next, err := fetch(page)
		if err != nil {
			return nil, err
		}
		if len(items) > 4096-len(all) {
			return nil, errors.New("node capacity provider items exceed their bound")
		}
		all = append(all, items...)
		if next == nil {
			return all, nil
		}
		if *next == "" || len(*next) > 4096 || seen[*next] {
			return nil, errors.New("node capacity provider continuation is invalid or repeated")
		}
		seen[*next] = true
		page = next
	}
	return nil, errors.New("node capacity provider pages exceed their bound")
}

var nodeProbeRegionName = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+){2,7}$`)

func (b *Backend) ObserveNodeProbeRegions(ctx context.Context, call rootoci.Call) (rootoci.NodeProbeRegionObservation, error) {
	ctx, cancel, scope, err := b.begin(ctx, call, rootoci.OperationObserveNodeProbeRegions)
	defer cancel()
	if err != nil {
		return rootoci.NodeProbeRegionObservation{}, err
	}
	bindings, _, err := nodeWorkerBindings(ctx, scope)
	if err != nil {
		return rootoci.NodeProbeRegionObservation{}, err
	}
	identities, err := b.factory.Identity()
	if err != nil {
		return rootoci.NodeProbeRegionObservation{}, err
	}
	listed, err := identities.ListRegions(ctx)
	if err != nil {
		return rootoci.NodeProbeRegionObservation{}, err
	}
	observed := rootoci.NodeProbeRegionObservation{Cell: scope.cell, OCIRegion: b.factory.Region(), GrantSHA256: scope.grant, ObservedAt: time.Now().UTC(), ExpiresAt: bindings.ExpiresAt()}
	if deadline := observed.ObservedAt.Add(2 * time.Minute); deadline.Before(observed.ExpiresAt) {
		observed.ExpiresAt = deadline
	}
	if len(listed.Items) == 0 || len(listed.Items) > 256 {
		return rootoci.NodeProbeRegionObservation{}, errors.New("OCI probe region catalog exceeds its finite bound")
	}
	for _, entry := range listed.Items {
		if entry.Name == nil || len(*entry.Name) > 96 || !nodeProbeRegionName.MatchString(*entry.Name) {
			return rootoci.NodeProbeRegionObservation{}, errors.New("OCI probe region catalog contains an invalid name")
		}
		observed.Regions = append(observed.Regions, *entry.Name)
	}
	slices.Sort(observed.Regions)
	if len(slices.Compact(slices.Clone(observed.Regions))) != len(observed.Regions) {
		return rootoci.NodeProbeRegionObservation{}, errors.New("OCI probe region catalog contains duplicate names")
	}
	if err := bindings.Revalidate(ctx); err != nil {
		return rootoci.NodeProbeRegionObservation{}, err
	}
	if !time.Now().Before(observed.ExpiresAt) {
		return rootoci.NodeProbeRegionObservation{}, ErrPending
	}
	if err := b.finish(ctx, call, scope); err != nil {
		return rootoci.NodeProbeRegionObservation{}, err
	}
	if !time.Now().Before(observed.ExpiresAt) {
		return rootoci.NodeProbeRegionObservation{}, ErrPending
	}
	return observed, nil
}
