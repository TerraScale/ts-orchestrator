package nodescale

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/limits"
)

// CapacityComputeAPI is OCI's image compatibility and current capacity surface.
type CapacityComputeAPI interface {
	ListShapes(context.Context, core.ListShapesRequest) (core.ListShapesResponse, error)
	CreateComputeCapacityReport(context.Context, core.CreateComputeCapacityReportRequest) (core.CreateComputeCapacityReportResponse, error)
}

// CapacityLimitsAPI reads effective service limits and compartment quotas.
type CapacityLimitsAPI interface {
	ListLimitDefinitions(context.Context, limits.ListLimitDefinitionsRequest) (limits.ListLimitDefinitionsResponse, error)
	GetResourceAvailability(context.Context, limits.GetResourceAvailabilityRequest) (limits.GetResourceAvailabilityResponse, error)
}

// QualifiedImage comes from admitted runtime/image qualification, never user configuration.
// The manifest must qualify this exact image, native architecture and isolation role.
type QualifiedImage struct {
	ID, Architecture, Role, RuntimeManifestDigest string
}

// CapacityRequest contains observed demand and authorized spending facts.
// OCPUs are billing units, not guest vCPUs or normalized workload capacity.
type CapacityRequest struct {
	TenancyID, CompartmentID string
	AvailabilityDomains      []string
	Role                     string
	Architectures            []string
	OCPUs, MemoryGB          float32
	BootGB                   int
	Images                   []QualifiedImage
	Prices                   []ocicost.Price
	// Nil means spending authority is unknown. The caller includes existing
	// capacity, migration overlap and non-node costs before computing headroom.
	MonthlyHeadroomCents *uint64
	// FactsExpireAt is the earliest validity deadline of the admitted image,
	// observed prices and spending authority used above.
	FactsExpireAt time.Time
}

// CapacityCandidate is one qualified launch opportunity, not a reservation.
// Persist its identity before allocating and re-discover immediately before mutation.
type CapacityCandidate struct {
	Capacity
	ImageID, AvailabilityDomain string
	RuntimeManifestDigest       string
	OCPUs, MemoryGB             float32
	BootGB                      int
	FactsExpireAt               time.Time
	MonthlyCents                uint64
}

// CapacitySelection leaves unqualified demand pending without changing healthy pools.
type CapacitySelection struct {
	Candidates []CapacityCandidate
	Pending    []string
}

var runtimeManifestDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// DiscoverCapacity checks actual image/AD compatibility, quota, price and current
// host capacity. Viable A1 is first; other candidates use price then stable identity.
func DiscoverCapacity(ctx context.Context, compute CapacityComputeAPI, quotas CapacityLimitsAPI, request CapacityRequest) (CapacitySelection, error) {
	var result CapacitySelection
	if request.TenancyID == "" || request.CompartmentID == "" || len(request.AvailabilityDomains) == 0 || slices.Contains(request.AvailabilityDomains, "") {
		return result, fmt.Errorf("capacity discovery needs tenancy, compartment and availability domains")
	}
	if err := (Capacity{Role: request.Role, Architecture: "arm64", Shape: PreferredShape}).Validate(); err != nil {
		return result, err
	}
	if !(request.OCPUs > 0 && request.MemoryGB > 0) || math.IsInf(float64(request.OCPUs), 0) || math.IsInf(float64(request.MemoryGB), 0) || request.BootGB != BootVolumeGB {
		return result, fmt.Errorf("capacity discovery needs finite positive resources and the fixed %d boot GB", BootVolumeGB)
	}
	for _, architecture := range request.Architectures {
		if architecture != "arm64" && architecture != "amd64" {
			return result, fmt.Errorf("unsupported workload architecture %q", architecture)
		}
	}
	if request.MonthlyHeadroomCents == nil {
		result.Pending = append(result.Pending, "authorized monthly spending headroom is unknown")
		return result, nil
	}
	if !time.Now().Before(request.FactsExpireAt) {
		result.Pending = append(result.Pending, "image qualification, prices or spending authority expired or have unknown validity")
		return result, nil
	}
	if len(request.Architectures) == 0 || len(request.Images) == 0 {
		result.Pending = append(result.Pending, "no admitted runtime/image and workload architecture qualification")
		return result, nil
	}
	definitions, err := listAll(func(page *string) ([]limits.LimitDefinitionSummary, *string, error) {
		response, err := quotas.ListLimitDefinitions(ctx, limits.ListLimitDefinitionsRequest{CompartmentId: new(request.TenancyID), ServiceName: new("compute"), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return result, fmt.Errorf("discover compute service limits: %w", err)
	}
	for _, image := range request.Images {
		if image.ID == "" || image.Role != request.Role || !slices.Contains(request.Architectures, image.Architecture) || !runtimeManifestDigest.MatchString(image.RuntimeManifestDigest) {
			result.Pending = append(result.Pending, fmt.Sprintf("image %s lacks admitted %s runtime/architecture qualification", image.ID, request.Role))
			continue
		}
		for _, domain := range request.AvailabilityDomains {
			shapes, err := listAll(func(page *string) ([]core.Shape, *string, error) {
				response, err := compute.ListShapes(ctx, core.ListShapesRequest{CompartmentId: new(request.CompartmentID), AvailabilityDomain: new(domain), ImageId: new(image.ID), Page: page})
				return response.Items, response.OpcNextPage, err
			})
			if err != nil {
				result.Pending = append(result.Pending, fmt.Sprintf("image %s in %s compatibility: %v", image.ID, domain, err))
				continue
			}
			if len(shapes) == 0 {
				result.Pending = append(result.Pending, fmt.Sprintf("image %s has no compatible shapes in %s", image.ID, domain))
			}
			for _, shape := range shapes {
				candidate := CapacityCandidate{Capacity: Capacity{Role: request.Role, Architecture: image.Architecture, Shape: deref(shape.Shape)}, ImageID: image.ID, AvailabilityDomain: domain, RuntimeManifestDigest: image.RuntimeManifestDigest, OCPUs: request.OCPUs, MemoryGB: request.MemoryGB, BootGB: request.BootGB, FactsExpireAt: request.FactsExpireAt}
				if err := qualifyCapacity(ctx, compute, quotas, request, candidate, shape, definitions); err != nil {
					result.Pending = append(result.Pending, fmt.Sprintf("%s image %s in %s: %v", candidate.Shape, image.ID, domain, err))
					continue
				}
				candidate.MonthlyCents, _ = ocicost.NodeMonthlyCents(request.Prices, candidate.Shape, float64(request.OCPUs), float64(request.MemoryGB), float64(request.BootGB))
				result.Candidates = append(result.Candidates, candidate)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return CapacitySelection{}, err
	}
	if !time.Now().Before(request.FactsExpireAt) {
		result.Candidates = nil
		result.Pending = append(result.Pending, "image qualification, prices or spending authority expired during discovery")
	}
	slices.SortFunc(result.Candidates, func(a, b CapacityCandidate) int {
		preferred := func(shape string) int {
			if shape == PreferredShape {
				return 0
			}
			return 1
		}
		return cmp.Or(cmp.Compare(preferred(a.Shape), preferred(b.Shape)), cmp.Compare(a.MonthlyCents, b.MonthlyCents), cmp.Compare(a.Shape, b.Shape), cmp.Compare(a.Architecture, b.Architecture), cmp.Compare(a.ImageID, b.ImageID), cmp.Compare(a.AvailabilityDomain, b.AvailabilityDomain))
	})
	result.Candidates = slices.Compact(result.Candidates)
	slices.Sort(result.Pending)
	result.Pending = slices.Compact(result.Pending)
	return result, nil
}

func qualifyCapacity(ctx context.Context, compute CapacityComputeAPI, quotas CapacityLimitsAPI, request CapacityRequest, candidate CapacityCandidate, shape core.Shape, definitions []limits.LimitDefinitionSummary) error {
	if err := candidate.Capacity.Validate(); err != nil {
		return err
	}
	architecture, err := catalog.ShapeArchitecture(deref(shape.ProcessorDescription))
	if err != nil || architecture != candidate.Architecture {
		return fmt.Errorf("processor does not establish qualified %s architecture", candidate.Architecture)
	}
	if err := ValidateResources(shape, request.OCPUs, request.MemoryGB); err != nil {
		return fmt.Errorf("requested OCPU/memory configuration: %w", err)
	}
	price, known := ocicost.NodeMonthlyCents(request.Prices, candidate.Shape, float64(request.OCPUs), float64(request.MemoryGB), float64(request.BootGB))
	if !known {
		return fmt.Errorf("actual shape/boot volume price is unknown")
	}
	if price > *request.MonthlyHeadroomCents {
		return fmt.Errorf("monthly node cost %d exceeds authorized headroom %d cents", price, *request.MonthlyHeadroomCents)
	}
	if len(shape.QuotaNames) == 0 {
		return fmt.Errorf("shape quota identities are unknown")
	}
	for _, name := range shape.QuotaNames {
		index := slices.IndexFunc(definitions, func(definition limits.LimitDefinitionSummary) bool {
			return deref(definition.Name) == name && deref(definition.ServiceName) == "compute"
		})
		if index < 0 || !deref(definitions[index].IsResourceAvailabilitySupported) {
			return fmt.Errorf("effective limit/quota availability for %s is unsupported", name)
		}
		needed := float32(0)
		switch {
		case strings.HasSuffix(name, "-core-count"):
			needed = request.OCPUs
		case strings.HasSuffix(name, "-memory-count"):
			needed = request.MemoryGB
		default:
			return fmt.Errorf("shape quota unit for %s is unknown", name)
		}
		query := limits.GetResourceAvailabilityRequest{ServiceName: new("compute"), LimitName: new(name), CompartmentId: new(request.CompartmentID)}
		switch definitions[index].ScopeType {
		case limits.LimitDefinitionSummaryScopeTypeAd:
			query.AvailabilityDomain = new(candidate.AvailabilityDomain)
		case limits.LimitDefinitionSummaryScopeTypeRegion, limits.LimitDefinitionSummaryScopeTypeGlobal:
		default:
			return fmt.Errorf("limit scope for %s is unknown", name)
		}
		availability, err := quotas.GetResourceAvailability(ctx, query)
		if err != nil {
			return fmt.Errorf("read effective limit/quota %s: %w", name, err)
		}
		available := float64(-1)
		if availability.Available != nil {
			available = float64(*availability.Available)
		}
		if availability.FractionalAvailability != nil {
			available = float64(*availability.FractionalAvailability)
		}
		if !(available >= float64(needed)) || math.IsInf(available, 0) {
			return fmt.Errorf("effective limit/quota %s has insufficient or unknown remaining capacity", name)
		}
	}
	report, err := compute.CreateComputeCapacityReport(ctx, core.CreateComputeCapacityReportRequest{CreateComputeCapacityReportDetails: core.CreateComputeCapacityReportDetails{
		CompartmentId: new(request.TenancyID), AvailabilityDomain: new(candidate.AvailabilityDomain),
		ShapeAvailabilities: []core.CreateCapacityReportShapeAvailabilityDetails{{InstanceShape: new(candidate.Shape), InstanceShapeConfig: &core.CapacityReportInstanceShapeConfig{Ocpus: new(request.OCPUs), MemoryInGBs: new(request.MemoryGB)}}},
	}})
	if err != nil {
		return fmt.Errorf("current host capacity report unavailable: %w", err)
	}
	if deref(report.AvailabilityDomain) != candidate.AvailabilityDomain {
		return fmt.Errorf("host capacity report returned a different availability domain")
	}
	for _, availability := range report.ShapeAvailabilities {
		config := availability.InstanceShapeConfig
		if deref(availability.InstanceShape) == candidate.Shape && config != nil && deref(config.Ocpus) == request.OCPUs && deref(config.MemoryInGBs) == request.MemoryGB &&
			availability.AvailabilityStatus == core.CapacityReportShapeAvailabilityAvailabilityStatusAvailable && availability.AvailableCount != nil && *availability.AvailableCount > 0 {
			return nil
		}
	}
	return fmt.Errorf("no current host capacity for the requested shape configuration")
}
