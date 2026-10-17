package capacityinventory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/resourcesearch"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

// Reader reads actual regional resources through the shared authenticated SDK
// factory. Public tariffs require no cloud credentials or Usage API history.
type Reader struct {
	factory                  *ociclient.Factory
	endpoint, pricesEndpoint string
	http                     *http.Client
}

func New(factory *ociclient.Factory) (*Reader, error) {
	if factory == nil {
		return nil, errors.New("infrastructure inventory requires authenticated OCI factory")
	}
	return &Reader{factory: factory, pricesEndpoint: priceCatalog, http: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("OCI price catalog redirect refused") }}}, nil
}

// Read prices directly enumerated compute and disks. Historical charges and
// exhaustive mutation coverage remain mandatory before authorizing growth.
func (r *Reader) Read(ctx context.Context, scope Scope) (Snapshot, error) {
	if err := scope.validate(time.Now()); err != nil {
		return Snapshot{}, err
	}
	result, err := r.ReadOwned(ctx, scope)
	if err != nil {
		return Snapshot{}, err
	}
	result.ExpiresAt = minTime(result.ExpiresAt, scope.ExpiresAt)
	result.seal = result.digest()
	return result, nil
}

// ReadOwned observes historical ownership without renewing expired spend authority.
func (r *Reader) ReadOwned(ctx context.Context, scope Scope) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	started := time.Now()
	if err := scope.validateIdentity(); err != nil {
		return Snapshot{}, err
	}
	tenancy, err := r.factory.Provider().TenancyOCID()
	if err != nil || tenancy != scope.TenancyID {
		return Snapshot{}, errors.New("inventory principal differs from signed tenancy")
	}
	result := Snapshot{ScopeSHA256: scope.SHA256, Currency: scope.Currency, ObservedAt: started, ExpiresAt: started.Add(2 * time.Minute),
		Pending: []string{"current-month scope inception and exhaustive mutation history are not authenticated", "non-node charges and usage commitments require bounded accounting"}}
	prices := catalogReader{client: r.http, endpoint: r.pricesEndpoint, currency: scope.Currency, cache: map[string]tariff{}}
	seen := map[string]bool{}
	for _, region := range scope.Regions {
		factory, err := r.factory.ForRegion(region.OCIRegion)
		if err != nil {
			result.Pending = append(result.Pending, region.Cell+": "+err.Error())
			continue
		}
		search, err := factory.Search()
		if err != nil {
			result.Pending = append(result.Pending, region.Cell+": "+err.Error())
			continue
		}
		compute, err := factory.Compute()
		if err != nil {
			result.Pending = append(result.Pending, region.Cell+": "+err.Error())
			continue
		}
		block, err := factory.Blockstorage()
		if err != nil {
			result.Pending = append(result.Pending, region.Cell+": "+err.Error())
			continue
		}
		ociclient.PinHost(&search.BaseClient, r.endpoint)
		ociclient.PinHost(&compute.BaseClient, r.endpoint)
		ociclient.PinHost(&block.BaseClient, r.endpoint)
		for _, compartment := range region.CompartmentIDs {
			if strings.ContainsAny(compartment, "'\n\r") {
				return Snapshot{}, errors.New("invalid signed compartment identifier")
			}
			direct, directErr := directResources(ctx, compute, block, compartment)
			if directErr != nil {
				result.Pending = append(result.Pending, "direct family inventory incomplete: "+region.Cell+"/"+compartment+": "+directErr.Error())
			}
			observe := func(item resourcesearch.ResourceSummary) error {
				if item.Identifier == nil || *item.Identifier == "" || item.CompartmentId == nil || *item.CompartmentId != compartment || seen[*item.Identifier] {
					result.Pending = append(result.Pending, "duplicate, absent or out-of-scope OCI resource")
					return nil
				}
				seen[*item.Identifier] = true
				resource := Resource{ID: *item.Identifier, Cell: region.Cell, CompartmentID: compartment}
				amount, err := observedCost(ctx, compute, block, item, &prices, &resource)
				resource.MonthlyCents = amount
				if err != nil {
					result.Pending = append(result.Pending, resource.ID+": "+err.Error())
				}
				if math.MaxUint64-result.MonthlyCents < resource.MonthlyCents {
					return errors.New("infrastructure cost overflow")
				}
				result.MonthlyCents += resource.MonthlyCents
				result.Resources = append(result.Resources, resource)
				return nil
			}
			for _, item := range direct {
				if err := observe(item); err != nil {
					return Snapshot{}, err
				}
			}
			var page *string
			complete := false
			for range 64 {
				query := "query all resources where compartmentId = '" + compartment + "'"
				response, err := search.SearchResources(ctx, resourcesearch.SearchResourcesRequest{SearchDetails: resourcesearch.StructuredSearchDetails{Query: new(query)}, Page: page})
				if err != nil {
					result.Pending = append(result.Pending, region.Cell+"/"+compartment+": "+err.Error())
					break
				}
				for _, item := range response.Items {
					if item.ResourceType != nil && (*item.ResourceType == "Instance" || *item.ResourceType == "Volume" || *item.ResourceType == "BootVolume") && item.Identifier != nil && seen[*item.Identifier] {
						continue
					}
					if err := observe(item); err != nil {
						return Snapshot{}, err
					}
				}
				page = response.OpcNextPage
				if page == nil || *page == "" {
					complete = true
					break
				}
			}
			if complete && directErr == nil {
				result.CoveredCompartments = append(result.CoveredCompartments, region.Cell+"/"+compartment)
			} else {
				result.Pending = append(result.Pending, "regional inventory pagination incomplete: "+region.Cell+"/"+compartment)
			}
		}
	}
	slices.SortFunc(result.Resources, func(a, b Resource) int { return strings.Compare(a.ID, b.ID) })
	slices.Sort(result.CoveredCompartments)
	slices.Sort(result.Pending)
	result.seal = result.digest()
	return result, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func observedCost(ctx context.Context, compute core.ComputeClient, block core.BlockstorageClient, item resourcesearch.ResourceSummary, prices *catalogReader, resource *Resource) (uint64, error) {
	if item.ResourceType == nil {
		return 0, errors.New("resource type missing")
	}
	var amount float64
	var evidenceErr error
	switch *item.ResourceType {
	case "Instance":
		response, err := compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: item.Identifier})
		if err != nil {
			return 0, err
		}
		if response.Id == nil || *response.Id != *item.Identifier || response.CompartmentId == nil || *response.CompartmentId != *item.CompartmentId {
			return 0, errors.New("instance dimensions or identity missing")
		}
		resource.LifecycleState = string(response.LifecycleState)
		resource.OperationID = response.FreeformTags["ts-operation-id"]
		resource.RecipeSHA256 = response.FreeformTags["ts-recipe-sha256"]
		if terminalState(resource.LifecycleState) {
			return 0, nil
		}
		if response.Shape == nil || response.ShapeConfig == nil || response.ShapeConfig.Ocpus == nil || response.ShapeConfig.MemoryInGBs == nil || resource.LifecycleState == "" {
			return 0, errors.New("instance dimensions or lifecycle state missing")
		}
		resource.Shape, resource.OCPUs, resource.MemoryGB = *response.Shape, float64(*response.ShapeConfig.Ocpus), float64(*response.ShapeConfig.MemoryInGBs)
		if prices == nil {
			return 0, nil
		}
		cpuSKU, memorySKU, known := ocicost.ComputeSKUs(*response.Shape)
		if !known {
			return 0, fmt.Errorf("unknown shape tariff: %s", *response.Shape)
		}
		cpu, err := prices.price(ctx, cpuSKU, "OCPU Per Hour")
		if err != nil {
			return 0, err
		}
		memory, err := prices.price(ctx, memorySKU, "Gigabyte Per Hour")
		if err != nil {
			return 0, err
		}
		if !(*response.ShapeConfig.Ocpus > 0 && *response.ShapeConfig.MemoryInGBs > 0) {
			return 0, errors.New("invalid instance dimensions")
		}
		amount = 744 * (float64(*response.ShapeConfig.Ocpus)*cpu + float64(*response.ShapeConfig.MemoryInGBs)*memory)
	case "BootVolume", "Volume":
		var size, vpus *int64
		if *item.ResourceType == "BootVolume" {
			response, err := block.GetBootVolume(ctx, core.GetBootVolumeRequest{BootVolumeId: item.Identifier})
			if err != nil {
				return 0, err
			}
			if response.Id == nil || *response.Id != *item.Identifier || response.CompartmentId == nil || *response.CompartmentId != *item.CompartmentId {
				return 0, errors.New("boot volume identity changed")
			}
			resource.LifecycleState = string(response.LifecycleState)
			resource.OperationID = response.FreeformTags["ts-operation-id"]
			resource.RecipeSHA256 = response.FreeformTags["ts-recipe-sha256"]
			if terminalState(resource.LifecycleState) {
				return 0, nil
			}
			if response.IsAutoTuneEnabled != nil && *response.IsAutoTuneEnabled || len(response.AutotunePolicies) > 0 {
				return 0, errors.New("autotuned disk requires a bounded performance charge ledger")
			}
			if prices != nil {
				evidenceErr = bootAttribution(ctx, compute, response.BootVolume, resource)
			}
			size, vpus = response.SizeInGBs, response.VpusPerGB
		} else {
			response, err := block.GetVolume(ctx, core.GetVolumeRequest{VolumeId: item.Identifier})
			if err != nil {
				return 0, err
			}
			if response.Id == nil || *response.Id != *item.Identifier || response.CompartmentId == nil || *response.CompartmentId != *item.CompartmentId {
				return 0, errors.New("volume identity changed")
			}
			resource.LifecycleState = string(response.LifecycleState)
			resource.OperationID = response.FreeformTags["ts-operation-id"]
			resource.RecipeSHA256 = response.FreeformTags["ts-recipe-sha256"]
			if terminalState(resource.LifecycleState) {
				return 0, nil
			}
			if response.IsAutoTuneEnabled != nil && *response.IsAutoTuneEnabled || len(response.AutotunePolicies) > 0 {
				return 0, errors.New("autotuned disk requires a bounded performance charge ledger")
			}
			size, vpus = response.SizeInGBs, response.VpusPerGB
		}
		if size == nil || vpus == nil || *size <= 0 || *vpus < 0 || resource.LifecycleState == "" {
			return 0, errors.New("retained disk size or performance missing")
		}
		resource.SizeGB, resource.VPUs = float64(*size), *vpus
		if prices == nil {
			return 0, nil
		}
		storage, err := prices.price(ctx, "B91961", "Gigabyte Storage Capacity Per Month")
		if err != nil {
			return 0, err
		}
		performance, err := prices.price(ctx, "B91962", "Performance Units Per Gigabyte Per Month")
		if err != nil {
			return 0, err
		}
		amount = float64(*size) * (storage + float64(*vpus)*performance)
	default:
		return 0, fmt.Errorf("non-node resource %s has no complete current charge observation", *item.ResourceType)
	}
	if math.IsNaN(amount) || math.IsInf(amount, 0) || amount < 0 || amount > 1e12 {
		return 0, errors.New("resource cost outside bounds")
	}
	return uint64(math.Ceil(amount * 100)), evidenceErr
}
