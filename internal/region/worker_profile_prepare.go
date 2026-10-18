package region

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// PrepareWorkerProfilesSDK derives explicit fixed worker authority for the same
// root ceremony. It reads qualified artifacts and SDK facts, never creates hosts.
func PrepareWorkerProfilesSDK(ctx context.Context, factory *ociclient.Factory, namespace string, roots trust.Keyring, grant FoundationGrant, now time.Time) ([]WorkerProfile, error) {
	if factory == nil || namespace == "" || len(roots) == 0 || grant.InfrastructureSpend == nil || grant.InfrastructureSpend.MonthlyLimitMinor <= 0 {
		return nil, errors.New("worker profiles require independent OCI identity and explicit infrastructure spending approval")
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != grant.TenancyID {
		return nil, errors.New("worker profile producer differs from approved tenancy")
	}
	var profiles []WorkerProfile
	for _, region := range grant.Regions {
		cell, _ := region.Plan["cell"].(string)
		ociRegion, _ := region.Plan["region"].(string)
		if region.BootstrapMaterial == nil {
			return nil, errors.New("worker profiles require an authorized regional bootstrap source")
		}
		regional, err := factory.ForRegion(ociRegion)
		if err != nil {
			return nil, err
		}
		compute, err := regional.Compute()
		if err != nil {
			return nil, err
		}
		identities, err := regional.Identity()
		if err != nil {
			return nil, err
		}
		ads, err := identities.ListAvailabilityDomains(ctx, identity.ListAvailabilityDomainsRequest{CompartmentId: new(tenancy)})
		if err != nil {
			return nil, err
		}
		domains := make([]string, 0, len(ads.Items))
		for _, ad := range ads.Items {
			if ad.Name != nil && *ad.Name != "" {
				domains = append(domains, *ad.Name)
			}
		}
		slices.Sort(domains)
		domains = slices.Compact(domains)
		for _, role := range []string{"container", "wasm"} {
			for _, architecture := range []string{"arm64", "amd64"} {
				current, found, err := releasechannel.ReadCurrentImageSDK(ctx, factory, namespace, roots, releasechannel.CurrentImageExpectation{Cell: cell, Environment: "production", Architecture: architecture, Role: role}, now)
				if err != nil {
					return nil, err
				}

				placements := map[string][]string{}
				for _, domain := range domains {
					var page *string
					seen := map[string]bool{}
					for {
						response, err := compute.ListShapes(ctx, core.ListShapesRequest{CompartmentId: new(grant.ParentCompartmentID), AvailabilityDomain: new(domain), Page: page})
						if err != nil {
							return nil, err
						}
						for _, shape := range response.Items {
							if shape.Shape == nil || shape.ProcessorDescription == nil || !workerShapeFits(shape) {
								continue
							}
							actual, err := catalog.ShapeArchitecture(*shape.ProcessorDescription)
							if err != nil || actual != architecture {
								continue
							}
							placements[*shape.Shape] = append(placements[*shape.Shape], domain)
						}
						if response.OpcNextPage == nil || *response.OpcNextPage == "" {
							break
						}
						if seen[*response.OpcNextPage] {
							return nil, errors.New("worker shape discovery repeated a page")
						}
						seen[*response.OpcNextPage] = true
						page = response.OpcNextPage
					}
				}
				shapes := make([]string, 0, len(placements))
				for shape := range placements {
					shapes = append(shapes, shape)
				}
				slices.Sort(shapes)
				ref := func(key string) string { value, _ := FoundationResourceReference(cell, key); return value }
				for _, shape := range shapes {
					bucket, err := releasechannel.BucketName(cell)
					if err != nil {
						return nil, err
					}
					p := WorkerProfile{ImageSource: WorkerImageSource{OCIRegion: ociRegion, Namespace: namespace, Bucket: bucket, CurrentObject: releasechannel.CurrentImageObject(role, architecture, "production"), ImageDomain: release.ImageDomain, QualificationDomain: release.ProductionQualificationDomain}, Cell: cell, Environment: "production", Role: role, Architecture: architecture, Shape: shape, OCPUs: 2, MemoryGB: 12, BootGB: 50,
						AvailabilityDomains: slices.Compact(placements[shape]), CompartmentRef: ref("workload_compartment"), SubnetRef: ref("subnet"), NSGRef: ref("workload_network_security_group"),
						Runtime:         release.ProductionRuntime,
						PoolMembership:  WorkerPoolMembership{Purpose: PoolMembershipQuarantineV1, Provenance: PoolMembershipProvenanceV1},
						CapacityJournal: WorkerCapacityJournal{Purpose: CapacityJournalPurposeV1, Principal: CapacityJournalPrincipalV1, Delta: CapacityJournalDeltaV1},
						Bootstrap:       WorkerBootstrapTemplate{Derivation: WorkerBootstrapDerivationV1, MaterialPlanSHA256: region.BootstrapMaterial.PlanSHA256, VaultRef: ref("vault"), KMSKeyRef: ref("key"), RecipientPermission: "SECRET_BUNDLE_READ"}}
					if found {
						p.ImageReceipt = current.ReceiptWire
						p.ImageDelegation = current.DelegationWire
						p.RuntimeSHA256 = current.Image.Receipt().ImageSHA256
					}
					if err := ValidateWorkerProfile(grant, p); err != nil {
						return nil, err
					}
					profiles = append(profiles, p)
				}
			}
		}
	}
	if err := ValidateWorkerProfiles(grant, profiles, roots, now); err != nil {
		return nil, err
	}
	return profiles, nil
}

func workerShapeFits(shape core.Shape) bool {
	if shape.Shape == nil || !strings.HasPrefix(*shape.Shape, "VM.Standard.") || shape.IsFlexible == nil || !*shape.IsFlexible || shape.OcpuOptions == nil || shape.MemoryOptions == nil {
		return false
	}
	cpu, memory := shape.OcpuOptions, shape.MemoryOptions
	for _, v := range []*float32{cpu.Min, cpu.Max, memory.MinInGBs, memory.MaxInGBs, memory.MinPerOcpuInGBs, memory.MaxPerOcpuInGBs} {
		if v == nil || !(*v > 0) || *v > 1e9 {
			return false
		}
	}
	return *cpu.Min <= 2 && *cpu.Max >= 2 && *memory.MinInGBs <= 12 && *memory.MaxInGBs >= 12 && *memory.MinPerOcpuInGBs <= 6 && *memory.MaxPerOcpuInGBs >= 6
}
