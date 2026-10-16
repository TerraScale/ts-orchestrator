package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	platform "github.com/TerraScale/ts-orchestrator/deploy/oci-region"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// FoundationPreparation keeps the root ceremony's two public inputs together;
// only signing the grant establishes the anchor's exact grant-wire digest.
type FoundationPreparation struct {
	Grant  FoundationGrant           `json:"grant"`
	Anchor bootstrap.BootstrapAnchor `json:"anchor"`
}

// FoundationHostApproval is a finite permission for one initial A1 host.
// Region, role, address, image and placement are derived by the producer.
type FoundationHostApproval struct {
	OCPUs             float64 `json:"ocpus"`
	MemoryGB          float64 `json:"memoryGb"`
	BootGB            int64   `json:"bootGb"`
	MonthlyLimitMinor int64   `json:"monthlyLimitMinor"`
}

// FoundationPreparationInput contains the initial caller-approved authority,
// not regional plans, credentials, discovered membership or runtime settings.
type FoundationPreparationInput struct {
	TenancyID                       string                            `json:"tenancyId"`
	ParentCompartmentID             string                            `json:"parentCompartmentId"`
	SharedCompartmentID             string                            `json:"sharedCompartmentId"`
	Currency                        string                            `json:"currency"`
	MonthlyLimitMinor               int64                             `json:"monthlyLimitMinor"`
	InfrastructureMonthlyLimitMinor int64                             `json:"infrastructureMonthlyLimitMinor"`
	BootstrapReservedMinor          int64                             `json:"bootstrapReservedMinor"`
	CleanupOwner                    string                            `json:"cleanupOwner"`
	HomeStorageDomain               bootstrap.StorageDomain           `json:"homeStorageDomain"`
	SourceVaultTarget               bootstrapmaterial.VaultTarget     `json:"sourceVaultTarget"`
	TrustedSigners                  jsontext.Value                    `json:"trustedSigners"`
	ReleaseAuthorities              []ContainerReleaseAuthorityIntent `json:"releaseAuthorities"`
	OCIRRepositoryName              string                            `json:"ocirRepositoryName"`
	OCIRPrincipalName               string                            `json:"ocirPrincipalName"`
	OCIRPrincipalEmail              string                            `json:"ocirPrincipalEmail"`
	OCIRSecretName                  string                            `json:"ocirSecretName"`
	GRUController                   FoundationHostApproval            `json:"gruController"`
	SFOController                   FoundationHostApproval            `json:"sfoController"`
	FRAController                   FoundationHostApproval            `json:"fraController"`
	NetBirdManager                  FoundationHostApproval            `json:"netbirdManager"`
}

func (input FoundationPreparationInput) validate() error {
	validID := func(value, kind string) bool {
		return strings.HasPrefix(value, "ocid1."+kind+".oc1..") && len(value) <= 255 && !strings.ContainsAny(value, " \t\r\n")
	}
	if !validID(input.TenancyID, "tenancy") || !validID(input.ParentCompartmentID, "compartment") || !validID(input.SharedCompartmentID, "compartment") ||
		(input.Currency != "USD" && input.Currency != "BRL") || input.MonthlyLimitMinor <= 0 || input.InfrastructureMonthlyLimitMinor <= 0 || input.InfrastructureMonthlyLimitMinor > input.MonthlyLimitMinor ||
		input.BootstrapReservedMinor <= 0 || input.BootstrapReservedMinor > input.InfrastructureMonthlyLimitMinor || input.CleanupOwner == "" || len(input.CleanupOwner) > 128 || strings.ContainsAny(input.CleanupOwner, "\r\n") ||
		input.HomeStorageDomain.Validate() != nil || input.HomeStorageDomain.HeadBucket != foundationDiscoveryBucket || input.HomeStorageDomain.LedgerBucket != "gru-1-ledger" || input.SourceVaultTarget.Validate(foundationHomeRegion) != nil ||
		input.HomeStorageDomain.HeadKMSKeyOCID != input.SourceVaultTarget.KMSKeyOCID || !strings.HasPrefix(input.HomeStorageDomain.LedgerKMSKeyOCID, "ocid1.key.oc1.sa-saopaulo-1.") {
		return errors.New("initial approval lacks exact tenancy, home storage/Vault prerequisite or finite numerical spending authority")
	}
	remaining := input.BootstrapReservedMinor
	for _, host := range []FoundationHostApproval{input.GRUController, input.SFOController, input.FRAController, input.NetBirdManager} {
		if !positiveBootstrapDimension(host.OCPUs) || !positiveBootstrapDimension(host.MemoryGB) || host.OCPUs > 80 || host.MemoryGB < host.OCPUs || host.MemoryGB > host.OCPUs*64 || host.OCPUs != math.Trunc(host.OCPUs) || host.MemoryGB != math.Trunc(host.MemoryGB) || host.BootGB < 50 || host.BootGB > 32768 || host.MonthlyLimitMinor <= 0 || host.MonthlyLimitMinor > remaining {
			return errors.New("initial approval requires four supported A1 host geometries whose finite caps fit the reserved slice")
		}
		remaining -= host.MonthlyLimitMinor
	}
	return nil
}

// PrepareFoundationGrantSDK only reads current public signed image metadata and
// OCI catalog facts. The returned candidate remains unsigned until the existing
// offline root ceremony; no cloud resource or credential is created here.
func PrepareFoundationGrantSDK(ctx context.Context, input FoundationPreparationInput, factory *ociclient.Factory, roots trust.Keyring) (FoundationPreparation, error) {
	if err := input.validate(); err != nil {
		return FoundationPreparation{}, err
	}
	client, tenancy, err := foundationHomeClient(factory)
	if err != nil || tenancy != input.TenancyID || len(roots) == 0 {
		return FoundationPreparation{}, errors.Join(errors.New("initial approval differs from authenticated OCI tenancy or independent trust roots"), err)
	}
	namespace, err := discoveryNamespace(ctx, client, tenancy)
	if err != nil || namespace != input.HomeStorageDomain.Namespace {
		return FoundationPreparation{}, errors.Join(errors.New("approved home storage differs from authenticated OCI namespace"), err)
	}
	for _, bucket := range []struct{ name, key string }{{input.HomeStorageDomain.HeadBucket, input.HomeStorageDomain.HeadKMSKeyOCID}, {input.HomeStorageDomain.LedgerBucket, input.HomeStorageDomain.LedgerKMSKeyOCID}} {
		readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		response, err := client.GetBucket(ociclient.RequestContext(readCtx), objectstorage.GetBucketRequest{NamespaceName: new(namespace), BucketName: new(bucket.name)})
		cancel()
		if err != nil || deref(response.Name) != bucket.name || deref(response.CompartmentId) != input.SourceVaultTarget.CompartmentOCID || deref(response.KmsKeyId) != bucket.key {
			return FoundationPreparation{}, errors.Join(errors.New("preauthorized home storage prerequisite differs from exact OCI readback"), err)
		}
	}
	chain := trust.RootChain{Version: 1}
	chainWire, err := readDiscoveryObject(ctx, client, namespace, foundationRootChainObject, trust.MaxRootChainBytes)
	if service, missing := common.IsServiceError(err); err != nil && (!missing || service.GetHTTPStatusCode() != 404) {
		return FoundationPreparation{}, err
	} else if err == nil {
		chain, err = trust.DecodeRootChain(chainWire)
		if err != nil {
			return FoundationPreparation{}, err
		}
	}
	installation := foundationPreparationInstallation(input)
	lineage, err := trust.VerifyRootChain(roots, foundationChainIdentity(entityid.Derive("foundation-deployment", installation, "GRU")), chain)
	if err != nil {
		return FoundationPreparation{}, err
	}
	roots = lineage.Current
	images := make(map[string]releasechannel.CurrentImage, 4)
	for _, cell := range []string{"GRU", "SFO", "FRA", "netbird-manager"} {
		role, region := "controller", cell
		if cell == "netbird-manager" {
			role, region = cell, "GRU"
		}
		image, found, err := releasechannel.ReadCurrentImageSDK(ctx, factory, namespace, roots,
			releasechannel.CurrentImageExpectation{Cell: region, Environment: "production", Architecture: "arm64", Role: role}, time.Now())
		if err != nil || !found {
			return FoundationPreparation{}, errors.Join(fmt.Errorf("current qualified %s %s image is pending", region, role), err)
		}
		images[cell] = image
	}
	prepared, err := PrepareFoundationGrant(ctx, input, images, func(ctx context.Context, tenancy, ociRegion string) (Live, error) {
		regional, err := factory.ForRegion(ociRegion)
		if err != nil {
			return Live{}, err
		}
		return liveSDK(ctx, regional, tenancy, ociRegion)
	})
	if err != nil {
		return FoundationPreparation{}, err
	}
	if err := ValidateContainerReleaseAuthorities(prepared.Grant, roots, input.HomeStorageDomain, time.Now()); err != nil {
		return FoundationPreparation{}, err
	}
	return prepared, nil
}

// PrepareFoundationGrant derives the complete fixed first footprint from one
// platform template and current verified image-source results.
func PrepareFoundationGrant(ctx context.Context, input FoundationPreparationInput, images map[string]releasechannel.CurrentImage, lookup Lookup) (FoundationPreparation, error) {
	if err := input.validate(); err != nil {
		return FoundationPreparation{}, err
	}
	if lookup == nil {
		return FoundationPreparation{}, errors.New("foundation preparation requires current OCI regional catalog facts")
	}
	var template map[string]any
	if err := json.Unmarshal([]byte(platform.FoundationTemplate()), &template); err != nil {
		return FoundationPreparation{}, err
	}
	installation := foundationPreparationInstallation(input)
	grant := FoundationGrant{InstallationID: installation, SchemaVersion: 2, Generation: 1, TenancyID: input.TenancyID, ParentCompartmentID: input.ParentCompartmentID,
		SharedCompartmentID: input.SharedCompartmentID, Currency: input.Currency, MonthlyLimitMinor: input.MonthlyLimitMinor, CleanupOwner: input.CleanupOwner,
		ReleaseAuthorities:  input.ReleaseAuthorities,
		InfrastructureSpend: &InfrastructureSpendIntent{BudgetID: entityid.Derive("foundation-infrastructure-budget", installation), Currency: input.Currency, MonthlyLimitMinor: input.InfrastructureMonthlyLimitMinor, Bootstrap: &BootstrapSpendingIntent{ReservedMinor: input.BootstrapReservedMinor}}}
	regionIntent := oci.RegionIntent{SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		regionIntent.Regions = append(regionIntent.Regions, oci.RegionMapping{Cell: oci.Region(cell), OCIRegion: catalog.OCIRegion(cell)})
	}
	intentWire, err := trust.EncodePayload(regionIntent)
	if err != nil {
		return FoundationPreparation{}, err
	}
	var anchor bootstrap.BootstrapAnchor
	for index, cell := range []string{"GRU", "SFO", "FRA"} {
		if err := ctx.Err(); err != nil {
			return FoundationPreparation{}, err
		}
		live, err := lookup(ctx, input.TenancyID, catalog.OCIRegion(cell))
		if err != nil {
			return FoundationPreparation{}, err
		}
		plan, err := deriveFoundation(template, strings.ToLower(cell), catalog.OCIRegion(cell), live)
		if err != nil {
			return FoundationPreparation{}, err
		}
		plan["tenancy_id"], plan["parent_compartment_id"], plan["shared_compartment_id"] = input.TenancyID, input.ParentCompartmentID, input.SharedCompartmentID
		delete(plan, "existing_operations_host")
		plan["controller_replicas"] = 1
		ids := plan["resource_ids"].(map[string]any)
		if cell == "GRU" {
			ids["control_compartment"], ids["vault"], ids["key"] = input.SourceVaultTarget.CompartmentOCID, input.SourceVaultTarget.VaultOCID, input.SourceVaultTarget.KMSKeyOCID
		}
		host := []FoundationHostApproval{input.GRUController, input.SFOController, input.FRAController}[index]
		material, err := prepareFoundationMaterial(input, installation, cell, plan, live, host, images[cell], intentWire)
		if err != nil {
			return FoundationPreparation{}, fmt.Errorf("prepare %s: %w", cell, err)
		}
		// Only controller-a is initially funded; material for the other slots
		// conveys neither a launch allocation nor a desired host count.
		hosts := plan["hosts"].([]any)
		first := hosts[0].(map[string]any)
		first["ocpus"], first["memory_gb"], first["boot_gb"] = host.OCPUs, host.MemoryGB, host.BootGB
		plan["hosts"] = []any{first}
		plan["budget"].(map[string]any)["currency"] = input.Currency
		plan["budget"].(map[string]any)["monthly_limit"] = float64(input.MonthlyLimitMinor) / 100
		regional := FoundationIntent{Generation: 1, Plan: plan, BootstrapMaterial: &material}
		grant.Regions = append(grant.Regions, regional)
		slot, err := controllerBootstrapSlot(installation, cell, *material.Startup, host)
		if err != nil {
			return FoundationPreparation{}, err
		}
		grant.InfrastructureSpend.Bootstrap.Slots = append(grant.InfrastructureSpend.Bootstrap.Slots, slot)
		if cell == "GRU" {
			anchor = bootstrap.BootstrapAnchor{SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion, DeploymentID: material.Config.DeploymentID, Environment: "production", ClusterID: material.Config.ClusterID,
				Cell: oci.RegionGRU, OCIRegion: foundationHomeRegion, StorageDomain: input.HomeStorageDomain, ControllerSlots: slices.Clone(material.SourceRegistration.ControllerSlots),
				InitialSourceRegistration: new(material.SourceRegistration.Clone()), InitialRegionIntentGeneration: 1, InitialRegionIntentWire: slices.Clone(intentWire), InitialRegionIntentSHA256: preparationDigest(intentWire),
				FoundationScope: &bootstrap.FoundationScope{InstallationID: installation, DeploymentID: material.Config.DeploymentID, ClusterID: material.Config.ClusterID, TenancyID: input.TenancyID, OCIRegion: foundationHomeRegion, StorageDomain: input.HomeStorageDomain, GrantGeneration: 1}}
		}
	}
	manager, managerSlot, err := prepareFoundationNetBird(input, installation, grant.Regions[0].Plan, images["netbird-manager"])
	if err != nil {
		return FoundationPreparation{}, err
	}
	grant.Regions[0].NetBirdManager = &manager
	grant.InfrastructureSpend.Bootstrap.Slots = append(grant.InfrastructureSpend.Bootstrap.Slots, managerSlot)
	grant.OCIRIssuance = &OCIRIssuerIntent{OCIRegion: foundationHomeRegion, RepositoryCompartmentID: input.SourceVaultTarget.CompartmentOCID, RepositoryName: input.OCIRRepositoryName,
		RegistryNamespace: input.HomeStorageDomain.Namespace, PrincipalName: input.OCIRPrincipalName, PrincipalEmail: input.OCIRPrincipalEmail, SecretName: input.OCIRSecretName,
		VaultTarget: vaultsecret.Target{CompartmentID: input.SourceVaultTarget.CompartmentOCID, VaultID: input.SourceVaultTarget.VaultOCID, KeyID: input.SourceVaultTarget.KMSKeyOCID}}
	grant.InfrastructureSpend.ScopeSHA256, err = FoundationInfrastructureScopeDigest(grant)
	if err != nil {
		return FoundationPreparation{}, err
	}
	if err := ValidatePreparedFoundation(grant); err != nil {
		return FoundationPreparation{}, err
	}
	return FoundationPreparation{Grant: grant, Anchor: anchor}, nil
}

func preparationDigest(wire []byte) string {
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}

func foundationPreparationInstallation(input FoundationPreparationInput) string {
	return entityid.Derive("foundation-installation", input.TenancyID, input.ParentCompartmentID, input.SharedCompartmentID)
}

func prepareFoundationMaterial(input FoundationPreparationInput, installation, cell string, plan map[string]any, live Live, host FoundationHostApproval, image releasechannel.CurrentImage, intentWire []byte) (BootstrapMaterialIntent, error) {
	if err := validatePreparationImage(image, cell); err != nil {
		return BootstrapMaterialIntent{}, err
	}
	deployment := entityid.Derive("foundation-deployment", installation, cell)
	config := bootstrapmaterial.Config{Environment: "production", Cell: strings.ToLower(cell), Region: catalog.OCIRegion(cell), DeploymentID: deployment,
		ClusterID: entityid.Derive("foundation-cluster", installation, cell), SubnetCIDR: plan["subnet_cidr"].(string), ValidityHours: int(bootstrapmaterial.MaxValidity.Hours())}
	control, err := preparationResource(plan, cell, "control_compartment")
	if err != nil {
		return BootstrapMaterialIntent{}, err
	}
	subnet, err := preparationResource(plan, cell, "subnet")
	if err != nil {
		return BootstrapMaterialIntent{}, err
	}
	nsg, err := preparationResource(plan, cell, "network_security_group")
	if err != nil {
		return BootstrapMaterialIntent{}, err
	}
	startup := bootstrap.StartupTemplate{SeedSlot: "controller-a", ImageOCID: image.Image.Receipt().OCIImageOCID, ImageArchitecture: "linux-arm64",
		ReleaseImageReceiptWire: slices.Clone(image.ReceiptWire), ReleaseDelegationWire: slices.Clone(image.DelegationWire), TrustedSigners: slices.Clone(input.TrustedSigners), ControllerConfigDerivation: bootstrap.ControllerConfigDerivationV1,
		FounderResources: &bootstrap.StartupFounderResources{LaunchDeadline: image.ExpiresAt}}
	for _, value := range plan["hosts"].([]any) {
		hostPlan := value.(map[string]any)
		slot, _ := hostPlan["slot"].(string)
		ip, _ := hostPlan["private_ip"].(string)
		faultDomain, _ := hostPlan["fault_domain"].(string)
		config.Slots = append(config.Slots, bootstrapmaterial.Slot{Name: slot, PrivateIP: ip})
		startup.Profiles = append(startup.Profiles, bootstrap.LaunchProfile{Slot: slot, CompartmentOCID: control, AvailabilityDomain: live.AvailabilityDomain, FaultDomain: faultDomain,
			SubnetOCID: subnet, NetworkSecurityGroupOCIDs: []string{nsg}, Shape: "VM.Standard.A1.Flex"})
		startup.FounderResources.Slots = append(startup.FounderResources.Slots, bootstrap.StartupSlotResources{Slot: slot, ImageCompartmentOCID: control,
			WholeOCPUs: uint32(host.OCPUs), MemoryInGB: uint32(host.MemoryGB), BootVolumeGB: uint32(host.BootGB), BootVolumeTier: bootstrap.FounderBootVolumeTier("balanced")})
	}
	if err := config.Validate(); err != nil {
		return BootstrapMaterialIntent{}, err
	}
	fleet := oci.RegionConfig{Region: oci.Region(cell), Generation: 1, Endpoint: "https://iaas." + config.Region + ".oraclecloud.com", CompartmentID: control, ImageCompartmentID: control,
		AvailabilityDomain: live.AvailabilityDomain, FaultDomains: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"}, SubnetID: subnet, NetworkSecurityGroupIDs: []string{nsg},
		ImageID: startup.ImageOCID, Shape: "VM.Standard.A1.Flex", BootVolumeGB: uint32(host.BootGB), BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 32768, Owner: strings.ToLower(cell) + "-orch"}
	placement := map[string]any{"environment": "production", "member_role": "terrabase", "resources": map[string]any{"cpu": 1, "memory_bytes": 4 << 30, "disk_bytes": 20 << 30}}
	for i, value := range []any{nil, fleet, placement} {
		wire := intentWire
		if i != 0 {
			wire, err = json.Marshal(value, json.Deterministic(true))
			if err != nil {
				return BootstrapMaterialIntent{}, err
			}
		}
		startup.ControllerFiles = append(startup.ControllerFiles, bootstrap.ControllerConfigFile{Name: bootstrap.ControllerConfigFileNames[i], Bytes: slices.Clone(wire), SHA256: preparationDigest(wire)})
	}
	if err := startup.ValidateFoundation(cell); err != nil {
		return BootstrapMaterialIntent{}, err
	}
	configWire, err := json.Marshal(config, json.Deterministic(true))
	if err != nil {
		return BootstrapMaterialIntent{}, err
	}
	registration := bootstrap.InitialSourceRegistration{InstallationID: installation, DeploymentID: deployment, Environment: "production", ClusterID: config.ClusterID, Cell: oci.Region(cell), Generation: 1,
		PlanSHA256: preparationDigest(configWire), SeedSlot: startup.SeedSlot, ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}, StorageDomain: input.HomeStorageDomain, LedgerRecordDomains: bootstrap.BootstrapLedgerCapabilityDomains()}
	if err := registration.Validate(); err != nil {
		return BootstrapMaterialIntent{}, err
	}
	return BootstrapMaterialIntent{InstallationID: installation, PlanSHA256: registration.PlanSHA256, Config: config, SourceVaultTarget: input.SourceVaultTarget, Startup: &startup, SourceRegistration: &registration}, nil
}

func preparationResource(plan map[string]any, cell, key string) (string, error) {
	ids, _ := plan["resource_ids"].(map[string]any)
	if value, ok := ids[key].(string); ok && value != "" {
		return value, nil
	}
	return FoundationResourceReference(cell, key)
}

func validatePreparationImage(image releasechannel.CurrentImage, cell string) error {
	if !image.Image.IsVerified() || !time.Now().Before(image.ExpiresAt) || image.ExpiresAt.After(image.Image.ExpiresAt()) || image.Image.Receipt().OCIRegion != cell || image.Image.Receipt().Architecture != "arm64" ||
		image.Image.EnvelopeSHA256() != preparationDigest(image.ReceiptWire) || len(image.DelegationWire) == 0 {
		return errors.New("foundation image source is absent, expired or differs from its exact verified regional ARM receipt")
	}
	return nil
}

func prepareFoundationNetBird(input FoundationPreparationInput, installation string, plan map[string]any, image releasechannel.CurrentImage) (NetBirdManagerIntent, BootstrapSlotIntent, error) {
	if err := validatePreparationImage(image, "GRU"); err != nil {
		return NetBirdManagerIntent{}, BootstrapSlotIntent{}, err
	}
	// The dedicated manager uses its own /24 next to the controller network.
	network, err := netip.ParsePrefix(plan["network_cidr"].(string))
	if err != nil {
		return NetBirdManagerIntent{}, BootstrapSlotIntent{}, err
	}
	address := network.Addr().As4()
	address[2]++
	managerNetwork := netip.PrefixFrom(netip.AddrFrom4(address), 24)
	address[3] = 10
	host := input.NetBirdManager
	intent := NetBirdManagerIntent{Role: NetBirdManagerRole, StoreOrigin: "new", ImageOCID: image.Image.Receipt().OCIImageOCID, Architecture: "arm64",
		Profile:          NetBirdManagerProfile{AvailabilityDomain: plan["availability_domain"].(string), FaultDomain: "FAULT-DOMAIN-1", PrivateIP: netip.AddrFrom4(address).String(), NetworkCIDR: managerNetwork.String(), Shape: "VM.Standard.A1.Flex", OCPUs: float32(host.OCPUs), MemoryGB: float32(host.MemoryGB), BootVolumeGB: host.BootGB},
		ImageReceiptWire: slices.Clone(image.ReceiptWire), ImageDelegationWire: slices.Clone(image.DelegationWire), QualificationWire: slices.Clone(image.QualificationWire), QualificationDelegationWire: slices.Clone(image.QualificationDelegationWire)}
	profileDigest, err := NetBirdManagerProfileDigest(intent.Profile)
	if err != nil {
		return NetBirdManagerIntent{}, BootstrapSlotIntent{}, err
	}
	recipeDigest, err := NetBirdManagerRecipeDigest(intent, image.Image.Receipt().ImageSHA256)
	if err != nil {
		return NetBirdManagerIntent{}, BootstrapSlotIntent{}, err
	}
	return intent, BootstrapSlotIntent{SlotID: BootstrapSlotID(installation, "GRU", NetBirdManagerRole, NetBirdManagerRole), Cell: "GRU", Role: NetBirdManagerRole, Slot: NetBirdManagerRole,
		CompartmentID: input.SourceVaultTarget.CompartmentOCID, ProfileSHA256: profileDigest, RecipeSHA256: recipeDigest, Shape: intent.Profile.Shape, OCPUs: host.OCPUs, MemoryGB: host.MemoryGB, BootGB: float64(host.BootGB), MonthlyLimitMinor: host.MonthlyLimitMinor}, nil
}

// ControllerBootstrapProfileDigest binds the signed logical launch profile;
// resource projection must preserve this original authorization digest.
func ControllerBootstrapProfileDigest(profile bootstrap.LaunchProfile) (string, error) {
	return bootstrap.ControllerBootstrapProfileDigest(profile)
}

// ControllerBootstrapRecipeDigest binds all public startup inputs, including
// the release proof, sidecars, operator grants and logical resource references.
func ControllerBootstrapRecipeDigest(startup bootstrap.StartupTemplate) (string, error) {
	return bootstrap.ControllerBootstrapRecipeDigest(startup)
}

func controllerBootstrapSlot(installation, cell string, startup bootstrap.StartupTemplate, host FoundationHostApproval) (BootstrapSlotIntent, error) {
	profileIndex := slices.IndexFunc(startup.Profiles, func(profile bootstrap.LaunchProfile) bool { return profile.Slot == startup.SeedSlot })
	if profileIndex < 0 || startup.SeedSlot != "controller-a" {
		return BootstrapSlotIntent{}, errors.New("initial controller allocation requires the exact controller-a seed profile")
	}
	profile := startup.Profiles[profileIndex]
	profileDigest, err := ControllerBootstrapProfileDigest(profile)
	if err != nil {
		return BootstrapSlotIntent{}, err
	}
	recipeDigest, err := ControllerBootstrapRecipeDigest(startup)
	if err != nil {
		return BootstrapSlotIntent{}, err
	}
	return BootstrapSlotIntent{SlotID: BootstrapSlotID(installation, cell, "controller", startup.SeedSlot), Cell: cell, Role: "controller", Slot: startup.SeedSlot,
		CompartmentID: profile.CompartmentOCID, ProfileSHA256: profileDigest, RecipeSHA256: recipeDigest, Shape: profile.Shape,
		OCPUs: host.OCPUs, MemoryGB: host.MemoryGB, BootGB: float64(host.BootGB), MonthlyLimitMinor: host.MonthlyLimitMinor}, nil
}

// ValidatePreparedFoundation prevents the ceremony from signing spending
// hashes unrelated to the recipes its launch consumers actually enforce.
func ValidatePreparedFoundation(grant FoundationGrant) error {
	if err := ValidateBootstrapSpending(grant); err != nil {
		return err
	}
	if grant.SchemaVersion != 2 || grant.Generation != 1 || grant.InfrastructureSpend == nil || grant.InfrastructureSpend.Bootstrap == nil || len(grant.InfrastructureSpend.Bootstrap.Slots) != 4 || len(grant.Regions) != 3 {
		return errors.New("prepared foundation requires exactly three controller allocations and one dedicated GRU manager")
	}
	slots := make(map[string]BootstrapSlotIntent, 4)
	for _, slot := range grant.InfrastructureSpend.Bootstrap.Slots {
		key := slot.Cell + "/" + slot.Role
		if _, exists := slots[key]; exists || slot.Slot != "controller-a" && slot.Role == "controller" {
			return errors.New("prepared foundation repeats a bootstrap role or funds a non-seed controller")
		}
		slots[key] = slot
	}
	seen := map[string]bool{}
	for _, regional := range grant.Regions {
		cell, _ := regional.Plan["cell"].(string)
		if !slices.Contains([]string{"GRU", "SFO", "FRA"}, cell) || seen[cell] || regional.BootstrapMaterial == nil || regional.BootstrapMaterial.Startup == nil {
			return errors.New("prepared foundation differs from the fixed bootstrap footprint")
		}
		seen[cell] = true
		material := regional.BootstrapMaterial
		startup := *material.Startup
		configWire, err := json.Marshal(material.Config, json.Deterministic(true))
		if err != nil || material.Config.Validate() != nil || startup.ValidateFoundation(cell) != nil || material.InstallationID != grant.InstallationID ||
			material.Config.Cell != strings.ToLower(cell) || material.Config.Region != regional.Plan["region"] || material.PlanSHA256 != preparationDigest(configWire) || regional.Generation != grant.Generation ||
			material.SourceRegistration == nil || material.SourceRegistration.Validate() != nil || material.SourceRegistration.InstallationID != grant.InstallationID || material.SourceRegistration.PlanSHA256 != material.PlanSHA256 ||
			material.SourceRegistration.DeploymentID != material.Config.DeploymentID || material.SourceRegistration.ClusterID != material.Config.ClusterID || material.SourceRegistration.Generation != grant.Generation ||
			material.SourceRegistration.Cell != oci.Region(cell) || material.SourceRegistration.Environment != material.Config.Environment || material.SourceRegistration.SeedSlot != startup.SeedSlot {
			return errors.New("prepared material differs from its exact config, source registration or startup recipe")
		}
		var hosts []struct {
			Slot     string  `json:"slot"`
			Shape    string  `json:"shape"`
			OCPUs    float64 `json:"ocpus"`
			MemoryGB float64 `json:"memory_gb"`
			BootGB   int64   `json:"boot_gb"`
		}
		hostWire, err := json.Marshal(regional.Plan["hosts"])
		if err != nil || json.Unmarshal(hostWire, &hosts) != nil || len(hosts) != 1 || hosts[0].Slot != startup.SeedSlot || hosts[0].Shape != "VM.Standard.A1.Flex" {
			return errors.New("prepared plan must contain exactly its funded initial controller")
		}
		slot, exists := slots[cell+"/controller"]
		expected, err := controllerBootstrapSlot(grant.InstallationID, cell, startup, FoundationHostApproval{OCPUs: hosts[0].OCPUs, MemoryGB: hosts[0].MemoryGB, BootGB: hosts[0].BootGB, MonthlyLimitMinor: slot.MonthlyLimitMinor})
		if !exists || err != nil || expected != slot {
			return errors.New("controller allocation differs from its exact signed logical profile, geometry or startup recipe")
		}
		if startup.FounderResources == nil {
			return errors.New("controller startup lacks exact signed founder resources")
		}
		for _, resources := range startup.FounderResources.Slots {
			if float64(resources.WholeOCPUs) != slot.OCPUs || float64(resources.MemoryInGB) != slot.MemoryGB || float64(resources.BootVolumeGB) != slot.BootGB {
				return errors.New("controller founder resources differ from the finite host allocation")
			}
		}
		if cell != "GRU" {
			if regional.NetBirdManager != nil {
				return errors.New("dedicated NetBird manager is confined to GRU")
			}
			continue
		}
		manager := regional.NetBirdManager
		if manager == nil || manager.validate() != nil {
			return errors.New("prepared GRU foundation lacks the dedicated qualified NetBird manager")
		}
		managerSlot, exists := slots["GRU/"+NetBirdManagerRole]
		profileDigest, err := NetBirdManagerProfileDigest(manager.Profile)
		if !exists || err != nil || managerSlot.ProfileSHA256 != profileDigest || managerSlot.Shape != manager.Profile.Shape || managerSlot.OCPUs != float64(manager.Profile.OCPUs) || managerSlot.MemoryGB != float64(manager.Profile.MemoryGB) || managerSlot.BootGB != float64(manager.Profile.BootVolumeGB) {
			return errors.New("NetBird allocation differs from its exact signed logical profile or geometry")
		}
		envelope, err := trust.DecodeEnvelope(manager.ImageReceiptWire)
		if err != nil {
			return err
		}
		var receipt release.ImageReceipt
		if err := json.Unmarshal(envelope.Payload, &receipt, json.RejectUnknownMembers(true)); err != nil || receipt.Validate() != nil || receipt.OCIImageOCID != manager.ImageOCID || receipt.Architecture != manager.Architecture || receipt.OCIRegion != "GRU" {
			return errors.New("NetBird recipe differs from its exact image receipt")
		}
		recipeDigest, err := NetBirdManagerRecipeDigest(*manager, receipt.ImageSHA256)
		if err != nil || managerSlot.RecipeSHA256 != recipeDigest {
			return errors.New("NetBird allocation differs from its exact signed startup recipe")
		}
	}
	return nil
}
