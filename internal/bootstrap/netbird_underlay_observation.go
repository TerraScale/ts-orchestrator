package bootstrap

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// VerifiedNetBirdUnderlayObservation describes only the completed original
// route. It authorizes no effect, replay, credential, listener or serving role.
// It does not claim to recompute the regional foundation recipe.
type VerifiedNetBirdUnderlayObservation struct {
	factory  *ociclient.Factory
	genesis  trust.Keyring
	storage  StorageDomain
	original context.Context
	journal  NetBirdUnderlayRecord
	birth    string
	tenancy  string
}

func (v VerifiedNetBirdUnderlayObservation) IsVerified() bool {
	return v.factory != nil && v.original != nil && v.birth != "" && v.tenancy != ""
}

// VerifyNetBirdUnderlayObservation reads the actual protected object itself;
// caller-supplied journal DTOs and callbacks cannot manufacture this seal.
func VerifyNetBirdUnderlayObservation(ctx context.Context, factory *ociclient.Factory, genesis trust.Keyring, storage StorageDomain) (VerifiedNetBirdUnderlayObservation, error) {
	var zero VerifiedNetBirdUnderlayObservation
	if ctx == nil || ctx.Err() != nil || factory == nil || len(genesis) == 0 || storage.Validate() != nil || storage.HeadBucket != netBirdOriginBucket {
		return zero, errors.New("original NetBird observation requires live authenticated OCI, independent roots and root-pinned home storage")
	}
	genesis = maps.Clone(genesis)
	for id, key := range genesis {
		genesis[id] = bytes.Clone(key)
	}
	v := VerifiedNetBirdUnderlayObservation{factory: factory, genesis: genesis, storage: storage, original: ctx}
	journal, birth, tenancy, err := v.observe(ctx)
	if err != nil {
		return zero, err
	}
	v.journal, v.birth, v.tenancy = journal, birth, tenancy
	return v, nil
}

// WriterRules repeats protected/archive/native reads at the actual comparison
// and binds the allowance to every writer network ID in the inspected plan.
func (v VerifiedNetBirdUnderlayObservation) WriterRules(ctx context.Context, tenancy, cell, vcn, subnet, route, security, nsg string) (core.RouteRule, core.IngressSecurityRule, error) {
	var emptyRoute core.RouteRule
	var emptyIngress core.IngressSecurityRule
	if !v.IsVerified() || ctx == nil || v.original.Err() != nil {
		return emptyRoute, emptyIngress, errors.New("original NetBird observation is absent or canceled")
	}
	current, birth, observedTenancy, err := v.observe(ctx)
	if err != nil {
		return emptyRoute, emptyIngress, err
	}
	w := current.Writer
	if !netBirdUnderlayEqual(current, v.journal) || birth != v.birth || observedTenancy != v.tenancy || tenancy != v.tenancy || cell != "GRU" ||
		vcn != w.NetworkID || subnet != w.SubnetID || route != w.RouteTableID || security != w.SecurityID || nsg != w.NSGID {
		return emptyRoute, emptyIngress, errors.New("original NetBird observation differs from the protected birth or inspected writer network")
	}
	if err := v.original.Err(); err != nil {
		return emptyRoute, emptyIngress, err
	}
	if err := ctx.Err(); err != nil {
		return emptyRoute, emptyIngress, err
	}
	return core.RouteRule{Destination: new(current.Recipe.ManagerPrivateIP + "/32"), DestinationType: core.RouteRuleDestinationTypeCidrBlock,
		NetworkEntityId: new(current.Requests["writer_gateway"].ResponseID)}, NetBirdUnderlayIngress(current.Recipe.ManagerPrivateIP), nil
}

type underlayOriginalSlot struct {
	SlotID        string  `json:"slotId"`
	Cell          string  `json:"cell"`
	Role          string  `json:"role"`
	Slot          string  `json:"slot"`
	CompartmentID string  `json:"compartmentId"`
	ProfileSHA256 string  `json:"profileSha256"`
	RecipeSHA256  string  `json:"recipeSha256"`
	Shape         string  `json:"shape"`
	OCPUs         float64 `json:"ocpus"`
	MemoryGB      float64 `json:"memoryGb"`
	BootGB        float64 `json:"bootGb"`
}

type underlayOriginalPhysicalRegion struct {
	Cell, OCIRegion string
	CompartmentIDs  []string
}

type underlayOriginalManagerProfile struct {
	AvailabilityDomain string  `json:"availabilityDomain"`
	FaultDomain        string  `json:"faultDomain"`
	PrivateIP          string  `json:"privateIp"`
	NetworkCIDR        string  `json:"networkCidr"`
	Shape              string  `json:"shape"`
	OCPUs              float32 `json:"ocpus"`
	MemoryGB           float32 `json:"memoryGb"`
	BootVolumeGB       int64   `json:"bootVolumeGb"`
}

type underlayOriginalManager struct {
	SlotID              string    `json:"slotId"`
	OperationID         string    `json:"operationId"`
	ProfileSHA256       string    `json:"profileSha256"`
	RecipeSHA256        string    `json:"recipeSha256"`
	RequestDigest       string    `json:"requestDigest"`
	RetryToken          string    `json:"retryToken"`
	StartedAt           time.Time `json:"startedAt"`
	InstanceID          string    `json:"instanceId"`
	BootVolumeID        string    `json:"bootVolumeId"`
	OriginGrantSHA256   string    `json:"originGrantSha256"`
	OriginBindingSHA256 string    `json:"originBindingSha256"`
	OriginalScopeSHA256 string    `json:"originalScopeSha256"`
	PhysicalScopeSHA256 string    `json:"physicalScopeSha256"`
}

type underlayOriginalWriter struct {
	Cell                string                     `json:"cell"`
	Slot                string                     `json:"slot"`
	InstallationID      string                     `json:"installationId"`
	GrantSHA256         string                     `json:"grantSha256"`
	Generation          uint64                     `json:"generation"`
	SlotID              string                     `json:"slotId"`
	OperationID         string                     `json:"operationId"`
	ProfileSHA256       string                     `json:"profileSha256"`
	RecipeSHA256        string                     `json:"recipeSha256"`
	BindingSHA256       string                     `json:"bindingSha256"`
	ScopeSHA256         string                     `json:"scopeSha256"`
	PhysicalScopeSHA256 string                     `json:"physicalScopeSha256"`
	Namespace           string                     `json:"namespace"`
	Bucket              string                     `json:"bucket"`
	BucketCompartment   string                     `json:"bucketCompartment"`
	KMSKeyID            string                     `json:"kmsKeyId"`
	Request             core.LaunchInstanceDetails `json:"request"`
	RequestDigest       string                     `json:"requestDigest"`
	RetryToken          string                     `json:"retryToken"`
	FirstAttemptAt      time.Time                  `json:"firstAttemptAt"`
	InstanceID          string                     `json:"instanceId"`
	Policy              *struct {
		PolicyID   string    `json:"policyId"`
		VerifiedAt time.Time `json:"verifiedAt"`
	} `json:"policy"`
}

type underlayOriginalRecord struct {
	SchemaVersion       int                      `json:"schemaVersion"`
	Cell                string                   `json:"cell"`
	OCIRegion           string                   `json:"ociRegion"`
	TenancyID           string                   `json:"tenancyId"`
	ParentCompartmentID string                   `json:"parentCompartmentId"`
	SharedCompartmentID string                   `json:"sharedCompartmentId"`
	Generation          uint64                   `json:"generation"`
	OperationID         string                   `json:"operationId"`
	Epoch               uint64                   `json:"epoch"`
	ResourceIDs         map[string]string        `json:"resourceIds"`
	AuxiliaryIDs        map[string]string        `json:"auxiliaryIds"`
	NetBirdUnderlay     jsontext.Value           `json:"netbirdUnderlay"`
	NetBirdManager      *underlayOriginalManager `json:"netbirdManager"`
	FoundationWriter    *underlayOriginalWriter  `json:"foundationWriter"`
}

func (v VerifiedNetBirdUnderlayObservation) observe(ctx context.Context) (NetBirdUnderlayRecord, string, string, error) {
	var zero NetBirdUnderlayRecord
	if ctx == nil || v.original == nil || v.original.Err() != nil {
		return zero, "", "", errors.New("original NetBird observation requires live current read and original caller contexts")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	stop := context.AfterFunc(v.original, cancel)
	defer func() { stop(); cancel() }()
	if deadline, ok := v.original.Deadline(); ok {
		var release context.CancelFunc
		ctx, release = context.WithDeadline(ctx, deadline)
		defer release()
	}
	home, err := v.factory.ForRegion("sa-saopaulo-1")
	if err != nil {
		return zero, "", "", err
	}
	client, err := home.ObjectStorage()
	if err != nil {
		return zero, "", "", err
	}
	bucket, err := client.GetBucket(ociclient.RequestContext(ctx), objectstorage.GetBucketRequest{NamespaceName: new(v.storage.Namespace), BucketName: new(v.storage.HeadBucket)})
	if err != nil || underlayValue(bucket.Name) != v.storage.HeadBucket || underlayValue(bucket.Namespace) != v.storage.Namespace ||
		underlayValue(bucket.KmsKeyId) != v.storage.HeadKMSKeyOCID || bucket.PublicAccessType != objectstorage.BucketPublicAccessTypeNopublicaccess {
		return zero, "", "", errors.Join(errors.New("original NetBird protected store differs from its root-pinned private KMS bucket"), err)
	}
	response, err := client.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(v.storage.Namespace), BucketName: new(v.storage.HeadBucket), ObjectName: new("orchestrator/regions/v1/GRU.json")})
	if err != nil {
		return zero, "", "", err
	}
	if response.Content == nil {
		return zero, "", "", errors.New("original NetBird protected record has no content")
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, 128<<10+1))
	var record underlayOriginalRecord
	if err != nil || len(wire) == 0 || len(wire) > 128<<10 || json.Unmarshal(wire, &record) != nil || len(record.NetBirdUnderlay) == 0 || record.NetBirdManager == nil || record.FoundationWriter == nil {
		return zero, "", "", errors.Join(errors.New("original NetBird protected record lacks its retained native births and underlay"), err)
	}
	var journal NetBirdUnderlayRecord
	if err := json.Unmarshal(record.NetBirdUnderlay, &journal, json.RejectUnknownMembers(true)); err != nil {
		return zero, "", "", err
	}
	if err := journal.Validate(); err != nil {
		return zero, "", "", err
	}
	for _, step := range netBirdUnderlaySteps {
		if journal.Requests[step].VerifiedAt.IsZero() {
			return zero, "", "", errors.New("original NetBird observation denies a pending or ambiguous native operation")
		}
	}
	documents, err := ReadNetBirdJournalOrigin(ctx, home, v.genesis, journal.Origin, journal.StartedAt)
	if err != nil {
		return zero, "", "", err
	}
	manager, writer, tenancy, err := v.originalLaunches(documents.GrantWire, record, journal, underlayValue(bucket.CompartmentId))
	if err != nil {
		return zero, "", "", err
	}
	if err := observeOriginalUnderlayLaunch(ctx, home, journal.Manager, manager, record.NetBirdManager.BootVolumeID, journal.Recipe.ManagerPrivateIP, false); err != nil {
		return zero, "", "", err
	}
	if err := observeOriginalUnderlayLaunch(ctx, home, journal.Writer, writer, "", journal.Recipe.WriterPrivateIP, true); err != nil {
		return zero, "", "", err
	}
	if err := observeOriginalUnderlayNetworks(ctx, home, journal.Recipe, journal.Manager, journal.Writer); err != nil {
		return zero, "", "", err
	}
	network, err := home.Network()
	if err != nil {
		return zero, "", "", err
	}
	for _, step := range netBirdUnderlaySteps {
		if err := observeOriginalUnderlayRequest(ctx, network, journal, step); err != nil {
			return zero, "", "", err
		}
	}
	birthWire, err := json.Marshal(struct {
		Manager *underlayOriginalManager
		Writer  *underlayOriginalWriter
	}{record.NetBirdManager, record.FoundationWriter}, json.Deterministic(true))
	if err != nil {
		return zero, "", "", err
	}
	if err := v.original.Err(); err != nil {
		return zero, "", "", err
	}
	if err := ctx.Err(); err != nil {
		return zero, "", "", err
	}
	return journal, digestBytes(birthWire), tenancy, nil
}

func (v VerifiedNetBirdUnderlayObservation) originalLaunches(grantWire []byte, record underlayOriginalRecord, j NetBirdUnderlayRecord, bucketCompartment string) (core.LaunchInstanceDetails, core.LaunchInstanceDetails, string, error) {
	var empty core.LaunchInstanceDetails
	fail := func() (core.LaunchInstanceDetails, core.LaunchInstanceDetails, string, error) {
		return empty, empty, "", errors.New("original NetBird archive, purpose, source, allocations or protected native launches differ")
	}
	envelope, err := trust.DecodeEnvelope(grantWire)
	if err != nil {
		return empty, empty, "", err
	}
	var grant struct {
		InstallationID      string           `json:"installationId"`
		Generation          uint64           `json:"generation"`
		TenancyID           string           `json:"tenancyId"`
		ParentCompartmentID string           `json:"parentCompartmentId"`
		SharedCompartmentID string           `json:"sharedCompartmentId"`
		Currency            string           `json:"currency"`
		Regions             []jsontext.Value `json:"regions"`
		InfrastructureSpend struct {
			ScopeSHA256 string `json:"scopeSha256"`
			Bootstrap   struct {
				Slots []underlayOriginalSlot `json:"slots"`
			} `json:"bootstrap"`
		} `json:"infrastructureSpend"`
	}
	if json.Unmarshal(envelope.Payload, &grant) != nil || record.SchemaVersion != 1 || record.Cell != "GRU" || record.OCIRegion != "sa-saopaulo-1" || record.TenancyID != grant.TenancyID ||
		record.ParentCompartmentID != grant.ParentCompartmentID || record.SharedCompartmentID != grant.SharedCompartmentID {
		return fail()
	}
	m, w := *record.NetBirdManager, *record.FoundationWriter
	if j.OperationID != entityid.Derive("regional-foundation", grant.TenancyID, "GRU", fmt.Sprint(grant.Generation)) || record.Generation < grant.Generation ||
		record.OperationID != entityid.Derive("regional-foundation", grant.TenancyID, "GRU", fmt.Sprint(record.Generation)) || record.Epoch < j.Epoch ||
		j.Origin.Namespace != v.storage.Namespace || j.Origin.GrantObject != strings.TrimSuffix(v.storage.Prefix, "/")+"/"+netBirdOriginGrantObject {
		return fail()
	}
	var selected struct {
		Generation     uint64         `json:"generation"`
		Plan           map[string]any `json:"plan"`
		NetBirdManager *struct {
			Profile        underlayOriginalManagerProfile `json:"profile"`
			ImageOCID      string                         `json:"imageOcid"`
			JournalPurpose NetBirdJournalPurpose          `json:"journalPurpose"`
		} `json:"netbirdManager"`
		BootstrapMaterial *struct {
			InstallationID    string           `json:"installationId"`
			PlanSHA256        string           `json:"planSha256"`
			Config            jsontext.Value   `json:"config"`
			Startup           *StartupTemplate `json:"startup"`
			SourceVaultTarget struct {
				CompartmentOCID string `json:"compartmentOcid"`
			} `json:"sourceVaultTarget"`
		} `json:"bootstrapMaterial"`
	}
	found := false
	for _, raw := range grant.Regions {
		var candidate struct {
			Plan           map[string]any `json:"plan"`
			NetBirdManager jsontext.Value `json:"netbirdManager"`
		}
		if json.Unmarshal(raw, &candidate) != nil {
			return fail()
		}
		if candidate.Plan["cell"] != "GRU" {
			if len(candidate.NetBirdManager) != 0 {
				return fail()
			}
			continue
		}
		if found || json.Unmarshal(raw, &selected) != nil {
			return fail()
		}
		var object map[string]any
		if json.Unmarshal(raw, &object) != nil {
			return fail()
		}
		canonical, err := json.Marshal(object, json.Deterministic(true))
		if err != nil || digestBytes(canonical) != j.IntentDigest {
			return fail()
		}
		found = true
	}
	if !found || selected.NetBirdManager == nil || selected.BootstrapMaterial == nil || selected.BootstrapMaterial.Startup == nil || selected.Generation != grant.Generation {
		return fail()
	}
	p := selected.NetBirdManager.JournalPurpose
	purposeDigest, err := p.Digest()
	if err != nil || purposeDigest != j.PurposeSHA256 || p.Storage != v.storage || p.InstallationID != grant.InstallationID || p.SourceGeneration != grant.Generation ||
		p.DeploymentID != envelope.Scope.DeploymentID || p.ClusterID != envelope.Scope.Slot || p.ExpiresAt.After(envelope.ExpiresAt) || !j.StartedAt.Before(p.ExpiresAt) || j.ExpiresAt.After(p.ExpiresAt) || j.Recipe != p.Underlay {
		return fail()
	}
	material := selected.BootstrapMaterial
	if bucketCompartment != material.SourceVaultTarget.CompartmentOCID || w.BucketCompartment != bucketCompartment {
		return fail()
	}
	var config struct {
		Environment  string `json:"environment"`
		Region       string `json:"region"`
		Cell         string `json:"cell"`
		DeploymentID string `json:"deploymentId"`
		ClusterID    string `json:"clusterId"`
		SubnetCIDR   string `json:"subnetCidr"`
		Slots        []struct {
			Name      string `json:"name"`
			PrivateIP string `json:"privateIp"`
		} `json:"slots"`
		ValidityHours int    `json:"validityHours"`
		LinkSigner    string `json:"linkSigner,omitempty"`
	}
	if json.Unmarshal(material.Config, &config, json.RejectUnknownMembers(true)) != nil {
		return fail()
	}
	configWire, err := json.Marshal(config, json.Deterministic(true))
	if err != nil || digestBytes(configWire) != p.SourcePlanSHA256 || material.PlanSHA256 != p.SourcePlanSHA256 || material.InstallationID != grant.InstallationID ||
		config.DeploymentID != p.DeploymentID || config.ClusterID != p.ClusterID || config.Environment != "production" || config.Cell != "gru" || config.Region != "sa-saopaulo-1" {
		return fail()
	}
	seedCount := 0
	for _, slot := range config.Slots {
		if slot.Name == "controller-a" {
			if slot.PrivateIP != p.Underlay.WriterPrivateIP {
				return fail()
			}
			seedCount++
		}
	}
	if seedCount != 1 || selected.Plan["network_cidr"] != p.Underlay.WriterNetworkCIDR || selected.Plan["subnet_cidr"] != p.Underlay.WriterSubnetCIDR ||
		selected.NetBirdManager.Profile.NetworkCIDR != p.Underlay.ManagerNetworkCIDR || selected.NetBirdManager.Profile.PrivateIP != p.Underlay.ManagerPrivateIP {
		return fail()
	}
	lookup := func(reference string) (string, error) {
		cell, key, err := foundationbinding.Parse(reference)
		id := record.ResourceIDs[key]
		if err != nil || cell != "GRU" || id == "" {
			return "", ErrManifestInvalid
		}
		return id, nil
	}
	startup, err := projectFoundationStartup(*material.Startup, "GRU", lookup)
	if err != nil || startup.SeedSlot != "controller-a" || startup.FounderResources == nil {
		return fail()
	}
	var seed LaunchProfile
	var resources StartupSlotResources
	for _, profile := range startup.Profiles {
		if profile.Slot == startup.SeedSlot {
			seed = profile
		}
	}
	for _, resource := range startup.FounderResources.Slots {
		if resource.Slot == startup.SeedSlot {
			resources = resource
		}
	}
	manager := selected.NetBirdManager.Profile
	profileWire, err := json.Marshal(manager, json.Deterministic(true))
	if err != nil || digestBytes(profileWire) != p.Manager.ProfileSHA256 {
		return fail()
	}
	writerRecipe, err := ControllerBootstrapRecipeDigest(*material.Startup)
	if err != nil || writerRecipe != p.Writer.RecipeSHA256 {
		return fail()
	}
	var expectedBindings, expectedPhysicalScopes [2]string
	for index, allocation := range []NetBirdJournalAllocation{p.Manager, p.Writer} {
		role, name, endpoint := "netbird-manager", "netbird-manager", j.Manager
		shape, cpus, memory, boot := manager.Shape, float64(manager.OCPUs), float64(manager.MemoryGB), float64(manager.BootVolumeGB)
		if index == 1 {
			role, name, endpoint = "controller", "controller-a", j.Writer
			shape, cpus, memory, boot = seed.Shape, float64(resources.WholeOCPUs), float64(resources.MemoryInGB), float64(resources.BootVolumeGB)
		}
		matches := 0
		for _, slot := range grant.InfrastructureSpend.Bootstrap.Slots {
			if slot.SlotID != allocation.SlotID {
				continue
			}
			compartment := slot.CompartmentID
			if strings.HasPrefix(compartment, "foundation:") {
				compartment, err = lookup(compartment)
				if err != nil {
					return fail()
				}
			}
			if slot.Cell != "GRU" || slot.Role != role || slot.Slot != name || slot.ProfileSHA256 != allocation.ProfileSHA256 || slot.RecipeSHA256 != allocation.RecipeSHA256 || compartment != endpoint.CompartmentID ||
				slot.Shape != shape || slot.OCPUs != cpus || slot.MemoryGB != memory || slot.BootGB != boot {
				return fail()
			}
			if slot.CompartmentID != compartment {
				links := []struct {
					Cell, Reference, ResourceID, GrantSHA256 string
					Generation                               uint64
				}{{"GRU", slot.CompartmentID, compartment, j.GrantSHA256, grant.Generation}}
				wire, err := json.Marshal(links, json.Deterministic(true))
				if err != nil {
					return fail()
				}
				expectedBindings[index] = digestBytes(wire)
			}
			// This is the original finite slot's descriptive scope hash, not a
			// current spending scope or independently verified binding capability.
			wire, err := json.Marshal(struct {
				SignedScopeSHA256   string
				TenancyID, Currency string
				Regions             []underlayOriginalPhysicalRegion
			}{grant.InfrastructureSpend.ScopeSHA256, grant.TenancyID, grant.Currency, []underlayOriginalPhysicalRegion{{"GRU", "sa-saopaulo-1", []string{compartment}}}}, json.Deterministic(true))
			if err != nil {
				return fail()
			}
			expectedPhysicalScopes[index] = digestBytes(wire)
			matches++
		}
		if matches != 1 {
			return fail()
		}
	}
	writerProfile, err := ControllerBootstrapProfileDigest(func() LaunchProfile {
		for _, profile := range material.Startup.Profiles {
			if profile.Slot == startup.SeedSlot {
				return profile
			}
		}
		return LaunchProfile{}
	}())
	if err != nil || writerProfile != p.Writer.ProfileSHA256 {
		return fail()
	}
	for _, side := range []struct {
		endpoint NetBirdUnderlayEndpoint
		ids      map[string]string
		keys     []string
	}{
		{j.Manager, record.AuxiliaryIDs, []string{p.Underlay.ManagerVCNKey, p.Underlay.ManagerSubnetKey, p.Underlay.ManagerRouteTableKey, p.Underlay.ManagerSecurityKey, p.Underlay.ManagerNSGKey}},
		{j.Writer, record.ResourceIDs, []string{p.Underlay.WriterVCNKey, p.Underlay.WriterSubnetKey, p.Underlay.WriterRouteTableKey, p.Underlay.WriterSecurityKey, p.Underlay.WriterNSGKey}},
	} {
		values := []string{side.endpoint.NetworkID, side.endpoint.SubnetID, side.endpoint.RouteTableID, side.endpoint.SecurityID, side.endpoint.NSGID}
		for index, key := range side.keys {
			if side.ids[key] != values[index] {
				return fail()
			}
		}
		if side.endpoint.NetworkCompartmentID != record.ResourceIDs["network_compartment"] {
			return fail()
		}
	}
	if m.SlotID != p.Manager.SlotID || m.OperationID != p.Manager.OperationID || m.ProfileSHA256 != p.Manager.ProfileSHA256 || m.RecipeSHA256 != p.Manager.RecipeSHA256 || m.InstanceID != j.Manager.InstanceID ||
		m.OriginGrantSHA256 != j.GrantSHA256 || m.OriginBindingSHA256 != expectedBindings[0] || !validDigest(grant.InfrastructureSpend.ScopeSHA256) || m.OriginalScopeSHA256 != grant.InfrastructureSpend.ScopeSHA256 || m.PhysicalScopeSHA256 != expectedPhysicalScopes[0] || !netBirdUnderlayNativeID("bootvolume", m.BootVolumeID) ||
		m.StartedAt.Before(envelope.IssuedAt) || !m.StartedAt.Before(j.StartedAt) || w.Cell != "GRU" || w.Slot != startup.SeedSlot || w.InstallationID != p.InstallationID || w.Generation != p.SourceGeneration ||
		w.SlotID != p.Writer.SlotID || w.OperationID != p.Writer.OperationID || w.ProfileSHA256 != p.Writer.ProfileSHA256 || w.RecipeSHA256 != p.Writer.RecipeSHA256 || w.InstanceID != j.Writer.InstanceID || w.GrantSHA256 != j.GrantSHA256 ||
		w.BindingSHA256 != expectedBindings[1] || w.ScopeSHA256 != grant.InfrastructureSpend.ScopeSHA256 || w.PhysicalScopeSHA256 != expectedPhysicalScopes[1] || w.Namespace != p.Storage.Namespace || w.Bucket != p.Storage.HeadBucket || w.KMSKeyID != p.Storage.HeadKMSKeyOCID ||
		w.FirstAttemptAt.Before(envelope.IssuedAt) || !w.FirstAttemptAt.Before(j.StartedAt) || w.Policy == nil || !strings.HasPrefix(w.Policy.PolicyID, "ocid1.policy.") || w.Policy.VerifiedAt.IsZero() || w.Policy.VerifiedAt.After(j.StartedAt) {
		return fail()
	}
	managerLaunch := core.LaunchInstanceDetails{AvailabilityDomain: new(manager.AvailabilityDomain), CompartmentId: new(j.Manager.CompartmentID), FaultDomain: new(manager.FaultDomain), DisplayName: new("gru-1-netbird-manager"), Shape: new(manager.Shape),
		ShapeConfig: &core.LaunchInstanceShapeConfigDetails{Ocpus: new(manager.OCPUs), MemoryInGBs: new(manager.MemoryGB)}, SourceDetails: core.InstanceSourceViaImageDetails{ImageId: new(selected.NetBirdManager.ImageOCID), BootVolumeSizeInGBs: new(manager.BootVolumeGB), BootVolumeVpusPerGB: new(int64(10))},
		CreateVnicDetails: &core.CreateVnicDetails{SubnetId: new(j.Manager.SubnetID), NsgIds: []string{j.Manager.NSGID}, PrivateIp: new(p.Underlay.ManagerPrivateIP), AssignPublicIp: new(true)}}
	writerLaunch := originalUnderlayWriterLaunch(startup, seed, resources, p.Underlay.WriterPrivateIP)
	managerDigest, err := originalUnderlayLaunchDigest(managerLaunch)
	if err != nil || managerDigest != m.RequestDigest || m.RetryToken != digestBytes([]byte("foundation-host-request:"+m.OperationID+":"+managerDigest)) {
		return fail()
	}
	writerDigest, err := originalUnderlayLaunchDigest(writerLaunch)
	actualWriterDigest, actualErr := originalUnderlayLaunchDigest(w.Request)
	if err != nil || actualErr != nil || writerDigest != w.RequestDigest || actualWriterDigest != writerDigest || w.RetryToken != digestBytes([]byte("foundation-host-request:"+w.OperationID+":"+writerDigest)) ||
		seed.CompartmentOCID != j.Writer.CompartmentID || seed.SubnetOCID != j.Writer.SubnetID || !slices.Equal(seed.NetworkSecurityGroupOCIDs, []string{j.Writer.NSGID}) {
		return fail()
	}
	return managerLaunch, writerLaunch, grant.TenancyID, nil
}

func originalUnderlayWriterLaunch(startup StartupTemplate, profile LaunchProfile, resources StartupSlotResources, privateIP string) core.LaunchInstanceDetails {
	return core.LaunchInstanceDetails{AvailabilityDomain: new(profile.AvailabilityDomain), CompartmentId: new(profile.CompartmentOCID), FaultDomain: new(profile.FaultDomain), DisplayName: new("gru-1-" + startup.SeedSlot), Shape: new(profile.Shape),
		Metadata: map[string]string{"terrascale-bootstrap": fmt.Sprintf(`{"schemaVersion":1,"slot":%q}`, startup.SeedSlot)}, LaunchVolumeAttachments: []core.LaunchAttachVolumeDetails{}, LicensingConfigs: []core.LaunchInstanceLicensingConfig{}, DefinedTags: map[string]map[string]any{}, SecurityAttributes: map[string]map[string]any{}, ExtendedMetadata: map[string]any{}, FreeformTags: map[string]string{},
		ShapeConfig: &core.LaunchInstanceShapeConfigDetails{Ocpus: new(float32(resources.WholeOCPUs)), MemoryInGBs: new(float32(resources.MemoryInGB))}, SourceDetails: core.InstanceSourceViaImageDetails{ImageId: new(startup.ImageOCID), BootVolumeSizeInGBs: new(int64(resources.BootVolumeGB)), BootVolumeVpusPerGB: new(int64(10))},
		CreateVnicDetails: &core.CreateVnicDetails{SubnetId: new(profile.SubnetOCID), NsgIds: slices.Clone(profile.NetworkSecurityGroupOCIDs), PrivateIp: new(privateIP), AssignPublicIp: new(false), DefinedTags: map[string]map[string]any{}, FreeformTags: map[string]string{}, SecurityAttributes: map[string]map[string]any{}, Ipv6AddressIpv6SubnetCidrPairDetails: []core.Ipv6AddressIpv6SubnetCidrPairDetails{}}}
}

func originalUnderlayLaunchDigest(details core.LaunchInstanceDetails) (string, error) {
	request, err := (core.LaunchInstanceRequest{LaunchInstanceDetails: details}).HTTPRequest(http.MethodPost, "/20160918/instances", nil, nil)
	if err != nil {
		return "", err
	}
	if request.Body == nil {
		return "", errors.New("original NetBird launch has no native SDK body")
	}
	defer request.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(request.Body, 1<<20+1))
	if err != nil || len(wire) > 1<<20 {
		return "", errors.Join(errors.New("original NetBird launch exceeds its fixed body bound"), err)
	}
	var body map[string]any
	if err := json.Unmarshal(wire, &body); err != nil {
		return "", err
	}
	wire, err = json.Marshal(body, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestBytes(wire), nil
}
