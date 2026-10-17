package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// OriginalFoundationWriter is produced only after the operator's exact SDK
// launch result has been durably read back. Observation cannot construct it.
type OriginalFoundationWriter struct {
	instance, grant, request, cell string
}

// FoundationWriterRecord permanently reserves the initial home controller.
// Grant renewal cannot transfer this launch or its exact protected objects.
type FoundationWriterRecord struct {
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
	InstanceID          string                     `json:"instanceId,omitempty"`
	Policy              *FoundationWriterPolicy    `json:"policy,omitempty"`
}

type FoundationWriterPolicy struct {
	Request        identity.CreatePolicyDetails `json:"request"`
	RequestDigest  string                       `json:"requestDigest"`
	RetryToken     string                       `json:"retryToken"`
	FirstAttemptAt time.Time                    `json:"firstAttemptAt"`
	PolicyID       string                       `json:"policyId,omitempty"`
	VerifiedAt     time.Time                    `json:"verifiedAt,omitzero"`
}

// launchFoundationWriter buys only the same-grant regional seed slot. A lost response
// retains its original bounded token and never adopts a discovered instance.
func launchFoundationWriter(ctx context.Context, authority *HomeIAMAuthority, resolver FoundationResolver, bundle RetainedFoundation, cell string) (OriginalFoundationWriter, error) {
	if !slices.Contains([]string{"GRU", "SFO", "FRA"}, cell) {
		return OriginalFoundationWriter{}, errors.New("writer cell is outside the fixed footprint")
	}
	ctx, release, err := authority.HomeWrite(ctx, 0)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	defer release()
	factory, ctx, err := authority.GuardedFactory(ctx)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	if _, err := resolver.Resolve(ctx, cell); err != nil {
		return OriginalFoundationWriter{}, err
	}
	material, err := resolver.BootstrapMaterial(ctx, cell)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	record, etag, err := resolver.Store.Load(ctx, cell)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	startup, err := material.Startup()
	if err != nil || startup.FounderResources == nil {
		return OriginalFoundationWriter{}, errors.Join(errors.New("home writer requires signed finite founder resources"), err)
	}
	slotID := BootstrapSlotID(material.InstallationID(), cell, "controller", startup.SeedSlot)
	allocation, err := resolver.BootstrapAllocation(ctx, slotID)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	slot := allocation.Slot()
	originalStartup, err := foundationWriterOriginalStartup(ctx, resolver, cell)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	originalProfile := bootstrap.LaunchProfile{}
	profile := bootstrap.LaunchProfile{}
	for _, p := range originalStartup.Profiles {
		if p.Slot == startup.SeedSlot {
			originalProfile = p
		}
	}
	for _, p := range startup.Profiles {
		if p.Slot == startup.SeedSlot {
			profile = p
		}
	}
	profileDigest, err := bootstrap.ControllerBootstrapProfileDigest(originalProfile)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	recipeDigest, err := bootstrap.ControllerBootstrapRecipeDigest(originalStartup)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	if slot.Cell != cell || slot.Role != "controller" || slot.Slot != startup.SeedSlot || slot.CompartmentID != profile.CompartmentOCID || slot.ProfileSHA256 != profileDigest || slot.RecipeSHA256 != recipeDigest || slot.Shape != profile.Shape || allocation.GrantDigest() != digestSource(bundle.GrantWire) || allocation.Generation() != material.Generation() {
		return OriginalFoundationWriter{}, errors.New("home writer differs from the exact same-grant seed allocation")
	}
	var resources bootstrap.StartupSlotResources
	for _, r := range startup.FounderResources.Slots {
		if r.Slot == startup.SeedSlot {
			resources = r
		}
	}
	if slot.OCPUs != float64(resources.WholeOCPUs) || slot.MemoryGB != float64(resources.MemoryInGB) || slot.BootGB != float64(resources.BootVolumeGB) || resources.WholeOCPUs > 1<<24 || resources.MemoryInGB > 1<<24 {
		return OriginalFoundationWriter{}, errors.New("home writer billing geometry differs from signed founder resources")
	}
	privateIP := ""
	for _, s := range material.Config().Slots {
		if s.Name == startup.SeedSlot {
			privateIP = s.PrivateIP
		}
	}
	if privateIP == "" {
		return OriginalFoundationWriter{}, errors.New("home writer has no signed seed address")
	}
	details := core.LaunchInstanceDetails{AvailabilityDomain: new(profile.AvailabilityDomain), CompartmentId: new(profile.CompartmentOCID), FaultDomain: new(profile.FaultDomain), DisplayName: new(strings.ToLower(cell) + "-1-" + startup.SeedSlot), Shape: new(profile.Shape),
		ShapeConfig:       &core.LaunchInstanceShapeConfigDetails{Ocpus: new(float32(resources.WholeOCPUs)), MemoryInGBs: new(float32(resources.MemoryInGB))},
		SourceDetails:     core.InstanceSourceViaImageDetails{ImageId: new(startup.ImageOCID), BootVolumeSizeInGBs: new(int64(resources.BootVolumeGB)), BootVolumeVpusPerGB: new(int64(10))},
		CreateVnicDetails: &core.CreateVnicDetails{SubnetId: new(profile.SubnetOCID), NsgIds: slices.Clone(profile.NetworkSecurityGroupOCIDs), PrivateIp: new(privateIP), AssignPublicIp: new(false)}}
	digest, err := netBirdRequestDigest(details)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	domain := material.StorageDomain()
	pending := FoundationWriterRecord{Cell: cell, Slot: startup.SeedSlot, InstallationID: material.InstallationID(), GrantSHA256: digestSource(bundle.GrantWire), Generation: material.Generation(), SlotID: slotID, OperationID: allocation.OperationID(), ProfileSHA256: profileDigest, RecipeSHA256: recipeDigest,
		BindingSHA256: allocation.BindingDigest(), ScopeSHA256: allocation.ScopeDigest(), PhysicalScopeSHA256: allocation.PhysicalScopeDigest(), Namespace: domain.Namespace, Bucket: domain.HeadBucket, BucketCompartment: material.EscrowTarget().CompartmentOCID, KMSKeyID: domain.HeadKMSKeyOCID,
		Request: details, RequestDigest: digest, RetryToken: BootstrapRetryToken(allocation.OperationID(), digest), FirstAttemptAt: time.Now().UTC()}
	if record.FoundationWriter != nil {
		pending = *record.FoundationWriter
		if pending.RequestDigest != digest || pending.GrantSHA256 != digestSource(bundle.GrantWire) || pending.SlotID != slotID || pending.BindingSHA256 != allocation.BindingDigest() || pending.ScopeSHA256 != allocation.ScopeDigest() || pending.PhysicalScopeSHA256 != allocation.PhysicalScopeDigest() {
			return OriginalFoundationWriter{}, errors.New("home writer immutable original reservation changed")
		}
		if pending.InstanceID != "" {
			return foundationWriterReceipt(ctx, resolver, pending)
		}
	}
	prices, err := capacityinventory.New(factory)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	quote, err := prices.Quote(ctx, allocation.Footprint(), cell, slot.CompartmentID, slot.Shape, slot.OCPUs, slot.MemoryGB, slot.BootGB)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	request := BootstrapLaunchRequest{SlotID: slotID, OperationID: pending.OperationID, Cell: cell, CompartmentID: slot.CompartmentID, ProfileSHA256: profileDigest, RecipeSHA256: recipeDigest, Shape: slot.Shape, OCPUs: slot.OCPUs, MemoryGB: slot.MemoryGB, BootGB: slot.BootGB, RequestSHA256: digest, RetryToken: pending.RetryToken, StartedAt: pending.FirstAttemptAt}
	guard := func(ctx context.Context) error {
		err := authority.Guard(ctx, 0)
		if err != nil {
			return err
		}
		if _, err := resolver.Resolve(ctx, cell); err != nil {
			return err
		}
		saved, _, err := resolver.Store.Load(ctx, cell)
		if err != nil {
			return err
		}
		if saved.FoundationWriter == nil || saved.FoundationWriter.RequestDigest != digest || saved.FoundationWriter.RetryToken != pending.RetryToken || saved.FoundationWriter.InstanceID != "" {
			return ErrFoundationFenced
		}
		if err := allocation.Revalidate(ctx); err != nil {
			return err
		}
		if !time.Now().Before(startup.FounderResources.LaunchDeadline) {
			return errors.New("home writer founder launch deadline expired")
		}
		actual, err := netBirdRequestDigest(details)
		if err != nil || actual != digest {
			return errors.Join(ErrFoundationFenced, err)
		}
		return allocation.Validate(request, quote, time.Now())
	}
	if err := allocation.Validate(request, quote, time.Now()); err != nil {
		return OriginalFoundationWriter{}, err
	}
	if record.FoundationWriter == nil {
		if err := authority.Guard(ctx, 0); err != nil {
			return OriginalFoundationWriter{}, err
		}
		record.FoundationWriter = &pending
		record.UpdatedAt = time.Now().UTC()
		if _, err := resolver.Store.CompareAndSwap(ctx, record, etag); err != nil {
			return OriginalFoundationWriter{}, err
		}
	}
	if err := guard(ctx); err != nil {
		return OriginalFoundationWriter{}, err
	}
	regional, err := factory.ForRegion(record.OCIRegion)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	compute, err := regional.Compute()
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	noRetry := common.NoRetryPolicy()
	response, err := compute.LaunchInstance(ociclient.RequestContext(ociclient.WithAuthority(ctx, guard)), core.LaunchInstanceRequest{LaunchInstanceDetails: details, OpcRetryToken: new(pending.RetryToken), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	if response.Id == nil || !sourceInstancePattern.MatchString(*response.Id) || !strings.HasPrefix(*response.Id, "ocid1.instance.oc1."+record.OCIRegion+".") {
		return OriginalFoundationWriter{}, errors.New("home writer launch returned no positive exact instance identity")
	}
	record, etag, err = resolver.Store.Load(ctx, cell)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	if record.FoundationWriter == nil || record.FoundationWriter.RequestDigest != pending.RequestDigest || record.FoundationWriter.InstanceID != "" && record.FoundationWriter.InstanceID != *response.Id {
		return OriginalFoundationWriter{}, ErrFoundationFenced
	}
	if err := authority.Guard(ctx, 0); err != nil {
		return OriginalFoundationWriter{}, err
	}
	pending.InstanceID = *response.Id
	record.FoundationWriter = &pending
	record.UpdatedAt = time.Now().UTC()
	if _, err := resolver.Store.CompareAndSwap(ctx, record, etag); err != nil {
		return OriginalFoundationWriter{}, err
	}
	return foundationWriterReceipt(ctx, resolver, pending)
}

func foundationWriterOriginalStartup(ctx context.Context, resolver FoundationResolver, cell string) (BootstrapStartupIntent, error) {
	footprint, err := resolver.Footprint.AuthorizedRegions(ctx)
	if err != nil {
		return BootstrapStartupIntent{}, err
	}
	for _, region := range footprint.Regions {
		if region.Plan["cell"] == cell && region.BootstrapMaterial != nil && region.BootstrapMaterial.Startup != nil {
			return region.BootstrapMaterial.Startup.Clone(), nil
		}
	}
	return BootstrapStartupIntent{}, errors.New("home writer lacks original signed startup")
}

func foundationWriterReceipt(ctx context.Context, resolver FoundationResolver, expected FoundationWriterRecord) (OriginalFoundationWriter, error) {
	record, _, err := resolver.Store.Load(ctx, expected.Cell)
	if err != nil {
		return OriginalFoundationWriter{}, err
	}
	saved := record.FoundationWriter
	if saved == nil || saved.validate() != nil || saved.InstanceID == "" || saved.InstanceID != expected.InstanceID || saved.RequestDigest != expected.RequestDigest || saved.GrantSHA256 != expected.GrantSHA256 {
		return OriginalFoundationWriter{}, ErrFoundationFenced
	}
	return OriginalFoundationWriter{instance: saved.InstanceID, grant: saved.GrantSHA256, request: saved.RequestDigest, cell: saved.Cell}, nil
}

func foundationWriterPolicy(record FoundationWriterRecord) (identity.CreatePolicyDetails, error) {
	if !sourceInstancePattern.MatchString(record.InstanceID) || !sourceCompartmentPattern.MatchString(record.BucketCompartment) || !sourceStoragePattern.MatchString(record.Bucket) {
		return identity.CreatePolicyDetails{}, errors.New("home writer policy has invalid exact scope")
	}
	principal := fmt.Sprintf("request.principal.type='instance', request.principal.id='%s'", record.InstanceID)
	statements := make([]string, 0, 5)
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		key := "orchestrator/regions/v1/" + cell + ".json"
		permissions := "request.permission='OBJECT_READ'"
		if cell == record.Cell {
			permissions += ", request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE'"
		}
		statements = append(statements, fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {%s, target.bucket.name='%s', target.object.name='%s', any {%s}}", record.BucketCompartment, principal, record.Bucket, key, permissions))
	}
	statements = append(statements, fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {%s, target.bucket.name='%s', target.object.name='%s', any {request.permission='OBJECT_READ', request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE'}}", record.BucketCompartment, principal, record.Bucket, homeIAMObject))
	// OCI cannot constrain a created policy body; the root process confines this principal.
	statements = append(statements, fmt.Sprintf("Allow any-user to manage policies in compartment id %s where all {%s, any {request.permission='POLICY_INSPECT', request.permission='POLICY_READ', request.permission='POLICY_CREATE'}}", record.BucketCompartment, principal))
	return identity.CreatePolicyDetails{CompartmentId: new(record.BucketCompartment), Name: new("ts-foundation-writer-" + digestSource([]byte(record.InstallationID + "\x00" + record.Cell))[:32]), Description: new("Original home writer exact protected journals and policy creation"), Statements: statements}, nil
}

// installFoundationWriter installs only the protected writer's original exact
// policy after its launch receipt and durable birth checkpoint agree.
func installFoundationWriter(ctx context.Context, authority *HomeIAMAuthority, resolver FoundationResolver, bundle RetainedFoundation, cell string, receipt OriginalFoundationWriter) error {
	if receipt.cell != cell {
		return ErrFoundationFenced
	}
	ctx, release, err := authority.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	factory, ctx, err := authority.GuardedFactory(ctx)
	if err != nil {
		return err
	}
	record, etag, err := resolver.Store.Load(ctx, cell)
	if err != nil {
		return err
	}
	if record.FoundationWriter == nil || receipt.instance == "" || receipt.instance != record.FoundationWriter.InstanceID || receipt.grant != record.FoundationWriter.GrantSHA256 || receipt.request != record.FoundationWriter.RequestDigest || receipt.grant != digestSource(bundle.GrantWire) {
		return ErrFoundationFenced
	}
	pending := *record.FoundationWriter
	details, err := foundationWriterPolicy(pending)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(details, json.Deterministic(true))
	if err != nil {
		return err
	}
	home, err := factory.HomeRegion(ctx, bundle.TenancyID)
	if err != nil {
		return err
	}
	regional, err := factory.ForRegion(home)
	if err != nil {
		return err
	}
	iam, err := regional.Identity()
	if err != nil {
		return err
	}
	actor := &SourceFounder{iam: iam}
	guard := func(ctx context.Context) error {
		err := authority.Guard(ctx, 0)
		if err != nil {
			return err
		}
		if _, err := resolver.Resolve(ctx, cell); err != nil {
			return err
		}
		saved, _, err := resolver.Store.Load(ctx, cell)
		if err != nil {
			return err
		}
		if saved.FoundationWriter == nil || saved.FoundationWriter.InstanceID != receipt.instance || saved.FoundationWriter.GrantSHA256 != receipt.grant || saved.FoundationWriter.RequestDigest != receipt.request {
			return ErrFoundationFenced
		}
		return nil
	}
	ctx = ociclient.WithAuthority(ctx, guard)
	found, err := actor.findPolicy(ctx, details)
	if err != nil {
		return err
	}
	if pending.Policy == nil {
		if found != "" {
			return errors.New("same-name home writer policy lacks original protected reservation")
		}
		pending.Policy = &FoundationWriterPolicy{Request: details, RequestDigest: digestSource(wire), RetryToken: digestSource([]byte(pending.RequestDigest + "\x00" + pending.InstanceID + "\x00" + digestSource(wire))), FirstAttemptAt: time.Now().UTC()}
		record.FoundationWriter = &pending
		record.UpdatedAt = time.Now().UTC()
		if err := guard(ctx); err != nil {
			return err
		}
		if _, err := resolver.Store.CompareAndSwap(ctx, record, etag); err != nil {
			return err
		}
	}
	policy := *pending.Policy
	if err := pending.validate(); err != nil {
		return err
	}
	if policy.PolicyID != "" && found != policy.PolicyID {
		return errors.New("home writer policy original identity changed")
	}
	if found == "" {
		if !time.Now().Before(policy.FirstAttemptAt.Add(bootstrapRetryLifetime)) {
			return errors.New("home writer policy retry deadline expired")
		}
		if err := guard(ctx); err != nil {
			return err
		}
		noRetry := common.NoRetryPolicy()
		response, err := iam.CreatePolicy(ociclient.RequestContext(ctx), identity.CreatePolicyRequest{CreatePolicyDetails: policy.Request, OpcRetryToken: new(policy.RetryToken), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
		if err != nil {
			return err
		}
		if response.Id == nil || !validAuxiliaryID("controller_usage_policy", *response.Id, "") {
			return errors.New("home writer policy create returned no exact identity")
		}
		found = *response.Id
	}
	if err := actor.verifyPolicy(ctx, SourcePolicyRecord{Request: policy.Request, PolicyID: found}); err != nil {
		return err
	}
	record, etag, err = resolver.Store.Load(ctx, cell)
	if err != nil {
		return err
	}
	if record.FoundationWriter == nil || record.FoundationWriter.InstanceID != receipt.instance || record.FoundationWriter.Policy == nil || record.FoundationWriter.Policy.RequestDigest != policy.RequestDigest {
		return ErrFoundationFenced
	}
	policy.PolicyID, policy.VerifiedAt = found, time.Now().UTC()
	pending.Policy = &policy
	record.FoundationWriter = &pending
	record.UpdatedAt = time.Now().UTC()
	if err := guard(ctx); err != nil {
		return err
	}
	if _, err := resolver.Store.CompareAndSwap(ctx, record, etag); err != nil {
		return err
	}
	if _, err := resolver.Resolve(ctx, cell); err != nil {
		return err
	}
	saved, _, err := resolver.Store.Load(ctx, cell)
	if err != nil {
		return err
	}
	if saved.FoundationWriter == nil || saved.FoundationWriter.Policy == nil || saved.FoundationWriter.Policy.PolicyID != found {
		return ErrFoundationFenced
	}
	return actor.verifyPolicy(ctx, SourcePolicyRecord{Request: policy.Request, PolicyID: found})
}

// VerifyFoundationWriter gates principal effects on sealed local identity and
// the independently read original launch and current exact IAM policy.
func (authority *HomeIAMAuthority) VerifyFoundationWriter(ctx context.Context) error {
	if err := authority.guardScope(ctx); err != nil {
		return err
	}
	entry, ok := catalog.CellForOCIRegion(authority.factory.Region())
	if !ok {
		return ErrFoundationFenced
	}
	record, _, err := authority.resolver.Store.Load(ctx, entry.Cell)
	if err != nil {
		return err
	}
	pending := record.FoundationWriter
	if pending == nil || pending.validate() != nil || pending.Cell != entry.Cell || pending.InstanceID != authority.instanceID || pending.InstallationID != authority.installationID || pending.Namespace != authority.domain.Namespace || pending.Bucket != authority.domain.HeadBucket || pending.KMSKeyID != authority.domain.HeadKMSKeyOCID || pending.BucketCompartment != authority.bucketCompartment || pending.Policy == nil || pending.Policy.PolicyID == "" || pending.Policy.VerifiedAt.IsZero() {
		return ErrFoundationFenced
	}
	home, err := authority.factory.HomeRegion(ctx, authority.tenancyID)
	if err != nil {
		return err
	}
	factory, err := authority.factory.ForRegion(home)
	if err != nil {
		return err
	}
	iam, err := factory.Identity()
	if err != nil {
		return err
	}
	return (&SourceFounder{iam: iam}).verifyPolicy(ctx, SourcePolicyRecord{Request: pending.Policy.Request, PolicyID: pending.Policy.PolicyID})
}

func (record FoundationWriterRecord) validate() error {
	digest, err := netBirdRequestDigest(record.Request)
	entry, ok := catalog.Lookup(record.Cell)
	if err != nil || !ok || !slices.Contains([]string{"GRU", "SFO", "FRA"}, record.Cell) || !entityid.Valid(record.InstallationID) || record.SlotID != BootstrapSlotID(record.InstallationID, record.Cell, "controller", record.Slot) || record.OperationID != BootstrapOperationID(record.InstallationID, record.SlotID) || record.InstanceID != "" && !strings.HasPrefix(record.InstanceID, "ocid1.instance.oc1."+entry.OCIRegion+".") || record.Generation == 0 || !sourceDigest(record.GrantSHA256) || !sourceDigest(record.ProfileSHA256) || !sourceDigest(record.RecipeSHA256) || !sourceDigest(record.ScopeSHA256) || !sourceDigest(record.PhysicalScopeSHA256) || record.BindingSHA256 != "" && !sourceDigest(record.BindingSHA256) || record.RequestDigest != digest || record.RetryToken != BootstrapRetryToken(record.OperationID, digest) || record.FirstAttemptAt.IsZero() || !bootstrapSlotName.MatchString(record.Slot) || !validAuxiliaryID("key", record.KMSKeyID, foundationHomeRegion) || !sourceStoragePattern.MatchString(record.Namespace) || !sourceStoragePattern.MatchString(record.Bucket) || !sourceCompartmentPattern.MatchString(record.BucketCompartment) || record.InstanceID != "" && !sourceInstancePattern.MatchString(record.InstanceID) || record.Request.CompartmentId == nil || !sourceCompartmentPattern.MatchString(*record.Request.CompartmentId) || len(record.Request.Metadata) != 0 || len(record.Request.ExtendedMetadata) != 0 {
		return errors.New("home writer original launch reservation is invalid")
	}
	if record.Policy == nil {
		return nil
	}
	expected, err := foundationWriterPolicy(record)
	if err != nil {
		return err
	}
	expectedWire, err := json.Marshal(expected, json.Deterministic(true))
	if err != nil {
		return err
	}
	actualWire, err := json.Marshal(record.Policy.Request, json.Deterministic(true))
	policy := record.Policy
	if err != nil || string(expectedWire) != string(actualWire) || policy.RequestDigest != digestSource(actualWire) || policy.RetryToken != digestSource([]byte(record.RequestDigest+"\x00"+record.InstanceID+"\x00"+policy.RequestDigest)) || policy.FirstAttemptAt.Before(record.FirstAttemptAt) || policy.PolicyID == "" && !policy.VerifiedAt.IsZero() || policy.PolicyID != "" && (!validAuxiliaryID("controller_usage_policy", policy.PolicyID, "") || policy.VerifiedAt.Before(policy.FirstAttemptAt)) {
		return errors.New("home writer IAM reservation differs from its canonical original policy")
	}
	return nil
}
