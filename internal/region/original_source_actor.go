package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var ErrOriginalSourceActorHold = errors.New("original source actor current signed, protected and physical proof is unavailable; HOLD")

// OriginalSourceActorScope identifies original archive custody only. Its values
// confer neither accepted startup identity nor ordinary foundation authority.
type OriginalSourceActorScope struct {
	SHA256               string
	InstanceID           string
	Cell                 string
	InstallationID       string
	Generation           uint64
	GrantSHA256          string
	BundleSHA256         string
	BirthSHA256          string
	ActorRequestSHA256   string
	ActorReadbackSHA256  string
	SourceIAMSHA256      string
	AdmissionReadsSHA256 string
	PublicationSHA256    string
	PlanSHA256           string
	TemplateSHA256       string
	Deadline             time.Time
}

// VerifiedOriginalSourceActor can only be opened from this machine's fixed
// production observations. The zero value grants no source custody.
type VerifiedOriginalSourceActor struct{ proof *originalSourceActorProof }

type originalSourceActorProof struct {
	factory     *ociclient.Factory
	scope       OriginalSourceActorScope
	config      bootstrapmaterial.Config
	intent      OriginalSourceProducerIntent
	attestor    VerifiedAdmissionAttestor
	recordETag  string
	publicETags [2]string
}

func (v VerifiedOriginalSourceActor) IsVerified() bool {
	return v.proof != nil && v.proof.factory != nil && v.proof.scope.SHA256 != ""
}

func (v VerifiedOriginalSourceActor) Scope() OriginalSourceActorScope {
	if !v.IsVerified() {
		return OriginalSourceActorScope{}
	}
	return v.proof.scope
}

func (v VerifiedOriginalSourceActor) Config() bootstrapmaterial.Config {
	if !v.IsVerified() {
		return bootstrapmaterial.Config{}
	}
	config := v.proof.config
	config.Slots = slices.Clone(config.Slots)
	return config
}

func (v VerifiedOriginalSourceActor) OriginalIntent() OriginalSourceProducerIntent {
	if !v.IsVerified() {
		return OriginalSourceProducerIntent{}
	}
	intent := v.proof.intent
	intent.Profile.NetworkSecurityGroupOCIDs = slices.Clone(intent.Profile.NetworkSecurityGroupOCIDs)
	return intent
}

func (v VerifiedOriginalSourceActor) Guard(ctx context.Context) error {
	if !v.IsVerified() || !time.Now().Before(v.proof.scope.Deadline) {
		return ErrOriginalSourceActorHold
	}
	current, err := OpenOriginalSourceActor(ociclient.CheckpointContext(ctx))
	if err != nil || !current.IsVerified() || current.proof.scope != v.proof.scope || current.proof.recordETag != v.proof.recordETag || current.proof.publicETags != v.proof.publicETags {
		return errors.Join(ErrOriginalSourceActorHold, err)
	}
	return ctx.Err()
}

// GuardedFactory adds no authority to the factory itself. Consumers must retain
// the returned context and use only their private, exact signed request scope.
func (v VerifiedOriginalSourceActor) GuardedFactory(ctx context.Context) (*ociclient.Factory, context.Context, error) {
	if err := v.Guard(ctx); err != nil {
		return nil, nil, err
	}
	guard := func(sendCtx context.Context) error {
		if err := v.Guard(sendCtx); err != nil {
			return err
		}
		return ociclient.LimitAdmission(sendCtx, v.proof.scope.Deadline)
	}
	return v.proof.factory, ociclient.WithAuthority(ctx, guard), nil
}

func (v VerifiedOriginalSourceActor) AdmissionAttestor(ctx context.Context) (release.AdmissionAttestorAuthorization, error) {
	if err := v.Guard(ctx); err != nil {
		return release.AdmissionAttestorAuthorization{}, err
	}
	if err := v.proof.attestor.Revalidate(ctx); err != nil {
		return release.AdmissionAttestorAuthorization{}, err
	}
	return v.proof.attestor.Authorization(), nil
}

// OpenOriginalSourceActor accepts no caller-selected roots, principal, location
// or proof. Original public delivery remains a locator, never startup authority.
func OpenOriginalSourceActor(ctx context.Context) (VerifiedOriginalSourceActor, error) {
	imds := bootstrapstart.NewIMDSClient()
	digest, err := imds.FetchOriginalBundleSHA256(ctx)
	if err != nil || !validFoundationDigest(digest) {
		return VerifiedOriginalSourceActor{}, errors.Join(ErrOriginalSourceActorHold, err)
	}
	instance, err := imds.FetchInstanceID(ctx)
	if err != nil {
		return VerifiedOriginalSourceActor{}, errors.Join(ErrOriginalSourceActorHold, err)
	}
	parts := strings.Split(instance, ".")
	if len(parts) != 5 {
		return VerifiedOriginalSourceActor{}, ErrOriginalSourceActorHold
	}
	entry, ok := catalog.CellForOCIRegion(parts[3])
	if !ok {
		return VerifiedOriginalSourceActor{}, ErrOriginalSourceActorHold
	}
	factory, err := ociclient.InstancePrincipalContext(ctx, entry.OCIRegion)
	if err != nil {
		return VerifiedOriginalSourceActor{}, errors.Join(ErrOriginalSourceActorHold, err)
	}
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return VerifiedOriginalSourceActor{}, errors.Join(ErrOriginalSourceActorHold, err)
	}
	return readOriginalSourceActor(ctx, factory, instance, entry.Cell, digest, genesis)
}

func readOriginalSourceActor(ctx context.Context, factory *ociclient.Factory, instance, cell, digest string, genesis trust.Keyring) (VerifiedOriginalSourceActor, error) {
	deny := func(err error) (VerifiedOriginalSourceActor, error) {
		return VerifiedOriginalSourceActor{}, errors.Join(ErrOriginalSourceActorHold, err)
	}
	wire, err := readOriginalFoundationPublic(ctx, factory, instance, cell, digest, genesis)
	if err != nil {
		return deny(err)
	}
	var original RetainedFoundation
	if err := json.Unmarshal(wire, &original, json.RejectUnknownMembers(true)); err != nil {
		return deny(err)
	}
	objects, tenancy, err := foundationHomeClient(factory)
	if err != nil || tenancy != original.TenancyID {
		return deny(err)
	}
	// The delivered anchor selects the signed prefix only after independent
	// verification. Both current public documents are reread from OCI below.
	verified, err := verifyRetainedFoundation(ctx, original, genesis)
	if err != nil {
		return deny(err)
	}
	locator, ok := verified.Footprint.(*SignedFootprint)
	if !ok {
		return deny(nil)
	}
	current := original.clone()
	var etags [2]string
	for index, name := range [2]string{foundationRootChainObject, strings.TrimSuffix(locator.storage.Prefix, "/") + "/" + foundationGrantObject} {
		limit := int64(trust.MaxRootChainBytes)
		if index == 1 {
			limit = foundationRecordLimit
		}
		observed, etag, err := readOriginalSourceDocument(ctx, objects, original.Namespace, name, limit)
		if err != nil {
			return deny(err)
		}
		etags[index] = etag
		if index == 0 {
			current.RootChainWire = observed
		} else {
			current.GrantWire = observed
		}
	}
	if !bytes.Equal(current.RootChainWire, original.RootChainWire) || !bytes.Equal(current.GrantWire, original.GrantWire) {
		return deny(nil)
	}
	resolved, _, err := resolveCurrentFoundation(ctx, objects, tenancy, genesis, &current)
	if err != nil {
		return deny(err)
	}
	reader, ok := resolved.Footprint.(*SignedFootprint)
	if !ok {
		return deny(nil)
	}
	// Fresh public bytes were verified above. Subsequent typed attestor reads
	// must continue through the actual authenticated object client.
	reader.retainedGrant, reader.factory = nil, factory
	grant, expires, err := reader.verifyOriginalDocument(current.GrantWire)
	if err != nil {
		return deny(err)
	}
	store, err := NewObjectFoundationStore(objects, original.Namespace, foundationDiscoveryBucket)
	if err != nil {
		return deny(err)
	}
	record, recordETag, err := store.Load(ctx, "GRU")
	if err != nil {
		return deny(err)
	}
	index := slices.Index([]string{"GRU", "SFO", "FRA"}, cell)
	if index < 0 {
		return deny(nil)
	}
	if err := verifyOriginalSourceActorRecord(reader, grant, record, original, etags); err != nil {
		return deny(err)
	}
	regional := record.OriginalFoundationCompartments.Regions[index]
	actor, birth := regional.Actor, (*record.OriginalSourceProducers)[index]
	if originalActorID(actor) != instance || factory.Region() != regional.OCIRegion {
		return deny(nil)
	}
	bucket, err := objects.GetBucket(ociclient.RequestContext(ctx), objectstorage.GetBucketRequest{NamespaceName: new(birth.Intent.Home.Namespace), BucketName: new(birth.Intent.Home.HeadBucket)})
	if err != nil || deref(bucket.Id) != birth.HeadBucketID || deref(bucket.Name) != birth.Intent.Home.HeadBucket || deref(bucket.Namespace) != birth.Intent.Home.Namespace || deref(bucket.KmsKeyId) != birth.Intent.Home.HeadKMSKeyOCID || deref(bucket.CompartmentId) != regional.SourceIAM.BucketCompartment {
		return deny(err)
	}
	if err := verifyOriginalSourceActorPolicy(ctx, factory, *regional.SourceIAM); err != nil {
		return deny(err)
	}
	boot, vnic, err := readOriginalActor(ctx, factory, regional, actor)
	if err != nil || boot != actor.BootVolumeID || vnic != actor.PrimaryVNICID {
		return deny(err)
	}
	readback, err := originalActorReadback(actor, boot, vnic)
	if err != nil || readback != actor.ReadbackSHA256 {
		return deny(err)
	}
	image, err := verifyOriginalSourceActorImage(ctx, factory, reader, regional, birth.Intent)
	if err != nil {
		return deny(err)
	}
	if _, err := bootstrapstart.VerifyCurrentRunningBinary(image); err != nil {
		return deny(err)
	}
	attestor, err := reader.AdmissionAttestor(ctx, cell)
	if err != nil || !attestor.IsVerified() || !bytes.Equal(attestor.wire, current.GrantWire) {
		return deny(err)
	}
	material, err := originalActorMaterial(grant, cell)
	if err != nil {
		return deny(err)
	}
	deadline := originalActorDeadline(expires, reader.expires, image.ExpiresAt(), birth.Intent.LaunchDeadline)
	if !time.Now().Before(deadline) {
		return deny(nil)
	}
	scope, err := originalSourceActorScope(record, index, instance, deadline)
	if err != nil {
		return deny(err)
	}
	if err := ctx.Err(); err != nil {
		return deny(err)
	}
	config := material.Config
	config.Slots = slices.Clone(config.Slots)
	intent := birth.Intent
	intent.Profile.NetworkSecurityGroupOCIDs = slices.Clone(intent.Profile.NetworkSecurityGroupOCIDs)
	return VerifiedOriginalSourceActor{proof: &originalSourceActorProof{factory: factory, scope: scope, config: config, intent: intent, attestor: attestor, recordETag: recordETag, publicETags: etags}}, nil
}

func readOriginalSourceDocument(ctx context.Context, objects FoundationObjects, namespace, name string, limit int64) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(namespace), BucketName: new(foundationDiscoveryBucket), ObjectName: new(name)})
	if err != nil {
		return nil, "", err
	}
	if response.Content == nil {
		return nil, "", ErrOriginalSourceActorHold
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, limit+1))
	if err != nil || int64(len(wire)) > limit || !originalPublicationETag(deref(response.ETag)) {
		return nil, "", errors.Join(ErrOriginalSourceActorHold, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	return wire, *response.ETag, nil
}

func verifyOriginalSourceActorRecord(reader *SignedFootprint, grant FoundationGrant, record FoundationRecord, bundle RetainedFoundation, publicETags [2]string) error {
	if reader == nil || grant.SchemaVersion != 3 || grant.Generation != 1 || grant.OriginalActorAdmissionReads == nil || grant.OriginalPublication == nil || record.validate() != nil || completeOriginalFoundationAdmissionReads(record) != nil || record.validateOriginalFoundationPublication() != nil {
		return ErrOriginalSourceActorHold
	}
	root := record.OriginalFoundationCompartments
	if root == nil || root.Publication == nil || root.Publication.Readbacks == nil || root.GrantSHA256 != digestSource(bundle.GrantWire) {
		return ErrOriginalSourceActorHold
	}
	bundleWire, err := json.Marshal(bundle, json.Deterministic(true))
	if err != nil || root.BundleSHA256 != digestSource(bundleWire) || record.TenancyID != grant.TenancyID || record.ParentCompartmentID != grant.ParentCompartmentID || record.SharedCompartmentID != grant.SharedCompartmentID || root.UserID != (*record.OriginalSourceProducers)[0].Intent.OriginalUserID || root.Currency != grant.Currency || root.MonthlyLimitMinor != grant.MonthlyLimitMinor || root.CleanupOwner != grant.CleanupOwner {
		return errors.Join(ErrOriginalSourceActorHold, err)
	}
	if requireOriginalSourceProducerPurposes(grant) != nil || validateOriginalAdmissionReadIntents(grant, reader.storage) != nil || validateOriginalFoundationPublicationIntent(grant, reader.storage) != nil || ValidatePreparedFoundation(grant) != nil {
		return ErrOriginalSourceActorHold
	}
	for index, regional := range root.Regions {
		material, err := originalActorMaterial(grant, regional.Cell)
		if err != nil || material.OriginalSourceProducer == nil || !sameOriginalSourceValue(material.OriginalSourceProducer, (*record.OriginalSourceProducers)[index].Intent) {
			return errors.Join(ErrOriginalSourceActorHold, err)
		}
		var signed *FoundationIntent
		for i := range grant.Regions {
			if grant.Regions[i].Plan["cell"] == regional.Cell {
				signed = &grant.Regions[i]
			}
		}
		if signed == nil {
			return ErrOriginalSourceActorHold
		}
		digest, err := FoundationIntentDigest(*signed)
		if err != nil || digest != regional.IntentSHA256 {
			return errors.Join(ErrOriginalSourceActorHold, err)
		}
		expectedActor, err := originalActorScope(record, index, *material.Startup, material.Config)
		if err != nil || !sameOriginalSourceValue(regional.Actor.scopeOnly(), expectedActor) {
			return errors.Join(ErrOriginalSourceActorHold, err)
		}
		expectedReads, err := originalAdmissionReadScope(record, index, (*grant.OriginalActorAdmissionReads)[index])
		if err != nil || !sameOriginalSourceValue(regional.AdmissionReads.scopeOnly(), expectedReads) {
			return errors.Join(ErrOriginalSourceActorHold, err)
		}
	}
	expected, err := originalPublicationScope(record, *grant.OriginalPublication, digestSource(bundle.RootChainWire))
	if err != nil || !sameOriginalSourceValue(root.Publication.scopeOnly(), expected) {
		return errors.Join(ErrOriginalSourceActorHold, err)
	}
	for index, proof := range *root.Publication.Readbacks {
		if proof.ETag != publicETags[index] || proof.ContentSHA256 != [2]string{digestSource(bundle.RootChainWire), digestSource(bundle.GrantWire)}[index] {
			return ErrOriginalSourceActorHold
		}
	}
	return nil
}

func verifyOriginalSourceActorPolicy(ctx context.Context, factory *ociclient.Factory, entry OriginalFoundationSourceIAM) error {
	home, err := factory.ForRegion(foundationHomeRegion)
	if err != nil {
		return err
	}
	iam, err := home.Identity()
	if err != nil {
		return err
	}
	if entry.Provenance == nil {
		return ErrOriginalSourceActorHold
	}
	response, err := iam.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(entry.Provenance.ResourceID)})
	if err != nil {
		return err
	}
	if deref(response.Id) != entry.Provenance.ResourceID || deref(response.CompartmentId) != deref(entry.Request.CompartmentId) || deref(response.Name) != deref(entry.Request.Name) || deref(response.Description) != deref(entry.Request.Description) || response.LifecycleState != identity.PolicyLifecycleStateActive || !slices.Equal(response.Statements, entry.Request.Statements) || !sameOriginalSourceValue(response.VersionDate, entry.Request.VersionDate) || !sameOriginalSourceValue(response.FreeformTags, entry.Request.FreeformTags) || !sameOriginalSourceValue(response.DefinedTags, entry.Request.DefinedTags) {
		return ErrOriginalSourceActorHold
	}
	return ctx.Err()
}

func verifyOriginalSourceActorImage(ctx context.Context, factory *ociclient.Factory, reader *SignedFootprint, regional OriginalFoundationCompartmentRegion, intent OriginalSourceProducerIntent) (release.VerifiedImage, error) {
	startup := regional.Actor.Startup
	expected := release.ImageExpectation{Environment: intent.Environment, LogicalRegion: regional.Cell, OCIImageOCID: startup.ImageOCID, Architecture: strings.TrimPrefix(startup.ImageArchitecture, "linux-")}
	image, err := release.VerifyImageCurrent(startup.ReleaseImageReceiptWire, startup.ReleaseDelegationWire, reader.roots, expected, time.Now())
	if err != nil {
		return release.VerifiedImage{}, err
	}
	compute, err := factory.Compute()
	if err != nil {
		return release.VerifiedImage{}, err
	}
	response, err := compute.GetImage(ociclient.RequestContext(ctx), core.GetImageRequest{ImageId: new(startup.ImageOCID)})
	compartment, scopeErr := originalActorImageCompartment(regional.Cell, originalActorResources(startup).ImageCompartmentOCID, regional.Actor.ControlCompartmentID)
	if err != nil || scopeErr != nil || deref(response.Id) != startup.ImageOCID || deref(response.CompartmentId) != compartment || response.LifecycleState != core.ImageLifecycleStateAvailable {
		return release.VerifiedImage{}, errors.Join(ErrOriginalSourceActorHold, err, scopeErr)
	}
	return image, ctx.Err()
}

func originalSourceActorScope(record FoundationRecord, index int, instance string, deadline time.Time) (OriginalSourceActorScope, error) {
	root := record.OriginalFoundationCompartments
	regional, birth := root.Regions[index], (*record.OriginalSourceProducers)[index]
	digest := func(value any) (string, error) {
		wire, err := json.Marshal(value, json.Deterministic(true))
		return digestSource(wire), err
	}
	scope := OriginalSourceActorScope{InstanceID: instance, Cell: regional.Cell, InstallationID: birth.Intent.InstallationID, Generation: birth.Intent.Generation, GrantSHA256: root.GrantSHA256, BundleSHA256: root.BundleSHA256, ActorRequestSHA256: regional.Actor.Pending.Request.RequestDigest, ActorReadbackSHA256: regional.Actor.ReadbackSHA256, PlanSHA256: birth.Intent.PlanSHA256, Deadline: deadline}
	var err error
	if scope.BirthSHA256, err = digest(birth); err != nil {
		return OriginalSourceActorScope{}, err
	}
	if scope.SourceIAMSHA256, err = digest(regional.SourceIAM); err != nil {
		return OriginalSourceActorScope{}, err
	}
	if scope.AdmissionReadsSHA256, err = digest(regional.AdmissionReads); err != nil {
		return OriginalSourceActorScope{}, err
	}
	if scope.PublicationSHA256, err = digest(root.Publication); err != nil {
		return OriginalSourceActorScope{}, err
	}
	if scope.TemplateSHA256, err = digest(regional.Actor.Startup); err != nil {
		return OriginalSourceActorScope{}, err
	}
	scope.SHA256, err = digest(scope)
	return scope, err
}
