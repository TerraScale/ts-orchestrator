package region

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const homeIAMObject = "orchestrator/foundation/v1/iam-lease.json"

type homeIAMRecord struct {
	SchemaVersion   int       `json:"schemaVersion"`
	TenancyID       string    `json:"tenancyId"`
	InstallationID  string    `json:"installationId"`
	InstanceID      string    `json:"instanceId"`
	OperatorID      string    `json:"operatorId,omitempty"`
	GrantDigest     string    `json:"grantDigest"`
	GrantGeneration uint64    `json:"grantGeneration"`
	Generation      uint64    `json:"generation"`
	OwnerID         string    `json:"ownerId"`
	OperationID     string    `json:"operationId"`
	LeaseID         string    `json:"leaseId"`
	AcquiredAt      time.Time `json:"acquiredAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
	ReleasedAt      time.Time `json:"releasedAt,omitzero"`
}

// HomeIAMAuthority serializes every foundation and source IAM write through
// the same protected, conditional home object before NATS exists.
type HomeIAMAuthority struct {
	proof             bootstrapstart.VerifiedSourceFounder
	runtime           bootstrapstart.VerifiedRuntimeIAM
	instanceID        string
	operator          *foundationOperator
	tenancyID         string
	installationID    string
	grantDigest       string
	grantGeneration   uint64
	planDigest        string
	resolver          FoundationResolver
	factory           *ociclient.Factory
	objects           *objectstorage.ObjectStorageClient
	currentGenesis    trust.Keyring
	domain            bootstrap.StorageDomain
	ownerID           string
	bucketCompartment string
}

func NewHomeIAMAuthority(ctx context.Context, proof bootstrapstart.VerifiedSourceFounder, resolver FoundationResolver) (*HomeIAMAuthority, error) {
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return nil, err
	}
	return newHomeIAMAuthority(ctx, proof, resolver, nil, genesis)
}

func newHomeIAMAuthority(ctx context.Context, proof bootstrapstart.VerifiedSourceFounder, resolver FoundationResolver, objects *objectstorage.ObjectStorageClient, genesis trust.Keyring) (*HomeIAMAuthority, error) {
	authority := &HomeIAMAuthority{proof: proof, resolver: resolver, currentGenesis: genesis,
		instanceID: proof.InstanceID(), tenancyID: proof.TenancyID(), installationID: proof.InstallationID(),
		grantDigest: proof.GrantDigest(), grantGeneration: proof.Generation(), planDigest: proof.PlanDigest()}
	factory, guarded, err := proof.GuardedFactory(ctx)
	return authority.initialize(ctx, factory, guarded, objects, err)
}

// NewRuntimeHomeIAMAuthority admits an installed controller using its current
// signed selection and its own independently observed instance principal.
func NewRuntimeHomeIAMAuthority(ctx context.Context, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity, resolver FoundationResolver) (*HomeIAMAuthority, error) {
	proof, err := bootstrapstart.VerifyRuntimeIAM(ctx, reader, accepted)
	if err != nil {
		return nil, err
	}
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return nil, err
	}
	scope := proof.FoundationScope()
	authority := &HomeIAMAuthority{runtime: proof, resolver: resolver, currentGenesis: genesis,
		instanceID: proof.InstanceID(), tenancyID: scope.TenancyID, installationID: scope.InstallationID,
		grantDigest: scope.GrantSHA256, grantGeneration: scope.GrantGeneration}
	factory, guarded, err := proof.GuardedFactory(ctx)
	return authority.initialize(ctx, factory, guarded, nil, err)
}

func (authority *HomeIAMAuthority) initialize(ctx context.Context, factory *ociclient.Factory, guarded context.Context, objects *objectstorage.ObjectStorageClient, principalErr error) (*HomeIAMAuthority, error) {
	resolver := authority.resolver
	err := principalErr
	if err != nil || resolver.Footprint == nil || resolver.Store == nil {
		return nil, errors.Join(bootstrapstart.ErrSourceFounder, err)
	}
	entry, ok := catalog.CellForOCIRegion(factory.Region())
	if !ok {
		return nil, bootstrapstart.ErrSourceFounder
	}
	var domain bootstrap.StorageDomain
	if authority.operator != nil {
		domain = authority.operator.domain
	} else {
		grant, err := resolver.BootstrapMaterial(ctx, entry.Cell)
		if err != nil || !grant.IsVerified() || homeGrantDigest(grant.FoundationGrantWire()) != authority.grantDigest || grant.InstallationID() != authority.installationID || grant.Generation() != authority.grantGeneration {
			return nil, errors.Join(bootstrapstart.ErrSourceFounder, err)
		}
		domain = grant.StorageDomain()
		if authority.runtime.IsVerified() {
			if domain != authority.runtime.FoundationScope().StorageDomain {
				return nil, bootstrapstart.ErrSourceFounder
			}
			authority.planDigest = grant.PlanDigest()
		} else if !authority.proof.IsVerified() || grant.PlanDigest() != authority.planDigest {
			return nil, bootstrapstart.ErrSourceFounder
		}
	}
	parts := strings.Split(domain.HeadKMSKeyOCID, ".")
	if domain.Validate() != nil || len(parts) < 5 || !catalog.IsOCIRegion(parts[3]) {
		return nil, errors.New("home IAM requires the signed regional storage key")
	}
	storage, err := factory.ForRegion(parts[3])
	if err != nil {
		return nil, err
	}
	if objects == nil {
		client, err := storage.ObjectStorage()
		if err != nil {
			return nil, err
		}
		objects = &client
	}
	namespace, err := objects.GetNamespace(ociclient.RequestContext(guarded), objectstorage.GetNamespaceRequest{})
	if err != nil || namespace.Value == nil || *namespace.Value != domain.Namespace {
		return nil, errors.New("authenticated OCI namespace differs from signed home storage")
	}
	bucket, err := objects.GetBucket(ociclient.RequestContext(guarded), objectstorage.GetBucketRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket)})
	if err != nil || bucket.Name == nil || *bucket.Name != domain.HeadBucket || bucket.Namespace == nil || *bucket.Namespace != domain.Namespace ||
		bucket.KmsKeyId == nil || *bucket.KmsKeyId != domain.HeadKMSKeyOCID || bucket.CompartmentId == nil || !strings.HasPrefix(*bucket.CompartmentId, "ocid1.compartment.oc1..") || bucket.Id == nil || !validAuxiliaryID("head_bucket", *bucket.Id, parts[3]) {
		return nil, errors.New("actual home bucket differs from signed encrypted storage")
	}
	authority.factory, authority.objects, authority.domain = factory, objects, domain
	authority.ownerID, authority.bucketCompartment = entityid.New(), *bucket.CompartmentId
	if err := authority.guardScope(ctx); err != nil {
		return nil, err
	}
	return authority, nil
}

func (authority *HomeIAMAuthority) guardScope(ctx context.Context) error {
	if authority == nil || authority.objects == nil || authority.resolver.Footprint == nil || authority.resolver.Store == nil {
		return bootstrapstart.ErrSourceFounder
	}
	if authority.operator != nil {
		return authority.operator.guard(ctx)
	}
	if authority.proof.IsVerified() {
		if err := authority.proof.VerifyCurrent(ctx); err != nil {
			return err
		}
	} else if err := authority.runtime.VerifyCurrent(ctx); err != nil {
		return err
	}
	entry, ok := catalog.CellForOCIRegion(authority.factory.Region())
	if !ok {
		return bootstrapstart.ErrSourceFounder
	}
	// The production constructor pins the independent embedded genesis. Every
	// guard rereads the full remote lineage and the durable anti-rollback floor.
	current, err := discoverCurrentFoundation(ctx, authority.objects, authority.tenancyID, authority.currentGenesis)
	if err != nil {
		return err
	}
	grant, err := current.BootstrapMaterial(ctx, entry.Cell)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(grant.FoundationGrantWire())
	if !grant.IsVerified() || hex.EncodeToString(digest[:]) != authority.grantDigest || grant.Generation() != authority.grantGeneration ||
		grant.InstallationID() != authority.installationID || grant.PlanDigest() != authority.planDigest || grant.StorageDomain() != authority.domain {
		return errors.New("source founder differs from the current signed foundation grant")
	}
	return nil
}

type homeIAMLeaseKey struct{}

// The founder proof is pre-NATS authority; regional records independently fence
// caller epochs. A grant generation is never treated as a leadership epoch.
func (authority *HomeIAMAuthority) Guard(ctx context.Context, _ uint64) error {
	if err := authority.guardScope(ctx); err != nil {
		if lease, ok := ctx.Value(homeIAMLeaseKey{}).(*homeIAMLease); ok && lease.authority == authority {
			lease.cancel(err)
		}
		return err
	}
	if lease, ok := ctx.Value(homeIAMLeaseKey{}).(*homeIAMLease); ok {
		if lease.authority != authority {
			return ErrFoundationFenced
		}
		err := lease.check(ctx)
		if err != nil {
			lease.cancel(err)
		}
		return err
	}
	return nil
}

func (authority *HomeIAMAuthority) HomeWrite(ctx context.Context, epoch uint64) (context.Context, func(), error) {
	if err := authority.Guard(ctx, epoch); err != nil {
		return ctx, nil, err
	}
	previous, etag, err := authority.load(ctx)
	if err != nil && !errors.Is(err, ErrFoundationMissing) {
		return ctx, nil, err
	}
	now := time.Now().UTC()
	if err == nil && previous.ReleasedAt.IsZero() && now.Before(previous.ExpiresAt) {
		return ctx, nil, ErrFoundationBusy
	}
	if previous.Generation == math.MaxUint64 {
		return ctx, nil, errors.New("home IAM lease generation exhausted")
	}
	record := homeIAMRecord{SchemaVersion: 1, TenancyID: authority.tenancyID, InstallationID: authority.installationID,
		InstanceID: authority.instanceID, GrantDigest: authority.grantDigest, GrantGeneration: authority.grantGeneration,
		Generation: previous.Generation + 1, OwnerID: authority.ownerID, OperationID: entityid.New(), LeaseID: entityid.New(),
		AcquiredAt: now, UpdatedAt: now, ExpiresAt: now.Add(foundationLease)}
	if authority.operator != nil {
		record.OperatorID = authority.operator.id
	}
	etag, err = authority.put(ctx, record, etag)
	if err != nil {
		// A lost conditional response can only recover this exact owner tuple.
		recovered, recoveredETag, readErr := authority.load(ctx)
		if readErr != nil || recovered != record || !time.Now().Before(recovered.ExpiresAt) || authority.guardScope(ctx) != nil {
			return ctx, nil, err
		}
		etag = recoveredETag
	}
	child, cancel := context.WithCancelCause(ctx)
	lease := &homeIAMLease{authority: authority, record: record, etag: etag, cancel: cancel, stop: make(chan struct{}), done: make(chan struct{})}
	child = context.WithValue(child, homeIAMLeaseKey{}, lease)
	guarded := ociclient.WithAuthority(child, func(ctx context.Context) error { return authority.Guard(ctx, epoch) })
	go lease.renew(guarded)
	return guarded, func() { lease.release(ctx, child) }, nil
}

func (authority *HomeIAMAuthority) load(ctx context.Context) (homeIAMRecord, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := authority.objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{
		NamespaceName: new(authority.domain.Namespace), BucketName: new(authority.domain.HeadBucket), ObjectName: new(homeIAMObject)})
	if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == 404 {
		return homeIAMRecord{}, "", ErrFoundationMissing
	}
	if err != nil {
		return homeIAMRecord{}, "", err
	}
	if response.Content == nil || response.ETag == nil || *response.ETag == "" {
		if response.Content != nil {
			response.Content.Close()
		}
		return homeIAMRecord{}, "", errors.New("home IAM lease omitted its conditional identity")
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, (16<<10)+1))
	var record homeIAMRecord
	if err != nil || len(wire) > 16<<10 || json.Unmarshal(wire, &record, json.RejectUnknownMembers(true)) != nil || authority.validate(record) != nil {
		return homeIAMRecord{}, "", errors.New("home IAM lease has invalid authenticated scope or schema")
	}
	return record, *response.ETag, nil
}

func (authority *HomeIAMAuthority) validate(record homeIAMRecord) error {
	digest, err := hex.DecodeString(record.GrantDigest)
	principalValid := strings.HasPrefix(record.InstanceID, "ocid1.instance.oc1.") && len(record.InstanceID) <= 512 && record.OperatorID == "" ||
		record.InstanceID == "" && strings.HasPrefix(record.OperatorID, "ocid1.user.oc1..") && len(record.OperatorID) <= 512
	if record.SchemaVersion != 1 || record.TenancyID != authority.tenancyID || record.InstallationID != authority.installationID ||
		!principalValid || err != nil || len(digest) != 32 ||
		record.Generation == 0 || record.GrantGeneration == 0 || !entityid.Valid(record.OwnerID) || !entityid.Valid(record.OperationID) || !entityid.Valid(record.LeaseID) ||
		record.AcquiredAt.IsZero() || record.UpdatedAt.Before(record.AcquiredAt) || record.ExpiresAt.Before(record.UpdatedAt) || record.ExpiresAt.After(record.UpdatedAt.Add(foundationLease)) ||
		!record.ReleasedAt.IsZero() && (record.ReleasedAt.Before(record.AcquiredAt) || record.ReleasedAt.After(record.UpdatedAt)) {
		return errors.New("home IAM lease is invalid")
	}
	return nil
}

func (authority *HomeIAMAuthority) put(ctx context.Context, record homeIAMRecord, etag string) (string, error) {
	if err := authority.validate(record); err != nil {
		return "", err
	}
	wire, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ociclient.WithAuthority(ctx, authority.guardScope), 10*time.Second)
	defer cancel()
	policy := common.NoRetryPolicy()
	request := objectstorage.PutObjectRequest{NamespaceName: new(authority.domain.Namespace), BucketName: new(authority.domain.HeadBucket), ObjectName: new(homeIAMObject),
		ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire)), ContentType: new("application/json"),
		OpcSseKmsKeyId: new(authority.domain.HeadKMSKeyOCID), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}}
	if etag == "" {
		request.IfNoneMatch = new("*")
	} else {
		request.IfMatch = new(etag)
	}
	response, err := authority.objects.PutObject(ociclient.RequestContext(ctx), request)
	if service, ok := common.IsServiceError(err); ok && (service.GetHTTPStatusCode() == 409 || service.GetHTTPStatusCode() == 412) {
		return "", ErrFoundationConflict
	}
	if err != nil {
		return "", err
	}
	if response.ETag == nil || *response.ETag == "" {
		return "", errors.New("home IAM lease write omitted its ETag")
	}
	return *response.ETag, nil
}

type homeIAMLease struct {
	authority *HomeIAMAuthority
	mu        sync.Mutex
	record    homeIAMRecord
	etag      string
	cancel    context.CancelCauseFunc
	stop      chan struct{}
	done      chan struct{}
	once      sync.Once
}

func sameHomeIAMOwner(a, b homeIAMRecord) bool {
	return a.Generation == b.Generation && a.OwnerID == b.OwnerID && a.OperationID == b.OperationID && a.LeaseID == b.LeaseID &&
		a.InstanceID == b.InstanceID && a.OperatorID == b.OperatorID && a.GrantDigest == b.GrantDigest && a.GrantGeneration == b.GrantGeneration &&
		a.TenancyID == b.TenancyID && a.InstallationID == b.InstallationID && a.AcquiredAt.Equal(b.AcquiredAt)
}

func (lease *homeIAMLease) check(ctx context.Context) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	current, _, err := lease.authority.load(ctx)
	if err != nil {
		return err
	}
	if !sameHomeIAMOwner(current, lease.record) || !current.ReleasedAt.IsZero() || !time.Now().Before(current.ExpiresAt) {
		return ErrFoundationFenced
	}
	return nil
}

func (lease *homeIAMLease) renew(ctx context.Context) {
	defer close(lease.done)
	ticker := time.NewTicker(foundationLease / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-lease.stop:
			return
		case <-ticker.C:
			if err := lease.renewOnce(ctx); err != nil {
				lease.cancel(err)
				return
			}
		}
	}
}

func (lease *homeIAMLease) renewOnce(ctx context.Context) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	current, etag, err := lease.authority.load(ctx)
	if err != nil {
		return err
	}
	if !sameHomeIAMOwner(current, lease.record) || !current.ReleasedAt.IsZero() || !time.Now().Before(current.ExpiresAt) {
		return ErrFoundationFenced
	}
	current.UpdatedAt = time.Now().UTC()
	current.ExpiresAt = current.UpdatedAt.Add(foundationLease)
	etag, err = lease.authority.put(ctx, current, etag)
	if err == nil {
		lease.record, lease.etag = current, etag
	}
	return err
}

func (lease *homeIAMLease) release(parent, child context.Context) {
	lease.once.Do(func() {
		close(lease.stop)
		<-lease.done
		defer lease.cancel(context.Canceled)
		if parent.Err() != nil || child.Err() != nil {
			return
		}
		lease.mu.Lock()
		defer lease.mu.Unlock()
		current, etag, err := lease.authority.load(parent)
		if err != nil || !sameHomeIAMOwner(current, lease.record) || !current.ReleasedAt.IsZero() || !time.Now().Before(current.ExpiresAt) {
			return
		}
		current.UpdatedAt = time.Now().UTC()
		current.ReleasedAt, current.ExpiresAt = current.UpdatedAt, current.UpdatedAt
		_, _ = lease.authority.put(parent, current, etag)
	})
}

func homeGrantDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

// GuardedFactory preserves the exact authenticated founder and checks the
// current protected home claim before every SDK mutation attempt.
func (authority *HomeIAMAuthority) GuardedFactory(ctx context.Context) (*ociclient.Factory, context.Context, error) {
	if err := authority.Guard(ctx, 0); err != nil {
		return nil, ctx, err
	}
	return authority.factory, ociclient.WithAuthority(ctx, func(ctx context.Context) error { return authority.Guard(ctx, 0) }), nil
}

func (authority *HomeIAMAuthority) StorageDomain() bootstrap.StorageDomain {
	if authority == nil {
		return bootstrap.StorageDomain{}
	}
	return authority.domain
}
