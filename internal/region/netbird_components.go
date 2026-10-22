package region

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/registry/pullauth"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var errNetBirdComponents = errors.New("dedicated NetBird component material is absent, changed or expired")

func netBirdComponentRoles() [3]string {
	return [3]string{"netbird-server", "netbird-dashboard", "netbird-ingress"}
}

// NetBirdComponent contains public release and CURRENT credential metadata.
// It grants no native task, persistent store or process ownership.
type NetBirdComponent struct {
	role      string
	release   release.VerifiedContainer
	pull      pullauth.PullClaim
	authority VerifiedContainerReleaseAuthority
	issuer    VerifiedOCIRIssuer
}

func (v NetBirdComponent) Role() string                       { return v.role }
func (v NetBirdComponent) Release() release.VerifiedContainer { return v.release }
func (v NetBirdComponent) PullClaim() pullauth.PullClaim      { return v.pull }

// NetBirdComponents is a finite complete snapshot, never a retained release
// floor. A future native owner must separately enforce ordering and OS custody.
type NetBirdComponents struct{ state *netBirdComponents }

type netBirdComponents struct {
	factory    *ociclient.Factory
	resolver   FoundationResolver
	reader     *SignedFootprint
	manager    VerifiedNetBirdManager
	intent     verifiedNetBirdIntent
	original   bool
	expires    time.Time
	components [3]NetBirdComponent
}

func (v NetBirdComponents) ExpiresAt() time.Time {
	if v.state == nil {
		return time.Time{}
	}
	return v.state.expires
}

// Component rechecks the whole mandatory set; a partial set never authorizes
// even one role. Resolve must reread CURRENT again for the actual future pull.
func (v NetBirdComponents) Component(ctx context.Context, role string) (NetBirdComponent, error) {
	if err := v.Check(ctx); err != nil {
		return NetBirdComponent{}, err
	}
	for _, component := range v.state.components {
		if component.role == role {
			return component, nil
		}
	}
	return NetBirdComponent{}, errNetBirdComponents
}

func (v NetBirdComponents) Check(ctx context.Context) error {
	if v.state == nil || ctx == nil {
		return errNetBirdComponents
	}
	s := v.state
	ctx, cancel := context.WithDeadline(ctx, s.expires)
	defer cancel()
	// One check verifies the original foundation once for all of its requests.
	ctx = withOriginalNetBirdStateMemo(ctx)
	if err := s.guard(ctx); err != nil {
		return err
	}
	location, err := s.location()
	if err != nil {
		return err
	}
	for i, role := range netBirdComponentRoles() {
		component := s.components[i]
		if component.role != role || !component.release.Valid(time.Now()) {
			return errNetBirdComponents
		}
		guarded := s.requestContext(ctx, &component.issuer)
		if err := s.checkAuthority(guarded, component.authority, role); err != nil {
			return err
		}
		bundle, found, err := releasechannel.ReadContainerBundle(guarded, location, role, "arm64")
		if err != nil || !found {
			return errors.Join(errNetBirdComponents, err)
		}
		digest, err := release.ContainerBundleSHA256(bundle)
		if err != nil || digest != component.release.BundleSHA256() {
			return errors.Join(errNetBirdComponents, err)
		}
		pulls, err := pullauth.NewPullSecrets(s.factory)
		if err != nil {
			return err
		}
		current, err := pulls.Describe(guarded, component.pull.Scope, component.pull.Secret, component.pull.Generation)
		if err != nil || current != component.pull {
			return errors.Join(errNetBirdComponents, err)
		}
	}
	return s.guard(ctx)
}

// ReadNetBirdComponents reads only genuine signed OCI material before NATS.
// It neither creates credentials nor consumes genesis or marks a store ready.
func ReadNetBirdComponents(ctx context.Context, factory *ociclient.Factory, resolver FoundationResolver, manager VerifiedNetBirdManager) (NetBirdComponents, error) {
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if ctx == nil || factory == nil || !ok || reader == nil || reader.factory != factory || factory.Region() != foundationHomeRegion || reader.scope.Cell != "GRU" || reader.scope.Environment != "production" {
		return NetBirdComponents{}, errNetBirdComponents
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// One read verifies the original foundation once for all of its requests.
	ctx = withOriginalNetBirdStateMemo(ctx)
	if err := manager.Check(ctx); err != nil {
		return NetBirdComponents{}, err
	}
	original, err := reader.originalNetBirdGrant(ctx)
	if err != nil {
		return NetBirdComponents{}, err
	}
	var intent verifiedNetBirdIntent
	if original {
		state, err := reader.originalNetBirdState(ctx, resolver)
		if err != nil {
			return NetBirdComponents{}, err
		}
		intent = state.intent
	} else {
		intent, err = reader.authorizedNetBirdManager(ctx)
		if err != nil {
			return NetBirdComponents{}, err
		}
	}
	deadline, _ := ctx.Deadline()
	s := &netBirdComponents{factory: factory, resolver: resolver, reader: reader, manager: manager, intent: intent, original: original, expires: deadline}
	s.capDeadline(intent.expires)
	if err := s.guard(ctx); err != nil {
		return NetBirdComponents{}, err
	}
	location, err := s.location()
	if err != nil {
		return NetBirdComponents{}, err
	}
	for i, role := range netBirdComponentRoles() {
		component, err := s.readComponent(ctx, location, role)
		if err != nil {
			return NetBirdComponents{}, err
		}
		s.components[i] = component
	}
	result := NetBirdComponents{state: s}
	if err := result.Check(ctx); err != nil {
		return NetBirdComponents{}, err
	}
	return result, nil
}

func (s *netBirdComponents) capDeadline(expires time.Time) {
	if expires.Before(s.expires) {
		s.expires = expires
	}
}

func (s *netBirdComponents) guard(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(s.expires) || s.reader.factory != s.factory || s.resolver.Footprint != s.reader {
		return errNetBirdComponents
	}
	tenancy, err := s.factory.Provider().TenancyOCID()
	if err != nil || tenancy != s.reader.tenancy {
		return errors.Join(errNetBirdComponents, err)
	}
	if s.original {
		ctx = withOriginalNetBirdStateMemo(ctx)
		state, err := s.reader.originalNetBirdState(ctx, s.resolver)
		if err != nil || state.intent.grantDigest != s.intent.grantDigest || state.intent.installationID != s.intent.installationID || state.intent.generation != s.intent.generation ||
			s.manager.originalGrantSHA256 != state.intent.grantDigest || s.manager.CredentialTarget() != state.target() || s.manager.VaultTarget() != state.regionalTarget() ||
			s.manager.StoreGeneration() != state.intent.intent.Material.Context.StoreGeneration {
			return errors.Join(errNetBirdComponents, err)
		}
		if err := s.manager.Check(ctx); err != nil {
			return err
		}
		if !time.Now().Before(s.expires) {
			return errNetBirdComponents
		}
		return ctx.Err()
	}
	intent, err := s.reader.authorizedNetBirdManager(ctx)
	if err != nil || intent.grantDigest != s.intent.grantDigest || intent.installationID != s.intent.installationID || intent.generation != s.intent.generation ||
		s.manager.StoreGeneration() != entityid.Derive("netbird-foundation-store", intent.installationID)+":1" {
		return errors.Join(errNetBirdComponents, err)
	}
	record, err := s.resolver.Resolve(ctx, "GRU")
	if err != nil || record.TenancyID != tenancy || record.OCIRegion != foundationHomeRegion {
		return errors.Join(errNetBirdComponents, err)
	}
	target, err := record.VaultTarget()
	if err != nil || target != s.manager.VaultTarget() {
		return errors.Join(errNetBirdComponents, err)
	}
	if err := s.manager.Check(ctx); err != nil {
		return err
	}
	if !time.Now().Before(s.expires) {
		return errNetBirdComponents
	}
	return ctx.Err()
}

func (s *netBirdComponents) requestContext(base context.Context, issuer *VerifiedOCIRIssuer) context.Context {
	return ociclient.WithRequestGuard(base, func(context.Context) error {
		// Revalidation uses the original context, avoiding recursive wire guards;
		// one request's guard verifies the original foundation once.
		scope := withOriginalNetBirdStateMemo(base)
		if err := s.guard(scope); err != nil {
			return err
		}
		if issuer != nil {
			var err error
			if s.original {
				err = GuardNetBirdOCIRIssuer(scope, s.factory, s.resolver, s.manager, *issuer)
			} else {
				err = s.resolver.GuardOCIRIssuer(base, *issuer)
			}
			if err != nil {
				return err
			}
		}
		if !time.Now().Before(s.expires) {
			return errNetBirdComponents
		}
		return base.Err()
	})
}

func (s *netBirdComponents) location() (releasechannel.Location, error) {
	bucket, err := releasechannel.BucketName("GRU")
	if err != nil {
		return releasechannel.Location{}, err
	}
	client, err := s.factory.ObjectStorage()
	return releasechannel.Location{Client: client, Namespace: s.reader.storage.Namespace, Bucket: bucket}, err
}

func (s *netBirdComponents) checkAuthority(ctx context.Context, expected VerifiedContainerReleaseAuthority, role string) error {
	current, err := s.componentAuthority(ctx, role)
	if err != nil || !current.IsVerified() || !time.Now().Before(current.ExpiresAt()) || !slices.Contains(current.Architectures(), "arm64") ||
		current.ImageRepository() != expected.ImageRepository() || current.SourceRepository() != expected.SourceRepository() ||
		!bytes.Equal(current.DelegationWire(), expected.DelegationWire()) || !bytes.Equal(current.SequenceMigrationWire(), expected.SequenceMigrationWire()) {
		return errors.Join(errNetBirdComponents, err)
	}
	return nil
}

func (s *netBirdComponents) readComponent(ctx context.Context, location releasechannel.Location, role string) (NetBirdComponent, error) {
	guarded := s.requestContext(ctx, nil)
	authority, err := s.componentAuthority(guarded, role)
	if err != nil || !authority.IsVerified() || !slices.Contains(authority.Architectures(), "arm64") {
		return NetBirdComponent{}, errors.Join(errNetBirdComponents, err)
	}
	s.capDeadline(authority.ExpiresAt())
	issuer, err := s.componentIssuer(guarded, role, authority)
	if err != nil || issuer.InstallationID() != s.intent.installationID || issuer.TenancyID() != s.reader.tenancy || issuer.Intent().OCIRegion != foundationHomeRegion || issuer.Intent().VaultTarget != s.manager.CredentialTarget() {
		return NetBirdComponent{}, errors.Join(errNetBirdComponents, err)
	}
	s.capDeadline(issuer.ExpiresAt())
	guarded = s.requestContext(ctx, &issuer)
	bundle, found, err := releasechannel.ReadContainerBundle(guarded, location, role, "arm64")
	if err != nil || !found || !bytes.Equal(bundle.Delegation, authority.DelegationWire()) || !bytes.Equal(bundle.Migration, authority.SequenceMigrationWire()) {
		return NetBirdComponent{}, errors.Join(errNetBirdComponents, err)
	}
	target := release.ContainerTarget{Cell: "GRU", Environment: "production", Role: role, Architecture: "arm64"}
	historical, err := release.VerifyContainerHistorical(bundle, s.reader.roots, target)
	if err != nil {
		return NetBirdComponent{}, err
	}
	claim := historical.Claim()
	repository, digest, ok := strings.Cut(claim.Image, "@")
	if !ok || repository != authority.ImageRepository() || claim.SourceRepository != authority.SourceRepository() {
		return NetBirdComponent{}, errNetBirdComponents
	}
	for _, wire := range [][]byte{bundle.Claim, bundle.Delegation, claim.Production.Qualification, claim.Production.Delegation} {
		if len(wire) == 0 {
			continue
		}
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return NetBirdComponent{}, err
		}
		s.capDeadline(envelope.ExpiresAt)
	}
	ctx, cancel := context.WithDeadline(ctx, s.expires)
	defer cancel()
	guarded = s.requestContext(ctx, &issuer)
	migrationEnvelope, err := trust.DecodeEnvelope(bundle.Migration)
	if err != nil {
		return NetBirdComponent{}, err
	}
	migration, err := release.VerifySequenceMigrationHistorical(migrationEnvelope, s.reader.roots, role, "production")
	if err != nil || migration.Namespace != s.reader.storage.Namespace || migration.Bucket != s.reader.storage.HeadBucket {
		return NetBirdComponent{}, errors.Join(errNetBirdComponents, err)
	}
	entry, ok := catalog.Lookup(migration.Region)
	if !ok {
		return NetBirdComponent{}, errNetBirdComponents
	}
	regional, err := s.factory.ForRegion(entry.OCIRegion)
	if err != nil {
		return NetBirdComponent{}, err
	}
	objects, err := regional.ObjectStorage()
	if err != nil {
		return NetBirdComponent{}, err
	}
	allocations := release.SequenceLocation{Client: netBirdComponentAllocations{client: objects}, Namespace: migration.Namespace, Bucket: migration.Bucket}
	verified, err := release.VerifyContainerCurrent(guarded, bundle, s.reader.roots, target, time.Now().UTC(), s.expires.Add(-time.Nanosecond), func(ctx context.Context, digest string) (io.ReadCloser, error) {
		return releasechannel.ReadContainerEvidence(ctx, location, role, digest)
	}, allocations)
	if err != nil {
		return NetBirdComponent{}, err
	}
	s.capDeadline(verified.ExpiresAt())
	intent := issuer.Intent()
	scope := pullauth.PullScope{RegistryHost: intent.RegistryHost, Repository: intent.RegistryNamespace + "/" + intent.RepositoryName, Digest: digest,
		TaskPrincipal: entityid.Derive("netbird-component", s.manager.StoreGeneration(), role)}
	owned := pullauth.PullSecret{RegistryHost: scope.RegistryHost, Repository: scope.Repository, Ref: vaultsecret.Ref{Vault: intent.VaultTarget.VaultID, Name: intent.SecretName}}
	pulls, err := pullauth.NewPullSecrets(regional)
	if err != nil {
		return NetBirdComponent{}, err
	}
	pull, err := pulls.Describe(guarded, scope, owned, issuer.Generation())
	if err != nil {
		return NetBirdComponent{}, err
	}
	return NetBirdComponent{role: role, release: verified, pull: pull, authority: authority, issuer: issuer}, nil
}

type netBirdComponentAllocations struct {
	client objectstorage.ObjectStorageClient
}

func (r netBirdComponentAllocations) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	return r.client.GetObject(ociclient.RequestContext(ctx), request)
}

func (netBirdComponentAllocations) PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	return objectstorage.PutObjectResponse{}, errors.New("NetBird component verification cannot write release sequences")
}
