package rootrelease

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var _ rootoci.ContainerMaterial = (*Backend)(nil)

type materialScope struct {
	target        release.ContainerTarget
	originalProof []byte
	intent        delivery.Intent
	retained      release.HistoricalContainer
	roots         trust.Keyring
	proof         release.ProductionQualification
	expires       time.Time
	guard         func(context.Context) error
}

func (b *Backend) material(ctx context.Context, call rootoci.Call, operation rootoci.Operation, operationID, fingerprint string) (materialScope, error) {
	if b == nil || b.factory == nil || os.Geteuid() != 0 || !entityid.Valid(operationID) || !validDigest(fingerprint) || call.Operation() != operation {
		return materialScope{}, rootoci.ErrInvalid
	}
	if err := call.Guard(ctx); err != nil {
		return materialScope{}, err
	}
	b.mu.RLock()
	s := b.sources
	b.mu.RUnlock()
	if s == nil {
		return materialScope{}, ErrPending
	}
	source, err := s.Authority.ReadRuntimeAuthority(ctx, s.Accepted, time.Now().UTC())
	if err != nil {
		return materialScope{}, err
	}
	ctx, stopSource := context.WithDeadline(ctx, source.ExpiresAt())
	defer stopSource()
	identity := source.Identity()
	if identity.OCIRegion != b.factory.Region() || call.Expected().Cell != "" && !strings.EqualFold(call.Expected().Cell, identity.Cell) {
		return materialScope{}, rootoci.ErrUnauthorized
	}
	rootEntry, err := s.current(ctx, "TS_TRUST_ROOTS", "chain")
	if err != nil {
		return materialScope{}, err
	}
	roots, err := currentRoots(s.Accepted, rootEntry.Value())
	if err != nil {
		return materialScope{}, err
	}
	materialRoots := roots.Current
	readIntent := s.Intents.ContainerIntent
	if operation == rootoci.OperationRetainedContainerEvidence || operation == rootoci.OperationRetainedContainerAllocation {
		// Rotated roots authenticate retained provenance, never current authority.
		materialRoots = roots.Historical
		readIntent = s.Intents.RetainedContainerIntent
	}
	intent, err := readIntent(ctx, operationID)
	if err != nil {
		return materialScope{}, err
	}
	if intent.Container == nil || intent.Cell != strings.ToLower(identity.Cell) || intent.Environment != identity.Environment ||
		call.Expected().OperationID != "" && call.Expected().OperationID != intent.OperationID || call.Expected().Epoch != 0 && call.Expected().Epoch != intent.AuthorityEpoch {
		return materialScope{}, rootoci.ErrUnauthorized
	}
	if operation != rootoci.OperationRetainedContainerEvidence && operation != rootoci.OperationRetainedContainerAllocation {
		var stopProof context.CancelFunc
		ctx, stopProof, err = containerProofContext(ctx, *intent.Container)
		defer stopProof()
		if err != nil {
			return materialScope{}, err
		}
	}
	specEntry, err := s.current(ctx, "TS_SERVICE_SET", "current")
	if err != nil {
		return materialScope{}, err
	}

	specIdentity := cellspec.Identity{DeploymentID: identity.DeploymentID, Cell: strings.ToLower(identity.Cell), Environment: identity.Environment}
	switch operation {
	case rootoci.OperationRetainedContainerEvidence, rootoci.OperationRetainedContainerAllocation:
		// Historical bytes may describe an older profile. Current signed authority
		// must still retain the role; these reads never admit that old profile.
		adopted, err := cellspec.VerifyHistorical(specEntry.Value(), roots.Current, specIdentity)
		if err != nil || !adopted.RootSigned {
			return materialScope{}, errors.Join(ErrPending, err)
		}
		retainedRole := false
		for _, service := range adopted.Services {
			if service.Role == intent.Role {
				retainedRole = true
			}
		}
		if !retainedRole {
			return materialScope{}, rootoci.ErrUnauthorized
		}
	default:
		if _, err := containermaterial.VerifyProfile(specEntry.Value(), roots.Current, specIdentity, intent); err != nil {
			return materialScope{}, err
		}
	}

	envelope, err := trust.DecodeEnvelope(intent.Container.Claim)
	if err != nil {
		return materialScope{}, err
	}
	// Scope selectors come from an authenticated retained intent, then the signed
	// claim is checked again against the root process's actual regional identity.
	var claim release.ContainerClaim
	if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
		return materialScope{}, err
	}
	target := release.ContainerTarget{Cell: identity.Cell, Environment: identity.Environment, Role: intent.Role, Architecture: claim.Architecture}
	var genesisResolver region.FoundationResolver
	var originalProof []byte
	if len(intent.Container.Migration) == 0 {
		genesisResolver, err = region.NewFoundationDiscovery(b.factory, source.Anchor(), roots.Current)
		if err != nil {
			return materialScope{}, err
		}
		target.Genesis, originalProof, err = genesisResolver.WorkloadGenesis(ctx, target.Cell, target.Role, target.Environment)
		if err != nil {
			return materialScope{}, err
		}
	}
	retained, err := release.VerifyContainerHistorical(*intent.Container, materialRoots, target)
	if err != nil {
		return materialScope{}, err
	}
	if retained.Fingerprint() != fingerprint {
		return materialScope{}, rootoci.ErrUnauthorized
	}
	now := time.Now().UTC()
	expires, ok := ctx.Deadline()
	if !ok {
		return materialScope{}, rootoci.ErrUnauthorized
	}

	expires = earlier(expires, source.ExpiresAt())
	verifyAt := now
	switch operation {
	case rootoci.OperationRetainedContainerEvidence, rootoci.OperationRetainedContainerAllocation:
		// The signed issue instant authenticates provenance, never execution now.
		verifyAt = envelope.IssuedAt
		if now.Before(verifyAt) {
			return materialScope{}, trust.ErrExpired
		}
		if !target.Genesis.IsVerified() {
			migration, err := trust.DecodeEnvelope(intent.Container.Migration)
			if err != nil {
				return materialScope{}, err
			}
			if _, err := release.VerifySequenceMigrationCurrent(migration, materialRoots, intent.Role, intent.Environment, migration.IssuedAt); err != nil {
				return materialScope{}, err
			}
		}
	default:
		expires = earlier(expires, envelope.ExpiresAt)
		qualification, err := trust.DecodeEnvelope(claim.Production.Qualification)
		if err != nil {
			return materialScope{}, err
		}
		expires = earlier(expires, qualification.ExpiresAt)
		for _, wire := range [][]byte{intent.Container.Delegation, claim.Production.Delegation} {
			if len(wire) == 0 {
				continue
			}
			delegation, err := trust.DecodeEnvelope(wire)
			if err != nil {
				return materialScope{}, err
			}
			expires = earlier(expires, delegation.ExpiresAt)
		}
		// An envelope's expiry is exclusive; the original finite read cannot renew it.
		expires = expires.Add(-time.Nanosecond)
		if !now.Before(expires) {
			return materialScope{}, trust.ErrExpired
		}

	}
	if !now.Before(expires) {
		return materialScope{}, trust.ErrExpired
	}
	verifyClaim := func(at time.Time) error {
		if len(intent.Container.Delegation) == 0 {
			_, err := trust.VerifyCurrent(envelope, release.ContainerScope(target), materialRoots, at, trust.Policy{MaxLifetime: release.MaxUpdateReceiptLifetime})
			return err
		}
		delegation, err := trust.DecodeEnvelope(intent.Container.Delegation)
		if err != nil {
			return err
		}
		if target.Genesis.IsVerified() {
			if err := target.Genesis.VerifyCurrentDelegation(delegation, materialRoots, at); err != nil {
				return err
			}
		}
		grant, err := trust.VerifyDelegationCurrent(delegation, materialRoots, at, trust.Policy{MaxLifetime: release.MaxUpdateReceiptLifetime})
		if err != nil {
			return err
		}
		_, err = trust.VerifyDelegatedCurrent(envelope, release.ContainerScope(target), grant, at, trust.Policy{MaxLifetime: release.MaxUpdateReceiptLifetime})
		return err
	}
	if err := verifyClaim(verifyAt); err != nil {
		return materialScope{}, err
	}

	if operation == rootoci.OperationContainerEvidence || operation == rootoci.OperationContainerAllocation {
		if err := verifyClaim(expires); err != nil {
			return materialScope{}, err
		}
	}
	_, imageDigest, _ := strings.Cut(claim.Image, "@sha256:")
	candidate := release.ProductionExpectation{SourceRevision: claim.SourceRevision, ArtifactSHA256: imageDigest, QualificationSHA256: claim.QualificationSHA256, Cell: target.Cell, Environment: target.Environment, Runtime: release.ProductionRuntime, Architecture: target.Architecture, Role: target.Role}
	proof, err := release.VerifyProductionCurrent(claim.Production.Qualification, claim.Production.Delegation, materialRoots, candidate, verifyAt)
	if err != nil {
		return materialScope{}, err
	}

	if operation == rootoci.OperationContainerEvidence || operation == rootoci.OperationContainerAllocation {
		if _, err := release.VerifyProductionCurrent(claim.Production.Qualification, claim.Production.Delegation, materialRoots, candidate, expires); err != nil {
			return materialScope{}, err
		}
	}
	pinned, err := intent.Fingerprint()
	if err != nil {
		return materialScope{}, err
	}
	guard := func(ctx context.Context) error {
		// Scope validation may itself read OCI; retain the process/session guard
		// while preventing those source reads from recursively validating scope.
		ctx = ociclient.WithRequestGuard(ctx, call.Guard)
		if target.Genesis.IsVerified() {
			currentGenesis, evidence, err := genesisResolver.WorkloadGenesis(ctx, target.Cell, target.Role, target.Environment)
			if err != nil || currentGenesis.Fingerprint() != target.Genesis.Fingerprint() || !bytes.Equal(evidence, originalProof) {
				return errors.Join(ErrPending, err)
			}
		}
		if err := call.Guard(ctx); err != nil {
			return err
		}
		if !time.Now().Before(expires) {
			return trust.ErrExpired
		}
		current, err := s.Authority.ReadRuntimeAuthority(ctx, s.Accepted, time.Now().UTC())
		if err != nil || current.Identity() != identity || !time.Now().Before(current.ExpiresAt()) {
			return errors.Join(ErrPending, err)
		}
		rootNow, err := s.current(ctx, "TS_TRUST_ROOTS", "chain")
		if err != nil || rootNow.Revision() != rootEntry.Revision() || !bytes.Equal(rootNow.Value(), rootEntry.Value()) {
			return errors.Join(ErrPending, err)
		}
		specNow, err := s.current(ctx, "TS_SERVICE_SET", "current")
		if err != nil || specNow.Revision() != specEntry.Revision() || !bytes.Equal(specNow.Value(), specEntry.Value()) {
			return errors.Join(ErrPending, err)
		}
		currentIntent, err := readIntent(ctx, operationID)
		if err != nil {
			return err
		}
		actual, err := currentIntent.Fingerprint()
		if err != nil || actual != pinned {
			return errors.Join(ErrPending, err)
		}
		if !time.Now().Before(expires) {
			return trust.ErrExpired
		}
		return call.Guard(ctx)
	}
	return materialScope{target: target, originalProof: originalProof, intent: intent, retained: retained, roots: materialRoots, proof: proof, expires: expires, guard: guard}, guard(ctx)
}

func (b *Backend) ContainerEvidence(ctx context.Context, call rootoci.Call, request rootoci.ContainerEvidenceRequest) (rootoci.ContainerEvidenceChunk, error) {
	return b.containerEvidence(ctx, call, rootoci.OperationContainerEvidence, request)
}

func (b *Backend) RetainedContainerEvidence(ctx context.Context, call rootoci.Call, request rootoci.RetainedContainerEvidenceRequest) (rootoci.RetainedContainerEvidenceChunk, error) {
	result, err := b.containerEvidence(ctx, call, rootoci.OperationRetainedContainerEvidence, rootoci.ContainerEvidenceRequest(request))
	return rootoci.RetainedContainerEvidenceChunk(result), err
}

func (b *Backend) containerEvidence(ctx context.Context, call rootoci.Call, operation rootoci.Operation, request rootoci.ContainerEvidenceRequest) (rootoci.ContainerEvidenceChunk, error) {
	var result rootoci.ContainerEvidenceChunk
	if !validDigest(request.EvidenceSHA256) || request.Offset < 0 || request.Offset >= release.MaxProductionEvidenceBytes {
		return result, rootoci.ErrInvalid
	}
	ctx, cancel, err := materialContext(ctx, call)
	if err != nil {
		return result, err
	}
	defer cancel()
	scope, err := b.material(ctx, call, operation, request.OperationID, request.ExpectedFingerprint)
	if err != nil {
		return result, err
	}
	ctx, expire := context.WithDeadline(ctx, scope.expires)
	defer expire()
	ctx = ociclient.WithRequestGuard(ctx, scope.guard)
	var evidence *release.ProductionGateEvidence
	for _, entry := range scope.proof.Evidence {
		if entry.SHA256 == request.EvidenceSHA256 {
			if evidence != nil && evidence.Bytes != entry.Bytes {
				return result, rootoci.ErrInvalid
			}
			evidence = new(entry)
		}
	}
	if evidence == nil || request.Offset >= evidence.Bytes {
		return result, rootoci.ErrInvalid
	}
	count := min(int64(rootoci.ContainerEvidenceChunkBytes), evidence.Bytes-request.Offset)
	location, err := b.location(ctx, scope.retained.Claim().Cell)
	if err != nil {
		return result, err
	}
	name := releasechannel.ContainerEvidenceObject(scope.intent.Role, evidence.SHA256)
	// Only one allowlisted signed evidence object and a bounded signed-size range
	// can reach OCI; the consumer still verifies the assembled evidence digest.
	response, err := ociclient.ReadObject(ctx, location.Client, objectstorage.GetObjectRequest{NamespaceName: new(location.Namespace), BucketName: new(location.Bucket), ObjectName: new(name), Range: new(fmt.Sprintf("bytes=%d-%d", request.Offset, request.Offset+count-1))})
	if err != nil {
		return result, err
	}
	if response.Content == nil {
		return result, ErrPending
	}
	wire, readErr := io.ReadAll(io.LimitReader(response.Content, count+1))
	closeErr := response.Content.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return result, err
	}
	if int64(len(wire)) != count {
		return result, errors.New("container evidence range differs from signed size")
	}
	if err := scope.guard(ctx); err != nil {
		return result, err
	}
	return rootoci.ContainerEvidenceChunk{OperationID: request.OperationID, Fingerprint: scope.retained.Fingerprint(), EvidenceSHA256: evidence.SHA256, Offset: request.Offset, TotalBytes: evidence.Bytes, Data: wire, ExpiresAt: scope.expires}, nil
}

func (b *Backend) ContainerAllocation(ctx context.Context, call rootoci.Call, request rootoci.ContainerAllocationRequest) (rootoci.ContainerAllocationObservation, error) {
	return b.containerAllocation(ctx, call, rootoci.OperationContainerAllocation, request)
}

func (b *Backend) RetainedContainerAllocation(ctx context.Context, call rootoci.Call, request rootoci.RetainedContainerAllocationRequest) (rootoci.RetainedContainerAllocationObservation, error) {
	result, err := b.containerAllocation(ctx, call, rootoci.OperationRetainedContainerAllocation, rootoci.ContainerAllocationRequest(request))
	return rootoci.RetainedContainerAllocationObservation(result), err
}

func (b *Backend) containerAllocation(ctx context.Context, call rootoci.Call, operation rootoci.Operation, request rootoci.ContainerAllocationRequest) (rootoci.ContainerAllocationObservation, error) {
	var result rootoci.ContainerAllocationObservation
	ctx, cancel, err := materialContext(ctx, call)
	if err != nil {
		return result, err
	}
	defer cancel()
	scope, err := b.material(ctx, call, operation, request.OperationID, request.ExpectedFingerprint)
	if err != nil {
		return result, err
	}
	ctx, expire := context.WithDeadline(ctx, scope.expires)
	defer expire()
	ctx = ociclient.WithRequestGuard(ctx, scope.guard)
	claim := scope.retained.Claim()
	location, err := b.allocations(ctx, *scope.intent.Container, scope.roots, scope.target)
	if err != nil {
		return result, err
	}
	wire, err := release.ReadContainerAllocation(ctx, location, scope.roots, scope.retained)
	if err != nil {
		return result, err
	}
	if err := scope.guard(ctx); err != nil {
		return result, err
	}
	return rootoci.ContainerAllocationObservation{OriginalProof: scope.originalProof, OperationID: request.OperationID, Fingerprint: scope.retained.Fingerprint(), Namespace: location.Namespace, Bucket: location.Bucket, ObjectName: release.SequenceReservationObject(claim.Role, claim.Environment, claim.OrderingSHA256(), claim.ReleaseSequence), Data: wire, ExpiresAt: scope.expires}, nil
}

func materialContext(ctx context.Context, call rootoci.Call) (context.Context, context.CancelFunc, error) {
	if call.Deadline().IsZero() {
		return nil, func() {}, rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, earlier(call.Deadline(), time.Now().Add(30*time.Second)))
	return ociclient.WithRequestGuard(ctx, call.Guard), cancel, nil
}
