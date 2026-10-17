// Package rootrelease publishes release telemetry from root-observed admission
// and current upstream runtime state. Socket callers supply selectors only.
package rootrelease

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var ErrPending = errors.New("root container status observation is pending")

type Backend struct {
	factory *ociclient.Factory
	mu      sync.RWMutex
	sources *Sources
}

// Sources are actual root-created regional readers, never child pointers or
// child-provided callbacks. Bind is called once after the root broker opens.
type Sources struct {
	JS        jetstream.JetStream
	Fleet     oci.FleetObserver
	Node      *swarmruntime.Node
	Intents   *delivery.Service
	Specs     jetstream.KeyValue
	Roots     jetstream.KeyValue
	Leases    *authority.Reader
	Hosts     *host.Reader
	Authority *bootstrapstart.CurrentFounderAuthorityReader
	Accepted  bootstrapstart.AcceptedIdentity
}

var _ rootoci.ContainerReleases = (*Backend)(nil)

func New(factory *ociclient.Factory) (*Backend, error) {
	if os.Geteuid() != 0 || factory == nil || !catalog.IsOCIRegion(factory.Region()) {
		return nil, rootoci.ErrUnauthorized
	}
	return &Backend{factory: factory}, nil
}

func (b *Backend) Bind(s Sources) error {
	if os.Geteuid() != 0 || b == nil || s.JS == nil || s.JS.Conn() == nil || s.Node == nil || s.Intents == nil || s.Specs == nil || s.Roots == nil || s.Leases == nil || s.Hosts == nil || s.Fleet == nil || s.Authority == nil || s.Accepted.Validate() != nil {
		return ErrPending
	}
	if s.Specs.Bucket() != "TS_SERVICE_SET" || s.Roots.Bucket() != "TS_TRUST_ROOTS" {
		return rootoci.ErrInvalid
	}
	s.Accepted = s.Accepted.Clone()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sources != nil {
		return errors.New("root release sources already bound")
	}
	b.sources = &s
	return nil
}

func (b *Backend) ReconcileContainerStatus(ctx context.Context, call rootoci.Call, request rootoci.ContainerStatusRequest) (rootoci.ContainerStatusReceipt, error) {
	pending := func(err error) (rootoci.ContainerStatusReceipt, error) {
		return rootoci.ContainerStatusReceipt{}, errors.Join(ErrPending, err)
	}
	if b == nil || b.factory == nil || os.Geteuid() != 0 || !entityid.Valid(request.OperationID) || !validDigest(request.ExpectedFingerprint) || call.Operation() != rootoci.OperationReconcileContainerStatus {
		return pending(rootoci.ErrInvalid)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if deadline := call.Deadline(); deadline.IsZero() {
		return pending(rootoci.ErrUnauthorized)
	} else {
		var stop context.CancelFunc
		ctx, stop = context.WithDeadline(ctx, deadline)
		defer stop()
	}
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	if err := call.Guard(ctx); err != nil {
		return pending(err)
	}
	b.mu.RLock()
	s := b.sources
	b.mu.RUnlock()
	if s == nil {
		return pending(nil)
	}
	source, err := s.Authority.ReadRuntimeAuthority(ctx, s.Accepted, time.Now().UTC())
	if err != nil {
		return pending(err)
	}
	identity := source.Identity()
	if identity.OCIRegion != b.factory.Region() || call.Expected().Cell != "" && !strings.EqualFold(call.Expected().Cell, identity.Cell) {
		return pending(rootoci.ErrUnauthorized)
	}
	rootsEntry, err := s.current(ctx, "TS_TRUST_ROOTS", "chain")
	if err != nil {
		return pending(err)
	}
	roots, err := currentRoots(s.Accepted, rootsEntry.Value())
	if err != nil {
		return pending(err)
	}
	intent, err := s.Intents.ContainerIntent(ctx, request.OperationID)
	if err != nil {
		return pending(err)
	}
	if intent.Container == nil || intent.Cell != strings.ToLower(identity.Cell) || intent.Environment != identity.Environment ||
		call.Expected().OperationID != "" && call.Expected().OperationID != intent.OperationID || call.Expected().Epoch != 0 && call.Expected().Epoch != intent.AuthorityEpoch {
		return pending(rootoci.ErrUnauthorized)
	}
	intentFingerprint, err := intent.Fingerprint()
	if err != nil {
		return pending(err)
	}
	lease, err := s.Leases.AdmitCurrentLease(ctx, identity.DeploymentID, call.RuntimeID(), intent.AuthorityEpoch)
	if err != nil {
		return pending(err)
	}
	specEntry, err := s.current(ctx, "TS_SERVICE_SET", "current")
	if err != nil {
		return pending(err)
	}
	specIdentity := cellspec.Identity{DeploymentID: identity.DeploymentID, Cell: strings.ToLower(identity.Cell), Environment: identity.Environment}
	profile, err := containermaterial.VerifyProfile(specEntry.Value(), roots.Current, specIdentity, intent)
	if err != nil {
		return pending(err)
	}
	envelope, err := trust.DecodeEnvelope(intent.Container.Claim)
	if err != nil {
		return pending(err)
	}
	var claim release.ContainerClaim
	if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
		return pending(err)
	}
	expected, err := containermaterial.ServiceIntent(profile, claim.Architecture)
	if err != nil {
		return pending(err)
	}
	spec, err := cellspec.VerifyHistorical(specEntry.Value(), roots.Current, specIdentity)
	if err != nil || !spec.RootSigned {
		return pending(err)
	}
	var policy *workload.ServiceSpec
	for _, service := range spec.Services {
		if service.Role == intent.Role {
			policy = service.Spec
		}
	}
	if policy == nil || policy.Kind != workload.KindStateless || policy.Validate() != nil {
		return pending(nil)
	}
	location, err := b.location(ctx, identity.Cell)
	if err != nil {
		return pending(err)
	}
	allocations, err := b.allocations(ctx, *intent.Container, roots.Current, release.ContainerTarget{Cell: identity.Cell, Environment: intent.Environment, Role: intent.Role, Architecture: claim.Architecture})
	if err != nil {
		return pending(err)
	}
	deadline, _ := ctx.Deadline()
	deadline = earlier(deadline, source.ExpiresAt(), lease.Deadline())
	for _, wire := range [][]byte{intent.Container.Claim, intent.Container.Delegation, claim.Production.Qualification, claim.Production.Delegation} {
		if len(wire) == 0 {
			continue
		}
		finite, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return pending(err)
		}
		deadline = earlier(deadline, finite.ExpiresAt.Add(-time.Nanosecond))
	}

	ctx, finish := context.WithDeadline(ctx, deadline)
	defer finish()
	verified, err := release.VerifyContainerCurrent(ctx, *intent.Container, roots.Current, release.ContainerTarget{Cell: identity.Cell, Environment: intent.Environment, Role: intent.Role, Architecture: claim.Architecture}, time.Now().UTC(), deadline, func(ctx context.Context, digest string) (io.ReadCloser, error) {
		return releasechannel.ReadContainerEvidence(ctx, location, intent.Role, digest)
	}, allocations)
	if err != nil {
		return pending(err)
	}
	if verified.Fingerprint() != request.ExpectedFingerprint {
		return pending(rootoci.ErrUnauthorized)
	}
	deadline = earlier(deadline, verified.ExpiresAt())
	client, err := s.Node.ControlClient(ctx)
	if err != nil {
		return pending(err)
	}
	originalOperation, err := swarmruntime.CurrentContainerOperation(ctx, client, expected)
	if err != nil || !entityid.Valid(originalOperation) {
		return pending(err)
	}
	original := intent.Clone()
	if originalOperation != intent.OperationID {
		original, err = s.Intents.ContainerIntent(ctx, originalOperation)
		if err != nil || !equivalentIntents(intent, original) {
			return pending(err)
		}
		profile, err = containermaterial.VerifyProfile(specEntry.Value(), roots.Current, specIdentity, original)
		if err != nil {
			return pending(err)
		}
		expected, err = containermaterial.ServiceIntent(profile, claim.Architecture)
		if err != nil {
			return pending(err)
		}
	}
	originalFingerprint, err := original.Fingerprint()
	if err != nil {
		return pending(err)
	}

	sourceGuard := func(ctx context.Context) error {
		if err := call.Guard(ctx); err != nil {
			return err
		}
		if !time.Now().Before(deadline) || !verified.Valid(time.Now().UTC()) {
			return ErrPending
		}
		current, err := s.Authority.ReadRuntimeAuthority(ctx, s.Accepted, time.Now().UTC())
		if err != nil || current.Identity() != identity || !time.Now().Before(current.ExpiresAt()) {
			return errors.Join(ErrPending, err)
		}
		rootNow, err := s.current(ctx, "TS_TRUST_ROOTS", "chain")
		if err != nil || rootNow.Revision() != rootsEntry.Revision() || !bytes.Equal(rootNow.Value(), rootsEntry.Value()) {
			return errors.Join(ErrPending, err)
		}
		specNow, err := s.current(ctx, "TS_SERVICE_SET", "current")
		if err != nil || specNow.Revision() != specEntry.Revision() || !bytes.Equal(specNow.Value(), specEntry.Value()) {
			return errors.Join(ErrPending, err)
		}
		retained, err := s.Intents.ContainerIntent(ctx, intent.OperationID)
		if err != nil {
			return err
		}
		fingerprint, err := retained.Fingerprint()
		if err != nil || fingerprint != intentFingerprint {
			return ErrPending
		}
		if err := lease.Guard(ctx); err != nil {
			return err
		}

		originalNow, err := s.Intents.ContainerIntent(ctx, original.OperationID)
		if err != nil {
			return err
		}
		originalNowFingerprint, err := originalNow.Fingerprint()
		if err != nil || originalNowFingerprint != originalFingerprint {
			return ErrPending
		}
		return nil
	}
	sessions := map[string]*host.ContainerGenerationSession{}
	controllers := map[string]*bootstrapstart.ControllerHostRecipient{}
	guard := func(ctx context.Context) error {
		if err := sourceGuard(ctx); err != nil {
			return err
		}
		client, err := s.Node.ControlClient(ctx)
		if err != nil {
			return err
		}
		service, err := swarmruntime.VerifyCurrentContainerService(ctx, client, expected, verified, roots.Current)
		if err != nil {
			return err
		}
		replicas := service.Spec.GetReplicated().Replicas
		if replicas < uint64(policy.Replicas.Min) || replicas > uint64(policy.Replicas.Max) {
			return ErrPending
		}
		readyUntil, err := b.ready(ctx, s, client, service, expected, verified, roots.Current, profile, specEntry.Value(), sessions, controllers)
		if err != nil {
			return err
		}
		deadline = earlier(deadline, readyUntil)

		if err := sourceGuard(ctx); err != nil {
			return err
		}
		confirmed, err := swarmruntime.VerifyCurrentContainerService(ctx, client, expected, verified, roots.Current)
		if err != nil || confirmed.Meta.Version.Index != service.Meta.Version.Index {
			return errors.Join(ErrPending, err)
		}
		if err := call.Guard(ctx); err != nil {
			return err
		}
		return ociclient.LimitAdmission(ctx, deadline)
	}
	if err := guard(ctx); err != nil {
		return pending(err)
	}
	status := releasechannel.ContainerStatus{Schema: releasechannel.ContainerStatusSchema, OperationID: original.OperationID, Cell: claim.Cell, Environment: claim.Environment, Role: claim.Role, Architecture: claim.Architecture, Image: claim.Image, ReleaseSequence: claim.ReleaseSequence, Fingerprint: verified.Fingerprint(), State: releasechannel.StateComplete, UpdatedAt: time.Now().UTC()}
	effect := ociclient.WithAdmission(ctx, func(ctx context.Context) (func(), error) { return func() {}, guard(ctx) })
	writeErr := releasechannel.WriteContainerStatus(effect, location, status)
	// Even a successful SDK response is followed by exact protected readback.
	actual, found, err := releasechannel.ReadContainerStatus(ctx, location, status.Role, status.Architecture)
	if err != nil || !found || !sameStatus(actual, status) {
		return pending(errors.Join(writeErr, err))
	}
	if err := guard(ctx); err != nil {
		return pending(err)
	}
	return rootoci.ContainerStatusReceipt{OperationID: intent.OperationID, Status: actual, ExpiresAt: deadline}, nil
}

func currentRoots(accepted bootstrapstart.AcceptedIdentity, wire []byte) (trust.VerifiedRoots, error) {
	installed, err := bootstrapstart.LoadTrustInputs(accepted)
	if err != nil {
		return trust.VerifiedRoots{}, err
	}
	chain, err := trust.DecodeRootChain(wire)
	if err != nil || len(chain.Rotations) < len(installed.Chain.Rotations) {
		return trust.VerifiedRoots{}, errors.Join(ErrPending, err)
	}
	prefix := chain
	prefix.Rotations = prefix.Rotations[:len(installed.Chain.Rotations)]
	floor, err := trust.VerifyRootChain(installed.Genesis, installed.ChainIdentity, prefix)
	if err != nil || floor.Head != installed.Roots.Head {
		return trust.VerifiedRoots{}, errors.Join(ErrPending, err)
	}
	return trust.VerifyRootChain(installed.Genesis, installed.ChainIdentity, chain)
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}
func earlier(values ...time.Time) time.Time {
	var earliest time.Time
	for _, value := range values {
		if earliest.IsZero() || value.Before(earliest) {
			earliest = value
		}
	}
	return earliest
}
func sameStatus(a, b releasechannel.ContainerStatus) bool {
	return a.Schema == b.Schema && a.OperationID == b.OperationID && a.Cell == b.Cell && a.Environment == b.Environment && a.Role == b.Role && a.Architecture == b.Architecture && a.Image == b.Image && a.ReleaseSequence == b.ReleaseSequence && a.Fingerprint == b.Fingerprint && a.State == b.State && a.Reason == b.Reason && a.UpdatedAt.Equal(b.UpdatedAt)
}

// sdkObjects joins every retry to the original operation cancellation boundary.
type sdkObjects struct {
	objectstorage.ObjectStorageClient
}

func (c sdkObjects) GetObject(ctx context.Context, r objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	return c.ObjectStorageClient.GetObject(ociclient.RequestContext(ctx), r)
}
func (c sdkObjects) PutObject(ctx context.Context, r objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	return c.ObjectStorageClient.PutObject(ociclient.RequestContext(ctx), r)
}
func (b *Backend) location(ctx context.Context, cell string) (releasechannel.Location, error) {
	bucket, err := releasechannel.BucketName(cell)
	if err != nil {
		return releasechannel.Location{}, err
	}
	client, err := b.factory.ObjectStorage()
	if err != nil {
		return releasechannel.Location{}, err
	}
	namespace, err := client.GetNamespace(ociclient.RequestContext(ctx), objectstorage.GetNamespaceRequest{})
	if err != nil || namespace.Value == nil || *namespace.Value == "" {
		return releasechannel.Location{}, errors.Join(ErrPending, err)
	}
	return releasechannel.Location{Client: sdkObjects{client}, Namespace: *namespace.Value, Bucket: bucket}, nil
}
func (b *Backend) allocations(ctx context.Context, bundle release.ContainerBundle, roots trust.Keyring, target release.ContainerTarget) (release.SequenceLocation, error) {
	envelope, err := trust.DecodeEnvelope(bundle.Migration)
	if err != nil {
		return release.SequenceLocation{}, err
	}
	migration, err := release.VerifySequenceMigrationHistorical(envelope, roots, target.Role, target.Environment)
	if err != nil {
		return release.SequenceLocation{}, err
	}
	entry, ok := catalog.Lookup(migration.Region)
	if !ok {
		return release.SequenceLocation{}, ErrPending
	}
	regional, err := b.factory.ForRegion(entry.OCIRegion)
	if err != nil {
		return release.SequenceLocation{}, err
	}
	client, err := regional.ObjectStorage()
	if err != nil {
		return release.SequenceLocation{}, err
	}
	return release.SequenceLocation{Client: sdkObjects{client}, Namespace: migration.Namespace, Bucket: migration.Bucket}, ctx.Err()
}

// Equivalent metadata may retain the original task operation. Both journal
// entries remain independently authorized; no new operation execution is implied.
func equivalentIntents(request, original delivery.Intent) bool {
	if request.Container == nil || original.Container == nil {
		return false
	}
	request = request.Clone()
	original = original.Clone()
	request.OperationID = original.OperationID
	request.AuthorityEpoch = original.AuthorityEpoch
	before, err := request.Fingerprint()
	after, otherErr := original.Fingerprint()
	return err == nil && otherErr == nil && before == after
}
