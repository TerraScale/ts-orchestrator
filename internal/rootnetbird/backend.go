// Package rootnetbird rederives public NET proposals from root-owned sources.
// The dedicated manager separately authenticates its broker reads before effects.
package rootnetbird

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type Backend struct {
	factory *ociclient.Factory
	mu      sync.RWMutex
	sources *Sources
}

// Sources retain the original root-created reader and accepted installation.
// A successor connection or credential generation requires a new runtime.
type Sources struct {
	JS           jetstream.JetStream
	Specs, Roots jetstream.KeyValue
	Leases       *authority.Reader
	Authority    *bootstrapstart.CurrentFounderAuthorityReader
	Accepted     bootstrapstart.AcceptedIdentity
	Credentials  *rootsecret.ControllerReader
}

var _ rootoci.NetBird = (*Backend)(nil)

// New requires no broker; Bind supplies genuine retained readers after READY.
func New(factory *ociclient.Factory) (*Backend, error) {
	if os.Geteuid() != 0 || factory == nil || !catalog.IsOCIRegion(factory.Region()) {
		return nil, rootoci.ErrUnauthorized
	}
	return &Backend{factory: factory}, nil
}

func (b *Backend) Bind(s Sources) error {
	if b == nil || os.Geteuid() != 0 || s.JS == nil || s.JS.Conn() == nil || s.Specs == nil || s.Roots == nil ||
		s.Leases == nil || s.Authority == nil || s.Accepted.Validate() != nil || s.Credentials == nil ||
		s.Credentials.Conn() != s.JS.Conn() || s.Specs.Bucket() != "TS_SERVICE_SET" || s.Roots.Bucket() != "TS_TRUST_ROOTS" {
		return rootoci.ErrUnauthorized
	}
	lifetime := s.Credentials.Context()
	if lifetime == nil || lifetime.Done() == nil || lifetime.Err() != nil || s.Credentials.Guard(lifetime) != nil {
		return rootoci.ErrUnauthorized
	}
	s.Accepted = s.Accepted.Clone()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sources != nil {
		return errors.New("root NetBird sources are already bound")
	}
	b.sources = &s
	return nil
}

func (b *Backend) AuthorizeNetBirdIntent(ctx context.Context, call rootoci.Call, request rootoci.NetBirdIntentRequest) (rootoci.NetBirdIntentReceipt, error) {
	fail := func(err error) (rootoci.NetBirdIntentReceipt, error) {
		return rootoci.NetBirdIntentReceipt{}, errors.Join(rootoci.ErrUnauthorized, err)
	}
	if b == nil || b.factory == nil || ctx == nil || os.Geteuid() != 0 || call.Operation() != rootoci.OperationAuthorizeNetBirdIntent ||
		!entityid.Valid(call.RuntimeID()) || request.RuntimeID != call.RuntimeID() ||
		!entityid.Valid(request.OperationID) || !entityid.Valid(request.OwnerID) || request.Epoch == 0 || request.LeaseRevision == 0 ||
		request.ExpiresAt.IsZero() || !time.Now().Before(request.ExpiresAt) || call.Deadline().IsZero() {
		return fail(nil)
	}
	ctx, cancel := context.WithDeadline(ctx, earlier(call.Deadline(), request.ExpiresAt))
	defer cancel()
	b.mu.RLock()
	s := b.sources
	b.mu.RUnlock()
	if s == nil {
		return rootoci.NetBirdIntentReceipt{}, rootoci.ErrUnavailable
	}
	guard := func(ctx context.Context) error {
		if err := call.Guard(ctx); err != nil {
			return err
		}
		return s.Credentials.Guard(ctx)
	}
	ctx = ociclient.WithRequestGuard(ctx, guard)
	if err := guard(ctx); err != nil {
		return fail(err)
	}
	source, err := s.Authority.ReadRuntimeAuthority(ctx, s.Accepted, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	identity := source.Identity()
	if identity.OCIRegion != b.factory.Region() || request.Cell != identity.Cell ||
		call.Expected().Cell != "" && !strings.EqualFold(call.Expected().Cell, identity.Cell) ||
		call.Expected().OperationID != "" && call.Expected().OperationID != request.OperationID ||
		call.Expected().Epoch != 0 && call.Expected().Epoch != request.Epoch {
		return fail(nil)
	}
	original, err := authority.ObserveLeaseRevision(ctx, s.JS, strings.ToLower(identity.Cell), request.LeaseRevision)
	if err != nil {
		return fail(err)
	}
	if original.DeploymentID != identity.DeploymentID || original.CandidateID != call.RuntimeID() || original.OwnerID != request.OwnerID ||
		original.Epoch != request.Epoch || request.ExpiresAt.After(original.ExpiresAt) || request.ExpiresAt.After(source.ExpiresAt()) {
		return fail(nil)
	}
	lease, err := s.Leases.AdmitCurrentLease(ctx, identity.DeploymentID, call.RuntimeID(), request.Epoch)
	if err != nil {
		return fail(err)
	}
	current, err := authority.Observe(ctx, s.JS, strings.ToLower(identity.Cell))
	if err != nil || !current.Ready || current.OwnerID != original.OwnerID || current.Revision < original.Revision {
		return fail(err)
	}
	canonical, err := b.canonical(ctx, s, identity, request.ExpiresAt)
	if err != nil {
		return fail(err)
	}
	originalFacts := canonical
	canonical.OperationID, canonical.RuntimeID, canonical.OwnerID = request.OperationID, call.RuntimeID(), original.OwnerID
	canonical.Epoch, canonical.LeaseRevision, canonical.ExpiresAt = request.Epoch, original.Revision, request.ExpiresAt
	if call.Expected().GrantSHA256 != "" && call.Expected().GrantSHA256 != canonical.SourceGrantSHA256 {
		return fail(nil)
	}
	if err := lease.Guard(ctx); err != nil {
		return fail(err)
	}
	var entry authority.LogEntry
	if request.IntentRevision != 0 {
		entry, err = s.Leases.ReadNetBirdIntent(ctx)
		if err != nil || entry.Sequence != request.IntentRevision || entry.OperationID != request.OperationID || entry.Epoch != request.Epoch ||
			entry.Sequence <= original.Revision || !entry.CreatedAt.Before(request.ExpiresAt) {
			return fail(err)
		}
		var proposal rootoci.NetBirdIntent
		if protocol.DecodeStrict(entry.Payload, &proposal, 1<<20) != nil || !reflect.DeepEqual(proposal, canonical) {
			return fail(nil)
		}
	}
	if err := guard(ctx); err != nil {
		return fail(err)
	}
	currentSource, err := s.Authority.ReadRuntimeAuthority(ctx, s.Accepted, time.Now().UTC())
	if err != nil || currentSource.Identity() != identity || currentSource.Anchor().Digest() != source.Anchor().Digest() ||
		!currentSource.ExpiresAt().Equal(source.ExpiresAt()) {
		return fail(err)
	}
	currentFacts, err := b.canonical(ctx, s, identity, request.ExpiresAt)
	if err != nil || !reflect.DeepEqual(currentFacts, originalFacts) {
		return fail(err)
	}
	if err := lease.Guard(ctx); err != nil {
		return fail(err)
	}
	if err := guard(ctx); err != nil {
		return fail(err)
	}
	rootPin, err := s.current(ctx, "TS_TRUST_ROOTS", "chain")
	if err != nil || rootPin.revision != originalFacts.RootRevision || !bytes.Equal(rootPin.wire, originalFacts.RootChain) {
		return fail(err)
	}
	specPin, err := s.current(ctx, "TS_SERVICE_SET", "current")
	if err != nil || specPin.revision != originalFacts.SpecRevision || !bytes.Equal(specPin.wire, originalFacts.SignedSpec) {
		return fail(err)
	}
	if err := lease.Guard(ctx); err != nil {
		return fail(err)
	}
	if err := guard(ctx); err != nil {
		return fail(err)
	}
	if ctx.Err() != nil || !time.Now().Before(request.ExpiresAt) {
		return fail(ctx.Err())
	}
	canonical.IntentRevision, canonical.IssuedAt = entry.Sequence, entry.CreatedAt
	return rootoci.NetBirdIntentReceipt{Intent: canonical}, nil
}

func (b *Backend) canonical(ctx context.Context, s *Sources, identity bootstrapstart.RuntimeIdentity, deadline time.Time) (rootoci.NetBirdIntent, error) {
	resolver, err := region.DiscoverCurrentFoundation(ctx, b.factory)
	if err != nil {
		return rootoci.NetBirdIntent{}, err
	}
	material, err := resolver.BootstrapMaterial(ctx, identity.Cell)
	if err != nil {
		return rootoci.NetBirdIntent{}, err
	}
	config := material.Config()
	if deadline.After(material.ExpiresAt()) {
		return rootoci.NetBirdIntent{}, rootoci.ErrUnauthorized
	}
	if config.DeploymentID != identity.DeploymentID || config.ClusterID != identity.ClusterID || config.Environment != identity.Environment ||
		config.Cell != strings.ToLower(identity.Cell) || config.Region != identity.OCIRegion {
		return rootoci.NetBirdIntent{}, rootoci.ErrUnauthorized
	}
	root, err := s.current(ctx, "TS_TRUST_ROOTS", "chain")
	if err != nil {
		return rootoci.NetBirdIntent{}, err
	}
	installed, err := bootstrapstart.LoadTrustInputs(s.Accepted)
	if err != nil {
		return rootoci.NetBirdIntent{}, err
	}
	chain, err := trust.DecodeRootChain(root.wire)
	if err != nil || len(chain.Rotations) < len(installed.Chain.Rotations) {
		return rootoci.NetBirdIntent{}, rootoci.ErrUnauthorized
	}
	prefix := chain
	prefix.Rotations = prefix.Rotations[:len(installed.Chain.Rotations)]
	floor, err := trust.VerifyRootChain(installed.Genesis, installed.ChainIdentity, prefix)
	if err != nil || floor.Head != installed.Roots.Head {
		return rootoci.NetBirdIntent{}, rootoci.ErrUnauthorized
	}
	roots, err := trust.VerifyRootChain(installed.Genesis, installed.ChainIdentity, chain)
	if err != nil {
		return rootoci.NetBirdIntent{}, err
	}
	signedSpec, err := s.current(ctx, "TS_SERVICE_SET", "current")
	if err != nil {
		return rootoci.NetBirdIntent{}, err
	}
	spec, err := cellspec.VerifyHistorical(signedSpec.wire, roots.Current, cellspec.Identity{DeploymentID: config.DeploymentID, Environment: config.Environment, Cell: config.Cell})
	if err != nil || !spec.RootSigned {
		return rootoci.NetBirdIntent{}, rootoci.ErrUnauthorized
	}
	hosts := make([]rootoci.NetBirdIntentHost, 0, len(spec.HostGrants))
	for _, grant := range spec.HostGrants {
		role := ""
		if grant.Controller != "" || slices.Contains(grant.Roles, "controller") || slices.Contains(grant.Roles, "nats") {
			role = "controller"
		} else if slices.Contains(grant.Roles, "member") || slices.Contains(grant.Roles, "terrabase") {
			role = "member"
		}
		if role != "" {
			hosts = append(hosts, rootoci.NetBirdIntentHost{Name: grant.Node, PrivateIP: grant.PrivateIP, Role: role})
		}
	}
	slices.SortFunc(hosts, func(a, b rootoci.NetBirdIntentHost) int { return strings.Compare(a.Name, b.Name) })
	return rootoci.NetBirdIntent{Cell: identity.Cell, InstallationID: material.InstallationID(), DeploymentID: identity.DeploymentID,
		SourceGrantSHA256: digest(material.FoundationGrantWire()), MaterialGeneration: material.Generation(),
		SpecGeneration: spec.Generation, SpecSHA256: digest(signedSpec.wire), SpecRevision: signedSpec.revision, RootRevision: root.revision, SubnetCIDR: config.SubnetCIDR, Hosts: hosts,
		SignedSpec: signedSpec.wire, RootChain: root.wire, SourceSlot: identity.Slot, SourceInstanceID: identity.InstanceID,
		ManagerStoreGeneration: entityid.Derive("netbird-foundation-store", material.InstallationID()) + ":1"}, nil
}

// current always reads the stream leader, never a follower's direct KV cache.
type sourceRecord struct {
	wire     []byte
	revision uint64
}

func (s *Sources) current(ctx context.Context, bucket, key string) (sourceRecord, error) {
	options := s.JS.Options()
	var opts []nats.JSOpt
	if options.Domain != "" {
		opts = append(opts, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		opts = append(opts, nats.APIPrefix(options.APIPrefix))
	}
	reader, err := s.JS.Conn().JetStream(opts...)
	if err != nil {
		return sourceRecord{}, err
	}
	subject := "$KV." + bucket + "." + key
	entry, err := reader.GetLastMsg("KV_"+bucket, subject, nats.Context(ctx))
	if err != nil {
		return sourceRecord{}, err
	}
	if entry == nil || entry.Subject != subject || entry.Sequence == 0 || len(entry.Data) == 0 || entry.Header.Get("KV-Operation") != "" || entry.Header.Get(jetstream.MarkerReasonHeader) != "" {
		return sourceRecord{}, rootoci.ErrUnauthorized
	}
	return sourceRecord{wire: bytes.Clone(entry.Data), revision: entry.Sequence}, ctx.Err()
}

func digest(wire []byte) string { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }
func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
