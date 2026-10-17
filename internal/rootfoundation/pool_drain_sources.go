package rootfoundation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// PoolDrainSources contains only actual ROOT-created retained readers.
type PoolDrainSources struct {
	JS          jetstream.JetStream
	Node        *swarmruntime.Node
	Leases      *authority.Reader
	Hosts       *host.Reader
	Authority   *bootstrapstart.CurrentFounderAuthorityReader
	Accepted    bootstrapstart.AcceptedIdentity
	Credentials *rootsecret.ControllerReader
}

func (b *Backend) BindPoolDrain(s PoolDrainSources) error {
	if os.Geteuid() != 0 || b == nil || s.JS == nil || s.JS.Conn() == nil || s.Node == nil || s.Leases == nil || s.Hosts == nil ||
		s.Authority == nil || s.Credentials == nil || s.Accepted.Validate() != nil || s.Credentials.Conn() != s.JS.Conn() ||
		s.Credentials.Context() == nil || s.Credentials.Context().Done() == nil || s.Credentials.Guard(context.Background()) != nil || s.Accepted.Cell != b.cell {
		return ErrScope
	}
	b.poolMu.Lock()
	defer b.poolMu.Unlock()
	if b.poolSources != nil {
		return errors.New("root pool drain sources already bound")
	}
	s.Accepted = s.Accepted.Clone()
	b.poolSources = &s
	return nil
}

type poolDrainSnapshot struct {
	source             drainwire.PoolSource
	specWire, rootWire []byte
	lease              *authority.LeaseAdmission
}

func (b *Backend) poolSnapshot(ctx context.Context, call rootoci.Call) (poolDrainSnapshot, error) {
	var empty poolDrainSnapshot
	s := b.poolSources
	if s == nil || s.Credentials.Context().Err() != nil || s.JS.Conn().IsClosed() {
		return empty, rootoci.ErrPending
	}
	if err := b.guard(ctx, call); err != nil {
		return empty, err
	}
	if err := s.Credentials.Guard(ctx); err != nil {
		return empty, err
	}
	accepted, err := s.Authority.ReadRuntimeAuthority(ctx, s.Accepted, time.Now().UTC())
	if err != nil {
		return empty, err
	}
	identity := accepted.Identity()
	if identity.Cell != b.cell || identity.InstanceID != s.Accepted.InstanceOCID || identity.OCIRegion != b.factory.Region() {
		return empty, ErrScope
	}
	rootWire, err := poolSourceWire(ctx, s.JS, "TS_TRUST_ROOTS", "chain", trust.MaxRootChainBytes)
	if err != nil {
		return empty, err
	}
	chain, err := trust.DecodeRootChain(rootWire)
	if err != nil {
		return empty, err
	}
	installed, err := bootstrapstart.LoadTrustInputs(s.Accepted)
	if err != nil || !chain.Extends(installed.Chain) {
		return empty, errors.Join(ErrScope, err)
	}
	roots, err := trust.VerifyRootChain(installed.Genesis, installed.ChainIdentity, chain)
	if err != nil {
		return empty, err
	}
	specWire, err := poolSourceWire(ctx, s.JS, "TS_SERVICE_SET", "current", cellspec.MaxSignedBytes)
	if err != nil {
		return empty, err
	}
	spec, err := cellspec.VerifyCurrent(specWire, roots.Current, cellspec.Identity{DeploymentID: identity.DeploymentID, Cell: strings.ToLower(b.cell), Environment: identity.Environment}, time.Now().UTC())
	if err != nil || !spec.RootSigned {
		return empty, errors.Join(ErrScope, err)
	}
	observed, err := s.Leases.CurrentLease(ctx)
	if err != nil {
		return empty, err
	}
	if observed.DeploymentID != identity.DeploymentID || call.RuntimeID() != "" && observed.CandidateID != call.RuntimeID() {
		return empty, ErrScope
	}
	lease, err := s.Leases.AdmitCurrentLease(ctx, observed.DeploymentID, observed.CandidateID, observed.Epoch)
	if err != nil {
		return empty, err
	}
	original := lease.Original()
	deadline := original.ExpiresAt
	for _, expiry := range []time.Time{accepted.ExpiresAt(), call.Deadline()} {
		if expiry.Before(deadline) {
			deadline = expiry
		}
	}
	credentialDeadline, ok := s.Credentials.Context().Deadline()
	if !ok {
		return empty, ErrScope
	}
	if credentialDeadline.Before(deadline) {
		deadline = credentialDeadline
	}
	if !time.Now().Before(deadline) {
		return empty, ErrScope
	}
	return poolDrainSnapshot{source: drainwire.PoolSource{ControllerConfigSHA256: s.Accepted.ConfigSHA256["controller.json"],
		CellSpecSHA256: poolDigest(specWire), CellSpecGeneration: spec.Generation, RootSHA256: poolDigest(rootWire),
		ManagerInstanceID: identity.InstanceID, ManagerNodeID: s.Node.ID(), DeploymentID: identity.DeploymentID,
		CandidateID: original.CandidateID, OwnerID: original.OwnerID, Epoch: original.Epoch, LeaseRevision: original.Revision, ExpiresAt: deadline},
		specWire: specWire, rootWire: rootWire, lease: lease}, nil
}

func (b *Backend) guardPoolReceipt(ctx context.Context, call rootoci.Call, receipt drainwire.PoolReceipt) error {
	if !time.Now().Before(receipt.ExpiresAt) {
		return rootoci.ErrPending
	}
	current, err := b.poolSnapshot(ctx, call)
	if err != nil {
		return err
	}
	want, got := receipt.Source, current.source
	if got.LeaseRevision < receipt.PauseBarrierRevision || got.LeaseRevision < want.LeaseRevision || got.ExpiresAt.Before(receipt.ExpiresAt) {
		return ErrScope
	}
	got.LeaseRevision, got.ExpiresAt = want.LeaseRevision, want.ExpiresAt
	if got != want || !bytes.Equal(current.specWire, receipt.CellSpecWire) || !bytes.Equal(current.rootWire, receipt.RootChainWire) {
		return ErrScope
	}
	return current.lease.Guard(ctx)
}

func poolSourceWire(ctx context.Context, js jetstream.JetStream, bucket, key string, limit int) ([]byte, error) {
	options := js.Options()
	var opts []nats.JSOpt
	if options.Domain != "" {
		opts = append(opts, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		opts = append(opts, nats.APIPrefix(options.APIPrefix))
	}
	reader, err := js.Conn().JetStream(opts...)
	if err != nil {
		return nil, err
	}
	subject := "$KV." + bucket + "." + key
	entry, err := reader.GetLastMsg("KV_"+bucket, subject, nats.Context(ctx))
	if err != nil {
		return nil, err
	}
	if entry == nil || entry.Sequence == 0 || entry.Subject != subject || entry.Header.Get("KV-Operation") != "" || entry.Header.Get(jetstream.MarkerReasonHeader) != "" || len(entry.Data) == 0 || len(entry.Data) > limit {
		return nil, ErrScope
	}
	return bytes.Clone(entry.Data), ctx.Err()
}

func poolDigest(wire []byte) string { return fmt.Sprintf("%x", sha256.Sum256(wire)) }
