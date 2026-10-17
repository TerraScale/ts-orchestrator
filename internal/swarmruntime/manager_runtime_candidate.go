package swarmruntime

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
)

// ManagerRuntimeCandidate joins independently read native membership, the
// root-manager signature, original host carrier and actual current regional R3.
// Its public identity is descriptive; only this retained proof can revalidate.
type ManagerRuntimeCandidate struct {
	original                                    context.Context
	control                                     *manager.ControlReader
	local                                       *ControllerHostBinding
	session                                     *host.ManagerRuntimeSession
	lease                                       *authority.LeaseAdmission
	signed                                      host.SignedManagerRuntimeBinding
	certificate, clusterCA                      []byte
	clusterID, slot, sourceDigest, anchorDigest string
	deadline                                    time.Time
}

func (p *ManagerRuntimeCandidate) LeaseEpoch() uint64                   { return p.lease.Epoch() }
func (p *ManagerRuntimeCandidate) Identity() host.ManagerRuntimeBinding { return p.signed.Binding }
func (p *ManagerRuntimeCandidate) ExpiresAt() time.Time                 { return p.deadline }
func (p *ManagerRuntimeCandidate) BindingSHA256() string                { return p.session.BindingSHA256() }
func (p *ManagerRuntimeCandidate) SourceSHA256() string                 { return p.sourceDigest }

func (n *Node) ReadManagerRuntimeCandidate(ctx context.Context, hosts *host.Reader, leases *authority.Reader,
	localBinding *ControllerHostBinding, authenticatedOriginNodeID string,
) (*ManagerRuntimeCandidate, error) {
	if ctx == nil || ctx.Err() != nil || localBinding == nil || localBinding.reader == nil || hosts == nil || leases == nil {
		return nil, errors.New("manager runtime candidate sources unavailable")
	}
	if _, err := localBinding.currentRegistration(ctx); err != nil {
		return nil, err
	}
	current, err := localBinding.reader.ReadRuntimeAuthority(ctx, localBinding.accepted, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	control, err := n.ReadOnlyControlClient(ctx)
	if err != nil {
		return nil, err
	}
	cluster, err := control.ClusterIdentity(ctx)
	if err != nil || cluster == nil {
		return nil, errors.New("manager runtime native cluster unavailable")
	}
	got, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: authenticatedOriginNodeID})
	if err != nil || got == nil || got.Node == nil {
		return nil, errors.New("authenticated manager runtime native origin unavailable")
	}
	session, err := hosts.FindManagerRuntimeSession(ctx, authenticatedOriginNodeID)
	if err != nil {
		return nil, err
	}
	signed, ok := session.SignedBinding()
	if !ok {
		return nil, errors.New("manager runtime original signed carrier unavailable")
	}
	if err := host.VerifySignedManagerRuntimeBinding(signed, got.Node.Certificate.Certificate, cluster.RootCACert, cluster.ID, time.Now().UTC()); err != nil {
		return nil, err
	}
	b, id := signed.Binding, current.Identity()
	if b.NodeID != authenticatedOriginNodeID || b.DeploymentID != id.DeploymentID || b.ClusterID != id.ClusterID ||
		b.Environment != id.Environment || !strings.EqualFold(b.Cell, id.Cell) || b.OCIRegion != id.OCIRegion ||
		b.AnchorSHA256 != current.Anchor().Digest() || b.SourceSHA256 == "" || b.SourceSHA256 != current.ManagerSourceSHA256() {
		return nil, errors.New("manager runtime binding differs from independently current signed regional source")
	}
	lease, err := leases.AdmitRuntimeLease(ctx, b.DeploymentID, b.RuntimeCandidateID)
	if err != nil {
		return nil, err
	}
	deadline := b.ExpiresAt
	for _, expiry := range []time.Time{session.ExpiresAt(), lease.Deadline(), current.ExpiresAt()} {
		if expiry.Before(deadline) {
			deadline = expiry
		}
	}
	if original, ok := ctx.Deadline(); ok && original.Before(deadline) {
		deadline = original
	}
	proof := &ManagerRuntimeCandidate{original: ctx, control: control, local: localBinding, session: session, lease: lease, signed: signed,
		certificate: bytes.Clone(got.Node.Certificate.Certificate), clusterCA: bytes.Clone(cluster.RootCACert), clusterID: cluster.ID,
		slot: got.Node.Spec.Annotations.Name, sourceDigest: current.ManagerSourceSHA256(), anchorDigest: current.Anchor().Digest(), deadline: deadline}
	if err := proof.Revalidate(ctx); err != nil {
		return nil, err
	}
	return proof, nil
}

func (p *ManagerRuntimeCandidate) Revalidate(ctx context.Context) error {
	if p == nil || p.original == nil || ctx == nil || ctx.Err() != nil || p.original.Err() != nil ||
		p.control == nil || p.local == nil || p.session == nil || p.lease == nil || !time.Now().Before(p.deadline) {
		return errors.New("original manager runtime candidate expired or cancelled")
	}
	ctx, cancel := context.WithDeadline(ctx, p.deadline)
	stop := context.AfterFunc(p.original, cancel)
	defer cancel()
	defer stop()
	if _, err := p.local.currentRegistration(ctx); err != nil {
		return err
	}
	current, err := p.local.reader.ReadRuntimeAuthority(ctx, p.local.accepted, time.Now().UTC())
	if err != nil {
		return err
	}
	b, id := p.signed.Binding, current.Identity()
	if current.ManagerSourceSHA256() != p.sourceDigest || current.Anchor().Digest() != p.anchorDigest ||
		b.SourceSHA256 != p.sourceDigest || b.AnchorSHA256 != p.anchorDigest || b.DeploymentID != id.DeploymentID ||
		b.ClusterID != id.ClusterID || b.Environment != id.Environment || !strings.EqualFold(b.Cell, id.Cell) || b.OCIRegion != id.OCIRegion ||
		!slices.Contains(p.local.accepted.ControllerSlots, p.slot) {
		return errors.New("original manager runtime signed regional source changed")
	}
	if err := p.session.Revalidate(ctx); err != nil {
		return err
	}
	registration := p.session.Registration()
	if registration.ID != b.HostID || registration.Node != b.HostNode || registration.Cell != b.Cell || registration.Environment != b.Environment ||
		registration.PublicKey != b.HostPublicKey || registration.NATSUserPublicKey != b.NATSUserPublicKey || registration.Generation != b.RegistrationGeneration ||
		p.session.SessionID() != b.HostSessionID || p.session.SessionEpoch() != b.HostSessionEpoch ||
		p.session.RegistrationRevision() != b.RegistrationRevision || p.session.SourceRevision() <= b.SourceRevision {
		return errors.New("original manager runtime signed host binding differs from actual carrier")
	}
	got, err := p.control.GetNode(ctx, &api.GetNodeRequest{NodeID: b.NodeID})
	if err != nil || got == nil || got.Node == nil {
		return errors.New("original manager runtime native member unavailable")
	}
	native := got.Node
	if native.ID != b.NodeID || native.Role != api.NodeRoleManager || native.Spec.DesiredRole != api.NodeRoleManager ||
		native.Spec.Membership != api.NodeMembershipAccepted || native.Status.State != api.NodeStatus_READY ||
		native.Spec.Annotations.Name != p.slot || native.Spec.Annotations.Labels[LabelInstanceID] != b.InstanceID ||
		native.Spec.Annotations.Labels[LabelRegion] != b.OCIRegion || native.Spec.Annotations.Labels[LabelHostRole] != "manager" ||
		native.Spec.Annotations.Labels[LabelExecutionScope] != "platform" || native.Certificate.CN != b.NodeID ||
		native.Certificate.Role != api.NodeRoleManager || !bytes.Equal(native.Certificate.Certificate, p.certificate) {
		return errors.New("original manager runtime native identity changed")
	}
	cluster, err := p.control.ClusterIdentity(ctx)
	if err != nil || cluster == nil || cluster.ID != p.clusterID || !bytes.Equal(cluster.RootCACert, p.clusterCA) {
		return errors.New("original manager runtime native cluster changed")
	}
	if err := host.VerifySignedManagerRuntimeBinding(p.signed, p.certificate, p.clusterCA, p.clusterID, time.Now().UTC()); err != nil {
		return err
	}
	if err := p.lease.Guard(ctx); err != nil {
		return err
	}
	if err := p.session.Revalidate(ctx); err != nil {
		return err
	}
	fresh, err := p.local.reader.ReadRuntimeAuthority(ctx, p.local.accepted, time.Now().UTC())
	if err != nil || fresh.Identity() != current.Identity() || fresh.Anchor().Digest() != p.anchorDigest || fresh.ManagerSourceSHA256() != p.sourceDigest {
		return errors.New("original manager runtime source changed during native and lease verification")
	}
	if !time.Now().Before(p.deadline) || p.original.Err() != nil {
		return errors.New("original manager runtime candidate expired")
	}
	return ctx.Err()
}
