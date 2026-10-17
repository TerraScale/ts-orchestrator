package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

type rootManagerRuntimeBinding struct {
	signed  host.SignedManagerRuntimeBinding
	session context.Context
}

// The ordinary response key cannot certify a process candidate. Only the actual
// root-owned Node signs the process and enrolled host observed together here.
func (authority *rootOCIAuthority) publishManagerRuntimeBinding(ctx context.Context, process *rootOCIProcess,
	binding *swarmruntime.ControllerHostBinding, identity host.HostRuntimeIdentity, current bootstrapstart.RuntimeAuthority,
) error {
	source, sources := authority.ownhost, authority.sources
	if process == nil || process == authority.child || sources == nil || source.node == nil || source.agent == nil ||
		source.session == nil || source.session.Err() != nil || ctx == nil || ctx.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	control, err := source.node.ReadOnlyControlClient(ctx)
	if err != nil {
		return err
	}
	got, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: source.nodeID})
	if err != nil || got == nil || got.Node == nil {
		return rootoci.ErrUnauthorized
	}
	manager := got.Node
	block, _ := pem.Decode(manager.Certificate.Certificate)
	if block == nil || block.Type != "CERTIFICATE" {
		return rootoci.ErrUnauthorized
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return rootoci.ErrUnauthorized
	}
	for _, expiry := range []time.Time{identity.ExpiresAt(), current.ExpiresAt(), sources.deadline, certificate.NotAfter} {
		deadline = earlier(deadline, expiry)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	cluster, err := control.ClusterIdentity(ctx)
	if err != nil || cluster == nil || cluster.ID == "" || len(cluster.RootCACert) == 0 {
		return rootoci.ErrUnauthorized
	}
	worker := identity.Identity()
	snapshot, err := sources.hosts.ReadManagerRuntimeSession(ctx, worker.HostNode)
	if err != nil {
		return err
	}
	deadline = earlier(deadline, snapshot.ExpiresAt())
	ctx, cancelSnapshot := context.WithDeadline(ctx, deadline)
	defer cancelSnapshot()
	registration := snapshot.Registration()
	if registration.ID != binding.HostID() || registration.Node != worker.HostNode || registration.PublicKey != worker.HostPublicKey ||
		registration.NATSUserPublicKey != worker.NATSUserPublicKey || registration.Generation != worker.RegistrationGeneration ||
		snapshot.SessionID() != worker.HostSessionID || snapshot.SessionEpoch() != identity.SessionEpoch() ||
		snapshot.RegistrationRevision() == 0 || snapshot.SourceRevision() == 0 {
		return rootoci.ErrUnauthorized
	}
	candidate := entityid.Derive("controller-runtime", process.witness.Binding())
	acceptance := sha256.Sum256(authority.encoded)
	certificateDigest := sha256.Sum256(block.Bytes)
	payload := host.ManagerRuntimeBinding{Version: 1,
		DeploymentID: current.Identity().DeploymentID, ClusterID: current.Identity().ClusterID, SwarmClusterID: cluster.ID,
		Environment: current.Identity().Environment, Cell: strings.ToUpper(current.Identity().Cell), OCIRegion: current.Identity().OCIRegion,
		NodeID: source.nodeID, InstanceID: worker.InstanceID, HostID: registration.ID, HostNode: worker.HostNode,
		HostSessionID: worker.HostSessionID, HostSessionEpoch: snapshot.SessionEpoch(), RegistrationGeneration: registration.Generation,
		RegistrationRevision: snapshot.RegistrationRevision(), SourceRevision: snapshot.SourceRevision(),
		HostPublicKey: worker.HostPublicKey, NATSUserPublicKey: worker.NATSUserPublicKey, RuntimeCandidateID: candidate,
		AcceptanceSHA256: hex.EncodeToString(acceptance[:]), AnchorSHA256: current.Anchor().Digest(), SourceSHA256: current.ManagerSourceSHA256(),
		CertificateSHA256: hex.EncodeToString(certificateDigest[:]), IssuedAt: time.Now().UTC(), ExpiresAt: deadline}
	guard := func(effect context.Context) error {
		if effect == nil || effect.Err() != nil || !time.Now().Before(deadline) || source.session.Err() != nil || authority.ctx.Err() != nil ||
			authority.verifyMarker() != nil || authority.verifyBinary(process.witness) != nil || authority.verifyProcess(effect, process) != nil {
			return rootoci.ErrUnauthorized
		}
		if err := sources.guard(effect); err != nil {
			return err
		}
		fresh, err := source.reader.ReadRuntimeAuthority(effect, authority.accepted, time.Now().UTC())
		if err != nil || fresh.Identity() != current.Identity() || fresh.Anchor().Digest() != payload.AnchorSHA256 || fresh.ManagerSourceSHA256() != payload.SourceSHA256 {
			return rootoci.ErrUnauthorized
		}
		if err := binding.VerifyRegistration(effect, registration); err != nil {
			return err
		}
		if err := snapshot.Revalidate(effect); err != nil {
			return err
		}
		freshIdentity, err := source.agent.RuntimeWorkerIdentity(binding.Identity().InstanceID, source.nodeID)
		if err != nil || freshIdentity.Identity() != worker || freshIdentity.SessionEpoch() != identity.SessionEpoch() {
			return rootoci.ErrUnauthorized
		}
		native, err := control.GetNode(effect, &api.GetNodeRequest{NodeID: source.nodeID})
		if err != nil || native == nil || native.Node == nil {
			return rootoci.ErrUnauthorized
		}
		node := native.Node
		if node.ID != source.nodeID || node.ID != worker.NodeID || node.Role != api.NodeRoleManager || node.Spec.DesiredRole != api.NodeRoleManager ||
			node.Spec.Membership != api.NodeMembershipAccepted || node.Status.State != api.NodeStatus_READY ||
			node.Spec.Annotations.Name != authority.accepted.Slot || node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != worker.InstanceID ||
			node.Spec.Annotations.Labels[swarmruntime.LabelRegion] != payload.OCIRegion || node.Spec.Annotations.Labels[swarmruntime.LabelHostRole] != "manager" ||
			node.Certificate.CN != node.ID || node.Certificate.Role != api.NodeRoleManager || !bytes.Equal(node.Certificate.Certificate, manager.Certificate.Certificate) {
			return rootoci.ErrUnauthorized
		}
		freshCluster, err := control.ClusterIdentity(effect)
		if err != nil || freshCluster == nil || freshCluster.ID != cluster.ID || !bytes.Equal(freshCluster.RootCACert, cluster.RootCACert) {
			return rootoci.ErrUnauthorized
		}
		if err := sources.guard(effect); err != nil {
			return err
		}
		if effect.Err() != nil || source.session.Err() != nil || !time.Now().Before(deadline) || authority.verifyProcess(effect, process) != nil {
			return rootoci.ErrUnauthorized
		}
		return nil
	}
	if err := guard(ctx); err != nil {
		return err
	}
	if retained := process.managerBinding; retained != nil && retained.session == source.session {
		old := retained.signed.Binding
		if old.RuntimeCandidateID == candidate && old.HostSessionID == worker.HostSessionID && old.HostSessionEpoch == payload.HostSessionEpoch &&
			old.RegistrationRevision == payload.RegistrationRevision && old.SourceSHA256 == payload.SourceSHA256 &&
			old.CertificateSHA256 == payload.CertificateSHA256 && time.Now().Before(old.ExpiresAt) {
			if err := source.agent.SetManagerRuntimeBinding(retained.signed); err != nil {
				return err
			}
			return guard(ctx)
		}
		if payload.SourceRevision <= old.SourceRevision {
			return rootoci.ErrUnauthorized
		}
	}
	signed, err := source.node.SignManagerRuntimeBinding(ctx, payload, guard)
	if err != nil {
		return err
	}
	if err := guard(ctx); err != nil {
		return err
	}
	if err := source.agent.SetManagerRuntimeBinding(signed); err != nil {
		return err
	}
	process.managerBinding = &rootManagerRuntimeBinding{signed: signed, session: source.session}
	return guard(ctx)
}
