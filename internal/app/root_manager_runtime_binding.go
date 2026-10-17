package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

type rootManagerRuntimeBinding struct {
	signed  host.SignedManagerRuntimeBinding
	session context.Context
	digest  string
}

type rootManagerRuntimeObservation struct {
	ctx      context.Context
	payload  host.ManagerRuntimeBinding
	existing *host.SignedManagerRuntimeBinding
	guard    func(context.Context) error
	readback func(context.Context, host.SignedManagerRuntimeBinding) error
}

func (authority *rootOCIAuthority) withManagerRuntimeObservation(ctx context.Context, process *rootOCIProcess,
	binding *swarmruntime.ControllerHostBinding, identity host.HostRuntimeIdentity, current bootstrapstart.RuntimeAuthority,
	consume func(rootManagerRuntimeObservation) error,
) error {
	source, sources := authority.ownhost, authority.sources
	if process == nil || process == authority.child || sources == nil || source.node == nil || source.agent == nil ||
		source.session == nil || source.session.Err() != nil || ctx == nil || ctx.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return rootoci.ErrUnauthorized
	}
	for _, expiry := range []time.Time{identity.ExpiresAt(), current.ExpiresAt(), sources.deadline} {
		deadline = earlier(deadline, expiry)
	}
	ctx, cancelOriginal := context.WithDeadline(ctx, deadline)
	defer cancelOriginal()
	binary, err := authority.readVerifiedBinary(ctx, process.witness)
	if err != nil {
		return err
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
	deadline = earlier(deadline, certificate.NotAfter)
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
	if registration.ID != binding.HostID() || registration.Cell != worker.Cell || !strings.EqualFold(worker.Cell, current.Identity().Cell) ||
		registration.Node != worker.HostNode || registration.PublicKey != worker.HostPublicKey ||
		registration.NATSUserPublicKey != worker.NATSUserPublicKey || registration.Generation != worker.RegistrationGeneration ||
		snapshot.SessionID() != worker.HostSessionID || snapshot.SessionEpoch() != identity.SessionEpoch() ||
		snapshot.RegistrationRevision() == 0 || snapshot.SourceRevision() == 0 {
		return rootoci.ErrUnauthorized
	}
	candidate := entityid.Derive("controller-runtime", process.witness.Binding())
	acceptance := sha256.Sum256(authority.encoded)
	certificateDigest := sha256.Sum256(block.Bytes)
	clusterDigest := sha256.Sum256(cluster.RootCACert)
	payload := host.ManagerRuntimeBinding{Version: 1,
		DeploymentID: current.Identity().DeploymentID, ClusterID: current.Identity().ClusterID, SwarmClusterID: cluster.ID,
		Environment: current.Identity().Environment, Cell: worker.Cell, OCIRegion: current.Identity().OCIRegion,
		NodeID: source.nodeID, InstanceID: worker.InstanceID, HostID: registration.ID, HostNode: worker.HostNode,
		HostSessionID: worker.HostSessionID, HostSessionEpoch: snapshot.SessionEpoch(), RegistrationGeneration: registration.Generation,
		RegistrationRevision: snapshot.RegistrationRevision(), SourceRevision: snapshot.SourceRevision(),
		HostPublicKey: worker.HostPublicKey, NATSUserPublicKey: worker.NATSUserPublicKey, RuntimeCandidateID: candidate, BinarySHA256: binary.SHA256,
		AcceptanceSHA256: hex.EncodeToString(acceptance[:]), AnchorSHA256: current.Anchor().Digest(), SourceSHA256: current.ManagerSourceSHA256(),
		CertificateSHA256: hex.EncodeToString(certificateDigest[:]), ClusterCASHA256: hex.EncodeToString(clusterDigest[:]), IssuedAt: time.Now().UTC(), ExpiresAt: deadline}
	guard := func(effect context.Context) error {
		if effect == nil || effect.Err() != nil || !time.Now().Before(deadline) || source.session.Err() != nil || authority.ctx.Err() != nil ||
			authority.verifyMarker() != nil || authority.verifyProcess(effect, process) != nil {
			return rootoci.ErrUnauthorized
		}
		measured, err := authority.readVerifiedBinary(effect, process.witness)
		if err != nil || measured.SHA256 != payload.BinarySHA256 {
			return rootoci.ErrUnauthorized
		}
		if err := sources.guard(effect); err != nil {
			return err
		}
		fresh, err := source.reader.ReadRuntimeAuthority(effect, authority.accepted, time.Now().UTC())
		if err != nil || fresh.Identity() != current.Identity() || fresh.Anchor().Digest() != payload.AnchorSHA256 || fresh.ManagerSourceSHA256() != payload.SourceSHA256 || fresh.ExpiresAt().Before(deadline) {
			return rootoci.ErrUnauthorized
		}
		if err := binding.VerifyRegistration(effect, registration); err != nil {
			return err
		}
		if err := snapshot.Revalidate(effect); err != nil {
			return err
		}
		freshIdentity, err := source.agent.RuntimeWorkerIdentity(binding.Identity().InstanceID, source.nodeID)
		if err != nil || freshIdentity.Identity() != worker || freshIdentity.SessionEpoch() != identity.SessionEpoch() || freshIdentity.ExpiresAt().Before(deadline) {
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
		measured, err = authority.readVerifiedBinary(effect, process.witness)
		if err != nil || measured.SHA256 != payload.BinarySHA256 {
			return rootoci.ErrUnauthorized
		}
		return nil
	}
	if err := guard(ctx); err != nil {
		return err
	}
	readback := func(ctx context.Context, signed host.SignedManagerRuntimeBinding) error {
		published, err := sources.hosts.ReadManagerRuntimeSession(ctx, worker.HostNode)
		if err != nil {
			return err
		}
		actual, found := published.SignedBinding()
		if !found || !reflect.DeepEqual(actual, signed) || !reflect.DeepEqual(published.Registration(), registration) ||
			published.SessionID() != worker.HostSessionID || published.SessionEpoch() != identity.SessionEpoch() ||
			published.RegistrationRevision() != signed.Binding.RegistrationRevision || published.SourceRevision() <= signed.Binding.SourceRevision ||
			published.ExpiresAt().Before(signed.Binding.ExpiresAt) {
			return rootoci.ErrUnauthorized
		}
		snapshot = published
		return guard(ctx)
	}
	var existing *host.SignedManagerRuntimeBinding
	if signed, found := snapshot.SignedBinding(); found {
		existing = &signed
	}
	return consume(rootManagerRuntimeObservation{ctx: ctx, payload: payload, existing: existing, guard: guard, readback: readback})
}

// Only the dedicated root producer calls this method. Request authorization and
// held Call guards only validate an already published immutable observation.
func (authority *rootOCIAuthority) publishManagerRuntimeBinding(ctx context.Context, process *rootOCIProcess,
	binding *swarmruntime.ControllerHostBinding, identity host.HostRuntimeIdentity, current bootstrapstart.RuntimeAuthority,
) error {
	return authority.withManagerRuntimeObservation(ctx, process, binding, identity, current, func(observation rootManagerRuntimeObservation) error {
		if retained := process.managerBinding; retained != nil && retained.session == authority.ownhost.session {
			old, expected := retained.signed.Binding, observation.payload
			expected.SourceRevision, expected.IssuedAt, expected.ExpiresAt = old.SourceRevision, old.IssuedAt, old.ExpiresAt
			if old == expected && old.SourceRevision <= observation.payload.SourceRevision &&
				!old.ExpiresAt.After(observation.payload.ExpiresAt) && time.Now().Before(old.ExpiresAt) {
				ctx, cancel := context.WithDeadline(observation.ctx, old.ExpiresAt)
				defer cancel()
				return observation.readback(ctx, retained.signed)
			}
			if observation.payload.SourceRevision <= old.SourceRevision {
				return rootoci.ErrUnauthorized
			}
		} else if old := observation.existing; old != nil && old.Binding.RuntimeCandidateID == observation.payload.RuntimeCandidateID &&
			old.Binding.HostSessionID == observation.payload.HostSessionID && old.Binding.HostSessionEpoch == observation.payload.HostSessionEpoch {
			// Lost local publication state cannot grant this observation a new lifetime.
			return rootoci.ErrUnauthorized
		}
		signed, err := authority.ownhost.node.SignManagerRuntimeBinding(observation.ctx, observation.payload, observation.guard)
		if err != nil {
			return err
		}
		if err := observation.guard(observation.ctx); err != nil {
			return err
		}
		wire, err := json.Marshal(signed, json.Deterministic(true))
		if err != nil {
			return err
		}
		digest := sha256.Sum256(wire)
		// Retain the original before dispatch: an ambiguous setter is read back, never retransmitted.
		process.managerBinding = &rootManagerRuntimeBinding{signed: signed, session: authority.ownhost.session, digest: hex.EncodeToString(digest[:])}
		if err := authority.ownhost.agent.SetManagerRuntimeBinding(observation.ctx, signed); err != nil {
			return err
		}
		return observation.readback(observation.ctx, signed)
	})
}

// This source supervisor deliberately observes independently of request guards.
func (authority *rootOCIAuthority) runManagerRuntimeBindings(ctx context.Context) {
	for ctx.Err() == nil {
		if err := authority.observeManagerRuntimeBinding(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "root manager runtime observation pending", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (authority *rootOCIAuthority) observeManagerRuntimeBinding(ctx context.Context) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || authority.ctx.Err() != nil || authority.sources == nil {
		return rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, earlier(time.Now().Add(30*time.Second), authority.sources.deadline))
	stopAuthority := context.AfterFunc(authority.ctx, cancel)
	stopSources := context.AfterFunc(authority.sources.lease, cancel)
	defer func() { stopAuthority(); stopSources(); cancel() }()
	if err := authority.sources.guard(ctx); err != nil {
		return err
	}
	service, err := observeRootOCIController(ctx)
	if err != nil {
		return err
	}
	process, err := authority.currentProcess(ctx, nativerootoci.Peer{PID: service.pid, UID: authority.uid, GID: authority.gid})
	if err != nil || process == authority.child || authority.verifyMarker() != nil || authority.verifyBinary(process.witness) != nil || authority.verifyProcess(ctx, process) != nil {
		return rootoci.ErrUnauthorized
	}
	// currentProcess may read ownhost generation, so resolve it before this lock.
	source := authority.ownhost
	source.mu.RLock()
	defer source.mu.RUnlock()
	if source.agent == nil || source.node == nil || source.session == nil || source.session.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	stopSession := context.AfterFunc(source.session, cancel)
	defer stopSession()
	current, err := source.reader.ReadRuntimeAuthority(ctx, authority.accepted, time.Now().UTC())
	if err != nil {
		return err
	}
	ctx, cancelCurrent := context.WithDeadline(ctx, current.ExpiresAt())
	defer cancelCurrent()
	binding, err := swarmruntime.ReadControllerHostBinding(ctx, source.reader, authority.accepted, source.agent, source.transport.Request, source.transport.Response)
	if err != nil || binding.ControllerSlot() != authority.accepted.Slot || binding.Identity() != current.Identity() {
		return rootoci.ErrUnauthorized
	}
	identity, err := source.agent.RuntimeWorkerIdentity(binding.Identity().InstanceID, source.nodeID)
	if err != nil {
		return err
	}
	process.runtime = true
	return authority.publishManagerRuntimeBinding(ctx, process, binding, identity, current)
}

func (authority *rootOCIAuthority) verifyManagerRuntimeBinding(ctx context.Context, process *rootOCIProcess,
	binding *swarmruntime.ControllerHostBinding, identity host.HostRuntimeIdentity, current bootstrapstart.RuntimeAuthority,
) error {
	retained := process.managerBinding
	if retained == nil || retained.session != authority.ownhost.session || retained.digest == "" {
		return rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, retained.signed.Binding.ExpiresAt)
	defer cancel()
	return authority.withManagerRuntimeObservation(ctx, process, binding, identity, current, func(observation rootManagerRuntimeObservation) error {
		old, expected := retained.signed.Binding, observation.payload
		expected.SourceRevision, expected.IssuedAt, expected.ExpiresAt = old.SourceRevision, old.IssuedAt, old.ExpiresAt
		if old != expected || old.SourceRevision > observation.payload.SourceRevision || old.ExpiresAt.After(observation.payload.ExpiresAt) || !time.Now().Before(old.ExpiresAt) {
			return rootoci.ErrUnauthorized
		}
		return observation.readback(observation.ctx, retained.signed)
	})
}
