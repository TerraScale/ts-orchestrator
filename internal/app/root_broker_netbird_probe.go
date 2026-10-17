package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/networkplan"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
)

func (broker *rootBrokerRuntime) probeNetBirdController(parent context.Context, request rootBrokerNetBirdProbeRequest, callGuard func() error) (*rootBrokerNetBirdProbeResponse, error) {
	meshIP, err := netip.ParseAddr(request.MeshIP)
	if parent == nil || parent.Err() != nil || callGuard == nil || naming.Validate(request.Node) != nil ||
		err != nil || meshIP.String() != request.MeshIP || !meshIP.Is4() ||
		!netip.MustParsePrefix(networkplan.Mesh).Contains(meshIP) || request.DNS != request.Node+".nb.ts.internal" {
		return nil, rootoci.ErrUnauthorized
	}
	ctx, cancel := broker.operationContext(parent)
	defer cancel()
	broker.authority.mu.Lock()
	sources, ownhost := broker.authority.sources, broker.authority.ownhost
	accepted := broker.authority.accepted.Clone()
	if sources == nil || sources.spec == nil || ownhost == nil {
		broker.authority.mu.Unlock()
		return nil, rootoci.ErrUnavailable
	}
	ownhost.mu.RLock()
	node, reader, originalSession := ownhost.node, ownhost.reader, ownhost.session
	ownhost.mu.RUnlock()
	broker.authority.mu.Unlock()
	if node == nil || reader == nil || originalSession == nil || originalSession.Err() != nil {
		return nil, rootoci.ErrUnauthorized
	}
	stopSource := context.AfterFunc(sources.lease, cancel)
	stopSession := context.AfterFunc(originalSession, cancel)
	defer func() { stopSource(); stopSession() }()
	var limits []context.CancelFunc
	defer func() {
		for _, stop := range limits {
			stop()
		}
	}()
	limit := func(deadline time.Time) error {
		var stop context.CancelFunc
		ctx, stop = context.WithDeadline(ctx, deadline)
		limits = append(limits, stop)
		return ctx.Err()
	}
	var signed cellspec.Signed
	if protocol.DecodeStrict(sources.spec.Value(), &signed, cellspec.MaxSignedBytes) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	envelope, err := trust.DecodeEnvelope(signed.Spec)
	if err != nil || limit(envelope.ExpiresAt) != nil || callGuard() != nil || sources.guard(ctx) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	now := time.Now().UTC()
	verified, err := sources.specs.verify(sources.spec.Value(), &now)
	if err != nil || !verified.RootSigned || verified.NetBird == nil || verified.NetBird.Validate(broker.cfg.NATS.Cell) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	grant, ok := verified.Grant(request.Node)
	if !ok || grant.Controller == "" || verified.NetBird.Enrollment.PeerNames[grant.PrivateIP] != request.Node {
		return nil, rootoci.ErrUnauthorized
	}
	session, err := sources.hosts.ReadManagerRuntimeSession(ctx, request.Node)
	if err != nil {
		return nil, err
	}
	signedBinding, found := session.SignedBinding()
	if !found || limit(session.ExpiresAt()) != nil || limit(signedBinding.Binding.ExpiresAt) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	binding, identity := signedBinding.Binding, broker.origin.Identity()
	if binding.DeploymentID != identity.DeploymentID || binding.ClusterID != identity.ClusterID ||
		binding.Environment != identity.Environment || !strings.EqualFold(binding.Cell, identity.Cell) ||
		binding.OCIRegion != identity.OCIRegion || binding.HostNode != request.Node ||
		binding.AnchorSHA256 != broker.origin.Anchor().Digest() || binding.SourceSHA256 != broker.origin.ManagerSourceSHA256() {
		return nil, rootoci.ErrUnauthorized
	}
	control, err := node.ReadOnlyControlClient(ctx)
	if err != nil {
		return nil, err
	}
	cluster, err := control.ClusterIdentity(ctx)
	if err != nil || cluster == nil {
		return nil, rootoci.ErrUnauthorized
	}
	member, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: binding.NodeID})
	if err != nil || member == nil || member.Node == nil {
		return nil, rootoci.ErrUnauthorized
	}
	certificate, clusterCA, clusterID := bytes.Clone(member.Node.Certificate.Certificate), bytes.Clone(cluster.RootCACert), cluster.ID
	if host.VerifySignedManagerRuntimeBinding(signedBinding, certificate, clusterCA, clusterID, time.Now().UTC()) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	// Native ancestor expiry also bounds pending transport, not just revalidation.
	for _, wire := range [][]byte{certificate, clusterCA} {
		for len(wire) != 0 {
			block, rest := pem.Decode(wire)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, rootoci.ErrUnauthorized
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil || limit(cert.NotAfter) != nil {
				return nil, rootoci.ErrUnauthorized
			}
			wire = bytes.TrimSpace(rest)
		}
	}
	for _, wire := range signedBinding.CertificateChain {
		certificate, err := x509.ParseCertificate(wire)
		if err != nil || limit(certificate.NotAfter) != nil {
			return nil, rootoci.ErrUnauthorized
		}
	}
	recipient, err := bootstrapstart.ReadControllerHostRecipient(ctx, reader, accepted, sources.spec.Value(), request.Node, binding.InstanceID, grant.PrivateIP)
	if err != nil || recipient.ControllerSlot() != grant.Controller || limit(recipient.ExpiresAt()) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	deadline, _ := ctx.Deadline()
	live := func() error {
		if ctx.Err() != nil || parent.Err() != nil || sources.lease.Err() != nil || originalSession.Err() != nil || !time.Now().Before(deadline) {
			return rootoci.ErrUnauthorized
		}
		return nil
	}
	guard := func(effect context.Context) error {
		if effect == nil || effect.Err() != nil || live() != nil || callGuard() != nil {
			return rootoci.ErrUnauthorized
		}
		broker.authority.mu.Lock()
		unchanged := broker.authority.sources == sources && broker.authority.ownhost == ownhost
		ownhost.mu.RLock()
		unchanged = unchanged && ownhost.node == node && ownhost.reader == reader && ownhost.session == originalSession
		ownhost.mu.RUnlock()
		broker.authority.mu.Unlock()
		if !unchanged || broker.guard(effect) != nil || sources.guard(effect) != nil || session.Revalidate(effect) != nil {
			return rootoci.ErrUnauthorized
		}
		registration := session.Registration()
		if registration.ID != binding.HostID || registration.Node != request.Node || registration.Cell != binding.Cell ||
			registration.Environment != binding.Environment || registration.PublicKey != binding.HostPublicKey ||
			registration.NATSUserPublicKey != binding.NATSUserPublicKey || registration.Generation != binding.RegistrationGeneration ||
			session.SessionID() != binding.HostSessionID || session.SessionEpoch() != binding.HostSessionEpoch ||
			session.RegistrationRevision() != binding.RegistrationRevision || session.SourceRevision() <= binding.SourceRevision ||
			recipient.VerifyRegistration(effect, registration) != nil || live() != nil {
			return rootoci.ErrUnauthorized
		}
		current, err := control.GetNode(effect, &api.GetNodeRequest{NodeID: binding.NodeID})
		if err != nil || current == nil || current.Node == nil || live() != nil {
			return rootoci.ErrUnauthorized
		}
		native := current.Node
		if native.ID != binding.NodeID || native.Role != api.NodeRoleManager || native.Spec.DesiredRole != api.NodeRoleManager ||
			native.Spec.Membership != api.NodeMembershipAccepted || native.Status.State != api.NodeStatus_READY ||
			native.Spec.Annotations.Name != grant.Controller || native.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != binding.InstanceID ||
			native.Spec.Annotations.Labels[swarmruntime.LabelRegion] != binding.OCIRegion || native.Spec.Annotations.Labels[swarmruntime.LabelHostRole] != "manager" ||
			native.Spec.Annotations.Labels[swarmruntime.LabelExecutionScope] != "platform" || native.Certificate.CN != binding.NodeID ||
			native.Certificate.Role != api.NodeRoleManager || !bytes.Equal(native.Certificate.Certificate, certificate) {
			return rootoci.ErrUnauthorized
		}
		currentCluster, err := control.ClusterIdentity(effect)
		if err != nil || currentCluster == nil || currentCluster.ID != clusterID || !bytes.Equal(currentCluster.RootCACert, clusterCA) ||
			host.VerifySignedManagerRuntimeBinding(signedBinding, certificate, clusterCA, clusterID, time.Now().UTC()) != nil || live() != nil {
			return rootoci.ErrUnauthorized
		}
		route, err := netbird.BrokerRoute(effect, request.Node)
		if err != nil || route != meshIP || live() != nil || session.Revalidate(effect) != nil || sources.guard(effect) != nil || callGuard() != nil {
			return rootoci.ErrUnauthorized
		}
		return live()
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if guard(ctx) != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-done }()
	serverName := natscell.ServerName(broker.cfg.NATS.Cell, grant.Controller)
	transportExpiry, err := broker.runtime.ProbeNetBirdController(ctx, meshIP, grant.PrivateIP, serverName, guard)
	if err != nil {
		return nil, err
	}
	if err := guard(ctx); err != nil || transportExpiry.IsZero() || !time.Now().Before(transportExpiry) {
		return nil, rootoci.ErrUnauthorized
	}
	if err := live(); err != nil {
		return nil, err
	}
	return &rootBrokerNetBirdProbeResponse{Target: request, ServerName: serverName, ExpiresAt: earlier(deadline, transportExpiry).UTC()}, nil
}
