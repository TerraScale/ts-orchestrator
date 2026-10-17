package swarmruntime

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
)

// ManagerHostRecipient proves a target's native membership and enrolled host.
// It never supplies an origin regional lease or permission to change the target.
type ManagerHostRecipient struct {
	original, lifetime                    context.Context
	control                               *manager.ControlReader
	local                                 *ControllerHostBinding
	recipient                             *bootstrapstart.ControllerHostRecipient
	session                               *host.ManagerRuntimeSession
	query                                 WorkerRegistrationQuery
	enrollment                            WorkerRegistrationSnapshot
	signed                                host.SignedManagerRuntimeBinding
	certificate, clusterCA                []byte
	clusterID, sourceDigest, anchorDigest string
	deadline                              time.Time
}

func (p *ManagerHostRecipient) Identity() host.ManagerRuntimeBinding { return p.signed.Binding }
func (p *ManagerHostRecipient) BindingSHA256() string                { return p.session.BindingSHA256() }
func (p *ManagerHostRecipient) SourceSHA256() string                 { return p.sourceDigest }
func (p *ManagerHostRecipient) ExpiresAt() time.Time                 { return p.deadline }

func (n *Node) ReadManagerHostRecipient(ctx context.Context, hosts *host.Reader, localBinding *ControllerHostBinding,
	recipient *bootstrapstart.ControllerHostRecipient, nodeID string, query WorkerRegistrationQuery,
) (_ *ManagerHostRecipient, resultErr error) {
	if n == nil || ctx == nil || ctx.Err() != nil || hosts == nil || localBinding == nil || localBinding.reader == nil || recipient == nil || query.Swarm != nil {
		return nil, errors.New("manager host recipient sources unavailable")
	}
	p := &ManagerHostRecipient{original: ctx, local: localBinding, recipient: recipient,
		query: WorkerRegistrationQuery{Request: bytes.Clone(query.Request), Response: bytes.Clone(query.Response)}}
	var limits []context.CancelFunc
	defer func() {
		if resultErr != nil {
			for _, cancel := range limits {
				cancel()
			}
		}
	}()
	limit := func(deadline time.Time) error {
		if existing, ok := ctx.Deadline(); !ok || deadline.Before(existing) {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline)
			limits = append(limits, cancel)
		}
		return ctx.Err()
	}
	if err := limit(recipient.Deadline()); err != nil {
		return nil, err
	}
	_, _, response, err := p.readEnrollmentResponse()
	if err != nil {
		return nil, err
	}
	if err := limit(response.ExpiresAt); err != nil {
		return nil, err
	}
	current, err := localBinding.reader.ReadRuntimeAuthority(ctx, localBinding.accepted, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := limit(current.ExpiresAt()); err != nil {
		return nil, err
	}
	if _, err := localBinding.currentRegistration(ctx); err != nil {
		return nil, err
	}
	p.enrollment, err = p.readEnrollment(ctx)
	if err != nil {
		return nil, err
	}
	if err := recipient.VerifyRegistration(ctx, p.enrollment.Registration); err != nil {
		return nil, err
	}
	control, err := n.ReadOnlyControlClient(ctx)
	if err != nil {
		return nil, err
	}
	cluster, err := control.ClusterIdentity(ctx)
	if err != nil || cluster == nil {
		return nil, errors.New("manager host recipient native cluster unavailable")
	}
	got, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: nodeID})
	if err != nil || got == nil || got.Node == nil {
		return nil, errors.New("manager host recipient native target unavailable")
	}
	session, err := hosts.FindManagerRuntimeSession(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	signed, ok := session.SignedBinding()
	if !ok {
		return nil, errors.New("manager host recipient original signed carrier unavailable")
	}
	for _, expiry := range []time.Time{session.ExpiresAt(), signed.Binding.ExpiresAt} {
		if err := limit(expiry); err != nil {
			return nil, err
		}
	}
	if err := host.VerifySignedManagerRuntimeBinding(signed, got.Node.Certificate.Certificate, cluster.RootCACert, cluster.ID, time.Now().UTC()); err != nil {
		return nil, err
	}
	if signed.Binding.NodeID != nodeID {
		return nil, errors.New("manager host recipient differs from its exact native selector")
	}
	p.control, p.session, p.signed = control, session, signed
	p.certificate, p.clusterCA, p.clusterID = bytes.Clone(got.Node.Certificate.Certificate), bytes.Clone(cluster.RootCACert), cluster.ID
	p.sourceDigest, p.anchorDigest = current.ManagerSourceSHA256(), current.Anchor().Digest()
	p.deadline, _ = ctx.Deadline()
	p.lifetime = ctx
	if err := p.Revalidate(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *ManagerHostRecipient) readEnrollmentResponse() (hostenroll.Request, hostboot.Descriptor, hostenroll.Response, error) {
	fail := func(err error) (hostenroll.Request, hostboot.Descriptor, hostenroll.Response, error) {
		return hostenroll.Request{}, hostboot.Descriptor{}, hostenroll.Response{}, err
	}
	launch, err := bootstrapstart.LoadAcceptedHostLaunchMaterial(p.local.accepted)
	if err != nil {
		return fail(err)
	}
	bundle, err := hostenroll.ParsePublicBundle(launch.HostEnrollment)
	if err != nil {
		return fail(err)
	}
	public, err := bundle.ResponsePublicKey()
	if err != nil {
		return fail(err)
	}
	request, descriptor, err := hostenroll.ParseRetainedWorkerRequest(p.query.Request, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	response, err := hostenroll.VerifyResponse(p.query.Response, public, request, p.query.Request, descriptor)
	if err != nil {
		return fail(err)
	}
	if p.query.Swarm != nil || response.Swarm != nil || !descriptor.IsController() ||
		descriptor.Node != p.recipient.Node() || request.InstanceID != p.recipient.InstanceID() ||
		!strings.EqualFold(descriptor.Region, p.local.accepted.Cell) || descriptor.Cell != strings.ToLower(p.local.accepted.Cell) ||
		bundle.Cell != descriptor.Cell || bundle.Environment != p.local.accepted.Environment || p.recipient.Environment() != bundle.Environment {
		return fail(errors.New("manager host recipient enrollment differs from its exact accepted region and OCI target"))
	}
	return request, descriptor, response, nil
}

func (p *ManagerHostRecipient) readEnrollment(ctx context.Context) (WorkerRegistrationSnapshot, error) {
	request, descriptor, response, err := p.readEnrollmentResponse()
	if err != nil {
		return WorkerRegistrationSnapshot{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, response.ExpiresAt)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return WorkerRegistrationSnapshot{}, err
	}
	snapshot, err := readCurrentHostRegistration(ctx, p.query, "runtime-controller-host-admission-source")
	if err != nil {
		return WorkerRegistrationSnapshot{}, err
	}
	if err := verifyManagerHostEnrollment(p.query, snapshot, request, descriptor, response, p.local.accepted.Environment); err != nil {
		return WorkerRegistrationSnapshot{}, err
	}
	if ctx.Err() != nil || !time.Now().Before(response.ExpiresAt) {
		return WorkerRegistrationSnapshot{}, errors.New("manager host recipient completed enrollment expired")
	}
	return snapshot, nil
}

func verifyManagerHostEnrollment(query WorkerRegistrationQuery, snapshot WorkerRegistrationSnapshot, request hostenroll.Request,
	descriptor hostboot.Descriptor, response hostenroll.Response, environment string,
) error {
	r := snapshot.Registration
	if query.Swarm != nil || response.Swarm != nil || !descriptor.IsController() || snapshot.Retired || snapshot.Disabled || snapshot.Pending ||
		snapshot.TerminalOperationID != "" || snapshot.IdentityResetOperationID != "" || snapshot.InstanceID != request.InstanceID ||
		snapshot.RequestSHA256 != hostenroll.RequestSHA256(query.Request) || r.Cell != descriptor.Cell || r.Node != descriptor.Node ||
		r.Environment != environment || r.PublicKey != request.IdentityPublicKey || r.NATSUserPublicKey != request.NATSUserPublicKey ||
		r.Generation != response.RegistrationReceipt.Generation || snapshot.Sequence != response.RegistrationReceipt.Revision ||
		len(r.Roles) == 0 || !slices.Equal(r.Roles, response.Roles) || slices.Contains(r.Roles, "terrabase") || slices.Contains(r.Roles, "function-worker") ||
		r.ManagedOCI != nil || r.ManagedMember != nil || r.ManagedPlacement != nil {
		return errors.New("manager host recipient differs from exact current completed enrollment")
	}
	return nil
}

func verifyManagerHostNative(native *api.Node, b host.ManagerRuntimeBinding, slot string, certificate []byte) error {
	if native == nil || native.ID != b.NodeID || native.Role != api.NodeRoleManager || native.Spec.DesiredRole != api.NodeRoleManager ||
		native.Spec.Membership != api.NodeMembershipAccepted || native.Status.State != api.NodeStatus_READY ||
		native.Spec.Annotations.Name != slot || native.Spec.Annotations.Labels[LabelInstanceID] != b.InstanceID ||
		native.Spec.Annotations.Labels[LabelRegion] != b.OCIRegion || native.Spec.Annotations.Labels[LabelHostRole] != "manager" ||
		native.Spec.Annotations.Labels[LabelExecutionScope] != "platform" || native.Certificate.CN != b.NodeID ||
		native.Certificate.Role != api.NodeRoleManager || !bytes.Equal(native.Certificate.Certificate, certificate) {
		return errors.New("manager host recipient native target identity changed")
	}
	return nil
}

func (p *ManagerHostRecipient) verifyEnrollment(ctx context.Context, registration host.Registration) error {
	enrollment, err := p.readEnrollment(ctx)
	want, beforeErr := protocol.EncodeJSON(p.enrollment)
	actual, afterErr := protocol.EncodeJSON(enrollment)
	wantRegistration, registrationErr := protocol.EncodeJSON(registration)
	if err != nil || beforeErr != nil || afterErr != nil || registrationErr != nil || !bytes.Equal(want, actual) {
		return errors.New("original manager host recipient completed enrollment changed")
	}
	enrolledRegistration, err := protocol.EncodeJSON(enrollment.Registration)
	if err != nil || !bytes.Equal(wantRegistration, enrolledRegistration) {
		return errors.New("original manager host recipient carrier differs from completed enrollment")
	}
	return nil
}

func (p *ManagerHostRecipient) Revalidate(ctx context.Context) error {
	if p == nil || p.original == nil || p.lifetime == nil || p.lifetime.Err() != nil || p.original.Err() != nil || ctx == nil || ctx.Err() != nil ||
		p.local == nil || p.recipient == nil || p.session == nil || p.control == nil || !time.Now().Before(p.deadline) {
		return errors.New("original manager host recipient expired or cancelled")
	}
	ctx, cancel := context.WithDeadline(ctx, p.deadline)
	stop := context.AfterFunc(p.lifetime, cancel)
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
	if current.ExpiresAt().Before(p.deadline) || p.recipient.Deadline().Before(p.deadline) ||
		current.ManagerSourceSHA256() != p.sourceDigest || current.Anchor().Digest() != p.anchorDigest ||
		b.SourceSHA256 != p.sourceDigest || b.AnchorSHA256 != p.anchorDigest || b.DeploymentID != id.DeploymentID || b.ClusterID != id.ClusterID ||
		b.Environment != id.Environment || !strings.EqualFold(b.Cell, id.Cell) || b.OCIRegion != id.OCIRegion || b.OCIRegion != p.recipient.OCIRegion() ||
		b.HostNode != p.recipient.Node() || b.InstanceID != p.recipient.InstanceID() || !slices.Contains(p.local.accepted.ControllerSlots, p.recipient.ControllerSlot()) {
		return errors.New("original manager host recipient signed regional source or target changed")
	}
	if err := p.session.Revalidate(ctx); err != nil {
		return err
	}
	registration := p.session.Registration()
	if registration.ID != b.HostID || registration.Node != b.HostNode || registration.Cell != b.Cell || registration.Environment != b.Environment ||
		registration.PublicKey != b.HostPublicKey || registration.NATSUserPublicKey != b.NATSUserPublicKey || registration.Generation != b.RegistrationGeneration ||
		p.session.SessionID() != b.HostSessionID || p.session.SessionEpoch() != b.HostSessionEpoch ||
		p.session.RegistrationRevision() != b.RegistrationRevision || p.session.SourceRevision() <= b.SourceRevision {
		return errors.New("original manager host recipient signed binding differs from actual host carrier")
	}
	if err := p.recipient.VerifyRegistration(ctx, registration); err != nil {
		return err
	}
	if err := p.verifyEnrollment(ctx, registration); err != nil {
		return err
	}
	got, err := p.control.GetNode(ctx, &api.GetNodeRequest{NodeID: b.NodeID})
	if err != nil || got == nil {
		return errors.New("original manager host recipient native target unavailable")
	}
	if err := verifyManagerHostNative(got.Node, b, p.recipient.ControllerSlot(), p.certificate); err != nil {
		return err
	}
	cluster, err := p.control.ClusterIdentity(ctx)
	if err != nil || cluster == nil || cluster.ID != p.clusterID || !bytes.Equal(cluster.RootCACert, p.clusterCA) {
		return errors.New("original manager host recipient native cluster changed")
	}
	if err := host.VerifySignedManagerRuntimeBinding(p.signed, p.certificate, p.clusterCA, p.clusterID, time.Now().UTC()); err != nil {
		return err
	}
	if err := p.session.Revalidate(ctx); err != nil {
		return err
	}
	if err := p.recipient.VerifyRegistration(ctx, registration); err != nil {
		return err
	}
	if err := p.verifyEnrollment(ctx, registration); err != nil {
		return err
	}
	fresh, err := p.local.reader.ReadRuntimeAuthority(ctx, p.local.accepted, time.Now().UTC())
	if err != nil || fresh.ExpiresAt().Before(p.deadline) || fresh.Identity() != current.Identity() ||
		fresh.Anchor().Digest() != p.anchorDigest || fresh.ManagerSourceSHA256() != p.sourceDigest {
		return errors.New("original manager host recipient source changed during native verification")
	}
	if !time.Now().Before(p.deadline) || p.original.Err() != nil {
		return errors.New("original manager host recipient expired")
	}
	return ctx.Err()
}
