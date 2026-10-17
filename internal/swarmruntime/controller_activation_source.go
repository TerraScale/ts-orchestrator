//go:build linux

package swarmruntime

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/controllercredential"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var ErrControllerActivationPending = errors.New("controller execution admission awaits current authority and complete execution history")

type controllerSourcePin struct {
	bucket, key string
	sequence    uint64
	wire        []byte
}

type controllerActivationAdmission struct {
	original           context.Context
	release            context.CancelFunc
	local              *controllerActivationControl
	binding            *ControllerHostBinding
	recipient          *bootstrapstart.ControllerHostRecipient
	session            *host.ContainerGenerationSession
	origin             *ManagerRuntimeCandidate
	credentials        *controllercredential.ControllerReader
	js                 nats.JetStreamContext
	stream             jetstream.JetStream
	mutations          *authority.Reader
	pins               []controllerSourcePin
	domains            map[string]bootstrap.ControllerFailureDomain
	deadline           time.Time
	grant              hostenroll.Grant
	grantRevision      uint64
	enrollmentDeadline time.Time
	retirements        []*bootstrapstart.ManagerRetirement
}

func (admitted *controllerActivationAdmission) guard(ctx context.Context) error {
	if admitted == nil || admitted.original == nil || ctx == nil || ctx.Err() != nil || admitted.original.Err() != nil ||
		!time.Now().Before(admitted.deadline) || admitted.credentials == nil {
		return ErrControllerActivationPending
	}
	ctx, cancel := context.WithDeadline(ctx, admitted.deadline)
	stop := context.AfterFunc(admitted.original, cancel)
	stopCredentials := context.AfterFunc(admitted.credentials.Context(), cancel)
	defer cancel()
	defer stop()
	defer stopCredentials()
	if err := admitted.credentials.Guard(ctx); err != nil {
		return err
	}
	if err := admitted.origin.Revalidate(ctx); err != nil {
		return err
	}
	if err := admitted.session.Guard(ctx); err != nil {
		return err
	}
	registration, err := admitted.session.Registration()
	if err != nil {
		return err
	}
	if err := admitted.recipient.VerifyRegistration(ctx, registration); err != nil {
		return err
	}
	if err := admitted.local.guard(ctx); err != nil {
		return err
	}
	grant, revision, expires, err := admitted.currentEnrollment(ctx)
	if err != nil || revision != admitted.grantRevision || !expires.Equal(admitted.enrollmentDeadline) || !reflect.DeepEqual(grant, admitted.grant) {
		return ErrControllerActivationPending
	}
	for _, pin := range admitted.pins {
		current, err := admitted.readPin(ctx, pin.bucket, pin.key)
		if err != nil || current.sequence != pin.sequence || !bytes.Equal(current.wire, pin.wire) {
			return ErrControllerActivationPending
		}
	}
	for _, retired := range admitted.retirements {
		if err := retired.Verify(ctx); err != nil {
			return err
		}
	}
	if err := admitted.origin.Revalidate(ctx); err != nil {
		return err
	}
	if !time.Now().Before(admitted.deadline) || admitted.original.Err() != nil {
		return ErrControllerActivationPending
	}
	return ctx.Err()
}

// Preserve an original request guard while adding independently read sources.
func (admitted *controllerActivationAdmission) requestContext(ctx context.Context) context.Context {
	original := ctx
	return ociclient.WithRequestGuard(ctx, func(check context.Context) error {
		if err := ociclient.CheckRequestGuard(original); err != nil {
			return err
		}
		return admitted.guard(check)
	})
}

// Native task absence cannot establish inception or prove pruned execution.
// The protected all-manager foundation and complete-history producer is required.
func (admitted *controllerActivationAdmission) executionLineage(ctx context.Context, candidate *api.Node, conflicts []*api.Node, tasks []*api.Task) error {
	if err := admitted.guard(ctx); err != nil {
		return err
	}
	return ErrControllerActivationPending
}

func (admitted *controllerActivationAdmission) readPin(ctx context.Context, bucket, key string) (controllerSourcePin, error) {
	subject := "$KV." + bucket + "." + key
	message, err := admitted.js.GetLastMsg("KV_"+bucket, subject, nats.Context(ctx))
	if err != nil {
		return controllerSourcePin{}, err
	}
	if message == nil || message.Subject != subject || message.Sequence == 0 || len(message.Data) == 0 || len(message.Data) > 1<<20 ||
		message.Header.Get("KV-Operation") != "" || message.Header.Get("Nats-Marker-Reason") != "" || ctx.Err() != nil {
		return controllerSourcePin{}, ErrControllerActivationPending
	}
	return controllerSourcePin{bucket: bucket, key: key, sequence: message.Sequence, wire: bytes.Clone(message.Data)}, nil
}

func (admitted *controllerActivationAdmission) currentEnrollment(ctx context.Context) (hostenroll.Grant, uint64, time.Time, error) {
	fail := func(err error) (hostenroll.Grant, uint64, time.Time, error) {
		return hostenroll.Grant{}, 0, time.Time{}, err
	}
	grant, revision, err := hostenroll.ReadCurrentGrant(ctx, admitted.stream, admitted.recipient.InstanceID())
	if err != nil || revision == 0 || grant.Disabled || grant.TerminalOperationID != "" || grant.IdentityResetOperationID != "" {
		return fail(ErrControllerActivationPending)
	}
	transport := hostenroll.WorkerTransport{Request: grant.Request, Response: grant.Response}
	if len(grant.RenewalResponse) != 0 {
		transport.Request, transport.Response = grant.RenewalRequest, grant.RenewalResponse
	}
	if !grant.MatchesCompletedWorkerEnrollment(transport) {
		return fail(ErrControllerActivationPending)
	}
	request, descriptor, err := hostenroll.ParseRetainedWorkerRequest(transport.Request, time.Now().UTC())
	if err != nil || !descriptor.IsController() || request.InstanceID != admitted.recipient.InstanceID() {
		return fail(ErrControllerActivationPending)
	}
	launch, err := bootstrapstart.LoadAcceptedHostLaunchMaterial(admitted.binding.accepted.Clone())
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
	response, err := hostenroll.VerifyResponse(transport.Response, public, request, transport.Request, descriptor)
	if err != nil || response.Swarm != nil || !time.Now().Before(response.ExpiresAt) {
		return fail(ErrControllerActivationPending)
	}
	registration, err := admitted.session.Registration()
	if err != nil || descriptor.Cell != registration.Cell || descriptor.Node != registration.Node ||
		registration.Generation != response.RegistrationReceipt.Generation || registration.PublicKey != request.IdentityPublicKey ||
		registration.NATSUserPublicKey != request.NATSUserPublicKey || !reflect.DeepEqual(registration.Roles, response.Roles) {
		return fail(ErrControllerActivationPending)
	}
	subject := registration.Cell + "." + registration.Node
	entry, err := admitted.mutations.ReadHostMutation(ctx, authority.MutationRegistration, subject)
	wire, wireErr := protocol.EncodeJSON(registration)
	if err != nil || wireErr != nil || entry.Kind != authority.MutationRegistration || entry.SubjectKey != subject ||
		entry.Sequence != response.RegistrationReceipt.Revision || !bytes.Equal(entry.Payload, wire) {
		return fail(ErrControllerActivationPending)
	}
	if err := admitted.session.Guard(ctx); err != nil {
		return fail(err)
	}
	confirmed, err := admitted.mutations.ReadHostMutation(ctx, authority.MutationRegistration, subject)
	if err != nil || confirmed.Sequence != entry.Sequence || !bytes.Equal(confirmed.Payload, entry.Payload) {
		return fail(ErrControllerActivationPending)
	}
	return grant, revision, response.ExpiresAt, nil
}
