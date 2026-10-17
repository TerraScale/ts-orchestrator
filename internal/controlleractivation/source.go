//go:build linux

// Package controlleractivation binds an original root call to the existing
// authenticated Swarm control path. The actual leader reconstructs authority.
package controlleractivation

import (
	"context"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

var ErrPending = swarmruntime.ErrControllerActivationPending

type Admission struct {
	original    context.Context
	node        *swarmruntime.Node
	binding     *swarmruntime.ControllerHostBinding
	recipient   *bootstrapstart.ControllerHostRecipient
	session     *host.ContainerGenerationSession
	lease       *authority.LeaseAdmission
	credentials *rootsecret.ControllerReader
	call        rootoci.Call
	deadline    time.Time
}

func Read(ctx context.Context, node *swarmruntime.Node, binding *swarmruntime.ControllerHostBinding,
	recipient *bootstrapstart.ControllerHostRecipient, session *host.ContainerGenerationSession,
	lease *authority.LeaseAdmission, credentials *rootsecret.ControllerReader, call rootoci.Call,
) (*Admission, error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil || node == nil || binding == nil || recipient == nil || session == nil || lease == nil || credentials == nil ||
		call.RuntimeID() == "" || call.Operation() != "activate_controller_node" || call.Guard(ctx) != nil {
		return nil, ErrPending
	}
	deployment, candidate := lease.RuntimeIdentity()
	identity := binding.Identity()
	if deployment != identity.DeploymentID || candidate != call.RuntimeID() || recipient.OCIRegion() != identity.OCIRegion || recipient.Environment() != identity.Environment {
		return nil, ErrPending
	}
	if credentials.Context() == nil || credentials.Context().Done() == nil {
		return nil, ErrPending
	}
	deadline, ok := credentials.Context().Deadline()
	if !ok {
		return nil, ErrPending
	}
	for _, until := range []time.Time{call.Deadline(), recipient.ExpiresAt(), session.Deadline(), lease.Deadline()} {
		if until.IsZero() {
			return nil, ErrPending
		}
		if until.Before(deadline) {
			deadline = until
		}
	}
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	admitted := &Admission{original: ctx, node: node, binding: binding, recipient: recipient, session: session, lease: lease, credentials: credentials, call: call, deadline: deadline}
	if err := admitted.guard(ctx); err != nil {
		return nil, err
	}
	return admitted, nil
}

func (admitted *Admission) ExpiresAt() time.Time { return admitted.deadline }

func (admitted *Admission) operationContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if admitted == nil || admitted.original == nil || ctx == nil || ctx.Err() != nil || admitted.original.Err() != nil || !time.Now().Before(admitted.deadline) {
		return nil, nil, ErrPending
	}
	bounded, cancel := context.WithDeadline(ctx, admitted.deadline)
	stopOriginal := context.AfterFunc(admitted.original, cancel)
	stopCredentials := context.AfterFunc(admitted.credentials.Context(), cancel)
	return bounded, func() { stopOriginal(); stopCredentials(); cancel() }, nil
}

func (admitted *Admission) guard(ctx context.Context) error {
	ctx, cancel, err := admitted.operationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err := admitted.call.Guard(ctx); err != nil {
		return err
	}
	if err := admitted.credentials.Guard(ctx); err != nil {
		return err
	}
	if err := admitted.lease.Guard(ctx); err != nil {
		return err
	}
	if err := admitted.session.Guard(ctx); err != nil {
		return err
	}
	registration, err := admitted.session.Registration()
	if err != nil {
		return err
	}
	if err := admitted.binding.VerifyRegistration(ctx, registration); err != nil {
		return err
	}
	if err := admitted.recipient.VerifyRegistration(ctx, registration); err != nil {
		return err
	}
	if err := admitted.call.Guard(ctx); err != nil {
		return err
	}
	return ctx.Err()
}
