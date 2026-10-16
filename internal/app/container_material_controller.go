package app

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

type controllerEnrollmentSnapshot struct {
	Query    swarmruntime.WorkerRegistrationQuery
	Snapshot swarmruntime.WorkerRegistrationSnapshot
}

func completedControllerEnrollment(ctx context.Context, config containerMaterialConfig, registration host.Registration, instanceID string) (controllerEnrollmentSnapshot, error) {
	fail := func(err error) (controllerEnrollmentSnapshot, error) { return controllerEnrollmentSnapshot{}, err }
	grant, _, err := hostenroll.ReadCurrentGrant(ctx, config.JS, instanceID)
	if err != nil || grant.Disabled || grant.TerminalOperationID != "" || grant.IdentityResetOperationID != "" {
		return fail(errors.New("controller material requires active completed enrollment"))
	}
	query := swarmruntime.WorkerRegistrationQuery{Request: grant.Request, Response: grant.Response}
	if len(grant.RenewalResponse) != 0 {
		query.Request, query.Response = grant.RenewalRequest, grant.RenewalResponse
	}
	if !grant.MatchesCompletedWorkerEnrollment(hostenroll.WorkerTransport{Request: query.Request, Response: query.Response}) {
		return fail(errors.New("controller material has no exact completed enrollment"))
	}
	request, descriptor, err := hostenroll.ParseRetainedWorkerRequest(query.Request, time.Now().UTC())
	if err != nil || request.InstanceID != instanceID {
		return fail(errors.New("controller material enrollment differs from the requested OCI instance"))
	}
	response, err := hostenroll.VerifyResponse(query.Response, config.ResponsePublic, request, query.Request, descriptor)
	if err != nil {
		return fail(err)
	}
	snapshot, err := currentWorkerRegistration(ctx, config.Mutations, config.Registrations, config.JS, query, instanceID, descriptor.Node, registration.Cell)
	if err != nil || snapshot.Pending {
		return fail(errors.New("controller material registration is not currently completed"))
	}
	if err := controllerHostRegistration(query, snapshot, request, descriptor, response, config.Accepted); err != nil {
		return fail(err)
	}
	want, err := protocol.EncodeJSON(registration)
	actual, actualErr := protocol.EncodeJSON(snapshot.Registration)
	if err != nil || actualErr != nil || !bytes.Equal(want, actual) {
		return fail(errors.New("controller material recipient differs from the current ordered registration"))
	}
	return controllerEnrollmentSnapshot{Query: query, Snapshot: snapshot}, nil
}
