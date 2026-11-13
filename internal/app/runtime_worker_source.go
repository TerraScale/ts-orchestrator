package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go/jetstream"
)

func currentWorkerRegistration(ctx context.Context, mutations *authority.Reader, reader *host.Reader, js jetstream.JetStream, query swarmruntime.WorkerRegistrationQuery, instanceID, node, cell string) (swarmruntime.WorkerRegistrationSnapshot, error) {
	fail := func(err error) (swarmruntime.WorkerRegistrationSnapshot, error) {
		return swarmruntime.WorkerRegistrationSnapshot{}, err
	}
	entry, err := mutations.ReadHostMutation(ctx, authority.MutationRegistration, cell+"."+node)
	if err != nil {
		return fail(err)
	}
	var registration host.Registration
	if err := protocol.DecodeStrict(entry.Payload, &registration, maxRegistrationBytes); err != nil {
		return fail(err)
	}
	if entry.Kind != authority.MutationRegistration || entry.SubjectKey != cell+"."+node || entry.Sequence == 0 || entry.Epoch == 0 ||
		registration.ID != entityid.Derive("host", cell, node) || registration.Cell != cell || registration.Node != node {
		return fail(errors.New("worker registration log identity is invalid"))
	}
	statuses, err := reader.ListHosts(ctx)
	if err != nil {
		return fail(err)
	}
	found := false
	retired := true
	for _, status := range statuses {
		if status.Registration.ID != registration.ID {
			continue
		}
		want, err := protocol.EncodeJSON(registration)
		actual, actualErr := protocol.EncodeJSON(status.Registration)
		if found || err != nil || actualErr != nil || !bytes.Equal(want, actual) {
			return fail(errors.New("worker registration changed during current host read"))
		}
		found, retired = true, status.Retired
	}
	if !found {
		return fail(errors.New("worker has no current registered host"))
	}
	grant, _, err := hostenroll.ReadCurrentGrant(ctx, js, instanceID)
	if err != nil {
		return fail(err)
	}
	if grant.InstanceID != instanceID || !workerGrantAuthorizesPreparation(grant, query, time.Now().UTC()) {
		return fail(errors.New("worker enrollment request is not the current admitted instance grant"))
	}
	confirmed, err := mutations.ReadHostMutation(ctx, authority.MutationRegistration, entry.SubjectKey)
	if err != nil || confirmed.Sequence != entry.Sequence || !bytes.Equal(confirmed.Payload, entry.Payload) {
		return fail(errors.New("worker registration changed during enrollment grant read"))
	}
	return swarmruntime.WorkerRegistrationSnapshot{Registration: registration, Sequence: entry.Sequence, Retired: retired,
		Pending:  !grant.MatchesCompletedWorkerEnrollment(hostenroll.WorkerTransport{Request: query.Request, Response: query.Response}),
		Disabled: grant.Disabled, TerminalOperationID: grant.TerminalOperationID, IdentityResetOperationID: grant.IdentityResetOperationID,
		RequestSHA256: hostenroll.RequestSHA256(query.Request), InstanceID: instanceID}, nil
}

func refuseUnprovenPoolDescriptor(descriptor hostboot.Descriptor) error {
	cell, err := naming.RegionCell(descriptor.Region).Name()
	if err != nil {
		return err
	}
	if descriptor.IsStatic() && strings.HasPrefix(descriptor.Node, cell+"-pool-") {
		return oci.ErrPoolCreationLineagePending
	}
	return nil
}

func workerGrantAuthorizesPreparation(grant hostenroll.Grant, query swarmruntime.WorkerRegistrationQuery, now time.Time) bool {
	if grant.Disabled || grant.TerminalOperationID != "" || grant.IdentityResetOperationID != "" {
		return false
	}
	if grant.MatchesCompletedWorkerEnrollment(hostenroll.WorkerTransport{Request: query.Request, Response: query.Response}) {
		return true
	}
	// Initial preparation precedes Finish: only the exact live claim may proceed.
	return len(query.Request) != 0 && (bytes.Equal(query.Request, grant.Request) && len(grant.Response) == 0 && grant.OwnerToken != "" && now.Before(grant.LeaseUntil) ||
		bytes.Equal(query.Request, grant.RenewalRequest) && len(grant.RenewalResponse) == 0 && grant.RenewalToken != "" && now.Before(grant.RenewalLeaseUntil))
}
