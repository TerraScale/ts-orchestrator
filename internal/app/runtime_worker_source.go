package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go/jetstream"
)

// runRuntimeWorkerAdmissionSource exposes current registered identity only to
// the root runtime's fixed same-binary child protocol.
func runRuntimeWorkerAdmissionSource(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	if len(args) != 0 {
		return errors.New("runtime-worker-admission-source accepts no arguments")
	}
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	if os.Geteuid() != int(uid) || os.Getegid() != int(gid) {
		return errors.New("worker admission source requires the controller service account")
	}
	wire, err := io.ReadAll(io.LimitReader(input, (128<<10)+1))
	if err != nil || len(wire) == 0 || len(wire) > 128<<10 {
		return errors.New("worker admission query is missing or oversized")
	}
	var query swarmruntime.WorkerRegistrationQuery
	if err := json.Unmarshal(wire, &query, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	cfg, err := LoadConfig(controllerConfigDirectory + "/" + controllerConfigFilename)
	if err != nil {
		return err
	}
	gate, accepted, err := acceptedControllerAdmissionGate(cfg, bootstrapstart.NewMarkerStore(), controllerClockCheck(controllerBrokerClockProbe()))
	if err != nil {
		return err
	}
	if _, err := gate.AdmitRestartLocal(ctx); err != nil {
		return err
	}
	key, err := readPrivateKey(cfg.Controller.ResponseKeyFile)
	if err != nil {
		return err
	}
	defer clear(key)
	request, descriptor, err := hostenroll.ParseRetainedWorkerRequest(query.Request, time.Now().UTC())
	if err != nil {
		return err
	}
	// Static grants do not retain independent admission provenance, including
	// legacy pool names: a saved credential cannot establish creation authority.
	if descriptor.IsStatic() {
		return oci.ErrPoolCreationLineagePending
	}
	response, err := hostenroll.VerifyResponse(query.Response, key.Public().(ed25519.PublicKey), request, query.Request, descriptor)
	if err != nil {
		return err
	}
	if descriptor.Cell != cfg.NATS.Cell || !strings.EqualFold(descriptor.Region, accepted.Cell) {
		return errors.New("worker source query belongs to another region")
	}
	// The controller already owns the broker; this child opens only its client.
	cfg.NATS.Embedded = nil
	cfg.NATS.ClientRole = "controller"
	runtime, err := natscell.Start(ctx, cfg.NATS)
	if err != nil {
		return err
	}
	defer runtime.Close()
	mutations, err := authority.OpenReader(ctx, runtime.JetStream(), cfg.NATS.Cell)
	if err != nil {
		return err
	}
	reader, err := host.NewReader(ctx, host.ReaderConfig{Cell: cfg.NATS.Cell, Conn: runtime.Conn(), JS: runtime.JetStream(), StateReplicas: cfg.NATS.Replicas, HostMutations: mutations})
	if err != nil {
		return err
	}
	snapshot, err := currentWorkerRegistration(ctx, mutations, reader, runtime.JetStream(), query, request.InstanceID, descriptor.Node, cfg.NATS.Cell)
	if err != nil {
		return err
	}
	registration := snapshot.Registration
	if snapshot.Retired || registration.PublicKey != request.IdentityPublicKey || registration.NATSUserPublicKey != request.NATSUserPublicKey ||
		registration.Generation != response.RegistrationReceipt.Generation || snapshot.Sequence != response.RegistrationReceipt.Revision || registration.Environment != accepted.Environment {
		return errors.New("worker query differs from current registered recipient")
	}
	managed, err := loadManagedControllerConfig(cfg)
	if err != nil || managed == nil {
		return errors.New("worker source requires the current admitted managed controller")
	}
	local, err := foundationDiscovery(ctx)
	if err != nil {
		return err
	}
	members, err := placement.OpenMemberPinReader(ctx, runtime.JetStream(), cfg.NATS.Cell, cfg.NATS.Replicas)
	if err != nil {
		return err
	}
	journal, err := oci.OpenJournalReader(ctx, runtime.JetStream(), cfg.NATS.Replicas)
	if err != nil {
		return err
	}
	services, _, err := runtimeRegistryPolicy(ctx, cfg, runtime.JetStream())
	if err != nil {
		return err
	}
	images, err := managedImageVerifierFor(cfg.Controller, services.hostImageSnapshot, services.holdLaunch)(ctx, managed.region)
	if err != nil {
		return err
	}
	fleet, err := oci.NewFleetObserver(managed.region, managed.intent, local.factory, journal, images)
	if err != nil {
		return err
	}
	verifier, err := newManagedRegistrationVerifier(cfg.NATS.Cell, managed.region.Region, managed.region.Owner,
		managed.region.Generation, mutations, members, fleet)
	if err != nil {
		return err
	}
	if err := verifier.VerifyManagedRegistration(ctx, registration); err != nil {
		return err
	}
	if query.Swarm != nil {
		initial, err := bootstrapstart.NewMarkerStore().ReadInitialFormation()
		if err != nil {
			return err
		}
		floor, err := bootstrapstart.NewServiceFounderSelectionFloorStore(uid)
		if err != nil {
			return err
		}
		founders, err := currentControllerFounderReader(ctx, local.baked, initial, floor)
		if err != nil {
			return err
		}
		current, err := founders.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
		if err != nil {
			return err
		}
		observer, err := bootstrapstart.NewOCIInstanceObserver(local.baked.Identity.Cell, local.factory.Provider())
		if err != nil {
			return err
		}
		observed, err := observer.ObserveInstance(ctx, request.InstanceID)
		if err != nil {
			return err
		}
		architecture, err := observer.ObserveWorkerArchitecture(ctx, observed)
		if err != nil {
			return err
		}
		worker := *query.Swarm
		identity := current.Identity()
		role := "container"
		if slices.Contains(registration.Roles, "function-worker") {
			if len(registration.Roles) != 1 {
				return errors.New("function worker registration must be dedicated")
			}
			role = "wasm"
		}
		if worker.Validate(time.Now().UTC()) != nil || len(registration.Roles) == 0 ||
			worker.DeploymentID != identity.DeploymentID || worker.ClusterID != identity.ClusterID || worker.Environment != identity.Environment ||
			worker.Cell != registration.Cell || worker.Region != identity.OCIRegion || worker.OCIRegion != identity.OCIRegion || worker.FounderID != identity.SeedSlot ||
			worker.RegistrationID != registration.ID || worker.Generation != registration.Generation || worker.Revision != snapshot.Sequence ||
			worker.InstanceID != request.InstanceID || worker.PrivateIP != observed.PrimaryPrivateIP || worker.Architecture != architecture || worker.Role != role ||
			worker.ExpiresAt.After(response.ExpiresAt) || worker.ExpiresAt.After(current.ExpiresAt()) || !observed.PrimaryVNIC || observed.LifecycleState != "RUNNING" {
			return errors.New("worker projection differs from current signed regional and OCI scope")
		}
		response.Swarm = &worker
		if err := response.Sign(key); err != nil {
			return err
		}
		snapshot.Response, err = protocol.EncodeJSON(response)
		if err != nil {
			return err
		}
	}
	if err := verifier.VerifyManagedRegistration(ctx, registration); err != nil {
		return err
	}
	confirmed, err := currentWorkerRegistration(ctx, mutations, reader, runtime.JetStream(), query, request.InstanceID, descriptor.Node, cfg.NATS.Cell)
	before, beforeErr := protocol.EncodeJSON(snapshot)
	if err != nil {
		return err
	}
	confirmed.Response = snapshot.Response
	after, afterErr := protocol.EncodeJSON(confirmed)
	if beforeErr != nil || afterErr != nil || !bytes.Equal(before, after) {
		return errors.New("worker registration changed during source observation")
	}
	wire, err = protocol.EncodeJSON(snapshot)
	if err != nil || len(wire) > 128<<10 {
		return errors.New("worker admission source result is oversized")
	}
	_, err = output.Write(wire)
	return err
}

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
