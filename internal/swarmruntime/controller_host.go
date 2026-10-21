package swarmruntime

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
)

// ControllerHostBinding associates one accepted manager slot with its separately
// enrolled ownhost identity. It cannot authorize WASM or managed DATA execution.
type ControllerHostBinding struct {
	reader   *bootstrapstart.CurrentFounderAuthorityReader
	agent    *host.Agent
	accepted bootstrapstart.AcceptedIdentity
	query    WorkerRegistrationQuery
	identity bootstrapstart.RuntimeIdentity
	hostID   string
}

// ReadControllerHostBinding consumes real base enrollment bytes. The accepted
// launch pins their issuer's public bundle, never the enrollment response itself.
func ReadControllerHostBinding(ctx context.Context, reader *bootstrapstart.CurrentFounderAuthorityReader,
	accepted bootstrapstart.AcceptedIdentity, agent *host.Agent, requestWire, responseWire []byte,
) (*ControllerHostBinding, error) {
	authority, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	binding := &ControllerHostBinding{reader: reader, agent: agent, accepted: accepted.Clone(), identity: authority.Identity(),
		query: WorkerRegistrationQuery{Request: bytes.Clone(requestWire), Response: bytes.Clone(responseWire)}}
	registration, err := binding.currentRegistration(ctx)
	if err != nil {
		return nil, err
	}
	binding.hostID = registration.ID
	return binding, nil
}

func (binding *ControllerHostBinding) HostID() string         { return binding.hostID }
func (binding *ControllerHostBinding) ControllerSlot() string { return binding.identity.Slot }
func (binding *ControllerHostBinding) Identity() bootstrapstart.RuntimeIdentity {
	return binding.identity
}

// VerifyRegistration repeats the signed authority, current completed grant,
// ordered registration and OCI observations for each ownhost material request.
func (binding *ControllerHostBinding) VerifyRegistration(ctx context.Context, registration host.Registration) error {
	if binding == nil || binding.hostID == "" {
		return errors.New("controller host binding is unavailable")
	}
	current, err := binding.currentRegistration(ctx)
	if err != nil {
		return err
	}
	wanted, err := json.Marshal(current, json.Deterministic(true))
	actual, otherErr := json.Marshal(registration, json.Deterministic(true))
	if err != nil || otherErr != nil || !bytes.Equal(wanted, actual) || current.ID != binding.hostID {
		return errors.New("ownhost registration differs from the accepted controller host binding")
	}
	return nil
}

func (binding *ControllerHostBinding) currentRegistration(ctx context.Context) (host.Registration, error) {
	fail := func(err error) (host.Registration, error) { return host.Registration{}, err }
	if binding == nil || binding.reader == nil || binding.agent == nil {
		return fail(errors.New("controller host binding is unavailable"))
	}
	current, err := binding.reader.ReadRuntimeAuthority(ctx, binding.accepted, time.Now().UTC())
	if err != nil || current.Identity() != binding.identity {
		return fail(errors.New("controller host binding has no current accepted regional authority"))
	}
	launch, err := bootstrapstart.LoadAcceptedHostLaunchMaterial(binding.accepted)
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
	request, descriptor, err := hostenroll.ParseRetainedWorkerRequest(binding.query.Request, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	response, err := hostenroll.VerifyResponse(binding.query.Response, public, request, binding.query.Request, descriptor)
	if err != nil {
		return fail(err)
	}
	identity := binding.identity
	if !descriptor.IsController() || !strings.EqualFold(descriptor.Region, identity.Cell) ||
		descriptor.Cell != strings.ToLower(identity.Cell) || request.InstanceID != identity.InstanceID || response.Swarm != nil ||
		bundle.Cell != descriptor.Cell || bundle.Environment != identity.Environment {
		return fail(errors.New("controller host enrollment differs from its accepted instance and region"))
	}
	snapshot, err := readCurrentHostRegistration(ctx, binding.query, "runtime-controller-host-admission-source")
	if err != nil {
		return fail(err)
	}
	registration := snapshot.Registration
	if snapshot.Retired || snapshot.Disabled || snapshot.Pending || snapshot.TerminalOperationID != "" || snapshot.IdentityResetOperationID != "" ||
		snapshot.InstanceID != identity.InstanceID || snapshot.RequestSHA256 != hostenroll.RequestSHA256(binding.query.Request) ||
		registration.ID != entityid.Derive("host", descriptor.Cell, descriptor.Node) || registration.Cell != descriptor.Cell ||
		registration.Node != descriptor.Node || registration.Environment != identity.Environment ||
		registration.PublicKey != request.IdentityPublicKey || registration.NATSUserPublicKey != request.NATSUserPublicKey ||
		registration.Generation != response.RegistrationReceipt.Generation || snapshot.Sequence != response.RegistrationReceipt.Revision ||
		len(registration.Roles) == 0 || !slices.Equal(registration.Roles, response.Roles) || slices.Contains(registration.Roles, "function-worker") ||
		slices.Contains(registration.Roles, "terrabase") ||
		registration.ManagedOCI != nil || registration.ManagedMember != nil || registration.ManagedPlacement != nil {
		return fail(errors.New("controller host enrollment differs from its current completed registration"))
	}
	if err := binding.agent.VerifyOwnRegistration(registration, public); err != nil {
		return fail(err)
	}
	observer, err := binding.reader.RuntimeInstanceObserver(ctx, binding.accepted)
	if err != nil {
		return fail(err)
	}
	observed, err := observer.ObserveInstance(ctx, identity.InstanceID)
	if err != nil {
		return fail(err)
	}
	if observed.InstanceOCID != identity.InstanceID || observed.ImageOCID != binding.accepted.ImageOCID ||
		observed.PrimaryVNICOCID != binding.accepted.PrimaryVNICOCID || observed.PrimaryPrivateIP != identity.PrivateIP ||
		!observed.PrimaryVNIC || observed.LifecycleState != "RUNNING" {
		return fail(errors.New("controller host binding differs from its live accepted OCI recipient"))
	}
	confirmed, err := readCurrentHostRegistration(ctx, binding.query, "runtime-controller-host-admission-source")
	if err != nil {
		return fail(err)
	}
	before, err := json.Marshal(snapshot, json.Deterministic(true))
	after, otherErr := json.Marshal(confirmed, json.Deterministic(true))
	if err != nil || otherErr != nil || !bytes.Equal(before, after) {
		return fail(errors.New("controller host registration changed during OCI verification"))
	}
	current, err = binding.reader.ReadRuntimeAuthority(ctx, binding.accepted, time.Now().UTC())
	if err != nil || current.Identity() != identity || !time.Now().Before(response.ExpiresAt) {
		return fail(errors.New("controller host authority changed during recipient verification"))
	}
	if err := binding.agent.VerifyOwnRegistration(registration, public); err != nil {
		return fail(err)
	}
	return registration, nil
}
