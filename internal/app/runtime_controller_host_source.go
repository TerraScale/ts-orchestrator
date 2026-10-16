package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const runtimeControllerHostSourceCommand = "runtime-controller-host-admission-source"

func currentControllerHostReader(ctx context.Context) (*bootstrapstart.CurrentFounderAuthorityReader, error) {
	initial, err := bootstrapstart.NewMarkerStore().ReadInitialFormation()
	if err != nil {
		return nil, err
	}
	uid, _, err := controllerServiceIdentity()
	if err != nil {
		return nil, err
	}
	floor, err := bootstrapstart.NewServiceFounderSelectionFloorStore(uid)
	if err != nil {
		return nil, err
	}
	local, err := foundationDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	return currentControllerFounderReader(ctx, local.baked, initial, floor)
}

func controllerHostSpecCurrent(ctx context.Context, js jetstream.JetStream, services *specRegistry, entry jetstream.KeyValueEntry, rootHead string) error {
	if js == nil || js.Conn() == nil {
		return errors.New("controller host profile requires its current broker leader")
	}
	options := js.Options()
	var opts []nats.JSOpt
	if options.Domain != "" {
		opts = append(opts, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		opts = append(opts, nats.APIPrefix(options.APIPrefix))
	}
	reader, err := js.Conn().JetStream(opts...)
	if err != nil {
		return err
	}
	subject := "$KV." + cellSpecBucket + "." + cellSpecKey
	latest, err := reader.GetLastMsg("KV_"+cellSpecBucket, subject, nats.Context(ctx))
	if err != nil {
		return err
	}
	services.mu.Lock()
	adopted := services.revision
	services.mu.Unlock()
	if latest == nil || latest.Subject != subject || latest.Sequence == 0 || latest.Header.Get("KV-Operation") != "" || latest.Header.Get(jetstream.MarkerReasonHeader) != "" ||
		len(latest.Data) == 0 || len(latest.Data) > cellspec.MaxSignedBytes || latest.Sequence != entry.Revision() || adopted != entry.Revision() ||
		!bytes.Equal(latest.Data, entry.Value()) || services.roots.reply("").Head != rootHead {
		return errors.New("controller host profile or roots changed during recipient verification")
	}
	return nil
}

func controllerHostRegistration(query swarmruntime.WorkerRegistrationQuery, snapshot swarmruntime.WorkerRegistrationSnapshot,
	request hostenroll.Request, descriptor hostboot.Descriptor, response hostenroll.Response, accepted bootstrapstart.AcceptedIdentity,
) error {
	registration := snapshot.Registration
	if !descriptor.IsController() || query.Swarm != nil || response.Swarm != nil || snapshot.Retired || snapshot.Disabled ||
		snapshot.TerminalOperationID != "" || snapshot.IdentityResetOperationID != "" ||
		descriptor.Cell != registration.Cell || !strings.EqualFold(descriptor.Region, accepted.Cell) ||
		registration.Node != descriptor.Node || registration.Environment != accepted.Environment ||
		registration.PublicKey != request.IdentityPublicKey || registration.NATSUserPublicKey != request.NATSUserPublicKey ||
		registration.Generation != response.RegistrationReceipt.Generation || snapshot.Sequence != response.RegistrationReceipt.Revision ||
		len(registration.Roles) == 0 || !slices.Equal(registration.Roles, response.Roles) ||
		registration.ManagedOCI != nil || registration.ManagedMember != nil || registration.ManagedPlacement != nil {
		return errors.New("controller host query differs from its current registered recipient")
	}
	return nil
}

func (enrollment *managedHostEnrollment) prepareRuntimeControllerHost(ctx context.Context, epoch uint64, requestWire, responseWire []byte) ([]byte, error) {
	if enrollment.services == nil || enrollment.registrationMutations == nil || enrollment.registrations == nil {
		return nil, errors.New("controller host preparation requires current ordered registration and signed services")
	}
	request, descriptor, err := hostenroll.ParseRetainedWorkerRequest(requestWire, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	response, err := hostenroll.VerifyResponse(responseWire, enrollment.responseKey.Public().(ed25519.PublicKey), request, requestWire, descriptor)
	if err != nil {
		return nil, err
	}
	query := swarmruntime.WorkerRegistrationQuery{Request: requestWire, Response: responseWire}
	originalGrant, originalRevision, err := hostenroll.ReadCurrentGrant(ctx, enrollment.js, request.InstanceID)
	if err != nil || !workerGrantAuthorizesPreparation(originalGrant, query, time.Now().UTC()) {
		return nil, errors.New("controller host preparation requires its exact current enrollment claim")
	}
	snapshot, err := currentWorkerRegistration(ctx, enrollment.registrationMutations, enrollment.registrations, enrollment.js, query, request.InstanceID, descriptor.Node, enrollment.cell)
	if err != nil {
		return nil, err
	}
	if err := controllerHostRegistration(query, snapshot, request, descriptor, response, enrollment.runtimeIdentity); err != nil {
		return nil, err
	}
	entry, err := enrollment.services.kv.Get(ctx, cellSpecKey)
	if err != nil {
		return nil, err
	}
	rootHead := enrollment.services.roots.reply("").Head
	if err := controllerHostSpecCurrent(ctx, enrollment.js, enrollment.services, entry, rootHead); err != nil {
		return nil, err
	}
	grant, _, ok := enrollment.services.hostGrant(descriptor.Node)
	if !ok || grant.Controller == "" {
		return nil, errors.New("controller enrollment requires an explicit root-signed controller slot")
	}
	founders, err := currentControllerHostReader(ctx)
	if err != nil {
		return nil, err
	}
	proof, err := bootstrapstart.ReadControllerHostRecipient(ctx, founders, enrollment.runtimeIdentity, entry.Value(), descriptor.Node, request.InstanceID, grant.PrivateIP)
	if err != nil {
		return nil, err
	}
	if err := proof.VerifyRegistration(ctx, snapshot.Registration); err != nil {
		return nil, err
	}
	confirmed, err := currentWorkerRegistration(ctx, enrollment.registrationMutations, enrollment.registrations, enrollment.js, query, request.InstanceID, descriptor.Node, enrollment.cell)
	before, beforeErr := protocol.EncodeJSON(snapshot)
	after, afterErr := protocol.EncodeJSON(confirmed)
	if err != nil || beforeErr != nil || afterErr != nil || !bytes.Equal(before, after) {
		return nil, errors.New("controller enrollment changed during recipient observation")
	}
	if err := controllerHostSpecCurrent(ctx, enrollment.js, enrollment.services, entry, rootHead); err != nil {
		return nil, err
	}
	if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	currentGrant, currentRevision, err := hostenroll.ReadCurrentGrant(ctx, enrollment.js, request.InstanceID)
	grantBefore, grantBeforeErr := protocol.EncodeJSON(originalGrant)
	grantAfter, grantAfterErr := protocol.EncodeJSON(currentGrant)
	if err != nil || currentRevision != originalRevision || grantBeforeErr != nil || grantAfterErr != nil || !bytes.Equal(grantBefore, grantAfter) ||
		!workerGrantAuthorizesPreparation(currentGrant, query, time.Now().UTC()) {
		return nil, errors.New("controller host enrollment claim changed during recipient verification")
	}
	if err := controllerHostSpecCurrent(ctx, enrollment.js, enrollment.services, entry, rootHead); err != nil {
		return nil, err
	}
	if !proof.Valid(time.Now()) || !time.Now().Before(response.ExpiresAt) || !workerGrantAuthorizesPreparation(currentGrant, query, time.Now().UTC()) || ctx.Err() != nil {
		return nil, errors.New("controller enrollment observation expired")
	}
	return bytes.Clone(responseWire), nil
}

// This dedicated child accepts only completed base controller enrollment.
func runRuntimeControllerHostAdmissionSource(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	if len(args) != 0 || os.Geteuid() != int(uid) || os.Getegid() != int(gid) {
		return errors.New("controller host source requires the fixed controller service account and no arguments")
	}
	wire, err := io.ReadAll(io.LimitReader(input, (128<<10)+1))
	var query swarmruntime.WorkerRegistrationQuery
	if err != nil || len(wire) == 0 || protocol.DecodeStrict(wire, &query, 128<<10) != nil || query.Swarm != nil {
		return errors.New("controller host source requires one bounded base enrollment query")
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
	if err != nil || !descriptor.IsController() || descriptor.Cell != cfg.NATS.Cell {
		return errors.New("controller host source requires a regional controller recipient")
	}
	response, err := hostenroll.VerifyResponse(query.Response, key.Public().(ed25519.PublicKey), request, query.Request, descriptor)
	if err != nil {
		return err
	}
	cfg.NATS.Embedded, cfg.NATS.ClientRole = nil, "controller"
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
	if err != nil || snapshot.Pending {
		return errors.Join(err, errors.New("controller host source requires completed current enrollment"))
	}
	if err := controllerHostRegistration(query, snapshot, request, descriptor, response, accepted); err != nil {
		return err
	}
	services, _, err := runtimeRegistryPolicy(ctx, cfg, runtime.JetStream())
	if err != nil {
		return err
	}
	entry, err := services.kv.Get(ctx, cellSpecKey)
	if err != nil {
		return err
	}
	rootHead := services.roots.reply("").Head
	if err := controllerHostSpecCurrent(ctx, runtime.JetStream(), services, entry, rootHead); err != nil {
		return err
	}
	grant, _, ok := services.hostGrant(descriptor.Node)
	if !ok || grant.Controller == "" {
		return errors.New("controller host source has no signed controller slot association")
	}
	founders, err := currentControllerHostReader(ctx)
	if err != nil {
		return err
	}
	proof, err := bootstrapstart.ReadControllerHostRecipient(ctx, founders, accepted, entry.Value(), descriptor.Node, request.InstanceID, grant.PrivateIP)
	if err != nil {
		return err
	}
	if err := proof.VerifyRegistration(ctx, snapshot.Registration); err != nil {
		return err
	}
	confirmed, err := currentWorkerRegistration(ctx, mutations, reader, runtime.JetStream(), query, request.InstanceID, descriptor.Node, cfg.NATS.Cell)
	before, beforeErr := protocol.EncodeJSON(snapshot)
	after, afterErr := protocol.EncodeJSON(confirmed)
	if err != nil || beforeErr != nil || afterErr != nil || !bytes.Equal(before, after) || !proof.Valid(time.Now()) || !time.Now().Before(response.ExpiresAt) {
		return errors.New("controller host registration changed during source observation")
	}
	if err := controllerHostSpecCurrent(ctx, runtime.JetStream(), services, entry, rootHead); err != nil {
		return err
	}
	if !proof.Valid(time.Now()) || !time.Now().Before(response.ExpiresAt) || ctx.Err() != nil {
		return errors.New("controller host source observation expired")
	}
	wire, err = protocol.EncodeJSON(snapshot)
	if err != nil || len(wire) > 128<<10 {
		return errors.New("controller host source result is oversized")
	}
	_, err = output.Write(wire)
	return err
}
