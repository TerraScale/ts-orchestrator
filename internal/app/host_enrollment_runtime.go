package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func hostNATSUserPublicKey(config natscell.Config) (string, error) {
	path := config.CredentialsFile
	if path == "" {
		path = config.NKeySeedFile
	}
	if path == "" {
		return "", errors.New("host NATS credentials are required")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	defer clear(wire)
	if len(wire) == 0 || len(wire) > 64<<10 {
		return "", errors.New("host NATS credentials are missing or too large")
	}
	pair, err := nkeys.ParseDecoratedUserNKey(wire)
	if err != nil {
		return "", fmt.Errorf("parse host NATS user key: %w", err)
	}
	defer pair.Wipe()
	return pair.PublicKey()
}

type managedHostEnrollment struct {
	cell        string
	region      oci.Region
	owner       string
	generation  uint64
	environment string
	// diskBytes is the installed controller's pre-volume reservation policy.
	// Placement verifies the actual OCI retained volume size before attachment.
	diskBytes   int64
	fleet       oci.Fleet
	intents     placementIntentLookup
	members     placement.MemberPinReader
	controller  *host.Controller
	verifier    host.ManagedRegistrationVerifier
	grants      *hostenroll.GrantStore
	issuer      *hostenroll.Issuer
	responseKey ed25519.PrivateKey
	fencer      authority.Fencer
	// services holds the adopted cell spec. A static host (hostboot.Static)
	// enrolls as a member its effective terrabase profile lists, or by one
	// of its host grants.
	services *specRegistry
	// pool admits the node pool's instances. Nil refuses every pool node.
	pool            nodePoolMembers
	runtimeIdentity bootstrapstart.AcceptedIdentity
}

var errStaleUnclaimedRenewal = errors.New("stale unclaimed host renewal")

func startManagedHostEnrollment(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	managed *managedControllerConfig, fleet oci.Fleet, intents placementIntentLookup,
	members placement.MemberPinReader, controller *host.Controller, verifier host.ManagedRegistrationVerifier,
	responseKey ed25519.PrivateKey,
	fencer authority.Fencer, services *specRegistry, pool *nodePoolBinding,
) (*http.Server, net.Listener, <-chan error, error) {
	if managed == nil || fleet == nil || intents == nil || members == nil || controller == nil || verifier == nil ||
		cfg.NATS.Embedded == nil || cfg.Controller.HostEnrollmentListenAddress == "" {
		return nil, nil, nil, errors.New("managed host enrollment requires a complete private controller runtime")
	}
	runtimeIdentity, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return nil, nil, nil, err
	}
	grantStore, err := hostenroll.OpenGrantStore(ctx, runtime.JetStream(), cfg.NATS.Replicas)
	if err != nil {
		return nil, nil, nil, err
	}
	issuer, err := loadHostIssuer(cfg, runtime)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := issuer.ValidateAccountScope(runtime.InitialCellJWT()); err != nil {
		return nil, nil, nil, err
	}
	// The listener shares the broker's address and certificate, so it serves
	// a renewed certificate as soon as the broker does. Session tickets are
	// off so no client resumes a session made under the old certificate.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	if reloading := runtime.BrokerTLS(); reloading != nil {
		tlsConfig.GetCertificate = reloading.Certificate
	} else {
		certificate, err := tls.LoadX509KeyPair(cfg.NATS.Embedded.TLS.CertFile, cfg.NATS.Embedded.TLS.KeyFile)
		if err != nil {
			return nil, nil, nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	listenIP, listenPort, err := net.SplitHostPort(cfg.Controller.HostEnrollmentListenAddress)
	if err != nil || listenPort != "8443" || net.ParseIP(listenIP) == nil || listenIP != cfg.NATS.Embedded.Host {
		return nil, nil, nil, errors.New("host enrollment listener must bind the exact private broker IP on port 8443")
	}
	listener, err := net.Listen("tcp", cfg.Controller.HostEnrollmentListenAddress)
	if err != nil {
		return nil, nil, nil, err
	}
	placementConfig := managed.placementConfig(cfg.NATS.Cell, nil, nil)
	handler := &managedHostEnrollment{
		cell: cfg.NATS.Cell, region: managed.region.Region, owner: managed.region.Owner,
		generation: managed.region.Generation, environment: placementConfig.Environment,
		diskBytes: placementConfig.Resources.DiskBytes,
		fleet:     fleet, intents: intents, members: members, controller: controller, verifier: verifier,
		grants: grantStore, issuer: issuer, responseKey: responseKey, fencer: fencer,
		services: services, runtimeIdentity: runtimeIdentity,
	}
	// A nil pool refuses every pool node. The typed nil is kept out of the interface.
	// A pool that has not bound yet refuses until it does.
	if pool != nil {
		handler.pool = pool
	}
	server := &http.Server{Handler: observability.TraceHTTP(handler), ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes: 4096, TLSConfig: tlsConfig}
	errors := make(chan error, 1)
	go func() { errors <- server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	return server, listener, errors, nil
}

func (enrollment *managedHostEnrollment) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/v1/runtime/worker-refresh" {
		enrollment.refreshRuntimeWorker(writer, request)
		return
	}
	if request.URL.Path == "/v1/runtime/worker-bind" {
		enrollment.bindRuntimeWorker(writer, request)
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != "/v1/host-enrollment" || request.TLS == nil ||
		request.Header.Get("Forwarded") != "" || request.Header.Get("X-Forwarded-For") != "" ||
		request.Header.Get("X-Real-IP") != "" {
		http.Error(writer, "invalid host enrollment request", http.StatusBadRequest)
		return
	}
	snapshot := enrollment.fencer.Current()
	if !snapshot.CanMutate() {
		http.Error(writer, "regional authority is not writable", http.StatusServiceUnavailable)
		return
	}
	peerIP, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || net.ParseIP(peerIP) == nil {
		http.Error(writer, "direct private peer is required", http.StatusForbidden)
		return
	}
	wire, err := io.ReadAll(io.LimitReader(request.Body, hostenroll.MaxRequestBytes+1))
	if err != nil || len(wire) > hostenroll.MaxRequestBytes {
		http.Error(writer, "host enrollment request is too large", http.StatusRequestEntityTooLarge)
		return
	}
	enrollmentRequest, descriptor, err := hostenroll.ParseRequest(wire, time.Now().UTC())
	if err != nil {
		var historical hostenroll.Request
		if json.Unmarshal(wire, &historical, json.RejectUnknownMembers(true)) != nil ||
			historical.IssuedAt.IsZero() || !historical.IssuedAt.Before(time.Now().Add(-48*time.Hour)) {
			http.Error(writer, "host enrollment request is invalid", http.StatusBadRequest)
			return
		}
		enrollmentRequest, descriptor, err = hostenroll.ParseRequest(wire, historical.IssuedAt.Add(time.Second))
		if err != nil {
			http.Error(writer, "host enrollment request is invalid", http.StatusBadRequest)
			return
		}
		grant, _, readErr := enrollment.grants.Read(request.Context(), enrollmentRequest.InstanceID)
		stored := grant.Request
		if enrollmentRequest.Operation == "renew" {
			stored = grant.RenewalRequest
		}
		if readErr != nil || grant.Disabled || !bytes.Equal(wire, stored) {
			http.Error(writer, "stale host request has no exact grant", http.StatusPreconditionFailed)
			return
		}
	}
	response, err := enrollment.enroll(request.Context(), snapshot.Epoch, peerIP, wire, enrollmentRequest, descriptor)
	if err != nil {
		if errors.Is(err, errStaleUnclaimedRenewal) {
			writer.Header().Set("X-TerraScale-Host-Enrollment-Error", staleUnclaimedRenewal)
			http.Error(writer, "stale unclaimed host renewal", http.StatusPreconditionFailed)
			return
		}
		http.Error(writer, "host enrollment held", http.StatusConflict)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_, _ = writer.Write(response)
}

func (enrollment *managedHostEnrollment) enroll(ctx context.Context, epoch uint64, peerIP string, wire []byte,
	request hostenroll.Request, descriptor hostboot.Descriptor,
) ([]byte, error) {
	if descriptor.IsStatic() {
		return enrollment.enrollStatic(ctx, epoch, peerIP, wire, request, descriptor)
	}
	ctx = authority.WithActiveWorkloadEffectContext(ctx)
	release, err := enrollment.beginActiveEffect(ctx, epoch, descriptor)
	if err != nil {
		return nil, err
	}
	defer release()
	return enrollment.enrollActive(ctx, epoch, peerIP, wire, request, descriptor)
}

func (enrollment *managedHostEnrollment) beginActiveEffect(ctx context.Context, epoch uint64,
	descriptor hostboot.Descriptor,
) (func(), error) {
	gate, ok := enrollment.fencer.(interface {
		BeginActiveWorkloadEffect(context.Context, uint64, authority.WorkloadScope) (func(), error)
	})
	if !ok {
		return nil, errors.New("managed host enrollment requires a terminal effect gate")
	}
	return gate.BeginActiveWorkloadEffect(ctx, epoch, authority.WorkloadScope{
		DatabaseID: descriptor.DatabaseID, PartitionID: descriptor.PartitionID,
	})
}

func (enrollment *managedHostEnrollment) enrollActive(ctx context.Context, epoch uint64, peerIP string, wire []byte,
	request hostenroll.Request, descriptor hostboot.Descriptor,
) ([]byte, error) {
	if err := enrollment.guardActiveEffect(ctx, epoch, descriptor); err != nil {
		return nil, err
	}
	if descriptor.Cell != enrollment.cell || descriptor.Region != string(enrollment.region) ||
		descriptor.Owner != enrollment.owner || descriptor.FleetGeneration != enrollment.generation {
		return nil, errors.New("host descriptor is outside this regional fleet")
	}
	csr, err := hostenroll.ParseCSR(request.CSRPEM)
	if err != nil {
		return nil, err
	}
	instance, err := enrollment.observePeer(ctx, peerIP, request.InstanceID, descriptor)
	if err != nil {
		return nil, err
	}
	registration, err := enrollment.registration(ctx, request, descriptor, instance)
	if err != nil {
		return nil, err
	}
	if err := enrollment.verifier.VerifyManagedRegistration(ctx, registration); err != nil {
		return nil, err
	}
	digest, err := descriptor.Digest()
	if err != nil {
		return nil, err
	}
	var grant hostenroll.Grant
	var revision uint64
	var effectID string
	var effectSequence uint64
	var priorGrant enrollmentGrantSnapshot
	if request.Operation == "renew" {
		prior, _, err := enrollment.grants.Read(ctx, request.InstanceID)
		if err != nil || prior.Disabled || prior.CreateKey != descriptor.CreateKey ||
			prior.DescriptorSHA256 != digest {
			return nil, errors.New("host renewal has no active exact enrollment grant")
		}
		var original hostenroll.Request
		if json.Unmarshal(prior.Request, &original, json.RejectUnknownMembers(true)) != nil ||
			original.IdentityPublicKey != request.IdentityPublicKey ||
			original.NATSUserPublicKey != request.NATSUserPublicKey || original.CSRPEM != request.CSRPEM {
			return nil, errors.New("host renewal changes an enrolled identity or CSR")
		}
		if time.Since(request.IssuedAt) > 5*time.Minute && !bytes.Equal(prior.RenewalRequest, wire) {
			return nil, errStaleUnclaimedRenewal
		}
		priorGrant, err = enrollment.readGrantSnapshot(ctx, request.InstanceID)
		if err != nil {
			return nil, err
		}
		effectID, effectSequence, err = enrollment.beginGrantMutation(ctx, epoch, descriptor, request.InstanceID)
		if err != nil {
			return nil, err
		}
		grant, revision, err = enrollment.grants.ClaimRenew(ctx, request.InstanceID, wire, time.Now().UTC())
	} else {
		priorGrant, err = enrollment.readGrantSnapshot(ctx, request.InstanceID)
		if err != nil {
			return nil, err
		}
		effectID, effectSequence, err = enrollment.beginGrantMutation(ctx, epoch, descriptor, request.InstanceID)
		if err != nil {
			return nil, err
		}
		grant, revision, err = enrollment.grants.Claim(ctx, hostenroll.Grant{SchemaVersion: 1,
			InstanceID: request.InstanceID, CreateKey: descriptor.CreateKey,
			DescriptorSHA256: digest, Request: wire})
	}
	if err != nil {
		return nil, enrollment.settleKnownNoWrite(ctx, epoch, descriptor, request.InstanceID,
			effectID, effectSequence, priorGrant, err)
	}
	if err := enrollment.settleGrantMutation(ctx, epoch, descriptor, request.InstanceID,
		effectID, effectSequence, grant, revision, false); err != nil {
		return nil, err
	}
	cached := grant.Response
	if request.Operation == "renew" {
		cached = grant.RenewalResponse
	}
	if len(cached) != 0 {
		if err := enrollment.guardActiveEffect(ctx, epoch, descriptor); err != nil {
			return nil, err
		}
		return cached, nil
	}
	receipt, err := enrollment.controller.Register(ctx, registration)
	if err != nil {
		return nil, err
	}
	if _, err := enrollment.observePeer(ctx, peerIP, request.InstanceID, descriptor); err != nil {
		return nil, err
	}
	if err := enrollment.guardActiveEffect(ctx, epoch, descriptor); err != nil {
		return nil, err
	}
	jwt, chain, expires, err := enrollment.issuer.Issue(request, csr, descriptor.Node, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	response := hostenroll.Response{SchemaVersion: 1, Operation: request.Operation,
		InstanceID: request.InstanceID, Node: descriptor.Node, DescriptorSHA256: digest,
		RequestSHA256: hostenroll.RequestSHA256(wire), Nonce: request.Nonce,
		RegistrationReceipt: receipt, NATSUserJWT: jwt, TLSCertificatePEM: string(chain), ExpiresAt: expires}
	if enrollment.services != nil {
		response.NetBird = enrollment.services.netbird()
	}
	if err := response.Sign(enrollment.responseKey); err != nil {
		return nil, err
	}
	responseWire, err := protocol.EncodeJSON(response)
	if err != nil {
		return nil, err
	}
	responseWire, err = enrollment.prepareRuntimeWorker(ctx, epoch, wire, responseWire)
	if err != nil {
		return nil, err
	}
	if _, err := enrollment.observePeer(ctx, peerIP, request.InstanceID, descriptor); err != nil {
		return nil, err
	}
	priorGrant, err = enrollment.readGrantSnapshot(ctx, request.InstanceID)
	if err != nil {
		return nil, err
	}
	effectID, effectSequence, err = enrollment.beginGrantMutation(ctx, epoch, descriptor, request.InstanceID)
	if err != nil {
		return nil, err
	}
	if request.Operation == "renew" {
		if err := enrollment.grants.FinishRenew(ctx, grant, revision, responseWire, time.Now().UTC()); err != nil {
			return nil, enrollment.settleKnownNoWrite(ctx, epoch, descriptor, request.InstanceID,
				effectID, effectSequence, priorGrant, err)
		}
		grant.RenewalResponse = bytes.Clone(responseWire)
	} else {
		grant, err = enrollment.grants.Finish(ctx, grant, revision, responseWire)
		if err != nil {
			return nil, enrollment.settleKnownNoWrite(ctx, epoch, descriptor, request.InstanceID,
				effectID, effectSequence, priorGrant, err)
		}
	}
	if err := enrollment.settleGrantMutation(ctx, epoch, descriptor, request.InstanceID,
		effectID, effectSequence, grant, revision, true); err != nil {
		return nil, err
	}
	return responseWire, nil
}

type enrollmentGrantJournal interface {
	BeginEnrollmentEffect(context.Context, uint64, authority.WorkloadScope, string, string) (uint64, error)
	SettleEnrollmentEffect(context.Context, uint64, authority.WorkloadScope, string, string, uint64) (uint64, error)
}

type enrollmentGrantSnapshot struct {
	grant    hostenroll.Grant
	revision uint64
	absent   bool
}

func (enrollment *managedHostEnrollment) readGrantSnapshot(ctx context.Context,
	instanceID string,
) (enrollmentGrantSnapshot, error) {
	grant, revision, err := enrollment.grants.Read(ctx, instanceID)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return enrollmentGrantSnapshot{absent: true}, nil
	}
	if err != nil {
		return enrollmentGrantSnapshot{}, err
	}
	return enrollmentGrantSnapshot{grant: grant, revision: revision}, nil
}

func (enrollment *managedHostEnrollment) settleKnownNoWrite(ctx context.Context, epoch uint64,
	descriptor hostboot.Descriptor, instanceID, effectID string, effectSequence uint64,
	before enrollmentGrantSnapshot, mutationErr error,
) error {
	if !hostenroll.IsGrantMutationNotApplied(mutationErr) {
		return mutationErr
	}
	after, err := enrollment.readGrantSnapshot(ctx, instanceID)
	if err != nil || !reflect.DeepEqual(after, before) {
		return mutationErr
	}
	journal, ok := enrollment.fencer.(enrollmentGrantJournal)
	if !ok {
		return mutationErr
	}
	scope := authority.WorkloadScope{DatabaseID: descriptor.DatabaseID, PartitionID: descriptor.PartitionID}
	if _, err := journal.SettleEnrollmentEffect(ctx, epoch, scope, effectID, instanceID, effectSequence); err != nil {
		return errors.Join(mutationErr, err)
	}
	return mutationErr
}

func (enrollment *managedHostEnrollment) beginGrantMutation(ctx context.Context, epoch uint64,
	descriptor hostboot.Descriptor, instanceID string,
) (string, uint64, error) {
	journal, ok := enrollment.fencer.(enrollmentGrantJournal)
	if !ok {
		return "", 0, errors.New("managed host enrollment requires an R3 grant effect journal")
	}
	effectID := entityid.New()
	scope := authority.WorkloadScope{DatabaseID: descriptor.DatabaseID, PartitionID: descriptor.PartitionID}
	sequence, err := journal.BeginEnrollmentEffect(ctx, epoch, scope, effectID, instanceID)
	if err != nil {
		return "", 0, err
	}
	if err := enrollment.guardActiveEffect(ctx, epoch, descriptor); err != nil {
		return "", 0, err
	}
	return effectID, sequence, nil
}

func (enrollment *managedHostEnrollment) settleGrantMutation(ctx context.Context, epoch uint64,
	descriptor hostboot.Descriptor, instanceID, effectID string, effectSequence uint64,
	expected hostenroll.Grant, revision uint64, requireNewRevision bool,
) error {
	observed, observedRevision, err := enrollment.grants.Read(ctx, instanceID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(observed, expected) ||
		(!requireNewRevision && observedRevision != revision) ||
		(requireNewRevision && observedRevision <= revision) {
		return errors.New("host enrollment grant changed before exact effect readback")
	}
	journal, ok := enrollment.fencer.(enrollmentGrantJournal)
	if !ok {
		return errors.New("managed host enrollment requires an R3 grant effect journal")
	}
	scope := authority.WorkloadScope{DatabaseID: descriptor.DatabaseID, PartitionID: descriptor.PartitionID}
	_, err = journal.SettleEnrollmentEffect(ctx, epoch, scope, effectID, instanceID, effectSequence)
	return err
}

func (enrollment *managedHostEnrollment) guardActiveEffect(ctx context.Context, epoch uint64,
	descriptor hostboot.Descriptor,
) error {
	reader, ok := enrollment.fencer.(authority.TerminalIntentReader)
	if !ok {
		return errors.New("managed host enrollment requires terminal marker readback")
	}
	_, err := reader.ReadTerminalIntent(ctx, descriptor.DatabaseID, descriptor.PartitionID)
	if err == nil {
		return authority.ErrFenced
	}
	if !errors.Is(err, authority.ErrNotFound) {
		return err
	}
	return enrollment.fencer.Guard(ctx, epoch)
}

func (enrollment *managedHostEnrollment) observePeer(ctx context.Context, peerIP, instanceID string,
	descriptor hostboot.Descriptor,
) (oci.Instance, error) {
	address, err := netip.ParseAddr(peerIP)
	if err != nil || !address.Is4() || !address.IsPrivate() || address.IsLoopback() {
		return oci.Instance{}, errors.New("host enrollment peer is not a private IPv4 address")
	}
	observed, err := enrollment.fleet.Observe(ctx)
	if err != nil {
		return oci.Instance{}, err
	}
	var selected oci.Instance
	count := 0
	for _, instance := range observed {
		if instance.ID == instanceID || instance.PrivateIP == peerIP || instance.Node == descriptor.Node {
			selected = instance
			count++
		}
	}
	digest, err := descriptor.Digest()
	if err != nil {
		return oci.Instance{}, err
	}
	if count != 1 || selected.ID != instanceID || selected.PrivateIP != peerIP ||
		selected.Node != descriptor.Node || selected.CreateKey != descriptor.CreateKey ||
		selected.Owner != enrollment.owner || selected.Region != enrollment.region ||
		selected.Generation != enrollment.generation || selected.ImageID != descriptor.ImageID ||
		selected.BootDescriptorSHA256 != digest || selected.PlacementGeneration != descriptor.IntentGeneration ||
		selected.PlacementProfileDigest != descriptor.ManagedHostProfileDigest || selected.State != "RUNNING" {
		return oci.Instance{}, errors.New("direct peer does not match the exact current OCI host launch")
	}
	return selected, nil
}

func (enrollment *managedHostEnrollment) registration(ctx context.Context, request hostenroll.Request,
	descriptor hostboot.Descriptor, instance oci.Instance,
) (host.Registration, error) {
	versioned, err := enrollment.members.ReadMember(ctx, descriptor.DatabaseID, descriptor.PartitionID, descriptor.SeatID)
	if err != nil {
		return host.Registration{}, err
	}
	state := versioned.State
	if versioned.Revision == 0 || state.Validate() != nil || state.InstanceID != instance.ID ||
		state.HostNode != descriptor.Node || state.CreateKey != descriptor.CreateKey ||
		state.HostAttempt != descriptor.HostAttempt || state.IntentGeneration != descriptor.IntentGeneration ||
		state.IntentPayloadDigest != descriptor.IntentPayloadDigest ||
		state.CanonicalRosterDigest != descriptor.CanonicalRosterDigest ||
		state.ManagedHostProfileDigest != descriptor.ManagedHostProfileDigest ||
		state.RuntimeManifestDigest != descriptor.RuntimeManifestDigest || !managedRegistrationStage(state.Stage) {
		return host.Registration{}, errors.New("host descriptor differs from the active durable placement seat")
	}
	entry, err := enrollment.intents.ReadPlacementIntent(ctx, descriptor.DatabaseID, descriptor.PartitionID)
	if err != nil {
		return host.Registration{}, err
	}
	if entry.Kind != authority.MutationPlacementIntent || entry.SubjectKey != descriptor.DatabaseID+"."+descriptor.PartitionID ||
		entry.Sequence == 0 || len(entry.Payload) == 0 || len(entry.Payload) > maxPlacementIntentBytes {
		return host.Registration{}, errors.New("current placement intent is invalid")
	}
	intent, err := placement.DecodeCommittedIntent(entry.Payload)
	if err != nil || intent.ValidateForAdmission() != nil || intent.Generation != descriptor.IntentGeneration ||
		intent.PayloadDigest() != descriptor.IntentPayloadDigest {
		return host.Registration{}, errors.New("host enrollment placement intent is stale")
	}
	row, ok := rosterRowForSeat(intent, enrollment.region, descriptor.SeatID)
	if !ok || row != state.CanonicalRosterRow || row.FailureDomain != instance.FaultDomain {
		return host.Registration{}, errors.New("host enrollment roster seat differs from OCI placement")
	}
	profile, err := intent.ManagedHostProfile(enrollment.region)
	if err != nil || profile != state.ManagedHostProfile {
		return host.Registration{}, errors.New("host enrollment compute profile is stale")
	}
	if profile.AllocatableMemoryBytes > uint64(^uint64(0)>>1) || profile.SystemReserveBytes > uint64(^uint64(0)>>1) {
		return host.Registration{}, errors.New("host enrollment memory profile exceeds signed range")
	}
	return host.Registration{
		ID:   entityid.Derive("host", enrollment.cell, descriptor.Node),
		Cell: enrollment.cell, Node: descriptor.Node, FailureDomain: row.FailureDomain,
		Environment: enrollment.environment, Roles: []string{"terrabase"},
		PublicKey: request.IdentityPublicKey, NATSUserPublicKey: request.NATSUserPublicKey,
		Generation: 1, Capacity: host.Capacity{CPU: int(profile.Compute.WholeOCPUs),
			MemoryBytes: int64(profile.AllocatableMemoryBytes), DiskBytes: enrollment.diskBytes},
		SystemReserveBytes: int64(profile.SystemReserveBytes),
		ManagedPlacement: &host.ManagedPlacementBinding{DatabaseID: descriptor.DatabaseID,
			PartitionID: descriptor.PartitionID, SeatID: descriptor.SeatID,
			IntentGeneration: descriptor.IntentGeneration, IntentPayloadDigest: descriptor.IntentPayloadDigest,
			CanonicalRosterDigest: descriptor.CanonicalRosterDigest, ManagedHostProfileDigest: descriptor.ManagedHostProfileDigest},
		ManagedMember: &host.ManagedMemberBinding{Scope: host.MemberScope{
			ClusterID: intent.CanonicalRoster.ClusterID, TenantID: intent.CanonicalRoster.TenantID,
			DatabaseID: intent.CanonicalRoster.DatabaseID, ShardID: intent.CanonicalRoster.ShardID,
			MemberID: row.MemberID, Incarnation: row.Incarnation}, HostAttempt: descriptor.HostAttempt},
		ManagedOCI: &host.ManagedOCIBinding{Region: string(instance.Region), InstanceID: instance.ID,
			Owner: instance.Owner, FleetGeneration: instance.Generation, CreateKey: instance.CreateKey},
	}, nil
}
