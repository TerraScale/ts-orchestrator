package swarmruntime

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/moby/swarmkit/v2/api"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// This starts at the existing admission fixture's actual TLS join/dual-key
// boundary. Fixed-child ordered registration and live OCI are separate fixtures.
func checkWorkerMembershipIntegration(t *testing.T, ctx context.Context, manager, worker *Node, accepted hostenroll.VerifiedSwarmWorker,
	binding hostenroll.SwarmNodeBinding, certificate []byte, responsePublic ed25519.PublicKey, responseKey, hostKey ed25519.PrivateKey,
) {
	t.Helper()
	var transport hostenroll.WorkerTransport
	if err := protocol.DecodeStrict(accepted.Wire(), &transport, 128<<10); err != nil {
		t.Fatal(err)
	}
	record := hostenroll.SwarmMembership{Transport: transport, Binding: binding, Certificate: certificate}
	if _, err := hostenroll.VerifySwarmMembership(record, responsePublic); err != nil {
		t.Fatal("retained actual worker admission did not authenticate", err)
	}
	for _, mutate := range []func(*hostenroll.SwarmMembership){
		func(r *hostenroll.SwarmMembership) { r.Binding.NodeID += "other" },
		func(r *hostenroll.SwarmMembership) { r.Binding.HostSignature = r.Binding.NodeSignature },
		func(r *hostenroll.SwarmMembership) { r.Binding.NodeSignature = r.Binding.HostSignature },
		func(r *hostenroll.SwarmMembership) { r.Transport.Response = []byte("another signed admission") },
	} {
		changed := record
		mutate(&changed)
		if _, err := hostenroll.VerifySwarmMembership(changed, responsePublic); err == nil {
			t.Fatal("retained admission accepted a changed node, signature or transport")
		}
	}
	server, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	t.Cleanup(func() { server.Shutdown(); server.WaitForShutdown() })
	if !server.ReadyForConnections(5 * time.Second) {
		t.Fatal("membership grant broker unavailable")
	}
	connection, err := nats.Connect(server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	store, err := hostenroll.OpenGrantStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	grant, _, err := store.Claim(ctx, hostenroll.Grant{SchemaVersion: 1, InstanceID: accepted.Worker().InstanceID,
		CreateKey: entityid.Derive("worker-membership-test", accepted.Worker().InstanceID), DescriptorSHA256: hostenroll.RequestSHA256(transport.Request), Request: transport.Request})
	if err != nil {
		t.Fatal(err)
	}
	grant, revision, err := store.Read(ctx, grant.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	grant, err = store.Finish(ctx, grant, revision, transport.Response)
	if err != nil {
		t.Fatal(err)
	}
	grant, revision, err = store.Read(ctx, grant.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordSwarmMembership(ctx, grant, revision, record); err != nil {
		t.Fatal("actual JetStream membership CAS failed", err)
	}
	if _, err := store.RecordSwarmMembership(ctx, grant, revision, record); err == nil {
		t.Fatal("membership overwrote a newer grant revision")
	}
	// Reopening readers models a new manager, with no local admission cache.
	reopened, err := hostenroll.OpenGrantStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	held, heldRevision, err := reopened.Read(ctx, grant.InstanceID)
	if err != nil || held.SwarmMembership == nil {
		t.Fatal("membership did not survive a new manager reader", err)
	}
	if _, err := hostenroll.VerifySwarmMembership(*held.SwarmMembership, responsePublic); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.TerminalFence(ctx, held, heldRevision, entityid.Derive("terminal", grant.InstanceID)); err != nil {
		t.Fatal(err)
	}
	disabled, disabledRevision, err := reopened.Read(ctx, grant.InstanceID)
	if err != nil || !disabled.Disabled {
		t.Fatal("terminal fence did not retain worker grant", err)
	}
	if _, err := store.RecordSwarmMembership(ctx, disabled, disabledRevision, record); err == nil {
		t.Fatal("disabled instance accepted a worker membership")
	}
	client, err := manager.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, availability := range []api.NodeSpec_Availability{api.NodeAvailabilityPause, api.NodeAvailabilityActive, api.NodeAvailabilityDrain} {
		before, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: worker.ID()})
		if err != nil {
			t.Fatal(err)
		}
		if err := updateWorkerMembership(ctx, client, before.Node, availability, availability == api.NodeAvailabilityDrain); err != nil {
			t.Fatal(err)
		}
		after, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: worker.ID()})
		if err != nil || after.Node.Spec.Availability != availability {
			t.Fatal("actual Swarm node availability did not follow membership", err)
		}
		if availability == api.NodeAvailabilityPause && after.Node.Spec.Annotations.Labels[LabelHostRole] != accepted.Worker().Role {
			t.Fatal("temporary outage revoked trusted identity")
		}
		if availability == api.NodeAvailabilityDrain && len(after.Node.Spec.Annotations.Labels) != 0 {
			t.Fatal("verified revocation retained trusted placement labels")
		}
	}
	// Restore only through the original verified admission for the outer fixture.
	if _, err := AdmitNode(ctx, client, worker.ID(), Admission{Region: accepted.Worker().Region, HostID: accepted.Worker().RegistrationID,
		InstanceID: accepted.Worker().InstanceID, FounderID: accepted.Worker().FounderID, Role: accepted.Worker().Role}); err != nil {
		t.Fatal(err)
	}
	var response hostenroll.Response
	if err := json.Unmarshal(transport.Response, &response); err != nil {
		t.Fatal(err)
	}
	shortWorker := *response.Swarm
	shortWorker.IssuedAt, shortWorker.ExpiresAt = time.Now().UTC(), time.Now().UTC().Add(time.Second)
	response.Swarm, response.ExpiresAt = &shortWorker, shortWorker.ExpiresAt
	if err := response.Sign(responseKey); err != nil {
		t.Fatal(err)
	}
	shortResponse, err := protocol.EncodeJSON(response)
	if err != nil {
		t.Fatal(err)
	}
	shortTransport := hostenroll.WorkerTransport{Request: transport.Request, Response: shortResponse}
	wire, err := protocol.EncodeJSON(shortTransport)
	if err != nil {
		t.Fatal(err)
	}
	request, descriptor, err := hostenroll.ParseRequest(transport.Request, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	short, err := hostenroll.VerifyWorkerTransport(wire, responsePublic, hostenroll.InstanceMetadata{InstanceID: request.InstanceID, Descriptor: descriptor}, shortWorker.Architecture, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := worker.nodeSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	shortBinding, err := hostenroll.SignWorkerBinding(short, worker.ID(), hostKey, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	shortRecord := hostenroll.SwarmMembership{Transport: shortTransport, Binding: shortBinding, Certificate: certificate}
	select {
	case <-time.After(time.Until(shortWorker.ExpiresAt) + 10*time.Millisecond):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := hostenroll.VerifyWorkerTransport(wire, responsePublic, hostenroll.InstanceMetadata{InstanceID: request.InstanceID, Descriptor: descriptor}, shortWorker.Architecture, time.Now()); err == nil {
		t.Fatal("expired projection still admitted a new runtime")
	}
	if _, err := hostenroll.VerifySwarmMembership(shortRecord, responsePublic); err != nil {
		t.Fatal("admission expiry invalidated the authenticated historical membership", err)
	}
}
