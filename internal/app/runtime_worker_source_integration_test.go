package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func TestWorkerSourceReadsCurrentRegistrationAndRevocationOverNATS(t *testing.T) {
	ctx := t.Context()
	js := testRolloutJetStream(t)
	control, err := authority.Start(ctx, js, authority.Config{DeploymentID: entityid.New(), Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	artifacts, err := js.CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket})
	if err != nil {
		t.Fatal(err)
	}
	_, responseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := host.NewController(ctx, host.ControllerConfig{Cell: "gru", Conn: js.Conn(), JS: js, Artifacts: artifacts,
		ResponseKey: responseKey, StateReplicas: 1, HostMutations: control, AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard})
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	natsPublic, err := pair.PublicKey()
	pair.Wipe()
	if err != nil {
		t.Fatal(err)
	}
	registration := host.Registration{Cell: "gru", Node: "worker-a", Environment: "canary", Roles: []string{"api"},
		PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: natsPublic, Generation: 1,
		Capacity: host.Capacity{CPU: 1, MemoryBytes: 256 << 20, DiskBytes: 1 << 30}}
	receipt, err := hosts.Register(ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	mutations, err := authority.OpenReader(ctx, js, "gru")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := host.NewReader(ctx, host.ReaderConfig{Cell: "gru", Conn: js.Conn(), JS: js, StateReplicas: 1, HostMutations: mutations})
	if err != nil {
		t.Fatal(err)
	}
	grants, err := hostenroll.OpenGrantStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	query := swarmruntime.WorkerRegistrationQuery{Request: []byte("retained authenticated enrollment request")}
	instance := "ocid1.instance.oc1.sa-saopaulo-1.worker"
	if _, _, err := grants.Claim(ctx, hostenroll.Grant{SchemaVersion: 1, InstanceID: instance, CreateKey: entityid.New(),
		DescriptorSHA256: hostenroll.RequestSHA256([]byte("descriptor")), Request: query.Request}); err != nil {
		t.Fatal(err)
	}
	read := func(query swarmruntime.WorkerRegistrationQuery) (swarmruntime.WorkerRegistrationSnapshot, error) {
		return currentWorkerRegistration(ctx, mutations, reader, js, query, instance, registration.Node, "gru")
	}
	snapshot, err := read(query)
	if err != nil || snapshot.Sequence != receipt.Revision || snapshot.Registration.Generation != 1 || snapshot.Retired || snapshot.InstanceID != instance {
		t.Fatalf("current snapshot: %+v error=%v", snapshot, err)
	}
	if _, err := read(swarmruntime.WorkerRegistrationQuery{Request: []byte("other request")}); err == nil {
		t.Fatal("another request inherited the retained enrollment grant")
	}
	if _, err := grants.Disable(ctx, instance); err != nil {
		t.Fatal(err)
	}
	if _, err := read(query); err == nil {
		t.Fatal("disabled enrollment remained admissible")
	}
}
