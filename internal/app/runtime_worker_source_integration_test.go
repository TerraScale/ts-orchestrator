package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"strings"
	"testing"
	"time"

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
		finish := assertGrantReadsUseLeader(t, js)
		defer finish()
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

func assertGrantReadsUseLeader(t *testing.T, js jetstream.JetStream) func() {
	t.Helper()
	options := js.Options()
	prefix := strings.TrimSuffix(options.APIPrefix, ".")
	if options.Domain != "" {
		prefix = "$JS." + options.Domain + ".API"
	} else if prefix == "" {
		prefix = "$JS.API"
	}
	leader, err := js.Conn().SubscribeSync(prefix + ".STREAM.MSG.GET.KV_" + hostenroll.GrantBucket)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := js.Conn().SubscribeSync(prefix + ".DIRECT.GET.>")
	if err != nil {
		_ = leader.Unsubscribe()
		t.Fatal(err)
	}
	if err := js.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	return func() {
		defer leader.Unsubscribe()
		defer direct.Unsubscribe()
		if err := js.Conn().Flush(); err != nil {
			t.Fatal(err)
		}
		reads, _, err := leader.Pending()
		if err != nil || reads == 0 {
			t.Fatalf("no leader enrollment reads: count=%d, error=%v", reads, err)
		}
		count, _, err := direct.Pending()
		if err != nil {
			t.Fatal(err)
		}
		for range count {
			message, err := direct.NextMsg(time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(message.Subject, prefix+".DIRECT.GET.KV_"+hostenroll.GrantBucket) {
				t.Fatalf("enrollment authorization used follower read: %s", message.Subject)
			}
		}
	}
}

func TestWorkerPreparationRequiresExactLiveClaim(t *testing.T) {
	now := time.Now().UTC()
	request := []byte("exact authenticated request")
	query := swarmruntime.WorkerRegistrationQuery{Request: request}
	for _, test := range []struct {
		name  string
		grant hostenroll.Grant
		want  bool
	}{
		{"initial", hostenroll.Grant{Request: request, OwnerToken: "owner", LeaseUntil: now.Add(time.Minute)}, true},
		{"renewal", hostenroll.Grant{RenewalRequest: request, RenewalToken: "owner", RenewalLeaseUntil: now.Add(time.Minute)}, true},
		{"expired initial", hostenroll.Grant{Request: request, OwnerToken: "owner", LeaseUntil: now}, false},
		{"expired renewal", hostenroll.Grant{RenewalRequest: request, RenewalToken: "owner", RenewalLeaseUntil: now}, false},
		{"missing owner", hostenroll.Grant{Request: request, LeaseUntil: now.Add(time.Minute)}, false},
		{"other request", hostenroll.Grant{Request: []byte("other"), OwnerToken: "owner", LeaseUntil: now.Add(time.Minute)}, false},
		{"completed mismatch", hostenroll.Grant{Request: request, Response: []byte("completed"), OwnerToken: "owner", LeaseUntil: now.Add(time.Minute)}, false},
		{"disabled", hostenroll.Grant{Request: request, OwnerToken: "owner", LeaseUntil: now.Add(time.Minute), Disabled: true}, false},
		{"terminal", hostenroll.Grant{Request: request, OwnerToken: "owner", LeaseUntil: now.Add(time.Minute), TerminalOperationID: "terminal"}, false},
		{"identity reset", hostenroll.Grant{Request: request, OwnerToken: "owner", LeaseUntil: now.Add(time.Minute), IdentityResetOperationID: "reset"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := workerGrantAuthorizesPreparation(test.grant, query, now); got != test.want {
				t.Fatalf("claim authorizes preparation=%v, want %v", got, test.want)
			}
		})
	}
}

func TestWorkerPoolAdmissionRemainsPendingWithoutCreationLineage(t *testing.T) {
	descriptor := hostboot.Static("gru", "GRU", "gru-1-pool-app-4")
	if err := refuseUnprovenPoolDescriptor(descriptor); !errors.Is(err, oci.ErrPoolCreationLineagePending) {
		t.Fatalf("pool descriptor admission=%v", err)
	}
	// Even an old node name cannot use the actual pool enrollment branch.
	var enrollment managedHostEnrollment
	if _, _, err := enrollment.observePoolNode(t.Context(), "10.0.0.4", hostenroll.Request{}, hostboot.Static("gru", "GRU", "ts-gru-4")); !errors.Is(err, oci.ErrPoolCreationLineagePending) {
		t.Fatalf("legacy pool branch admission=%v", err)
	}
}
