//go:build sandboxvm

package vmqualruntime

import (
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

func TestGuestReadyCallsAdmittedSourceOnlyAfterAllLaunchGuests(t *testing.T) {
	config := vmnet.DefaultConfig()
	config.Regions = append(config.Regions, vmnet.RegionSpec{Code: vmqual.FourthRegion, Guests: []vmnet.GuestSpec{{ID: "iad-member-1"}, {ID: "iad-member-2"}}})
	plan, err := vmnet.Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	services := &qualificationRuntimeServices{plan: plan}
	factory := &firecrackerFactory{services: services, active: map[string]*sandboxVM{}}
	if err := factory.SetQualificationControlRuntimeSource(&qualificationAdmittedControlSource{}); err != nil {
		t.Fatal(err)
	}
	var launch []string
	for _, region := range plan.Regions {
		for _, guest := range region.Guests {
			factory.active[guest.ID] = &sandboxVM{id: guest.ID, guest: vmqual.Guest{ID: guest.ID, Region: region.Code}}
			if region.Code != vmqual.FourthRegion {
				launch = append(launch, guest.ID)
			}
		}
	}
	if err := factory.guestReady(t.Context(), "iad-member-1"); err != nil || len(services.controlReady) != 0 {
		t.Fatalf("reserved guest changed launch readiness: %v", err)
	}
	for _, id := range launch[:len(launch)-1] {
		if err := factory.guestReady(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	// The actual admitted source has no records. Its refusal must reach the
	// final transition, rather than silently returning a ready control runtime.
	if err := factory.guestReady(t.Context(), launch[len(launch)-1]); !errors.Is(err, bootstrap.ErrControlRuntimeUnavailable) {
		t.Fatalf("final ready transition did not call the admitted source: %v", err)
	}
	if err := factory.guestReady(t.Context(), launch[0]); !errors.Is(err, bootstrap.ErrControlRuntimeUnavailable) {
		t.Fatalf("startup failure was lost on repeated ready transition: %v", err)
	}
}

func TestAdmittedControlSourceSelectsLiveCandidateAndRejectsChangedMembership(t *testing.T) {
	plan, err := vmnet.Plan(vmnet.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	for i := range plan.Listeners {
		if plan.Listeners[i].Name == "nats" {
			plan.Listeners[i].Address = "127.0.0.1"
		}
	}
	server, transport := startDeliveryTestNATSPlan(t, plan)
	options, err := transport.options(transport.controller)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := nats.Connect(server.ClientURL(), options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	leaders, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "ORCH_LEADERS", Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "ORCH_RUNTIME", Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lease := authority.RegionalAuthorityLeaseDocument{SchemaVersion: 1, AuthorityId: "gru-regional", Epoch: 7, CandidateId: "gru-controller-gru-member-2", LeaseId: "test-live-lease", IssuedAt: now.Add(-time.Second), DurationMilliseconds: 30000}
	writeLease := func() {
		t.Helper()
		raw, err := json.Marshal(lease)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaders.Put(t.Context(), "authority.regional", raw); err != nil {
			t.Fatal(err)
		}
	}
	writeLease()
	identity, err := directory.RegionalRuntimeMembershipIdentityCreate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.Dispose)
	record := directory.RegionalRuntimeMember{SchemaVersion: 1, Cell: "gru", Cluster: "orchestrator-control-gru", Instance: "gru-member-2", SessionId: "0123456789abcdef0123456789abcdef", Build: "qualified", Capabilities: []string{"authority"}, StartedAt: now.Add(-time.Minute), ObservedAt: now, LeaseExpiresAt: now.Add(30 * time.Second), AuthorityState: "leader", IsAuthorityLeader: true, AuthorityEpoch: 7, AuthorityRevision: 1, IdentityKeyId: identity.KeyId, IdentityPublicKey: identity.PublicKey}
	writeMember := func() {
		t.Helper()
		record.IdentitySignature = identity.Sign(record)
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := membership.Put(t.Context(), "controller.gru-member-2", raw); err != nil {
			t.Fatal(err)
		}
	}
	writeMember()
	source := &qualificationAdmittedControlSource{config: bootstrap.NATSControlRuntimeConfig{
		Stores: map[string]bootstrap.ControlNATSStore{"gru": {URL: server.ClientURL(), Options: options}},
		Members: []bootstrap.ControlRuntimeMember{
			{MemberID: "first", HostID: "gru-member-1", Region: "gru", Instance: "gru-member-1", Store: "gru"},
			{MemberID: "second", HostID: "gru-member-2", Region: "gru", Instance: "gru-member-2", Store: "gru", IdentityPublicKey: identity.PublicKey},
		},
	}, admissions: map[string]qualificationControlHostAdmission{"gru-member-2": {Architecture: runtimeplan.HostArchitectureArm64, Generation: 19}}, expectedStoreServers: map[string]string{"gru": connection.ConnectedServerName()}}
	consumerConfig, _, err := source.RuntimeConfig(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	consumerConfig.Members[0].Instance = "foreign"
	delete(consumerConfig.Stores, "gru")
	if source.config.Members[0].Instance != "gru-member-1" || len(source.config.Stores) != 1 {
		t.Fatal("consumer changed the immutable source admission")
	}
	candidate, resolve, command, err := source.HostControlResolvers(t.Context(), "gru")
	if err != nil || candidate != lease.CandidateId {
		t.Fatalf("live candidate = %q: %v", candidate, err)
	}
	host, err := resolve(t.Context(), "gru-member-2")
	if err != nil {
		t.Fatal(err)
	}
	observed, err := command(t.Context(), host)
	if err != nil || observed.DesiredGeneration != 19 || observed.Epoch != 7 || observed.CandidateID != candidate {
		t.Fatalf("command authority = %+v: %v", observed, err)
	}
	record.AuthorityEpoch = 6
	writeMember()
	if _, err := resolve(t.Context(), "gru-member-2"); err == nil {
		t.Fatal("accepted signed membership from replaced authority")
	}
	record.AuthorityEpoch = 7
	record.AuthorityRevision = 1000
	writeMember()
	if _, err := resolve(t.Context(), "gru-member-2"); err == nil {
		t.Fatal("accepted a membership revision beyond the live lease revision")
	}
	record.AuthorityRevision = 1
	writeMember()
	lease.CandidateId = "gru-controller-gru-member-1"
	writeLease()
	if _, err := command(t.Context(), host); err == nil {
		t.Fatal("retained the former command signer after leader replacement")
	}
}
