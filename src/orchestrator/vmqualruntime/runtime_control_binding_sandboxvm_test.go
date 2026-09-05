//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

func TestQualificationHostControlSignsWithEnrolledCandidateAndLiveAuthority(t *testing.T) {
	server, authority := startDeliveryTestNATS(t)
	config := vmnet.DefaultConfig()
	config.RunID = "0123456789abcdef0123456789abcdef"
	plan, err := vmnet.Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	region := plan.Regions[0]
	code := strings.ToLower(string(region.Code))
	guest := region.Guests[0]
	candidate := code + "-controller-" + guest.ID
	services := &qualificationRuntimeServices{plan: plan, started: true, nats: server, natsAuthority: authority}
	t.Cleanup(func() {
		if err := services.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	factory := &firecrackerFactory{services: services, active: map[string]*sandboxVM{guest.ID: {guest: vmqual.Guest{ID: guest.ID, Region: region.Code}}}}
	node, err := hostagent.NewNodeId(guest.ID)
	if err != nil {
		t.Fatal(err)
	}
	host := hostcontrol.Host{NodeID: node, Region: strings.ToUpper(code), Architecture: runtimeplan.HostArchitectureArm64}
	resolve := func(context.Context, string) (hostcontrol.Host, error) { return host, nil }
	now := time.Now().UTC()
	lease := delivery.RegionalCommandAuthority{AuthorityID: code + "-regional", Epoch: 7, DesiredGeneration: 9, CandidateID: candidate, LeaseID: "real-resolver-test-lease", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	var resolveErr error
	calls := 0
	refuseAt := 0
	takeoverAt := 0
	live := func(context.Context, hostcontrol.Host) (delivery.RegionalCommandAuthority, error) {
		calls++
		if calls == takeoverAt {
			changed := lease
			changed.CandidateID = code + "-controller-" + region.Guests[1].ID
			return changed, nil
		}
		if calls == refuseAt {
			return delivery.RegionalCommandAuthority{}, errors.New("live lease lost")
		}
		return lease, resolveErr
	}
	for _, badCandidate := range []string{"", code + "-controller-unknown", strings.ToLower(string(plan.Regions[1].Code)) + "-controller-" + plan.Regions[1].Guests[0].ID} {
		if _, err := factory.QualificationHostControl(context.Background(), code, badCandidate, resolve, live); err == nil {
			t.Fatalf("accepted unenrolled candidate %s", badCandidate)
		}
	}
	if _, err := factory.QualificationHostControl(context.Background(), strings.ToUpper(code), candidate, resolve, live); err == nil {
		t.Fatal("accepted noncanonical Region")
	}
	if _, err := factory.QualificationHostControl(context.Background(), code, candidate, resolve, nil); err == nil {
		t.Fatal("accepted absent live authority")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := factory.QualificationHostControl(canceled, code, candidate, resolve, live); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled binding: %v", err)
	}
	client, err := factory.QualificationHostControl(context.Background(), code, candidate, resolve, live)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.QualificationHostControl(context.Background(), code, candidate, resolve, live); err == nil {
		t.Fatal("accepted duplicate binding")
	}
	options, err := authority.options(authority.guests[guest.ID])
	if err != nil {
		t.Fatal(err)
	}
	responder, err := nats.Connect(server.ClientURL(), options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(responder.Close)
	topic, err := hostagent.NodeDrainSubject(node)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 10)
	var published atomic.Int32
	_, err = responder.Subscribe(topic, func(message *nats.Msg) {
		published.Add(1)
		received <- append([]byte(nil), message.Data...)
		receipt, _ := hostagent.NewDrainReceipt("drain-qualification", guest.ID, true, true, "")
		data, _ := json.Marshal(receipt)
		_ = message.Respond(data)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := responder.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SetDrain(context.Background(), guest.ID, "drain-qualification", true); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("live authority resolved %d times; want before signing, for signing, before publish", calls)
	}
	envelope, err := protocol.DecodeCommandEnvelope(<-received)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := base64.StdEncoding.DecodeString(authority.commandSigners[candidate].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := security.NewCommandSignatureVerifierFromKeys([]security.CommandSignatureTrustKey{{Algorithm: security.CommandSignatureAlgorithm, PublicKeySPKI: spki}})
	if err != nil {
		t.Fatal(err)
	}
	if verifier.Verify(envelope.SignedMaterial, envelope.Signature) != protocol.VerificationOutcomeValid {
		t.Fatal("wire command not signed by enrolled candidate")
	}
	var binding nodeauthority.SignedNodeCommand
	if err := json.Unmarshal(envelope.Payload.Bytes(), &binding); err != nil {
		t.Fatal(err)
	}
	if binding.CandidateID != candidate || binding.AuthorityID != lease.AuthorityID || binding.LeaseID != lease.LeaseID || binding.Subject != topic || binding.NodeID != guest.ID {
		t.Fatalf("incorrect signed binding: %+v", binding)
	}
	for _, step := range []int{2, 3} {
		calls = 0
		refuseAt = step
		if _, err := client.SetDrain(context.Background(), guest.ID, "drain-qualification", true); err == nil {
			t.Fatalf("published after authority lost at check %d", step)
		}
	}
	refuseAt = 0
	calls = 0
	takeoverAt = 3
	if _, err := client.SetDrain(context.Background(), guest.ID, "drain-qualification", true); err == nil {
		t.Fatal("published after final-check candidate takeover")
	}
	takeoverAt = 0
	original := lease
	for _, test := range []struct {
		name   string
		change func()
	}{
		{"expired", func() { lease.ExpiresAt = time.Now().Add(-time.Second) }},
		{"future", func() { lease.IssuedAt = time.Now().Add(time.Minute) }},
		{"wrong candidate", func() { lease.CandidateID = code + "-controller-" + region.Guests[1].ID }},
		{"cross Region", func() { lease.AuthorityID = "other-regional" }},
		{"missing lease", func() { lease.LeaseID = "" }},
		{"missing epoch", func() { lease.Epoch = 0 }},
		{"missing generation", func() { lease.DesiredGeneration = 0 }},
		{"resolver unavailable", func() { resolveErr = errors.New("lease unavailable") }},
		{"unowned guest", func() { delete(factory.active, guest.ID) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease = original
			resolveErr = nil
			test.change()
			if _, err := client.SetDrain(context.Background(), guest.ID, "drain-qualification", true); err == nil {
				t.Fatal("invalid authority or guest published")
			}
		})
	}
	if published.Load() != 1 {
		t.Fatalf("published %d commands, expected only valid command", published.Load())
	}
	signer := services.controlSigners[0]
	if err := services.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(envelope.SignedMaterial); err == nil {
		t.Fatal("parsed command signer survived service cleanup")
	}
}
