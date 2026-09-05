//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"
)

func TestOrdinaryMutationNeverUsesBootstrapGrant(t *testing.T) {
	server, authority := startDeliveryTestNATS(t)
	host := "gru-member-1"
	factory := &firecrackerFactory{active: map[string]*sandboxVM{host: {id: host, guest: vmqual.Guest{ID: host}}}, services: &qualificationRuntimeServices{nats: server, started: true, natsAuthority: authority}}
	data, err := desiredHostManifest([]guestArtifactInput{
		{manifest: vmimage.GuestArtifact{Component: "orchestrator", Version: "1.0.0", SHA256: strings.Repeat("a", 64)}},
		{manifest: vmimage.GuestArtifact{Component: "terrabase", Version: "2.0.0", SHA256: strings.Repeat("b", 64)}},
	}, 8443)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := hostagent.ParseHostManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := vmqualbootstrap.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = issuer.Close() })
	if _, err := issuer.Grant(host, manifest); err != nil {
		t.Fatal(err)
	}
	factory.services.(*qualificationRuntimeServices).bootstrapIssuer = issuer
	digest, _ := hostagent.HostManifestSha256(manifest)
	options, err := authority.options(authority.guests[host])
	if err != nil {
		t.Fatal(err)
	}
	connection, err := nats.Connect(server.ClientURL(), options...)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	node, _ := hostagent.NewNodeId(host)
	statusSubject, _ := hostagent.NodeDrainStatusSubject(node)
	drainSubject, _ := hostagent.NodeDrainSubject(node)
	deploySubject, _ := hostagent.NodeDeploySubject(node)
	var mu sync.Mutex
	mutations, observations := 0, 0
	for _, subject := range []string{statusSubject, drainSubject, deploySubject} {
		subject := subject
		_, err := connection.Subscribe(subject, func(message *nats.Msg) {
			mu.Lock()
			defer mu.Unlock()
			var reply any
			switch subject {
			case statusSubject:
				var request hostagent.NodeStatusRequest
				_ = json.Unmarshal(message.Data, &request)
				observations++
				facts := hostagent.HostFacts{State: hostagent.NodeStateServing, ManifestSha256: digest, Components: []hostagent.ComponentFact{}}
				for _, spec := range manifest.Components {
					facts.Components = append(facts.Components, hostagent.ComponentFact{Name: spec.Name, Desired: spec.Version, Installed: true})
				}
				reply = hostagent.NodeStatusReport{CommandId: request.CommandId, NodeId: host, State: hostagent.NodeStateServing, Facts: facts}
			case drainSubject, deploySubject:
				mutations++
				return
			}
			encoded, _ := json.Marshal(reply)
			_ = message.Respond(encoded)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := connection.Flush(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for attempt := 0; attempt < 2; attempt++ {
		if err := factory.requestTSNode(ctx, host, drainSubject, hostagent.DrainCommand{}, &hostagent.DrainReceipt{}); err == nil || !strings.Contains(err.Error(), "actual regional lease holder") {
			t.Fatalf("activation without bootstrap authority = %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if mutations != 0 || observations != 0 {
		t.Fatalf("mutations=%d observations=%d; want zero mutations and zero status observations", mutations, observations)
	}
}

func TestInitialGrantUsesAuthenticatedTransportAndRealReceiverVerifier(t *testing.T) {
	server, authority := startDeliveryTestNATS(t)
	host := "gru-member-1"
	issuer, err := vmqualbootstrap.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	factory := &firecrackerFactory{active: map[string]*sandboxVM{host: {id: host, guest: vmqual.Guest{ID: host}}}, services: &qualificationRuntimeServices{nats: server, started: true, natsAuthority: authority, bootstrapIssuer: issuer}}
	data, err := desiredHostManifest([]guestArtifactInput{{manifest: vmimage.GuestArtifact{Component: "orchestrator", Version: "1.0.0", SHA256: strings.Repeat("a", 64)}}, {manifest: vmimage.GuestArtifact{Component: "terrabase", Version: "1.0.0", SHA256: strings.Repeat("b", 64)}}}, 8443)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := hostagent.ParseHostManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	material, err := issuer.Grant(host, manifest)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := hostagent.VerifyBootstrapGrant(host, material.PublicKeyPEM, material.SignedGrant)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := hostagent.NewBootstrapAuthority(rejectBootstrapRuntime{}, host, material.PublicKeyPEM, material.SignedGrant)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := hostagent.BootstrapCommands(grant)
	if err != nil {
		t.Fatal(err)
	}
	options, err := authority.options(authority.guests[host])
	if err != nil {
		t.Fatal(err)
	}
	connection, err := nats.Connect(server.ClientURL(), options...)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	verified := make(chan error, 1)
	_, err = connection.Subscribe(steps[0].Subject, func(message *nats.Msg) {
		admitted, err := receiver.Authorize(context.Background(), message.Subject, message.Data)
		if err != nil {
			verified <- err
			return
		}
		if admitted.Epoch != 0 || admitted.LeaseID != "" || admitted.BootstrapGrantSHA256 == "" {
			verified <- errors.New("grant fabricated a runtime fence")
			return
		}
		var command hostagent.DrainCommand
		if err := json.Unmarshal(admitted.Command, &command); err != nil {
			verified <- err
			return
		}
		receipt := hostagent.DrainReceipt{CommandId: command.CommandId, NodeId: host, Draining: command.Drain, Quiesced: true}
		encoded, _ := json.Marshal(receipt)
		verified <- message.Respond(encoded)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Flush(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var receipt hostagent.DrainReceipt
	if err := factory.requestBootstrapStep(ctx, host, steps[0].Subject, steps[0].Command, &receipt); err != nil {
		t.Fatal(err)
	}
	if err := <-verified; err != nil {
		t.Fatal(err)
	}
	if receipt.NodeId != host || !receipt.Quiesced {
		t.Fatal("bootstrap receipt lost verified host binding")
	}
}

type rejectBootstrapRuntime struct{}

func (rejectBootstrapRuntime) Authorize(context.Context, string, []byte) (nodeauthority.CommandAuthorization, error) {
	return nodeauthority.CommandAuthorization{}, errors.New("no regional authority")
}
