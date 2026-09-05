//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

func TestInitialActivationRefusesForeignOrUninstalledState(t *testing.T) {
	manifest := hostagent.HostManifest{Components: []hostagent.ComponentSpec{{Name: "orchestrator", Version: "1.0.0"}, {Name: "terrabase", Version: "2.0.0"}}}
	report := hostagent.NodeStatusReport{Facts: hostagent.HostFacts{ManifestSha256: "admitted", Components: []hostagent.ComponentFact{
		{Name: "orchestrator", Desired: "1.0.0", Installed: true}, {Name: "terrabase", Desired: "2.0.0", Installed: true},
	}}}
	if ready, err := initialActivationStatus(report, manifest, "admitted"); err != nil || !ready {
		t.Fatalf("initial: %v %v", ready, err)
	}
	report.Facts.Components[0].Version = "1.0.0"
	if ready, err := initialActivationStatus(report, manifest, "admitted"); err != nil || !ready {
		t.Fatalf("partial recovery: %v %v", ready, err)
	}
	report.Facts.Components[1].Installed = false
	if ready, err := initialActivationStatus(report, manifest, "admitted"); err != nil || ready {
		t.Fatalf("uninstalled: %v %v", ready, err)
	}
	report.Facts.Components[0].Version = "9.0.0"
	if _, err := initialActivationStatus(report, manifest, "admitted"); err == nil {
		t.Fatal("foreign serving release accepted")
	}
	report.Facts.Components[0].Version = ""
	if _, err := initialActivationStatus(report, manifest, "foreign"); err == nil {
		t.Fatal("foreign manifest accepted")
	}
	report.Facts.Components[1] = report.Facts.Components[0]
	if _, err := initialActivationStatus(report, manifest, "admitted"); err == nil {
		t.Fatal("duplicate component evidence accepted")
	}
}

func TestInitialActivationRequiresActualCommandAuthorityBeforeMutation(t *testing.T) {
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
		if err := factory.activateAdmittedGuest(ctx, host, manifest); err == nil || !strings.Contains(err.Error(), "actual regional lease holder") {
			t.Fatalf("activation without bootstrap authority = %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if mutations != 0 || observations != 2 {
		t.Fatalf("mutations=%d observations=%d; want zero mutations and two status observations", mutations, observations)
	}
}
