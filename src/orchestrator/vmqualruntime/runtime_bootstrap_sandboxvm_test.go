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

func TestInitialActivationUsesPerComponentDrainAndResumes(t *testing.T) {
	server := startDeliveryTestNATS(t)
	host := "gru-member-1"
	factory := &firecrackerFactory{active: map[string]*sandboxVM{host: {id: host, guest: vmqual.Guest{ID: host}}}, services: &qualificationRuntimeServices{nats: server, started: true}}
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
	connection, err := nats.Connect(server.ClientURL(), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	node, _ := hostagent.NewNodeId(host)
	statusSubject, _ := hostagent.NodeDrainStatusSubject(node)
	drainSubject, _ := hostagent.NodeDrainSubject(node)
	deploySubject, _ := hostagent.NodeDeploySubject(node)
	var mu sync.Mutex
	draining, active := false, false
	current := map[string]string{}
	deployed, drains := 0, 0
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
				state := hostagent.NodeStateServing
				if draining {
					state = hostagent.NodeStateDraining
				}
				facts := hostagent.HostFacts{State: state, ManifestSha256: digest, Components: []hostagent.ComponentFact{}}
				for _, spec := range manifest.Components {
					facts.Components = append(facts.Components, hostagent.ComponentFact{Name: spec.Name, Desired: spec.Version, Version: current[spec.Name], Installed: true, UnitActive: active})
				}
				reply = hostagent.NodeStatusReport{CommandId: request.CommandId, NodeId: host, State: state, Quiesced: draining && !active, Facts: facts}
			case drainSubject:
				var command hostagent.DrainCommand
				_ = json.Unmarshal(message.Data, &command)
				draining = command.Drain
				active = !draining
				if draining {
					drains++
				}
				reply = hostagent.DrainReceipt{CommandId: command.CommandId, NodeId: host, Draining: draining, Quiesced: draining, Detail: "observed"}
			case deploySubject:
				var command hostagent.DeployCommand
				_ = json.Unmarshal(message.Data, &command)
				accepted := draining && !active
				if accepted {
					current[command.Component] = command.Version
					active = true
					deployed++
				}
				reply = hostagent.DeployReceipt{CommandId: command.CommandId, NodeId: host, Accepted: accepted, Current: current[command.Component], Detail: "observed"}
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
	if err := factory.activateAdmittedGuest(ctx, host, manifest); err != nil {
		t.Fatal(err)
	}
	if err := factory.activateAdmittedGuest(ctx, host, manifest); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if deployed != 2 || drains != 2 {
		t.Fatalf("deploys=%d drains=%d", deployed, drains)
	}
}
