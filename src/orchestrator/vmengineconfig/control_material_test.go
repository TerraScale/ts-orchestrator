package vmengineconfig_test

import (
	"encoding/json/v2"
	"os"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/internal/testengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

func TestExplicitControlCredentialsAndExactNATSGrant(t *testing.T) {
	bindings := []vmengineconfig.Binding{{NodeID: "gru-one", Region: "GRU", Address: "10.77.0.10"}, {NodeID: "gru-two", Region: "GRU", Address: "10.77.0.11"}}
	artifact := strings.Repeat("a", 64)
	declaration, path := testengineconfig.ControlDeclaration(t, bindings, artifact, "1.0.0")
	materials, err := vmengineconfig.Load(path, artifact, "1.0.0", bindings)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, material := range materials {
			material.Clear()
		}
	}()
	for _, host := range declaration.Hosts {
		material := materials[host.NodeID]
		files := material.ControlFiles()
		config, err := placementpublisher.ParseHostFile(files[placementpublisher.HostFilePath], "gru", host.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := nkeys.FromSeed(files[config.NKeyFile])
		if err != nil {
			t.Fatal(err)
		}
		public, err := pair.PublicKey()
		pair.Wipe()
		if err != nil {
			t.Fatal(err)
		}
		grant := material.ControlAuthorization()
		publish, subscribe, err := placementpublisher.HostPermissions(config.EngineIdentity)
		if err != nil || grant.PublicNKey != public || strings.Join(publish, ",") != strings.Join(grant.Publish, ",") || strings.Join(subscribe, ",") != strings.Join(grant.Subscribe, ",") {
			t.Fatal("broker grant differs from exact admitted host identity")
		}
		files[config.NKeyFile][0] = 'x'
		if material.ControlFiles()[config.NKeyFile][0] == 'x' {
			t.Fatal("caller mutated private captured material")
		}
	}
	for name, change := range map[string]func(*vmengineconfig.Declaration){
		"observer key reuse": func(d *vmengineconfig.Declaration) {
			d.Hosts[0].EngineControl.CertificateFile = d.Hosts[0].ObserverCertificateFile
			d.Hosts[0].EngineControl.PrivateKeyFile = d.Hosts[0].ObserverPrivateKeyFile
		},
		"NKey host reuse": func(d *vmengineconfig.Declaration) {
			d.Hosts[1].EngineControl.NKeyFile = d.Hosts[0].EngineControl.NKeyFile
		},
		"unadmitted principal": func(d *vmengineconfig.Declaration) { d.Hosts[0].OrchestratorPrincipals = nil },
		"plaintext NATS":       func(d *vmengineconfig.Declaration) { d.Hosts[0].EngineControl.NATSURL = "nats://10.77.0.10:4222" },
	} {
		t.Run(name, func(t *testing.T) {
			original, _ := json.Marshal(declaration)
			var modified vmengineconfig.Declaration
			if err := json.Unmarshal(original, &modified); err != nil {
				t.Fatal(err)
			}
			change(&modified)
			data, _ := json.Marshal(modified)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := vmengineconfig.Load(path, artifact, "1.0.0", bindings); err == nil {
				t.Fatal("invalid control credentials accepted")
			}
		})
	}
}
