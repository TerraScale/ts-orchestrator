package vmengineconfig_test

import (
	"encoding/json/v2"
	"os"
	"slices"
	"strings"
	"testing"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/internal/testengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

func TestDatabaseHostMaterialHasDedicatedLifecyclePublisher(t *testing.T) {
	declaration, path := testengineconfig.DatabaseDeclaration(t, bindings, strings.Repeat("a", 64), "1.0.0")
	materials, err := vmengineconfig.Load(path, declaration.ArtifactSHA256, declaration.Release, bindings)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, m := range materials {
			m.Clear()
		}
	}()
	for _, host := range declaration.Hosts {
		m := materials[host.NodeID]
		files := m.DatabaseFiles()
		var config databaseadmission.HostFileConfig
		if err := json.Unmarshal(files[databaseadmission.HostFilePath], &config, json.RejectUnknownMembers(true)); err != nil {
			t.Fatal(err)
		}
		if config.Instance != host.NodeID || config.MemberID != host.Member || config.Environment != declaration.Environment || config.EngineUID != 62011 || config.CatalogPath != host.DatabaseHost.CatalogPath || config.LifecycleNKeyFile == config.NKeyFile {
			t.Fatal("database admission identity drift")
		}
		publics := []string{}
		for _, path := range []string{config.NKeyFile, config.LifecycleNKeyFile} {
			pair, err := nkeys.FromSeed(files[path])
			if err != nil {
				t.Fatal(err)
			}
			public, err := pair.PublicKey()
			pair.Wipe()
			if err != nil {
				t.Fatal(err)
			}
			publics = append(publics, public)
		}
		if publics[0] == publics[1] || publics[0] == m.ControlAuthorization().PublicNKey || publics[1] == m.ControlAuthorization().PublicNKey {
			t.Fatal("database roles reuse a credential")
		}
		grants, err := databaseadmission.ParseBrokerGrants(files[databaseadmission.BrokerGrantsPath])
		if err != nil {
			t.Fatal(err)
		}
		broker, err := databaseadmission.ApplyBrokerGrants(&natsserver.Options{}, grants)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, user := range broker.Nkeys {
			if user.Nkey == publics[1] {
				found = true
				publish, subscribe := databaseadmission.LifecyclePublisherPermissions()
				if !slices.Equal(user.Permissions.Publish.Allow, publish) || !slices.Equal(user.Permissions.Subscribe.Allow, subscribe) {
					t.Fatal("lifecycle publisher gained non-lifecycle grants")
				}
			}
		}
		if !found {
			t.Fatal("lifecycle publisher not admitted by actual broker renderer")
		}
		files[config.NKeyFile][0] ^= 1
		if files[config.NKeyFile][0] == m.DatabaseFiles()[config.NKeyFile][0] {
			t.Fatal("private file alias")
		}
	}
}
func TestDatabaseHostMaterialRejectsRoleAndHostReuse(t *testing.T) {
	for name, change := range map[string]func(*vmengineconfig.Declaration){
		"lifecycle host reuse": func(d *vmengineconfig.Declaration) {
			d.Hosts[0].DatabaseHost.LifecycleNKeyFile = d.Hosts[0].DatabaseHost.NKeyFile
		},
		"placement reuse": func(d *vmengineconfig.Declaration) {
			d.Hosts[0].DatabaseHost.NKeyFile = d.Hosts[0].EngineControl.NKeyFile
		},
		"other host reuse": func(d *vmengineconfig.Declaration) {
			d.Hosts[1].DatabaseHost.LifecycleNKeyFile = d.Hosts[0].DatabaseHost.NKeyFile
		},
		"engine TLS reuse": func(d *vmengineconfig.Declaration) {
			d.Hosts[0].DatabaseHost.CertificateFile = d.Hosts[0].CertificateFile
			d.Hosts[0].DatabaseHost.PrivateKeyFile = d.Hosts[0].PrivateKeyFile
		},
		"root ingress": func(d *vmengineconfig.Declaration) { d.Hosts[0].DatabaseHost.IngressUID = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			d, path := testengineconfig.DatabaseDeclaration(t, bindings, strings.Repeat("a", 64), "1.0.0")
			change(&d)
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, bindings); err == nil {
				t.Fatal("invalid database material accepted")
			}
		})
	}
}
