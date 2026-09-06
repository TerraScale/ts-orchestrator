package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
)

func TestConfiguredPlacementBrokerCarriesExactPublicGrants(t *testing.T) {
	key, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	public, _ := key.PublicKey()
	grant := placementpublisher.BrokerGrant{ServerIdentity: "spiffe://terrascale.tech/production/terrabase/member-a", PublicNKey: public, Account: "$G"}
	data, err := placementpublisher.EncodeBrokerGrants([]placementpublisher.BrokerGrant{grant})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "grants.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	lookup := func(name string) (string, bool) {
		if name == placementpublisher.BrokerGrantsEnvironment {
			return path, true
		}
		return "", false
	}
	config := &bootstrap.NatsServerConfig{ConfigPath: "/etc/terrascale/nats.conf"}
	if err := configurePlacementBroker(config, lookup); err != nil {
		t.Fatal(err)
	}
	if len(config.PlacementHosts) != 1 || config.PlacementHosts[0] != grant {
		t.Fatal("run broker omitted or changed dedicated host grant")
	}
	if config, err := selectedNatsConfiguration(lookup); err != nil || config != nil {
		t.Fatal("public grants invented a local broker")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"hosts":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := configurePlacementBroker(config, lookup); err == nil {
		t.Fatal("malformed grant file ignored")
	}
}
