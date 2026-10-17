package app

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func TestNetBirdRegionalDesiredRequiresExactSignedHosts(t *testing.T) {
	keys := newTestSpecTrust(t, t.TempDir(), cellspec.Identity{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Cell: "gru", Environment: "production"})
	wire, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema, Identity: keys.identity, Generation: 1, RequiresBinary: 1,
		HostGrants: []cellspec.HostGrant{
			{Node: "ts-gru-1", PrivateIP: "10.251.0.11", Controller: "controller-a", Roles: []string{"nats"}, Environment: "production"},
			{Node: "ts-gru-2", PrivateIP: "10.251.0.12", Roles: []string{"terrabase"}, Environment: "production"},
		}}, nil, keys.roots, time.Now(), time.Hour, keys.root)
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := cellspec.VerifyHistorical(wire, keys.roots, keys.identity)
	if err != nil || !adopted.RootSigned {
		t.Fatalf("genuine signed spec: %v", err)
	}
	intent := rootoci.NetBirdIntent{Cell: "GRU", SubnetCIDR: "10.251.0.0/25", Hosts: []rootoci.NetBirdIntentHost{
		{Name: "ts-gru-1", PrivateIP: "10.251.0.11", Role: "controller"},
		{Name: "ts-gru-2", PrivateIP: "10.251.0.12", Role: "member"},
	}}
	desired, err := netBirdAccountDesired(intent, adopted)
	if err != nil || desired.PeerNames()["10.251.0.11"] != "ts-gru-1" || desired.PeerNames()["10.251.0.12"] != "ts-gru-2" {
		t.Fatalf("exact signed hosts did not derive canonical regional peers: %v", err)
	}
	for _, change := range []func(*rootoci.NetBirdIntent){
		func(i *rootoci.NetBirdIntent) { i.Hosts[0].PrivateIP = "10.251.0.99" },
		func(i *rootoci.NetBirdIntent) { i.Hosts[1].Role = "controller" },
		func(i *rootoci.NetBirdIntent) { i.Hosts = i.Hosts[:1] },
		func(i *rootoci.NetBirdIntent) {
			i.Hosts = append(i.Hosts, rootoci.NetBirdIntentHost{Name: "ts-gru-3", PrivateIP: "10.251.0.13", Role: "controller"})
		},
		func(i *rootoci.NetBirdIntent) { slices.Reverse(i.Hosts) },
	} {
		candidate := intent
		candidate.Hosts = slices.Clone(intent.Hosts)
		change(&candidate)
		if _, err := netBirdAccountDesired(candidate, adopted); err == nil {
			t.Fatal("changed, omitted, added or reordered hosts acquired regional desired effects")
		}
	}
}

func TestNetBirdRegionalAccountCannotRenewAnEndedSession(t *testing.T) {
	for _, session := range []*netBirdRegionalAccount{nil, {}, {failure: errors.Join(foundation.ErrAdmissionExpired, errors.New("original authentication lost"))}} {
		if _, _, err := session.current(t.Context(), region.VerifiedNetBirdManager{}); !errors.Is(err, foundation.ErrAdmissionExpired) {
			t.Fatalf("absent or ended original session did not require a fresh lifecycle: %v", err)
		}
	}
}
