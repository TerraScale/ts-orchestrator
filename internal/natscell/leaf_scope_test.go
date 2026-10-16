package natscell

import (
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestChildLeafPermissionsAreScopedToTheSubtree(t *testing.T) {
	t.Parallel()

	// IAD dials SFO; SFO and FRA dial GRU.
	topology := HubAndSpoke("gru", []string{"fra", "iad", "sfo"}).WithSpokeParent("iad", "sfo")
	subtrees := topology.Subtrees("gru")
	if !slices.Equal(subtrees["sfo"], []string{"iad", "sfo"}) || !slices.Equal(subtrees["fra"], []string{"fra"}) || len(subtrees) != 2 {
		t.Fatalf("subtrees = %v", subtrees)
	}
	if spoke := topology.Subtrees("sfo"); len(spoke) != 1 || !slices.Equal(spoke["iad"], []string{"iad"}) {
		t.Fatalf("sfo subtrees = %v", spoke)
	}
	contract := InterRegionContract{Cell: "gru", Peers: topology.Peers("gru"), GlobalHome: "gru", Subtrees: subtrees}
	sfo := contract.ChildLeafPermissions("sfo")
	reset := func(region string) string {
		return protocol.JSConsumerResetSubject(protocol.JSDomainAPIPrefix("gru"), protocol.GlobalControlStream,
			protocol.GlobalMirrorConsumer(region))
	}
	for _, own := range []string{"sfo", "iad"} {
		if !slices.Contains(sfo.Pub.Allow, protocol.RegionHealthSubject(own)) || !slices.Contains(sfo.Pub.Allow, reset(own)) ||
			!slices.Contains(sfo.Sub.Allow, protocol.Regional(own, "query", ">")) ||
			!slices.Contains(sfo.Sub.Allow, protocol.InterRegionGlobalDeliverSubject(own)) {
			t.Errorf("SFO's leaf lacks its subtree region %s", own)
		}
	}
	for _, foreign := range []string{"fra", "gru"} {
		if slices.Contains(sfo.Pub.Allow, protocol.RegionHealthSubject(foreign)) || slices.Contains(sfo.Pub.Allow, reset(foreign)) ||
			slices.Contains(sfo.Sub.Allow, protocol.Regional(foreign, "query", ">")) ||
			slices.Contains(sfo.Sub.Allow, protocol.InterRegionGlobalDeliverSubject(foreign)) {
			t.Errorf("SFO's leaf may act for %s", foreign)
		}
	}
	if unknown := contract.ChildLeafPermissions("lhr"); !denyAll(unknown) {
		t.Fatalf("unknown child permissions = %+v", unknown)
	}

	keys := newTestRegionKeys(t)
	system, cell, interregion := keys.claims(contract, 2)
	if err := contract.verify(system, cell, interregion, 2); err != nil {
		t.Fatal(err)
	}
	if !denyAll(interregion.DefaultPermissions) {
		t.Fatal("interregion defaults are not deny-all")
	}
	scopeOf := func(claim *jwt.AccountClaims, child string) *jwt.UserScope {
		for _, scope := range claim.SigningKeys {
			if user, ok := scope.(*jwt.UserScope); ok && user.Role == child {
				return user
			}
		}
		t.Fatalf("no scope for %s", child)
		return nil
	}
	mutations := map[string]func(*jwt.AccountClaims){
		"unscoped signing key": func(claim *jwt.AccountClaims) {
			extra, _ := nkeys.CreateAccount()
			public, _ := extra.PublicKey()
			claim.SigningKeys.Add(public)
		},
		"missing child scope": func(claim *jwt.AccountClaims) {
			delete(claim.SigningKeys, scopeOf(claim, "fra").Key)
		},
		"widened template": func(claim *jwt.AccountClaims) {
			scopeOf(claim, "fra").Template.Pub.Allow.Add(protocol.RegionHealthSubject("sfo"))
		},
		"sibling template": func(claim *jwt.AccountClaims) {
			scopeOf(claim, "fra").Template.Permissions = contract.ChildLeafPermissions("sfo")
		},
		"client connections": func(claim *jwt.AccountClaims) {
			scopeOf(claim, "fra").Template.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeStandard}
		},
		"bearer users":   func(claim *jwt.AccountClaims) { scopeOf(claim, "fra").Template.BearerToken = true },
		"unknown role":   func(claim *jwt.AccountClaims) { scopeOf(claim, "fra").Role = "lhr" },
		"duplicate role": func(claim *jwt.AccountClaims) { scopeOf(claim, "fra").Role = "sfo" },
		"permissive defaults": func(claim *jwt.AccountClaims) {
			claim.DefaultPermissions = contract.LeafPermissions()
		},
	}
	for name, mutate := range mutations {
		system, cell, interregion := keys.claims(contract, 2)
		mutate(interregion)
		if err := contract.verify(system, cell, interregion, 2); err == nil {
			t.Errorf("%s: widened interregion account verified", name)
		}
	}
}
