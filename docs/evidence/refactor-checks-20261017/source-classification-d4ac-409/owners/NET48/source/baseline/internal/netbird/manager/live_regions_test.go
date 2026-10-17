package manager

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSyncDiscoversRegionalGroupsWithoutNATSOrPeerHealth(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	operator := f.addPeer("ts-fra-1", "203.0.113.8", true, time.Now(), ids.operators)
	ungrouped := f.addPeer("ts-sfo-1", "203.0.113.9", true, time.Now())
	api := f.api(t)
	if _, err := Sync(t.Context(), api, GRU(), true); err != nil {
		t.Fatal(err)
	}
	if len(f.groups) != len(GRU().Groups) || len(f.policies) != len(GRU().Policies) {
		t.Fatal("peer names or the compiled catalog created regional access")
	}
	sfo := f.addGroup("sfo-servers")
	f.group(sfo).Resources = []resourceRef{{ID: "retained-resource", Type: "host"}}
	offline := f.addPeer("ts-sfo-2", "203.0.113.10", false, time.Now().Add(-48*time.Hour), sfo)
	t.Setenv("NB_PAT", testPAT)
	if err := Run(t.Context(), []string{"sync", "--apply", "--management-url", f.server.URL}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(f.policies) != len(GRU().Policies)+8 {
		t.Fatalf("SFO access policies: %d", len(f.policies))
	}
	// A new empty region is seen on the next controller cycle, before its
	// first peer, leaf connection or heartbeat exists.
	fra := f.addGroup("fra-servers")
	loop := Loop{Leader: func() bool { return true }, Desired: GRU(), ManagementURL: f.server.URL,
		Token: func(context.Context) ([]byte, error) { return []byte(testPAT), nil }}
	loop = loop.withDefaults()
	if err := loop.cycle(t.Context(), map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if len(f.policies) != len(GRU().Policies)+16 {
		t.Fatalf("new region access policies: %d", len(f.policies))
	}
	for group, groupID := range map[string]string{"sfo-servers": sfo, "fra-servers": fra} {
		for _, expected := range []struct {
			name, protocol               string
			ports, sources, destinations []string
		}{
			{"operators-to-" + group + "-ssh", "netbird-ssh", nil, []string{ids.operators}, []string{groupID}},
			{"ops-automation-to-" + group + "-ssh", "netbird-ssh", nil, []string{f.groupByName("ops-automation").ID}, []string{groupID}},
			{"gru-servers-to-" + group + "-terrabase", "tcp", []string{"9443"}, []string{ids.servers}, []string{groupID}},
			{group + "-to-gru-servers-terrabase", "tcp", []string{"9443"}, []string{groupID}, []string{ids.servers}},
			{group + "-to-gru-servers-fabric", "tcp", []string{"7422"}, []string{groupID}, []string{ids.servers}},
			{"operators-to-" + group + "-dashboard", "tcp", []string{"9463"}, []string{ids.operators, f.groupByName("ops-automation").ID}, []string{groupID}},
			{group + "-to-" + group + "-ping", "icmp", nil, []string{groupID}, []string{groupID}},
			{group + "-to-" + group + "-service-health", "tcp", []string{"4222", "8080", "9465"}, []string{groupID}, []string{groupID}},
		} {
			index := slices.IndexFunc(f.policies, func(policy apiPolicy) bool { return policy.Name == expected.name })
			if index < 0 || len(f.policies[index].Rules) != 1 {
				t.Fatalf("missing one-rule policy %s", expected.name)
			}
			rule := f.policies[index].Rules[0]
			if !rule.Enabled || rule.Action != "accept" || rule.Bidirectional || rule.Protocol != expected.protocol ||
				!slices.Equal(rule.Ports, expected.ports) || !slices.Equal(minimumIDs(rule.Sources), expected.sources) ||
				!slices.Equal(minimumIDs(rule.Destinations), expected.destinations) {
				t.Fatalf("policy %s broadened or changed: %+v", expected.name, rule)
			}
		}
	}
	if f.peer(offline) == nil || len(f.group(sfo).Peers) != 1 || f.group(sfo).Peers[0].ID != offline ||
		len(f.group(sfo).Resources) != 1 || len(f.group(fra).Peers) != 0 {
		t.Fatal("regional group IDs, members/resources or remote offline peer changed")
	}
	if groups := f.peerView(f.peer(operator)).Groups; len(groups) != 1 || groups[0].ID != ids.operators {
		t.Fatal("operator with a server-looking name gained server access")
	}
	if len(f.peerView(f.peer(ungrouped)).Groups) != 0 {
		t.Fatal("ungrouped peer with a server-looking name gained server access")
	}
	f.mutations = nil
	if err := loop.cycle(t.Context(), map[string]bool{}); err != nil || len(f.mutations) != 0 {
		t.Fatalf("repeated reconciliation did not converge: %v %v", f.mutations, err)
	}
}

func TestSyncRefusesUntrustedOrAmbiguousRegionalGroupsBeforeMutation(t *testing.T) {
	for _, issuer := range []string{"jwt", "integration", "", "duplicate"} {
		t.Run(issuer, func(t *testing.T) {
			f := newFakeManager(t)
			f.seedLegacy(t)
			group := f.addGroup("sfo-servers")
			if issuer == "duplicate" {
				f.addGroup("sfo-servers")
			} else {
				f.group(group).Issued = issuer
			}
			if _, err := Sync(t.Context(), f.api(t), GRU(), true); err == nil || len(f.mutations) != 0 {
				t.Fatalf("untrusted region mutated manager: %v %v", f.mutations, err)
			}
		})
	}
}

func TestSetupKeyCreatesOnlyItsCanonicalRegionalGroup(t *testing.T) {
	f := newFakeManager(t)
	f.seedLegacy(t)
	api := f.api(t)
	desired := GRU()
	desired.ServersGroup, desired.SetupKeyName = "fra-servers", "fra-servers"
	var secret bytes.Buffer
	report, err := CreateServerSetupKey(t.Context(), api, desired, &secret, false)
	if err != nil || len(report.Changes) != 2 || len(f.mutations) != 0 || secret.Len() != 0 {
		t.Fatalf("group/key dry run: %+v %v %v", report, f.mutations, err)
	}
	if _, err := CreateServerSetupKey(t.Context(), api, desired, &secret, true); err != nil {
		t.Fatal(err)
	}
	if len(f.mutations) != 2 || !strings.HasPrefix(f.mutations[0], "POST groups") ||
		!strings.HasPrefix(f.mutations[1], "POST setup-keys") || f.groupByName("sfo-servers") != nil {
		t.Fatalf("regional group was not created before the scoped key: %v", f.mutations)
	}
	key := f.setupKeys[len(f.setupKeys)-1]
	if !slices.Equal(key["auto_groups"].([]string), []string{f.groupByName("fra-servers").ID}) || secret.Len() == 0 {
		t.Fatal("key did not bind exactly its regional group")
	}
	f.mutations = nil
	desired.ServersGroup, desired.SetupKeyName = "ts-ops-gateway", "ts-ops-gateway"
	if _, err := CreateServerSetupKey(t.Context(), api, desired, io.Discard, true); err == nil || len(f.mutations) != 0 {
		t.Fatal("server enrollment key targeted a non-server group")
	}
}
