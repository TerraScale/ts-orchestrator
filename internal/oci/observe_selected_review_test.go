package oci

import (
	"context"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
)

var _ SelectiveObserver = (*fleet)(nil)

type countingGetProvider struct {
	*fakeProvider
	gets map[string]int
}

func (provider *countingGetProvider) GetInstance(ctx context.Context, id string) (CloudInstance, error) {
	provider.gets[id]++
	return provider.fakeProvider.GetInstance(ctx, id)
}

// Registration verification reads only the hosts that can match its seat,
// so a large managed fleet does not exhaust the registration deadline under
// the OCI rate limit; the selected hosts get Observe's full verification
// (#127 12105).
func TestObserveSelectedVerifiesOnlySelectedHosts(t *testing.T) {
	config, intent := testRegionConfig()
	base := newFakeProvider(config)
	provider := &countingGetProvider{fakeProvider: base, gets: map[string]int{}}
	created, err := newTestFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	built := created.(*fleet)
	var hosts []Instance
	for index, key := range []string{"selected-a", "other-b", "other-c"} {
		request := testEnsureRequest(entityid.Derive("test-operation", key))
		request.PrivateIP = []string{"10.251.0.31", "10.251.0.32", "10.251.0.33"}[index]
		host, err := built.EnsureHost(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		hosts = append(hosts, host)
	}
	all, err := built.Observe(t.Context())
	if err != nil || len(all) != len(hosts) {
		t.Fatalf("full observation = %d %v", len(all), err)
	}
	clear(provider.gets)
	selected, err := built.ObserveSelected(t.Context(), func(id, node string) bool {
		return id == hosts[0].ID || node == hosts[0].Node
	})
	if err != nil || len(selected) != 1 || selected[0].ID != hosts[0].ID {
		t.Fatalf("selected observation = %+v %v", selected, err)
	}
	if provider.gets[hosts[1].ID] != 0 || provider.gets[hosts[2].ID] != 0 || provider.gets[hosts[0].ID] == 0 {
		t.Fatalf("unselected hosts were verified: %v", provider.gets)
	}
	// Every selected host is returned, so a caller's ambiguity check over
	// the matching hosts keeps working.
	twins, err := built.ObserveSelected(t.Context(), func(id, node string) bool {
		return id == hosts[0].ID || id == hosts[1].ID
	})
	if err != nil || len(twins) != 2 {
		t.Fatalf("multi-host selection = %d %v", len(twins), err)
	}
	if _, err := built.ObserveSelected(t.Context(), nil); err == nil {
		t.Fatal("a nil selector observed the whole fleet")
	}
}
