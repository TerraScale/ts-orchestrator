package oci

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

type countingReadback struct {
	*observeSDKReadback
	bootReads int
}

func (counter *countingReadback) Do(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Path, "/bootVolumeAttachments") {
		counter.bootReads++
	}
	return counter.observeSDKReadback.Do(request)
}

// Only an Observe that opts in reuses a cached storage and network
// verification; admission paths call Observe with a plain context and verify
// afresh every time (#127 12104).
func TestObserveUsesCachedVerificationOnlyWhenOptedIn(t *testing.T) {
	config, intent := testRegionConfig()
	setupProvider := newFakeProvider(config)
	journal := newFakeJournal()
	setup, err := newTestFleet(config, intent, setupProvider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, err := setup.EnsureHost(t.Context(), testEnsureRequest(entityid.Derive("test-operation", "cached-host")))
	if err != nil {
		t.Fatal(err)
	}
	readback := &countingReadback{observeSDKReadback: &observeSDKReadback{config: config,
		instances: map[string]CloudInstance{host.ID: setupProvider.instances[host.ID]}, getInstanceCalls: make(map[string]int)}}
	base := common.BaseClient{Host: "https://sdk.test.invalid", BasePath: "20160918",
		UserAgent: "oci-observe-cache-test", Signer: observeSDKSigner{}, HTTPClient: readback}
	cache, err := newVerificationCache(30 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	adapter := &sdkProvider{config: config, compute: core.ComputeClient{BaseClient: base},
		storage: core.BlockstorageClient{BaseClient: base}, network: core.VirtualNetworkClient{BaseClient: base},
		verified: cache}
	provider := &observeSDKProvider{sdkProvider: adapter, listed: []CloudInstance{setupProvider.instances[host.ID]}}
	fleet, err := newTestFleet(config, intent, provider, &observeReadOnlyJournal{fakeJournal: journal},
		&fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	observe := func(cached bool) int {
		t.Helper()
		before := readback.bootReads
		ctx := t.Context()
		if cached {
			ctx = WithCachedVerification(ctx)
		}
		observed, err := fleet.Observe(ctx)
		if err != nil || len(observed) != 1 {
			t.Fatalf("observe = %+v %v", observed, err)
		}
		return readback.bootReads - before
	}
	if reads := observe(false); reads == 0 {
		t.Fatal("first observation did not verify")
	}
	if reads := observe(false); reads == 0 {
		t.Fatal("an admission observation reused a cached verification")
	}
	if reads := observe(true); reads != 0 {
		t.Fatalf("the opted-in sweep verified again (%d boot reads)", reads)
	}
	if reads := observe(false); reads == 0 {
		t.Fatal("a plain observation after a cached sweep reused the cache")
	}
}
