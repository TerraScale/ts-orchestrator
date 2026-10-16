package region

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

type netBirdFixtureHTTP struct {
	client   *http.Client
	endpoint *url.URL
}

func netBirdFixtureDispatcher(t *testing.T, address string, config *tls.Config) netBirdFixtureHTTP {
	t.Helper()
	endpoint, err := url.Parse(address)
	if err != nil || net.ParseIP(endpoint.Hostname()) == nil || !net.ParseIP(endpoint.Hostname()).IsLoopback() || endpoint.Port() == "" {
		t.Fatalf("fixture endpoint is not a literal loopback listener: %s", address)
	}
	transport := &http.Transport{TLSClientConfig: config, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != endpoint.Host {
			t.Errorf("forbidden NetBird fixture dial: %s %s", network, address)
			return nil, errors.New("NetBird fixture permits only its literal loopback listener")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return netBirdFixtureHTTP{endpoint: endpoint, client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("NetBird fixture rejects redirects")
	}}}
}

func (p netBirdFixtureHTTP) Do(r *http.Request) (*http.Response, error) {
	if r.Response != nil {
		return nil, errors.New("NetBird fixture rejects redirected requests")
	}
	copy := r.Clone(r.Context())
	copy.Host = r.URL.Host
	copy.URL.Scheme, copy.URL.Host = p.endpoint.Scheme, p.endpoint.Host
	return p.client.Do(copy)
}

// Called by the signed manager protocol scenario after its real SDK launch and
// store recovery, preserving that scenario's actual signed grant and journal.
func testNetBirdNetworkTeardown(t *testing.T, factory *ociclient.Factory, resolver FoundationResolver, install func(http.Handler)) {
	t.Helper()
	t.Run("owned-network-teardown-inventory", func(t *testing.T) {
		reader := resolver.Footprint.(*SignedFootprint)
		intent, err := reader.authorizedNetBirdManager(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		record, etag, err := resolver.Store.Load(t.Context(), "GRU")
		if err != nil {
			t.Fatal(err)
		}
		record.AuxiliaryIDs = maps.Clone(record.AuxiliaryIDs)
		record.AuxiliaryIDs["backup_bucket"] = "ocid1.bucket.oc1.sa-saopaulo-1.retainedbackup"
		if _, err := resolver.Store.CompareAndSwap(t.Context(), record, etag); err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		state, compartment := "TERMINATED", record.ResourceIDs["control_compartment"]
		var attachments any = []any{}
		var privateIPs any = []any{}
		var nsgVnics any = []any{}
		status := http.StatusOK
		install(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			if r.Method != http.MethodGet || r.Header.Get("Authorization") == "" {
				t.Errorf("teardown observation attempted an unsigned mutation: %s", r.Method)
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if status != http.StatusOK {
				w.WriteHeader(status)
				json.MarshalWrite(w, map[string]string{"code": "NotAuthorizedOrNotFound", "message": "unknown retirement"})
				return
			}
			switch {
			case strings.HasPrefix(r.URL.Path, "/20160918/instances/"):
				p := intent.intent.Profile
				json.MarshalWrite(w, map[string]any{"id": record.NetBirdManager.InstanceID, "compartmentId": compartment, "availabilityDomain": p.AvailabilityDomain, "faultDomain": p.FaultDomain,
					"shape": p.Shape, "shapeConfig": map[string]any{"ocpus": p.OCPUs, "memoryInGBs": p.MemoryGB}, "sourceDetails": map[string]any{"sourceType": "image", "imageId": intent.intent.ImageOCID}, "lifecycleState": state})
			case r.URL.Path == "/20160918/vnicAttachments":
				json.MarshalWrite(w, attachments)
			case r.URL.Path == "/20160918/privateIps":
				json.MarshalWrite(w, privateIPs)
			default:
				json.MarshalWrite(w, nsgVnics)
			}
		}))
		t.Cleanup(func() { install(nil) })
		observed, err := ObserveNetBirdNetworkTeardown(t.Context(), factory, resolver)
		if err != nil {
			t.Fatal(err)
		}
		if len(observed.Resources()) != 6 || len(observed.Keep()) != 5 || len(observed.Blockers()) != 2 || observed.InstanceID() != record.NetBirdManager.InstanceID {
			t.Fatalf("teardown lost exact IDs or treated termination as destructive authority: %+v", observed)
		}
		if err := observed.CheckProvenance(t.Context()); err != nil {
			t.Fatal(err)
		}
		resources := observed.Resources()
		resources[0].ID = "ocid1.subnet.oc1.sa-saopaulo-1.foreign"
		if observed.Resources()[0].ID == resources[0].ID {
			t.Fatal("caller changed sealed teardown provenance")
		}
		mu.Lock()
		state = "RUNNING"
		mu.Unlock()
		if err := observed.CheckProvenance(t.Context()); err == nil {
			t.Fatal("running replacement retained stale termination observation")
		}
		running, err := ObserveNetBirdNetworkTeardown(t.Context(), factory, resolver)
		if err != nil || len(running.Blockers()) != 3 {
			t.Fatalf("running host was not retained: blockers=%v err=%v", running.Blockers(), err)
		}
		mu.Lock()
		state = "TERMINATED"
		attachments = nil
		mu.Unlock()
		if _, err := ObserveNetBirdNetworkTeardown(t.Context(), factory, resolver); err == nil {
			t.Fatal("null attachment list proved emptiness")
		}
		mu.Lock()
		attachments = []any{}
		privateIPs = nil
		mu.Unlock()
		if _, err := ObserveNetBirdNetworkTeardown(t.Context(), factory, resolver); err == nil {
			t.Fatal("null private IP list proved empty subnet")
		}
		mu.Lock()
		privateIPs = []any{}
		nsgVnics = nil
		mu.Unlock()
		if _, err := ObserveNetBirdNetworkTeardown(t.Context(), factory, resolver); err == nil {
			t.Fatal("null VNIC list proved empty NSG")
		}
		mu.Lock()
		nsgVnics = []any{}
		status = http.StatusNotFound
		mu.Unlock()
		if _, err := ObserveNetBirdNetworkTeardown(t.Context(), factory, resolver); err == nil {
			t.Fatal("404 proved manager termination")
		}
		mu.Lock()
		status = http.StatusOK
		compartment = "ocid1.compartment.oc1..foreign"
		mu.Unlock()
		if _, err := ObserveNetBirdNetworkTeardown(t.Context(), factory, resolver); err == nil {
			t.Fatal("foreign manager identity admitted for cleanup")
		}
	})
}
