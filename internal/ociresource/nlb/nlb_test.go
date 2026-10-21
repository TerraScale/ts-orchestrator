package nlb

import (
	"context"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
)

const nlbID = "ocid1.networkloadbalancer.oc1.sa-saopaulo-1.public"

type providerState struct {
	api              API
	loseResponse     bool
	holdWorkRequests bool
	beforeWrite      func(http.ResponseWriter, *http.Request)
	retries          map[string]string
	balancer         LoadBalancer
	backends         []Backend
	calls            []string
	pending          map[string]bool
	finished         map[string]bool
	failWR           bool
	seq              int
	gone             bool
	setGone          bool
}

func (f *providerState) GetLoadBalancer(context.Context, string) (LoadBalancer, error) {
	if f.gone {
		return LoadBalancer{}, fmt.Errorf("get OCI NLB: %w", ociresource.ErrGone)
	}
	return f.balancer, nil
}
func (f *providerState) ListBackends(context.Context, string, string) ([]Backend, error) {
	if f.setGone {
		return nil, fmt.Errorf("list OCI NLB backends: %w", ociresource.ErrGone)
	}
	return slices.Clone(f.backends), nil
}

// workRequest records a mutation; the next mutation is refused until the
// previous work request was waited on, mirroring OCI's NLB serialization.
func (f *providerState) workRequest(call string) (string, error) {
	if len(f.pending) > 0 {
		return "", errors.New("NLB has a mutation in progress")
	}
	f.calls = append(f.calls, call)
	f.seq++
	// Every NLB mutation advances its ETag, as OCI does.
	f.balancer.ETag = fmt.Sprintf("etag-%d", f.seq)
	id := fmt.Sprintf("wr%d", f.seq)
	f.pending = map[string]bool{id: true}
	return id, nil
}

func (f *providerState) CreateBackend(_ context.Context, _, _ string, backend Backend) (string, error) {
	id, err := f.workRequest("create " + backend.key())
	if err == nil {
		f.backends = append(f.backends, Backend{IP: backend.IP, Port: backend.Port, Weight: backend.weight(), name: backend.key()})
	}
	return id, err
}
func (f *providerState) UpdateBackend(_ context.Context, _, _ string, backend Backend) (string, error) {
	id, err := f.workRequest("update " + backend.Name())
	for i := range f.backends {
		if f.backends[i].Name() == backend.Name() {
			f.backends[i].Weight = backend.weight()
		}
	}
	return id, err
}
func (f *providerState) DeleteBackend(_ context.Context, _, _, name string) (string, error) {
	id, err := f.workRequest("delete " + name)
	f.backends = slices.DeleteFunc(f.backends, func(b Backend) bool { return b.Name() == name })
	return id, err
}
func (f *providerState) UpdateTags(_ context.Context, _, etag string, tags ociresource.Tags) (string, error) {
	if etag != f.balancer.ETag {
		return "", errors.New("etag mismatch")
	}
	id, err := f.workRequest("tags")
	if err == nil {
		f.balancer.Tags = tags
	}
	return id, err
}
func (f *providerState) WaitWorkRequest(_ context.Context, id string) error {
	if success, ok := f.finished[id]; ok {
		if !success {
			return errors.New("work request FAILED")
		}
		return nil
	}
	if !f.pending[id] {
		return errors.New("unknown work request")
	}
	f.pending = nil
	if f.finished == nil {
		f.finished = map[string]bool{}
	}
	f.finished[id] = !f.failWR
	if f.failWR {
		return errors.New("work request FAILED")
	}
	return nil
}

type allow struct{}

func (allow) Guard(context.Context, uint64) error { return nil }

var (
	key   = ociresource.Key{Region: "GRU", Kind: Kind, Name: "public-api"}
	owner = ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
)

func controller(t *testing.T, api *providerState, store ociresource.Store) *ociresource.Controller[Spec, Observed] {
	return &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store,
		Ownership: owner, Authority: allow{}}
}

func instance(ip, state string) oci.Instance { return oci.Instance{PrivateIP: ip, State: state} }

func TestBackendsFollowPlacement(t *testing.T) {
	api := &providerState{balancer: LoadBalancer{ID: nlbID, ETag: "e", Tags: owner.Stamp(key, 0, "")},
		backends: []Backend{{IP: "10.0.1.9", Port: 8443, Weight: 1, name: "10.0.1.9:8443"}}}
	store := persistentStore(t)
	ctx := t.Context()

	spec := FromPlacement(nlbID, "api", 8443, []oci.Instance{
		instance("10.0.1.12", "RUNNING"), instance("10.0.1.11", "RUNNING"), instance("10.0.1.13", "STOPPED"),
		instance("", "RUNNING"), instance("10.0.1.11", "RUNNING"),
	})
	if len(spec.Backends) != 2 || spec.Backends[0].IP != "10.0.1.11" {
		t.Fatalf("spec=%+v", spec)
	}
	changed, err := Publish(ctx, store, key, ociresource.PolicyEnforce, spec)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if changed, err = Publish(ctx, store, key, ociresource.PolicyEnforce, spec); err != nil || changed {
		t.Fatalf("republished an unchanged spec: changed=%v err=%v", changed, err)
	}
	result, err := controller(t, api, store).Reconcile(ctx, 1)
	if err != nil || result.Applied != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	want := []string{"create 10.0.1.11:8443", "create 10.0.1.12:8443", "delete 10.0.1.9:8443", "tags"}
	if !slices.Equal(api.calls, want) {
		t.Fatalf("calls=%v want %v", api.calls, want)
	}
	if result, err = controller(t, api, store).Reconcile(ctx, 1); err != nil || result.InSync != 1 {
		t.Fatalf("second pass result=%+v err=%v", result, err)
	}

	// A host scales out; only the new backend is added.
	api.calls = nil
	spec = FromPlacement(nlbID, "api", 8443, []oci.Instance{instance("10.0.1.11", "RUNNING"), instance("10.0.1.12", "RUNNING"), instance("10.0.1.14", "RUNNING")})
	if changed, err := Publish(ctx, store, key, ociresource.PolicyEnforce, spec); err != nil || !changed {
		t.Fatal(err)
	}
	if _, err := controller(t, api, store).Reconcile(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(api.calls, []string{"create 10.0.1.14:8443", "tags"}) {
		t.Fatalf("calls=%v", api.calls)
	}
}

func TestEmptyPlacementIsNeverPublishedOrApplied(t *testing.T) {
	store := persistentStore(t)
	spec := FromPlacement(nlbID, "api", 8443, []oci.Instance{instance("10.0.1.11", "STOPPED")})
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err == nil {
		t.Fatal("published an empty backend set")
	}
	spec.AllowEmpty = true
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
}

func TestForeignNLBAndFailedWorkRequests(t *testing.T) {
	store := persistentStore(t)
	spec := Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.1.11", Port: 8443}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	foreign := &providerState{balancer: LoadBalancer{ID: nlbID, Tags: ociresource.Tags{Freeform: map[string]string{"terrascale-owner": "cell-gru"}}}}
	if result, err := controller(t, foreign, store).Reconcile(t.Context(), 1); err != nil || result.Foreign != 1 || len(foreign.calls) != 0 {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, foreign.calls)
	}
	failing := &providerState{balancer: LoadBalancer{ID: nlbID, Tags: owner.Stamp(key, 0, "")}, failWR: true}
	if _, err := controller(t, failing, store).Reconcile(t.Context(), 1); err == nil {
		t.Fatal("ignored a failed work request")
	}
	status, _, _ := store.GetStatus(t.Context(), key)
	if status.Error == "" || status.Applied {
		t.Fatalf("status=%+v", status)
	}
}

func TestTombstoneDrainsBackendsThenPurges(t *testing.T) {
	api := &providerState{balancer: LoadBalancer{ID: nlbID, Tags: owner.Stamp(key, 0, "")}}
	store := persistentStore(t)
	spec := Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.1.11", Port: 8443, Weight: 5}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	confirm(t, api, store)
	// Reweighting uses update, not delete and re-add.
	spec.Backends[0].Weight = 7
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	api.calls = nil
	if _, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(api.calls, []string{"update 10.0.1.11:8443", "tags"}) || api.backends[0].Weight != 7 {
		t.Fatalf("calls=%v backends=%+v", api.calls, api.backends)
	}
	confirm(t, api, store)
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err == nil {
		t.Fatal("published over a tombstone")
	}
	for range 2 {
		if _, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil {
			t.Fatal(err)
		}
	}
	if len(api.backends) != 0 {
		t.Fatalf("backends=%+v", api.backends)
	}
	if _, err := store.Get(t.Context(), key); !errors.Is(err, ociresource.ErrNotFound) {
		t.Fatalf("record survived: %v", err)
	}
}

func TestTombstonePurgesWhenTheNLBIsGone(t *testing.T) {
	api := &providerState{balancer: LoadBalancer{ID: nlbID, Tags: owner.Stamp(key, 0, "")}}
	store := persistentStore(t)
	spec := Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.1.11", Port: 8443}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	api.gone = true
	if result, err := controller(t, api, store).Reconcile(t.Context(), 1); err == nil || result.Failed != 1 {
		t.Fatalf("live spec over a missing NLB: result=%+v err=%v", result, err)
	}
	confirm(t, api, store)
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	if result, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil || result.Deleted != 1 {
		t.Fatalf("tombstone over a missing NLB: result=%+v err=%v", result, err)
	}
	if _, err := store.Get(t.Context(), key); !errors.Is(err, ociresource.ErrNotFound) {
		t.Fatalf("record survived: %v", err)
	}
	if len(api.calls) != 0 {
		t.Fatalf("unexpected mutations: %v", api.calls)
	}
}

func TestSpecValidation(t *testing.T) {
	store := persistentStore(t)
	for _, spec := range []Spec{
		{NLBID: "ocid1.loadbalancer.oc1..x", BackendSet: "api", Backends: []Backend{{IP: "10.0.0.1", Port: 1}}},
		{NLBID: nlbID, Backends: []Backend{{IP: "10.0.0.1", Port: 1}}},
		{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "8.8.8.8", Port: 1}}},
		{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.0.1", Port: 0}}},
		{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.0.1", Port: 1}, {IP: "10.0.0.1", Port: 1, Weight: 3}}},
		{NLBID: nlbID, BackendSet: "api"},
	} {
		if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err == nil {
			t.Fatalf("accepted %+v", spec)
		}
	}
	if _, err := Publish(t.Context(), store, ociresource.Key{Region: "GRU", Kind: "0000000000V4MRM46HP1SNGDYW", Name: "x"},
		ociresource.PolicyEnforce, Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.0.1", Port: 1}}}); err == nil {
		t.Fatal("published under another kind")
	}
	records, err := store.List(t.Context(), "GRU", Kind)
	if err != nil || len(records) != 0 {
		t.Fatalf("invalid input changed persistent state: records=%v err=%v", records, err)
	}
}

// fenceAfter allows a number of guards and then reports lost authority.
type fenceAfter struct{ remaining int }

func (f *fenceAfter) Guard(context.Context, uint64) error {
	if f.remaining <= 0 {
		return errors.New("lost leadership")
	}
	f.remaining--
	return nil
}

func TestApplyReguardsBeforeEveryMutation(t *testing.T) {
	api := &providerState{balancer: LoadBalancer{ID: nlbID, Tags: owner.Stamp(key, 0, "")}}
	store := persistentStore(t)
	spec := Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{
		{IP: "10.0.1.11", Port: 8443}, {IP: "10.0.1.12", Port: 8443}, {IP: "10.0.1.13", Port: 8443}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	// The controller's own guard plus one mutation (seven guards: controller,
	// write authority and wire authority), then leadership is lost.
	fenced := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store,
		Ownership: owner, Authority: &fenceAfter{remaining: 1 + 7}}
	if _, err := fenced.Reconcile(t.Context(), 1); err == nil {
		t.Fatal("a fenced pass reported success")
	}
	if len(api.calls) != 1 {
		t.Fatalf("mutations after losing authority: %v", api.calls)
	}
}

func TestRestampAfterBackendChangesUsesAFreshETag(t *testing.T) {
	api := &providerState{balancer: LoadBalancer{ID: nlbID, ETag: "etag-0", Tags: owner.Stamp(key, 0, "")}}
	store := persistentStore(t)
	spec := Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.1.11", Port: 8443}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	result, err := controller(t, api, store).Reconcile(t.Context(), 1)
	if err != nil || result.Failed != 0 {
		t.Fatalf("drift with a generation bump: result=%+v err=%v", result, err)
	}
	if !slices.Equal(api.calls, []string{"create 10.0.1.11:8443", "tags"}) {
		t.Fatalf("calls = %v", api.calls)
	}
}

func TestTombstonePurgesWhenTheBackendSetIsGone(t *testing.T) {
	api := &providerState{balancer: LoadBalancer{ID: nlbID, Tags: owner.Stamp(key, 0, "")}}
	store := persistentStore(t)
	spec := Spec{NLBID: nlbID, BackendSet: "typo", Backends: []Backend{{IP: "10.0.1.11", Port: 8443}}}
	if _, err := Publish(t.Context(), store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	api.setGone = true
	if result, err := controller(t, api, store).Reconcile(t.Context(), 1); err == nil || result.Failed != 1 {
		t.Fatalf("live spec over a missing backend set: result=%+v err=%v", result, err)
	}
	confirm(t, api, store)
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now, now); err != nil {
		t.Fatal(err)
	}
	if result, err := controller(t, api, store).Reconcile(t.Context(), 1); err != nil || result.Deleted != 1 {
		t.Fatalf("tombstone over a missing backend set: result=%+v err=%v", result, err)
	}
	if _, err := store.Get(t.Context(), key); !errors.Is(err, ociresource.ErrNotFound) {
		t.Fatalf("record survived: %v", err)
	}
}

func (f *providerState) client(t *testing.T) API {
	t.Helper()
	if f.api != nil {
		return f.api
	}
	factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		respond := func(value any) {
			body, err := json.Marshal(value)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			_, _ = w.Write(body)
		}
		refuse := func(status int, message string) {
			w.WriteHeader(status)
			respond(map[string]string{"code": "ProviderRefused", "message": message})
		}
		path := r.URL.Path
		name := path[strings.LastIndex(path, "/")+1:]
		if f.gone || (f.setGone && strings.Contains(path, "/backendSets/")) {
			refuse(404, "resource gone")
			return
		}
		if strings.Contains(path, "/workRequests/") || strings.Contains(path, "/loadBalancerWorkRequests/") {
			if f.holdWorkRequests {
				refuse(400, "work request observation interrupted")
				return
			}
			err := f.WaitWorkRequest(r.Context(), name)
			state := "SUCCEEDED"
			if err != nil {
				state = "FAILED"
			}
			respond(map[string]string{"id": name, "lifecycleState": state, "status": state})
			return
		}
		if r.Method == http.MethodGet {
			switch {
			case strings.HasSuffix(path, "/health"):
				refuse(405, "health not supported")
			case strings.HasSuffix(path, "/backends"):
				backends := []map[string]any{}
				for _, b := range f.backends {
					backends = append(backends, map[string]any{"ipAddress": b.IP, "port": b.Port, "name": b.Name(), "weight": b.Weight})
				}
				respond(map[string]any{"items": backends})
			default:
				w.Header().Set("etag", f.balancer.ETag)
				respond(map[string]any{"id": f.balancer.ID, "freeformTags": f.balancer.Tags.Freeform, "definedTags": f.balancer.Tags.Defined})
			}
			return
		}
		if f.beforeWrite != nil {
			f.beforeWrite(w, r)
			return
		}
		token := r.Header.Get("opc-retry-token")
		if token != "" && f.retries[token] != "" {
			w.Header().Set("opc-work-request-id", f.retries[token])
			w.WriteHeader(202)
			respond(map[string]any{})
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			refuse(400, "body read failed")
			return
		}
		var workRequest string
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/backends"):
			var details networkloadbalancer.CreateBackendDetails
			if err = json.Unmarshal(body, &details); err == nil {
				workRequest, err = f.CreateBackend(r.Context(), nlbID, "set", Backend{IP: deref(details.IpAddress), Port: intValue(details.Port), Weight: intValue(details.Weight)})
			}
		case r.Method == http.MethodPut && strings.Contains(path, "/backends/"):
			var details networkloadbalancer.UpdateBackendDetails
			if err = json.Unmarshal(body, &details); err == nil {
				workRequest, err = f.UpdateBackend(r.Context(), nlbID, "set", Backend{name: name, Weight: intValue(details.Weight)})
			}
		case r.Method == http.MethodDelete && strings.Contains(path, "/backends/"):
			workRequest, err = f.DeleteBackend(r.Context(), nlbID, "set", name)
		case r.Method == http.MethodPut:
			var details networkloadbalancer.UpdateNetworkLoadBalancerDetails
			if err = json.Unmarshal(body, &details); err == nil {
				workRequest, err = f.UpdateTags(r.Context(), nlbID, r.Header.Get("if-match"), ociresource.Tags{Freeform: details.FreeformTags, Defined: details.DefinedTags})
			}
		default:
			t.Errorf("unexpected %s %s", r.Method, path)
			refuse(405, "unexpected operation")
			return
		}
		if err != nil {
			refuse(412, err.Error())
			return
		}
		if token != "" {
			if f.retries == nil {
				f.retries = map[string]string{}
			}
			f.retries[token] = workRequest
		}
		if f.loseResponse {
			f.loseResponse = false
			connection, _, hijackErr := w.(http.Hijacker).Hijack()
			if hijackErr != nil {
				t.Error(hijackErr)
				return
			}
			_ = connection.Close()
			return
		}
		w.Header().Set("opc-work-request-id", workRequest)
		w.WriteHeader(202)
		respond(map[string]any{})
	})
	client, err := factory.NetworkLoadBalancer()
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&client.BaseClient, endpoint)
	f.api = sdkAPI{client: client, pause: sleep}
	return f.api
}

func persistentStore(t *testing.T) *ociresource.KVStore {
	t.Helper()
	return ociresourcetest.Store(t)
}

func confirm(t *testing.T, api *providerState, store ociresource.Store) {
	t.Helper()
	current, err := store.Get(t.Context(), key)
	if errors.Is(err, ociresource.ErrNotFound) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if current.Operation == nil || !current.Operation.CompletedAt.IsZero() {
		return
	}
	for range 2 {
		result, err := controller(t, api, store).Reconcile(t.Context(), 1)
		if err != nil {
			t.Fatal(err)
		}
		if result.InSync == 1 {
			return
		}
	}
	t.Fatal("operation did not converge")
}

func TestDurableWorkRequestRecoversAfterNATSAndControllerRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	token, storeDir := rand.Text(), t.TempDir()
	openJetStream := func() (jetstream.JetStream, func()) {
		broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1,
			JetStream: true, StoreDir: storeDir, Authorization: token})
		if err != nil {
			t.Fatal(err)
		}
		broker.Start()
		shutdown := func() { broker.Shutdown(); broker.WaitForShutdown() }
		t.Cleanup(shutdown)
		if !broker.ReadyForConnections(5 * time.Second) {
			t.Fatal("OCI restart broker did not become ready")
		}
		connection, err := nats.Connect(broker.ClientURL(), nats.Token(token))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(connection.Close)
		js, err := jetstream.New(connection)
		if err != nil {
			t.Fatal(err)
		}
		return js, func() { connection.Close(); shutdown() }
	}
	js, closeNATS := openJetStream()
	openAuthority := func() *authority.Runtime {
		leader, err := authority.Start(ctx, js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "0000000000C66H81REBS854264", Replicas: 1})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = leader.Close() })
		return leader
	}
	leader := openAuthority()
	firstEpoch := leader.Current().Epoch
	store, err := ociresource.OpenKVStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &providerState{balancer: LoadBalancer{ID: nlbID, ETag: "e1", Tags: owner.Stamp(key, 0, "")}, holdWorkRequests: true}
	spec := Spec{NLBID: nlbID, BackendSet: "api", Backends: []Backend{{IP: "10.0.1.11", Port: 8443}}}
	if _, err := Publish(ctx, store, key, ociresource.PolicyEnforce, spec); err != nil {
		t.Fatal(err)
	}
	reconciler := controller(t, api, store)
	reconciler.Authority = leader
	if _, err := reconciler.Reconcile(ctx, firstEpoch); err == nil {
		t.Fatal("interrupted work request reported success")
	}
	pending, err := store.Get(ctx, key)
	if err != nil || pending.Operation == nil || len(pending.Operation.WorkRequests) != 1 || len(api.calls) != 1 {
		t.Fatalf("pending=%+v err=%v calls=%v", pending, err, api.calls)
	}
	operationID := pending.Operation.ID
	expectedToken := ociresource.RetryToken(ociresource.WithOperation(ctx, operationID), "nlb/create/"+nlbID+"/api/10.0.1.11:8443/1")
	if api.retries[expectedToken] == "" {
		t.Fatalf("create did not use persisted operation token: %v", api.retries)
	}
	staleAuthority := leader
	if err := leader.Close(); err != nil {
		t.Fatal(err)
	}
	closeNATS()
	js, _ = openJetStream()
	leader = openAuthority()
	if leader.Current().Epoch <= firstEpoch {
		t.Fatal("restart reused authority epoch")
	}
	store, err = ociresource.OpenKVStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	api.holdWorkRequests = false
	reconciler = controller(t, api, store)
	reconciler.Authority = leader
	if _, err := reconciler.Reconcile(ctx, leader.Current().Epoch); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, leader.Current().Epoch); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.Get(ctx, key)
	if err != nil || recovered.Operation == nil || recovered.Operation.ID != operationID || recovered.Operation.Epoch != leader.Current().Epoch || recovered.Operation.CompletedAt.IsZero() || len(recovered.Operation.WorkRequests) != 0 || !slices.Equal(api.calls, []string{"create 10.0.1.11:8443", "tags"}) {
		t.Fatalf("operation=%+v err=%v calls=%v", recovered.Operation, err, api.calls)
	}
	api.backends[0].Weight = 2
	stale := controller(t, api, store)
	stale.Authority = staleAuthority
	if _, err := stale.Reconcile(ctx, firstEpoch); !errors.Is(err, ociresource.ErrFenced) || len(api.calls) != 2 {
		t.Fatalf("stale writer err=%v calls=%v", err, api.calls)
	}
	// A rejected write must recheck the original authority before its retry.
	attempts := 0
	api.beforeWrite = func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if err := leader.Close(); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"code":"TooManyRequests","message":"retry after authority handoff"}`)
	}
	if _, err := reconciler.Reconcile(ctx, leader.Current().Epoch); !errors.Is(err, ociresource.ErrFenced) || attempts != 1 || len(api.calls) != 2 {
		t.Fatalf("retry after authority loss: err=%v attempts=%d calls=%v", err, attempts, api.calls)
	}

	leader = openAuthority()
	reconciler.Authority = leader
	requestCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	api.beforeWrite = func(w http.ResponseWriter, r *http.Request) {
		attempts++
		cancelRequest()
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"code":"TooManyRequests","message":"caller canceled"}`)
	}
	if _, err := reconciler.Reconcile(requestCtx, leader.Current().Epoch); !errors.Is(err, context.Canceled) || attempts != 2 || len(api.calls) != 2 {
		t.Fatalf("canceled write: err=%v attempts=%d calls=%v", err, attempts, api.calls)
	}
	persisted, err := store.Get(ctx, key)
	if err != nil || persisted.Operation == nil || persisted.Operation.Epoch != leader.Current().Epoch || !persisted.Operation.CompletedAt.IsZero() {
		t.Fatalf("canceled operation checkpoint: desired=%+v err=%v", persisted, err)
	}
	api.beforeWrite = nil
	if _, err := reconciler.Reconcile(ctx, leader.Current().Epoch); err != nil || len(api.calls) != 3 {
		t.Fatalf("resume after cancellation: err=%v calls=%v", err, api.calls)
	}
}
