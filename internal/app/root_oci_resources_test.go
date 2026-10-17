package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/bucket"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestRootResourceSnapshotRefusesMissingDeletedAndPurgedAuthority(t *testing.T) {
	runtime, err := newAuthenticatedNATS(t, "lab", "root-resource-source").start(t, t.Context(), natscell.Config{Cell: "lab", Instance: "root-resource-source", Replicas: 1, Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "jetstream")}})
	if err != nil {
		t.Fatal(err)
	}
	js := runtime.JetStream()
	if _, err := rootResourceKV(t.Context(), js, cellSpecBucket, cellSpecKey); err == nil {
		t.Fatal("missing source stream treated as signed baseline")
	}
	kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: cellSpecBucket, History: 4, Storage: jetstream.FileStorage, MaxValueSize: 65536})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rootResourceKV(t.Context(), js, cellSpecBucket, cellSpecKey); err == nil {
		t.Fatal("empty stream treated as signed mutation authority")
	}
	revision, err := kv.Put(t.Context(), cellSpecKey, []byte(`{"signed":"exact-wire"}`))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := rootResourceKV(t.Context(), js, cellSpecBucket, cellSpecKey)
	if err != nil || entry == nil || entry.Sequence != revision {
		t.Fatalf("ordered source = %+v %v", entry, err)
	}
	if err := kv.Delete(t.Context(), cellSpecKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rootResourceKV(t.Context(), js, cellSpecBucket, cellSpecKey); err == nil {
		t.Fatal("deleted signed source accepted")
	}
	stream, err := js.Stream(t.Context(), "KV_"+cellSpecBucket)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Purge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := rootResourceKV(t.Context(), js, cellSpecBucket, cellSpecKey); err == nil {
		t.Fatal("purged signed history treated as fresh genesis")
	}
	if err := js.DeleteKeyValue(t.Context(), cellSpecBucket); err != nil {
		t.Fatal(err)
	}
	kv, err = js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: cellSpecBucket, History: 4, Storage: jetstream.FileStorage, MaxValueSize: 65536})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rootResourceKV(t.Context(), js, cellSpecBucket, cellSpecKey); err == nil {
		t.Fatal("deleted and recreated stream treated as fresh genesis")
	}

	// The original source deadline survives subsequent broker reads and caps.
	now := time.Now()
	call, lease, spec := now.Add(time.Minute), now.Add(20*time.Second), now.Add(10*time.Second)
	if deadline := minResourceDeadline(call, lease, spec); !deadline.Equal(spec) {
		t.Fatalf("deadline=%v", deadline)
	}
	if deadline := minResourceDeadline(call, lease, time.Time{}); !deadline.Equal(lease) {
		t.Fatalf("deadline=%v", deadline)
	}
	if !minResourceDeadline(call, time.Time{}, spec).IsZero() {
		t.Fatal("missing original lease admitted")
	}
	if _, err := kv.Put(t.Context(), cellSpecKey, []byte(`{"signed":"exact-wire"}`)); err != nil {
		t.Fatal(err)
	}
	bounded, stop := context.WithDeadline(t.Context(), minResourceDeadline(call, lease, spec))
	defer stop()
	if entry, err := rootResourceKV(bounded, js, cellSpecBucket, cellSpecKey); err != nil || entry == nil {
		t.Fatalf("bounded source read=%+v %v", entry, err)
	}
	expired, stopExpired := context.WithDeadline(t.Context(), now.Add(-time.Second))
	defer stopExpired()
	if _, err := rootResourceKV(expired, js, cellSpecBucket, cellSpecKey); err == nil {
		t.Fatal("expired original source read admitted")
	}
	observed := rootResourceFencer{deadline: now.Add(-time.Second)}
	if err := observed.Guard(t.Context(), 0); err == nil {
		t.Fatal("expired original observation admitted")
	}
	if observed.Current().Leader {
		t.Fatal("observed NATS lease promoted to mutation authority")
	}
}

func TestRootResourceSDKObservationsAndMissingCAPAdmission(t *testing.T) {
	profiles := terraBaseSeats("gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443")
	public := OciReconcileLBConfig{LoadBalancerID: publicLBID, BackendSet: "terrabase"}
	key, err := public.key("GRU")
	if err != nil {
		t.Fatal(err)
	}
	bucketKey := ociresource.Key{Region: "GRU", Kind: bucket.Kind, Name: "backups"}
	owner := ociresource.Ownership{Owner: "terrascale"}
	var scenario atomic.Value
	scenario.Store("")
	var mutations atomic.Int64
	factory := rootResourceSDKFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned OCI SDK request")
			w.WriteHeader(401)
			return
		}
		if r.Method != http.MethodGet {
			mutations.Add(1)
			w.WriteHeader(405)
			return
		}
		mode := scenario.Load().(string)
		var response any
		switch r.URL.Path {
		case "/20170115/loadBalancers/" + publicLBID:
			id, tags := publicLBID, owner.Stamp(key, 1, "digest")
			if mode == "wrong load balancer" {
				id = "ocid1.loadbalancer.oc1.sa-saopaulo-1.other"
			}
			if mode == "foreign" {
				tags = ociresource.Tags{}
			}
			response = map[string]any{"id": id, "freeformTags": tags.Freeform}
		case "/20170115/loadBalancers/" + publicLBID + "/backendSets/terrabase/backends":
			backends := []map[string]any{{"ipAddress": "10.251.0.21", "port": 9465, "drain": true, "name": "10.251.0.21:9465"}, {"ipAddress": "10.251.0.22", "port": 9465, "name": "10.251.0.22:9465"}}
			if mode == "unknown member" {
				backends[0]["ipAddress"] = "10.251.0.99"
			}
			if mode == "duplicate member" {
				backends[1] = backends[0]
			}
			response = backends
		case "/20170115/loadBalancers/" + publicLBID + "/backendSets/terrabase/health":
			names := []string{"10.251.0.21:9465"}
			if mode == "unknown health" {
				names = append(names, "10.251.0.99:9465")
			}
			response = map[string]any{"warningStateBackendNames": names}
		case "/n/tenancy/b/backups":
			response = map[string]any{"namespace": "tenancy", "name": "backups", "versioning": "Disabled", "freeformTags": owner.Stamp(bucketKey, 1, "digest").Freeform}
		case "/n/tenancy/b/backups/retentionRules":
			response = map[string]any{"items": []any{}}
		default:
			t.Errorf("unexpected OCI SDK path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		wire, err := json.Marshal(response)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(wire)
	}))
	api, err := lb.NewSDKAPI(factory)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rootPublicSeatBackends(t.Context(), api, public, profiles, "GRU", "terrascale")
	if err != nil || len(got) != 2 || !got["10.251.0.21:9465"].Drained || got["10.251.0.21:9465"].Healthy || !got["10.251.0.22:9465"].Healthy {
		t.Fatalf("backends=%+v %v", got, err)
	}
	for _, mode := range []string{"wrong load balancer", "foreign", "unknown member", "duplicate member", "unknown health"} {
		t.Run(mode, func(t *testing.T) {
			scenario.Store(mode)
			if _, err := rootPublicSeatBackends(t.Context(), api, public, profiles, "GRU", "terrascale"); err == nil {
				t.Fatal("outside backend authority accepted")
			}
		})
	}
	bucketAPI, err := bucket.NewSDKAPI(factory)
	if err != nil {
		t.Fatal(err)
	}
	resource := rootBucketResource{Reconciler: bucket.Reconciler{API: bucketAPI}}
	for _, spec := range []bucket.Spec{
		{Namespace: "tenancy", Bucket: "backups", Versioning: bucket.VersioningEnabled},
		{Namespace: "tenancy", Bucket: "backups", Retention: []bucket.Retention{{Name: "daily", Days: 30}}},
	} {
		target := ociresource.Target[bucket.Spec]{Key: bucketKey, Spec: spec, Ownership: owner}
		observed, found, err := resource.Observe(t.Context(), target)
		if err != nil || !found {
			t.Fatalf("SDK bucket observation found=%v err=%v", found, err)
		}
		plan := resource.Diff(target, observed, found)
		if plan.Empty() {
			t.Fatal("fixture must observe property drift")
		}
		if err := resource.Apply(t.Context(), target, observed, found, plan); err == nil || mutations.Load() != 0 {
			t.Fatal("bucket mutation reached SDK without protected CAP admission")
		}
	}
}

func rootResourceSDKFixture(t *testing.T, handler http.Handler) *ociclient.Factory {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.Proxy = nil
	dialer := tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "iaas.sa-saopaulo-1.oraclecloud.com:443" && address != "objectstorage.sa-saopaulo-1.oraclecloud.com:443" {
			return nil, fmt.Errorf("unexpected OCI SDK endpoint %q", address)
		}
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("root resource fixture requires pinned TLS OCI endpoints")
	}
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("tenancy", "user", "sa-saopaulo-1", "fingerprint", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return factory
}
