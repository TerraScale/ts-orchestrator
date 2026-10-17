package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/bucket"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/nats-io/nats.go/jetstream"
)

func TestRootResourceSnapshotRefusesMissingDeletedAndPurgedAuthority(t *testing.T) {
	runtime, err := natscell.Start(t.Context(), natscell.Config{Cell: "lab", Instance: "root-resource-source", Replicas: 1, Lab: true, Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "jetstream")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	js := runtime.JetStream()
	if _, err := rootResourceKV(t.Context(), js, cellSpecBucket, cellSpecKey); err == nil {
		t.Fatal("missing source stream treated as signed baseline")
	}
	kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: cellSpecBucket, History: 4, Storage: jetstream.FileStorage, MaxValueSize: 65536})
	if err != nil {
		t.Fatal(err)
	}
	if entry, err := rootResourceKV(t.Context(), js, cellSpecBucket, cellSpecKey); err != nil || entry != nil {
		t.Fatalf("fresh genesis = %+v %v", entry, err)
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
}

func TestRootResourceDeadlineCannotUseRenewedAuthority(t *testing.T) {
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
	observed := rootResourceFencer{deadline: now.Add(-time.Second)}
	if err := observed.Guard(t.Context(), 0); err == nil {
		t.Fatal("expired original observation admitted")
	}
	if observed.Current().Leader {
		t.Fatal("observed NATS lease promoted to mutation authority")
	}
}

type rootSeatAPI struct {
	seatLBAPI
	balancer lb.LoadBalancer
}

func (a rootSeatAPI) GetLoadBalancer(context.Context, string) (lb.LoadBalancer, error) {
	return a.balancer, nil
}

func TestRootSeatObservationRequiresOwnedSignedMembership(t *testing.T) {
	profiles := terraBaseSeats("gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443")
	public := OciReconcileLBConfig{LoadBalancerID: publicLBID, BackendSet: "terrabase"}
	key, err := public.key("GRU")
	if err != nil {
		t.Fatal(err)
	}
	api := rootSeatAPI{seatLBAPI: seatLBAPI{backends: []lb.Backend{{IP: "10.251.0.21", Port: 9465, Drain: true}, {IP: "10.251.0.22", Port: 9465}}, unhealthy: map[string]bool{"10.251.0.21:9465": true}}, balancer: lb.LoadBalancer{ID: publicLBID, Tags: (ociresource.Ownership{Owner: "terrascale"}).Stamp(key, 1, "digest")}}
	got, err := rootPublicSeatBackends(t.Context(), api, public, profiles, "GRU", "terrascale")
	if err != nil || len(got) != 2 || !got["10.251.0.21:9465"].Drained || got["10.251.0.21:9465"].Healthy || !got["10.251.0.22:9465"].Healthy {
		t.Fatalf("backends=%+v %v", got, err)
	}
	for _, scenario := range []string{"wrong load balancer", "foreign", "unknown member", "duplicate member", "unknown health"} {
		t.Run(scenario, func(t *testing.T) {
			changed := api
			switch scenario {
			case "wrong load balancer":
				changed.balancer.ID = "ocid1.loadbalancer.oc1.sa-saopaulo-1.other"
			case "foreign":
				changed.balancer.Tags = ociresource.Tags{}
			case "unknown member":
				changed.backends = []lb.Backend{{IP: "10.251.0.99", Port: 9465}}
			case "duplicate member":
				changed.backends = []lb.Backend{api.backends[0], api.backends[0]}
			case "unknown health":
				changed.unhealthy = map[string]bool{"10.251.0.99:9465": true}
			}
			if _, err := rootPublicSeatBackends(t.Context(), changed, public, profiles, "GRU", "terrascale"); err == nil {
				t.Fatal("outside backend authority accepted")
			}
		})
	}
}

func TestRootBucketPropertiesRequireProtectedCAPAdmission(t *testing.T) {
	// A nil API panics if the missing admission ever reaches a cloud method.
	resource := rootBucketResource{}
	for _, spec := range []bucket.Spec{
		{Namespace: "tenancy", Bucket: "backups", Versioning: bucket.VersioningEnabled},
		{Namespace: "tenancy", Bucket: "backups", Retention: []bucket.Retention{{Name: "daily", Days: 30}}},
	} {
		if err := resource.Apply(t.Context(), ociresource.Target[bucket.Spec]{Spec: spec}, bucket.Observed{}, true, ociresource.Plan{}); err == nil {
			t.Fatal("bucket property mutation admitted without protected CAP authority")
		}
	}
}
