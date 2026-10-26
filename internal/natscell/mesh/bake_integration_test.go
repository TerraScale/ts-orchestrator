package mesh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func (f *fakeApplier) Bake(context.Context, swarmruntime.ServiceSpec, swarmruntime.ServiceRollout) (rollout.BakeVerdict, error) {
	return rollout.BakeVerdict{Started: time.Now(), Finished: time.Now(), Samples: 1, Checks: map[string]string{"candidate": "ok"}}, nil
}

func (deferredApplier) Bake(ctx context.Context, spec swarmruntime.ServiceSpec, ready swarmruntime.ServiceRollout) (rollout.BakeVerdict, error) {
	return (&fakeApplier{}).Bake(ctx, spec, ready)
}

func TestTerraBaseRolloutPausesOnFailure(t *testing.T) {
	spec, err := (swarmruntime.ServiceSpec{Name: "terrabase", Image: "ghcr.io/terrascale/terrabase@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}).SwarmSpec()
	if err != nil || spec.Update == nil || spec.Update.FailureAction != api.UpdateConfig_PAUSE {
		t.Fatalf("storage update must pause: spec=%+v, err=%v", spec, err)
	}
}

// Only the runtime boundary is synthetic: readiness succeeds before the HTTP
// dependency breaks, and the channel lets the test inspect an unfinished bake.
type failingBakeApplier struct {
	*fakeApplier
	image, url, check string
	status            *atomic.Int32
	entered, finish   chan struct{}
	once              sync.Once
}

func (f *failingBakeApplier) Wait(ctx context.Context, spec swarmruntime.ServiceSpec, original *api.Service) (swarmruntime.ServiceRollout, error) {
	result, err := f.fakeApplier.Wait(ctx, spec, original)
	if err == nil && spec.Image == f.image {
		result.Ready = time.Millisecond
		f.status.Store(http.StatusServiceUnavailable)
	}
	return result, err
}

func (f *failingBakeApplier) Bake(ctx context.Context, spec swarmruntime.ServiceSpec, ready swarmruntime.ServiceRollout) (rollout.BakeVerdict, error) {
	if spec.Image != f.image {
		return f.fakeApplier.Bake(ctx, spec, ready)
	}
	verdict := rollout.BakeVerdict{Started: time.Now(), Checks: map[string]string{}}
	f.once.Do(func() { close(f.entered) })
	select {
	case <-ctx.Done():
		return verdict, ctx.Err()
	case <-f.finish:
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return verdict, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return verdict, err
	}
	defer response.Body.Close()
	verdict.Finished, verdict.Samples = time.Now(), 1
	verdict.Checks[f.check] = response.Status
	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s: %s", f.check, response.Status)
		verdict.Reason = err.Error()
	}
	return verdict, err
}

func TestMeshFailedPostReadinessBakeHoldsRollout(t *testing.T) {
	for _, check := range []string{"dependency", "anchor"} {
		t.Run(check, func(t *testing.T) {
			regions, nodes, appliers := startMeshRegions(t, 0)
			spec := swarmruntime.ServiceSpec{Name: "terrabase", Image: "ghcr.io/terrascale/terrabase@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
			order := rolloutOrder(&spec)
			first, home := order[0], nodes[regions[0]]
			if _, err := applySpec(t.Context(), home.conn, spec, "", false, 30*time.Second); err != nil {
				t.Fatal(err)
			}
			var status atomic.Int32
			status.Store(http.StatusOK)
			fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(int(status.Load())) }))
			defer fixture.Close()
			bad := spec
			bad.Image = "ghcr.io/terrascale/terrabase@sha256:" + strings.Repeat("b", 64)
			fault := &failingBakeApplier{fakeApplier: appliers[first], image: bad.Image, url: fixture.URL + "/" + check, check: check, status: &status, entered: make(chan struct{}), finish: make(chan struct{})}
			cfg := nodes[first].cfg
			restart := func(applier Applier) {
				t.Helper()
				nodes[first].Close()
				cfg.applier = applier
				var err error
				nodes[first], err = start(cfg)
				if err != nil {
					t.Fatal(err)
				}
				go nodes[first].run(t.Context())
				eventually(t, "restarted region to rejoin", func() bool { return Ping(t.Context(), home.conn, time.Second, io.Discard) == nil })
			}
			restart(fault)
			result := make(chan error, 1)
			go func() {
				var err error
				if check == "dependency" {
					_, err = release(t.Context(), home.conn, bad.Name, bad.Image, 30*time.Second, time.Second)
				} else {
					_, err = applySpec(t.Context(), home.conn, bad, "", false, 30*time.Second)
				}
				result <- err
			}()
			select {
			case <-fault.entered:
			case <-time.After(10 * time.Second):
				t.Fatal("candidate never reached its post-readiness bake")
			}
			generation := appliers[first].generation(spec.Name)
			assertHeld := func(failed bool) {
				t.Helper()
				raw, err := appliers[first].Ready(t.Context())
				state := home.states(t.Context())[first]
				if err != nil || state.Region != first || raw[spec.Name] != generation || state.Ready[spec.Name] == generation || (state.Failed[spec.Name] == generation) != failed {
					t.Fatalf("runtime ready=%v, advertised=%+v, error=%v", raw, state, err)
				}
				for _, region := range order[1:] {
					nodes[region].sync(t.Context())
					if image := appliers[region].appliedImage(spec.Name); image != spec.Image {
						t.Fatalf("%s advanced to %s while bake held", region, image)
					}
				}
			}
			assertHeld(false)
			close(fault.finish)
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("failed bake accepted")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("failed bake did not stop rollout")
			}
			path := nodes[first].bakePath(spec.Name, generation)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			record, err := nodes[first].readBake(spec.Name, generation)
			if err != nil {
				t.Fatal(err)
			}
			if record.Generation != generation || record.Image != bad.Image || record.Rollout.Ready == 0 || record.Bake.Started.IsZero() || record.Bake.Finished.Before(record.Bake.Started) || record.Bake.Samples != 1 || record.Bake.Checks[check] != "503 Service Unavailable" || !strings.Contains(record.Bake.Reason, check) {
				t.Fatalf("incomplete durable failure: %+v", record)
			}
			assertHeld(true)
			// A healthy runtime boundary after restart must not erase retained failure.
			restart(appliers[first])
			assertHeld(true)
			spec.Image = "ghcr.io/terrascale/terrabase@sha256:" + strings.Repeat("c", 64)
			if _, err := applySpec(t.Context(), home.conn, spec, "", false, 30*time.Second); err != nil {
				t.Fatal(err)
			}
			for _, region := range regions {
				if image := appliers[region].appliedImage(spec.Name); image != spec.Image {
					t.Fatalf("%s did not fix forward: %s", region, image)
				}
			}
			retained, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(retained, data) {
				t.Fatalf("fix-forward lost failure evidence: %v", err)
			}
		})
	}
}
