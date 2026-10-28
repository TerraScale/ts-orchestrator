package rollout

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestBakeWindowAndFailures(t *testing.T) {
	for _, mode := range []string{"healthy", "regressed", "cancelled", "cancelled-probe", "late"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if mode == "cancelled" {
					cancel()
				}
				calls := 0
				v, err := RunBake(ctx, func(context.Context) (map[string]string, error) {
					calls++
					if mode == "cancelled-probe" {
						cancel()
						return nil, errors.New("probe request failed")
					}
					if mode == "late" {
						time.Sleep(11 * time.Second)
					}
					if mode == "regressed" && calls == 2 {
						return map[string]string{"dependency": "HTTP 503"}, errors.New("dependency failed")
					}
					return map[string]string{"candidate": "ok"}, nil
				})
				if mode == "healthy" {
					if err != nil || v.Samples != 16 || v.Finished.Sub(v.Started) != 30*time.Second || MaxBakeWindow != 90*time.Second {
						t.Fatalf("healthy bake: %+v %v", v, err)
					}
				} else if err == nil || v.Reason == "" || v.Samples != calls {
					t.Fatalf("failed bake: %+v %v", v, err)
				}
				if mode == "regressed" && (v.Checks["dependency"] != "HTTP 503" || calls != 2) {
					t.Fatalf("lost regression evidence: %+v", v)
				}
			})
		})
	}
}

// ts-dashboard 8894ff6 and 9bf95a0: fra's dependency probes took over 2 s, and
// a sample bounded by the 2 s poll failed the bake with a bare deadline.
func TestBakeSampleSlowerThanPollStillCounts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		v, err := RunBake(t.Context(), func(ctx context.Context) (map[string]string, error) {
			select {
			case <-time.After(3 * time.Second):
				return map[string]string{"candidate": "ok"}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
		if err != nil || v.Samples < 2 || v.Finished.Sub(v.HealthySince) < BakeWindow {
			t.Fatalf("slow healthy samples failed the bake: %+v %v", v, err)
		}
	})
}
