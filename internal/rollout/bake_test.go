package rollout

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestBakeWindowAndFailures(t *testing.T) {
	for _, mode := range []string{"healthy", "regressed", "cancelled", "late"} {
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
					if mode == "late" {
						time.Sleep(11 * time.Second)
					}
					if mode == "regressed" && calls == 2 {
						return map[string]string{"dependency": "HTTP 503"}, errors.New("dependency failed")
					}
					return map[string]string{"candidate": "ok"}, nil
				})
				if mode == "healthy" {
					if err != nil || v.Samples != 31 || v.Finished.Sub(v.Started) != BakeWindow {
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
