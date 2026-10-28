package rollout

import (
	"context"
	"errors"
	"maps"
	"testing"
	"testing/synctest"
	"time"
)

func TestBakeTerraBaseSwapAuthRecovery(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failures int
		elapsed  time.Duration
		samples  int
	}{
		{"ready-then-auth503", 1, 32 * time.Second, 17},
		{"auth503-through2s", 2, 34 * time.Second, 18},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				if DependencyRecoveryWindow != 30*time.Second {
					t.Fatalf("recovery window = %s", DependencyRecoveryWindow)
				}
				started := time.Now()
				calls := 0
				checks := map[string]string{"candidate": "ready", "ts-auth": "HTTP 503"}
				var lastRecovery map[string]string
				v, err := RunBake(t.Context(), func(context.Context) (map[string]string, error) {
					calls++
					if calls <= tc.failures {
						lastRecovery = maps.Clone(checks)
						return checks, &DependencyFailure{Service: "ts-auth", Status: "HTTP 503"}
					}
					// Reusing the probe's map must not overwrite retained failure evidence.
					checks["ts-auth"] = "ok"
					return checks, nil
				})
				if err != nil || v.Reason != "" {
					t.Fatalf("recovered bake failed: %+v, %v", v, err)
				}
				if v.Samples != tc.samples || calls != tc.samples || time.Since(started) != tc.elapsed || v.Finished.Sub(v.Started) != tc.elapsed {
					t.Fatalf("bake completed without a full healthy window: %+v; calls=%d elapsed=%s", v, calls, time.Since(started))
				}
				wantHealthy := started.Add(time.Duration(tc.failures) * 2 * time.Second)
				if !v.HealthySince.Equal(wantHealthy) || v.Finished.Sub(v.HealthySince) != 30*time.Second {
					t.Fatalf("healthy clock: %+v; want start %s", v, wantHealthy)
				}
				if v.RecoverySamples != tc.failures || !maps.Equal(v.RecoveryChecks, lastRecovery) || !maps.Equal(v.Checks, checks) {
					t.Fatalf("lost recovery or final evidence: %+v", v)
				}
			})
		})
	}
}

func TestBakeRecoveryRejectsFailures(t *testing.T) {
	auth503 := &DependencyFailure{Service: "ts-auth", Status: "HTTP 503"}
	for _, tc := range []struct {
		name            string
		initialFailures int
		fatalAt         int
		failure         error
		cancel          bool
	}{
		{"candidate-during-recovery", 1, 2, errors.New("candidate readiness failed"), false},
		{"catalog-during-recovery", 1, 2, &DependencyFailure{Service: "ts-catalog", Status: "HTTP 503"}, false},
		{"auth500-during-recovery", 1, 2, &DependencyFailure{Service: "ts-auth", Status: "HTTP 500"}, false},
		{"logs-during-recovery", 1, 2, errors.New("candidate log read failed"), false},
		{"untyped-auth503", 0, 1, errors.New(auth503.Error()), false},
		{"untyped-auth503-during-recovery", 1, 2, errors.New(auth503.Error()), false},
		{"cancel-after-recovery-failure", 1, 2, auth503, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				started := time.Now()
				calls := 0
				lastRecovery := map[string]string{"candidate": "ready", "ts-auth": "HTTP 503"}
				fatalChecks := map[string]string{"candidate": "ready", "failure": tc.failure.Error()}
				v, err := RunBake(ctx, func(context.Context) (map[string]string, error) {
					calls++
					if calls <= tc.initialFailures {
						return lastRecovery, auth503
					}
					if calls == tc.fatalAt {
						if tc.cancel {
							cancel()
						}
						return fatalChecks, tc.failure
					}
					return map[string]string{"candidate": "ready", "ts-auth": "ok"}, nil
				})
				wantErr := tc.failure
				if tc.cancel {
					wantErr = context.Canceled
				}
				if !errors.Is(err, wantErr) || v.Reason == "" || v.Reason != err.Error() {
					t.Fatalf("fatal error/reason: %+v, %v; want %v", v, err, wantErr)
				}
				wantElapsed := time.Duration(tc.fatalAt-1) * 2 * time.Second
				if calls != tc.fatalAt || v.Samples != tc.fatalAt || time.Since(started) != wantElapsed || v.Finished.Sub(v.Started) != wantElapsed {
					t.Fatalf("failure did not stop immediately: %+v; calls=%d elapsed=%s", v, calls, time.Since(started))
				}
				if v.RecoverySamples != tc.initialFailures {
					t.Fatalf("tolerated %d samples; want %d", v.RecoverySamples, tc.initialFailures)
				}
				if tc.initialFailures > 0 && !maps.Equal(v.RecoveryChecks, lastRecovery) {
					t.Fatalf("lost tolerated evidence: %+v", v)
				}
				for key, value := range fatalChecks {
					if v.Checks[key] != value {
						t.Fatalf("lost fatal evidence: %+v; want %s=%s", v, key, value)
					}
				}
				if tc.cancel && v.Checks["observation"] != context.Canceled.Error() {
					t.Fatalf("lost cancellation evidence: %+v", v)
				}
			})
		})
	}
}

func TestBakeRepeatedDependencyRollsAreBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		v, err := RunBake(t.Context(), func(context.Context) (map[string]string, error) {
			calls++
			if calls%13 == 1 {
				return map[string]string{"ts-dashboard": "HTTP 503"}, &DependencyFailure{Service: "ts-dashboard", Status: "HTTP 503"}
			}
			return map[string]string{"candidate": "ok", "ts-dashboard": "ok"}, nil
		})
		if !errors.Is(err, context.DeadlineExceeded) || v.Finished.Sub(v.Started) != MaxBakeWindow || v.RecoverySamples < 2 || v.RecoveryChecks["ts-dashboard"] != "HTTP 503" || v.Checks["observation"] != context.DeadlineExceeded.Error() {
			t.Fatalf("repeated rollovers extended the bake indefinitely or lost evidence: %+v %v", v, err)
		}
	})
}
