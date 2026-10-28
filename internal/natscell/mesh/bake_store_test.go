package mesh

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

type countedBake struct {
	*fakeApplier
	calls     int
	healthy   bool
	interrupt func()
}

func (a *countedBake) Bake(ctx context.Context, _ swarmruntime.ServiceSpec, _ swarmruntime.ServiceRollout) (rollout.BakeVerdict, error) {
	a.calls++
	if a.interrupt != nil {
		a.interrupt()
		if ctx.Err() != nil {
			return rollout.BakeVerdict{}, ctx.Err()
		}
	}
	if a.healthy {
		return (&fakeApplier{}).Bake(ctx, swarmruntime.ServiceSpec{}, swarmruntime.ServiceRollout{})
	}
	return rollout.BakeVerdict{Started: time.Now(), Finished: time.Now(), Samples: 1}, errors.New("dependency HTTP 503")
}

func TestBakePersistenceFailureAndInterruptedRestart(t *testing.T) {
	for _, scenario := range []string{"write failure", "write failure restart", "successful write failure", "shutdown"} {
		t.Run(scenario, func(t *testing.T) {
			a := &countedBake{fakeApplier: &fakeApplier{running: map[string]int64{}}}
			a.healthy = scenario == "successful write failure"
			n := stateTestNodesWithAppliers(t, func(string) Applier { return a }, "sjc")[0]
			spec := swarmruntime.ServiceSpec{Name: "terrabase", Image: "ghcr.io/terrascale/terrabase@sha256:" + strings.Repeat("b", 64), Port: 8080, Replicas: 1, Regions: []string{"sjc"}}
			applied, err := n.apply(t.Context(), ApplyRequest{Name: spec.Name, Entry: Entry{Generation: 1, Spec: &spec}})
			if err != nil {
				t.Fatal(err)
			}
			key := n.bakePath(spec.Name, 1)
			blocked := key + ".tmp" + strconv.Itoa(os.Getpid())
			if strings.Contains(scenario, "write failure") {
				// Blocking the temporary file fails even when tests run as root.
				a.interrupt = func() {
					if err := os.Mkdir(blocked, 0700); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				a.interrupt = n.cancel
			}
			if _, err := n.evaluate(n.ctx, applied); err == nil {
				t.Fatal("failed bake accepted")
			}
			if strings.Contains(scenario, "write failure") {
				if err := os.Remove(blocked); err != nil {
					t.Fatal(err)
				}
			} else {
				record, err := n.readBake(spec.Name, 1)
				if err != nil || !record.Bake.Finished.IsZero() || record.Bake.Reason != "" {
					t.Fatal("shutdown became a terminal failure")
				}
				desired, err := loadDesired(n.cfg.dir)
				if err != nil {
					t.Fatal(err)
				}
				n = &Node{cfg: n.cfg, ctx: t.Context(), desired: desired}
				a.interrupt = nil
			}
			if scenario == "write failure restart" {
				n.bakeUnsaved = nil
			}
			n.failed = map[string]int64{spec.Name: 1}
			if strings.Contains(scenario, "write failure") && scenario != "write failure restart" {
				n.sync(n.ctx)
				if len(n.bakeUnsaved) != 0 {
					t.Fatal("sync did not retry terminal evidence persistence")
				}
			}
			if _, err := n.evaluate(n.ctx, applied); (err == nil) != a.healthy {
				t.Fatalf("unexpected retry result: %v", err)
			}
			if a.healthy {
				state := stateReply{Ready: map[string]int64{spec.Name: 1}, Failed: n.failed}
				n.bakeState(&state)
				if state.Ready[spec.Name] != 1 || state.Failed[spec.Name] != 0 {
					t.Fatal("persisted success still marked failed")
				}
			}
			want := 1
			if scenario == "shutdown" {
				want = 2
			}
			if a.calls != want {
				t.Fatalf("observed %d times, want %d", a.calls, want)
			}
			record, err := n.readBake(spec.Name, 1)
			wantReason := "503"
			if scenario == "write failure restart" {
				wantReason = "interrupted"
			}
			if a.healthy {
				wantReason = ""
			}
			if err != nil || !strings.Contains(record.Bake.Reason, wantReason) {
				t.Fatalf("lost evidence: %+v %v", record, err)
			}
		})
	}
}

func TestBakePhaseUnfinished(t *testing.T) {
	v := rollout.BakeVerdict{Started: time.Now(), Samples: 2}
	if got := bakePhase(v); got != ", bake unfinished (2 samples)" {
		t.Fatal(got)
	}
	v.Finished = v.Started.Add(30 * time.Second)
	if got := bakePhase(v); got != ", bake 30s (2 samples)" {
		t.Fatal(got)
	}
}

func TestSupersededBeforeBakeUsesReleaseVerdict(t *testing.T) {
	n := &Node{desired: map[string]desiredState{"web": stateFor(Entry{Generation: 2})}}
	_, err := n.evaluate(t.Context(), applyResult{
		spec: swarmruntime.ServiceSpec{Name: "web", Generation: 1}, state: stateFor(Entry{Generation: 1}),
	})
	if !errors.Is(err, swarmruntime.ErrSupersededDuringBake) {
		t.Fatalf("superseded before bake: %v", err)
	}
}
