package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
)

const (
	// releaseWait is the minimum wait; rolloutWait adds regional bake budgets.
	releaseWait = 70 * time.Second
	// Rollback runs in parallel; the previous image is already on every host.
	rollbackWait = 40 * time.Second
)

// Release serves app image releases (releasepush.Handler.App) on this host's
// mesh node: it updates the image and declared all-region app budgets.
func Release(state string) func(ctx context.Context, service, image string, claims releasepush.Claims, progress releasepush.Progress) (json.RawMessage, error) {
	return func(ctx context.Context, service, image string, claims releasepush.Claims, progress releasepush.Progress) (json.RawMessage, error) {
		fence, err := rolloutmaintenance.Open(state)
		if err != nil {
			return nil, err
		}
		if err := fence.Publication(ctx, service); err != nil {
			if !errors.Is(err, rolloutmaintenance.ErrFenced) {
				return nil, err
			}
			attempt, _ := strconv.ParseUint(claims.RunAttempt, 10, 64)
			if err = fence.RetainCandidate(ctx, rolloutmaintenance.Candidate{Image: image, Repository: claims.Repository, RunID: claims.RunID, RunAttempt: attempt, Revision: claims.SHA, Workflow: claims.JobWorkflowRef}); err != nil {
				return nil, err
			}
			return protocol.EncodeJSON(struct {
				Held  bool   `json:"held"`
				Image string `json:"image"`
			}{true, image})
		}
		conn, err := Connect(state)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		attempt, _ := strconv.ParseUint(claims.RunAttempt, 10, 64)
		rows, failed := releaseDeployment(ctx, conn, service, image, &Deployment{Repository: claims.Repository, RunID: claims.RunID, RunAttempt: attempt, Revision: claims.SHA, Image: image, Workflow: claims.JobWorkflowRef}, releaseWait, rollbackWait, progress)
		if rows == nil {
			return nil, failed
		}
		data, err := protocol.EncodeJSON(rows)
		return data, errors.Join(failed, err)
	}
}

// release applies the desired spec with only its image changed. When a
// targeted region fails or does not get ready within wait, it re-applies the
// previous spec everywhere, unless a newer release replaced this one meanwhile;
// the rollback's rows follow the release's.
func release(ctx context.Context, conn *nats.Conn, service, image string, wait, rollbackWait time.Duration) ([]Reply, error) {
	return releaseDeployment(ctx, conn, service, image, nil, wait, rollbackWait, unreported{})
}

type unreported struct{}

func (unreported) Deadline(time.Time) {}
func (unreported) Event(string)       {}

func regionEvent(prefix string, reply Reply) string {
	elapsed := time.Duration(reply.ElapsedMS) * time.Millisecond
	switch {
	case reply.Error != "":
		return fmt.Sprintf("%s%s failed after %s: %s", prefix, reply.Region, elapsed, reply.Error)
	case reply.Phases != "":
		return fmt.Sprintf("%s%s %s in %s (%s)", prefix, reply.Region, reply.Result, elapsed, reply.Phases)
	default:
		return fmt.Sprintf("%s%s %s in %s", prefix, reply.Region, reply.Result, elapsed)
	}
}

func releaseDeployment(ctx context.Context, conn *nats.Conn, service, image string, deployment *Deployment, wait, rollbackWait time.Duration, progress releasepush.Progress) ([]Reply, error) {
	entries, err := desiredStates(ctx, conn)
	if err != nil {
		return nil, err
	}
	before := entries[service].entry()
	previous := before.Spec
	if err := entries[service].accepts(deployment); err != nil {
		return nil, fmt.Errorf("%s refused release %+v; current signed release %+v: %w", service, deployment, entries[service].Floor, err)
	}
	// The retained signed floor survives rollback and operator changes. Once
	// this run's image is no longer desired, losing the handler's cache must
	// not turn its terminal failure into a fresh attempt with a new generation.
	if deployment != nil && entries[service].Floor != nil && *entries[service].Floor == *deployment && (before.RollbackOf != 0 || previous == nil || previous.Image != image) {
		return nil, fmt.Errorf("%s: signed deployment was rolled back or replaced; retry requires a newer signed run", service)
	}
	resume := deployment != nil && before.Deployment != nil && *before.Deployment == *deployment && previous != nil && previous.Image == image
	if resume && failedAnywhere(ctx, conn, service, before.Generation) {
		return nil, fmt.Errorf("%s held at failed generation %d by release %+v; refused release %+v; repair the cause and release again from a strictly newer signed run or attempt", service, before.Generation, before.Deployment, deployment)
	}
	var next swarmruntime.ServiceSpec
	if previous == nil {
		// Only the authenticated canary workflow can create its fixed workload.
		// A newer signed run also restores a removed canary, using its fixed spec.
		if service != "app-canary" || deployment == nil {
			return nil, fmt.Errorf("%s is not a mesh service", service)
		}
		data, err := m1.Files.ReadFile("services/app-canary.json")
		if err != nil {
			return nil, err
		}
		if err := protocol.DecodeStrict(data, &next, 64<<10); err != nil {
			return nil, err
		}
	} else {
		next = *previous
	}
	if repository(next.Image) != repository(image) && !dashboardPackageCutover(service, next.Image, image, deployment) {
		return nil, fmt.Errorf("%s runs %s; a release may change only its digest", service, repository(next.Image))
	}
	next.Image = image
	if deployment != nil && before.HoldAfter == "" {
		if err := declaredReleasePlacement(&next, deployment); err != nil {
			return nil, err
		}
	}
	generation := max(time.Now().UnixNano(), before.Generation+1)
	hold := before.HoldAfter
	if deployment != nil {
		hold = ""
	}
	request := ApplyRequest{Name: service, Entry: Entry{Generation: generation, Spec: &next, Deployment: deployment, HoldAfter: hold}}
	if resume {
		generation = before.Generation
		request.Entry = before
	}
	rollout, rollback := max(wait, rolloutWait(&next)), max(rollbackWait, regionWindow(previous))
	deadline := time.Now().Add(rollout + rollback + 2*stateWait)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	progress.Deadline(deadline)
	progress.Event(fmt.Sprintf("%s %s rolls out to %s one region at a time; other regions answer at once; outcome by %s (rollout %s, rollback %s)",
		service, image, strings.Join(rolloutOrder(&next), ", "), deadline.UTC().Format(time.RFC3339), rollout, rollback))
	rows, failed := sendObserved(ctx, conn, request, rollout, func(reply Reply) { progress.Event(regionEvent("", reply)) })
	if failed == nil || bakeHeld(rows, service) {
		return rows, failed
	}
	if current, err := desiredStates(ctx, conn); err != nil || current[service].entry().Generation != generation {
		return rows, errors.Join(failed, errors.New("not rolled back: a newer release replaced it"), err)
	}
	target := "absence"
	if previous != nil {
		target = previous.Image
	}
	progress.Event(fmt.Sprintf("rolling back to %s in every region: %s", target, failed))
	back, err := sendObserved(ctx, conn, ApplyRequest{Name: service, ExpectedGeneration: generation, Entry: Entry{Generation: max(time.Now().UnixNano(), generation+1), Spec: previous, Deployment: deployment, HoldAfter: entries[service].entry().HoldAfter}}, rollback,
		func(reply Reply) { progress.Event(regionEvent("rollback ", reply)) })
	if err != nil {
		return append(rows, back...), errors.Join(failed, fmt.Errorf("rollback to %s: %w", target, err))
	}
	return append(rows, back...), errors.Join(failed, errors.New("rolled back to "+target))
}

// dashboardPackageCutover admits only the signed monorepo dashboard move.
// Unsigned operations and every other package change retain the digest-only boundary.
func dashboardPackageCutover(service, current, next string, deployment *Deployment) bool {
	return service == "ts-dashboard" && deployment != nil &&
		deployment.Repository == "TerraScale/terrascale" && deployment.Image == next &&
		repository(current) == "ghcr.io/terrascale/ts-dashboard" &&
		repository(next) == "ghcr.io/terrascale/terrascale-dashboard"
}

// repository is image without its digest.
func repository(image string) string {
	name, _, _ := strings.Cut(image, "@")
	return name
}

// desiredImages maps every mesh service that runs to its desired image.
func desiredImages(ctx context.Context, conn *nats.Conn) (map[string]string, error) {
	newest, err := desiredStates(ctx, conn)
	if err != nil {
		return nil, err
	}
	images := map[string]string{}
	for name, state := range newest {
		entry := state.entry()
		if entry.Spec != nil {
			images[name] = entry.Spec.Image
		}
	}
	return images, nil
}

// failedAnywhere reports a region whose rollout of name's generation failed.
func failedAnywhere(ctx context.Context, conn *nats.Conn, name string, generation int64) bool {
	if generation <= 0 {
		return false
	}
	failed := false
	_ = collect(ctx, conn, StateSubject, nil, len(Regions()), stateWait, func(data []byte) bool {
		var reply stateReply
		if protocol.DecodeTolerant(data, &reply, maxWire) == nil && reply.Failed[name] == generation {
			failed = true
		}
		return true
	})
	return failed
}

// desiredStates merges both candidates and the floor from every replying region.
func desiredStates(ctx context.Context, conn *nats.Conn) (map[string]desiredState, error) {
	newest := map[string]desiredState{}
	var conflict error
	err := collect(ctx, conn, StateSubject, nil, len(Regions()), stateWait, func(data []byte) bool {
		var reply stateReply
		if protocol.DecodeTolerant(data, &reply, maxWire) == nil {
			for name, entry := range reply.Desired {
				if validState(name, entry) == nil {
					merged, err := mergeState(newest[name], entry)
					if err != nil {
						conflict = errors.Join(conflict, fmt.Errorf("%s: %w", name, err))
					} else {
						newest[name] = merged
					}
				}
			}
		}
		return true
	})
	return newest, errors.Join(err, conflict)
}

// declaredReleasePlacement uses the embedded first-party declaration as the
// authority for all-region placement and packing, rather than a service list.
func declaredReleasePlacement(next *swarmruntime.ServiceSpec, deployment *Deployment) error {
	data, err := m1.Files.ReadFile("services/" + next.Name + ".json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var declared swarmruntime.ServiceSpec
	if err := protocol.DecodeStrict(data, &declared, 64<<10); err != nil {
		return err
	}
	if declared.Name != next.Name || repository(declared.Image) != repository(next.Image) && !dashboardPackageCutover(next.Name, declared.Image, next.Image, deployment) {
		return fmt.Errorf("%s: release declaration identity mismatch", next.Name)
	}
	if len(declared.Regions) == 0 {
		next.Regions = nil
		next.MilliCPU, next.MemoryMiB = declared.MilliCPU, declared.MemoryMiB
		// The declared env listens on the task's own ${PORT}, so the release
		// starts the new task before stopping the old one. Secret references
		// stay the runtime's.
		next.Env = maps.Clone(declared.Env)
	}
	return nil
}
