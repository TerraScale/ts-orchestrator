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
func Release(state string) func(ctx context.Context, service, image string, claims releasepush.Claims) (json.RawMessage, error) {
	return func(ctx context.Context, service, image string, claims releasepush.Claims) (json.RawMessage, error) {
		conn, err := Connect(state)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		attempt, _ := strconv.ParseUint(claims.RunAttempt, 10, 64)
		rows, failed := releaseDeployment(ctx, conn, service, image, &Deployment{Repository: claims.Repository, RunID: claims.RunID, RunAttempt: attempt, Revision: claims.SHA, Image: image}, releaseWait, rollbackWait)
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
	return releaseDeployment(ctx, conn, service, image, nil, wait, rollbackWait)
}

func releaseDeployment(ctx context.Context, conn *nats.Conn, service, image string, deployment *Deployment, wait, rollbackWait time.Duration) ([]Reply, error) {
	entries, err := desiredStates(ctx, conn)
	if err != nil {
		return nil, err
	}
	before := entries[service].entry()
	previous := before.Spec
	if err := entries[service].accepts(deployment); err != nil {
		return nil, err
	}
	// The retained signed floor survives rollback and operator changes. Once
	// this run's image is no longer desired, losing the handler's cache must
	// not turn its terminal failure into a fresh attempt with a new generation.
	if deployment != nil && entries[service].Floor != nil && *entries[service].Floor == *deployment && (before.RollbackOf != 0 || previous == nil || previous.Image != image) {
		return nil, fmt.Errorf("%s: signed deployment was rolled back or replaced; retry requires a newer signed run", service)
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
	// A new signed release adopts the all-region declaration's placement and
	// budgets, without replacing runtime credentials, routes or other fields.
	// Holds retain their placement/order and budgets until explicitly resumed.
	if deployment != nil && before.HoldAfter == "" {
		if err := declaredReleasePlacement(&next); err != nil {
			return nil, err
		}
	}
	generation := max(time.Now().UnixNano(), before.Generation+1)
	// A signed release does not inherit a canary hold: every region already
	// waits for the earlier regions' successful bakes, and a hold left behind
	// kept TerraBase's fix out of sjc and fra. Its placement stays as held.
	// An unsigned apply of a held service stays held until `service resume`.
	hold := before.HoldAfter
	if deployment != nil {
		hold = ""
	}
	request := ApplyRequest{Name: service, Entry: Entry{Generation: generation, Spec: &next, Deployment: deployment, HoldAfter: hold}}
	// A reconnect or process restart resumes the signed deployment's existing
	// bake instead of publishing a fresh generation and restarting its window.
	// A failed bake is not resumed: a retry bakes a fresh generation, rather
	// than replaying a verdict a since-recovered dependency caused.
	if deployment != nil && before.Deployment != nil && *before.Deployment == *deployment && previous != nil && previous.Image == image &&
		!failedAnywhere(ctx, conn, service, before.Generation) {
		generation = before.Generation
		request.Entry = before
	}
	rows, failed := send(ctx, conn, request, max(wait, rolloutWait(&next)))
	if failed == nil || bakeHeld(rows, service) {
		return rows, failed
	}
	if current, err := desiredStates(ctx, conn); err != nil || current[service].entry().Generation != generation {
		return rows, errors.Join(failed, errors.New("not rolled back: a newer release replaced it"), err)
	}
	back, err := send(ctx, conn, ApplyRequest{Name: service, ExpectedGeneration: generation, Entry: Entry{Generation: max(time.Now().UnixNano(), generation+1), Spec: previous, Deployment: deployment, HoldAfter: entries[service].entry().HoldAfter}}, max(rollbackWait, regionWindow(previous)))
	target := "absence"
	if previous != nil {
		target = previous.Image
	}
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
	failed := false
	_ = collect(ctx, conn, StateSubject, nil, len(Regions()), stateWait, func(data []byte) bool {
		var reply stateReply
		if protocol.DecodeTolerant(data, &reply, maxWire) == nil && (reply.Failed[name] >= generation || reply.Excused[name] >= generation) {
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
func declaredReleasePlacement(next *swarmruntime.ServiceSpec) error {
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
	if declared.Name != next.Name || repository(declared.Image) != repository(next.Image) {
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
