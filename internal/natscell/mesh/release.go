package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats.go"
)

const (
	// releaseWait is how long every targeted region has to run the new image
	// and answer its ready path before the release rolls back.
	releaseWait = 70 * time.Second
	// releaseWait, rollbackWait and two state reads (3 s each) fit in the
	// release handler's 2 min; the previous image is already on every host.
	rollbackWait = 40 * time.Second
)

// Release serves app image releases (releasepush.Handler.App) on this host's
// mesh node: it swaps service's image in its desired spec for every region.
func Release(state string) func(ctx context.Context, service, image string, claims releasepush.Claims) (json.RawMessage, error) {
	return func(ctx context.Context, service, image string, claims releasepush.Claims) (json.RawMessage, error) {
		conn, err := Connect(state)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		rows, failed := releaseDeployment(ctx, conn, service, image, &Deployment{Repository: claims.Repository, RunID: claims.RunID, Revision: claims.SHA, Image: image}, releaseWait, rollbackWait)
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
	previous := entries[service].entry().Spec
	if previous == nil {
		return nil, fmt.Errorf("%s is not a mesh service", service)
	}
	if err := entries[service].Floor.Accepts(deployment); err != nil {
		return nil, err
	}
	if repository(previous.Image) != repository(image) {
		return nil, fmt.Errorf("%s runs %s; a release may change only its digest", service, repository(previous.Image))
	}
	next := *previous
	next.Image = image
	generation := max(time.Now().UnixNano(), entries[service].entry().Generation+1)
	request := ApplyRequest{Name: service, Entry: Entry{Generation: generation, Spec: &next, Deployment: deployment}}
	rows, failed := send(ctx, conn, request, max(wait, rolloutWait(&next)))
	if failed == nil {
		return rows, nil
	}
	if current, err := desiredStates(ctx, conn); err != nil || current[service].entry().Generation != generation {
		return rows, errors.Join(failed, errors.New("not rolled back: a newer release replaced it"), err)
	}
	back, err := send(ctx, conn, ApplyRequest{Name: service, ExpectedGeneration: generation, Entry: Entry{Generation: max(time.Now().UnixNano(), generation+1), Spec: previous, Deployment: deployment}}, max(rollbackWait, regionWindow(previous)))
	if err != nil {
		return append(rows, back...), errors.Join(failed, fmt.Errorf("rollback to %s: %w", previous.Image, err))
	}
	return append(rows, back...), errors.Join(failed, errors.New("rolled back to "+previous.Image))
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
