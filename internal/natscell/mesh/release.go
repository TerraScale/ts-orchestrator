package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
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
func Release(state string) func(ctx context.Context, service, image string) (json.RawMessage, error) {
	return func(ctx context.Context, service, image string) (json.RawMessage, error) {
		conn, err := Connect(state)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		rows, failed := release(ctx, conn, service, image, releaseWait, rollbackWait)
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
	previous, err := desiredSpec(ctx, conn, service)
	if err != nil {
		return nil, err
	}
	if repository(previous.Image) != repository(image) {
		return nil, fmt.Errorf("%s runs %s; a release may change only its digest", service, repository(previous.Image))
	}
	next := *previous
	next.Image = image
	rows, failed := applySpec(ctx, conn, next, wait)
	if failed == nil {
		return rows, nil
	}
	if current, err := desiredSpec(ctx, conn, service); err != nil || current.Image != image {
		return rows, errors.Join(failed, errors.New("not rolled back: a newer release replaced it"), err)
	}
	back, err := applySpec(ctx, conn, *previous, rollbackWait)
	if err != nil {
		return append(rows, back...), errors.Join(failed, fmt.Errorf("rollback to %s: %w", previous.Image, err))
	}
	return append(rows, back...), errors.Join(failed, errors.New("rolled back to "+previous.Image))
}

// desiredSpec is service's newest desired spec among the regions that answer.
func desiredSpec(ctx context.Context, conn *nats.Conn, service string) (*swarmruntime.ServiceSpec, error) {
	newest, err := desiredEntries(ctx, conn)
	if err != nil {
		return nil, err
	}
	if newest[service].Spec == nil {
		return nil, fmt.Errorf("%s is not a mesh service; apply its deploy/m1/services spec once with `ts-orch service apply -f`", service)
	}
	return newest[service].Spec, nil
}

// repository is image without its digest.
func repository(image string) string {
	name, _, _ := strings.Cut(image, "@")
	return name
}

// desiredImages maps every mesh service that runs to its desired image.
func desiredImages(ctx context.Context, conn *nats.Conn) (map[string]string, error) {
	newest, err := desiredEntries(ctx, conn)
	if err != nil {
		return nil, err
	}
	images := map[string]string{}
	for name, entry := range newest {
		if entry.Spec != nil {
			images[name] = entry.Spec.Image
		}
	}
	return images, nil
}

// desiredEntries is each service's newest entry among the regions that answer.
func desiredEntries(ctx context.Context, conn *nats.Conn) (map[string]Entry, error) {
	newest := map[string]Entry{}
	err := collect(ctx, conn, StateSubject, nil, len(Regions()), stateWait, func(data []byte) bool {
		var reply stateReply
		if protocol.DecodeTolerant(data, &reply, maxWire) == nil {
			for name, entry := range reply.Desired {
				if entry.Generation > newest[name].Generation {
					newest[name] = entry
				}
			}
		}
		return true
	})
	return newest, err
}
