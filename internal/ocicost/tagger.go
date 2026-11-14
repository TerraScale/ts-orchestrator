package ocicost

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// TagAPI lists a region's resources and stamps freeform tags on one.
type TagAPI interface {
	Resources(ctx context.Context) ([]Resource, error)
	// Retag merges tags into the resource's freeform tags. It returns
	// ErrChanged when the resource changed between its read and the update,
	// and ErrNotPermitted when the principal may not update it.
	Retag(ctx context.Context, resource Resource, tags map[string]string) error
}

var (
	ErrChanged      = errors.New("OCI resource changed during the tag pass")
	ErrNotPermitted = errors.New("not permitted to tag the OCI resource")
)

// TagResult counts one pass.
type TagResult struct {
	Stamped, Changed, NotPermitted, Untagged int
}

// passTimeout bounds one pass over every resource in the region.
const passTimeout = 10 * time.Minute

// applyStamps retags each planned resource. A resource that changed or that
// the principal may not update is counted, not fatal; any other error stops
// the pass with the counts so far.
func applyStamps(ctx context.Context, api TagAPI, stamps []Stamp) (TagResult, error) {
	var result TagResult
	for _, stamp := range stamps {
		switch err := api.Retag(ctx, stamp.Resource, stamp.Tags); {
		case errors.Is(err, ErrChanged):
			result.Changed++
		case errors.Is(err, ErrNotPermitted):
			result.NotPermitted++
		case err != nil:
			return result, fmt.Errorf("tag OCI %s %s: %w", stamp.Resource.Type, stamp.Resource.Name, err)
		default:
			result.Stamped++
		}
	}
	return result, nil
}
