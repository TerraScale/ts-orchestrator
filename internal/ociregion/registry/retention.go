package registry

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/artifacts"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// Pins is the complete admitted current/rollback/live-task inventory for this
// repository. Children must contain an entry for every reachable digest,
// including leaves with no children. Producers pin before admitting or starting.
type Pins struct {
	Generation uint64              `json:"generation"`
	ObservedAt time.Time           `json:"observed_at"`
	Current    []string            `json:"current,omitempty"`
	Rollback   []string            `json:"rollback,omitempty"`
	Tasks      []string            `json:"tasks,omitempty"`
	Children   map[string][]string `json:"children"`
}

func validDigest(digest string) bool {
	sum, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(sum) != 64 || strings.ToLower(sum) != sum {
		return false
	}
	_, err := hex.DecodeString(sum)
	return err == nil
}

func (pins Pins) retained(now time.Time) (map[string]bool, error) {
	if pins.Generation == 0 || pins.Children == nil || pins.ObservedAt.IsZero() ||
		now.Sub(pins.ObservedAt) > 2*time.Minute || pins.ObservedAt.Sub(now) > 30*time.Second {
		return nil, ErrPins
	}
	keep := map[string]bool{}
	queue := append(append(append([]string{}, pins.Current...), pins.Rollback...), pins.Tasks...)
	for len(queue) > 0 {
		digest := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if keep[digest] {
			continue
		}
		children, ok := pins.Children[digest]
		if !validDigest(digest) || !ok || len(keep) >= 4096 {
			return nil, ErrPins
		}
		keep[digest] = true
		queue = append(queue, children...)
	}
	return keep, nil
}

// SetPins serializes a complete inventory with retirement claims in the same KV
// record. A claimed digest cannot be admitted again, including after restart.
// Missing collectors must return an error rather than publishing an empty inventory.
func (c *Controller) SetPins(ctx context.Context, repository Repository, pins Pins) error {
	keep, err := pins.retained(time.Now())
	if err != nil {
		return err
	}
	state, err := c.load(ctx, repository)
	if err != nil {
		return err
	}
	if state.RepositoryID == "" || pins.Generation <= state.Pins.Generation {
		return ErrPins
	}
	for digest := range keep {
		if state.Images[digest].Retiring != "" {
			return fmt.Errorf("%w: %s", ErrRetiring, digest)
		}
	}
	state.Pins = pins
	return c.save(ctx, state)
}

// RememberImage records the exact OCID/digest pair after release admission.
// Arbitrary images discovered by OCI list APIs are never retirement candidates.
func (c *Controller) RememberImage(ctx context.Context, repository Repository, id, digest string) error {
	if id == "" || !validDigest(digest) {
		return errors.New("invalid admitted OCIR image")
	}
	state, err := c.load(ctx, repository)
	if err != nil {
		return err
	}
	response, err := c.client.GetContainerImage(ctx, artifacts.GetContainerImageRequest{ImageId: new(id)})
	if err != nil {
		return err
	}
	if state.RepositoryID == "" || text(response.Id) != id || text(response.Digest) != digest ||
		text(response.RepositoryId) != state.RepositoryID || text(response.CompartmentId) != repository.CompartmentID ||
		text(response.RepositoryName) != repository.Name || response.LifecycleState != artifacts.ContainerImageLifecycleStateAvailable {
		return ErrOwnership
	}
	if previous, ok := state.Images[digest]; ok {
		if previous.ID != id {
			return ErrOwnership
		}
		if previous.Retiring != "" {
			return ErrRetiring
		}
		return nil
	}
	state.Images[digest] = imageRecord{ID: id, RecordedAt: time.Now().UTC()}
	return c.save(ctx, state)
}

// Collect returns digests whose retirement OCI accepted, keeping the full dependency
// closure of current releases, rollbacks and live tasks. New admissions retain
// a one-hour grace period. Unknown OCI objects and incomplete inventories stay.
func (c *Controller) Collect(ctx context.Context, repository Repository) ([]string, error) {
	if _, err := c.Ensure(ctx, repository); err != nil {
		return nil, err
	}
	state, err := c.load(ctx, repository)
	if err != nil {
		return nil, err
	}
	keep, err := state.Pins.retained(time.Now())
	if err != nil {
		return nil, err
	}
	var deleted []string
	for digest, image := range state.Images {
		if keep[digest] || image.RecordedAt.IsZero() || time.Since(image.RecordedAt) < time.Hour {
			continue
		}
		requested, err := c.retire(ctx, repository, digest)
		if err != nil {
			return deleted, err
		}
		if requested {
			deleted = append(deleted, digest)
		}
	}
	return deleted, nil
}

func (c *Controller) retire(ctx context.Context, repository Repository, digest string) (bool, error) {
	state, err := c.load(ctx, repository)
	if err != nil {
		return false, err
	}
	keep, err := state.Pins.retained(time.Now())
	if err != nil {
		return false, err
	}
	image := state.Images[digest]
	if keep[digest] {
		return false, nil
	}
	if image.ID == "" || time.Since(image.RecordedAt) < time.Hour {
		return false, ErrPins
	}
	if image.Retiring == "" {
		image.Retiring = common.RetryToken()
		state.Images[digest] = image
		// This CAS conflicts with a new pin, or permanently excludes a later pin.
		if err := c.save(ctx, state); err != nil {
			return false, err
		}
	}
	response, err := c.client.GetContainerImage(ctx, artifacts.GetContainerImageRequest{ImageId: new(image.ID)})
	if serviceErr, ok := common.IsServiceError(err); ok && serviceErr.GetHTTPStatusCode() == 404 {
		// Absence is ambiguous in OCI (also permission loss); retain the journal tombstone.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if text(response.Id) != image.ID || text(response.Digest) != digest || text(response.RepositoryId) != state.RepositoryID ||
		text(response.CompartmentId) != repository.CompartmentID || text(response.RepositoryName) != repository.Name {
		return false, ErrOwnership
	}
	if response.LifecycleState == artifacts.ContainerImageLifecycleStateDeleting || response.LifecycleState == artifacts.ContainerImageLifecycleStateDeleted {
		return false, nil
	}
	if response.LifecycleState != artifacts.ContainerImageLifecycleStateAvailable || text(response.Etag) == "" {
		return false, ErrOwnership
	}
	if err := c.guard(ctx); err != nil {
		return false, err
	}
	_, err = c.client.DeleteContainerImage(ctx, artifacts.DeleteContainerImageRequest{ImageId: new(image.ID), IfMatch: response.Etag,
		OpcRequestId: new(image.Retiring)})
	return err == nil, err
}
