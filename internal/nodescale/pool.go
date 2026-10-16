package nodescale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"time"

	"encoding/json/v2"
)

// Recipe is everything a pool node is launched from. Its digest names the instance configuration.
// The compartment is the pool's.
type Recipe struct {
	Cell                string // e.g. "gru"
	Capacity            Capacity
	SubnetID            string
	NSGIDs              []string
	AvailabilityDomains []string // one placement configuration each, in this order
	ImageID             string
	OCPUs               float32
	MemoryGB            float32
	Metadata            map[string]string // instance metadata (host descriptor, enrollment bundle, ssh_authorized_keys)
}

var cellPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// Validate refuses a recipe that cannot launch a node.
func (r Recipe) Validate() error {
	if !cellPattern.MatchString(r.Cell) {
		return fmt.Errorf("node cell %q is not a cell name", r.Cell)
	}
	if err := r.Capacity.Validate(); err != nil {
		return err
	}
	if r.SubnetID == "" || r.ImageID == "" {
		return fmt.Errorf("node recipe for cell %s needs a subnet and image", r.Cell)
	}
	if len(r.NSGIDs) == 0 || slices.Contains(r.NSGIDs, "") {
		return fmt.Errorf("node recipe for cell %s needs network security groups", r.Cell)
	}
	if len(r.AvailabilityDomains) == 0 || slices.Contains(r.AvailabilityDomains, "") {
		return fmt.Errorf("node recipe for cell %s needs availability domains", r.Cell)
	}
	if len(r.Metadata) == 0 {
		return fmt.Errorf("node recipe for cell %s needs instance metadata", r.Cell)
	}
	// Written as !(x > 0) so NaN is refused too.
	if !(r.OCPUs > 0) || !(r.MemoryGB > 0) || math.IsInf(float64(r.OCPUs), 0) || math.IsInf(float64(r.MemoryGB), 0) {
		return fmt.Errorf("node recipe for cell %s needs positive finite OCPUs and memory", r.Cell)
	}
	return nil
}

// Digest is the first 12 hex characters of a SHA-256 over the canonical recipe and the launch constants.
// NSG order does not matter; availability domain order does, because it is the placement order.
func (r Recipe) Digest() string { return r.digest(r.Capacity.Shape, BootVolumeGB) }

// digest hashes the recipe as launched with the given shape and boot volume size.
func (r Recipe) digest(shape string, bootVolumeGB int) string {
	canonical := struct {
		Cell                string
		Role                string
		Architecture        string
		SubnetID            string
		NSGIDs              []string
		AvailabilityDomains []string
		ImageID             string
		OCPUs               string // strings: float encoding fails on NaN
		MemoryGB            string
		Metadata            map[string]string
		NodeShape           string
		BootVolumeGB        int
	}{
		Cell:                r.Cell,
		Role:                r.Capacity.Role,
		Architecture:        r.Capacity.Architecture,
		SubnetID:            r.SubnetID,
		NSGIDs:              slices.Sorted(slices.Values(r.NSGIDs)),
		AvailabilityDomains: r.AvailabilityDomains,
		ImageID:             r.ImageID,
		OCPUs:               strconv.FormatFloat(float64(r.OCPUs), 'g', -1, 32),
		MemoryGB:            strconv.FormatFloat(float64(r.MemoryGB), 'g', -1, 32),
		Metadata:            r.Metadata,
		NodeShape:           shape,
		BootVolumeGB:        bootVolumeGB,
	}
	encoded, _ := json.Marshal(canonical, json.Deterministic(true)) // strings, ints and slices only: cannot fail
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])[:12]
}

// PoolName separates pools by isolation role, native architecture and OCI shape.
func PoolName(cell string, capacity Capacity) string { return configPrefix(cell, capacity) + "nodes" }

// ConfigurationName names the instance configuration for one recipe.
func ConfigurationName(r Recipe) string { return configPrefix(r.Cell, r.Capacity) + r.Digest() }

func configPrefix(cell string, capacity Capacity) string {
	return "ts-" + cell + "-" + capacity.Role + "-" + capacity.Architecture + "-" + capacity.Shape + "-"
}

const (
	BootVolumeGB = 50

	// MaxPoolNodes is the most nodes the pool holds, beside the region's 3 quorum nodes.
	MaxPoolNodes = 9
)

// PoolInstance is one live member of the pool.
type PoolInstance struct {
	ID, Name, State, PrivateIP, AvailabilityDomain, FaultDomain string
	Created                                                     time.Time
}

// PoolState is what the pool holds now. Instances exclude terminated ones.
type PoolState struct {
	Exists                                  bool
	PoolID, ConfigurationID, LifecycleState string
	Size                                    int
	Instances                               []PoolInstance // sorted by Name then ID
	Pending                                 string         // observations remain available while mutations are held
}

var ErrCapacityPending = errors.New("node capacity admission is pending")

var ErrPoolChanged = errors.New("instance pool size changed under the leader")
var ErrNotPoolInstance = errors.New("instance is not in this node pool")

// Pool is one region's instance pool of nodes with the same capacity identity.
type Pool interface {
	Observe(ctx context.Context) (PoolState, error)
	Ensure(ctx context.Context, recipe Recipe) (PoolState, error)
	Grow(ctx context.Context, from int) error
	Name(ctx context.Context, instanceID, node string) error
	Remove(ctx context.Context, instanceID string) error
}
