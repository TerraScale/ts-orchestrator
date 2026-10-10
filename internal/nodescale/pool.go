package nodescale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"encoding/json/v2"
)

// Recipe is everything a pool node is launched from. Its digest names the instance configuration.
type Recipe struct {
	Cell                string // e.g. "gru"
	CompartmentID       string
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
	if r.CompartmentID == "" || r.SubnetID == "" || r.ImageID == "" {
		return fmt.Errorf("node recipe for cell %s needs a compartment, subnet and image", r.Cell)
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
	if !(r.OCPUs > 0) || !(r.MemoryGB > 0) {
		return fmt.Errorf("node recipe for cell %s needs positive OCPUs and memory", r.Cell)
	}
	return nil
}

// Digest is the first 12 hex characters of a SHA-256 over the canonical recipe.
// NSG order does not matter; availability domain order does, because it is the placement order.
func (r Recipe) Digest() string {
	canonical := struct {
		Cell                string
		CompartmentID       string
		SubnetID            string
		NSGIDs              []string
		AvailabilityDomains []string
		ImageID             string
		OCPUs               string // strings: float encoding fails on NaN
		MemoryGB            string
		Metadata            map[string]string
	}{
		Cell:                r.Cell,
		CompartmentID:       r.CompartmentID,
		SubnetID:            r.SubnetID,
		NSGIDs:              slices.Sorted(slices.Values(r.NSGIDs)),
		AvailabilityDomains: r.AvailabilityDomains,
		ImageID:             r.ImageID,
		OCPUs:               strconv.FormatFloat(float64(r.OCPUs), 'g', -1, 32),
		MemoryGB:            strconv.FormatFloat(float64(r.MemoryGB), 'g', -1, 32),
		Metadata:            r.Metadata,
	}
	encoded, _ := json.Marshal(canonical, json.Deterministic(true)) // strings and slices only: cannot fail
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])[:12]
}

// PoolName is the cell's one instance pool.
func PoolName(cell string) string { return "ts-" + cell + "-nodes" }

// ConfigurationName names the instance configuration for one recipe.
func ConfigurationName(r Recipe) string { return configPrefix(r.Cell) + r.Digest() }

func configPrefix(cell string) string { return "ts-" + cell + "-node-" }

const (
	NodeShape    = "VM.Standard.A1.Flex"
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
}

var ErrPoolChanged = errors.New("instance pool size changed under the leader")
var ErrNotPoolInstance = errors.New("instance is not in this region's node pool")

// Pool is one region's instance pool of pool nodes.
type Pool interface {
	Observe(ctx context.Context) (PoolState, error)
	Ensure(ctx context.Context, recipe Recipe) (PoolState, error)
	Grow(ctx context.Context, from int) error
	Name(ctx context.Context, instanceID, node string) error
	Remove(ctx context.Context, instanceID string) error
}
