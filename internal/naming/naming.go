// Package naming is the one naming scheme for a regional cell's servers and
// the OCI, NetBird, NATS and DNS names given to them. A cell is
// <region>-<index> (gru-1), where region is a catalog cell code in lower case
// and index and n count from 1.
//
// A node is ts-<region>-<n> (ts-gru-1, ts-sfo-2), with no role in the name:
// every node runs the colocated controller, TerraBase member and ts-auth
// (TS-609). Its retained data volume adds -data (ts-gru-1-data).
//
// Servers named before TS-609 keep their names until renamed and stay valid:
// <cell>-<role>-<n> (gru-1-ctl-1, gru-1-db-2, gru-1-gw-1), a member's data
// volume <cell>-db-<n>-data, and a node pool's host <cell>-pool-<pool>-<n>
// (gru-1-pool-app-3).
//
// Names never carry a release, deployment ID, date, generation or digest, so
// they stay the same across rollouts and replacements. That identity belongs
// in tags and launch metadata.
package naming

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Server roles.
const (
	Controller = "ctl"
	Member     = "db"
	Gateway    = "gw"
)

// ErrName reports a name outside the scheme.
var ErrName = errors.New("name does not follow ts-<region>-<n>[-data], <region>-<index>[-<role>-<n>[-data]] or <region>-<index>-pool-<pool>-<n>")

var scheme = regexp.MustCompile(`^([a-z]+)-[1-9][0-9]{0,2}(?:-(?:ctl|gw)-[1-9][0-9]{0,2}|-db-[1-9][0-9]{0,2}(?:-data)?|` +
	`-pool-[a-z][a-z0-9]{1,11}-[1-9][0-9]{0,2})?$`)

var nodeScheme = regexp.MustCompile(`^ts-([a-z]+)-[1-9][0-9]{0,2}(?:-data)?$`)

var apiPart = regexp.MustCompile(`^[a-z]+$`)

// Cell is one region's cell.
type Cell struct {
	Region string // catalog cell code, e.g. GRU
	Index  int
}

// RegionCell returns the cell a region runs. Every region runs one cell
// today, cell 1.
func RegionCell(region string) Cell { return Cell{Region: region, Index: 1} }

// Name returns the cell name, e.g. gru-1.
func (c Cell) Name() (string, error) {
	return valid(fmt.Sprintf("%s-%d", strings.ToLower(c.Region), c.Index))
}

// Image returns the name of the cell's qualified ARM64 host image, e.g.
// gru-1-arm64. A new image import reuses the name; the source revision and
// digest belong in its signed receipt.
func (c Cell) Image() (string, error) {
	name, err := c.Name()
	if err != nil {
		return "", err
	}
	return name + "-arm64", nil
}

// Node returns the name of the region's n-th node, e.g. ts-gru-1.
func (c Cell) Node(n int) (string, error) {
	return valid(fmt.Sprintf("ts-%s-%d", strings.ToLower(c.Region), n))
}

// Server returns the name of the cell's n-th server of role, e.g. gru-1-ctl-1.
func (c Cell) Server(role string, n int) (string, error) {
	return valid(fmt.Sprintf("%s-%d-%s-%d", strings.ToLower(c.Region), c.Index, role, n))
}

// PoolServer returns the name of the n-th host of a node pool, e.g.
// gru-1-pool-app-3. A pool name is 2 to 12 lower-case letters and digits,
// starting with a letter.
func (c Cell) PoolServer(pool string, n int) (string, error) {
	return valid(fmt.Sprintf("%s-%d-pool-%s-%d", strings.ToLower(c.Region), c.Index, pool, n))
}

// ControllerSlot returns the server name of a signed controller slot:
// controller-a, -b and -c are the region's nodes 1, 2 and 3 (ts-sfo-1). GRU
// keeps ctl-1, -2 and -3 (gru-1-ctl-1) until its servers are renamed: a
// controller refuses a NATS store of another server name.
func (c Cell) ControllerSlot(slot string) (string, error) {
	if strings.ToUpper(c.Region) == catalog.GRU {
		return c.slot(slot, "controller-", Controller)
	}
	letter, ok := strings.CutPrefix(slot, "controller-")
	if !ok || len(letter) != 1 || letter[0] < 'a' || letter[0] > 'z' {
		return "", fmt.Errorf("%w: controller-slot %q", ErrName, slot)
	}
	return c.Node(int(letter[0]-'a') + 1)
}

// MemberSlot returns the server name of a regional plan's database host
// slot: member-a and -b are db-1 and -2.
func (c Cell) MemberSlot(slot string) (string, error) { return c.slot(slot, "member-", Member) }

func (c Cell) slot(slot, prefix, role string) (string, error) {
	letter, ok := strings.CutPrefix(slot, prefix)
	if !ok || len(letter) != 1 || letter[0] < 'a' || letter[0] > 'z' {
		return "", fmt.Errorf("%w: %sslot %q", ErrName, prefix, slot)
	}
	return c.Server(role, int(letter[0]-'a')+1)
}

// API returns the name of the cell's public API load balancer, e.g.
// gru-1-api, or with a part, of one of its resources, e.g. gru-1-api-subnet.
func (c Cell) API(part string) (string, error) {
	name, err := c.Name()
	if err != nil {
		return "", err
	}
	if part == "" {
		return name + "-api", nil
	}
	if !apiPart.MatchString(part) {
		return "", fmt.Errorf("%w: API part %q", ErrName, part)
	}
	return name + "-api-" + part, nil
}

// Data returns the name of a member's retained data volume, e.g. ts-gru-1-data.
func Data(member string) (string, error) { return valid(member + "-data") }

// Validate accepts only a cell, node, server or data volume name of the
// scheme in a catalog region.
func Validate(name string) error {
	match := nodeScheme.FindStringSubmatch(name)
	if match == nil {
		match = scheme.FindStringSubmatch(name)
	}
	if match == nil || !catalog.IsCell(strings.ToUpper(match[1])) {
		return fmt.Errorf("%w: %q", ErrName, name)
	}
	return nil
}

// IsNode reports whether name is a node of region, ts-<region>-<n> (not its
// data volume).
func IsNode(name, region string) bool {
	match := nodeScheme.FindStringSubmatch(name)
	return match != nil && match[1] == strings.ToLower(region) && !strings.HasSuffix(name, "-data") &&
		catalog.IsCell(strings.ToUpper(region))
}

// NATSServer is a NATS server name: a catalog cell's controller slot gets its
// server name (gru-1-ctl-1); lab cells and instances outside the scheme keep
// <cell>-<instance>.
func NATSServer(cell, instance string) string {
	if name, err := RegionCell(cell).ControllerSlot(instance); err == nil {
		return name
	}
	return cell + "-" + instance
}

func valid(name string) (string, error) {
	if err := Validate(name); err != nil {
		return "", err
	}
	return name, nil
}
