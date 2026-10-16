package host

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// ListDesired reads all committed host allocations from the ordered control
// log, including pending and withdrawn targets. An empty role selects all.
func (c *Controller) ListDesired(ctx context.Context, role string) ([]Desired, error) {
	if c == nil || c.controlLog == nil || c.mutations == nil {
		return nil, errors.New("ordered host state reader is unavailable")
	}
	if role != "" {
		if err := validateToken(role, "role"); err != nil {
			return nil, err
		}
	}
	prefix := protocol.Control(c.cell, "host", "desired", c.cell) + "."
	filter := prefix + ">"
	if role != "" {
		filter = prefix + "*." + role
	}
	info, err := c.controlLogSubjects(ctx, filter)
	if err != nil {
		return nil, err
	}
	var result []Desired
	for subject := range info.State.Subjects {
		suffix, ok := strings.CutPrefix(subject, prefix)
		if !ok {
			return nil, errors.New("desired log subject has unexpected prefix")
		}
		node, roleName, ok := strings.Cut(suffix, ".")
		if !ok || validateToken(node, "node") != nil || validateToken(roleName, "role") != nil || strings.Contains(roleName, ".") {
			return nil, errors.New("desired log subject is malformed")
		}
		if role != "" && roleName != role {
			continue
		}
		d, revision, exists, err := c.readDesired(ctx, node, roleName)
		if err != nil {
			return nil, err
		}
		if !exists || revision == 0 {
			return nil, errors.New("desired log index is inconsistent")
		}
		result = append(result, d)
	}
	slices.SortFunc(result, func(a, b Desired) int {
		if a.Node < b.Node {
			return -1
		}
		if a.Node > b.Node {
			return 1
		}
		return strings.Compare(a.Role, b.Role)
	})
	return result, nil
}

func (r *Reader) ListDesired(ctx context.Context, role string) ([]Desired, error) {
	return r.controller.ListDesired(ctx, role)
}
