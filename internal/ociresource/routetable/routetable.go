// Package routetable reconciles the static route rules of one owned OCI
// route table against a desired rule set.
//
// OCI replaces a route table's rules as a whole, so a spec owns every static
// rule of its table. The table must already carry the controller's ownership
// tags for the desired key; otherwise it is foreign and nothing is changed.
// The reconciler never creates or deletes the table, and a tombstone
// relinquishes management without touching the routes.
package routetable

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
)

// Kind is the desired-state kind for route table rule sets.
const Kind = "route-table-rules"

// maxRules is OCI's limit of route rules per route table.
const maxRules = 200

const (
	DestinationCIDR    = "CIDR_BLOCK"
	DestinationService = "SERVICE_CIDR_BLOCK"
	// RouteTypeLocal marks a rule OCI generates for VCN-local traffic. It is
	// never sent in an update and never compared.
	RouteTypeLocal = "LOCAL"
)

// Route is one normalized static route rule.
type Route struct {
	Destination     string `json:"destination"`
	DestinationType string `json:"destinationType,omitempty"`
	NetworkEntityID string `json:"networkEntityId"`
	Description     string `json:"description,omitempty"`
}

func (r Route) destinationType() string { return cmp.Or(r.DestinationType, DestinationCIDR) }

// identity is the route's semantic tuple; descriptions do not affect matching.
func (r Route) identity() string {
	return r.destinationType() + "|" + r.Destination + "|" + r.NetworkEntityID
}

func (r Route) validate() error {
	switch r.destinationType() {
	case DestinationCIDR:
		prefix, err := netip.ParsePrefix(r.Destination)
		if err != nil {
			return fmt.Errorf("route destination %q is invalid", r.Destination)
		}
		if canonical := prefix.Masked().String(); canonical != r.Destination {
			return fmt.Errorf("route destination %q is not canonical; use %q", r.Destination, canonical)
		}
	case DestinationService:
		if r.Destination == "" || len(r.Destination) > 255 {
			return errors.New("route service destination is invalid")
		}
	default:
		return fmt.Errorf("route destination type %q is unsupported", r.DestinationType)
	}
	if !strings.HasPrefix(r.NetworkEntityID, "ocid1.") || len(r.NetworkEntityID) > 255 ||
		strings.ContainsAny(r.NetworkEntityID, " \t\r\n") {
		return errors.New("route target is not an OCID")
	}
	if len(r.Description) > 255 {
		return errors.New("route description is too long")
	}
	return nil
}

// Spec is the desired static rule set of one route table.
type Spec struct {
	RouteTableID string  `json:"routeTableId"`
	Routes       []Route `json:"routes"`
	// AllowEmpty must be set to enforce a table without routes.
	AllowEmpty bool `json:"allowEmpty,omitempty"`
}

// Validate rejects malformed or overlapping routes.
func (s Spec) Validate() error {
	if !strings.HasPrefix(s.RouteTableID, "ocid1.routetable.") {
		return errors.New("route table spec requires a route table OCID")
	}
	if len(s.Routes) > maxRules {
		return fmt.Errorf("route table spec has %d routes, more than OCI's %d", len(s.Routes), maxRules)
	}
	if len(s.Routes) == 0 && !s.AllowEmpty {
		return errors.New("route table spec has no routes without allowEmpty")
	}
	destinations := map[string]bool{}
	for _, route := range s.Routes {
		if err := route.validate(); err != nil {
			return err
		}
		// OCI refuses two rules for one destination; so does the spec.
		destination := route.destinationType() + "|" + route.Destination
		if destinations[destination] {
			return fmt.Errorf("route table spec repeats destination %s", route.Destination)
		}
		destinations[destination] = true
	}
	return nil
}

// Table is an observed route table. Routes holds only static rules.
type Table struct {
	ID     string
	ETag   string
	Tags   ociresource.Tags
	Routes []Route
}

// API is the narrow OCI seam.
type API interface {
	GetTable(ctx context.Context, id string) (Table, error)
	// UpdateTable replaces every static route and the tags under If-Match.
	UpdateTable(ctx context.Context, id, etag string, routes []Route, tags ociresource.Tags) error
}

// Reconciler is the ociresource.Resource for route table rule sets.
type Reconciler struct{ API API }

var _ ociresource.Resource[Spec, Table] = Reconciler{}

func (Reconciler) Kind() string { return Kind }

func (r Reconciler) Observe(ctx context.Context, target ociresource.Target[Spec]) (Table, bool, error) {
	if err := target.Spec.Validate(); err != nil {
		return Table{}, false, err
	}
	if target.Deleting {
		// Deletion relinquishes management and never strips the routes.
		return Table{}, false, nil
	}
	table, err := r.API.GetTable(ctx, target.Spec.RouteTableID)
	if err != nil {
		return Table{}, false, err
	}
	if table.ID != target.Spec.RouteTableID || !target.Ownership.Owns(target.Key, table.Tags) {
		return Table{}, true, ociresource.ErrForeign
	}
	return table, true, nil
}

func identities(routes []Route) []string {
	out := make([]string, 0, len(routes))
	for _, route := range routes {
		out = append(out, route.identity())
	}
	slices.Sort(out)
	return out
}

func (Reconciler) Diff(target ociresource.Target[Spec], observed Table, found bool) ociresource.Plan {
	var plan ociresource.Plan
	if !found {
		plan.Add("blocked", "route table %s is not visible", target.Spec.RouteTableID)
		return plan
	}
	want, have := identities(target.Spec.Routes), identities(observed.Routes)
	for _, identity := range want {
		if _, ok := slices.BinarySearch(have, identity); !ok {
			plan.Add("add-route", "%s", identity)
		}
	}
	for index, identity := range have {
		if _, ok := slices.BinarySearch(want, identity); !ok || index > 0 && have[index-1] == identity {
			plan.Add("remove-route", "%s", identity)
		}
	}
	if target.Ownership.Stale(observed.Tags, target.Generation, target.SpecDigest) {
		plan.Add("tag", "restamp ownership generation %d", target.Generation)
	}
	return plan
}

// Apply writes the desired routes and restamped tags in one If-Match update.
func (r Reconciler) Apply(ctx context.Context, target ociresource.Target[Spec], observed Table, found bool, _ ociresource.Plan) error {
	if !found {
		return fmt.Errorf("route table %s is not visible; the reconciler never creates tables", target.Spec.RouteTableID)
	}
	if observed.ETag == "" {
		return errors.New("route table has no ETag; refusing an unconditional replace")
	}
	tags := observed.Tags.Merge(target.Ownership.Stamp(target.Key, target.Generation, target.SpecDigest))
	if err := target.Fence(ctx); err != nil {
		return err
	}
	if err := r.API.UpdateTable(ctx, target.Spec.RouteTableID, observed.ETag, slices.Clone(target.Spec.Routes), tags); err != nil {
		return fmt.Errorf("replace route table rules: %w", err)
	}
	return nil
}

// Delete is never reached: Observe reports a tombstoned table as not found.
func (Reconciler) Delete(context.Context, ociresource.Target[Spec], Table) error { return nil }
