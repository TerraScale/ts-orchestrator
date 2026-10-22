package hostnetwork

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

const usage = `Usage: ts-orch oci-region network CELL [--apply]

Converges CELL's static-host network: VCN, internet and service gateways,
public and private route tables and subnets, empty subnet security lists and
the role NSGs on the host's VNIC. Same-named resources are adopted and
tagged; missing ones are created. Without --apply it only prints the drift.
`

// Run is `ts-orch oci-region network`.
func Run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("oci-region network", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { io.WriteString(out, usage) }
	apply := fs.Bool("apply", false, "make the changes; without it, only print them")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	cell := fs.Arg(0)
	// Flags may also follow CELL.
	if fs.NArg() > 0 {
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return err
		}
	}
	if cell == "" || fs.NArg() != 0 {
		return errors.New("usage: ts-orch oci-region network CELL [--apply]")
	}
	changes, err := Converge(ctx, cell, *apply, out)
	if err != nil {
		return err
	}
	switch {
	case changes == 0:
		_, err = fmt.Fprintf(out, "%s network converged: no drift\n", cell)
	case !*apply:
		_, err = fmt.Fprintf(out, "%d changes planned; rerun with --apply to make them\n", changes)
	default:
		_, err = fmt.Fprintf(out, "%d changes applied\n", changes)
	}
	return err
}

// Converge plans (apply false) or makes CELL's network changes, printing one
// line per change to out, and returns how many there were.
func Converge(ctx context.Context, cell string, apply bool, out io.Writer) (int, error) {
	s, err := desired(cell)
	if err != nil {
		return 0, err
	}
	factory, err := ociclient.OperatorConfig(s.region)
	if err != nil {
		return 0, err
	}
	r := &reconciler{ctx: ctx, s: s, apply: apply, out: out}
	if r.net, err = factory.Network(); err != nil {
		return 0, err
	}
	if r.compute, err = factory.Compute(); err != nil {
		return 0, err
	}
	ids, err := factory.Identity()
	if err != nil {
		return 0, err
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil {
		return 0, err
	}
	c, err := ids.ListCompartments(ctx, identity.ListCompartmentsRequest{CompartmentId: &tenancy, Name: &s.compartment,
		CompartmentIdInSubtree: new(true), AccessLevel: identity.ListCompartmentsAccessLevelAccessible})
	if err != nil {
		return 0, err
	}
	if len(c.Items) != 1 {
		return 0, fmt.Errorf("want one compartment %s, found %d", s.compartment, len(c.Items))
	}
	r.compartment = *c.Items[0].Id
	err = r.reconcile()
	return r.changes, err
}

type reconciler struct {
	ctx         context.Context
	net         core.VirtualNetworkClient
	compute     core.ComputeClient
	s           spec
	apply       bool
	out         io.Writer
	changes     int
	compartment string
}

// step reports one change and makes it with --apply.
func (r *reconciler) step(what string, do func() error) error {
	r.changes++
	if !r.apply {
		_, err := fmt.Fprintln(r.out, "plan: "+what)
		return err
	}
	if err := do(); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	_, err := fmt.Fprintln(r.out, "done: "+what)
	return err
}

// tags returns the freeform tags proving ts-orch owns kind/name, or nil when
// live already carries them. A resource another owner claims is refused.
func (r *reconciler) tags(kind, name string, live map[string]string) (map[string]string, error) {
	key := ociresource.Key{Region: r.s.code, Kind: kind, Name: name}
	owner := ociresource.Ownership{Owner: "terrascale"}
	if owner.Owns(key, ociresource.Tags{Freeform: live}) {
		return nil, nil
	}
	// OCI copies the VCN's tags onto its default route table and security
	// list, so a claim for this cell's VCN is ours to re-key.
	inherited := owner.Owns(ociresource.Key{Region: r.s.code, Kind: "vcn", Name: "vcn"}, ociresource.Tags{Freeform: live})
	if !inherited && (live["terrascale-managed-by"] != "" || live["terrascale-resource-key"] != "") {
		return nil, fmt.Errorf("%s %s is claimed by another owner", kind, name)
	}
	merged := maps.Clone(live)
	if merged == nil {
		merged = map[string]string{}
	}
	maps.Copy(merged, map[string]string{"terrascale-managed-by": "ts-orchestrator", "terrascale-owner": "terrascale", "terrascale-resource-key": key.String()})
	return merged, nil
}

// one returns the single live item named name, or nil.
func one[T any](items []T, name string, get func(T) (string, string)) (*T, error) {
	var found *T
	for i := range items {
		n, state := get(items[i])
		if n != name || slices.Contains([]string{"TERMINATING", "TERMINATED"}, state) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("more than one live %s", name)
		}
		found = &items[i]
	}
	return found, nil
}

// await polls get until it reports AVAILABLE after a create.
func (r *reconciler) await(get func() (string, error)) error {
	for range 60 {
		if state, err := get(); err == nil && state == "AVAILABLE" {
			return nil
		}
		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("resource did not become AVAILABLE")
}

func (r *reconciler) reconcile() error {
	s, ctx := r.s, r.ctx
	cid := &r.compartment
	vcns, err := r.net.ListVcns(ctx, core.ListVcnsRequest{CompartmentId: cid, DisplayName: new(s.cell + "-vcn")})
	if err != nil {
		return err
	}
	vcn, err := one(vcns.Items, s.cell+"-vcn", func(v core.Vcn) (string, string) { return deref(v.DisplayName), string(v.LifecycleState) })
	if err != nil {
		return err
	}
	if vcn == nil {
		if err := r.step("create VCN "+s.cell+"-vcn "+s.vcn, func() error {
			t, _ := r.tags("vcn", "vcn", nil)
			v, err := r.net.CreateVcn(ctx, core.CreateVcnRequest{CreateVcnDetails: core.CreateVcnDetails{CompartmentId: cid, CidrBlocks: []string{s.vcn},
				DisplayName: new(s.cell + "-vcn"), DnsLabel: new(strings.ReplaceAll(s.cell, "-", "")), FreeformTags: t}})
			vcn = &v.Vcn
			return errors.Join(err, r.await(func() (string, error) {
				g, err := r.net.GetVcn(ctx, core.GetVcnRequest{VcnId: v.Id})
				return string(g.LifecycleState), err
			}))
		}); err != nil || vcn == nil {
			// A dry run cannot read inside a VCN it has not created.
			return err
		}
		if g, err := r.net.GetVcn(ctx, core.GetVcnRequest{VcnId: vcn.Id}); err == nil {
			vcn = &g.Vcn
		} else {
			return err
		}
	} else if !slices.Equal(vcn.CidrBlocks, []string{s.vcn}) {
		return fmt.Errorf("VCN %s has CIDRs %v, want %s; refusing to adopt", s.cell+"-vcn", vcn.CidrBlocks, s.vcn)
	} else if t, err := r.tags("vcn", "vcn", vcn.FreeformTags); err != nil {
		return err
	} else if t != nil {
		if err := r.step("tag VCN "+s.cell+"-vcn", func() error {
			_, err := r.net.UpdateVcn(ctx, core.UpdateVcnRequest{VcnId: vcn.Id, UpdateVcnDetails: core.UpdateVcnDetails{FreeformTags: t}})
			return err
		}); err != nil {
			return err
		}
	}
	n := network{reconciler: r, vcn: vcn.Id}
	igw, err := n.internetGateway()
	if err != nil {
		return err
	}
	sgw, services, err := n.serviceGateway()
	if err != nil {
		return err
	}
	publicRoutes, err := n.routeTable("public-routes", vcn.DefaultRouteTableId, "", []core.RouteRule{{Destination: new("0.0.0.0/0"),
		DestinationType: core.RouteRuleDestinationTypeCidrBlock, NetworkEntityId: igw}})
	if err != nil {
		return err
	}
	privateRoutes, err := n.routeTable("private-routes", nil, s.cell+"-private-routes", []core.RouteRule{{Destination: services,
		DestinationType: core.RouteRuleDestinationTypeServiceCidrBlock, NetworkEntityId: sgw}})
	if err != nil {
		return err
	}
	var nsgIDs []string
	for _, g := range s.nsgs {
		id, err := n.nsg(g)
		if err != nil {
			return err
		}
		nsgIDs = append(nsgIDs, deref(id))
	}
	// The VNIC carries every role NSG before the security lists lose their
	// rules, so 80/443 and SSH are never closed in between.
	if err := n.vnic(nsgIDs); err != nil {
		return err
	}
	hostList, err := n.securityList("host-security-list", nil, s.cell+"-host-sl")
	if err != nil {
		return err
	}
	if _, err := n.securityList("default-security-list", vcn.DefaultSecurityListId, ""); err != nil {
		return err
	}
	if err := n.subnet("host-subnet", s.cell+"-host-subnet", "host", s.publicSubnet, false, publicRoutes, hostList); err != nil {
		return err
	}
	return n.subnet("private-subnet", s.cell+"-private-subnet", "private", s.privateSubnet, true, privateRoutes, hostList)
}
