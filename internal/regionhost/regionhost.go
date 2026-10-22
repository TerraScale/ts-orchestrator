// Package regionhost is `ts-orch region add|rm`: it creates or adopts a whole
// milestone 1 region (compartment, network, host) in one idempotent command.
// A second run changes nothing and prints only `unchanged` lines.
package regionhost

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/hostnetwork"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

const usage = `Usage: ts-orch region add CODE [--shape SHAPE] [--host NAME] [--dry-run]

Creates or adopts region CODE's milestone 1 host: compartment CELL-control
under TerraScale, the ts-orch network (oci-region network) and one host.
Without --host the region host is the oldest live instance in the
compartment, or a new ts-CODE-1. --host NAME adopts or launches exactly NAME.
The default host is VM.Standard.A1.Flex 2 OCPU/12 GB; --shape SHAPE launches
the smallest SHAPE host (1 OCPU, 6 GB on Ampere, 8 GB on x86). Every new
region needs the user's approval. Prints one line per resource:
unchanged|created|updated KIND NAME ID (--dry-run: "plan" first, no change).
`

// Run is `ts-orch region add|rm`; args start with add or rm.
func Run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("region "+args[0], flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { io.WriteString(out, usage) }
	shape := fs.String("shape", "", "launch the smallest host of this shape")
	host := fs.String("host", "", "adopt or launch exactly this instance")
	dry := fs.Bool("dry-run", false, "print the plan, change nothing")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	code := fs.Arg(0)
	// Flags may also follow CODE.
	if fs.NArg() > 0 {
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return err
		}
	}
	entry, ok := catalog.LookupName(code)
	if !ok || fs.NArg() != 0 {
		return errors.New("usage: ts-orch region add CODE [--shape SHAPE] [--host NAME] [--dry-run]")
	}
	r, err := connect(ctx, entry, *dry, out)
	if err != nil {
		return err
	}
	return r.add(*host, *shape)
}

// run is one region's command state.
type run struct {
	ctx                  context.Context
	out                  io.Writer
	dry                  bool
	code, cell, region   string
	tenancy, compartment string
	parent               string                  // the TerraScale compartment
	home, ids            identity.IdentityClient // home region (writes) and this region (ADs)
	compute              core.ComputeClient
	net                  core.VirtualNetworkClient
}

func connect(ctx context.Context, entry catalog.Entry, dry bool, out io.Writer) (*run, error) {
	r := &run{ctx: ctx, out: out, dry: dry, code: entry.Name(), cell: entry.Name() + "-1", region: entry.OCIRegion}
	f, err := ociclient.OperatorConfig(r.region)
	if err != nil {
		return nil, err
	}
	if r.tenancy, err = f.Provider().TenancyOCID(); err != nil {
		return nil, err
	}
	home, err := f.HomeRegion(ctx, r.tenancy)
	if err != nil {
		return nil, err
	}
	hf, err := f.ForRegion(home)
	if err != nil {
		return nil, err
	}
	if r.home, err = hf.Identity(); err != nil {
		return nil, err
	}
	if r.ids, err = f.Identity(); err != nil {
		return nil, err
	}
	if r.compute, err = f.Compute(); err != nil {
		return nil, err
	}
	r.net, err = f.Network()
	return r, err
}

// report prints one resource line, prefixed with "plan" on a dry run.
func (r *run) report(verb, kind, name, id string) error {
	if r.dry && verb != "unchanged" {
		verb = "plan " + verb
	}
	_, err := fmt.Fprintln(r.out, verb, kind, name, id)
	return err
}

func (r *run) add(host, shape string) error {
	created, err := r.ensureCompartment()
	if err != nil || r.compartment == "" {
		return err // a dry run cannot plan inside a compartment it has not created
	}
	if err := r.ensureNetwork(created); err != nil {
		return err
	}
	if _, err := r.ensureInstance(host, shape); err != nil {
		return err
	}
	return r.ensureIAM()
}

func (r *run) ensureCompartment() (created bool, err error) {
	name := r.cell + "-control"
	parent, err := r.oneCompartment(r.tenancy, "TerraScale")
	if err != nil {
		return false, err
	}
	r.parent = parent
	if r.compartment, err = r.oneCompartment(parent, name); err != nil {
		return false, err
	}
	if r.compartment != "" {
		return false, r.report("unchanged", "compartment", name, r.compartment)
	}
	if r.dry {
		return true, r.report("created", "compartment", name, "-")
	}
	c, err := r.home.CreateCompartment(r.ctx, identity.CreateCompartmentRequest{CreateCompartmentDetails: identity.CreateCompartmentDetails{
		CompartmentId: &parent, Name: &name, Description: new("TerraScale " + r.cell + " control plane")}})
	if err != nil {
		return false, err
	}
	r.compartment = *c.Id
	if err := poll(r.ctx, 2*time.Second, 60, func() (bool, error) {
		g, err := r.home.GetCompartment(r.ctx, identity.GetCompartmentRequest{CompartmentId: c.Id})
		return g.LifecycleState == identity.CompartmentLifecycleStateActive, err
	}); err != nil {
		return false, err
	}
	return true, r.report("created", "compartment", name, r.compartment)
}

// oneCompartment is the ID of parent's single ACTIVE child named name, or "".
func (r *run) oneCompartment(parent, name string) (string, error) {
	list, err := r.home.ListCompartments(r.ctx, identity.ListCompartmentsRequest{CompartmentId: &parent, Name: &name,
		LifecycleState: identity.CompartmentLifecycleStateActive})
	switch {
	case err != nil:
		return "", err
	case len(list.Items) > 1:
		return "", fmt.Errorf("%d ACTIVE compartments named %s", len(list.Items), name)
	case len(list.Items) == 0 && name == "TerraScale":
		return "", errors.New("no ACTIVE TerraScale compartment")
	case len(list.Items) == 0:
		return "", nil
	}
	return *list.Items[0].Id, nil
}

// ensureNetwork converges the network; a new compartment takes a while to
// reach the other regions, so its first converge is retried.
func (r *run) ensureNetwork(newCompartment bool) error {
	tries := 1
	if newCompartment {
		tries = 9
	}
	var changes int
	err := poll(r.ctx, 20*time.Second, tries, func() (bool, error) {
		var err error
		changes, err = hostnetwork.Converge(r.ctx, r.cell, !r.dry, r.out)
		return err == nil, err
	})
	if err != nil {
		return err
	}
	subnet, err := r.subnet()
	if err != nil {
		return err
	}
	verb := "unchanged"
	if changes > 0 {
		verb = "updated"
	}
	return r.report(verb, "network", r.cell+"-host-subnet", subnet)
}

func (r *run) subnet() (string, error) {
	name := r.cell + "-host-subnet"
	list, err := r.net.ListSubnets(r.ctx, core.ListSubnetsRequest{CompartmentId: &r.compartment, DisplayName: &name,
		LifecycleState: core.SubnetLifecycleStateAvailable})
	switch {
	case err != nil:
		return "", err
	case len(list.Items) == 1:
		return *list.Items[0].Id, nil
	case r.dry:
		return "-", nil // not created yet
	}
	return "", fmt.Errorf("want one subnet %s, found %d", name, len(list.Items))
}

// poll calls done every interval until it reports true, at most tries times,
// and returns its last error.
func poll(ctx context.Context, interval time.Duration, tries int, done func() (bool, error)) error {
	var err error
	for i := range tries {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
		}
		var ok bool
		if ok, err = done(); ok {
			return nil
		}
	}
	if err == nil {
		err = errors.New("timed out waiting for OCI")
	}
	return err
}
