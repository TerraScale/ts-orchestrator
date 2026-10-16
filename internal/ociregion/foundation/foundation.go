// Package foundation creates a region's OCI foundation from its plan
// (TS-663): the cell compartments, the private network, the Vault and its
// key, the IAM and the buckets that inspect-foundation reads back. Every
// resource is found by its static name first, so a rerun creates nothing and
// an interrupted run resumes. A same-named resource that differs from the
// plan is refused, never adopted.
package foundation

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/command"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

const usage = `Usage: ts-orch oci-region foundation --plan PLAN --out BOUND_PLAN [--apply]

Creates the plan's missing OCI foundation: the cell compartments, VCN,
service gateway, route table, security list, private subnet and NSGs, the
Vault and its HSM key, the dynamic groups and policies (in the home region)
and the buckets. Without --apply it only prints the creates. With --apply it
creates them, runs inspect-foundation's live checks and writes BOUND_PLAN,
the plan with resource_ids bound. It never overwrites a different BOUND_PLAN.
`

type Object = map[string]any

// Foundation finds or creates one plan's foundation.
type Foundation struct {
	// Region serves the plan's OCI region and Home the tenancy's home
	// region, the only one that accepts IAM writes.
	Region, Home command.Client
	// OperationID is stable across retries and ownership transfers.
	OperationID string
	// BeforeWrite checks durable authority for every provider mutation. For
	// home IAM writes it also holds the tenancy-wide serialization lease.
	// The returned release must remain held until the provider call returns.
	BeforeWrite func(context.Context, bool) (func(), error)
	// Guard rechecks the claim before each SDK retry as well as each command.
	Guard func(context.Context) error
	// Checkpoint durably records each verified OCID before dependent work.
	Checkpoint func(context.Context, string, string) error
	ownership  map[string]string
	expected   map[string]string
	tenancy    string
	region     string
	inspect    func(context.Context, Object) error
	// Check runs inspect-foundation's live checks on the bound plan.
	Check        func(plan Object) error
	Pause        func(context.Context, time.Duration) error
	PollAttempts int
	Apply        bool
	Out          io.Writer
	planned      int
}

// New uses one authenticated provider for the regional and actual home-region
// clients. It grants no write authority; the caller must supply the guards.
func New(ctx context.Context, factory *ociclient.Factory, tenancy string) (*Foundation, error) {
	if factory == nil {
		return nil, errors.New("foundation requires an authenticated OCI factory")
	}
	providerTenancy, err := factory.Provider().TenancyOCID()
	if err != nil || providerTenancy != tenancy {
		return nil, errors.New("foundation tenancy differs from authenticated OCI identity")
	}
	homeRegion, err := factory.HomeRegion(ctx, tenancy)
	if err != nil {
		return nil, err
	}
	home, err := factory.ForRegion(homeRegion)
	if err != nil {
		return nil, err
	}
	inspect := func(ctx context.Context, plan Object) error {
		engine := &ociregion.Engine{Context: ctx, Dependency: func(name string, args []any, kwargs Object) (any, error) {
			if name != "oci" {
				return nil, fmt.Errorf("foundation inspection dependency %s is unsupported", name)
			}
			selected := home
			if region := text(kwargs["region"]); region != "" {
				var err error
				selected, err = factory.ForRegion(region)
				if err != nil {
					return nil, err
				}
			}
			words := make([]string, len(args))
			for i, arg := range args {
				words[i] = fmt.Sprint(arg)
			}
			data, _, err := sdkcli.NewClient(selected, "").Call(ctx, words)
			if err != nil {
				return nil, err
			}
			var value any
			if err := json.Unmarshal(data, &value); err != nil {
				return nil, err
			}
			return value, nil
		}}
		return engine.CheckFoundation(plan)
	}
	return &Foundation{Region: publicapi.NewClientWithFactory(factory), Home: publicapi.NewClientWithFactory(home), Out: io.Discard,
		Check: func(plan Object) error { return inspect(ctx, plan) }, inspect: inspect, tenancy: tenancy, region: factory.Region()}, nil
}

// Run is `ts-orch oci-region foundation`.
func Run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("oci-region foundation", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { io.WriteString(out, usage) }
	planPath := fs.String("plan", "", "regional plan JSON")
	outPath := fs.String("out", "", "bound plan to write")
	apply := fs.Bool("apply", false, "create the missing resources; without it, only print them")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 || *planPath == "" || *outPath == "" {
		return errors.New("usage: ts-orch oci-region foundation --plan PLAN --out BOUND_PLAN [--apply]")
	}
	plan, err := ociregion.LoadPlan(*planPath)
	if err != nil {
		return err
	}
	region, err := publicapi.NewClient(text(plan["region"]))
	if err != nil {
		return err
	}
	factory, err := ociclient.OperatorConfig(text(plan["region"]))
	if err != nil {
		return err
	}
	homeRegion, err := factory.HomeRegion(ctx, text(plan["tenancy_id"]))
	if err != nil {
		return err
	}
	home, err := publicapi.NewClient(homeRegion)
	if err != nil {
		return err
	}
	f := &Foundation{Region: region, Home: home, Apply: *apply, Out: out, Check: (&ociregion.Engine{Context: ctx}).CheckFoundation}
	return f.Run(ctx, plan, *outPath)
}

// Run binds plan's foundation and, with Apply, writes the bound plan to out.
func (f *Foundation) Run(ctx context.Context, plan Object, out string) error {
	delete(plan, "_source_path")
	ids, err := f.bind(ctx, plan)
	if err != nil {
		return err
	}
	if !f.Apply {
		if f.planned == 0 {
			_, err = fmt.Fprintln(f.Out, "no changes")
		} else {
			_, err = fmt.Fprintf(f.Out, "%d changes planned; rerun with --apply to make them\n", f.planned)
		}
		return err
	}
	plan["resource_ids"] = ids
	if err := f.Check(plan); err != nil {
		return fmt.Errorf("the bound foundation fails inspection: %w", err)
	}
	return write(out, plan, f.Out)
}

// Reconcile applies one authorized foundation without a CLI or file handoff.
// The caller supplies durable authority and OCID checkpoints before NATS exists.
func (f *Foundation) Reconcile(ctx context.Context, plan Object) (Object, error) {
	if f.BeforeWrite == nil || f.Guard == nil || f.Checkpoint == nil || f.Check == nil || f.OperationID == "" || len(f.OperationID) > 256 {
		return nil, errors.New("foundation reconciliation requires an operation ID, durable authority, checkpoints and live inspection")
	}
	working := *f
	working.Apply = true
	if working.Out == nil {
		working.Out = io.Discard
	}
	bound, err := ociregion.ValidatePlan(plan)
	if err != nil {
		return nil, err
	}
	if f.tenancy != "" && bound["tenancy_id"] != f.tenancy || f.region != "" && bound["region"] != f.region {
		return nil, errors.New("foundation plan differs from authenticated tenancy or regional client")
	}
	ctx = ociclient.WithAuthority(ociresource.WithOperation(ctx, f.OperationID), f.Guard)
	if working.inspect != nil {
		working.Check = func(plan Object) error { return working.inspect(ctx, plan) }
	}
	ids, err := working.bind(ctx, bound)
	if err != nil {
		return nil, err
	}
	bound["resource_ids"] = ids
	if err := working.Check(bound); err != nil {
		return nil, fmt.Errorf("the bound foundation fails inspection: %w", err)
	}
	return bound, nil
}

// write creates out, or accepts an identical one; it never replaces a
// different file.
func write(out string, plan Object, log io.Writer) error {
	wire, err := json.Marshal(plan, json.Deterministic(true), jsontext.Multiline(true), json.FormatNilMapAsNull(true))
	if err != nil {
		return err
	}
	wire = append(wire, '\n')
	if old, err := os.ReadFile(out); err == nil {
		if !bytes.Equal(old, wire) {
			return fmt.Errorf("%s exists and differs from the bound plan; it is never overwritten", out)
		}
		_, err = fmt.Fprintln(log, "unchanged: "+out)
		return err
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.WriteFile(out+".tmp", wire, 0o644); err != nil {
		return err
	}
	if err := os.Rename(out+".tmp", out); err != nil {
		return err
	}
	_, err = fmt.Fprintln(log, "wrote: "+out)
	return err
}

func (f *Foundation) call(ctx context.Context, c command.Client, args ...string) (any, error) {
	var release func()
	mutation := false
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") {
			break
		}
		mutation = mutation || slices.Contains([]string{"create", "add", "remove", "update", "connect"}, arg)
	}
	if mutation {
		if f.BeforeWrite == nil || f.Guard == nil {
			return nil, errors.New("foundation mutation requires durable authority and a retry guard")
		}
		var err error
		release, err = f.BeforeWrite(ctx, len(args) > 0 && args[0] == "iam")
		if err != nil {
			return nil, fmt.Errorf("foundation write authority: %w", err)
		}
		if release == nil {
			return nil, errors.New("foundation authority returned no lease release")
		}
		defer release()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if f.Guard != nil {
			if err := f.Guard(ctx); err != nil {
				return nil, err
			}
			ctx = ociclient.WithAuthority(ctx, f.Guard)
		}
	}
	r, err := c.Call(ctx, args...)
	if err != nil {
		return nil, err
	}
	return r["data"], nil
}

func (f *Foundation) data(ctx context.Context, c command.Client, args ...string) (Object, error) {
	v, err := f.call(ctx, c, args...)
	if err != nil {
		return nil, err
	}
	return command.Object(v)
}

// find returns the one live row of a list whose field is name. A list scoped
// by a parent a dry run has not created yet finds nothing.
func (f *Foundation) find(c command.Client, field, name string, args ...string) func(context.Context) (Object, error) {
	return func(ctx context.Context) (Object, error) {
		if slices.Contains(args, "") {
			return nil, nil
		}
		v, err := f.call(ctx, c, args...)
		if err != nil {
			return nil, err
		}
		rows, err := command.Rows(v)
		if err != nil {
			return nil, err
		}
		var found Object
		for _, r := range rows {
			if r[field] == name && !slices.Contains([]string{"TERMINATED", "TERMINATING", "DELETED", "DELETING", "PENDING_DELETION", "SCHEDULING_DELETION"}, fmt.Sprint(r["lifecycle-state"])) {
				if found != nil {
					return nil, fmt.Errorf("more than one live resource is named %s", name)
				}
				found = r
			}
		}
		if expected := f.expected[name]; expected != "" && (found == nil || found["id"] != expected) {
			return nil, fmt.Errorf("recorded resource %s (%s) is missing or differs; refusing replacement", name, expected)
		}
		if found != nil && len(f.ownership) > 0 && f.expected[name] == "" {
			// Mutable tags cannot replace an authenticated resource checkpoint.
			return nil, fmt.Errorf("resource %s has no authenticated foundation ownership checkpoint; refusing adoption", name)
		}
		return found, nil
	}
}

func (f *Foundation) create(c command.Client, args ...string) func(context.Context) (Object, error) {
	return func(ctx context.Context) (Object, error) {
		words := slices.Clone(args)
		if len(f.ownership) > 0 {
			words = append(words, "--freeform-tags", command.JSON(f.ownership))
		}
		return f.data(ctx, c, words...)
	}
}

// ensure finds a resource or, with Apply, creates it. A dry run reports the
// create and returns nil. A found resource valid rejects is refused.
func (f *Foundation) ensure(ctx context.Context, what string, find, create func(context.Context) (Object, error), valid func(Object) bool) (Object, error) {
	r, err := find(ctx)
	if err != nil {
		return nil, fmt.Errorf("find %s: %w", what, err)
	}
	if r == nil {
		if !f.Apply {
			f.planned++
			_, err := fmt.Fprintln(f.Out, "plan: create "+what)
			return nil, err
		}
		if r, err = create(ctx); err != nil {
			return nil, fmt.Errorf("create %s: %w", what, err)
		}
		fmt.Fprintln(f.Out, "created: "+what)
	}
	if !valid(r) {
		return nil, fmt.Errorf("%s exists but differs from the plan; inspect it before rerunning", what)
	}
	return r, nil
}

// await re-reads a resource until it reaches state. With tolerate, read
// errors count as not yet, as when a new compartment has not replicated to
// the region.
func (f *Foundation) await(ctx context.Context, c command.Client, what, state string, tolerate bool, args ...string) (Object, error) {
	attempts := f.PollAttempts
	if attempts <= 0 {
		attempts = 60
	}
	pause := f.Pause
	if pause == nil {
		pause = command.Pause
	}
	for n := 1; ; n++ {
		r, err := f.data(ctx, c, args...)
		if err == nil && r["lifecycle-state"] == state {
			return r, nil
		}
		if err != nil && (!tolerate || n == attempts) {
			return nil, fmt.Errorf("read %s: %w", what, err)
		}
		if n == attempts {
			return nil, fmt.Errorf("%s did not become %s", what, state)
		}
		if err := pause(ctx, 10*time.Second); err != nil {
			return nil, err
		}
	}
}

// bind finds or creates every foundation resource and returns the plan's
// resource_ids with them bound.
func (f *Foundation) bind(ctx context.Context, plan Object) (Object, error) {
	region := text(plan["region"])
	entry, _ := catalog.CellForOCIRegion(region)
	sec, secret := obj(plan["network_security"]), obj(plan["host_credential_secret"])
	service := text(sec["service_gateway_service_id"])
	switch {
	case plan["operator_gateway"] != nil:
		return nil, errors.New("foundation does not create an operator gateway peering; plan operator_gateway must be null")
	case secret["compartment_id"] != nil || secret["secret_id"] != nil:
		return nil, errors.New("foundation creates no host LiveS3Credential policy; plan host_credential_secret must be null")
	case service == "" || sec["service_gateway_cidr_block"] != "all-"+strings.ToLower(entry.OCIRegionKey)+"-services-in-oracle-services-network":
		return nil, fmt.Errorf("plan service gateway must route all %s services in the Oracle Services Network", entry.OCIRegionKey)
	}
	cell, err := naming.RegionCell(entry.Cell).Name()
	if err != nil {
		return nil, err
	}
	description := "TerraScale " + cell + " foundation (ts-orch oci-region foundation)"
	ids := maps.Clone(obj(plan["resource_ids"]))
	if ids == nil {
		ids = Object{}
	}
	f.ownership = map[string]string{"terrascale.owner": "ts-orch", "terrascale.cell": cell}
	if f.OperationID != "" {
		f.ownership["terrascale.operation"] = f.OperationID
	}
	f.expected = map[string]string{}
	names := obj(plan["preview_compartment_names"])
	for _, role := range []string{"control", "network", "workload"} {
		f.expected[text(names[role])] = text(ids[role+"_compartment"])
	}
	for key, suffix := range map[string]string{"vault": "vault", "key": "key", "vcn": "vcn", "service_gateway": "service-gateway", "route_table": "private-routes", "security_list": "private-security", "subnet": "private", "network_security_group": "controllers-nsg", "workload_network_security_group": "databases-nsg"} {
		f.expected[cell+"-"+suffix] = text(ids[key])
	}
	identity := obj(plan["identity"])
	for key, field := range map[string]string{"controller_dynamic_group": "controller_dynamic_group_name", "host_dynamic_group": "host_dynamic_group_name", "controller_policy": "controller_policy_name", "objectstorage_key_policy": "objectstorage_key_policy_name"} {
		f.expected[text(identity[field])] = text(ids[key])
	}
	bind := func(key string, r Object) error {
		if r == nil {
			return nil
		}
		if old := text(ids[key]); old != "" && old != r["id"] {
			return fmt.Errorf("plan binds %s %s, but its live resource is %v", key, old, r["id"])
		}
		resourceID, err := command.ID(r)
		if err != nil {
			return err
		}
		if f.Apply {
			if f.Checkpoint == nil {
				return errors.New("foundation binding requires durable checkpoints")
			}
			if err := f.Checkpoint(ctx, key, resourceID); err != nil {
				return fmt.Errorf("checkpoint %s: %w", key, err)
			}
		}
		ids[key] = resourceID
		return nil
	}
	id := func(key string) string { return text(ids[key]) }
	parent, tenancy := text(plan["parent_compartment_id"]), text(plan["tenancy_id"])

	for _, role := range []string{"control", "network", "workload"} {
		name := text(names[role])
		what := "compartment " + name
		r, err := f.ensure(ctx, what, f.find(f.Home, "name", name, "iam", "compartment", "list", "--compartment-id", parent, "--all"),
			f.create(f.Home, "iam", "compartment", "create", "--compartment-id", parent, "--name", name, "--description", description),
			func(r Object) bool { return r["compartment-id"] == parent })
		if err != nil {
			return nil, err
		}
		if r != nil {
			get := []string{"iam", "compartment", "get", "--compartment-id", text(r["id"])}
			if _, err := f.await(ctx, f.Home, what, "ACTIVE", false, get...); err != nil {
				return nil, err
			}
			if _, err := f.await(ctx, f.Region, what+" in "+region, "ACTIVE", true, get...); err != nil {
				return nil, err
			}
		}
		if err := bind(role+"_compartment", r); err != nil {
			return nil, err
		}
	}
	network, control := id("network_compartment"), id("control_compartment")

	if err := f.network(ctx, plan, cell, network, bind, id); err != nil {
		return nil, err
	}

	vault, err := f.ensure(ctx, "Vault "+cell+"-vault", f.find(f.Region, "display-name", cell+"-vault", "kms", "management", "vault", "list", "--compartment-id", control, "--all"),
		f.create(f.Region, "kms", "management", "vault", "create", "--compartment-id", control, "--display-name", cell+"-vault", "--vault-type", "DEFAULT"),
		func(r Object) bool { return r["vault-type"] == "DEFAULT" && r["compartment-id"] == control })
	if err != nil {
		return nil, err
	}
	endpoint := ""
	if vault != nil {
		if vault, err = f.await(ctx, f.Region, "Vault "+cell+"-vault", "ACTIVE", false, "kms", "management", "vault", "get", "--vault-id", text(vault["id"])); err != nil {
			return nil, err
		}
		endpoint = text(vault["management-endpoint"])
	}
	if err := bind("vault", vault); err != nil {
		return nil, err
	}
	key, err := f.ensure(ctx, "HSM key "+cell+"-key", f.find(f.Region, "display-name", cell+"-key", "kms", "management", "key", "list", "--compartment-id", control, "--endpoint", endpoint, "--all"),
		f.create(f.Region, "kms", "management", "key", "create", "--compartment-id", control, "--display-name", cell+"-key",
			"--key-shape", `{"algorithm":"AES","length":32}`, "--protection-mode", "HSM", "--endpoint", endpoint),
		func(r Object) bool {
			return r["compartment-id"] == control && r["protection-mode"] == "HSM" && r["vault-id"] == id("vault")
		})
	if err != nil {
		return nil, err
	}
	if key != nil {
		if _, err := f.await(ctx, f.Region, "HSM key "+cell+"-key", "ENABLED", false, "kms", "management", "key", "get", "--key-id", text(key["id"]), "--endpoint", endpoint); err != nil {
			return nil, err
		}
	}
	if err := bind("key", key); err != nil {
		return nil, err
	}

	if err := f.iam(ctx, plan, ids, cell, description, tenancy, parent, bind); err != nil {
		return nil, err
	}
	return ids, f.buckets(ctx, plan, control, id("key"))
}

// network creates the private network: VCN, service gateway, route table,
// security list, subnet and NSGs with their rules.
func (f *Foundation) network(ctx context.Context, plan Object, cell, network string, bind func(string, Object) error, id func(string) string) error {
	sec := obj(plan["network_security"])
	inVCN := func(r Object) bool { return r["compartment-id"] == network && r["vcn-id"] == id("vcn") }
	list := func(kind, name string) func(context.Context) (Object, error) {
		return f.find(f.Region, "display-name", name, "network", kind, "list", "--compartment-id", network, "--vcn-id", id("vcn"), "--all")
	}
	create := func(kind, name string, args ...string) func(context.Context) (Object, error) {
		return f.create(f.Region, append([]string{"network", kind, "create", "--compartment-id", network, "--vcn-id", id("vcn"), "--display-name", name, "--wait-for-state", "AVAILABLE"}, args...)...)
	}
	vcn, err := f.ensure(ctx, "VCN "+cell+"-vcn", f.find(f.Region, "display-name", cell+"-vcn", "network", "vcn", "list", "--compartment-id", network, "--all"),
		f.create(f.Region, "network", "vcn", "create", "--compartment-id", network, "--display-name", cell+"-vcn", "--cidr-block", text(plan["network_cidr"]),
			"--dns-label", strings.ReplaceAll(cell, "-", ""), "--wait-for-state", "AVAILABLE"),
		func(r Object) bool { return r["compartment-id"] == network && r["cidr-block"] == plan["network_cidr"] })
	if err != nil {
		return err
	}
	if err := bind("vcn", vcn); err != nil {
		return err
	}

	service := text(sec["service_gateway_service_id"])
	gateway, err := f.ensure(ctx, "service gateway "+cell+"-service-gateway", list("service-gateway", cell+"-service-gateway"),
		create("service-gateway", cell+"-service-gateway", "--services", command.JSON([]any{Object{"serviceId": service}})),
		func(r Object) bool {
			services, _ := command.Rows(r["services"])
			return inVCN(r) && len(services) == 1 && services[0]["service-id"] == service
		})
	if err != nil {
		return err
	}
	if err := bind("service_gateway", gateway); err != nil {
		return err
	}

	routes, err := f.ensure(ctx, "route table "+cell+"-private-routes", list("route-table", cell+"-private-routes"),
		create("route-table", cell+"-private-routes", "--route-rules", command.JSON([]any{Object{"destination": sec["service_gateway_cidr_block"],
			"destinationType": "SERVICE_CIDR_BLOCK", "networkEntityId": id("service_gateway")}})), inVCN)
	if err != nil {
		return err
	}
	if err := bind("route_table", routes); err != nil {
		return err
	}

	security, err := f.ensure(ctx, "security list "+cell+"-private-security", list("security-list", cell+"-private-security"),
		create("security-list", cell+"-private-security", "--ingress-security-rules", command.JSON(rules(sec["security_list_ingress_rules"], false)),
			"--egress-security-rules", command.JSON(rules(sec["security_list_egress_rules"], false))), inVCN)
	if err != nil {
		return err
	}
	if err := bind("security_list", security); err != nil {
		return err
	}

	subnet, err := f.ensure(ctx, "subnet "+cell+"-private", list("subnet", cell+"-private"),
		create("subnet", cell+"-private", "--cidr-block", text(plan["subnet_cidr"]), "--dns-label", "private", "--prohibit-public-ip-on-vnic", "true",
			"--route-table-id", id("route_table"), "--security-list-ids", command.JSON([]string{id("security_list")})),
		func(r Object) bool {
			return inVCN(r) && r["cidr-block"] == plan["subnet_cidr"] && r["prohibit-public-ip-on-vnic"] == true
		})
	if err != nil {
		return err
	}
	if err := bind("subnet", subnet); err != nil {
		return err
	}

	for _, n := range []struct{ key, rules, name string }{{"network_security_group", "nsg_rules", cell + "-controllers-nsg"},
		{"workload_network_security_group", "workload_nsg_rules", cell + "-databases-nsg"}} {
		if len(arr(sec[n.rules])) == 0 && n.key == "workload_network_security_group" {
			continue
		}
		nsg, err := f.ensure(ctx, "NSG "+n.name, list("nsg", n.name), create("nsg", n.name), inVCN)
		if err != nil {
			return err
		}
		if err := bind(n.key, nsg); err != nil {
			return err
		}
		// Rules are added in one call, so an NSG has none or all of them;
		// inspection compares them with the plan.
		var live []Object
		if nsg != nil {
			v, err := f.call(ctx, f.Region, "network", "nsg", "rules", "list", "--nsg-id", text(nsg["id"]), "--all")
			if err == nil {
				live, err = command.Rows(v)
			}
			if err != nil {
				return fmt.Errorf("read NSG %s rules: %w", n.name, err)
			}
		}
		if len(live) > 0 {
			continue
		}
		what := fmt.Sprintf("%d rules on NSG %s", len(arr(sec[n.rules])), n.name)
		if !f.Apply {
			f.planned++
			fmt.Fprintln(f.Out, "plan: add "+what)
			continue
		}
		if _, err := f.call(ctx, f.Region, "network", "nsg", "rules", "add", "--nsg-id", text(nsg["id"]), "--security-rules", command.JSON(rules(sec[n.rules], true))); err != nil {
			return fmt.Errorf("add %s: %w", what, err)
		}
		fmt.Fprintln(f.Out, "added: "+what)
	}
	return nil
}

// iam creates the dynamic groups and policies in the home region.
func (f *Foundation) iam(ctx context.Context, plan, ids Object, cell, description, tenancy, parent string, bind func(string, Object) error) error {
	identity := obj(plan["identity"])
	for _, g := range []struct{ key, name, compartment string }{{"controller_dynamic_group", "controller_dynamic_group_name", "control_compartment"},
		{"host_dynamic_group", "host_dynamic_group_name", "workload_compartment"}} {
		name := text(identity[g.name])
		rule := fmt.Sprintf("ALL {instance.compartment.id = '%s'}", text(ids[g.compartment]))
		r, err := f.ensure(ctx, "dynamic group "+name, f.find(f.Home, "name", name, "iam", "dynamic-group", "list", "--compartment-id", tenancy, "--all"),
			f.create(f.Home, "iam", "dynamic-group", "create", "--compartment-id", tenancy, "--name", name, "--description", description, "--matching-rule", rule),
			func(r Object) bool { return r["compartment-id"] == tenancy && r["matching-rule"] == rule })
		if err != nil {
			return err
		}
		if err := bind(g.key, r); err != nil {
			return err
		}
	}
	controller, err := ociregion.RequiredControllerStatements(plan, ids, text(plan["bootstrap_object_prefix"]))
	if err != nil {
		return err
	}
	type policy struct {
		key, name, compartment string
		statements             []string
	}
	control := text(ids["control_compartment"])
	policies := []policy{{"objectstorage_key_policy", text(identity["objectstorage_key_policy_name"]), control, []string{ociregion.ObjectStorageKeyStatement(plan, ids)}},
		{"controller_policy", text(identity["controller_policy_name"]), parent, controller},
		// Usage API statements must name the tenancy, so this one sits in
		// the root compartment; the controller policy's parent is not it.
		{"", cell + "-controller-usage", tenancy, []string{fmt.Sprintf("Allow dynamic-group %s to read usage-report in tenancy", text(identity["controller_dynamic_group_name"]))}}}
	if plan["netbird"] == nil {
		// Without a plan-bound NetBird secret, both dynamic groups may read
		// the setup key by its static name once it is stored. No resource ID
		// records this policy and inspect-foundation does not read it.
		var statements []string
		for _, g := range []string{"controller_dynamic_group_name", "host_dynamic_group_name"} {
			statements = append(statements, fmt.Sprintf("Allow dynamic-group %s to read secret-bundles in compartment id %s where target.secret.name = '%s-netbird-setup-key'", text(identity[g]), control, cell))
		}
		policies = append(policies, policy{"", cell + "-netbird-enrollment", control, statements})
	}
	for _, p := range policies {
		name := p.name
		r, err := f.ensure(ctx, "policy "+name, f.find(f.Home, "name", name, "iam", "policy", "list", "--compartment-id", p.compartment, "--all"),
			f.create(f.Home, "iam", "policy", "create", "--compartment-id", p.compartment, "--name", name, "--description", description, "--statements", command.JSON(p.statements)),
			func(r Object) bool {
				return r["compartment-id"] == p.compartment && command.JSON(r["statements"]) == command.JSON(p.statements)
			})
		if err != nil {
			return err
		}
		if p.key == "" {
			continue
		}
		if err := bind(p.key, r); err != nil {
			return err
		}
	}
	return nil
}

// buckets creates the private, key-encrypted buckets: head and material
// versioned, ledger and backup under the plan's retention rule.
func (f *Foundation) buckets(ctx context.Context, plan Object, control, key string) error {
	namespace := ""
	if f.Apply || control != "" {
		v, err := f.call(ctx, f.Region, "os", "ns", "get")
		if err != nil {
			return fmt.Errorf("read the Object Storage namespace: %w", err)
		}
		namespace = text(v)
	}
	names := obj(plan["foundation_buckets"])
	for _, role := range []string{"ledger", "head", "backup", "material"} {
		name := text(names[role])
		versioning := "Disabled"
		if role == "head" || role == "material" {
			versioning = "Enabled"
		}
		list := f.find(f.Region, "name", name, "os", "bucket", "list", "--compartment-id", control, "--all")
		bucket, err := f.ensure(ctx, "bucket "+name, func(ctx context.Context) (Object, error) {
			// A summary lacks the encryption and versioning to check.
			r, err := list(ctx)
			if r == nil || err != nil {
				return r, err
			}
			return f.data(ctx, f.Region, "os", "bucket", "get", "--namespace-name", namespace, "--bucket-name", name)
		}, f.create(f.Region, "os", "bucket", "create", "--namespace-name", namespace, "--compartment-id", control, "--name", name, "--kms-key-id", key,
			"--versioning", versioning, "--public-access-type", "NoPublicAccess", "--storage-tier", "Standard"),
			func(r Object) bool {
				return r["compartment-id"] == control && r["public-access-type"] == "NoPublicAccess" && r["kms-key-id"] == key && r["versioning"] == versioning
			})
		if err != nil {
			return err
		}
		if versioning == "Enabled" {
			continue
		}
		what := "retention rule " + role + "-retention on bucket " + name
		if bucket != nil {
			v, err := f.call(ctx, f.Region, "os", "retention-rule", "list", "--namespace-name", namespace, "--bucket-name", name, "--all")
			if err != nil {
				return fmt.Errorf("read %s: %w", what, err)
			}
			if len(arr(v)) > 0 {
				continue
			}
		}
		if !f.Apply {
			f.planned++
			fmt.Fprintln(f.Out, "plan: create "+what)
			continue
		}
		if _, err := f.call(ctx, f.Region, "os", "retention-rule", "create", "--namespace-name", namespace, "--bucket-name", name,
			"--display-name", role+"-retention", "--time-amount", fmt.Sprint(plan["bucket_retention_days"]), "--time-unit", "DAYS"); err != nil {
			return fmt.Errorf("create %s: %w", what, err)
		}
		fmt.Fprintln(f.Out, "created: "+what)
	}
	return nil
}

// rules renders the plan's normalized security rules as OCI rules: NSG
// rules carry their direction, security-list rules do not.
func rules(v any, nsg bool) []any {
	r := []any{}
	for _, x := range arr(v) {
		rule := obj(x)
		m := Object{"protocol": rule["protocol"], "isStateless": rule["stateless"]}
		if nsg {
			m["direction"] = rule["direction"]
		}
		for _, side := range []string{"source", "destination"} {
			if rule[side] != nil {
				m[side], m[side+"Type"] = rule[side], rule[side+"_type"]
			}
		}
		for _, kind := range []string{"tcp", "udp"} {
			if rule[kind+"_min"] != nil {
				m[kind+"Options"] = Object{"destinationPortRange": Object{"min": rule[kind+"_min"], "max": rule[kind+"_max"]}}
			}
		}
		r = append(r, m)
	}
	return r
}

func obj(v any) Object { m, _ := v.(Object); return m }
func arr(v any) []any  { a, _ := v.([]any); return a }
func text(v any) string {
	s, _ := v.(string)
	return s
}
