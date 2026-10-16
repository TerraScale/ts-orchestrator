package foundation

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/command"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
)

const peerUsage = `Usage: ts-orch oci-region peer --pair-intent INTENT --left-plan PLAN --right-plan PLAN --out BOUND_INTENT [--apply]
       ts-orch oci-region peer --pair-intent INTENT --left-plan PLAN --right-plan PLAN --drop-port PORT [--apply]

Creates the OCI private peering of two bound regional plans that
inspect-private-peer reads back: on each side a DRG with the cell VCN
attached, a remote peering connection (RPC) and DRG route tables importing
only the paired attachment; the left RPC connects to the right one; each
cell's route table, controller NSG and security list get the peer subnet's
route and the intent's TCP ports. INTENT may leave its resource OCIDs null.
Without --apply it only prints the changes. With --apply it reads both
sides first, makes the changes, writes BOUND_INTENT with the OCIDs bound and
runs inspect-private-peer's live network checks on it. It never removes or
replaces a rule and never overwrites a different BOUND_INTENT.

--drop-port removes, on both sides, only the controller NSG's ingress rule
for one of the intent's ports from the peer subnet, so new connections on it
cannot take the private path: a failover test. Rerun without it to restore.
`

// RunPeer is `ts-orch oci-region peer`.
func RunPeer(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("oci-region peer", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { io.WriteString(out, peerUsage) }
	intentPath := fs.String("pair-intent", "", "private peer pair intent JSON")
	left := fs.String("left-plan", "", "left bound regional plan; its RPC connects to the right one")
	right := fs.String("right-plan", "", "right bound regional plan")
	outPath := fs.String("out", "", "bound pair intent to write")
	apply := fs.Bool("apply", false, "make the changes; without it, only print them")
	drop := fs.Int("drop-port", 0, "remove both sides' NSG ingress rule for this intent port (failover test)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 || *intentPath == "" || *left == "" || *right == "" || (*outPath == "") == (*drop == 0) {
		return errors.New("usage: ts-orch oci-region peer --pair-intent INTENT --left-plan PLAN --right-plan PLAN (--out BOUND_INTENT | --drop-port PORT) [--apply]")
	}
	engine := &ociregion.Engine{Context: ctx}
	intent, plans, err := engine.PrivatePeerPair(*intentPath, *left, *right)
	if err != nil {
		return err
	}
	p := &Peer{Clients: map[string]command.Client{}, Out: out, Check: func(path string) error { return engine.CheckPrivatePeer(path, *left, *right) }}
	for _, plan := range plans {
		region := text(plan["region"])
		if p.Clients[region], err = publicapi.NewClient(region); err != nil {
			return err
		}
	}
	if *drop != 0 {
		return p.Drop(ctx, intent, plans, *drop, *apply)
	}
	return p.Run(ctx, intent, plans, *outPath, *apply)
}

// peerIDs are the resource OCIDs a pair intent binds per cell.
var peerIDs = []string{"drg_id", "vcn_attachment_id", "rpc_id", "rpc_attachment_id", "vcn_drg_route_table_id", "rpc_drg_route_table_id",
	"vcn_import_distribution_id", "rpc_import_distribution_id"}

// DraftPeerIntent is the pair intent `peer` binds for two bound plans: each
// plan's SHA-256 as inspect-private-peer computes it, the left plan's
// tenancy and realm, a monthly cross-region egress of 10 GB or the plan's
// smaller priced egress reserve, and every resource OCID null.
func DraftPeerIntent(left, right string, ports []int) (Object, error) {
	cells, tenancy := Object{}, ""
	for _, path := range []string{left, right} {
		plan, err := ociregion.LoadPlan(path)
		if err != nil {
			return nil, err
		}
		sum, err := ociregion.SHA256(path)
		if err != nil {
			return nil, err
		}
		reserve, err := strconv.ParseFloat(fmt.Sprint(obj(plan["budget"])["egress_gb_max"]), 64)
		if err != nil {
			return nil, fmt.Errorf("%s prices no egress reserve: %w", path, err)
		}
		row := Object{"plan_sha256": sum, "monthly_cross_region_egress_gb": min(10, reserve)}
		for _, key := range peerIDs {
			row[key] = nil
		}
		cells[text(plan["cell"])] = row
		if tenancy == "" {
			tenancy = text(plan["tenancy_id"])
		}
	}
	realm, _, _ := strings.Cut(strings.TrimPrefix(tenancy, "ocid1.tenancy."), ".")
	return Object{"schema_version": 1, "tenancy_id": tenancy, "realm": realm, "allowed_tcp_ports": ports, "cells": cells}, nil
}

// Peer creates the private peering of a validated pair intent (TS-668).
// Each resource is found by its static name first, so a rerun creates
// nothing and an interrupted run resumes. A same-named resource or a rule
// that inspect-private-peer would reject is refused, never adopted or
// removed.
type Peer struct {
	// Clients serve each plan's OCI region.
	Clients     map[string]command.Client
	BeforeWrite func(context.Context, bool) (context.Context, func(), error)
	Guard       func(context.Context) error
	// Check runs inspect-private-peer's live network checks on the bound
	// intent at path.
	Check        func(path string) error
	Pause        func(context.Context, time.Duration) error
	PollAttempts int
	Out          io.Writer
}

// side is one cell of the pair and the intent row its OCIDs are bound in.
type side struct {
	name, region, compartment string
	plan, ids, row            Object
	c                         command.Client
}

func (s *side) id(key string) string { return text(s.row[key]) }

func (s *side) bind(key string, r Object, err error) error {
	if err != nil {
		return err
	}
	if old := s.row[key]; old != nil && old != r["id"] {
		return fmt.Errorf("pair intent binds %s %s %v, but its live resource is %v", s.name, key, old, r["id"])
	}
	if r != nil {
		s.row[key] = r["id"]
	}
	return nil
}

// Run binds intent's OCIDs for the left and right plans. A dry pass reads
// both sides first, so every refusal comes before a change. With apply it
// then makes the changes, writes the bound intent to out and checks it.
func (p *Peer) Run(ctx context.Context, intent Object, plans []Object, out string, apply bool) error {
	f := &Foundation{Out: p.Out, Pause: p.Pause, PollAttempts: p.PollAttempts, BeforeWrite: p.BeforeWrite, Guard: p.Guard}
	if _, err := p.bind(ctx, f, intent, plans); err != nil {
		return err
	}
	if !apply {
		var err error
		if f.planned == 0 {
			_, err = fmt.Fprintln(p.Out, "no changes")
		} else {
			_, err = fmt.Fprintf(p.Out, "%d changes planned; rerun with --apply to make them\n", f.planned)
		}
		return err
	}
	f.Apply = true
	bound, err := p.bind(ctx, f, intent, plans)
	if err != nil {
		return err
	}
	if err := write(out, bound, p.Out); err != nil {
		return err
	}
	if err := p.Check(out); err != nil {
		return fmt.Errorf("the bound pair intent %s fails inspection: %w", out, err)
	}
	return nil
}

// Drop removes, on both sides, the controller NSG's ingress rules admitting
// TCP port from the peer subnet. It touches no other rule; a rerun of Run
// adds them back.
func (p *Peer) Drop(ctx context.Context, intent Object, plans []Object, port int, apply bool) error {
	want := strconv.Itoa(port)
	if !slices.ContainsFunc(arr(intent["allowed_tcp_ports"]), func(v any) bool { return fmt.Sprint(v) == want }) {
		return fmt.Errorf("TCP %d is not a port of the pair intent", port)
	}
	f := &Foundation{Out: p.Out, Apply: apply, BeforeWrite: p.BeforeWrite, Guard: p.Guard}
	for i, plan := range plans {
		name, err := naming.RegionCell(text(plan["cell"])).Name()
		if err != nil {
			return err
		}
		subnet, nsg, c := text(plans[1-i]["subnet_cidr"]), text(obj(plan["resource_ids"])["network_security_group"]), p.Clients[text(plan["region"])]
		v, err := f.call(ctx, c, "network", "nsg", "rules", "list", "--nsg-id", nsg, "--all")
		if err != nil {
			return fmt.Errorf("read %s's NSG rules: %w", name, err)
		}
		live, err := command.Rows(v)
		if err != nil {
			return err
		}
		var ids []string
		for _, r := range live {
			ports := obj(obj(r["tcp-options"])["destination-port-range"])
			if r["direction"] == "INGRESS" && r["source"] == subnet && r["protocol"] == "6" &&
				fmt.Sprint(ports["min"]) == want && fmt.Sprint(ports["max"]) == want {
				ids = append(ids, text(r["id"]))
			}
		}
		if len(ids) == 0 {
			fmt.Fprintf(p.Out, "%s's NSG has no TCP %d rule from %s\n", name, port, subnet)
			continue
		}
		if err := f.change(ctx, fmt.Sprintf("remove TCP %d from %s in %s's NSG", port, subnet, name), c,
			"network", "nsg", "rules", "remove", "--nsg-id", nsg, "--security-rule-ids", command.JSON(ids)); err != nil {
			return err
		}
	}
	if !apply && f.planned > 0 {
		_, err := fmt.Fprintf(p.Out, "%d changes planned; rerun with --apply to make them\n", f.planned)
		return err
	}
	return nil
}

func (p *Peer) bind(ctx context.Context, f *Foundation, intent Object, plans []Object) (Object, error) {
	sides := make([]*side, len(plans))
	cells := Object{}
	for i, plan := range plans {
		name, err := naming.RegionCell(text(plan["cell"])).Name()
		if err != nil {
			return nil, err
		}
		ids := obj(plan["resource_ids"])
		row := maps.Clone(obj(obj(intent["cells"])[text(plan["cell"])]))
		sides[i] = &side{name: name, region: text(plan["region"]), compartment: text(ids["network_compartment"]), plan: plan, ids: ids, row: row, c: p.Clients[text(plan["region"])]}
		cells[text(plan["cell"])] = row
	}
	for i, s := range sides {
		if err := p.drg(ctx, f, s, sides[1-i]); err != nil {
			return nil, err
		}
	}
	if err := p.connect(ctx, f, sides[0], sides[1]); err != nil {
		return nil, err
	}
	for i, s := range sides {
		if err := p.rules(ctx, f, s, sides[1-i], arr(intent["allowed_tcp_ports"])); err != nil {
			return nil, err
		}
	}
	bound := maps.Clone(intent)
	bound["cells"] = cells
	return bound, nil
}

// change makes one write, or in a dry run only prints it.
func (f *Foundation) change(ctx context.Context, what string, c command.Client, args ...string) error {
	if !f.Apply {
		f.planned++
		_, err := fmt.Fprintln(f.Out, "plan: "+what)
		return err
	}
	if _, err := f.call(ctx, c, args...); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	_, err := fmt.Fprintln(f.Out, "done: "+what)
	return err
}

// drg finds or creates the side's DRG, RPC, import distributions, DRG route
// tables and attachments, and scopes each import to the other attachment.
func (p *Peer) drg(ctx context.Context, f *Foundation, s, peer *side) error {
	nc, vcn := s.compartment, text(s.ids["vcn"])
	name := s.name + "-drg"
	r, err := f.ensure(ctx, "DRG "+name, f.find(s.c, "display-name", name, "network", "drg", "list", "--compartment-id", nc, "--all"),
		f.create(s.c, "network", "drg", "create", "--compartment-id", nc, "--display-name", name, "--wait-for-state", "AVAILABLE"),
		func(r Object) bool { return r["compartment-id"] == nc })
	if err := s.bind("drg_id", r, err); err != nil {
		return err
	}
	drg := s.id("drg_id")
	rpc := s.name + "-rpc-" + peer.name
	r, err = f.ensure(ctx, "RPC "+rpc, f.find(s.c, "display-name", rpc, "network", "remote-peering-connection", "list", "--compartment-id", nc, "--drg-id", drg, "--all"),
		f.create(s.c, "network", "remote-peering-connection", "create", "--compartment-id", nc, "--drg-id", drg, "--display-name", rpc, "--wait-for-state", "AVAILABLE"),
		func(r Object) bool { return r["compartment-id"] == nc && r["drg-id"] == drg })
	if err := s.bind("rpc_id", r, err); err != nil {
		return err
	}
	for _, role := range []string{"vcn", "rpc"} {
		name := s.name + "-drg-" + role + "-import"
		r, err := f.ensure(ctx, "DRG import distribution "+name, f.find(s.c, "display-name", name, "network", "drg-route-distribution", "list", "--drg-id", drg, "--all"),
			f.create(s.c, "network", "drg-route-distribution", "create", "--drg-id", drg, "--distribution-type", "IMPORT", "--display-name", name, "--wait-for-state", "AVAILABLE"),
			func(r Object) bool { return r["drg-id"] == drg && r["distribution-type"] == "IMPORT" })
		if err := s.bind(role+"_import_distribution_id", r, err); err != nil {
			return err
		}
		distribution := s.id(role + "_import_distribution_id")
		name = s.name + "-drg-" + role + "-routes"
		r, err = f.ensure(ctx, "DRG route table "+name, f.find(s.c, "display-name", name, "network", "drg-route-table", "list", "--drg-id", drg, "--all"),
			f.create(s.c, "network", "drg-route-table", "create", "--drg-id", drg, "--display-name", name, "--import-route-distribution-id", distribution,
				"--is-ecmp-enabled", "false", "--wait-for-state", "AVAILABLE"),
			func(r Object) bool {
				return r["drg-id"] == drg && r["import-drg-route-distribution-id"] == distribution && r["is-ecmp-enabled"] == false
			})
		if err := s.bind(role+"_drg_route_table_id", r, err); err != nil {
			return err
		}
	}
	attachments := func(kind string) []string {
		return []string{"network", "drg-attachment", "list", "--compartment-id", nc, "--drg-id", drg, "--attachment-type", kind, "--all"}
	}
	vcnTable, rpcTable := s.id("vcn_drg_route_table_id"), s.id("rpc_drg_route_table_id")
	name = s.name + "-vcn-attachment"
	r, err = f.ensure(ctx, "DRG attachment "+name, f.find(s.c, "display-name", name, attachments("VCN")...),
		f.create(s.c, "network", "drg-attachment", "create", "--drg-id", drg, "--display-name", name, "--network-details", command.JSON(Object{"type": "VCN", "id": vcn}),
			"--drg-route-table-id", vcnTable, "--wait-for-state", "ATTACHED"),
		func(r Object) bool {
			network := obj(r["network-details"])
			return network["type"] == "VCN" && network["id"] == vcn && r["drg-route-table-id"] == vcnTable
		})
	if err := s.bind("vcn_attachment_id", r, err); err != nil {
		return err
	}

	// OCI attaches a new RPC to the DRG's default RPC route table.
	var attachment Object
	if id := s.id("rpc_id"); id != "" {
		v, err := f.call(ctx, s.c, attachments("REMOTE_PEERING_CONNECTION")...)
		var rows []map[string]any
		if err == nil {
			rows, err = command.Rows(v)
		}
		if err != nil {
			return fmt.Errorf("read the attachment of RPC %s: %w", rpc, err)
		}
		for _, a := range rows {
			if obj(a["network-details"])["id"] == id {
				attachment = a
			}
		}
		if attachment == nil {
			return fmt.Errorf("RPC %s has no DRG attachment yet; rerun", rpc)
		}
	}
	if err := s.bind("rpc_attachment_id", attachment, nil); err != nil {
		return err
	}
	if attachment == nil || attachment["drg-route-table-id"] != rpcTable {
		if err := f.change(ctx, "route the attachment of RPC "+rpc+" through "+s.name+"-drg-rpc-routes", s.c,
			"network", "drg-attachment", "update", "--drg-attachment-id", s.id("rpc_attachment_id"), "--drg-route-table-id", rpcTable); err != nil {
			return err
		}
	}

	for _, role := range []string{"vcn", "rpc"} {
		name := s.name + "-drg-" + role + "-import"
		distribution, accepted, other := s.id(role+"_import_distribution_id"), s.id("rpc_attachment_id"), "RPC"
		if role == "rpc" {
			accepted, other = s.id("vcn_attachment_id"), "VCN"
		}
		var statements []map[string]any
		if distribution != "" {
			v, err := f.call(ctx, s.c, "network", "drg-route-distribution-statement", "list", "--route-distribution-id", distribution, "--all")
			if err == nil {
				statements, err = command.Rows(v)
			}
			if err != nil {
				return fmt.Errorf("read the statements of %s: %w", name, err)
			}
		}
		switch {
		case len(statements) == 1 && accepts(statements[0], accepted):
		case len(statements) == 0:
			statement := []any{Object{"action": "ACCEPT", "priority": 1, "matchCriteria": []any{Object{"matchType": "DRG_ATTACHMENT_ID", "drgAttachmentId": accepted}}}}
			if err := f.change(ctx, "import only the "+other+" attachment's routes in "+name, s.c,
				"network", "drg-route-distribution-statement", "add", "--route-distribution-id", distribution, "--statements", command.JSON(statement)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s holds statements inspect-private-peer rejects; inspect it before rerunning", name)
		}
	}
	return nil
}

// accepts reports whether a distribution statement imports exactly one
// attachment's routes.
func accepts(statement map[string]any, attachment string) bool {
	criteria, err := command.Rows(statement["match-criteria"])
	return err == nil && statement["action"] == "ACCEPT" && len(criteria) == 1 && len(criteria[0]) == 2 &&
		criteria[0]["match-type"] == "DRG_ATTACHMENT_ID" && criteria[0]["drg-attachment-id"] == attachment
}

// connect peers the two RPCs from the left side, then waits until both
// read PEERED with each other.
func (p *Peer) connect(ctx context.Context, f *Foundation, l, r *side) error {
	what := "connect RPC " + l.name + "-rpc-" + r.name + " to " + r.name + "-rpc-" + l.name + " in " + r.region
	args := []string{"network", "remote-peering-connection", "connect", "--remote-peering-connection-id", l.id("rpc_id"), "--peer-id", r.id("rpc_id"), "--peer-region-name", r.region}
	if l.id("rpc_id") == "" || r.id("rpc_id") == "" {
		return f.change(ctx, what, l.c, args...)
	}
	read := func() (Object, Object, error) {
		a, err := f.data(ctx, l.c, "network", "remote-peering-connection", "get", "--remote-peering-connection-id", l.id("rpc_id"))
		if err != nil {
			return nil, nil, err
		}
		b, err := f.data(ctx, r.c, "network", "remote-peering-connection", "get", "--remote-peering-connection-id", r.id("rpc_id"))
		return a, b, err
	}
	peered := func(a, b Object) bool {
		return a["peering-status"] == "PEERED" && a["peer-id"] == r.id("rpc_id") && b["peering-status"] == "PEERED" && b["peer-id"] == l.id("rpc_id")
	}
	a, b, err := read()
	if err != nil {
		return fmt.Errorf("read the RPCs: %w", err)
	}
	switch {
	case peered(a, b):
		return nil
	case a["peering-status"] == "NEW" && b["peering-status"] == "NEW":
		if err := f.change(ctx, what, l.c, args...); err != nil || !f.Apply {
			return err
		}
	case a["peering-status"] == "PENDING" || b["peering-status"] == "PENDING":
		if !f.Apply {
			return nil
		}
	default:
		return fmt.Errorf("RPCs %s-rpc-%s (%v) and %s-rpc-%s (%v) are not peered with each other; inspect them before rerunning",
			l.name, r.name, a["peering-status"], r.name, l.name, b["peering-status"])
	}
	attempts, pause := f.PollAttempts, f.Pause
	if attempts <= 0 {
		attempts = 60
	}
	if pause == nil {
		pause = command.Pause
	}
	for n := 1; ; n++ {
		if a, b, err = read(); err != nil {
			return fmt.Errorf("read the RPCs: %w", err)
		}
		if peered(a, b) {
			return nil
		}
		if n == attempts {
			return fmt.Errorf("RPCs %s-rpc-%s and %s-rpc-%s did not peer", l.name, r.name, r.name, l.name)
		}
		if err := pause(ctx, 10*time.Second); err != nil {
			return err
		}
	}
}

// rules adds the peer subnet's route through the DRG to the cell's subnet
// route table and the intent's ports from and to the peer subnet to its NSG
// and security list, judging the live rules as inspect-private-peer does:
// rules unrelated to the peer VCN are kept and never required to match the
// plan. OCI replaces a route table's or security list's rules as a whole, so
// an update resends every live rule as read with the missing ones appended,
// and only if the object is unchanged since that read (If-Match).
func (p *Peer) rules(ctx context.Context, f *Foundation, s, peer *side, ports []any) error {
	subnet, vcn := text(peer.plan["subnet_cidr"]), text(s.ids["vcn"])
	rt, sl, nsg := text(s.ids["route_table"]), text(s.ids["security_list"]), text(s.ids["network_security_group"])
	inVCN := func(r Object) bool { return r["compartment-id"] == s.compartment && r["vcn-id"] == vcn }
	cell, err := f.data(ctx, s.c, "network", "subnet", "get", "--subnet-id", text(s.ids["subnet"]))
	if err != nil {
		return fmt.Errorf("read %s's subnet: %w", s.name, err)
	}
	if !inVCN(cell) || cell["route-table-id"] != rt || command.JSON(cell["security-list-ids"]) != command.JSON([]string{sl}) {
		return fmt.Errorf("%s's subnet does not use the plan's route table and security list; inspect it before rerunning", s.name)
	}
	read := func(what string, args ...string) (Object, string, error) {
		r, err := s.c.Call(ctx, args...)
		if err != nil {
			return nil, "", fmt.Errorf("read %s: %w", what, err)
		}
		data, err := command.Object(r["data"])
		if err == nil && !inVCN(data) {
			err = fmt.Errorf("%s belongs to another VCN or compartment", what)
		}
		etag, _ := r["etag"].(string)
		if err == nil && f.Apply && etag == "" {
			err = fmt.Errorf("the read of %s carries no ETag; its full-list update is refused without one", what)
		}
		return data, etag, err
	}
	table, tableTag, err := read(s.name+"'s route table", "network", "route-table", "get", "--rt-id", rt)
	if err != nil {
		return err
	}
	nsgRules, err := f.call(ctx, s.c, "network", "nsg", "rules", "list", "--nsg-id", nsg, "--all")
	if err != nil {
		return fmt.Errorf("read %s's NSG rules: %w", s.name, err)
	}
	list, listTag, err := read(s.name+"'s security list", "network", "security-list", "get", "--security-list-id", sl)
	if err != nil {
		return err
	}
	routes, ingress, egress, err := ociregion.PrivatePeerMissing(s.plan, peer.plan, s.id("drg_id"), ports, table["route-rules"], nsgRules,
		list["ingress-security-rules"], list["egress-security-rules"])
	if err != nil {
		return fmt.Errorf("%s: %w; inspect it before rerunning", s.name, err)
	}

	if len(routes) > 0 {
		live, err := command.Rows(table["route-rules"])
		if err != nil {
			return err
		}
		all := []any{}
		for _, r := range live {
			route := Object{"destination": r["destination"], "destinationType": r["destination-type"], "networkEntityId": r["network-entity-id"]}
			if r["description"] != nil {
				route["description"] = r["description"]
			}
			all = append(all, route)
		}
		for _, v := range routes {
			r := obj(v)
			all = append(all, Object{"destination": r["destination"], "destinationType": r["destination_type"], "networkEntityId": r["network_entity_id"]})
		}
		if err := f.change(ctx, "route "+subnet+" through "+s.name+"-drg in "+s.name+"'s route table", s.c,
			"network", "route-table", "update", "--rt-id", rt, "--route-rules", command.JSON(all), "--if-match", tableTag); err != nil {
			return err
		}
	}
	if len(ingress) > 0 {
		if err := f.change(ctx, fmt.Sprintf("allow %d TCP ports from %s in %s's NSG", len(ingress), subnet, s.name), s.c,
			"network", "nsg", "rules", "add", "--nsg-id", nsg, "--security-rules", command.JSON(rules(ingress, true))); err != nil {
			return err
		}
	}
	if len(egress) == 0 {
		return nil
	}
	all := append(arr(camel(list["egress-security-rules"])), rules(egress, false)...)
	return f.change(ctx, fmt.Sprintf("allow %d TCP ports to %s in %s's security list", len(egress), subnet, s.name), s.c,
		"network", "security-list", "update", "--security-list-id", sl, "--egress-security-rules", command.JSON(all), "--if-match", listTag)
}

// camel turns a read's kebab-case members back into the API's camelCase, so
// a live rule is resent as it was read.
func camel(v any) any {
	switch x := v.(type) {
	case Object:
		r := Object{}
		for k, v := range x {
			parts := strings.Split(k, "-")
			for i := 1; i < len(parts); i++ {
				parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
			}
			r[strings.Join(parts, "")] = camel(v)
		}
		return r
	case []any:
		r := make([]any, len(x))
		for i, v := range x {
			r[i] = camel(v)
		}
		return r
	}
	return v
}
