package foundation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/command"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
)

const gru = home

// pair is SFO (left) and GRU (right), each with the private network
// `oci-region foundation` creates plus the live rules no plan carries, bound
// plans and a draft pair intent whose resource OCIDs are null. Both cells
// have the fixed NAT default route; GRU also keeps its operator gateway LPG
// route and SFO has the historical scoped HTTPS additions (TS-640).
type pair struct {
	f                        *fakeOCI
	intent, left, right, out string
	plans                    map[string]Object
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	wire, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0o644); err != nil {
		t.Fatal(err)
	}
}

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func newPair(t *testing.T) *pair {
	t.Helper()
	f := newFake()
	dir := t.TempDir()
	x := &pair{f: f, intent: filepath.Join(dir, "pair-intent.json"), out: filepath.Join(dir, "bound-pair-intent.json"), plans: map[string]Object{}}
	gruPlan, err := ociregion.LoadPlan(filepath.Join("..", "..", "..", "deploy", "oci-region", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i, plan := range []Object{loadPlan(t), gruPlan} {
		delete(plan, "_source_path")
		region, cell := text(plan["region"]), text(plan["cell"])
		name, err := naming.RegionCell(cell).Name()
		if err != nil {
			t.Fatal(err)
		}
		ids := obj(clone(plan["resource_ids"]))
		for _, role := range []string{"control", "network", "workload"} {
			ids[role+"_compartment"] = f.add("compartment", "", Object{"name": name + "-" + role})
		}
		foundation := &Foundation{Region: client{f, region}, Apply: true, Out: io.Discard, BeforeWrite: allowWrite, Guard: allowGuard}
		bind := func(key string, r Object) error { ids[key] = r["id"]; return nil }
		networkPlan := clone(plan).(Object)
		if cell == "GRU" {
			// The operator peering is attached after the private foundation.
			obj(networkPlan["network_security"])["route_rules"] = arr(obj(networkPlan["network_security"])["route_rules"])[:2]
		}
		if err := foundation.network(t.Context(), networkPlan, name, text(ids["network_compartment"]), bind, func(key string) string { return text(ids[key]) }); err != nil {
			t.Fatal(err)
		}
		for key, kind := range map[string]string{"vault": "vault", "key": "key"} {
			ids[key] = "ocid1." + kind + ".oc1." + region + "." + name[:3]
		}
		for key, kind := range map[string]string{"controller_dynamic_group": "dynamicgroup", "host_dynamic_group": "dynamicgroup", "controller_policy": "policy", "objectstorage_key_policy": "policy"} {
			ids[key] = "ocid1." + kind + ".oc1.." + name[:3] + strings.ReplaceAll(key, "_", "")
		}
		table, list := f.rows[text(ids["route_table"])].data, f.rows[text(ids["security_list"])].data
		https := func(cidr string) Object {
			return Object{"destination": cidr, "destination-type": "CIDR_BLOCK", "protocol": "6", "is-stateless": false,
				"tcp-options": Object{"destination-port-range": Object{"min": 443, "max": 443}}}
		}
		if cell == "GRU" {
			ids["local_peering_gateway"] = "ocid1.localpeeringgateway.oc1." + region + ".cell"
			obj(plan["operator_gateway"])["local_peering_gateway_id"] = "ocid1.localpeeringgateway.oc1." + region + ".operator"
			netbird := obj(plan["netbird"])
			netbird["secret_compartment_id"], netbird["setup_key_secret_id"], netbird["policy_id"] = ids["control_compartment"],
				"ocid1.vaultsecret.oc1."+region+".netbird", "ocid1.policy.oc1..netbird"
			table["route-rules"] = append(arr(table["route-rules"]), Object{"destination": "10.250.10.155/32", "destination-type": "CIDR_BLOCK",
				"network-entity-id": ids["local_peering_gateway"], "description": "operator gateway"})
		} else {
			list["egress-security-rules"] = append(arr(list["egress-security-rules"]), https("173.245.48.0/20"), https("104.16.0.0/13"), https("100.64.10.10/32"))
		}
		plan["resource_ids"] = ids
		path := filepath.Join(dir, name+"-plan.json")
		writeJSON(t, path, plan)
		if i == 0 {
			x.left = path
		} else {
			x.right = path
		}
		x.plans[cell] = plan
	}
	intent, err := DraftPeerIntent(x.left, x.right, []int{7422})
	if err != nil {
		t.Fatal(err)
	}
	writeJSON(t, x.intent, intent)
	f.peer = f.peering(text(x.plans["GRU"]["tenancy_id"]))
	f.writes, f.args = nil, nil
	return x
}

// peering serves the peering's actions: import statements, the dynamic DRG
// routes they import, RPC connection and the ETag-guarded full-list updates.
func (f *fakeOCI) peering(tenancy string) func(string, sdkcli.Command) (any, bool, error) {
	statements := map[string][]any{}
	// advertised are the CIDRs an attachment exports into its DRG: a VCN's
	// own, or the VCN routes the peer DRG imports for its peered RPC.
	var advertised func(attachment string, remote bool) []any
	advertised = func(attachment string, remote bool) []any {
		network := obj(f.rows[attachment].data["network-details"])
		target := f.rows[text(network["id"])]
		if network["type"] == "VCN" {
			return []any{target.data["cidr-block"]}
		}
		if remote || target.data["peering-status"] != "PEERED" {
			return nil
		}
		var cidrs []any
		for _, a := range f.find("drg-attachment", text(target.data["peer-region-name"]), func(o Object) bool { return obj(o["network-details"])["id"] == target.data["peer-id"] }) {
			table := f.rows[text(a.data["drg-route-table-id"])]
			if table == nil {
				continue
			}
			for _, s := range statements[text(table.data["import-drg-route-distribution-id"])] {
				for _, c := range arr(obj(s)["match-criteria"]) {
					cidrs = append(cidrs, advertised(text(obj(c)["drg-attachment-id"]), true)...)
				}
			}
		}
		return cidrs
	}
	return func(region string, c sdkcli.Command) (any, bool, error) {
		flags := c.Flags
		switch c.Path {
		case "network drg-route-distribution-statement add":
			id := flags["route-distribution-id"]
			for _, s := range kebab(decode([]byte(flags["statements"]))).([]any) {
				f.seq++
				s.(Object)["id"] = fmt.Sprintf("statement%d", f.seq)
				statements[id] = append(statements[id], s)
			}
			return clone(statements[id]), true, nil
		case "network drg-route-distribution-statement list":
			return clone(append([]any{}, statements[flags["route-distribution-id"]]...)), true, nil
		case "network drg-route-rule list":
			routes := []any{}
			table := f.rows[flags["drg-route-table-id"]].data
			for _, s := range statements[text(table["import-drg-route-distribution-id"])] {
				for _, c := range arr(obj(s)["match-criteria"]) {
					attachment := text(obj(c)["drg-attachment-id"])
					for _, cidr := range advertised(attachment, false) {
						routes = append(routes, Object{"destination": cidr, "destination-type": "CIDR_BLOCK", "next-hop-drg-attachment-id": attachment,
							"route-type": "DYNAMIC", "is-conflict": false, "is-blackhole": false})
					}
				}
			}
			return clone(routes), true, nil
		case "network drg-attachment update":
			r := f.rows[flags["drg-attachment-id"]]
			r.data["drg-route-table-id"] = flags["drg-route-table-id"]
			return clone(r.data), true, nil
		case "network remote-peering-connection connect":
			a, b := f.rows[flags["remote-peering-connection-id"]], f.rows[flags["peer-id"]]
			if a == nil || b == nil || a.region != region || b.region != flags["peer-region-name"] {
				return nil, true, errors.New("404 NotAuthorizedOrNotFound")
			}
			for _, x := range [][2]*row{{a, b}, {b, a}} {
				x[0].data["peering-status"], x[0].data["peer-id"], x[0].data["peer-region-name"], x[0].data["peer-tenancy-id"] = "PEERED", x[1].data["id"], x[1].region, tenancy
			}
			return Object{}, true, nil
		case "network route-table update", "network security-list update":
			id, key := flags["rt-id"], "route-rules"
			if c.Path == "network security-list update" {
				id, key = flags["security-list-id"], "egress-security-rules"
			}
			r := f.rows[id]
			if flags["if-match"] != r.data["etag"] {
				return nil, true, errors.New("412 PreconditionFailed")
			}
			r.data[key] = kebab(decode([]byte(flags[key])))
			r.data["etag"] = fmt.Sprint(r.data["etag"], "+")
			return clone(r.data), true, nil
		}
		return nil, false, nil
	}
}

func (x *pair) run(t *testing.T, apply bool) (string, error) {
	t.Helper()
	var log bytes.Buffer
	engine := &ociregion.Engine{Context: t.Context(), Dependency: x.f.dependency}
	intent, plans, err := engine.PrivatePeerPair(x.intent, x.left, x.right)
	if err != nil {
		return "", err
	}
	p := &Peer{Clients: map[string]command.Client{sfo: client{x.f, sfo}, gru: client{x.f, gru}}, Out: &log, BeforeWrite: allowWrite, Guard: allowGuard,
		Pause: func(context.Context, time.Duration) error { return nil },
		Check: func(path string) error { return engine.CheckPrivatePeer(path, x.left, x.right) }}
	err = p.Run(t.Context(), intent, plans, x.out, apply)
	return log.String(), err
}

// peerWrites are the writes a first apply makes, each once, in order.
func peerWrites() []string {
	var w []string
	for _, region := range []string{sfo, gru} {
		w = append(w, region+" network drg create", region+" network remote-peering-connection create")
		for range 2 {
			w = append(w, region+" network drg-route-distribution create", region+" network drg-route-table create")
		}
		w = append(w, region+" network drg-attachment create", region+" network drg-attachment update",
			region+" network drg-route-distribution-statement add", region+" network drg-route-distribution-statement add")
	}
	w = append(w, sfo+" network remote-peering-connection connect")
	for _, region := range []string{sfo, gru} {
		w = append(w, region+" network route-table update", region+" network nsg rules add", region+" network security-list update")
	}
	return w
}

func TestPeerDryRunPlansEveryChangeAndWritesNothing(t *testing.T) {
	x := newPair(t)
	log, err := x.run(t, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(x.f.writes) != 0 {
		t.Fatalf("dry run wrote %v", x.f.writes)
	}
	if _, err := os.Stat(x.out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run wrote the bound intent: %v", err)
	}
	for _, want := range []string{"plan: create DRG sfo-1-drg", "plan: create RPC gru-1-rpc-sfo-1", "plan: create DRG route table gru-1-drg-rpc-routes",
		"plan: connect RPC sfo-1-rpc-gru-1 to gru-1-rpc-sfo-1 in sa-saopaulo-1", "plan: route 10.252.0.0/25 through gru-1-drg in gru-1's route table",
		fmt.Sprintf("%d changes planned", len(peerWrites()))} {
		if !strings.Contains(log, want) {
			t.Fatalf("dry run output lacks %q:\n%s", want, log)
		}
	}
}

func TestPeerApplyPassesInspectionThenRerunIsANoOp(t *testing.T) {
	x := newPair(t)
	if log, err := x.run(t, true); err != nil {
		t.Fatalf("%v\n%s", err, log)
	}
	if got := x.f.writes; !slices.Equal(got, peerWrites()) {
		t.Fatalf("first apply wrote\n%v\nwant\n%v", got, peerWrites())
	}
	// The in-binary SDK client accepts every write exactly as sent.
	for _, args := range x.f.args {
		if err := publicapi.DecodeCreate(args); err != nil {
			t.Fatal(err)
		}
	}
	// Run already checked the bound intent; it binds every OCID.
	bound := decode(mustRead(t, x.out)).(Object)
	for cell, row := range obj(bound["cells"]) {
		for key, id := range obj(row) {
			if strings.HasSuffix(key, "_id") && !strings.HasPrefix(text(id), "ocid1.") {
				t.Fatalf("%s %s is unbound: %v", cell, key, id)
			}
		}
	}
	before := mustRead(t, x.out)
	x.f.writes = nil
	log, err := x.run(t, true)
	if err != nil || len(x.f.writes) != 0 || !strings.Contains(log, "unchanged: "+x.out) {
		t.Fatalf("rerun: err %v, writes %v, output:\n%s", err, x.f.writes, log)
	}
	if !bytes.Equal(before, mustRead(t, x.out)) {
		t.Fatal("rerun changed the bound intent")
	}
	if log, err := x.run(t, false); err != nil || !strings.Contains(log, "no changes") {
		t.Fatalf("dry run after apply: %v\n%s", err, log)
	}
	// The bound intent is a valid draft too: a rerun from it binds the same.
	if err := os.Rename(x.out, x.intent); err != nil {
		t.Fatal(err)
	}
	if log, err := x.run(t, false); err != nil || !strings.Contains(log, "no changes") {
		t.Fatalf("dry run from the bound intent: %v\n%s", err, log)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// The full-list updates resend every live rule as read, including the rules
// no plan carries, and only against the ETag of that read.
func TestPeerKeepsEveryExistingRule(t *testing.T) {
	x := newPair(t)
	type snapshot struct{ table, list, routes, ingress, egress any }
	before := map[string]snapshot{}
	for cell, plan := range x.plans {
		ids := obj(plan["resource_ids"])
		table, list := x.f.rows[text(ids["route_table"])].data, x.f.rows[text(ids["security_list"])].data
		if cell == "GRU" {
			obj(arr(table["route-rules"])[0])["description"] = "Oracle services, kept as written"
		}
		before[cell] = snapshot{table, list, clone(table["route-rules"]), clone(list["ingress-security-rules"]), clone(list["egress-security-rules"])}
	}
	if _, err := x.run(t, true); err != nil {
		t.Fatal(err)
	}
	bound := obj(decode(mustRead(t, x.out)).(Object)["cells"])
	for cell, b := range before {
		peer := map[string]string{"GRU": "10.252.0.0/25", "SFO": "10.251.0.0/25"}[cell]
		want := append(arr(b.routes), Object{"destination": peer, "destination-type": "CIDR_BLOCK", "network-entity-id": obj(bound[cell])["drg_id"]})
		if got := obj(b.table)["route-rules"]; command.JSON(got) != command.JSON(want) {
			t.Fatalf("%s route rules\n%s\nwant\n%s", cell, command.JSON(got), command.JSON(want))
		}
		egress := arr(obj(b.list)["egress-security-rules"])
		if kept := arr(b.egress); command.JSON(egress[:len(kept)]) != command.JSON(kept) || len(egress) != len(kept)+1 {
			t.Fatalf("%s egress rules\n%s\nkept\n%s", cell, command.JSON(egress), command.JSON(kept))
		}
		if command.JSON(obj(b.list)["ingress-security-rules"]) != command.JSON(b.ingress) {
			t.Fatalf("%s ingress rules changed", cell)
		}
	}
	for _, args := range x.f.args {
		if strings.Contains(strings.Join(args, " "), " update --rt-id ") || slices.Contains(args, "--security-list-id") {
			if i := slices.Index(args, "--if-match"); i < 0 || args[i+1] != "1" {
				t.Fatalf("full-list update without the read's ETag: %v", args)
			}
		}
	}
}

func TestPeerRefusesBeforeAnyChange(t *testing.T) {
	for name, test := range map[string]struct {
		setup func(*pair)
		want  string
	}{
		"same-named DRG route table with ECMP": {func(x *pair) {
			network := obj(x.plans["GRU"]["resource_ids"])["network_compartment"]
			drg := x.f.add("drg", gru, Object{"display-name": "gru-1-drg", "compartment-id": network})
			x.f.add("drg-route-table", gru, Object{"display-name": "gru-1-drg-vcn-routes", "drg-id": drg, "compartment-id": network, "is-ecmp-enabled": true})
		}, "DRG route table gru-1-drg-vcn-routes exists but differs from the plan"},
		"route to the peer subnet through another gateway": {func(x *pair) {
			table := x.f.rows[text(obj(x.plans["GRU"]["resource_ids"])["route_table"])].data
			table["route-rules"] = append(arr(table["route-rules"]), Object{"destination": "10.252.0.0/25", "destination-type": "CIDR_BLOCK",
				"network-entity-id": "ocid1.localpeeringgateway.oc1.sa-saopaulo-1.other"})
		}, "gru-1: live reciprocal subnet route table: a rule reaches the peer VCN"},
		"NSG rule from anywhere": {func(x *pair) {
			nsg := text(obj(x.plans["SFO"]["resource_ids"])["network_security_group"])
			x.f.nsgRules[nsg] = append(x.f.nsgRules[nsg], Object{"direction": "INGRESS", "protocol": "6", "source": "0.0.0.0/0", "source-type": "CIDR_BLOCK",
				"is-stateless": false, "tcp-options": Object{"destination-port-range": Object{"min": 7422, "max": 7422}}})
		}, "sfo-1: live peer NSG rules: a rule reaches the peer VCN"},
	} {
		t.Run(name, func(t *testing.T) {
			x := newPair(t)
			test.setup(x)
			if _, err := x.run(t, true); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err %v, want %q", err, test.want)
			}
			if len(x.f.writes) != 0 {
				t.Fatalf("refused run wrote %v", x.f.writes)
			}
		})
	}
}

func TestPeerRefusesOverlappingCells(t *testing.T) {
	x := newPair(t)
	// gru-1 renumbered into sfo-1's 10.252.0.0/24.
	wire := bytes.ReplaceAll(mustRead(t, x.right), []byte("10.251."), []byte("10.252."))
	if err := os.WriteFile(x.right, wire, 0o644); err != nil {
		t.Fatal(err)
	}
	intent := decode(mustRead(t, x.intent)).(Object)
	obj(obj(intent["cells"])["GRU"])["plan_sha256"] = fileSHA(t, x.right)
	writeJSON(t, x.intent, intent)
	// RunPeer refuses before it builds an OCI client.
	err := RunPeer(t.Context(), []string{"--pair-intent", x.intent, "--left-plan", x.left, "--right-plan", x.right, "--out", x.out, "--apply"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "CIDRs must not overlap") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(x.out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused run wrote the bound intent")
	}
}

func TestInterruptedPeerResumes(t *testing.T) {
	for _, step := range []string{"network drg-attachment create", "network remote-peering-connection connect", "network security-list update"} {
		t.Run(step, func(t *testing.T) {
			x := newPair(t)
			x.f.failOn = step
			if _, err := x.run(t, true); err == nil {
				t.Fatal("interrupted run succeeded")
			}
			if _, err := x.run(t, true); err != nil {
				t.Fatal(err)
			}
			got := x.f.writes
			i := slices.IndexFunc(got, func(w string) bool { return strings.HasSuffix(w, " "+step) })
			if got = slices.Delete(slices.Clone(got), i, i+1); !slices.Equal(got, peerWrites()) {
				t.Fatalf("resumed writes\n%v\nwant\n%v", got, peerWrites())
			}
		})
	}
}

// A failover test drops one port's NSG ingress rule on both sides and
// nothing else; the next apply restores exactly those rules.
func TestPeerDropPortRemovesOnlyThatRule(t *testing.T) {
	x := newPair(t)
	intent := decode(mustRead(t, x.intent)).(Object)
	intent["allowed_tcp_ports"] = []any{7422, 9443}
	writeJSON(t, x.intent, intent)
	if log, err := x.run(t, true); err != nil {
		t.Fatalf("%v\n%s", err, log)
	}
	rules := func() map[string][]any {
		r := map[string][]any{}
		for cell, plan := range x.plans {
			r[cell] = clone(x.f.nsgRules[text(obj(plan["resource_ids"])["network_security_group"])]).([]any)
		}
		return r
	}
	before := rules()
	drop := func(port int, apply bool) string {
		t.Helper()
		var log bytes.Buffer
		engine := &ociregion.Engine{Context: t.Context(), Dependency: x.f.dependency}
		intent, plans, err := engine.PrivatePeerPair(x.intent, x.left, x.right)
		if err != nil {
			t.Fatal(err)
		}
		p := &Peer{Clients: map[string]command.Client{sfo: client{x.f, sfo}, gru: client{x.f, gru}}, Out: &log, BeforeWrite: allowWrite, Guard: allowGuard}
		if err := p.Drop(t.Context(), intent, plans, port, apply); err != nil {
			t.Fatalf("drop %d: %v\n%s", port, err, log.String())
		}
		return log.String()
	}
	x.f.writes = nil
	if log := drop(7422, false); len(x.f.writes) != 0 || !strings.Contains(log, "2 changes planned") {
		t.Fatalf("dry drop wrote %v:\n%s", x.f.writes, log)
	}
	drop(7422, true)
	if want := []string{sfo + " network nsg rules remove", gru + " network nsg rules remove"}; !slices.Equal(x.f.writes, want) {
		t.Fatalf("drop wrote %v, want %v", x.f.writes, want)
	}
	for cell, live := range rules() {
		if len(live) != len(before[cell])-1 || strings.Contains(command.JSON(live), `"min":7422`) {
			t.Fatalf("%s NSG after drop: %s", cell, command.JSON(live))
		}
	}
	if log := drop(7422, true); !strings.Contains(log, "has no TCP 7422 rule") {
		t.Fatalf("second drop:\n%s", log)
	}
	if engine := (&ociregion.Engine{Context: t.Context(), Dependency: x.f.dependency}); engine.CheckPrivatePeer(x.out, x.left, x.right) == nil {
		t.Fatal("inspection passes with a dropped port")
	}
	x.f.writes = nil
	if log, err := x.run(t, true); err != nil {
		t.Fatalf("restore: %v\n%s", err, log)
	}
	if want := []string{sfo + " network nsg rules add", gru + " network nsg rules add"}; !slices.Equal(x.f.writes, want) {
		t.Fatalf("restore wrote %v, want %v", x.f.writes, want)
	}
	var log bytes.Buffer
	p := &Peer{Out: &log, BeforeWrite: allowWrite, Guard: allowGuard}
	if err := p.Drop(t.Context(), intent, nil, 22, true); err == nil {
		t.Fatal("dropped a port outside the intent")
	}
}
