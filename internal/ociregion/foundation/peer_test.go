package foundation

import (
	"bytes"
	"context"
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

// pair is SJC (left) and GRU (right), each with the private network
// `oci-region foundation` creates plus the live rules no plan carries, bound
// plans and a draft pair intent whose resource OCIDs are null. gru-1 keeps
// its operator gateway LPG route; sjc-1 has a NAT gateway default route and
// HTTPS egress to Cloudflare and NetBird, added by hand (TS-640).
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
		if err := foundation.network(t.Context(), plan, name, text(ids["network_compartment"]), bind, func(key string) string { return text(ids[key]) }); err != nil {
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
			table["route-rules"] = append(arr(table["route-rules"]), Object{"destination": "0.0.0.0/0", "destination-type": "CIDR_BLOCK",
				"network-entity-id": "ocid1.natgateway.oc1." + region + ".nat"})
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
	p := &Peer{Clients: map[string]command.Client{sjc: client{x.f, sjc}, gru: client{x.f, gru}}, Out: &log, BeforeWrite: allowWrite, Guard: allowGuard,
		Pause: func(context.Context, time.Duration) error { return nil },
		Check: func(path string) error { return engine.CheckPrivatePeer(path, x.left, x.right) }}
	err = p.Run(t.Context(), intent, plans, x.out, apply)
	return log.String(), err
}

// peerWrites are the writes a first apply makes, each once, in order.
func peerWrites() []string {
	var w []string
	for _, region := range []string{sjc, gru} {
		w = append(w, region+" network drg create", region+" network remote-peering-connection create")
		for range 2 {
			w = append(w, region+" network drg-route-distribution create", region+" network drg-route-table create")
		}
		w = append(w, region+" network drg-attachment create", region+" network drg-attachment update",
			region+" network drg-route-distribution-statement add", region+" network drg-route-distribution-statement add")
	}
	w = append(w, sjc+" network remote-peering-connection connect")
	for _, region := range []string{sjc, gru} {
		w = append(w, region+" network route-table update", region+" network nsg rules add", region+" network security-list update")
	}
	return w
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
