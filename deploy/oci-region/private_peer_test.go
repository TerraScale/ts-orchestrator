package ociregion_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
)

type ppObject = map[string]any

func ppMap(v any) ppObject { return v.(map[string]any) }
func ppRows(v any) []any   { return v.([]any) }
func ppJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func ppHash(t *testing.T, path string) string {
	t.Helper()
	d := sha256.Sum256(script.Read(t, path))
	return hex.EncodeToString(d[:])
}
func ppDecode(t *testing.T, b []byte) ppObject {
	t.Helper()
	var v ppObject
	if e := json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	return v
}

type ppFixture struct {
	plans, inventories, ids map[string]ppObject
	paths                   map[string][]string
	intent                  ppObject
	intentPath              string
	responses               map[string]any
}

func ppNew(t *testing.T) *ppFixture {
	t.Helper()
	f := &ppFixture{plans: map[string]ppObject{}, inventories: map[string]ppObject{}, ids: map[string]ppObject{}, paths: map[string][]string{}, responses: map[string]any{}}
	dir := t.TempDir()
	cells := []string{"GRU", "SJC"}
	regions := []string{"sa-saopaulo-1", "us-sanjose-1"}
	for i, cell := range cells {
		p := ppDecode(t, script.Read(t, filepath.Join(script.Root(t), "deploy/oci-region/plan.json")))
		lower := strings.ToLower(cell)
		region := regions[i]
		cidr := fmt.Sprintf("10.%d.0.0/24", 251+i)
		subnet := fmt.Sprintf("10.%d.0.0/25", 251+i)
		for _, k := range []string{"operator_gateway", "netbird", "public_api"} {
			p[k] = nil
		}
		p["cell"] = cell
		p["region"] = region
		p["network_cidr"] = cidr
		p["subnet_cidr"] = subnet
		p["controller_replicas"] = 1
		p["database_members"] = 0
		p["hosts"] = []any{ppObject{"slot": "controller-a", "shape": "VM.Standard.A1.Flex", "ocpus": 1, "memory_gb": 6, "boot_gb": 50, "data_gb": 0, "architecture": "arm64", "private_ip": fmt.Sprintf("10.%d.0.10", 251+i)}}
		ids := ppMap(p["resource_ids"])
		for _, role := range []string{"control", "network", "workload"} {
			ids[role+"_compartment"] = "ocid1.compartment.oc1.." + lower + role
		}
		for key, kind := range map[string]string{"vault": "vault", "key": "key", "vcn": "vcn", "subnet": "subnet", "network_security_group": "networksecuritygroup", "security_list": "securitylist", "route_table": "routetable", "service_gateway": "servicegateway"} {
			ids[key] = "ocid1." + kind + ".oc1." + region + "." + lower + strings.ReplaceAll(key, "_", "")
		}
		for key, kind := range map[string]string{"controller_dynamic_group": "dynamicgroup", "controller_policy": "policy", "objectstorage_key_policy": "policy", "host_dynamic_group": "dynamicgroup", "host_policy": "policy"} {
			ids[key] = "ocid1." + kind + ".oc1.." + lower + strings.ReplaceAll(key, "_", "")
		}
		ids["local_peering_gateway"] = nil
		ids["instances"] = ppObject{"controller-a": nil}
		ids["boot_volumes"] = ppObject{"controller-a": nil}
		ids["data_volumes"] = ppObject{}
		p["host_credential_secret"] = ppObject{"compartment_id": "ocid1.compartment.oc1.." + lower + "secrets", "secret_id": "ocid1.vaultsecret.oc1." + region + "." + lower + "secret"}
		sec := ppMap(p["network_security"])
		rules := []any{}
		for _, v := range ppRows(sec["nsg_rules"]) {
			r := ppMap(v)
			if r["source"] != "10.250.10.155/32" && r["tcp_min"] != float64(22) {
				r["source"] = cidr
				rules = append(rules, r)
			}
		}
		sec["nsg_rules"] = rules
		sec["workload_nsg_rules"] = []any{}
		service := "all-" + lower + "-services-in-oracle-services-network"
		sec["service_gateway_service_id"] = "ocid1.service.oc1." + region + "." + lower + "service"
		sec["service_gateway_cidr_block"] = service
		sec["route_rules"] = []any{ppObject{"destination": service, "destination_type": "SERVICE_CIDR_BLOCK", "network_entity_id": "{service_gateway_id}"}}
		for _, v := range ppRows(sec["security_list_egress_rules"]) {
			r := ppMap(v)
			if r["destination_type"] == "CIDR_BLOCK" && r["destination"] != "169.254.169.254/32" {
				r["destination"] = cidr
			}
			if r["destination_type"] == "SERVICE_CIDR_BLOCK" {
				r["destination"] = service
			}
		}
		paths := []string{filepath.Join(dir, lower+"-plan.json"), filepath.Join(dir, lower+"-inventory.json"), filepath.Join(dir, lower+"-admission.json")}
		script.Write(t, paths[0], ppJSON(t, p), 0600)
		f.plans[cell] = p
		f.paths[cell] = paths
		existing := ppMap(p["existing_operations_host"])
		shared := p["shared_compartment_id"]
		resources := []any{}
		for _, kind := range []string{"instance", "boot-volume", "volume", "public-ip", "internet-gateway"} {
			r := ppObject{"kind": kind, "compartment-id": shared}
			switch kind {
			case "instance":
				r["id"] = existing["instance_id"]
				r["lifecycle-state"] = "RUNNING"
				r["shape"] = "VM.Standard.A1.Flex"
				r["shape-config"] = ppObject{"ocpus": 2, "memory-in-gbs": 4}
			case "boot-volume":
				r["id"] = existing["boot_volume_id"]
				r["lifecycle-state"] = "AVAILABLE"
				r["size-in-gbs"] = 50
				r["vpus-per-gb"] = 10
			case "volume":
				r["id"] = existing["data_volume_id"]
				r["lifecycle-state"] = "AVAILABLE"
				r["size-in-gbs"] = existing["expected_volume_gb"]
				r["vpus-per-gb"] = existing["expected_volume_vpus_per_gb"]
			case "public-ip":
				r["id"] = existing["public_ip_id"]
				r["lifecycle-state"] = "ASSIGNED"
			case "internet-gateway":
				r["id"] = existing["internet_gateway_id"]
				r["vcn-id"] = existing["vcn_id"]
				r["lifecycle-state"] = "AVAILABLE"
			}
			resources = append(resources, r)
		}
		compartments := ppObject{}
		for _, role := range []string{"control", "network", "workload"} {
			compartments[role] = ids[role+"_compartment"]
		}
		inv := ppObject{"schema_version": 2, "captured_at": time.Now().UTC().Add(-2 * time.Second).Format(time.RFC3339Nano), "plan_sha256": ppHash(t, paths[0]), "tenancy_id": p["tenancy_id"], "regions": regions, "preview_compartment_ids": compartments, "images": []any{}, "resources": resources, "buckets": []any{ppObject{"name": "ts-forgejo", "bytes": 30 * 1024 * 1024 * 1024, "versioning": "Disabled", "storage_tier": "Standard", "public_access_type": "NoPublicAccess"}, ppObject{"name": "ts-forgejo-backup", "bytes": 28 * 1024 * 1024 * 1024, "versioning": "Disabled", "storage_tier": "Standard", "public_access_type": "NoPublicAccess"}}}
		script.Write(t, paths[1], ppJSON(t, inv), 0600)
		f.inventories[cell] = inv
		loaded, err := ociregion.LoadPlan(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		estimate, err := ociregion.Estimate(loaded, inv, paths[0])
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		admission := ppObject{"schema_version": 2, "admitted_at": now.Format(time.RFC3339), "expires_at": now.Add(15 * time.Minute).Format(time.RFC3339), "plan_sha256": ppHash(t, paths[0]), "inventory_sha256": ppHash(t, paths[1]), "preview_compartment_ids": compartments, "estimate": estimate}
		script.Write(t, paths[2], ppJSON(t, admission), 0600)
		peerIDs := ppObject{}
		for role, kind := range map[string]string{"drg": "drg", "vcn_attachment": "drgattachment", "rpc": "remotepeeringconnection", "rpc_attachment": "drgattachment", "vcn_route": "drgroutetable", "rpc_route": "drgroutetable", "vcn_import": "drgroutedistribution", "rpc_import": "drgroutedistribution"} {
			peerIDs[role] = "ocid1." + kind + ".oc1." + region + "." + lower + strings.ReplaceAll(role, "_", "")
		}
		f.ids[cell] = peerIDs
	}
	mapping := ppObject{}
	for _, cell := range cells {
		entry := ppObject{"plan_sha256": ppHash(t, f.paths[cell][0]), "monthly_cross_region_egress_gb": 20}
		for key, role := range map[string]string{"drg_id": "drg", "vcn_attachment_id": "vcn_attachment", "rpc_id": "rpc", "rpc_attachment_id": "rpc_attachment", "vcn_drg_route_table_id": "vcn_route", "rpc_drg_route_table_id": "rpc_route", "vcn_import_distribution_id": "vcn_import", "rpc_import_distribution_id": "rpc_import"} {
			entry[key] = f.ids[cell][role]
		}
		mapping[cell] = entry
	}
	f.intent = ppObject{"schema_version": 1, "tenancy_id": f.plans["GRU"]["tenancy_id"], "realm": "oc1", "allowed_tcp_ports": []any{4222, 7422}, "cells": mapping}
	f.intentPath = filepath.Join(dir, "pair-intent.json")
	f.saveIntent(t)
	f.makeResponses()
	return f
}
func (f *ppFixture) saveIntent(t *testing.T) {
	script.Write(t, f.intentPath, ppJSON(t, f.intent), 0600)
}
func ppLiveRules(rows []any) []any {
	result := []any{}
	for _, v := range rows {
		r := ppMap(v)
		live := ppObject{"direction": r["direction"], "protocol": r["protocol"], "is-stateless": r["stateless"]}
		for _, k := range []string{"source", "source_type", "destination", "destination_type"} {
			if r[k] != nil {
				live[strings.ReplaceAll(k, "_", "-")] = r[k]
			}
		}
		for _, proto := range []string{"tcp", "udp"} {
			if r[proto+"_min"] != nil {
				live[proto+"-options"] = ppObject{"destination-port-range": ppObject{"min": r[proto+"_min"], "max": r[proto+"_max"]}}
			}
		}
		result = append(result, live)
	}
	return result
}
func (f *ppFixture) makeResponses() {
	for _, cell := range []string{"GRU", "SJC"} {
		p := f.plans[cell]
		peer := "GRU"
		if cell == peer {
			peer = "SJC"
		}
		other := f.plans[peer]
		ids := ppMap(p["resource_ids"])
		own := f.ids[cell]
		remote := f.ids[peer]
		sec := ppMap(p["network_security"])
		region := p["region"].(string)
		put := func(command, id string, v any) { f.responses[region+"|"+command+"|"+id] = v }
		obj := func(id any) ppObject {
			return ppObject{"id": id, "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"], "lifecycle-state": "AVAILABLE"}
		}
		vcn := obj(ids["vcn"])
		vcn["cidr-block"] = p["network_cidr"]
		put("network vcn get", "", vcn)
		subnet := obj(ids["subnet"])
		subnet["cidr-block"] = p["subnet_cidr"]
		subnet["prohibit-public-ip-on-vnic"] = true
		subnet["prohibit-internet-ingress"] = true
		subnet["security-list-ids"] = []any{ids["security_list"]}
		subnet["route-table-id"] = ids["route_table"]
		put("network subnet get", "", subnet)
		put("network nsg get", "", obj(ids["network_security_group"]))
		nsg := ppLiveRules(ppRows(sec["nsg_rules"]))
		egress := ppLiveRules(ppRows(sec["security_list_egress_rules"]))
		for _, port := range []int{4222, 7422} {
			options := ppObject{"destination-port-range": ppObject{"min": port, "max": port}}
			nsg = append(nsg, ppObject{"direction": "INGRESS", "protocol": "6", "source": other["subnet_cidr"], "source-type": "CIDR_BLOCK", "is-stateless": false, "tcp-options": options})
			egress = append(egress, ppObject{"direction": "EGRESS", "protocol": "6", "destination": other["subnet_cidr"], "destination-type": "CIDR_BLOCK", "is-stateless": false, "tcp-options": options})
		}
		put("network nsg rules", "", nsg)
		sl := obj(ids["security_list"])
		sl["ingress-security-rules"] = ppLiveRules(ppRows(sec["security_list_ingress_rules"]))
		sl["egress-security-rules"] = egress
		put("network security-list get", "", sl)
		rt := obj(ids["route_table"])
		rt["route-rules"] = []any{ppObject{"destination": sec["service_gateway_cidr_block"], "destination-type": "SERVICE_CIDR_BLOCK", "network-entity-id": ids["service_gateway"]}, ppObject{"destination": other["subnet_cidr"], "destination-type": "CIDR_BLOCK", "network-entity-id": own["drg"]}}
		put("network route-table get", "", rt)
		sg := obj(ids["service_gateway"])
		sg["services"] = []any{ppObject{"service-id": sec["service_gateway_service_id"]}}
		put("network service-gateway get", "", sg)
		put("network drg get", "", obj(own["drg"]))
		put("network drg-attachment list", "", []any{ppObject{"id": own["vcn_attachment"], "lifecycle-state": "ATTACHED"}, ppObject{"id": own["rpc_attachment"], "lifecycle-state": "ATTACHED"}})
		for _, role := range []string{"vcn", "rpc"} {
			id := own[role+"_attachment"].(string)
			att := obj(id)
			att["drg-id"] = own["drg"]
			att["lifecycle-state"] = "ATTACHED"
			att["is-cross-tenancy"] = false
			att["drg-route-table-id"] = own[role+"_route"]
			delete(att, "vcn-id")
			kind := "REMOTE_PEERING_CONNECTION"
			netID := own["rpc"]
			if role == "vcn" {
				kind = "VCN"
				netID = ids["vcn"]
				att["vcn-id"] = nil
			}
			att["network-details"] = ppObject{"type": kind, "id": netID}
			put("network drg-attachment get", id, att)
			table := obj(own[role+"_route"])
			table["drg-id"] = own["drg"]
			table["import-drg-route-distribution-id"] = own[role+"_import"]
			table["is-ecmp-enabled"] = false
			put("network drg-route-table get", own[role+"_route"].(string), table)
			dist := obj(own[role+"_import"])
			dist["distribution-type"] = "IMPORT"
			dist["drg-id"] = own["drg"]
			put("network drg-route-distribution get", own[role+"_import"].(string), dist)
			accepted := own["rpc_attachment"]
			destination := other["network_cidr"]
			if role == "rpc" {
				accepted = own["vcn_attachment"]
				destination = p["network_cidr"]
			}
			put("network drg-route-distribution-statement list", own[role+"_import"].(string), []any{ppObject{"id": strings.ToLower(cell) + "-statement", "action": "ACCEPT", "priority": 100, "match-criteria": []any{ppObject{"match-type": "DRG_ATTACHMENT_ID", "drg-attachment-id": accepted}}}})
			put("network drg-route-rule list", own[role+"_route"].(string), []any{ppObject{"destination": destination, "destination-type": "CIDR_BLOCK", "next-hop-drg-attachment-id": accepted, "route-type": "DYNAMIC", "is-conflict": false, "is-blackhole": false}})
		}
		rpc := obj(own["rpc"])
		rpc["drg-id"] = own["drg"]
		rpc["peering-status"] = "PEERED"
		rpc["peer-id"] = remote["rpc"]
		rpc["peer-region-name"] = other["region"]
		rpc["peer-tenancy-id"] = p["tenancy_id"]
		rpc["is-cross-tenancy-peering"] = false
		put("network remote-peering-connection get", "", rpc)
	}
}
func (f *ppFixture) observe(t *testing.T, cli bool) ppObject {
	t.Helper()
	paths := []string{f.intentPath}
	paths = append(paths, f.paths["GRU"]...)
	paths = append(paths, f.paths["SJC"]...)
	calls := []any{}
	engine := &ociregion.Engine{Context: t.Context(), Dependency: func(name string, args []any, kwargs ppObject) (any, error) {
		if name != "oci" {
			t.Fatalf("unexpected dependency %s", name)
		}
		region := kwargs["region"].(string)
		calls = append(calls, []any{args, region})
		command := fmt.Sprint(args[0]) + " " + fmt.Sprint(args[1]) + " " + fmt.Sprint(args[2])
		identifier := ""
		switch command {
		case "network drg-attachment get", "network drg-route-table get", "network drg-route-distribution get", "network drg-route-distribution-statement list", "network drg-route-rule list":
			for i, arg := range args {
				if arg == "--drg-attachment-id" || arg == "--drg-route-table-id" || arg == "--route-distribution-id" {
					identifier = args[i+1].(string)
					break
				}
			}
		}
		key := region + "|" + command + "|" + identifier
		response, ok := f.responses[key]
		if !ok {
			t.Fatalf("missing provider fixture %s", key)
		}
		return response, nil
	}}
	output := ""
	var receipt ppObject
	var err error
	if cli {
		flags := []string{"--pair-intent", "--left-plan", "--left-inventory", "--left-admission", "--right-plan", "--right-inventory", "--right-admission"}
		args := []string{"inspect-private-peer"}
		for i, flag := range flags {
			args = append(args, flag, paths[i])
		}
		out := filepath.Join(filepath.Dir(f.intentPath), "receipt.json")
		args = append(args, "--out", out)
		var stdout bytes.Buffer
		err = engine.Run(args, &stdout)
		if err == nil {
			receipt = ppDecode(t, script.Read(t, out))
			output = stdout.String()
		}
	} else {
		receipt, err = engine.InspectPrivatePeer(paths...)
	}
	if err != nil {
		failure, ok := errors.AsType[ociregion.Failure](err)
		if !ok {
			t.Fatalf("unexpected driver failure: %v", err)
		}
		return ppObject{"error": err.Error(), "error_type": failure.Kind, "calls": calls}
	}
	return ppObject{"receipt": receipt, "output": output, "calls": calls}
}
func ppExpectError(t *testing.T, out ppObject, want string) {
	t.Helper()
	if out["error_type"] != "ValueError" || !strings.Contains(fmt.Sprint(out["error"]), want) {
		t.Fatalf("want %q, got %v", want, out)
	}
}
func TestPrivatePeerConfigurationReceipt(t *testing.T) {
	f := ppNew(t)
	out := f.observe(t, true)
	if out["receipt"] == nil {
		t.Fatal(out)
	}
	r := ppMap(out["receipt"])
	if r["status"] != "configuration_readback_pass" || r["pair_intent_sha256"] != ppHash(t, f.intentPath) {
		t.Fatal(r)
	}
	cells := ppMap(r["cells"])
	if len(cells) != 2 || cells["GRU"] == nil || cells["SJC"] == nil {
		t.Fatal(cells)
	}
	evidence := ppMap(r["source_evidence"])
	if ppMap(evidence["GRU"])["plan_sha256"] != ppHash(t, f.paths["GRU"][0]) || ppMap(evidence["SJC"])["inventory_sha256"] != ppHash(t, f.paths["SJC"][1]) {
		t.Fatal(evidence)
	}
	for _, v := range evidence {
		if ppMap(v)["estimate"] == nil {
			t.Fatal(v)
		}
	}
	budget := ppMap(r["budget_admission"])
	if budget["status"] != "blocked" || !strings.Contains(fmt.Sprint(budget["reason"]), "cannot prove the combined USD 200 monthly ceiling") {
		t.Fatal(budget)
	}
	for _, k := range []string{"combined_estimate", "headroom"} {
		if _, ok := r[k]; ok {
			t.Fatalf("unexpected %s", k)
		}
	}
	output := out["output"].(string)
	if !strings.Contains(output, "budget_admission=BLOCKED") || strings.Contains(output, "estimate_usd") {
		t.Fatal(output)
	}
	for k, v := range (ppObject{"dataplane_reachability": "not_tested", "application_mtls_required": true, "application_mtls_verified": false, "native_replication_ready": false}) {
		if r[k] != v {
			t.Fatalf("%s: %v", k, r[k])
		}
	}
	regions := map[string]bool{}
	for _, v := range ppRows(out["calls"]) {
		regions[ppRows(v)[1].(string)] = true
	}
	if !reflect.DeepEqual(regions, map[string]bool{"sa-saopaulo-1": true, "us-sanjose-1": true}) {
		t.Fatal(regions)
	}
}
func TestPrivatePeerReadbackSecurityMatrix(t *testing.T) {
	cases := []struct{ name, error string }{{"null_vcn_id", ""}, {"absent_vcn_id", ""}, {"matching_vcn_id", ""}, {"mismatched_vcn_id", "VCN DRG attachment identity"}, {"disconnected", "live RPC is disconnected, asymmetric"}, {"asymmetric", "live RPC is disconnected, asymmetric"}, {"wrong_peer_region", "live RPC is disconnected, asymmetric"}, {"extra_drg_route", "DRG route table rules"}, {"per_subnet_drg_routes", ""}, {"drg_route_outside_peer_vcn", "DRG route table rules"}, {"drg_route_misses_private_subnet", "do not reach the peer's private subnet"}, {"unrelated_nat_route", ""}, {"route_into_peer_vcn", "reciprocal subnet route table"}, {"missing_plan_route", "reciprocal subnet route table"}, {"unrelated_egress", ""}, {"egress_to_peer_vcn", "peer security-list egress rules"}, {"missing_peer_egress", "peer security-list egress rules"}, {"unrelated_nsg_rule", ""}, {"peer_port_on_security_list", ""}, {"peer_other_port_on_security_list", "peer security-list ingress rules"}, {"unrelated_icmp", ""}, {"broad_import", "DRG import distribution is not scoped"}, {"extra_import_statement", "contains extra statements"}, {"extra_attachment", "unexpected, missing, or disconnected attachment"}, {"wrong_owner", "DRG is unavailable or owned by another compartment"}, {"wide_nsg", "peer NSG rules"}, {"wrong_peer_port", "peer NSG rules"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := ppNew(t)
			region := "sa-saopaulo-1"
			own := f.ids["GRU"]
			get := func(cmd, id string) any { return f.responses[region+"|"+cmd+"|"+id] }
			set := func(cmd, id string, v any) { f.responses[region+"|"+cmd+"|"+id] = v }
			switch tc.name {
			case "absent_vcn_id":
				delete(ppMap(get("network drg-attachment get", own["vcn_attachment"].(string))), "vcn-id")
			case "matching_vcn_id":
				ppMap(get("network drg-attachment get", own["vcn_attachment"].(string)))["vcn-id"] = ppMap(f.plans["GRU"]["resource_ids"])["vcn"]
			case "mismatched_vcn_id":
				ppMap(get("network drg-attachment get", own["vcn_attachment"].(string)))["vcn-id"] = "ocid1.vcn.oc1.unexpected.foreignvcn"
			case "disconnected":
				ppMap(get("network remote-peering-connection get", ""))["peering-status"] = "PENDING"
			case "asymmetric":
				ppMap(get("network remote-peering-connection get", ""))["peer-id"] = "ocid1.remotepeeringconnection.oc1.sa-saopaulo-1.unexpected"
			case "wrong_peer_region":
				ppMap(get("network remote-peering-connection get", ""))["peer-region-name"] = "eu-frankfurt-1"
			case "wrong_owner":
				ppMap(get("network drg get", ""))["compartment-id"] = "ocid1.compartment.oc1..foreignowner"
			case "extra_attachment":
				set("network drg-attachment list", "", append(ppRows(get("network drg-attachment list", "")), ppObject{"id": "ocid1.drgattachment.oc1.sa-saopaulo-1.unexpected", "lifecycle-state": "ATTACHED"}))
			case "unrelated_nat_route", "route_into_peer_vcn":
				// A default route loses to the peer subnet route; one inside the peer VCN does not.
				destination := map[string]string{"unrelated_nat_route": "0.0.0.0/0", "route_into_peer_vcn": "10.252.0.0/24"}[tc.name]
				r := ppMap(get("network route-table get", ""))
				r["route-rules"] = append(ppRows(r["route-rules"]), ppObject{"destination": destination, "destination-type": "CIDR_BLOCK", "network-entity-id": "ocid1.natgateway.oc1.sa-saopaulo-1.other"})
			case "missing_plan_route":
				r := ppMap(get("network route-table get", ""))
				r["route-rules"] = ppRows(r["route-rules"])[1:]
			case "unrelated_egress", "egress_to_peer_vcn":
				rule := ppObject{"protocol": "all", "destination": "10.252.0.0/24", "destination-type": "CIDR_BLOCK", "is-stateless": false}
				if tc.name == "unrelated_egress" {
					rule = ppObject{"protocol": "6", "destination": "173.245.48.0/20", "destination-type": "CIDR_BLOCK", "is-stateless": false, "tcp-options": ppObject{"destination-port-range": ppObject{"min": 443, "max": 443}}}
				}
				sl := ppMap(get("network security-list get", ""))
				sl["egress-security-rules"] = append(ppRows(sl["egress-security-rules"]), rule)
			case "missing_peer_egress":
				sl := ppMap(get("network security-list get", ""))
				rules := ppRows(sl["egress-security-rules"])
				sl["egress-security-rules"] = rules[:len(rules)-1]
			case "unrelated_nsg_rule":
				set("network nsg rules", "", append(ppRows(get("network nsg rules", "")), ppObject{"direction": "INGRESS", "protocol": "6", "source": "10.250.10.155/32", "source-type": "CIDR_BLOCK", "is-stateless": false, "tcp-options": ppObject{"destination-port-range": ppObject{"min": 443, "max": 443}}}))
			case "peer_port_on_security_list", "peer_other_port_on_security_list":
				port := map[string]int{"peer_port_on_security_list": 7422, "peer_other_port_on_security_list": 22}[tc.name]
				sl := ppMap(get("network security-list get", ""))
				sl["ingress-security-rules"] = append(ppRows(sl["ingress-security-rules"]), ppObject{"protocol": "6", "source": "10.252.0.0/25", "source-type": "CIDR_BLOCK", "is-stateless": false, "tcp-options": ppObject{"destination-port-range": ppObject{"min": port, "max": port}}})
			case "unrelated_icmp":
				sl := ppMap(get("network security-list get", ""))
				sl["ingress-security-rules"] = append(ppRows(sl["ingress-security-rules"]), ppObject{"protocol": "1", "source": "10.251.0.0/24", "source-type": "CIDR_BLOCK", "is-stateless": false, "icmp-options": ppObject{"type": 3, "code": 4}})
			case "extra_drg_route":
				id := own["vcn_route"].(string)
				set("network drg-route-rule list", id, append(ppRows(get("network drg-route-rule list", id)), ppObject{"destination": "0.0.0.0/0", "destination-type": "CIDR_BLOCK", "next-hop-drg-attachment-id": own["rpc_attachment"], "route-type": "STATIC", "is-conflict": false, "is-blackhole": false}))
			case "per_subnet_drg_routes", "drg_route_outside_peer_vcn", "drg_route_misses_private_subnet":
				// OCI advertises the peer VCN per subnet: its private /25 and
				// the public /26 of its load balancer.
				destinations := map[string][]string{"per_subnet_drg_routes": {"10.252.0.0/25", "10.252.0.128/26"},
					"drg_route_outside_peer_vcn": {"10.252.0.0/25", "10.9.0.0/24"}, "drg_route_misses_private_subnet": {"10.252.0.128/26"}}[tc.name]
				var routes []any
				for _, destination := range destinations {
					routes = append(routes, ppObject{"destination": destination, "destination-type": "CIDR_BLOCK", "next-hop-drg-attachment-id": own["rpc_attachment"],
						"route-type": "DYNAMIC", "is-conflict": false, "is-blackhole": nil})
				}
				set("network drg-route-rule list", own["vcn_route"].(string), routes)
			case "broad_import":
				id := own["vcn_import"].(string)
				ppMap(ppRows(get("network drg-route-distribution-statement list", id))[0])["match-criteria"] = []any{ppObject{"match-type": "MATCH_ALL"}}
			case "extra_import_statement":
				id := own["vcn_import"].(string)
				set("network drg-route-distribution-statement list", id, append(ppRows(get("network drg-route-distribution-statement list", id)), ppObject{"id": "gru-extra", "action": "ACCEPT", "priority": 200, "match-criteria": []any{ppObject{"match-type": "MATCH_ALL"}}}))
			case "wide_nsg":
				set("network nsg rules", "", append(ppRows(get("network nsg rules", "")), ppObject{"direction": "INGRESS", "protocol": "6", "source": "0.0.0.0/0", "source-type": "CIDR_BLOCK", "is-stateless": false, "tcp-options": ppObject{"destination-port-range": ppObject{"min": 1, "max": 65535}}}))
			case "wrong_peer_port":
				rows := ppRows(get("network nsg rules", ""))
				ppMap(ppMap(ppMap(rows[len(rows)-1])["tcp-options"])["destination-port-range"])["max"] = 7423
			}
			out := f.observe(t, false)
			if tc.error != "" {
				ppExpectError(t, out, tc.error)
			} else if out["receipt"] == nil || ppMap(out["receipt"])["status"] != "configuration_readback_pass" {
				t.Fatal(out)
			}
		})
	}
}
func ppChangeCIDR(p ppObject, cidr, subnet, ip string) {
	p["network_cidr"] = cidr
	p["subnet_cidr"] = subnet
	ppMap(ppRows(p["hosts"])[0])["private_ip"] = ip
	sec := ppMap(p["network_security"])
	for _, v := range ppRows(sec["nsg_rules"]) {
		ppMap(v)["source"] = cidr
	}
	for _, v := range ppRows(sec["security_list_egress_rules"]) {
		r := ppMap(v)
		if r["destination_type"] == "CIDR_BLOCK" && r["destination"] != "169.254.169.254/32" {
			r["destination"] = cidr
		}
	}
}
func TestPrivatePeerInputSecurityMatrix(t *testing.T) {
	cases := []struct{ name, error string }{{"stale_plan", "stale for the SJC plan"}, {"overlap", "CIDRs must not overlap"}, {"wrong_tenancy", "do not share the exact tenancy and realm"}, {"missing_cell", "cell map differs"}, {"wrong_rpc_region", "invalid remotepeeringconnection OCID"}, {"wrong_route_kind", "invalid drgroutetable OCID"}, {"documentation_range", "address plan:"}, {"stale_inventory", "budget admission is stale"}, {"public_proof", "unexpected or missing fields"}, {"excess_egress", "exceeds the regional plan's priced egress reserve"}, {"duplicate_ports", "sorted, unique, exact TCP ports"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := ppNew(t)
			p := f.plans["SJC"]
			mapping := ppMap(f.intent["cells"])
			sjc := ppMap(mapping["SJC"])
			gru := ppMap(mapping["GRU"])
			switch tc.name {
			case "stale_plan", "overlap":
				if tc.name == "stale_plan" {
					ppChangeCIDR(p, "10.252.1.0/24", "10.252.1.0/25", "10.252.1.10")
				} else {
					ppChangeCIDR(p, "10.251.0.0/24", "10.251.0.0/25", "10.251.0.10")
				}
				script.Write(t, f.paths["SJC"][0], ppJSON(t, p), 0600)
				if tc.name == "overlap" {
					sjc["plan_sha256"] = ppHash(t, f.paths["SJC"][0])
				}
			case "wrong_tenancy":
				p["tenancy_id"] = "ocid1.tenancy.oc1..differenttenancy"
				script.Write(t, f.paths["SJC"][0], ppJSON(t, p), 0600)
				sjc["plan_sha256"] = ppHash(t, f.paths["SJC"][0])
			case "missing_cell":
				delete(mapping, "SJC")
			case "wrong_rpc_region":
				gru["rpc_id"] = "ocid1.remotepeeringconnection.oc1.us-sanjose-1.wrongregion"
			case "wrong_route_kind":
				gru["vcn_drg_route_table_id"] = "ocid1.drgroute.oc1.sa-saopaulo-1.wrongkind"
			case "documentation_range":
				ppChangeCIDR(p, "203.0.113.0/24", "203.0.113.0/25", "203.0.113.10")
				script.Write(t, f.paths["SJC"][0], ppJSON(t, p), 0600)
				sjc["plan_sha256"] = ppHash(t, f.paths["SJC"][0])
			case "stale_inventory":
				inv := f.inventories["GRU"]
				inv["captured_at"] = time.Now().UTC().Format(time.RFC3339Nano)
				script.Write(t, f.paths["GRU"][1], ppJSON(t, inv), 0600)
			case "public_proof":
				f.intent["public_peer_address"] = "203.0.113.9:7422"
			case "excess_egress":
				gru["monthly_cross_region_egress_gb"] = 101
			case "duplicate_ports":
				f.intent["allowed_tcp_ports"] = []any{7422, 7422}
			}
			f.saveIntent(t)
			out := f.observe(t, false)
			ppExpectError(t, out, tc.error)
			if tc.name == "public_proof" && len(ppRows(out["calls"])) != 0 {
				t.Fatalf("public proof triggered OCI calls: %v", out)
			}
		})
	}
}
