package ociregion

import (
	"slices"
	"testing"
	"time"
)

func legacyPublicPlan(p Object) {
	public := obj(p["public_api"])
	for _, field := range []string{"min_mbps", "max_mbps", "terrabase_members"} {
		delete(public, field)
	}
	security := obj(p["network_security"])
	security["nsg_rules"] = slices.DeleteFunc(arr(security["nsg_rules"]), func(rule any) bool {
		return tsAuthBackendRule("nsg_rules", obj(rule), public)
	})
}

func TestEstimateBillsHostsOutsideTheHomeRegionInFull(t *testing.T) {
	plan, err := balancerPlan(t, func(p Object) { legacyPublicPlan(p) })
	if err != nil {
		t.Fatal(err)
	}
	path := pathValue(plan["_source_path"])
	existing, shared := obj(plan["existing_operations_host"]), plan["shared_compartment_id"]
	inventory := Object{"schema_version": 2, "tenancy_id": plan["tenancy_id"], "plan_sha256": fileSHA(path), "captured_at": time.Now().UTC().Format(time.RFC3339Nano),
		"regions": []any{plan["region"]}, "preview_compartment_ids": Object{"control": nil, "network": "network", "workload": nil}, "images": []any{}, "buckets": []any{},
		"resources": []any{
			Object{"kind": "instance", "id": existing["instance_id"], "compartment-id": shared, "lifecycle-state": "RUNNING", "shape": "VM.Standard.A1.Flex", "shape-config": Object{"ocpus": 2, "memory-in-gbs": 4}},
			Object{"kind": "boot-volume", "id": existing["boot_volume_id"], "compartment-id": shared, "lifecycle-state": "AVAILABLE", "size-in-gbs": 50, "vpus-per-gb": 10},
			Object{"kind": "volume", "id": existing["data_volume_id"], "compartment-id": shared, "lifecycle-state": "AVAILABLE", "size-in-gbs": 50, "vpus-per-gb": 10},
			Object{"kind": "public-ip", "id": existing["public_ip_id"], "lifecycle-state": "ASSIGNED"},
			Object{"kind": "internet-gateway", "id": existing["internet_gateway_id"], "compartment-id": shared, "vcn-id": existing["vcn_id"], "lifecycle-state": "AVAILABLE"},
		}}
	// Five planned hosts: 5 OCPUs, 30 GB memory, 350 GB of volumes.
	for region, want := range map[string][2]string{
		"sa-saopaulo-1": {"58.6200", "10.6250"}, // (7×720−1500)×0.01 + (34×720−9000)×0.0015; (450−200)×0.0425
		"us-sanjose-1":  {"68.4000", "14.8750"}, // 5×720×0.01 + 30×720×0.0015; 350×0.0425
	} {
		plan["region"] = region
		cost, err := Estimate(plan, inventory, path)
		if err != nil {
			t.Fatal(err)
		}
		items := obj(cost["items"])
		if items["compute"] != want[0] || items["block_storage"] != want[1] {
			t.Fatalf("%s: compute %v, block %v, want %v", region, items["compute"], items["block_storage"], want)
		}
	}
}
