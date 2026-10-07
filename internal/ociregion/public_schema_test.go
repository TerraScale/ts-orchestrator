package ociregion

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
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

func TestPublicAPIPinsCustomerOriginTrust(t *testing.T) {
	ca, err := os.ReadFile(filepath.Join("publicapi", "testdata", "origin-pull-test-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	for name, origin := range map[string]any{
		"reviewed":    Object{"ca_certificate": string(ca), "certificate_id": "test-origin-pull"},
		"null":        nil,
		"missing ID":  Object{"ca_certificate": string(ca)},
		"unknown key": Object{"ca_certificate": string(ca), "certificate_id": "test-origin-pull", "private_key": "never in a plan"},
		"invalid CA":  Object{"ca_certificate": "invalid", "certificate_id": "test-origin-pull"},
		"numeric ID":  Object{"ca_certificate": string(ca), "certificate_id": 123},
	} {
		t.Run(name, func(t *testing.T) {
			plan, err := balancerPlan(t, func(p Object) { obj(p["public_api"])["origin_pull"] = origin })
			if name != "reviewed" {
				if err == nil {
					t.Fatal("accepted invalid origin trust")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			d, err := publicapi.ParsePlan([]byte(canonical(plan)))
			if err != nil || d.OriginPull.CACertificate != string(ca) || d.OriginPull.CertificateID != "test-origin-pull" {
				t.Fatalf("origin trust was not bound: %+v, %v", d.OriginPull, err)
			}
		})
	}
}

func TestPublicAPIRejectsNullFlexibleFields(t *testing.T) {
	for _, fields := range [][]string{
		{"min_mbps"}, {"max_mbps"}, {"terrabase_members"},
		{"min_mbps", "max_mbps"}, {"min_mbps", "terrabase_members"},
		{"max_mbps", "terrabase_members"}, {"min_mbps", "max_mbps", "terrabase_members"},
	} {
		t.Run(strings.Join(fields, "+"), func(t *testing.T) {
			_, err := balancerPlan(t, func(p Object) {
				for _, field := range fields {
					obj(p["public_api"])[field] = nil
				}
			})
			if err == nil || !strings.Contains(err.Error(), "manual public API") {
				t.Fatalf("null flexible fields %v: %v", fields, err)
			}
		})
	}
}

func TestLegacyPublicAPIDoesNotAdmitTSAuth(t *testing.T) {
	for _, allowAuth := range []bool{false, true} {
		_, err := balancerPlan(t, func(p Object) {
			public := obj(p["public_api"])
			for _, field := range []string{"min_mbps", "max_mbps", "terrabase_members"} {
				delete(public, field)
			}
			if !allowAuth {
				security := obj(p["network_security"])
				var rules []any
				for _, rule := range arr(security["nsg_rules"]) {
					if !tsAuthBackendRule("nsg_rules", obj(rule), public) {
						rules = append(rules, rule)
					}
				}
				security["nsg_rules"] = rules
			}
		})
		if allowAuth && (err == nil || !strings.Contains(err.Error(), "legacy public API")) || !allowAuth && err != nil {
			t.Fatalf("legacy auth ingress=%t: %v", allowAuth, err)
		}
	}
}

func TestPublicAPIListenerPortMatchesSchema(t *testing.T) {
	for _, schema := range []string{"legacy", "flexible"} {
		for _, port := range []int{0, 1, 80, 443, 8443, 65535, 65536} {
			t.Run(schema+"/"+strconv.Itoa(port), func(t *testing.T) {
				plan, err := balancerPlan(t, func(p Object) {
					public := obj(p["public_api"])
					if schema == "legacy" {
						legacyPublicPlan(p)
						obj(p["resource_ids"])["network_load_balancer"] = "ocid1.networkloadbalancer.oc1.sa-saopaulo-1.aaaaaaaanlb"
					} else {
						obj(p["resource_ids"])["network_load_balancer"] = testBalancerID
					}
					public["listener_port"] = port
				})
				valid := port == 443 || schema == "legacy" && port >= 1 && port <= 65535
				if (err == nil) != valid {
					t.Fatalf("listener port %d: err=%v, valid=%v", port, err, valid)
				}
				if valid && l7Public(plan) != (schema == "flexible") {
					t.Fatal("public API was classified as the wrong load balancer schema")
				}
			})
		}
	}
}

func TestPublicAPISchemaEstimateSafeguards(t *testing.T) {
	for _, tc := range []struct {
		name              string
		maxMbps, liveMbps int
		wantCost, wantErr string
		nullMax           bool
	}{
		{name: "legacy"},
		{name: "flexible", maxMbps: 100, liveMbps: 100, wantCost: "15.3360"},
		{name: "higher ceiling", maxMbps: 200, liveMbps: 200, wantCost: "22.5360"},
		{name: "null max is not legacy", maxMbps: 100, nullMax: true, wantErr: "invalid numeric amount"},
		{name: "unpriced live bandwidth", maxMbps: 100, liveMbps: 101, wantErr: "unpriced gateway or load balancer"},
		{name: "monthly ceiling", maxMbps: 8000, liveMbps: 8000, wantErr: "exceeds the monthly ceiling"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := balancerPlan(t, func(p Object) {
				public := obj(p["public_api"])
				if tc.maxMbps == 0 {
					legacyPublicPlan(p)
				} else {
					public["max_mbps"] = tc.maxMbps
					obj(p["resource_ids"])["network_load_balancer"] = testBalancerID
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			// In-memory estimates must not omit flexible pricing for a null ceiling.
			if tc.nullMax {
				obj(plan["public_api"])["max_mbps"] = nil
			}
			path := pathValue(plan["_source_path"])
			existing, shared := obj(plan["existing_forgejo"]), plan["shared_compartment_id"]
			resources := []any{
				Object{"kind": "instance", "id": existing["instance_id"], "compartment-id": shared, "lifecycle-state": "RUNNING", "shape": "VM.Standard.A1.Flex", "shape-config": Object{"ocpus": 2, "memory-in-gbs": 4}},
				Object{"kind": "boot-volume", "id": existing["boot_volume_id"], "compartment-id": shared, "lifecycle-state": "AVAILABLE", "size-in-gbs": 50, "vpus-per-gb": 10},
				Object{"kind": "volume", "id": existing["data_volume_id"], "compartment-id": shared, "lifecycle-state": "AVAILABLE", "size-in-gbs": 50, "vpus-per-gb": 10},
				Object{"kind": "public-ip", "id": existing["public_ip_id"], "lifecycle-state": "ASSIGNED"},
				Object{"kind": "internet-gateway", "id": existing["internet_gateway_id"], "compartment-id": shared, "vcn-id": existing["vcn_id"], "lifecycle-state": "AVAILABLE"},
			}
			if tc.liveMbps != 0 {
				resources = append(resources, Object{"kind": "load-balancer", "id": testBalancerID, "compartment-id": "network", "lifecycle-state": "ACTIVE", "shape-name": "flexible", "shape-details": Object{"maximum-bandwidth-in-mbps": tc.liveMbps}},
					Object{"kind": "public-ip", "id": "ocid1.publicip.balancer", "lifecycle-state": "ASSIGNED",
						"display-name": "Floating IP for VIP public-vip on LB " + testBalancerID})
			}
			inventory := Object{"schema_version": 2, "tenancy_id": plan["tenancy_id"], "plan_sha256": fileSHA(path), "captured_at": time.Now().UTC().Format(time.RFC3339Nano),
				"regions": []any{plan["region"]}, "preview_compartment_ids": Object{"control": nil, "network": "network", "workload": nil}, "images": []any{}, "resources": resources, "buckets": []any{}}
			cost, err := Estimate(plan, inventory, path)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("estimate err=%v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, present := obj(cost["items"])["load_balancer"]
			if present != (tc.wantCost != "") || present && got != tc.wantCost {
				t.Fatalf("load balancer cost=%v, present=%v, want %q", got, present, tc.wantCost)
			}
			// Only the balancer's own VIP joins the Forgejo address.
			inventory["resources"] = append(resources, Object{"kind": "public-ip", "id": "ocid1.publicip.other",
				"lifecycle-state": "ASSIGNED", "display-name": "Floating IP for VIP public-vip on LB ocid1.loadbalancer.other"})
			if _, err := Estimate(plan, inventory, path); err == nil || !strings.Contains(err.Error(), "public IP inventory") {
				t.Fatalf("an unrelated public IP was admitted: %v", err)
			}
		})
	}
}

// Always Free covers A1 compute and block storage only in the home region:
// Forgejo stays inside it, and a second region's hosts pay for all of theirs.
func TestEstimateBillsHostsOutsideTheHomeRegionInFull(t *testing.T) {
	plan, err := balancerPlan(t, func(p Object) { legacyPublicPlan(p) })
	if err != nil {
		t.Fatal(err)
	}
	path := pathValue(plan["_source_path"])
	existing, shared := obj(plan["existing_forgejo"]), plan["shared_compartment_id"]
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
