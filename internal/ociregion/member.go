package ociregion

import (
	"encoding/json/v2"
	"fmt"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

// memberName is a member slot's static C# database host name, e.g. gru-1-db-1.
func memberName(plan Object, slot string) string {
	name, err := naming.RegionCell(str(plan["cell"])).MemberSlot(slot)
	if err != nil {
		fail("plan cell has no static member name: " + err.Error())
	}
	return name
}

// memberTags are the exact freeform tags of an operator-launched C# database
// host. They carry no terrascale-managed-by, so the controller fleet ignores it.
func memberTags(plan Object, name string) Object {
	return Object{"terrascale-owner": plan["orchestrator_owner"], "terrascale-resource": "terrabase-host", "terrascale-host-node": name}
}

// MemberLaunchDocument is the C# database host launch input `preview
// member-launch` writes. It has SeedLaunchDocument's shape, so
// internal/attempt decodes it with the same strict reader.
func MemberLaunchDocument(plan, host Object, name, imageID string, metadata Object) Object {
	ids := obj(plan["resource_ids"])
	reviewed := Object{"availability_domain": plan["availability_domain"], "fault_domain": host["fault_domain"], "compartment_id": ids["workload_compartment"], "shape": host["shape"], "ocpus": host["ocpus"], "memory_gb": host["memory_gb"], "image_id": imageID, "boot_gb": host["boot_gb"], "boot_vpus_per_gb": plan["volume_vpus_per_gb"], "subnet_id": ids["subnet"], "network_security_group_ids": []any{ids["workload_network_security_group"]}, "assign_public_ip": false}
	document := SeedLaunchDocument(reviewed, host, name, metadata)
	document["freeformTags"] = memberTags(plan, name)
	return document
}

// memberLaunch builds the launch input of one C# database host. Its data
// lives on the boot volume, so it creates no block volume.
func (e *Engine) memberLaunch(plan Object, planPath, inventoryPath, admissionPath, slot, imageID, enrollmentPath, owner string) Object {
	inventory := readJSON(inventoryPath, 4*1024*1024, "manual region inventory")
	// The estimate fails above the plan's monthly ceiling.
	e.currentAdmission(plan, inventory, inventoryPath, admissionPath, planPath)
	ids := obj(plan["resource_ids"])
	if !truth(ids["workload_compartment"]) || !truth(ids["subnet"]) || !truth(ids["workload_network_security_group"]) || obj(inventory["preview_compartment_ids"])["workload"] != ids["workload_compartment"] {
		fail("member launch requires the plan-bound workload compartment, subnet, and workload network security group")
	}
	var host Object
	for _, v := range arr(plan["hosts"]) {
		if obj(v)["slot"] == slot && strings.HasPrefix(slot, "member-") {
			host = obj(v)
		}
	}
	if host == nil {
		fail("member launch requires a plan member slot")
	}
	name := memberName(plan, slot)
	for _, v := range active(inventory["resources"], "instance") {
		if obj(v)["display-name"] == name {
			fail(name + " already exists in the inventory")
		}
	}
	requireOCID(imageID, "image", text(plan["region"]))
	cell := str(plan["cell"])
	bundle := launchMaterial(enrollmentPath, "host enrollment bundle")
	if parsed, err := hostenroll.ParsePublicBundle([]byte(bundle)); err != nil || parsed.Cell != strings.ToLower(cell) || parsed.Region != cell {
		fail("host enrollment bundle is invalid or belongs to another cell")
	}
	descriptor, err := hostboot.Static(strings.ToLower(cell), cell, name).CanonicalBytes()
	if err != nil {
		fail("static host descriptor is invalid: " + err.Error())
	}
	metadata := Object{hostboot.MetadataKey: string(descriptor), hostboot.EnrollmentMetadataKey: bundle, "ssh_authorized_keys": validateSSH(owner)}
	size := 0
	for k, v := range metadata {
		size += len(k) + len(str(v))
	}
	if size > 32000 {
		fail(name + " launch metadata exceeds the OCI instance metadata limit")
	}
	return MemberLaunchDocument(plan, host, name, imageID, metadata)
}

// cellPlan is the read-only phase-2 plan: static names, placement, and the
// cost admission of every controller and C# database host.
func (e *Engine) cellPlan(plan, inventory Object, planPath, profilePath string) Object {
	cost := e.estimate(plan, inventory, planPath, e.now(), 15)
	cell := naming.RegionCell(str(plan["cell"]))
	cellName, err := cell.Name()
	image, imageErr := cell.Image()
	if err != nil || imageErr != nil {
		fail("plan cell has no static name or image name")
	}
	controllers, members := []any{}, []any{}
	peers := map[string]string{}
	for _, v := range arr(plan["hosts"]) {
		h := obj(v)
		slot := text(h["slot"])
		row := Object{"slot": slot, "fault_domain": h["fault_domain"], "private_ip": h["private_ip"], "shape": h["shape"], "ocpus": h["ocpus"], "memory_gb": h["memory_gb"], "boot_gb": h["boot_gb"]}
		if strings.HasPrefix(slot, "member-") {
			row["name"] = memberName(plan, slot)
			peers[text(row["name"])] = text(h["private_ip"])
			members = append(members, row)
		} else {
			row["name"] = controllerName(plan, slot)
			controllers = append(controllers, row)
		}
	}
	result := Object{"cell": cellName, "oci_region": plan["region"], "availability_domain": plan["availability_domain"], "image": image, "controllers": controllers, "members": members, "estimate": cost, "ceiling_usd": obj(plan["budget"])["monthly_limit"]}
	if profilePath == "" {
		return result
	}
	var profile struct {
		Env map[string]string `json:"env"`
	}
	if json.Unmarshal(readBytes(profilePath, 64*1024, "TerraBase workload profile"), &profile) != nil {
		fail("TerraBase workload profile is unreadable or invalid JSON")
	}
	parsed, err := terrabase.ParseProfile(profile.Env)
	if err != nil {
		fail("TerraBase workload profile is invalid: " + err.Error())
	}
	if len(parsed.Peers) != len(peers) {
		fail("TerraBase peers differ from the plan members")
	}
	for name, ip := range peers {
		if peer, ok := parsed.Peer(name); !ok || peer.Address.String() != fmt.Sprintf("%s:%d", ip, parsed.PeerPort) {
			fail("TerraBase peers differ from the plan members")
		}
	}
	result["terrabase_peers"] = profile.Env[terrabase.EnvPeers]
	return result
}
