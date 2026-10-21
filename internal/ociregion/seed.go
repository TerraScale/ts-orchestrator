package ociregion

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

var seedFields = []string{"schema_version", "slot", "shape", "ocpus", "memory_gb", "boot_gb", "boot_vpus_per_gb", "assign_public_ip", "compartment_id", "availability_domain", "fault_domain", "subnet_id", "network_security_group_ids", "image_id", "anchor_sha256", "manifest_sha256", "image_receipt_sha256", "admission_sha256", "inventory_sha256", "admission_admitted_at", "admission_expires_at", "monthly_estimate_usd", "create_identity"}

func canonicalSeed(value Object) []byte {
	if !exact(value, seedFields...) {
		fail("manual seed plan has an unexpected producer schema")
	}
	var wire []byte
	wire = append(wire, '{')
	for i, k := range seedFields {
		if i > 0 {
			wire = append(wire, ',')
		}
		wire = append(wire, must(json.Marshal(k))...)
		wire = append(wire, ':')
		wire = append(wire, must(json.Marshal(value[k]))...)
	}
	return append(wire, '}')
}
func createIdentity(plan Object, path string, manifest Object) string {
	if plan["seed_a_create_identity"] != nil {
		return str(plan["seed_a_create_identity"])
	}
	binding := strings.Join([]string{fileSHA(path), str(manifest["anchorSha256"]), str(manifest["manifestSha256"]), str(manifest["releaseReceiptSha256"])}, "\x00")
	return "seed-a-" + wireSHA([]byte(binding))[:32]
}
func validateManifest(path, cell string) []byte {
	wire := readBytes(path, 30*1024, "signed seed manifest")
	envelope := readJSON(path, 30*1024, "signed seed manifest")
	scope, payload := obj(envelope["scope"]), obj(envelope["payload"])
	if !eq(envelope["schemaVersion"], 1) || text(envelope["keyId"]) == "" || text(envelope["signature"]) == "" || scope["domain"] != "terrascale.bootstrap.manifest" || scope["role"] != "controller" || scope["slot"] != "controller-a" || scope["cell"] != cell || payload["cell"] != cell || !eq(payload["schemaVersion"], bootstrap.ManifestSchemaVersion) || payload["slot"] != "controller-a" || payload["seedSlot"] != "controller-a" {
		fail("signed manifest is not a controller-a seed envelope")
	}
	if !utf8.Valid(wire) {
		fail("signed seed manifest is not UTF-8 JSON")
	}
	if strings.ContainsRune(string(wire), 0) {
		fail("signed seed manifest contains an invalid NUL byte")
	}
	return wire
}
func validateSSH(path string) string {
	wire, err := os.ReadFile(path)
	if err != nil {
		fail("owner SSH public key is unreadable")
	}
	if len(wire) == 0 || len(wire) > 16*1024 {
		fail("owner SSH public key has invalid size")
	}
	for _, b := range wire {
		if b > 127 {
			fail("owner SSH public key must be ASCII")
		}
	}
	s := string(wire)
	line := strings.TrimSuffix(strings.TrimSuffix(s, "\n"), "\r")
	if strings.ContainsAny(line, "\r\n") {
		fail("owner SSH public key must contain exactly one OpenSSH key line")
	}
	parts := strings.Fields(line)
	if (len(parts) != 2 && len(parts) != 3) || parts[0] != "ssh-ed25519" {
		fail("owner SSH key must be one OpenSSH Ed25519 public key")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		fail("owner SSH Ed25519 key encoding is invalid")
	}
	if len(decoded) != 51 || binary.BigEndian.Uint32(decoded[:4]) != 11 || string(decoded[4:15]) != "ssh-ed25519" {
		fail("owner SSH key is not a canonical Ed25519 public key")
	}
	if binary.BigEndian.Uint32(decoded[15:19]) != 32 {
		fail("owner SSH key has an invalid Ed25519 public key length")
	}
	if len(parts) == 3 && !safeMatch(`[A-Za-z0-9._@+-]{1,128}`, parts[2]) {
		fail("owner SSH public key comment contains unsafe characters")
	}
	return strings.Join(parts, " ")
}
func seedUserData() []byte {
	console := `set -eu; IFS=' ' read -r key_type key_data key_comment < /etc/ssh/ssh_host_ed25519_key.pub; test "$key_type" = ssh-ed25519; test -n "$key_data"; printf '\nTERRASCALE_SEED_A_HOST_KEY_BEGIN\n%s %s\nTERRASCALE_SEED_A_HOST_KEY_END\n' "$key_type" "$key_data" > /dev/console`
	wire := `{"runcmd":[` + string(must(json.Marshal(console))) + `]`
	return []byte("#cloud-config\n" + wire + "}\n")
}
func launchMaterial(path, label string) string {
	wire := readBytes(path, 64*1024, label)
	var v any
	if !utf8.Valid(wire) || json.Unmarshal(wire, &v) != nil {
		fail(label + " must be UTF-8 JSON")
	}
	return string(wire)
}
func (e *Engine) seedLaunch(plan Object, reviewedPath, manifestPath, identityPath, anchorPath, enrollmentPath, owner, managedReceiptPath, managedDelegationPath string) Object {
	reviewed := readJSON(reviewedPath, 30*1024, "reviewed seed plan")
	manifest := validateManifest(manifestPath, str(plan["cell"]))
	anchor := launchMaterial(anchorPath, "signed bootstrap anchor")
	if wireSHA(manifest) != reviewed["manifest_sha256"] || wireSHA([]byte(anchor)) != reviewed["anchor_sha256"] {
		fail("seed launch manifest or anchor differs from the reviewed seed plan")
	}
	identity := launchMaterial(identityPath, "bootstrap identity")
	var id Object
	must(true, json.Unmarshal([]byte(identity), &id))
	if !entityid.Valid(text(id["deploymentId"])) {
		fail("bootstrap identity has an invalid deployment ID")
	}
	var host Object
	for _, v := range arr(plan["hosts"]) {
		if obj(v)["slot"] == "controller-a" {
			host = obj(v)
			break
		}
	}
	if host == nil {
		fail("plan has no controller-a host")
	}
	metadata := Object{"terrascale-bootstrap": `{"schemaVersion":1,"slot":"controller-a"}`, "terrascale-controller-manifest-v1": string(manifest), "terrascale-bootstrap-identity-v1": identity, "terrascale-bootstrap-anchor-v1": anchor, "terrascale-host-enrollment-v1": launchMaterial(enrollmentPath, "host enrollment bundle"), "ssh_authorized_keys": validateSSH(owner), "user_data": base64.StdEncoding.EncodeToString(seedUserData())}
	metadata[bootstrapstart.ManagedHostImageReceiptMetadataKey] = launchMaterial(managedReceiptPath, "managed host image receipt")
	metadata[bootstrapstart.ManagedHostImageDelegationMetadataKey] = launchMaterial(managedDelegationPath, "managed host image delegation")
	size := 0
	for k, v := range metadata {
		size += len(k) + len(str(v))
	}
	if size > 32000 {
		fail("controller-a launch metadata exceeds the OCI instance metadata limit")
	}
	return SeedLaunchDocument(reviewed, host, controllerName(plan, "controller-a"), metadata)
}

// controllerName is a controller slot's static name in the plan's cell, e.g.
// gru-1-ctl-1. The deployment ID stays in the identity launch metadata.
func controllerName(plan Object, slot string) string {
	name, err := naming.RegionCell(str(plan["cell"])).ControllerSlot(slot)
	if err != nil {
		fail("plan cell has no static controller name: " + err.Error())
	}
	return name
}

// SeedLaunchDocument is the controller-a launch input `preview seed-launch`
// writes. internal/attempt decodes it strictly, so its members are pinned by
// a round-trip test there.
func SeedLaunchDocument(reviewed, host Object, name string, metadata Object) Object {
	return Object{"availabilityDomain": reviewed["availability_domain"], "faultDomain": reviewed["fault_domain"], "compartmentId": reviewed["compartment_id"], "displayName": name, "shape": reviewed["shape"], "shapeConfig": Object{"ocpus": reviewed["ocpus"], "memoryInGBs": reviewed["memory_gb"]}, "sourceDetails": Object{"sourceType": "image", "imageId": reviewed["image_id"], "bootVolumeSizeInGBs": reviewed["boot_gb"], "bootVolumeVpusPerGB": reviewed["boot_vpus_per_gb"]}, "subnetId": reviewed["subnet_id"], "privateIp": host["private_ip"], "nsgIds": reviewed["network_security_group_ids"], "assignPublicIp": reviewed["assign_public_ip"], "metadata": metadata, "freeformTags": Object{"BootstrapCreateKey": reviewed["create_identity"]}}
}
func verifiedPrefix(plan, ids, anchor, manifest Object, namespace string) string {
	domain := obj(anchor["storageDomain"])
	if _, ok := domain["prefix"]; !ok {
		fail("verified bootstrap anchor lacks its storage domain")
	}
	prefix := canonicalPrefix(domain["prefix"])
	buckets := obj(plan["foundation_buckets"])
	if !eq(anchor["schemaVersion"], bootstrap.BootstrapAnchorSchemaVersion) || anchor["anchorSha256"] != manifest["anchorSha256"] || anchor["cell"] != plan["cell"] || anchor["ociRegion"] != plan["region"] || prefix != requiredPrefix(plan) || domain["namespace"] != namespace || domain["ledgerBucket"] != buckets["ledger"] || domain["headBucket"] != buckets["head"] || domain["ledgerKmsKeyOcid"] != ids["key"] || domain["headKmsKeyOcid"] != ids["key"] {
		fail("verified bootstrap anchor storage domain differs from the reviewed plan")
	}
	return prefix
}
func (e *Engine) verifySeed(plan Object, inventoryPath, admissionPath string, anchor, manifest Object, receiptPath, verification, path string) Object {
	inventory := readJSON(inventoryPath, 4*1024*1024, "manual region inventory")
	admission := readJSON(admissionPath, 64*1024, "manual budget admission")
	cost := e.estimate(plan, inventory, path, e.now(), 15)
	admitted, aok := parseTime(admission["admitted_at"])
	expires, eok := parseTime(admission["expires_at"])
	if !aok || !eok {
		fail("budget admission has invalid timestamps")
	}
	_, ao := admitted.Zone()
	_, eo := expires.Zone()
	now := e.now()
	if path == "" {
		path = sourcePath(e, plan)
	}
	if !eq(admission["schema_version"], 2) || ao != 0 || eo != 0 || admitted.After(now.Add(30*time.Second)) || now.Before(admitted) || !now.Before(expires) || expires.After(admitted.Add(15*time.Minute+30*time.Second)) || admission["plan_sha256"] != fileSHA(path) || admission["inventory_sha256"] != fileSHA(inventoryPath) || !eq(admission["preview_compartment_ids"], inventory["preview_compartment_ids"]) || !eq(admission["estimate"], cost) {
		fail("budget admission is stale or does not match the current plan and inventory")
	}
	ids, compartments := obj(plan["resource_ids"]), obj(inventory["preview_compartment_ids"])
	if !truth(ids["control_compartment"]) || !truth(ids["network_compartment"]) || !truth(ids["workload_compartment"]) || !eq(compartments, Object{"control": ids["control_compartment"], "network": ids["network_compartment"], "workload": ids["workload_compartment"]}) {
		fail("seed preflight requires exact plan-bound control, network, and workload compartments")
	}
	foundation := Object{}
	for _, row := range [][2]string{{"vcn", "vcn"}, {"subnet", "subnet"}, {"network-security-group", "network_security_group"}} {
		matches := []any{}
		for _, v := range active(inventory["resources"], row[0]) {
			m := obj(v)
			if m["id"] == ids[row[1]] && m["compartment-id"] == ids["network_compartment"] {
				matches = append(matches, v)
			}
		}
		if !truth(ids[row[1]]) || len(matches) != 1 {
			fail("seed preflight requires the exact recorded live " + row[0])
		}
		foundation[row[0]] = matches[0]
	}
	vcn, subnet := obj(foundation["vcn"]), obj(foundation["subnet"])
	if vcn["cidr-block"] != plan["network_cidr"] || subnet["cidr-block"] != plan["subnet_cidr"] || subnet["prohibit-public-ip-on-vnic"] != true || subnet["prohibit-internet-ingress"] != true {
		fail("seed preflight requires the exact private preview network")
	}
	for _, role := range []string{"ledger", "head", "backup", "material"} {
		name := obj(plan["foundation_buckets"])[role]
		versioning := "Disabled"
		if role == "head" || role == "material" {
			versioning = "Enabled"
		}
		matches := 0
		for _, v := range arr(inventory["buckets"]) {
			b := obj(v)
			if b["compartment_id"] == ids["control_compartment"] && b["region"] == plan["region"] && b["name"] == name && b["storage_tier"] == "Standard" && b["versioning"] == versioning {
				matches++
			}
		}
		if matches != 1 {
			fail("seed preflight requires the exact " + role + " control bucket")
		}
	}
	liveIDs := obj(e.call("required_resource_ids", []any{plan}, Object{}))
	for _, name := range []string{"check_live_compartments", "check_live_vault", "check_live_network"} {
		e.call(name, []any{plan, liveIDs}, Object{})
	}
	namespace := str(e.call("check_live_buckets", []any{plan, liveIDs}, Object{}))
	prefix := verifiedPrefix(plan, liveIDs, anchor, manifest, namespace)
	e.call("check_live_iam", []any{plan, liveIDs, prefix}, Object{})
	var seed Object
	for _, v := range arr(plan["hosts"]) {
		if obj(v)["slot"] == "controller-a" {
			seed = obj(v)
			break
		}
	}
	profile := obj(manifest["profile"])
	architecture := text(seed["architecture"])
	if architecture != "arm64" && architecture != "amd64" {
		fail("seed controller-a host has no qualified architecture")
	}
	nsgIDs := []string{str(ids["network_security_group"])}
	if !eq(manifest["schemaVersion"], bootstrap.ManifestSchemaVersion) || manifest["cell"] != plan["cell"] || manifest["ociRegion"] != plan["region"] || manifest["slot"] != seed["slot"] || manifest["imageArchitecture"] != "linux-"+architecture || profile["slot"] != seed["slot"] || profile["compartmentOcid"] != ids["control_compartment"] || profile["availabilityDomain"] != plan["availability_domain"] || profile["faultDomain"] != seed["fault_domain"] || profile["subnetOcid"] != ids["subnet"] || !eq(profile["networkSecurityGroupOcids"], nsgIDs) || profile["shape"] != seed["shape"] || !safeMatch(`[0-9a-f]{64}`, manifest["anchorSha256"]) || !safeMatch(`[0-9a-f]{64}`, manifest["manifestSha256"]) || !safeMatch(`[0-9a-f]{64}`, manifest["releaseReceiptSha256"]) {
		fail("verified seed manifest differs from the recorded controller-a profile")
	}
	if fileSHA(receiptPath) != manifest["releaseReceiptSha256"] {
		fail("verified image receipt bytes differ from the signed seed manifest")
	}
	image := text(manifest["imageOcid"])
	if !safeMatch(`ocid1\.image\.[a-z0-9-]+\.[a-z0-9-]*\.[a-z0-9-]+`, image) || !strings.HasPrefix(verification, "verified OCI image="+image+" region="+str(plan["cell"])+" ") || !strings.Contains(verification, " arch="+architecture+" ") {
		fail("verified image candidate differs from the signed seed manifest")
	}
	compatible := false
	for _, v := range rows(e.oci(str(plan["region"]), "compute", "shape", "list", "--compartment-id", str(ids["control_compartment"]), "--availability-domain", str(plan["availability_domain"]), "--image-id", image, "--all")) {
		shape := obj(v)
		if shape["shape"] == seed["shape"] {
			observed, err := catalog.ShapeArchitecture(text(shape["processor-description"]))
			if err != nil || observed != architecture {
				fail("seed image shape has an unknown or mismatched processor architecture")
			}
			compatible = true
		}
	}
	if !compatible {
		fail("seed image is not compatible with the planned host shape")
	}
	for _, v := range active(inventory["resources"], "instance") {
		m := obj(v)
		_, tag := obj(m["freeform-tags"])["BootstrapCreateKey"]
		if m["id"] == obj(ids["instances"])["controller-a"] || tag {
			fail("seed controller already exists in the preview inventory")
		}
	}
	return Object{"schema_version": 2, "slot": seed["slot"], "shape": seed["shape"], "ocpus": seed["ocpus"], "memory_gb": seed["memory_gb"], "boot_gb": seed["boot_gb"], "boot_vpus_per_gb": plan["volume_vpus_per_gb"], "assign_public_ip": false, "compartment_id": ids["control_compartment"], "availability_domain": profile["availabilityDomain"], "fault_domain": profile["faultDomain"], "subnet_id": profile["subnetOcid"], "network_security_group_ids": profile["networkSecurityGroupOcids"], "image_id": image, "anchor_sha256": manifest["anchorSha256"], "manifest_sha256": manifest["manifestSha256"], "image_receipt_sha256": manifest["releaseReceiptSha256"], "admission_sha256": fileSHA(admissionPath), "inventory_sha256": fileSHA(inventoryPath), "admission_admitted_at": admission["admitted_at"], "admission_expires_at": admission["expires_at"], "monthly_estimate_usd": cost["total"]}
}
func (e *Engine) checkedTool(command ...string) string {
	args := make([]any, len(command))
	for i, v := range command {
		args[i] = v
	}
	return str(e.call("checked_tool", args, Object{}))
}
func (e *Engine) realChecked(args []any) string {
	command := make([]string, len(args))
	for i, v := range args {
		command[i] = str(v)
	}
	p := e.process(command)
	if number(p["returncode"]) != 0 {
		fail(fmt.Sprintf("verification tool %s rejected its inputs (exit %s)", filepath.Base(command[0]), str(p["returncode"])))
	}
	return strings.TrimSpace(text(p["stdout"]))
}
func (e *Engine) seedPreflight(args, plan Object, path string) Object {
	roots := arr(args["bootstrap_root"])
	if len(roots) == 0 {
		fail("seed preflight requires at least one bootstrap trust root")
	}
	requiredPrefix(plan)
	base := []string{pathValue(args["bootstrap_tool"]), "bootstrap"}
	rootArgs := []string{}
	for _, v := range roots {
		rootArgs = append(rootArgs, "--root-key", pathValue(v))
	}
	anchorCmd := append(append(append([]string{}, base...), "verify-anchor", "--anchor", pathValue(args["anchor"]), "--identity", pathValue(args["identity"])), rootArgs...)
	manifestCmd := append(append(append([]string{}, base...), "verify-manifest", "--anchor", pathValue(args["anchor"]), "--manifest", pathValue(args["manifest"]), "--identity", pathValue(args["identity"]), "--slot", "controller-a", "--image-ocid", str(args["image_ocid"])), rootArgs...)
	var anchor, manifest Object
	must(true, json.Unmarshal([]byte(e.checkedTool(anchorCmd...)), &anchor))
	must(true, json.Unmarshal([]byte(e.checkedTool(manifestCmd...)), &manifest))
	releaseCmd := []string{pathValue(args["release_tool"]), "release", "verify-image", "--receipt", pathValue(args["image_receipt"]), "--delegation", pathValue(args["release_delegation"]), "--root-key", pathValue(args["release_root"]), "--image-file", pathValue(args["image_file"]), "--base-image-file", pathValue(args["base_image_file"]), "--kernel-file", pathValue(args["kernel_file"]), "--region", str(plan["cell"]), "--environment", str(manifest["environment"])}
	verification := e.checkedTool(releaseCmd...)
	reviewed := obj(e.call("verify_seed_preflight", []any{plan, args["inventory"], args["admission"], anchor, manifest, args["image_receipt"], verification, Path(path)}, Object{}))
	reviewed["create_identity"] = e.call("create_identity", []any{plan, Path(path), manifest}, Object{})
	return reviewed
}
