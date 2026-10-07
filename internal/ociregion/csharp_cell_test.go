package ociregion

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
)

var cellNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func checkedInPlan() string { return filepath.Join("..", "..", "deploy", "oci-region", "plan.json") }

func fakeOCID(kind, region, key string) string {
	return "ocid1." + kind + ".oc1." + region + ".fake" + strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", "")
}

// bindPhase1 binds every C# phase-1 foundation ID, leaving the Rust-era
// LiveS3Credential and the later public API stage unbound.
func bindPhase1(raw Object) {
	ids, region := obj(raw["resource_ids"]), text(raw["region"])
	for _, key := range []string{"control_compartment", "network_compartment", "workload_compartment", "vault", "key", "vcn", "subnet", "network_security_group", "workload_network_security_group", "security_list", "route_table", "service_gateway", "local_peering_gateway", "controller_dynamic_group", "controller_policy", "objectstorage_key_policy", "host_dynamic_group"} {
		kind, r := resourceKinds[key], region
		if kind == "compartment" || kind == "policy" || kind == "dynamicgroup" {
			r = ""
		}
		ids[key] = fakeOCID(kind, r, key)
	}
	obj(raw["operator_gateway"])["local_peering_gateway_id"] = fakeOCID("localpeeringgateway", region, "operator")
	netbird := obj(raw["netbird"])
	netbird["secret_compartment_id"] = fakeOCID("compartment", "", "netbird")
	netbird["setup_key_secret_id"] = fakeOCID("vaultsecret", region, "netbird")
	netbird["policy_id"] = fakeOCID("policy", "", "netbird")
}

// writePlan copies the checked-in plan into a temporary directory after mutate.
func writePlan(t *testing.T, mutate ...func(Object)) string {
	t.Helper()
	raw := readJSON(checkedInPlan(), 64*1024, "plan")
	for _, m := range mutate {
		m(raw)
	}
	path := filepath.Join(t.TempDir(), "plan.json")
	writeJSON(path, raw)
	return path
}

func mustCapture[T any](t *testing.T, fn func() T) T {
	t.Helper()
	v, err := capture(fn)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func wantFailure(t *testing.T, want string, fn func()) {
	t.Helper()
	_, err := capture(func() bool { fn(); return true })
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

// cellInventory is a fresh inventory of the unrelated Forgejo baseline, the
// plan-bound gateways, and extra instances.
func cellInventory(plan Object, path string, instances ...Object) Object {
	ids, existing, shared := obj(plan["resource_ids"]), obj(plan["existing_forgejo"]), plan["shared_compartment_id"]
	resources := []any{
		Object{"kind": "instance", "id": existing["instance_id"], "compartment-id": shared, "lifecycle-state": "RUNNING", "shape": "VM.Standard.A1.Flex", "shape-config": Object{"ocpus": existing["expected_ocpus"], "memory-in-gbs": existing["expected_memory_gb"]}},
		Object{"kind": "boot-volume", "id": existing["boot_volume_id"], "compartment-id": shared, "lifecycle-state": "AVAILABLE", "size-in-gbs": 50, "vpus-per-gb": 10},
		Object{"kind": "volume", "id": existing["data_volume_id"], "compartment-id": shared, "lifecycle-state": "AVAILABLE", "size-in-gbs": 50, "vpus-per-gb": 10},
		Object{"kind": "public-ip", "id": existing["public_ip_id"]},
		Object{"kind": "internet-gateway", "id": existing["internet_gateway_id"], "compartment-id": shared, "vcn-id": existing["vcn_id"], "lifecycle-state": "AVAILABLE"},
	}
	if id := obj(plan["operator_gateway"])["local_peering_gateway_id"]; id != nil {
		resources = append(resources, Object{"kind": "local-peering-gateway", "id": id, "compartment-id": shared, "vcn-id": existing["vcn_id"], "lifecycle-state": "AVAILABLE"})
	}
	if ids["local_peering_gateway"] != nil {
		resources = append(resources, Object{"kind": "local-peering-gateway", "id": ids["local_peering_gateway"], "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"], "lifecycle-state": "AVAILABLE"})
	}
	for _, m := range instances {
		resources = append(resources, m)
	}
	return Object{"schema_version": 2, "captured_at": pythonTime(cellNow), "plan_sha256": fileSHA(path), "tenancy_id": plan["tenancy_id"], "regions": []any{plan["region"]}, "preview_compartment_ids": Object{"control": ids["control_compartment"], "network": ids["network_compartment"], "workload": ids["workload_compartment"]}, "resources": resources, "buckets": []any{}, "images": []any{}}
}

func dbHost(plan Object, name string, tags Object) Object {
	return Object{"kind": "instance", "id": fakeOCID("instance", "sa-saopaulo-1", name), "compartment-id": obj(plan["resource_ids"])["workload_compartment"], "lifecycle-state": "RUNNING", "display-name": name, "shape": "VM.Standard.A1.Flex", "shape-config": Object{"ocpus": 1, "memory-in-gbs": 6}, "freeform-tags": tags}
}

func TestFoundationInspectionNeedsNoRustEraResources(t *testing.T) {
	e := cellEngine()
	plan := mustCapture(t, func() Object { return e.loadPlan(writePlan(t, bindPhase1)) })
	ids := mustCapture(t, func() Object { return e.requiredIDs(plan) })
	identity, netbird := obj(plan["identity"]), obj(plan["netbird"])
	matching := func(key string) string { return "ALL {instance.compartment.id = '" + str(ids[key]) + "'}" }
	keyStatement := "Allow service objectstorage-sa-saopaulo-1 to use keys in compartment gru-1-control where all {target.key.id='" + str(ids["key"]) + "', any {request.permission='KEY_READ', request.permission='KEY_ENCRYPT', request.permission='KEY_DECRYPT'}}"
	responses := map[string]Object{
		text(ids["controller_dynamic_group"]): {"lifecycle-state": "ACTIVE", "name": identity["controller_dynamic_group_name"], "matching-rule": matching("control_compartment")},
		text(ids["controller_policy"]):        {"lifecycle-state": "ACTIVE", "name": identity["controller_policy_name"], "compartment-id": plan["parent_compartment_id"], "statements": arr(controllerStatements(plan, ids, ""))},
		text(ids["objectstorage_key_policy"]): {"lifecycle-state": "ACTIVE", "name": identity["objectstorage_key_policy_name"], "compartment-id": ids["control_compartment"], "statements": []any{keyStatement}},
		text(ids["host_dynamic_group"]):       {"lifecycle-state": "ACTIVE", "name": identity["host_dynamic_group_name"], "matching-rule": matching("workload_compartment")},
		text(netbird["policy_id"]):            {"lifecycle-state": "ACTIVE", "name": netbird["policy_name"], "compartment-id": netbird["secret_compartment_id"], "statements": arr(netbirdStatements(plan))},
		text(netbird["setup_key_secret_id"]):  {"lifecycle-state": "ACTIVE", "compartment-id": netbird["secret_compartment_id"]},
	}
	read := []string{}
	e.Dependency = func(name string, args []any, kwargs Object) (any, error) {
		id := text(args[len(args)-1])
		read = append(read, id)
		response, ok := responses[id]
		if name != "oci" || !ok {
			return nil, errors.New("unexpected OCI read " + str(args))
		}
		response["id"] = id
		return response, nil
	}
	mustCapture(t, func() bool { e.liveIAM(plan, ids, ""); e.livePublic(plan, ids); return true })
	if len(read) != len(responses) {
		t.Fatalf("live IAM reads = %v, want exactly the controller, host, and NetBird resources", read)
	}
}

func TestFoundationInspectionRejectsPartialLegacyAndPublicBindings(t *testing.T) {
	e := cellEngine()
	for name, mutate := range map[string]func(Object){
		"host policy only": func(raw Object) { obj(raw["resource_ids"])["host_policy"] = fakeOCID("policy", "", "host") },
		"secret only": func(raw Object) {
			raw["host_credential_secret"] = Object{"compartment_id": fakeOCID("compartment", "", "host"), "secret_id": fakeOCID("vaultsecret", "sa-saopaulo-1", "host")}
		},
	} {
		plan := mustCapture(t, func() Object { return e.loadPlan(writePlan(t, bindPhase1, mutate)) })
		t.Run(name, func(t *testing.T) {
			wantFailure(t, "host LiveS3Credential secret and policy together or not at all", func() { e.requiredIDs(plan) })
			wantFailure(t, "host LiveS3Credential secret and policy together or not at all", func() { e.liveIAM(plan, obj(plan["resource_ids"]), "") })
		})
	}
	plan := mustCapture(t, func() Object {
		return e.loadPlan(writePlan(t, bindPhase1, func(raw Object) {
			obj(raw["resource_ids"])["internet_gateway"] = fakeOCID("internetgateway", "sa-saopaulo-1", "public")
		}))
	})
	wantFailure(t, "every public API resource ID or none", func() { e.requiredIDs(plan) })
	wantFailure(t, "every public API resource ID or none", func() { e.livePublic(plan, obj(plan["resource_ids"])) })
}

func TestInventoryAdmitsOperatorLaunchedCSharpHosts(t *testing.T) {
	e := cellEngine()
	path := writePlan(t, bindPhase1)
	plan := mustCapture(t, func() Object { return e.loadPlan(path) })
	tags := func(name string) Object { return memberTags(plan, name) }
	mustCapture(t, func() bool {
		e.verifyInventory(plan, cellInventory(plan, path, dbHost(plan, "gru-1-db-1", tags("gru-1-db-1")), dbHost(plan, "gru-1-db-2", tags("gru-1-db-2"))), path, cellNow, 15)
		return true
	})
	wrongOwner, managed := tags("gru-1-db-1"), tags("gru-1-db-1")
	wrongOwner["terrascale-owner"] = "another-owner"
	managed["terrascale-managed-by"] = "ts-orchestrator"
	for name, host := range map[string]Object{
		"wrong owner": dbHost(plan, "gru-1-db-1", wrongOwner),
		"wrong name":  dbHost(plan, "gru-1-db-9", tags("gru-1-db-9")),
		"tag node":    dbHost(plan, "gru-1-db-1", tags("gru-1-db-2")),
		"extra tag":   dbHost(plan, "gru-1-db-1", managed),
		"control plane": func() Object {
			h := dbHost(plan, "gru-1-db-1", tags("gru-1-db-1"))
			h["compartment-id"] = obj(plan["resource_ids"])["control_compartment"]
			return h
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			wantFailure(t, "preview instance has no approved owner", func() { e.verifyInventory(plan, cellInventory(plan, path, host), path, cellNow, 15) })
		})
	}
	duplicate := dbHost(plan, "gru-1-db-1", tags("gru-1-db-1"))
	second := dbHost(plan, "gru-1-db-1", tags("gru-1-db-1"))
	second["id"] = fakeOCID("instance", "sa-saopaulo-1", "other")
	wantFailure(t, "two active instances share the C# database host name gru-1-db-1", func() { e.verifyInventory(plan, cellInventory(plan, path, duplicate, second), path, cellNow, 15) })
	// Hosts match one of the plan's host profiles exactly.
	small := dbHost(plan, "gru-1-db-1", tags("gru-1-db-1"))
	small["shape-config"] = Object{"ocpus": 1, "memory-in-gbs": 4}
	wantFailure(t, "preview instance dimensions exceed the plan", func() { e.verifyInventory(plan, cellInventory(plan, path, small), path, cellNow, 15) })
	for _, v := range arr(plan["hosts"]) {
		obj(v)["memory_gb"] = 4
	}
	mustCapture(t, func() bool { e.verifyInventory(plan, cellInventory(plan, path, small), path, cellNow, 15); return true })
}

func enrollmentBundle(t *testing.T) []byte {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "member launch CA"}, NotBefore: cellNow.Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	responsePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	accountPublic, err := account.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := hostenroll.PublicBundle{SchemaVersion: 1, Cell: "gru", Region: "GRU",
		ControllerEndpoints: []string{"10.251.0.11:8443", "10.251.0.12:8443", "10.251.0.13:8443"},
		NATSURLs:            []string{"tls://10.251.0.11:4222", "tls://10.251.0.12:4222", "tls://10.251.0.13:4222"},
		CAPEM:               string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), ControllerResponsePublicKey: base64.StdEncoding.EncodeToString(responsePublic),
		CellAccountNKey: accountPublic, Environment: "production", InstallRoot: hostenroll.ImageInstallRoot, StateRoot: hostenroll.ImageStateRoot,
		ManagedRuntimeRoot: hostenroll.ImageManagedRuntimeRoot, WorkloadUID: hostenroll.ImageWorkloadUID, WorkloadGID: hostenroll.ImageWorkloadGID}
	wire, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func ownerSSHKey(t *testing.T) []byte {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire := binary.BigEndian.AppendUint32(nil, 11)
	wire = binary.BigEndian.AppendUint32(append(wire, "ssh-ed25519"...), 32)
	return []byte("ssh-ed25519 " + base64.StdEncoding.EncodeToString(append(wire, public...)) + " operator\n")
}

type launchFixture struct {
	dir, plan, inventory, admission, enrollment, owner string
}

// memberLaunchFixture writes a bound plan, a fresh inventory with instances,
// a current admission produced by `admit`, and the launch material.
func memberLaunchFixture(t *testing.T, instances ...func(Object) Object) launchFixture {
	t.Helper()
	path := writePlan(t, bindPhase1)
	dir := filepath.Dir(path)
	plan := mustCapture(t, func() Object { return cellEngine().loadPlan(path) })
	extra := []Object{}
	for _, instance := range instances {
		extra = append(extra, instance(plan))
	}
	f := launchFixture{dir, path, filepath.Join(dir, "inventory.json"), filepath.Join(dir, "admission.json"), filepath.Join(dir, "enrollment.json"), filepath.Join(dir, "owner.pub")}
	writeJSON(f.inventory, cellInventory(plan, path, extra...))
	for file, wire := range map[string][]byte{f.enrollment: enrollmentBundle(t), f.owner: ownerSSHKey(t)} {
		if err := os.WriteFile(file, wire, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := cellEngine().Run([]string{"admit", "--plan", path, "--inventory", f.inventory, "--out", f.admission}, io.Discard); err != nil {
		t.Fatal(err)
	}
	return f
}

// cellEngine refuses every OCI read, so no test reaches a live tenancy.
func cellEngine() *Engine {
	return &Engine{Clock: func() time.Time { return cellNow }, Dependency: func(name string, args []any, kwargs Object) (any, error) {
		return nil, errors.New("unexpected " + name + " call " + str(args))
	}}
}

func (f launchFixture) run(e *Engine, out io.Writer, slot, image string) (string, error) {
	path := filepath.Join(f.dir, "launch.json")
	return path, e.Run([]string{"member-launch", "--plan", f.plan, "--inventory", f.inventory, "--admission", f.admission, "--slot", slot, "--image-ocid", image, "--host-enrollment", f.enrollment, "--owner-ssh-public-key", f.owner, "--out", path}, out)
}

const memberImage = "ocid1.image.oc1.sa-saopaulo-1.fakegru1arm64"

func TestMemberLaunchWritesStaticCSharpHostInput(t *testing.T) {
	f := memberLaunchFixture(t)
	var stdout bytes.Buffer
	path, err := f.run(cellEngine(), &stdout, "member-a", memberImage)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 || !strings.HasPrefix(stdout.String(), "wrote gru-1-db-1 launch input bytes=") {
		t.Fatalf("launch input %v %v, stdout %q", info, err, stdout.String())
	}
	launch := readJSON(path, 64*1024, "launch")
	plan := readJSON(f.plan, 64*1024, "plan")
	ids := obj(plan["resource_ids"])
	want := Object{"availabilityDomain": "YDvv:SA-SAOPAULO-1-AD-1", "faultDomain": "FAULT-DOMAIN-1", "compartmentId": ids["workload_compartment"], "displayName": "gru-1-db-1", "shape": "VM.Standard.A1.Flex", "shapeConfig": Object{"ocpus": 1, "memoryInGBs": 6}, "sourceDetails": Object{"sourceType": "image", "imageId": memberImage, "bootVolumeSizeInGBs": 50, "bootVolumeVpusPerGB": 10}, "subnetId": ids["subnet"], "privateIp": "10.251.0.21", "nsgIds": []any{ids["workload_network_security_group"]}, "assignPublicIp": false, "freeformTags": Object{"terrascale-owner": "ts-470-gru-rebuild-2", "terrascale-resource": "terrabase-host", "terrascale-host-node": "gru-1-db-1"}}
	metadata := obj(launch["metadata"])
	delete(launch, "metadata")
	if !eq(launch, want) {
		t.Fatalf("launch input = %v, want %v", launch, want)
	}
	enrollment, _ := os.ReadFile(f.enrollment)
	if !exact(metadata, hostboot.MetadataKey, hostboot.EnrollmentMetadataKey, "ssh_authorized_keys") || metadata[hostboot.MetadataKey] != `{"schema_version":2,"cell":"gru","region":"GRU","node":"gru-1-db-1"}` || metadata[hostboot.EnrollmentMetadataKey] != string(enrollment) || !strings.HasPrefix(text(metadata["ssh_authorized_keys"]), "ssh-ed25519 ") {
		t.Fatalf("launch metadata = %v", metadata)
	}
}

func TestMemberLaunchRejectsUnadmittedOrInvalidInputs(t *testing.T) {
	f := memberLaunchFixture(t)
	expired := cellEngine()
	expired.Clock = func() time.Time { return cellNow.Add(16 * time.Minute) }
	for name, test := range map[string]struct {
		engine      *Engine
		slot, image string
		want        string
	}{
		"expired admission": {expired, "member-a", memberImage, "stale"},
		"controller slot":   {cellEngine(), "controller-a", memberImage, "requires a plan member slot"},
		"unplanned slot":    {cellEngine(), "member-c", memberImage, "requires a plan member slot"},
		"foreign image":     {cellEngine(), "member-a", "ocid1.image.oc1.us-ashburn-1.fakeimage", "invalid image OCID"},
		"not an image":      {cellEngine(), "member-a", "ocid1.instance.oc1.sa-saopaulo-1.fakeimage", "invalid image OCID"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.run(test.engine, io.Discard, test.slot, test.image); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	admission := readJSON(f.admission, 64*1024, "admission")
	obj(admission["estimate"])["total"] = "1.00"
	writeJSON(f.admission, admission)
	if _, err := f.run(cellEngine(), io.Discard, "member-a", memberImage); err == nil || !strings.Contains(err.Error(), "does not match the exact current plan and inventory") {
		t.Fatalf("mismatched admission: %v", err)
	}
	existing := memberLaunchFixture(t, func(plan Object) Object { return dbHost(plan, "gru-1-db-1", memberTags(plan, "gru-1-db-1")) })
	if _, err := existing.run(cellEngine(), io.Discard, "member-a", memberImage); err == nil || !strings.Contains(err.Error(), "gru-1-db-1 already exists in the inventory") {
		t.Fatalf("existing host: %v", err)
	}
	if _, err := existing.run(cellEngine(), io.Discard, "member-b", memberImage); err != nil {
		t.Fatalf("second host after the first: %v", err)
	}
}

func cellPlanOutput(t *testing.T, plan string, extra ...string) (Object, error) {
	t.Helper()
	dir := t.TempDir()
	loaded := mustCapture(t, func() Object { return cellEngine().loadPlan(plan) })
	inventory := filepath.Join(dir, "inventory.json")
	writeJSON(inventory, cellInventory(loaded, plan))
	var stdout bytes.Buffer
	if err := cellEngine().Run(append([]string{"cell-plan", "--plan", plan, "--inventory", inventory}, extra...), &stdout); err != nil {
		return nil, err
	}
	v, err := decodeJSON(stdout.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return obj(v), nil
}

func TestCellPlanNamesTheCheckedInPhase2Cell(t *testing.T) {
	profile := filepath.Join("..", "..", "deploy", "oci-region", "terrabase-gru-1-profile.json")
	result, err := cellPlanOutput(t, checkedInPlan(), "--profile", profile)
	if err != nil {
		t.Fatal(err)
	}
	names := func(key string) string {
		r := []string{}
		for _, v := range arr(result[key]) {
			r = append(r, text(obj(v)["name"])+"@"+text(obj(v)["private_ip"]))
		}
		return strings.Join(r, ",")
	}
	if result["cell"] != "gru-1" || result["oci_region"] != "sa-saopaulo-1" || result["image"] != "gru-1-arm64" || !eq(result["ceiling_usd"], 200) || greater(obj(result["estimate"])["total"], 200) ||
		names("controllers") != "gru-1-ctl-1@10.251.0.11,gru-1-ctl-2@10.251.0.12,gru-1-ctl-3@10.251.0.13" || names("members") != "gru-1-db-1@10.251.0.21,gru-1-db-2@10.251.0.22" ||
		result["terrabase_peers"] != "gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443" {
		t.Fatalf("cell plan = %v", result)
	}
}

// The checked-in sfo-1 plan founds a colocated cell of ts-sfo-1..3 outside
// the home region, beside ts-ops's peering gateway of another cell.
func TestCellPlanNamesTheCheckedInSFOCell(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "oci-region", "sfo-1-plan.json")
	plan := mustCapture(t, func() Object { return cellEngine().loadPlan(path) })
	profile := filepath.Join(t.TempDir(), "terrabase-sfo-1-profile.json")
	writeJSON(profile, Object{"env": Object{"TERRABASE_REGION": "sfo-1", "TERRABASE_PEER_PORT": "9443", "TERRABASE_CLIENT_PORT": "9465",
		"TERRABASE_PEERS": "ts-sfo-1=10.252.0.11:9443,ts-sfo-2=10.252.0.12:9443,ts-sfo-3=10.252.0.13:9443"}})
	existing := obj(plan["existing_forgejo"])
	gru := Object{"kind": "local-peering-gateway", "id": fakeOCID("localpeeringgateway", "sa-saopaulo-1", "gru"), "compartment-id": plan["shared_compartment_id"], "vcn-id": existing["vcn_id"], "lifecycle-state": "AVAILABLE"}
	inventory := filepath.Join(t.TempDir(), "inventory.json")
	writeJSON(inventory, cellInventory(plan, path, gru))
	var stdout bytes.Buffer
	if err := cellEngine().Run([]string{"cell-plan", "--plan", path, "--inventory", inventory, "--profile", profile}, &stdout); err != nil {
		t.Fatal(err)
	}
	v, err := decodeJSON(stdout.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	result := obj(v)
	var controllers []string
	for _, v := range arr(result["controllers"]) {
		controllers = append(controllers, text(obj(v)["name"])+"@"+text(obj(v)["private_ip"]))
	}
	if result["cell"] != "sfo-1" || result["oci_region"] != "us-sanjose-1" || result["image"] != "sfo-1-arm64" || len(arr(result["members"])) != 0 ||
		strings.Join(controllers, ",") != "ts-sfo-1@10.252.0.11,ts-sfo-2@10.252.0.12,ts-sfo-3@10.252.0.13" ||
		obj(obj(result["estimate"])["items"])["compute"] != "41.1600" || greater(obj(result["estimate"])["total"], 200) {
		t.Fatalf("cell plan = %v", result)
	}
}

func TestCellPlanRejectsProfileDriftAndOverCeiling(t *testing.T) {
	for name, peers := range map[string]string{
		"wrong address": "gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.23:9443",
		"wrong name":    "gru-1-db-1=10.251.0.21:9443,gru-1-db-3=10.251.0.22:9443",
		"extra peer":    "gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443,gru-1-db-3=10.251.0.23:9443",
		"missing peer":  "gru-1-db-1=10.251.0.21:9443",
	} {
		t.Run(name, func(t *testing.T) {
			profile := filepath.Join(t.TempDir(), "profile.json")
			writeJSON(profile, Object{"env": Object{"TERRABASE_PEER_PORT": "9443", "TERRABASE_PEERS": peers}})
			if _, err := cellPlanOutput(t, checkedInPlan(), "--profile", profile); err == nil || !strings.Contains(err.Error(), "TerraBase peers differ from the plan members") {
				t.Fatalf("error = %v", err)
			}
		})
	}
	expensive := writePlan(t, func(raw Object) { obj(raw["budget"])["misc_reserve_usd"] = 150 })
	if _, err := cellPlanOutput(t, expensive); err == nil || !strings.Contains(err.Error(), "exceeds the monthly ceiling") {
		t.Fatalf("over-ceiling plan: %v", err)
	}
}
