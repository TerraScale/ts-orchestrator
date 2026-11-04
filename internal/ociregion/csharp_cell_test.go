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

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/nats-io/nkeys"
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

// cellInventory is a fresh inventory of the unrelated operations host baseline, the
// plan-bound gateways, and extra instances.
func cellInventory(plan Object, path string, instances ...Object) Object {
	ids, existing, shared := obj(plan["resource_ids"]), obj(plan["existing_operations_host"]), plan["shared_compartment_id"]
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
	second["id"] = fakeOCID("instance", "sa-saopaulo-1", "0000000000V4MRM46HP1SNGDYW")
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
