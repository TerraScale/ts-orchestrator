package managedmember_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	fc "git.terrascale.tech/TerraScale/ts-orchestrator/internal/qualification/firecracker"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

type mmObject = map[string]any

func mmMap(v any) mmObject { return v.(map[string]any) }
func mmJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v, json.Deterministic(true))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func mmSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func mmReject(t *testing.T, err error, part string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), part) {
		t.Fatalf("want error containing %q, got %v", part, err)
	}
}

var mmMaterials = [][2]string{{"authority_tbca", "authority.tbca"}, {"trusted_public_key", "trusted-public-key"}, {"server_crt", "server.crt"}, {"server_key", "server.key"}, {"client_ca_pem", "client-ca.pem"}, {"server_ca_pem", "server-ca.pem"}, {"client_managed_manifest", "client-managed-manifest.json"}, {"client_config", "client-config.json"}, {"client_chain", "client-chain.pem"}, {"client_private_key", "client-private-key.pem"}, {"client_api_keys", "client-api-keys.json"}, {"signed_v2_s3_config", "signed-v2-s3-config.json"}}
var mmMemberNames = []string{"volume_ext4", "authority_tbca", "trusted_public_key", "server_crt", "server_key", "client_ca_pem", "server_ca_pem", "client_managed_manifest", "client_config", "client_chain", "client_private_key", "client_api_keys", "client_api_token", "client_https_ca_pem", "signed_v2_s3_config"}

const mmRegion = "sa-saopaulo-1"
const mmEndpoint = "https://rustfs.terrabase.test:9000"
const mmSecret = "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func mmID(member string) string {
	if member == "a" {
		return "018f0000-0000-7000-8000-000000000001"
	}
	return "018f0000-0000-7000-8000-000000000002"
}
func mmDir(scope mmObject) string {
	identity := fmt.Sprintf("%v/%v/%v/%v/%v/%v/1", scope["cluster_id"], scope["tenant_id"], scope["database_id"], scope["shard_id"], scope["member_id"], scope["incarnation"])
	return "/srv/ts-managed/" + mmSHA([]byte(identity))[:32]
}
func mmTarget(bucket string) string {
	b := []byte("terrabase-s3-target-v1\x00")
	for _, v := range []string{mmRegion, bucket, mmEndpoint} {
		b = binary.BigEndian.AppendUint64(b, uint64(len(v)))
		b = append(b, []byte(v)...)
	}
	return mmSHA(b)
}

type mmFixture struct {
	manifest mmObject
	dirs     map[string]string
	path     string
}

func mmManifest(t *testing.T) *mmFixture {
	t.Helper()
	dir := t.TempDir()
	record := func(name string, payload []byte) mmObject {
		if payload == nil {
			payload = []byte(name)
		}
		path := filepath.Join(dir, name)
		mode := os.FileMode(0600)
		if slices.Contains([]string{"firecracker", "go_host_test", "tb_server"}, name) {
			mode = 0700
		}
		script.Write(t, path, payload, mode)
		return mmObject{"path": path, "sha256": mmSHA(payload)}
	}
	common := mmObject{}
	for _, name := range []string{"kernel", "rootfs", "firecracker", "go_host_test", "tb_server"} {
		common[name] = record(name, nil)
	}
	authority := record("authority.tbca", nil)
	members := mmObject{}
	dirs := map[string]string{}
	bucket := "tbmm-" + strings.Repeat("2", 32)
	s3 := mmObject{"version": 1, "ack_profile": "object_durable", "bucket": bucket, "region": mmRegion, "endpoint": mmEndpoint}
	for _, member := range []string{"a", "b"} {
		peer := "b"
		inc := "bb"
		ip := "10.77.39.11"
		peerIP := "10.77.39.12"
		uuid := "76f1b43d-7d79-4f41-9a6e-cc1f4aaab102"
		fault := "FAULT-DOMAIN-1"
		if member == "b" {
			peer = "a"
			inc = "cc"
			ip, peerIP = peerIP, ip
			uuid = "76f1b43d-7d79-4f41-9a6e-cc1f4aaab103"
			fault = "FAULT-DOMAIN-2"
		}
		inputs := mmObject{}
		for _, name := range mmMemberNames {
			if name == "volume_ext4" {
				path := filepath.Join(dir, member+"-"+name)
				file, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = file.Truncate(256 << 20); err != nil {
					t.Fatal(err)
				}
				if err = file.Close(); err != nil {
					t.Fatal(err)
				}
				hash, err := fc.DirectDigest(path)
				if err != nil {
					t.Fatal(err)
				}
				inputs[name] = mmObject{"path": path, "sha256": hash}
			} else {
				inputs[name] = record(member+"-"+name, nil)
			}
		}
		inputs["authority_tbca"] = authority
		inputs["signed_v2_s3_config"] = record(member+"-signed-v2-s3-config.json", mmJSON(t, s3))
		scope := mmObject{"cluster_id": strings.Repeat("11", 16), "tenant_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "database_id": "22222222-2222-2222-2222-222222222222", "shard_id": 7, "member_id": mmID(member), "incarnation": strings.Repeat(inc, 16)}
		dirs[member] = mmDir(scope)
		runtime := mmObject{"device_path": "/dev/oracleoci/oraclevdb", "mount_path": dirs[member] + "/volume", "filesystem_uuid": uuid, "filesystem_type": "ext4", "replication_listen_address": ip + ":7000", "replication_peer_member_id": mmID(peer), "replication_peer_address": peerIP + ":7000", "live_s3_target_sha256": mmTarget(bucket), "live_s3_credential": mmObject{"secret_ocid": mmSecret, "version_number": 1}}
		for field, input := range map[string]string{"trusted_key_sha256": "trusted_public_key", "server_certificate_sha256": "server_crt", "server_private_key_sha256": "server_key", "client_ca_roots_sha256": "client_ca_pem", "client_managed_material_manifest_sha256": "client_managed_manifest", "replication_server_ca_sha256": "server_ca_pem", "live_s3_config_sha256": "signed_v2_s3_config"} {
			runtime[field] = mmMap(inputs[input])["sha256"]
		}
		config := mmObject{"version": 1, "node": "node-" + member, "failure_domain": fault, "member": mmObject{"scope": scope, "host_attempt": 1}, "authority": mmObject{"epoch": 1, "configuration_id": strings.Repeat("a", 64), "certificate_sha256": authority["sha256"], "tls_leaf_sha256": strings.Repeat("a", 64)}, "runtime": runtime, "volume_id": "ocid1.volume.fixture-" + member, "attachment_id": "ocid1.volumeattachment.fixture-" + member, "attachment_etag": "fixture-attachment-" + member, "source_digest": strings.Repeat("a", 64), "system_reserve_bytes": 1 << 30, "collection_id": "21212121-2121-2121-2121-212121212121", "schema_generation": 1, "schema_digest": strings.Repeat("a", 64), "document_id": "018f0000-0000-7000-8000-000000000021"}
		members[member] = mmObject{"inputs": inputs, "guest_config": config}
	}
	return &mmFixture{manifest: mmObject{"profile": "managed-member-serving-v1", "source_commits": mmObject{"orchestrator": strings.Repeat("a", 40), "terrabase": strings.Repeat("b", 40)}, "inputs": common, "members": members}, dirs: dirs, path: filepath.Join(dir, "manifest.json")}
}
func TestManagedMemberSupervisorReadBoundaryAndReservations(t *testing.T) {
	setup := fc.ManagedVolumeSetupScript("a")
	for _, want := range []string{`mkdir -m 0700 "$MOUNT/data" "$MOUNT/replication"`, `chown 65534:65534 "$MOUNT/data" "$MOUNT/replication"`, `$(/usr/sbin/blkid -s UUID`} {
		if !strings.Contains(setup, want) {
			t.Fatal(setup)
		}
	}
	host := string(script.Read(t, filepath.Join(script.Root(t), "deploy/systemd/terrascale-orchestrator-host.service")))
	for _, unit := range []string{host, fc.ManagedTestUnit} {
		directives := map[string]string{}
		for line := range strings.SplitSeq(unit, "\n") {
			if !strings.HasPrefix(line, "#") {
				if k, v, ok := strings.Cut(line, "="); ok {
					directives[k] = v
				}
			}
		}
		for _, key := range []string{"User", "Group"} {
			if _, ok := directives[key]; ok {
				t.Fatal(key)
			}
		}
		if directives["NoNewPrivileges"] != "yes" || directives["AmbientCapabilities"] != "" {
			t.Fatal(directives)
		}
		bounds := strings.Fields(directives["CapabilityBoundingSet"])
		slices.Sort(bounds)
		required := []string{"CAP_CHOWN", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_DAC_READ_SEARCH"}
		slices.Sort(required)
		if !reflect.DeepEqual(bounds, required) {
			t.Fatal(bounds)
		}
	}
	for _, directive := range []string{"MemoryMin=1G", "MemoryLow=1G"} {
		if !strings.Contains(fc.ManagedTestUnit, directive) || !strings.Contains(fc.ManagedSystemSliceReservation, directive) {
			t.Fatal(directive)
		}
	}
	for _, directive := range []string{"CPUWeight=10000", "IOWeight=10000", "Nice=-20", "OOMScoreAdjust=-1000", "ManagedOOMPreference=omit", "IOSchedulingPriority=0"} {
		if !strings.Contains(fc.ManagedTestUnit, directive) {
			t.Fatal(directive)
		}
	}
}
func TestManagedMemberFirecrackerResourceRoutesAndIDs(t *testing.T) {
	for _, member := range []string{"a", "b"} {
		lab := &fc.ManagedLab{Images: "/private/images", Taps: map[string]string{"a": "tap_a", "b": "tap_b"}}
		vm := fc.ManagedVM{Lab: lab, Member: member, Socket: "/tmp/" + member + ".sock"}
		rows, e := vm.ResourceRequests()
		if e != nil {
			t.Fatal(e)
		}
		routes := []string{"/drives/rootfs", "/drives/managed_volume", "/network-interfaces/eth0"}
		if len(rows) != 3 {
			t.Fatal(rows)
		}
		for i, row := range rows {
			if row.Route != routes[i] {
				t.Fatal(row)
			}
		}
		if rows[0].Body["drive_id"] != "rootfs" || rows[1].Body["drive_id"] != "managed_volume" || rows[1].Body["path_on_host"] != "/private/images/"+member+"-volume.ext4" {
			t.Fatal(rows)
		}
		network := rows[2].Body
		if network["iface_id"] != "eth0" || network["host_dev_name"] != "tap_"+member || network["guest_mac"] != fc.ManagedGuestMACs[member] {
			t.Fatal(network)
		}
	}
	for _, id := range []string{"managed-volume", "managed/volume", "", "volumé"} {
		_, _, e := fc.FirecrackerDriveRequest(id, "/private/volume.ext4", false)
		mmReject(t, e, "resource ID")
		_, _, e = fc.FirecrackerNetworkRequest(id, "tap_a", "02:fc:77:39:00:01")
		mmReject(t, e, "resource ID")
	}
}
func TestManagedMemberRejectsInvalidResourcesBeforeProcessStart(t *testing.T) {
	vm := &fc.ManagedVM{Lab: &fc.ManagedLab{}, Member: "a", Socket: "/tmp/unused.sock", Resources: func() ([]fc.FirecrackerRequest, error) { return nil, fmt.Errorf("invalid resource ID") }}
	err := vm.Start()
	mmReject(t, err, "resource ID")
	if vm.Process != nil {
		t.Fatal("spawned process before resource validation")
	}
}
func TestManagedMemberCanonicalGuestTools(t *testing.T) {
	mount := t.TempDir()
	tools := []string{"usr/lib/systemd/systemd", "usr/sbin/blkid", "usr/sbin/update-ca-certificates", "usr/bin/mount", "usr/bin/findmnt", "usr/bin/mountpoint", "usr/bin/readlink", "usr/bin/systemctl", "usr/bin/ip"}
	for _, tool := range tools {
		script.Write(t, filepath.Join(mount, tool), []byte("tool"), 0o600)
	}
	if e := fc.CheckManagedGuestTools(mount); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(filepath.Join(mount, "usr/sbin/blkid")); e != nil {
		t.Fatal(e)
	}
	script.Write(t, filepath.Join(mount, "usr/bin/blkid"), []byte("wrong location"), 0o600)
	mmReject(t, fc.CheckManagedGuestTools(mount), "/usr/sbin/blkid")
}
func TestManagedMemberDistinctSignedRuntimeDirectories(t *testing.T) {
	dirs := map[string]string{}
	for _, member := range []string{"a", "b"} {
		inc := "bb"
		if member == "b" {
			inc = "cc"
		}
		scope := mmObject{"cluster_id": strings.Repeat("aa", 16), "tenant_id": mmID("a"), "database_id": mmID("a"), "shard_id": 1, "member_id": mmID(member), "incarnation": strings.Repeat(inc, 16)}
		dirs[member] = fc.ManagedMemberDirectory(scope, 1)
		if dirs[member] != mmDir(scope) {
			t.Fatal(dirs)
		}
	}
	if dirs["a"] == dirs["b"] {
		t.Fatal(dirs)
	}
}
func TestManagedMemberExactInputDirectFileAndHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input")
	payload := []byte("pinned bytes")
	script.Write(t, path, payload, 0o600)
	record := mmObject{"path": path, "sha256": mmSHA(payload)}
	input, e := fc.ExactManagedInput("test", record)
	if e != nil || input.SHA256 != record["sha256"] {
		t.Fatal(input, e)
	}
	alias := filepath.Join(dir, "alias")
	if e = os.Symlink(path, alias); e != nil {
		t.Fatal(e)
	}
	_, e = fc.ExactManagedInput("test", mmObject{"path": alias, "sha256": record["sha256"]})
	mmReject(t, e, "regular, direct file")
	script.Write(t, path, []byte("changed"), 0o600)
	_, e = fc.ExactManagedInput("test", record)
	mmReject(t, e, "SHA-256 mismatch")
}
func TestManagedMemberPrivateS3CredentialBoundary(t *testing.T) {
	dir := t.TempDir()
	access, secret := filepath.Join(dir, "access"), filepath.Join(dir, "secret")
	script.Write(t, access, []byte("fixture_access_123"), 0o600)
	script.Write(t, secret, []byte("fixture_secret_456"), 0o600)
	credentials, e := fc.S3Credentials([2]string{access, secret})
	if e != nil || credentials != [2]string{"fixture_access_123", "fixture_secret_456"} {
		t.Fatal(credentials, e)
	}
	runner := fc.ManagedRunnerScript("a")
	for _, want := range []string{"TS_FC_MANAGED_S3_ACCESS_KEY_FILE=/etc/ts-managed-member/s3-access-key-id", "TS_FC_MANAGED_S3_SECRET_KEY_FILE=/etc/ts-managed-member/s3-secret-access-key"} {
		if !strings.Contains(runner, want) {
			t.Fatal(runner)
		}
	}
	if strings.Contains(runner, "fixture_access_123") {
		t.Fatal("secret embedded in runner")
	}
	script.Write(t, secret, []byte("fixture_secret_456\n"), 0o600)
	_, e = fc.S3Credentials([2]string{access, secret})
	mmReject(t, e, "invalid bytes")
	script.Write(t, secret, []byte("fixture_secret_456"), 0o644)
	_, e = fc.S3Credentials([2]string{access, secret})
	mmReject(t, e, "unsafe ownership, mode or size")
	if e = os.Chmod(secret, 0o600); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(dir, "alias")
	if e = os.Symlink(secret, alias); e != nil {
		t.Fatal(e)
	}
	_, e = fc.S3Credentials([2]string{access, alias})
	if e == nil {
		t.Fatal("accepted symlink")
	}
}
func TestManagedMemberMaterialStagingOrderAndFinalLayout(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			mount := t.TempDir()
			inputs := map[string]fc.ManagedInput{}
			for _, pair := range mmMaterials {
				inputs[pair[0]] = fc.ManagedInput{Path: filepath.Join(mount, pair[0]), SHA256: strings.Repeat("a", 64)}
			}
			directories := fc.ManagedDirectories("a")
			records := []string{}
			for _, d := range directories {
				records = append(records, fmt.Sprintf("0:65534:%x", 0o40000|d[1].(int)))
			}
			for i := range len(mmMaterials) {
				gid := "65534"
				if bad && i == 0 {
					gid = "0"
				}
				records = append(records, "0:"+gid+":8120")
			}
			events := [][]string{}
			lab := &fc.ManagedLab{Ctx: t.Context(), Commands: t.TempDir()}
			lab.Command = func(_ context.Context, argv []string, _ fc.CommandOptions) (fc.CommandResult, error) {
				args := argv[2:]
				events = append(events, slices.Clone(args))
				if args[0] == "sha256sum" {
					return fc.CommandResult{Stdout: strings.Repeat("a", 64) + "  " + args[1] + "\n"}, nil
				}
				if args[0] == "stat" {
					return fc.CommandResult{Stdout: strings.Join(records, "\n") + "\n"}, nil
				}
				return fc.CommandResult{}, nil
			}
			e := lab.StageManagedMaterial(mount, "a", inputs)
			if bad {
				mmReject(t, e, "unsafe final managed layout")
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if len(events) != 2*len(directories)+2*len(mmMaterials)+1 {
				t.Fatal(events)
			}
			for i, d := range directories {
				want := []string{"install", "-d", "-o", "root", "-g", "65534", "-m", "0755", filepath.Join(mount, strings.TrimPrefix(d[0].(string), "/"))}
				if !slices.Equal(events[i], want) {
					t.Fatal(events[i])
				}
			}
			for i, pair := range mmMaterials {
				idx := len(directories) + 2*i
				dest := filepath.Join(mount, strings.TrimPrefix(directories[1][0].(string), "/"), "material", pair[1])
				want := []string{"install", "-D", "-o", "root", "-g", "65534", "-m", "0440", inputs[pair[0]].Path, dest}
				if !slices.Equal(events[idx], want) || !slices.Equal(events[idx+1], []string{"sha256sum", dest}) {
					t.Fatal(events[idx : idx+2])
				}
			}
			for i := range len(directories) {
				d := directories[len(directories)-1-i]
				event := events[len(directories)+2*len(mmMaterials)+i]
				if event[7] != fmt.Sprintf("%04o", d[1]) || event[8] != filepath.Join(mount, strings.TrimPrefix(d[0].(string), "/")) {
					t.Fatal(event)
				}
			}
			verify := events[len(events)-1]
			if !slices.Equal(verify[:4], []string{"stat", "-c", "%u:%g:%f", "--"}) {
				t.Fatal(verify)
			}
		})
	}
}
func TestManagedMemberRejectsIncompleteManifestAndSubnetCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	script.Write(t, path, mmJSON(t, mmObject{"profile": fc.ManagedMemberProfile, "source_commits": mmObject{"orchestrator": strings.Repeat("a", 40), "terrabase": strings.Repeat("b", 40)}, "inputs": mmObject{}, "members": mmObject{"a": mmObject{}, "b": mmObject{}}}), 0o600)
	_, e := fc.LoadManagedManifest(path)
	mmReject(t, e, "missing or extra")
	calls := 0
	e = fc.CheckManagedSubnetCollision(t.Context(), func(context.Context, []string, fc.CommandOptions) (fc.CommandResult, error) {
		calls++
		return fc.CommandResult{Stdout: `[{"dst":"10.77.39.0/24"}]`}, nil
	})
	mmReject(t, e, "collides")
	if calls != 1 {
		t.Fatal(calls)
	}
}
func (f *mmFixture) load(t *testing.T, patchDirs bool) (fc.ManagedManifest, error) {
	t.Helper()
	script.Write(t, f.path, mmJSON(t, f.manifest), 0o600)
	original := map[string]string{}
	if patchDirs {
		for member, dir := range f.dirs {
			original[member] = fc.ManagedMemberDirs[member]
			fc.ManagedMemberDirs[member] = dir
		}
		defer func() {
			for member, dir := range original {
				fc.ManagedMemberDirs[member] = dir
			}
		}()
	}
	return fc.LoadManagedManifest(f.path)
}
func TestManagedMemberManifestSecurityMatrix(t *testing.T) {
	names := []string{"valid", "wrong_peer", "s3_config_hash", "s3_target_hash", "credential_version_2", "credential_version_bool", "credential_version_float", "credential_ocid", "s3_endpoint", "s3_region", "shard_zero", "shard_bool", "shard_negative", "shard_overflow", "uppercase_tenant", "runtime_directory"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			f := mmManifest(t)
			member := mmMap(mmMap(f.manifest["members"])["a"])
			config := mmMap(member["guest_config"])
			runtime := mmMap(config["runtime"])
			credential := mmMap(runtime["live_s3_credential"])
			scope := mmMap(mmMap(config["member"])["scope"])
			want := "runtime pins"
			switch name {
			case "wrong_peer":
				b := mmMap(mmMap(mmMap(f.manifest["members"])["b"])["guest_config"])
				mmMap(b["runtime"])["replication_peer_member_id"] = mmID("b")
			case "s3_config_hash":
				runtime["live_s3_config_sha256"] = strings.Repeat("0", 64)
			case "s3_target_hash":
				runtime["live_s3_target_sha256"] = strings.Repeat("0", 64)
			case "credential_version_2":
				credential["version_number"] = 2
				want = "S3 credential reference"
			case "credential_version_bool":
				credential["version_number"] = true
				want = "S3 credential reference"
			case "credential_version_float":
				credential["version_number"] = jsontext.Value(`1.0`)
				want = "S3 credential reference"
			case "credential_ocid":
				credential["secret_ocid"] = mmSecret + "-other"
				want = "S3 credential reference"
			case "shard_zero":
				scope["shard_id"] = 0
				want = "scope"
			case "shard_bool":
				scope["shard_id"] = true
				want = "scope"
			case "shard_negative":
				scope["shard_id"] = -1
				want = "scope"
			case "shard_overflow":
				scope["shard_id"] = jsontext.Value(`18446744073709551616`)
				want = "scope"
			case "uppercase_tenant":
				scope["tenant_id"] = strings.ToUpper(scope["tenant_id"].(string))
				want = "scope"
			case "runtime_directory":
				want = "runtime directory"
			case "s3_endpoint", "s3_region":
				record := mmMap(mmMap(member["inputs"])["signed_v2_s3_config"])
				s3 := mmObject{"version": 1, "ack_profile": "object_durable", "bucket": "tbmm-" + strings.Repeat("2", 32), "region": mmRegion, "endpoint": mmEndpoint}
				if name == "s3_endpoint" {
					s3["endpoint"] = "http://rustfs.terrabase.test:9000"
				} else {
					s3["region"] = "us-east-1"
				}
				payload := mmJSON(t, s3)
				script.Write(t, record["path"].(string), payload, 0o600)
				record["sha256"] = mmSHA(payload)
				runtime["live_s3_config_sha256"] = record["sha256"]
				want = "signed S3 target"
			}
			_, e := f.load(t, name != "runtime_directory")
			if name == "valid" {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				mmReject(t, e, want)
			}
		})
	}
}
func TestManagedMemberResultRequiresExactPassAndNativeEvidence(t *testing.T) {
	output := "=== RUN   TestManagedMemberFirecrackerSignedServing\nTS_MANAGED_MEMBER_PHASE=PASS node=node-a\n--- PASS: TestManagedMemberFirecrackerSignedServing (0.01s)\nPASS\n"
	marker := "[  42.1] ts-managed-member-test[100]: TS_MANAGED_MEMBER_QUALIFICATION_RESULT=PASS node=node-a\n"
	for _, tc := range []struct{ name, output, marker string }{{"valid", output, marker}, {"skip", strings.ReplaceAll(output, "--- PASS:", "--- SKIP:"), marker}, {"wrong_node", strings.ReplaceAll(output, "node=node-a", "node=node-b"), marker}, {"duplicate_pass", output + "--- PASS: TestManagedMemberFirecrackerSignedServing (0.01s)\n", marker}, {"duplicate_terminal", output, marker + marker}} {
		e := fc.ParseManagedTestResult("a", tc.output, tc.marker)
		if tc.name == "valid" {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			mmReject(t, e, "")
		}
	}
	evidence := mmObject{}
	for _, field := range []string{"version", "node", "member_id", "process_pid", "process_uid", "process_gid", "process_cgroup", "memory_max_bytes", "filesystem_uuid", "mount_id", "claim_sha256", "storage_recovered", "listener_ready", "metrics"} {
		evidence[field] = nil
	}
	mmReject(t, fc.ValidateManagedEvidence("a", evidence), "incomplete or inconsistent")
}
func mmSudo(t *testing.T, commands ...string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("requires a nonroot host user and passwordless sudo")
	}
	for _, name := range append([]string{"sudo"}, commands...) {
		if _, e := exec.LookPath(name); e != nil {
			t.Skip("requires " + name)
		}
	}
	if out := script.Run(t, "", nil, "sudo", "-n", "true"); out.Code != 0 {
		t.Skip("passwordless sudo unavailable")
	}
}
func mmCleanupSudo(t *testing.T, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
	defer cancel()
	if out, e := exec.CommandContext(ctx, "sudo", "-n", "rm", "-rf", "--", path).CombinedOutput(); e != nil {
		t.Errorf("sudo cleanup: %v %s", e, out)
	}
}
func TestManagedMemberRootSupervisorReadSearchPermission(t *testing.T) {
	mmSudo(t, "setpriv")
	base := t.TempDir()
	if e := os.Chmod(base, 0o755); e != nil {
		t.Fatal(e)
	}
	replication := filepath.Join(base, "replication")
	if out := script.Run(t, "", nil, "sudo", "-n", "install", "-d", "-o", "65534", "-g", "65534", "-m", "0700", replication); out.Code != 0 {
		t.Fatal(out)
	}
	t.Cleanup(func() { mmCleanupSudo(t, replication) })
	for _, tc := range [][2]string{{"-dac_override,-dac_read_search", "Permission denied"}, {"-dac_override", "No such file or directory"}} {
		out := script.Run(t, "", map[string]string{"LC_ALL": "C"}, "sudo", "-n", "setpriv", "--nnp", "--bounding-set="+tc[0], "stat", "--", filepath.Join(replication, "shard"))
		if out.Code != 1 || !strings.Contains(out.Stderr, tc[1]) {
			t.Fatal(out)
		}
	}
}
func TestManagedMemberRealProtectedMaterialStaging(t *testing.T) {
	mmSudo(t)
	base := t.TempDir()
	mount := filepath.Join(base, "guest-root")
	logs := filepath.Join(base, "logs")
	for _, dir := range []string{mount, logs} {
		if e := os.Mkdir(dir, 0o755); e != nil {
			t.Fatal(e)
		}
	}
	inputs := map[string]fc.ManagedInput{}
	for _, pair := range mmMaterials {
		payload := []byte("pinned-" + pair[0])
		path := filepath.Join(base, pair[0])
		script.Write(t, path, payload, 0o600)
		inputs[pair[0]] = fc.ManagedInput{Path: path, SHA256: mmSHA(payload), Size: int64(len(payload))}
	}
	t.Cleanup(func() { mmCleanupSudo(t, mount) })
	lab := &fc.ManagedLab{Ctx: t.Context(), Commands: logs}
	if e := lab.StageManagedMaterial(mount, "a", inputs); e != nil {
		t.Fatal(e)
	}
	commands := []string{}
	for _, event := range lab.Events {
		if event["kind"] == "command" {
			commands = append(commands, event["label"].(string))
		}
	}
	names := []string{"install-dir-ts-managed", "install-dir-6efe9447512debbf02bcd921c78d666c", "install-dir-material", "install-dir-control", "install-dir-volume"}
	want := slices.Clone(names)
	for _, pair := range mmMaterials {
		want = append(want, "install-"+pair[1], "hash-"+pair[1])
	}
	slices.Reverse(names)
	want = append(want, names...)
	want = append(want, "verify-a-managed-layout")
	if !slices.Equal(commands, want) {
		t.Fatal(commands)
	}
	protected := filepath.Join(mount, "srv/ts-managed")
	info, e := os.Stat(protected)
	if e != nil || info.Mode().Perm() != 0o750 {
		t.Fatal(info, e)
	}
	if _, e = os.Stat(filepath.Join(mount, strings.TrimPrefix(fc.ManagedMemberDirs["a"], "/"), "material", mmMaterials[0][1])); !os.IsPermission(e) {
		t.Fatal("want permission rejection", e)
	}
	argv := []string{"-n", "stat", "-c", "%u:%g:%f", "--"}
	records := []string{}
	for _, d := range fc.ManagedDirectories("a") {
		argv = append(argv, filepath.Join(mount, strings.TrimPrefix(d[0].(string), "/")))
		records = append(records, fmt.Sprintf("0:65534:%x", 0o40000|d[1].(int)))
	}
	for _, pair := range mmMaterials {
		argv = append(argv, filepath.Join(mount, strings.TrimPrefix(fc.ManagedMemberDirs["a"], "/"), "material", pair[1]))
		records = append(records, "0:65534:8120")
	}
	stat := script.Run(t, "", nil, "sudo", argv...)
	if stat.Code != 0 || strings.TrimSpace(stat.Stdout) != strings.Join(records, "\n") {
		t.Fatal(stat)
	}
}
func TestManagedMemberS3StartsBeforeGuestsAndSIGTERMCleanup(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			root := filepath.Join(t.TempDir(), "run")
			lab := &fc.ManagedLab{Ctx: ctx, Root: root, Logs: filepath.Join(root, "logs"), Commands: filepath.Join(root, "commands"), Images: filepath.Join(root, "images"), Mounts: filepath.Join(root, "mounts"), Stage: filepath.Join(root, "stage"), Fixture: filepath.Join(root, "rustfs"), Manifest: fc.ManagedManifest{Raw: []byte("{}"), SHA256: strings.Repeat("a", 64), Commits: mmObject{}}, VMs: map[string]*fc.ManagedVM{}, Mounted: map[string]bool{}, SourcePaths: map[string]string{}, SourceHashes: map[string]string{}}
			calls := []string{}
			lab.Step = func(label string, _ func() error) error {
				calls = append(calls, label)
				if cancelled && label == "start_rustfs" {
					cancel()
					return ctx.Err()
				}
				return nil
			}
			summary, e := lab.Run()
			if cancelled {
				if e == nil || summary["outcome"] != "FAILED" || !strings.Contains(summary["failure"].(string), "context canceled") {
					t.Fatal(summary, e)
				}
				if _, e = os.Stat(lab.Fixture); !os.IsNotExist(e) {
					t.Fatal("cleanup did not run", e)
				}
			} else {
				if e != nil || summary["outcome"] != "PASS" {
					t.Fatal(summary, e)
				}
				if !slices.Equal(calls[:7], []string{"recheck_inputs", "copy_images", "network", "start_rustfs", "stage_a", "stage_b", "start_vms"}) {
					t.Fatal(calls)
				}
			}
		})
	}
}
func TestManagedMemberCommandSignalAndTimeoutReaping(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			duration := 100 * time.Millisecond
			if cancelled {
				duration = time.Minute
				go func() { time.Sleep(100 * time.Millisecond); cancel() }()
			}
			r, e := fc.BoundedCommand(ctx, []string{"/bin/sh", "-c", `trap '' TERM; sleep 300 & wait`}, fc.CommandOptions{Timeout: duration, AllowFailure: true}, filepath.Join(dir, "child.log"), 32<<20)
			if e == nil {
				t.Fatal(r)
			}
			if cancelled {
				if !strings.Contains(e.Error(), "context canceled") {
					t.Fatal(e)
				}
			} else {
				if !strings.Contains(e.Error(), "deadline exceeded") {
					t.Fatal(e)
				}
			}
		})
	}
}
func TestManagedMemberSignedS3ConfigCanonicalEncoding(t *testing.T) {
	base := `{"version":1,"ack_profile":"object_durable","bucket":"tbmm-22222222222222222222222222222222","region":"sa-saopaulo-1","endpoint":"https://rustfs.terrabase.test:9000"}`
	for _, tc := range []struct{ name, raw, err string }{{"valid", base, ""}, {"whitespace", base + "\n", "canonical exporter"}, {"escaped_key", strings.Replace(base, `"bucket"`, `"\u0062ucket"`, 1), "canonical exporter"}, {"noninteger_version", strings.Replace(base, `"version":1`, `"version":1.0`, 1), "signed S3 target"}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "s3.json")
			script.Write(t, path, []byte(tc.raw), 0o600)
			_, e := fc.SignedS3Config("a", fc.ManagedInput{Path: path, SHA256: mmSHA([]byte(tc.raw)), Size: int64(len(tc.raw))})
			if tc.err == "" {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				mmReject(t, e, tc.err)
			}
		})
	}
}
