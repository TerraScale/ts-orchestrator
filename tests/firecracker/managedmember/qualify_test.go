package managedmember_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

type mmObject = map[string]any

func mmMap(v any) mmObject { return v.(map[string]any) }
func mmJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func mmSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func mmObserve(t *testing.T, args any, body string) mmObject {
	t.Helper()
	var v mmObject
	if err := json.Unmarshal(script.Python(t, "tests/firecracker/managedmember/qualify.py", args, "from pathlib import Path\nfrom unittest import mock\n"+body), &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func mmReject(t *testing.T, out mmObject, message string) {
	t.Helper()
	if out["error_type"] != "QualificationError" || !strings.Contains(fmt.Sprint(out["error"]), message) {
		t.Fatalf("want QualificationError containing %q: %v", message, out)
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
func TestManagedMemberSupervisorReadBoundaryAndReservations(t *testing.T) {
	out := mmObserve(t, nil, "result = {'setup': m.volume_setup_script('a'), 'unit': m.test_unit(), 'slice': m.system_slice_reservation()}\n")
	setup := out["setup"].(string)
	for _, want := range []string{`mkdir -m 0700 "$MOUNT/data" "$MOUNT/replication"`, `chown 65534:65534 "$MOUNT/data" "$MOUNT/replication"`, `$(/usr/sbin/blkid -s UUID`} {
		if !strings.Contains(setup, want) {
			t.Fatal(setup)
		}
	}
	host := string(script.Read(t, filepath.Join(script.Root(t), "deploy/systemd/terrascale-orchestrator-host.service")))
	for _, unit := range []string{host, out["unit"].(string)} {
		directives := map[string]string{}
		for line := range strings.SplitSeq(unit, "\n") {
			if !strings.HasPrefix(line, "#") {
				k, v, ok := strings.Cut(line, "=")
				if ok {
					directives[k] = v
				}
			}
		}
		for _, key := range []string{"User", "Group"} {
			if _, ok := directives[key]; ok {
				t.Fatalf("unexpected %s", key)
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
		if !strings.Contains(out["unit"].(string), directive) || !strings.Contains(out["slice"].(string), directive) {
			t.Fatal(out)
		}
	}
	for _, directive := range []string{"CPUWeight=10000", "IOWeight=10000", "Nice=-20", "OOMScoreAdjust=-1000", "ManagedOOMPreference=omit", "IOSchedulingPriority=0"} {
		if !strings.Contains(out["unit"].(string), directive) {
			t.Fatal(out)
		}
	}
}
func TestManagedMemberFirecrackerResourceRoutesAndIDs(t *testing.T) {
	for _, member := range []string{"a", "b"} {
		t.Run(member, func(t *testing.T) {
			out := mmObserve(t, member, `from types import SimpleNamespace
lab = SimpleNamespace(socket_dir=Path('/tmp'), images=Path('/private/images'), taps={'a':'tap_a', 'b':'tap_b'})
result = {'requests': m.VM(lab, a).resource_requests()}
`)
			rows := out["requests"].([]any)
			routes := []string{"/drives/rootfs", "/drives/managed_volume", "/network-interfaces/eth0"}
			if len(rows) != 3 {
				t.Fatal(rows)
			}
			for i, row := range rows {
				if row.([]any)[0] != routes[i] {
					t.Fatal(row)
				}
			}
			if mmMap(rows[0].([]any)[1])["drive_id"] != "rootfs" || mmMap(rows[1].([]any)[1])["drive_id"] != "managed_volume" || mmMap(rows[1].([]any)[1])["path_on_host"] != "/private/images/"+member+"-volume.ext4" {
				t.Fatal(rows)
			}
			network := mmMap(rows[2].([]any)[1])
			mac := "02:fc:77:39:00:01"
			if member == "b" {
				mac = "02:fc:77:39:00:02"
			}
			if network["iface_id"] != "eth0" || network["host_dev_name"] != "tap_"+member || network["guest_mac"] != mac {
				t.Fatal(network)
			}
		})
	}
	for _, id := range []string{"managed-volume", "managed/volume", "", "volumé"} {
		for _, kind := range []string{"drive", "network"} {
			t.Run(kind+"/"+id, func(t *testing.T) {
				body := "result = m.firecracker_drive_request(a, Path('/private/volume.ext4'), False)\n"
				if kind == "network" {
					body = "result = m.firecracker_network_request(a, 'tap_a', '02:fc:77:39:00:01')\n"
				}
				mmReject(t, mmObserve(t, id, body), "resource ID")
			})
		}
	}
	out := mmObserve(t, nil, `from types import SimpleNamespace
vm = m.VM(SimpleNamespace(socket_dir=Path('/tmp'), images=Path('/private/images'), taps={'a':'tap_a','b':'tap_b'}), 'a')
with mock.patch.object(vm, 'resource_requests', side_effect=m.QualificationError('invalid resource ID')), mock.patch.object(m.subprocess, 'Popen') as spawn:
    try:
        vm.start()
    except m.QualificationError as e:
        result = {'error': str(e), 'error_type': type(e).__name__, 'spawns': spawn.call_count}
`)
	mmReject(t, out, "resource ID")
	if out["spawns"] != float64(0) {
		t.Fatal(out)
	}
}
func TestManagedMemberCanonicalGuestTools(t *testing.T) {
	mount := t.TempDir()
	tools := []string{"usr/lib/systemd/systemd", "usr/sbin/blkid", "usr/sbin/update-ca-certificates", "usr/bin/mount", "usr/bin/findmnt", "usr/bin/mountpoint", "usr/bin/readlink", "usr/bin/systemctl", "usr/bin/ip"}
	for _, tool := range tools {
		script.Write(t, filepath.Join(mount, tool), []byte("tool"), 0600)
	}
	body := "m.check_guest_tools(Path(a))\nresult = {'ok': True}\n"
	if out := mmObserve(t, mount, body); out["ok"] != true {
		t.Fatal(out)
	}
	if err := os.Remove(filepath.Join(mount, "usr/sbin/blkid")); err != nil {
		t.Fatal(err)
	}
	script.Write(t, filepath.Join(mount, "usr/bin/blkid"), []byte("wrong location"), 0600)
	mmReject(t, mmObserve(t, mount, body), "/usr/sbin/blkid")
}
func TestManagedMemberDistinctSignedRuntimeDirectories(t *testing.T) {
	dirs := map[string]string{}
	for _, member := range []string{"a", "b"} {
		inc := "bb"
		if member == "b" {
			inc = "cc"
		}
		scope := mmObject{"cluster_id": strings.Repeat("aa", 16), "tenant_id": mmID("a"), "database_id": mmID("a"), "shard_id": 1, "member_id": mmID(member), "incarnation": strings.Repeat(inc, 16)}
		out := mmObserve(t, scope, "result = {'directory': str(m.member_directory(a, 1))}\n")
		dirs[member] = out["directory"].(string)
		if dirs[member] != mmDir(scope) {
			t.Fatal(out)
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
	script.Write(t, path, payload, 0600)
	record := mmObject{"path": path, "sha256": mmSHA(payload)}
	body := "result = m.exact_input('test', a)\nresult['path'] = str(result['path'])\n"
	if out := mmObserve(t, record, body); out["sha256"] != record["sha256"] {
		t.Fatal(out)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	mmReject(t, mmObserve(t, mmObject{"path": alias, "sha256": record["sha256"]}, body), "regular, direct file")
	script.Write(t, path, []byte("changed"), 0600)
	mmReject(t, mmObserve(t, record, body), "SHA-256 mismatch")
}
func TestManagedMemberPrivateS3CredentialBoundary(t *testing.T) {
	dir := t.TempDir()
	access := filepath.Join(dir, "access")
	secret := filepath.Join(dir, "secret")
	script.Write(t, access, []byte("fixture_access_123"), 0600)
	script.Write(t, secret, []byte("fixture_secret_456"), 0600)
	body := "result = {'credentials': m.s3_credentials(tuple(Path(p) for p in a)), 'runner': m.runner_script('a')}\n"
	out := mmObserve(t, []string{access, secret}, body)
	if !reflect.DeepEqual(out["credentials"], []any{"fixture_access_123", "fixture_secret_456"}) {
		t.Fatal(out)
	}
	runner := out["runner"].(string)
	for _, want := range []string{"TS_FC_MANAGED_S3_ACCESS_KEY_FILE=/etc/ts-managed-member/s3-access-key-id", "TS_FC_MANAGED_S3_SECRET_KEY_FILE=/etc/ts-managed-member/s3-secret-access-key"} {
		if !strings.Contains(runner, want) {
			t.Fatal(runner)
		}
	}
	if strings.Contains(runner, "fixture_access_123") {
		t.Fatal("secret embedded in runner")
	}
	script.Write(t, secret, []byte("fixture_secret_456\n"), 0600)
	mmReject(t, mmObserve(t, []string{access, secret}, body), "invalid bytes")
	script.Write(t, secret, []byte("fixture_secret_456"), 0644)
	mmReject(t, mmObserve(t, []string{access, secret}, body), "unsafe ownership, mode or size")
	if err := os.Chmod(secret, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(secret, alias); err != nil {
		t.Fatal(err)
	}
	out = mmObserve(t, []string{access, alias}, body)
	if out["error_type"] != "OSError" {
		t.Fatal(out)
	}
}
func mmDirectories() [][2]any {
	return [][2]any{{"/srv/ts-managed", 0750}, {"/srv/ts-managed/6efe9447512debbf02bcd921c78d666c", 0750}, {"/srv/ts-managed/6efe9447512debbf02bcd921c78d666c/material", 0750}, {"/srv/ts-managed/6efe9447512debbf02bcd921c78d666c/control", 0730}, {"/srv/ts-managed/6efe9447512debbf02bcd921c78d666c/volume", 0750}}
}
func TestManagedMemberMaterialStagingOrderAndFinalLayout(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			mount := t.TempDir()
			inputs := mmObject{}
			for _, pair := range mmMaterials {
				inputs[pair[0]] = mmObject{"path": filepath.Join(mount, pair[0]), "sha256": strings.Repeat("a", 64)}
			}
			directories := mmDirectories()
			records := []string{}
			for _, d := range directories {
				records = append(records, fmt.Sprintf("0:65534:%x", 0040000|d[1].(int)))
			}
			for i := range len(mmMaterials) {
				gid := "65534"
				if bad && i == 0 {
					gid = "0"
				}
				records = append(records, "0:"+gid+":8120")
			}
			out := mmObserve(t, mmObject{"mount": mount, "inputs": inputs, "records": strings.Join(records, "\n") + "\n", "bad": bad}, `events = []
lab = m.Lab.__new__(m.Lab)
def install_dir(mount, destination, mode, group='root'):
    events.append(['directory', str(destination), mode, group])
def install(mount, source, destination, mode, group='root'):
    events.append(['material', str(destination), mode, group])
def staged_sha256(mount, destination):
    events.append(['hash', str(destination)])
    return '`+strings.Repeat("a", 64)+`'
def run_cmd(label, argv, **kwargs):
    events.append(['verify', label, argv, kwargs])
    return a['records']
lab.install_dir, lab.install, lab.staged_sha256, lab.run_cmd = install_dir, install, staged_sha256, run_cmd
inputs = {k: {**v, 'path': Path(v['path'])} for k,v in a['inputs'].items()}
try:
    lab.stage_managed_material(Path(a['mount']), 'a', inputs)
    result = {'events': events}
except m.QualificationError as e:
    result = {'events': events, 'error': str(e), 'error_type': type(e).__name__}
`)
			if bad {
				mmReject(t, out, "unsafe final managed layout")
				return
			}
			events := out["events"].([]any)
			if len(events) != 2*len(directories)+2*len(mmMaterials)+1 {
				t.Fatal(events)
			}
			for i, d := range directories {
				if !reflect.DeepEqual(events[i], []any{"directory", d[0], "0755", "65534"}) {
					t.Fatal(events[i])
				}
			}
			for i, pair := range mmMaterials {
				idx := len(directories) + 2*i
				dest := directories[1][0].(string) + "/material/" + pair[1]
				if !reflect.DeepEqual(events[idx], []any{"material", dest, "0440", "65534"}) || !reflect.DeepEqual(events[idx+1], []any{"hash", dest}) {
					t.Fatal(events[idx : idx+2])
				}
			}
			for i := range len(directories) {
				d := directories[len(directories)-1-i]
				if !reflect.DeepEqual(events[len(directories)+2*len(mmMaterials)+i], []any{"directory", d[0], fmt.Sprintf("%04o", d[1]), "65534"}) {
					t.Fatal(events)
				}
			}
			verify := events[len(events)-1].([]any)
			if verify[0] != "verify" || verify[1] != "verify-a-managed-layout" || mmMap(verify[3])["sudo"] != true {
				t.Fatal(verify)
			}
			argv := verify[2].([]any)
			if !reflect.DeepEqual(argv[:4], []any{"stat", "-c", "%u:%g:%f", "--"}) {
				t.Fatal(argv)
			}
		})
	}
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
	out := script.Run(t, "", nil, "sudo", "-n", "true")
	if out.Code != 0 {
		t.Skip("passwordless sudo unavailable")
	}
}
func TestManagedMemberRootSupervisorReadSearchPermission(t *testing.T) {
	mmSudo(t, "setpriv")
	base := t.TempDir()
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	replication := filepath.Join(base, "replication")
	out := script.Run(t, "", nil, "sudo", "-n", "install", "-d", "-o", "65534", "-g", "65534", "-m", "0700", replication)
	if out.Code != 0 {
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
	if err := os.MkdirAll(mount, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logs, 0755); err != nil {
		t.Fatal(err)
	}
	inputs := mmObject{}
	for _, pair := range mmMaterials {
		payload := []byte("pinned-" + pair[0])
		path := filepath.Join(base, pair[0])
		script.Write(t, path, payload, 0600)
		inputs[pair[0]] = mmObject{"path": path, "sha256": mmSHA(payload)}
	}
	t.Cleanup(func() { mmCleanupSudo(t, mount) })
	out := mmObserve(t, mmObject{"mount": mount, "logs": logs, "inputs": inputs}, `events = []
lab = m.Lab.__new__(m.Lab)
lab.command_log = m.CommandLog(Path(a['logs']))
lab.note = lambda kind, **fields: events.append([kind, fields])
lab.stage_managed_material(Path(a['mount']), 'a', {k:{**v,'path':Path(v['path'])} for k,v in a['inputs'].items()})
result = {'events': events}
`)
	if out["error"] != nil {
		t.Fatal(out)
	}
	commands := []string{}
	for _, v := range out["events"].([]any) {
		event := v.([]any)
		if event[0] == "command" {
			commands = append(commands, mmMap(event[1])["label"].(string))
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
	if !reflect.DeepEqual(commands, want) {
		t.Fatal(commands)
	}
	protected := filepath.Join(mount, "srv/ts-managed")
	info, err := os.Stat(protected)
	if err != nil || info.Mode().Perm() != 0750 {
		t.Fatalf("protected parent: %v %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(mount, strings.TrimPrefix(mmDirectories()[1][0].(string), "/"), "material", mmMaterials[0][1])); !os.IsPermission(err) {
		t.Fatalf("want permission rejection: %v", err)
	}
	argv := []string{"-n", "stat", "-c", "%u:%g:%f", "--"}
	records := []string{}
	for _, d := range mmDirectories() {
		argv = append(argv, filepath.Join(mount, strings.TrimPrefix(d[0].(string), "/")))
		records = append(records, fmt.Sprintf("0:65534:%x", 0040000|d[1].(int)))
	}
	for _, pair := range mmMaterials {
		argv = append(argv, filepath.Join(mount, strings.TrimPrefix(mmDirectories()[1][0].(string), "/"), "material", pair[1]))
		records = append(records, "0:65534:8120")
	}
	stat := script.Run(t, "", nil, "sudo", argv...)
	if stat.Code != 0 || strings.TrimSpace(stat.Stdout) != strings.Join(records, "\n") {
		t.Fatal(stat)
	}
}

const mmLabAdapter = `lab = m.Lab.__new__(m.Lab)
lab.root = Path(a['root'])
lab.logs = lab.root / 'logs'
lab.manifest = a['manifest']
lab.source_paths, lab.source_hashes = {}, {}
lab.started_at = 'fixture-test'
lab.events = []
lab.failure = ''
lab.cleanup_errors = []
calls = []
lab.prepare_dirs = lambda: lab.root.mkdir()
`

func TestManagedMemberS3StartsBeforeGuestsAndSIGTERMCleanup(t *testing.T) {
	for _, signal := range []bool{false, true} {
		t.Run(fmt.Sprint(signal), func(t *testing.T) {
			args := mmObject{"root": filepath.Join(t.TempDir(), "run"), "manifest": mmObject{"sha256": strings.Repeat("a", 64), "source_commits": mmObject{}}, "signal": signal, "methods": []string{"recheck_inputs", "copy_images", "network", "start_rustfs", "start_vms", "exercise", "finish_guests", "collect_results", "cleanup"}}
			out := mmObserve(t, args, mmLabAdapter+`for name in a['methods']:
    setattr(lab, name, lambda name=name: calls.append(name))
lab.stage_guest = lambda member: calls.append('stage_' + member)
handlers = []
if a['signal']:
    lab.start_rustfs = lambda: handlers[-1](m.signal.SIGTERM, None)
with mock.patch.object(m.signal, 'signal', side_effect=lambda number, handler: handlers.append(handler)), mock.patch('builtins.print'):
    summary = lab.run()
result = {'summary': summary, 'calls': calls}
`)
			summary := mmMap(out["summary"])
			calls := out["calls"].([]any)
			if signal {
				if summary["outcome"] != "FAILED" || !strings.Contains(fmt.Sprint(summary["failure"]), "SIGTERM") || calls[len(calls)-1] != "cleanup" {
					t.Fatal(out)
				}
			} else {
				if summary["outcome"] != "PASS" || !reflect.DeepEqual(calls[:7], []any{"recheck_inputs", "copy_images", "network", "start_rustfs", "stage_a", "stage_b", "start_vms"}) {
					t.Fatal(out)
				}
			}
		})
	}
}
func TestManagedMemberCommandSignalAndTimeoutReaping(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			out := mmObserve(t, mmObject{"root": t.TempDir(), "timeout": timeout, "pid": 12345}, `log = m.CommandLog(Path(a['root']))
child = mock.Mock(pid=a['pid'])
observed = []
def wait(*, timeout):
    if not observed:
        observed.append(None)
        if a['timeout']:
            raise m.subprocess.TimeoutExpired(['unused'], 1)
        raise m.QualificationError('signal')
    observed.append(int(m.signal.getsignal(m.signal.SIGTERM)))
    return 0
child.wait.side_effect = wait
previous = m.signal.getsignal(m.signal.SIGTERM)
with mock.patch.object(m.subprocess, 'Popen', return_value=child), mock.patch.object(m.os, 'killpg') as killpg:
    try:
        log.run('active-child', ['unused'], timeout=1)
    except m.QualificationError as e:
        result = {'error': str(e), 'error_type': type(e).__name__, 'kills': [list(c.args) for c in killpg.call_args_list], 'waits': child.wait.call_count, 'reap_handler': observed[-1], 'ignored': int(m.signal.SIG_IGN), 'restored': m.signal.getsignal(m.signal.SIGTERM) == previous, 'sigkill': int(m.signal.SIGKILL)}
`)
			want := "signal"
			if timeout {
				want = "timed out"
			}
			mmReject(t, out, want)
			if out["waits"] != float64(2) || !reflect.DeepEqual(out["kills"], []any{[]any{float64(12345), out["sigkill"]}}) || out["restored"] != true {
				t.Fatal(out)
			}
			if !timeout && out["reap_handler"] != out["ignored"] {
				t.Fatal(out)
			}
		})
	}
}
func TestManagedMemberRejectsIncompleteManifestAndSubnetCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	script.Write(t, path, mmJSON(t, mmObject{"profile": "managed-member-serving-v1", "source_commits": mmObject{"orchestrator": strings.Repeat("a", 40), "terrabase": strings.Repeat("b", 40)}, "inputs": mmObject{}, "members": mmObject{"a": mmObject{}, "b": mmObject{}}}), 0600)
	mmReject(t, mmObserve(t, path, "result = m.load_manifest(Path(a))\n"), "missing or extra")
	out := mmObserve(t, `[{"dst":"10.77.39.0/24"}]`, `with mock.patch.object(m.subprocess, 'run', return_value=m.subprocess.CompletedProcess(['ip'], 0, stdout=a, stderr='')) as run:
    try:
        m.check_subnet_collision()
    except m.QualificationError as e:
        result = {'error': str(e), 'error_type': type(e).__name__, 'calls': run.call_count}
`)
	mmReject(t, out, "collides")
	if out["calls"] != float64(1) {
		t.Fatal(out)
	}
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
			inputs[name] = record(member+"-"+name, nil)
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
func (f *mmFixture) observe(t *testing.T, patchDirs bool) mmObject {
	t.Helper()
	script.Write(t, f.path, mmJSON(t, f.manifest), 0600)
	dirs := f.dirs
	if !patchDirs {
		dirs = map[string]string{}
	}
	return mmObserve(t, mmObject{"path": f.path, "dirs": dirs, "volume_size": len("a-volume_ext4")}, `with mock.patch.object(m, 'VOLUME_BYTES', a['volume_size']), mock.patch.dict(m.MEMBER_DIRS, {k:Path(v) for k,v in a['dirs'].items()}), mock.patch.object(m.subprocess, 'run') as run:
    try:
        m.load_manifest(Path(a['path']))
        result = {'ok': True, 'calls': run.call_count}
    except m.QualificationError as e:
        result = {'error': str(e), 'error_type': type(e).__name__, 'calls': run.call_count}
`)
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
				inputs := mmMap(member["inputs"])
				record := mmMap(inputs["signed_v2_s3_config"])
				s3 := mmObject{"version": 1, "ack_profile": "object_durable", "bucket": "tbmm-" + strings.Repeat("2", 32), "region": mmRegion, "endpoint": mmEndpoint}
				if name == "s3_endpoint" {
					s3["endpoint"] = "http://rustfs.terrabase.test:9000"
				} else {
					s3["region"] = "us-east-1"
				}
				payload := mmJSON(t, s3)
				script.Write(t, record["path"].(string), payload, 0600)
				record["sha256"] = mmSHA(payload)
				runtime["live_s3_config_sha256"] = record["sha256"]
				want = "signed S3 target"
			}
			out := f.observe(t, name != "runtime_directory")
			if name == "valid" {
				if out["ok"] != true {
					t.Fatal(out)
				}
			} else {
				mmReject(t, out, want)
			}
			if out["calls"] != float64(0) {
				t.Fatalf("validation caused subprocess effect: %v", out)
			}
		})
	}
}
func TestManagedMemberResultRequiresExactPassAndNativeEvidence(t *testing.T) {
	output := "=== RUN   TestManagedMemberFirecrackerSignedServing\nTS_MANAGED_MEMBER_PHASE=PASS node=node-a\n--- PASS: TestManagedMemberFirecrackerSignedServing (0.01s)\nPASS\n"
	marker := "[  42.1] ts-managed-member-test[100]: TS_MANAGED_MEMBER_QUALIFICATION_RESULT=PASS node=node-a\n"
	cases := []struct{ name, output, marker string }{{"valid", output, marker}, {"skip", strings.ReplaceAll(output, "--- PASS:", "--- SKIP:"), marker}, {"wrong_node", strings.ReplaceAll(output, "node=node-a", "node=node-b"), marker}, {"duplicate_pass", output + "--- PASS: TestManagedMemberFirecrackerSignedServing (0.01s)\n", marker}, {"duplicate_terminal", output, marker + marker}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := mmObserve(t, mmObject{"output": tc.output, "marker": tc.marker}, "m.Lab.parse_test_result('a', a['output'], a['marker'])\nresult = {'ok': True}\n")
			if tc.name == "valid" {
				if out["ok"] != true {
					t.Fatal(out)
				}
			} else {
				want := ""
				if tc.name == "duplicate_terminal" {
					want = "terminal"
				}
				mmReject(t, out, want)
			}
		})
	}
	evidence := mmObject{}
	for _, field := range []string{"version", "node", "member_id", "process_pid", "process_uid", "process_gid", "process_cgroup", "memory_max_bytes", "filesystem_uuid", "mount_id", "claim_sha256", "storage_recovered", "listener_ready", "metrics"} {
		evidence[field] = nil
	}
	mmReject(t, mmObserve(t, evidence, "lab = m.Lab.__new__(m.Lab)\nresult = lab.validate_evidence('a', a)\n"), "")
}

func mmCleanupSudo(t *testing.T, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "sudo", "-n", "rm", "-rf", "--", path).CombinedOutput(); err != nil {
		t.Errorf("sudo cleanup: %v %s", err, out)
	}
}
