package production

import (
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

func productionObserve(t *testing.T, args any, body string) map[string]any {
	t.Helper()
	wire := script.Python(t, filepath.Join(script.Root(t), "tests/firecracker/production/qualify.py"), args, body)
	var result map[string]any
	if err := json.Unmarshal(wire, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func productionEqual(t *testing.T, got, want any) {
	t.Helper()
	a, err := json.Marshal(got, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(want, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("got %s want %s", a, b)
	}
}
func productionContains(t *testing.T, value any, part string) {
	t.Helper()
	if !strings.Contains(fmt.Sprint(value), part) {
		t.Fatalf("missing %q in %v", part, value)
	}
}

func TestProductionNetworkNamespace(t *testing.T) {
	const observation = `from unittest.mock import patch
from types import SimpleNamespace
class Reexec(Exception): pass
with patch.object(m.os.path,"samefile",return_value=a["same"]), patch.object(m.os,"geteuid",return_value=0), patch.object(m,"check_network_collision") as collision, patch.object(m,"command",return_value=SimpleNamespace(stdout="yes\n")) as clock, patch.object(m.shutil,"which",return_value="/bin/unshare"), patch.object(m.os,"execv",side_effect=Reexec) as execv:
    error=None
    try: m.ensure_run_network_namespace(a["run"])
    except Reexec: error="Reexec"
result={"error":error,"collisions":collision.call_count,"clock":[list(call.args) for call in clock.call_args_list],"exec":[list(call.args[1]) for call in execv.call_args_list],"executable":m.sys.executable,"module":str(m.Path(m.__file__).resolve())}`
	for _, tc := range []struct {
		name      string
		run, same bool
	}{{"enters_after_host_checks", true, true}, {"prepare_only", false, true}, {"already_isolated", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			got := productionObserve(t, map[string]any{"run": tc.run, "same": tc.same}, observation)
			if tc.run && tc.same {
				productionEqual(t, got["error"], "Reexec")
				productionEqual(t, got["collisions"], 1)
				productionEqual(t, got["clock"], [][]string{{"timedatectl", "show", "-p", "NTPSynchronized", "--value"}})
				execs := got["exec"].([]any)
				argv := execs[0].([]any)
				productionEqual(t, argv[:5], []any{"/bin/unshare", "--net", "--", got["executable"], got["module"]})
			} else {
				productionEqual(t, got["exec"], []any{})
			}
		})
	}
}
func TestProductionNetworkRaisesLoopbackFirst(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(fmt.Sprint(same), func(t *testing.T) {
			got := productionObserve(t, map[string]any{"same": same}, `from unittest.mock import patch
from types import SimpleNamespace
run=m.Qualification(SimpleNamespace(run=True))
try:
    with patch.object(m.os.path,"samefile",return_value=a["same"]),patch.object(m,"command") as command,patch.object(run,"firewall"):
        error=None
        try: run.network()
        except RuntimeError as exc: error=str(exc)
    result={"error":error,"calls":[list(call.args) for call in command.call_args_list]}
finally: m.shutil.rmtree(run.root)`)
			if same {
				productionContains(t, got["error"], "private namespace")
				productionEqual(t, got["calls"], []any{})
			} else {
				calls := got["calls"].([]any)
				if len(calls) == 0 {
					t.Fatal("no network commands")
				}
				productionEqual(t, calls[0], []string{"ip", "link", "set", "lo", "up"})
			}
		})
	}
}
func TestProductionNTPResponse(t *testing.T) {
	got := productionObserve(t, nil, `request=bytearray(48)
request[0]=0x23
request[40:48]=b"client01"
answer=m.ntp_response(bytes(request),1700000000.25)
result={"length":len(answer),"mode":answer[0]&7,"stratum":answer[1],"origin":answer[24:32].decode()}`)
	productionEqual(t, got, map[string]any{"length": 48, "mode": 4, "stratum": 2, "origin": "client01"})
	got = productionObserve(t, nil, `result=m.ntp_response(b"short",1700000000)`)
	productionEqual(t, got["error_type"], "ValueError")
}
func TestProductionAudit(t *testing.T) {
	metadata := []string{"/opc/v2/instance/id", "/opc/v2/instance/canonicalRegionName", "/opc/v2/instance/region", "/opc/v2/instance/availabilityDomain", "/opc/v2/instance/compartmentId", "/opc/v2/identity/cert.pem"}
	// Fetch constants as observations, then build and mutate the full audit in Go.
	constants := productionObserve(t, nil, `result={"paths":sorted(m.IMDS_PATHS),"slots":list(m.SLOTS)}`)
	paths := constants["paths"].([]any)
	metadata = nil
	for _, p := range paths {
		metadata = append(metadata, p.(string))
	}
	slots := constants["slots"].([]any)
	for _, tc := range []string{"valid", "write", "bad_status", "duplicate_metadata_compute"} {
		t.Run(tc, func(t *testing.T) {
			var requests []any
			for _, path := range metadata {
				if tc == "duplicate_metadata_compute" {
					path = "/opc/v2/instance/id"
				}
				requests = append(requests, map[string]any{"method": "GET", "host": "169.254.169.254", "requestUri": path, "status": 200, "listed": true})
			}
			requests = append(requests, map[string]any{"method": "POST", "host": "auth.sa-saopaulo-1.oraclecloud.com", "status": 200, "listed": true})
			for i := range 3 {
				path := fmt.Sprintf("/compute/%d", i)
				if tc == "duplicate_metadata_compute" {
					path = "/compute/1"
				}
				requests = append(requests, map[string]any{"method": "GET", "host": "iaas.sa-saopaulo-1.oraclecloud.com", "requestUri": path, "status": 200, "listed": true})
			}
			requests = append(requests, map[string]any{"method": "GET", "host": "objectstorage.sa-saopaulo-1.oraclecloud.com", "status": 200, "listed": true})
			scoped := map[string]any{}
			for _, slot := range slots {
				scoped[slot.(string)] = map[string]any{"requests": requests, "overflow": 0}
			}
			if tc == "write" {
				scoped["seed-a"] = map[string]any{"requests": append(append([]any{}, requests...), map[string]any{"method": "PUT", "host": "objectstorage.sa-saopaulo-1.oraclecloud.com", "status": 405, "listed": false}), "overflow": 0}
			}
			if tc == "bad_status" {
				requests[0].(map[string]any)["status"] = 404
			}
			got := productionObserve(t, map[string]any{"unknownSources": 0, "slots": scoped}, `result=m.check_audit(a)`)
			if tc == "valid" {
				want := map[string]any{}
				for _, slot := range slots {
					want[slot.(string)] = 11
				}
				productionEqual(t, got, want)
			} else {
				productionEqual(t, got["error_type"], "RuntimeError")
			}
		})
	}
}
func TestProductionPinnedFileDetectsChange(t *testing.T) {
	file := filepath.Join(t.TempDir(), "input")
	script.Write(t, file, []byte("pinned"), 0o644)
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte("pinned")))
	args := map[string]any{"path": file, "digest": sum}
	const call = `result={"path":str(m.require_pinned_file(m.Path(a["path"]),a["digest"]))}`
	productionEqual(t, productionObserve(t, args, call), map[string]any{"path": file})
	script.Write(t, file, []byte("changed"), 0o644)
	productionEqual(t, productionObserve(t, args, call)["error_type"], "ValueError")
}
func TestProductionFirewallBoundaries(t *testing.T) {
	got := productionObserve(t, nil, `from unittest.mock import patch
from types import SimpleNamespace
calls=[]
def capture(*args,**kwargs):
    calls.append({"args":list(args),"input":kwargs.get("input_text")})
    return SimpleNamespace(returncode=1 if args[:3]==("nft","list","table") else 0,stdout="",stderr="")
run=m.Qualification(SimpleNamespace(run=False))
try:
    with patch.object(m,"command",side_effect=capture): run.firewall()
    result={"calls":calls}
finally: m.shutil.rmtree(run.root)`)
	var programs []string
	for _, v := range got["calls"].([]any) {
		call := v.(map[string]any)
		argv := call["args"].([]any)
		if call["input"] != nil {
			productionEqual(t, argv[:3], []string{"nft", "-f", "-"})
			programs = append(programs, call["input"].(string))
		}
	}
	if len(programs) != 2 {
		t.Fatalf("firewall programs %d", len(programs))
	}
	for _, part := range []string{"tcp dport { 4222, 6222 } accept", "ether type arp accept", "169.254.169.254 tcp dport 80 counter accept", "10.44.0.1 udp dport 123 counter accept", "counter drop"} {
		productionContains(t, programs[1], part)
	}
	productionContains(t, programs[0], "counter drop")
	if strings.Contains(programs[0], "policy drop") {
		t.Fatal("host traffic policy affected")
	}
}
func TestProductionVMStopExitSignalRace(t *testing.T) {
	root := t.TempDir()
	got := productionObserve(t, map[string]any{"root": root}, `from unittest.mock import patch
root=m.Path(a["root"])
vm=m.VM("controller-a","tap0",root/"root.ext4",root/"kernel",root/"firecracker",root,root/"ssh-key",root/"known-hosts")
vm.socket.touch()
vm.serial=(root/"serial.log").open("wb")
class ExitingProcess:
    pid=12345
    exited=False
    def poll(self): return 0 if self.exited else None
    def wait(self,timeout): self.exited=True;return 0
vm.process=ExitingProcess()
with patch.object(m.os,"killpg",side_effect=ProcessLookupError): vm.stop()
result={"process":vm.process,"serial":vm.serial,"socket_exists":vm.socket.exists()}`)
	productionEqual(t, got, map[string]any{"process": nil, "serial": nil, "socket_exists": false})
}
func TestProductionCleanupKillsStuckSimulator(t *testing.T) {
	got := productionObserve(t, nil, `from unittest.mock import patch
from types import SimpleNamespace
run=m.Qualification(SimpleNamespace(run=False))
class StuckSimulator:
    pid=12345
    killed=False
    def poll(self): return -m.signal.SIGKILL if self.killed else None
    def wait(self,timeout):
        if not self.killed: raise m.subprocess.TimeoutExpired("simulator",timeout)
        return -m.signal.SIGKILL
run.simulator=StuckSimulator()
def send(pid,sig):
    if sig==m.signal.SIGKILL: run.simulator.killed=True
try:
    with patch.object(m.os,"killpg",side_effect=send): errors=run.cleanup()
    result={"errors":errors,"killed":run.simulator.killed}
finally: m.shutil.rmtree(run.root)`)
	productionEqual(t, got, map[string]any{"errors": []string{"simulator required SIGKILL during cleanup"}, "killed": true})
}
func TestProductionFailedRunRetainsCounters(t *testing.T) {
	const rules = "table bridge tspr_test {\nudp dport 123 counter packets 6 bytes 288 accept\ncounter packets 1 bytes 48 drop\n}\n"
	got := productionObserve(t, map[string]any{"rules": rules}, `from unittest.mock import patch
from types import SimpleNamespace
run=m.Qualification(SimpleNamespace(run=False))
class NTP:
    requests={slot:2 for slot in m.SLOTS}
    counts={slot:0 for slot in m.SLOTS}
    send_errors={slot:0 for slot in m.SLOTS}
    unknown=0
    def close(self): pass
run.ntp=NTP()
run.created_tables=[("bridge","tspr_test")]
calls=[]
def nft(*args,**kwargs):
    calls.append(list(args))
    return SimpleNamespace(stdout=a["rules"] if args[:3]==("nft","list","table") else "")
try:
    with patch.object(m,"command",side_effect=nft): errors=run.cleanup()
    result={"errors":errors,"report":run.report,"file":(run.root/"firewall-bridge.txt").read_text(),"calls":calls,"slots":list(m.SLOTS)}
finally: m.shutil.rmtree(run.root)`)
	productionEqual(t, got["errors"], []any{})
	report := got["report"].(map[string]any)
	requests, replies := map[string]any{}, map[string]any{}
	for _, slot := range got["slots"].([]any) {
		requests[slot.(string)] = 2
		replies[slot.(string)] = 0
	}
	productionEqual(t, report["ntpRequests"], requests)
	productionEqual(t, report["ntpReplies"], replies)
	productionEqual(t, report["firewallDrops"], 1)
	productionEqual(t, report["firewallCounterFiles"], map[string]string{"bridge": "firewall-bridge.txt"})
	productionContains(t, got["file"], "counter packets 6 bytes 288 accept")
	for _, v := range got["calls"].([]any) {
		argv := v.([]any)
		if !reflect.DeepEqual(argv[:3], []any{"nft", "list", "table"}) {
			productionEqual(t, argv[:3], []string{"nft", "delete", "table"})
		}
	}
}
func TestProductionRebootDisconnectRequiresNewIdentity(t *testing.T) {
	got := productionObserve(t, nil, `from types import SimpleNamespace
run=m.Qualification(SimpleNamespace(run=False))
run.report["serviceIdentity"]={slot:{"uid":1000,"gid":1000} for slot in m.SLOTS}
class RebootingVM:
    rebooted=False
    def boot(self): pass
    def wait_ssh(self,*,different_boot_id=None): return "boot-new" if different_boot_id else "boot-old"
    def health(self,uid,gid): return {"bootId":"boot-new" if self.rebooted else "boot-old","controllerInvocation":"inv-new" if self.rebooted else "inv-old"}
    def ssh(self,script,*,timeout,check): self.rebooted=True;raise m.subprocess.TimeoutExpired("ssh",timeout)
run.vms={slot:RebootingVM() for slot in m.SLOTS}
try:
    run.run_vms()
    result={"guests":run.report["guests"],"slots":list(m.SLOTS)}
finally: m.shutil.rmtree(run.root)`)
	guests := got["guests"].(map[string]any)
	slots := got["slots"].([]any)
	if len(guests) != len(slots) {
		t.Fatal("missing guest receipts")
	}
	for _, slot := range slots {
		receipt, ok := guests[slot.(string)]
		if !ok {
			t.Fatal("missing guest", slot)
		}
		productionEqual(t, receipt.(map[string]any)["restart"].(map[string]any)["bootId"], "boot-new")
	}
}
func TestProductionHealthFailureNamesStageAndDiagnostics(t *testing.T) {
	root := t.TempDir()
	got := productionObserve(t, map[string]any{"root": root}, `from unittest.mock import patch
from types import SimpleNamespace
root=m.Path(a["root"])
vm=m.VM("controller-a","tap0",root/"root.ext4",root/"kernel",root/"firecracker",root,root/"ssh-key",root/"known-hosts")
responses=[SimpleNamespace(returncode=1,stdout="",stderr="failed-stage=ntp-synchronized\n"),SimpleNamespace(returncode=0,stdout="[clock]\nno\n",stderr="")]
with patch.object(vm,"ssh",side_effect=responses) as ssh,patch.object(m.time,"monotonic",side_effect=[0,0,301]),patch.object(m.time,"sleep"):
    error=None
    try: vm.health(988,988)
    except TimeoutError as exc: error=str(exc)
result={"error":error,"calls":[call.args[0] for call in ssh.call_args_list]}`)
	productionContains(t, got["error"], "failed-stage=ntp-synchronized")
	productionContains(t, got["error"], "guest diagnostics:\n[clock]\nno")
	calls := got["calls"].([]any)
	if len(calls) != 2 {
		t.Fatalf("SSH calls %d", len(calls))
	}
	productionContains(t, calls[0], "|| fail ntp-synchronized")
	productionContains(t, calls[1], "SYSLOG_IDENTIFIER=systemd")
}
