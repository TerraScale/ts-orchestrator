package ci_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

type rcObject = map[string]any

func rcMap(v any) rcObject { return v.(map[string]any) }
func rcJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func rcObserve(t *testing.T, args any, body string) rcObject {
	t.Helper()
	var v rcObject
	if e := json.Unmarshal(script.Python(t, "scripts/ci/m0_oci_real_caller.py", args, body), &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func rcSHA(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func rcReject(t *testing.T, out rcObject) {
	t.Helper()
	if out["error_type"] != "QualificationError" {
		t.Fatalf("expected QualificationError: %v", out)
	}
}
func rcStatus() rcObject {
	scope := rcObject{"cluster_id": strings.Repeat("a", 32), "tenant_id": "tenant", "database_id": "database", "shard_id": 1}
	a := rcObject{"seat_id": "seat-a", "member_id": "member-a", "incarnation": strings.Repeat("a", 32)}
	b := rcObject{"seat_id": "seat-b", "member_id": "member-b", "incarnation": strings.Repeat("b", 32)}
	binding := rcObject{"cluster_id": scope["cluster_id"], "tenant_id": "tenant", "database_id": "database", "shard_id": 1, "member_id": "member-a", "incarnation": a["incarnation"]}
	oci := func() rcObject {
		return rcObject{"instance_id": "ocid1.instance.a", "region": "GRU", "owner": "terrascale", "fleet_generation": 1, "create_key": "a"}
	}
	proof := rcObject{"serving": true, "listeners": rcObject{"client": true, "replication": true}, "scope": binding, "authority": rcObject{"epoch": 1}, "process": rcObject{"pid": 123, "start_nonce": "boot-a"}, "replication": rcObject{"peer_member_id": "member-b", "peer_incarnation": b["incarnation"], "current_authenticated": true, "local_source_sequence": 3, "peer_durable_sequence": 3, "peer_applied_sequence": 3, "local_inbox_durable_sequence": 2, "local_inbox_applied_sequence": 2}}
	status := rcObject{"verified": false, "session_expires_at": time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), "registration": rcObject{"cell": "gru", "node": "node-a", "environment": "production", "managed_member": rcObject{"scope": binding, "host_attempt": 1}, "managed_oci": oci(), "managed_placement": rcObject{"database_id": "placement-db", "partition_id": "partition-a", "seat_id": "seat-a"}}, "reports": []any{rcObject{"cell": "gru", "environment": "production", "node": "node-a", "role": "terrabase", "state": "running", "digest": strings.Repeat("c", 64), "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "managed": rcObject{"member": rcObject{"scope": binding, "host_attempt": 1}, "oci": oci(), "authority": rcObject{"epoch": 1}, "process_pid": 123, "process_boot_id": "boot-a", "storage_recovered": true, "listener_ready": true, "serving_proof": proof}}}}
	return rcObject{"status": status, "spec": rcObject{"scope": scope, "placement_database_id": "placement-db", "partition_id": "partition-a", "members": []any{a, b}}, "member": a, "peer": b, "instance": "ocid1.instance.a", "digest": strings.Repeat("c", 64)}
}
func TestRealCallerCurrentReportExactIdentity(t *testing.T) {
	for _, name := range []string{"valid", "foreign_instance", "registration_cell", "registration_region", "report_cell", "unauthenticated_replication"} {
		t.Run(name, func(t *testing.T) {
			args := rcStatus()
			status := rcMap(args["status"])
			reg := rcMap(status["registration"])
			report := rcMap(status["reports"].([]any)[0])
			switch name {
			case "foreign_instance":
				args["instance"] = "ocid1.instance.foreign"
			case "registration_cell":
				reg["cell"] = "sfo"
			case "registration_region":
				rcMap(reg["managed_oci"])["region"] = "SFO"
			case "report_cell":
				report["cell"] = "sfo"
			case "unauthenticated_replication":
				rcMap(rcMap(rcMap(report["managed"])["serving_proof"])["replication"])["current_authenticated"] = false
			}
			out := rcObserve(t, args, "result = m.member_report([a['status']], a['spec'], a['member'], a['peer'], 'gru', a['instance'], a['digest'])\n")
			if name == "valid" {
				if rcMap(rcMap(out["serving_proof"])["replication"])["peer_applied_sequence"] != float64(3) {
					t.Fatal(out)
				}
			} else {
				rcReject(t, out)
			}
		})
	}
}
func TestRealCallerCustomerEnvelopeCommitments(t *testing.T) {
	id := []byte(strings.Repeat("i", 16))
	secret := []byte(strings.Repeat("s", 32))
	encoded := base64.RawURLEncoding.EncodeToString(id)
	token := "tbk1." + encoded + "." + base64.RawURLEncoding.EncodeToString(secret)
	ca := "CA PEM"
	reply := rcObject{"customer": rcObject{"token_id": encoded, "verifier_sha256": rcSHA(append(append([]byte("TB-APIKEY-V1\x00"), id...), secret...)), "https_ca_sha256": rcSHA([]byte(ca))}}
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			material := rcObject{"version": 1, "token": token, "https_ca_pem": ca}
			if changed {
				material["https_ca_pem"] = "different CA"
			}
			out := rcObserve(t, rcObject{"reply": reply, "material": material}, "result = {'material': m.customer_material(a['reply'], a['material'])}\n")
			if changed {
				rcReject(t, out)
			} else if !reflect.DeepEqual(out["material"], []any{token, ca}) {
				t.Fatal(out)
			}
		})
	}
}
func TestRealCallerForwardMapRejections(t *testing.T) {
	valid := "10.251.0.21:9465=127.0.0.1:19465"
	cases := []struct {
		name     string
		values   []string
		targets  [][]any
		complete bool
	}{{"missing", []string{valid}, [][]any{{"10.251.0.21", 9465}, {"10.251.0.22", 9465}}, true}, {"unknown", []string{"10.251.0.23:9465=127.0.0.1:19465"}, [][]any{{"10.251.0.21", 9465}, {"10.251.0.22", 9465}}, false}, {"noncanonical", []string{"010.251.0.21:9465=127.0.0.1:19465"}, [][]any{{"10.251.0.21", 9465}, {"10.251.0.22", 9465}}, false}, {"public_bind", []string{"10.251.0.21:9465=0.0.0.0:19465"}, [][]any{{"10.251.0.21", 9465}, {"10.251.0.22", 9465}}, false}, {"duplicate", []string{valid, valid}, [][]any{{"10.251.0.21", 9465}}, true}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rcReject(t, rcObserve(t, rcObject{"values": tc.values, "targets": tc.targets, "complete": tc.complete}, "result = m.forwards(a['values'], {tuple(v) for v in a['targets']}, 9465, a['complete'])\n"))
		})
	}
}
func TestRealCallerHostsRepeatableNATSForwardFlags(t *testing.T) {
	flags := []string{"10.251.0.11:4222=127.0.0.1:14222", "10.251.0.12:4222=127.0.0.1:14223"}
	out := rcObserve(t, flags, `from pathlib import Path
from types import SimpleNamespace
from unittest import mock
with mock.patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'[]')) as invoke:
    hosts = m.hosts(Path('/tmp/operator'), Path('/tmp/operator.json'), a)
result = {'hosts': hosts, 'command': invoke.call_args.args[0]}
`)
	want := []any{"/tmp/operator", "operator", "hosts", "--config", "/tmp/operator.json", "--nats-forward", flags[0], "--nats-forward", flags[1]}
	if !reflect.DeepEqual(out["hosts"], []any{}) || !reflect.DeepEqual(out["command"], want) {
		t.Fatal(out)
	}
}

type rcBootstrap struct {
	dir, binary, receipt string
	record, qualified    rcObject
	retained             map[string]string
}

func rcBootstrapFixture(t *testing.T) *rcBootstrap {
	t.Helper()
	dir := t.TempDir()
	f := &rcBootstrap{dir: dir, binary: filepath.Join(dir, "renamed-tool"), receipt: filepath.Join(dir, "receipt.json"), retained: map[string]string{}}
	header := make([]byte, 20)
	copy(header, []byte{0x7f, 'E', 'L', 'F', 2, 1})
	header[18] = 62
	script.Write(t, f.binary, header, 0700)
	source := strings.Repeat("a", 40)
	tree := strings.Repeat("b", 40)
	digest := strings.Repeat("c", 64)
	f.record = rcObject{"schema": "terrascale.bootstrap.local-build.v1", "repository": "TerraScale/ts-orchestrator", "source_revision": source, "source_tree": tree, "source_clean_before": true, "source_clean_after": true, "go_version": "go1.27.1", "go_mod_sha256": digest, "go_sum_sha256": digest, "goos": "linux", "goarch": "amd64", "cgo_enabled": false, "binary_name": "ts-bootstrap", "binary_sha256": rcSHA(header), "binary_bytes": 20, "vcs_revision": source, "vcs_modified": false, "elf_machine": "Advanced Micro Devices X86-64", "has_interp": false, "has_needed": false, "build_exit": 0, "test_exit": 0}
	for _, name := range []string{"build_command", "build_log", "test_command", "test_log"} {
		p := filepath.Join(dir, name)
		b := []byte("retained " + name + "\n")
		script.Write(t, p, b, 0600)
		f.retained[name] = p
		f.record[name+"_sha256"] = rcSHA(b)
	}
	f.qualified = rcObject{"source_revision": source, "source_tree": tree, "go_mod_sha256": digest, "go_sum_sha256": digest}
	return f
}
func (f *rcBootstrap) provenance(t *testing.T) rcObject {
	t.Helper()
	b := rcJSON(t, f.record)
	script.Write(t, f.receipt, b, 0600)
	return rcObserve(t, rcObject{"receipt": f.receipt, "receipt_sha": rcSHA(b), "binary": f.binary, "binary_sha": f.record["binary_sha256"], "qualified": f.qualified, "retained": f.retained}, `from pathlib import Path
from types import SimpleNamespace
from unittest import mock
with mock.patch.object(m.subprocess, 'run', side_effect=[SimpleNamespace(returncode=0, stdout='go1.27.1\nCGO_ENABLED=0\nvcs.revision=`+strings.Repeat("a", 40)+`\nvcs.modified=false\n'), SimpleNamespace(returncode=0, stdout='ELF has no dynamic loader')]):
    provenance = m.bootstrap_provenance(Path(a['receipt']), a['receipt_sha'], Path(a['binary']), a['binary_sha'], a['qualified'], {k: Path(v) for k, v in a['retained'].items()})
result = {'provenance': provenance, 'fields': sorted(m.BOOTSTRAP_RECEIPT_FIELDS)}
`)
}
func TestRealCallerBootstrapReceiptAndCommandIdentity(t *testing.T) {
	for _, identity := range []string{"ts-bootstrap", "ts-orch", "terrascale-orchestrator", "terrascale-orchestrator-linux-amd64", "renamed-tool", "ts-release", "terrascale-orchestrator-linux-arm64"} {
		t.Run(identity, func(t *testing.T) {
			f := rcBootstrapFixture(t)
			f.record["binary_name"] = identity
			out := f.provenance(t)
			if identity == "renamed-tool" || identity == "ts-release" || identity == "terrascale-orchestrator-linux-arm64" {
				rcReject(t, out)
				return
			}
			p := rcMap(out["provenance"])
			if p["sha256"] != rcSHA(script.Read(t, f.receipt)) || p["binary_name"] != identity {
				t.Fatal(p)
			}
			fields := out["fields"].([]any)
			if len(fields) != len(f.record) {
				t.Fatal(fields)
			}
			for _, v := range fields {
				if _, ok := f.record[v.(string)]; !ok {
					t.Fatalf("missing %v", v)
				}
			}
			opened := filepath.Join(f.dir, "opened.json")
			script.Write(t, opened, []byte(`{"version":1}`), 0600)
			observed := rcObserve(t, rcObject{"binary": f.binary, "provenance": p, "opened": opened}, `from pathlib import Path
from types import SimpleNamespace
from unittest import mock
args = SimpleNamespace(bootstrap=Path(a['binary']), reply=Path('/tmp/reply.json'), spec=Path('/tmp/spec.json'), controller_key=Path('/tmp/controller.pub'), cell='gru', recipient_key=Path('/tmp/recipient.key'))
with mock.patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as invoke:
    material = m.open_customer_material(args, a['provenance'], Path(a['opened']))
result = {'material': material, 'command': invoke.call_args.args[0], 'kwargs': invoke.call_args.kwargs}
`)
			want := []any{f.binary}
			if identity != "ts-bootstrap" {
				want = append(want, "bootstrap")
			}
			want = append(want, "open-customer-material", "--reply", "/tmp/reply.json", "--spec", "/tmp/spec.json", "--controller-key", "/tmp/controller.pub", "--cell", "gru", "--recipient-key", "/tmp/recipient.key", "--out", opened)
			if !reflect.DeepEqual(observed["command"], want) || !reflect.DeepEqual(observed["material"], rcObject{"version": float64(1)}) || !reflect.DeepEqual(observed["kwargs"], rcObject{"capture_output": true, "timeout": float64(30), "check": false}) {
				t.Fatal(observed)
			}
			f.qualified["source_revision"] = strings.Repeat("d", 40)
			rcReject(t, f.provenance(t))
		})
	}
	for _, name := range []string{"tampered_build_log", "dirty_vcs"} {
		t.Run(name, func(t *testing.T) {
			f := rcBootstrapFixture(t)
			if name == "tampered_build_log" {
				script.Write(t, f.retained["build_log"], []byte("tampered log\n"), 0600)
			} else {
				f.record["vcs_modified"] = true
			}
			rcReject(t, f.provenance(t))
		})
	}
}
func TestRealCallerTerrabaseStaticARM64Qualification(t *testing.T) {
	for _, name := range []string{"valid", "dynamic", "old_schema", "gnu"} {
		t.Run(name, func(t *testing.T) {
			source := strings.Repeat("a", 40)
			sha := strings.Repeat("c", 64)
			artifact := rcObject{"name": "tb-server-linux-arm64", "target": "aarch64-unknown-linux-musl", "sha256": sha, "bytes": 42}
			record := rcObject{"schema": "terrascale.terrabase.qualification.v2", "repository": "TerraScale/TerraBase", "source_revision": source, "source_tree": strings.Repeat("b", 40), "build_profile": "release", "linkage": "static", "verification": rcObject{"workflow": "fast.yml", "job": "fast", "run_id": 7, "run_number": 3, "conclusion": "success"}, "artifacts": []any{rcObject{"name": "tb-server-linux-amd64", "target": "x86_64-unknown-linux-musl", "sha256": strings.Repeat("d", 64), "bytes": 11}, artifact}}
			switch name {
			case "dynamic":
				record["linkage"] = "dynamic"
			case "old_schema":
				record["schema"] = "terrascale.terrabase.qualification.v1"
			case "gnu":
				artifact["target"] = "aarch64-unknown-linux-gnu"
				record["artifacts"] = []any{artifact}
			}
			path := filepath.Join(t.TempDir(), "qualification.json")
			b := rcJSON(t, record)
			script.Write(t, path, b, 0600)
			out := rcObserve(t, rcObject{"path": path, "sha": rcSHA(b), "source": source, "artifact_sha": sha}, "from pathlib import Path\nresult = m.qualification(Path(a['path']), a['sha'], 'terrascale.terrabase.qualification.v2', 'fast.yml', a['source'], 'tb-server-linux-arm64', a['artifact_sha'], 42)\n")
			if name == "valid" {
				if out["artifact_sha256"] != sha {
					t.Fatal(out)
				}
			} else {
				rcReject(t, out)
			}
		})
	}
}
func TestRealCallerLoopbackTCPPreservesSignedIPTLSAndHost(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "10.251.0.21"}, IPAddresses: []net.IP{net.ParseIP("10.251.0.21")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	requests := make(chan *http.Request, 1)
	server := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r
		io.WriteString(w, `{"version":1,"state":"absent"}`)
	})}
	t.Cleanup(func() { server.Close() })
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	for _, signedIP := range []string{"10.251.0.21", "10.251.0.22"} {
		t.Run(signedIP, func(t *testing.T) {
			out := rcObserve(t, rcObject{"ca": string(certPEM), "port": port, "ip": signedIP}, "import ssl\ncontext = ssl.create_default_context(cadata=a['ca'])\nresult = m.request((a['ip'], 9465), ('127.0.0.1', a['port']), context, 'test-token', 'GET', '/point')\n")
			if signedIP == "10.251.0.21" {
				if out["state"] != "absent" {
					t.Fatal(out)
				}
			} else if out["error_type"] != "SSLCertVerificationError" {
				t.Fatal(out)
			}
		})
	}
	select {
	case req := <-requests:
		if req.Host != "10.251.0.21:9465" || req.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("host=%q authorization=%q", req.Host, req.Header.Get("Authorization"))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no authenticated request")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("TLS server did not stop")
	}
}
