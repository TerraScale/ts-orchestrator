package ci_test

import (
	"context"
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
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ci/realcaller"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
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
func rcSHA(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func rcStatus() rcObject {
	scope := rcObject{"cluster_id": strings.Repeat("a", 32), "tenant_id": "tenant", "database_id": "database", "shard_id": 1}
	a := rcObject{"seat_id": "000000000077F1R6E1XPKAC2D4", "member_id": "0000000000WM3QQGQPMW5X58P9", "incarnation": strings.Repeat("a", 32)}
	b := rcObject{"seat_id": "0000000000GXPF5F560P92PC00", "member_id": "0000000000N9X5GQEQJ9NA9A7V", "incarnation": strings.Repeat("b", 32)}
	binding := rcObject{"cluster_id": scope["cluster_id"], "tenant_id": "tenant", "database_id": "database", "shard_id": 1, "member_id": "0000000000WM3QQGQPMW5X58P9", "incarnation": a["incarnation"]}
	oci := rcObject{"instance_id": "ocid1.instance.a", "region": "GRU", "owner": "terrascale", "fleet_generation": 1, "create_key": "a"}
	proof := rcObject{"serving": true, "listeners": rcObject{"client": true, "replication": true}, "scope": binding, "authority": rcObject{"epoch": 1}, "process": rcObject{"pid": 123, "start_nonce": "boot-a"}, "replication": rcObject{"peer_member_id": "0000000000N9X5GQEQJ9NA9A7V", "peer_incarnation": b["incarnation"], "current_authenticated": true, "local_source_sequence": 3, "peer_durable_sequence": 3, "peer_applied_sequence": 3, "local_inbox_durable_sequence": 2, "local_inbox_applied_sequence": 2}}
	status := rcObject{"verified": false, "session_expires_at": time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), "registration": rcObject{"cell": "gru", "node": "node-a", "environment": "production", "managed_member": rcObject{"scope": binding, "host_attempt": 1}, "managed_oci": oci, "managed_placement": rcObject{"database_id": "placement-db", "partition_id": "0000000000Z3WK359G2W66CVT8", "seat_id": "000000000077F1R6E1XPKAC2D4"}}, "reports": []any{rcObject{"cell": "gru", "environment": "production", "node": "node-a", "role": "terrabase", "state": "running", "digest": strings.Repeat("c", 64), "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "managed": rcObject{"member": rcObject{"scope": binding, "host_attempt": 1}, "oci": oci, "authority": rcObject{"epoch": 1}, "process_pid": 123, "process_boot_id": "boot-a", "storage_recovered": true, "listener_ready": true, "serving_proof": proof}}}}
	return rcObject{"status": status, "spec": rcObject{"scope": scope, "placement_database_id": "placement-db", "partition_id": "0000000000Z3WK359G2W66CVT8", "members": []any{a, b}}, "member": a, "peer": b, "instance": "ocid1.instance.a", "digest": strings.Repeat("c", 64)}
}
func TestRealCallerCurrentReportExactIdentity(t *testing.T) {
	for _, name := range []string{"valid", "foreign_instance", "registration_cell", "registration_region", "report_cell", "unauthenticated_replication", "expired_session", "stale_report", "duplicate_report"} {
		t.Run(name, func(t *testing.T) {
			args := rcStatus()
			status := rcMap(args["status"])
			reg := rcMap(status["registration"])
			report := rcMap(status["reports"].([]any)[0])
			switch name {
			case "foreign_instance":
				args["instance"] = "ocid1.instance.foreign"
			case "registration_cell":
				reg["cell"] = "sjc"
			case "registration_region":
				rcMap(reg["managed_oci"])["region"] = "SJC"
			case "report_cell":
				report["cell"] = "sjc"
			case "unauthenticated_replication":
				rcMap(rcMap(rcMap(report["managed"])["serving_proof"])["replication"])["current_authenticated"] = false
			case "expired_session":
				status["session_expires_at"] = time.Now().Add(-time.Minute).Format(time.RFC3339)
			case "stale_report":
				report["observed_at"] = time.Now().Add(-time.Minute).Format(time.RFC3339)
			case "duplicate_report":
				status["reports"] = []any{report, report}
			}
			out, e := realcaller.MemberReport([]any{status}, rcMap(args["spec"]), rcMap(args["member"]), rcMap(args["peer"]), "gru", args["instance"].(string), args["digest"].(string), time.Now())
			if name == "valid" {
				if e != nil || rcMap(rcMap(out["serving_proof"])["replication"])["peer_applied_sequence"] != 3 {
					t.Fatal(out, e)
				}
			} else if e == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}
func TestRealCallerCustomerEnvelopeCommitments(t *testing.T) {
	id, err := entityid.Parse("01K78000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte(strings.Repeat("s", 32))
	encoded := id.String()
	token := "tbk1." + encoded + "." + base64.RawURLEncoding.EncodeToString(secret)
	ca := "CA PEM"
	reply := rcObject{"customer": rcObject{"token_id": encoded, "verifier_sha256": rcSHA(append(append([]byte("TB-APIKEY-V1\x00"), id[:]...), secret...)), "https_ca_sha256": rcSHA([]byte(ca))}}
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			material := rcObject{"version": 1, "token": token, "https_ca_pem": ca}
			if changed {
				material["https_ca_pem"] = "different CA"
			}
			gotToken, gotCA, e := realcaller.CustomerMaterial(reply, material)
			if changed {
				if e == nil {
					t.Fatal("accepted changed CA")
				}
			} else if e != nil || gotToken != token || gotCA != ca {
				t.Fatal(gotToken, gotCA, e)
			}
		})
	}
}

func TestRealCallerCustomerTokenRejectsNoncanonicalIDs(t *testing.T) {
	rawID := []byte(strings.Repeat("i", 16))
	rawSecret := []byte(strings.Repeat("s", 32))
	secret := base64.RawURLEncoding.EncodeToString(rawSecret)
	verifier := rcSHA(append(append([]byte("TB-APIKEY-V1\x00"), rawID...), rawSecret...))
	for _, id := range []string{
		"00000000000000000000000000", "01k78000000000000000000001",
		"token_01K78000000000000000000001", "81K78000000000000000000001",
		"01a1105a-7350-7f48-a96e-d71bbb45d7a8",
		base64.RawURLEncoding.EncodeToString(rawID),
	} {
		reply := rcObject{"customer": rcObject{"token_id": id, "verifier_sha256": verifier, "https_ca_sha256": rcSHA([]byte("CA PEM"))}}
		material := rcObject{"version": 1, "token": "tbk1." + id + "." + secret, "https_ca_pem": "CA PEM"}
		if _, _, err := realcaller.CustomerMaterial(reply, material); err == nil {
			t.Errorf("accepted noncanonical token ID %q", id)
		}
	}
}
func TestRealCallerForwardMapRejections(t *testing.T) {
	valid := "10.251.0.21:9465=127.0.0.1:19465"
	cases := []struct {
		name     string
		values   []string
		targets  []string
		complete bool
	}{{"missing", []string{valid}, []string{"10.251.0.21:9465", "10.251.0.22:9465"}, true}, {"unknown", []string{"10.251.0.23:9465=127.0.0.1:19465"}, []string{"10.251.0.21:9465", "10.251.0.22:9465"}, false}, {"noncanonical", []string{"010.251.0.21:9465=127.0.0.1:19465"}, []string{"10.251.0.21:9465"}, false}, {"public_bind", []string{"10.251.0.21:9465=0.0.0.0:19465"}, []string{"10.251.0.21:9465"}, false}, {"duplicate", []string{valid, valid}, []string{"10.251.0.21:9465"}, true}, {"duplicate_destination", []string{valid, "10.251.0.22:9465=127.0.0.1:19465"}, []string{"10.251.0.21:9465", "10.251.0.22:9465"}, true}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			targets := map[netip.AddrPort]bool{}
			for _, v := range tc.targets {
				targets[netip.MustParseAddrPort(v)] = true
			}
			if _, e := realcaller.Forwards(t.Context(), tc.values, targets, 9465, tc.complete); e == nil {
				t.Fatal("accepted invalid forwards")
			}
		})
	}
}
func TestRealCallerHostsRepeatableNATSForwardFlags(t *testing.T) {
	flags := []string{"10.251.0.11:4222=127.0.0.1:14222", "10.251.0.12:4222=127.0.0.1:14223"}
	var command []string
	statuses, e := realcaller.Hosts(t.Context(), "/tmp/operator", "/tmp/operator.json", flags, func(ctx context.Context, timeout time.Duration, args []string) ([]byte, error) {
		command = args
		if timeout != 30*time.Second {
			t.Fatal(timeout)
		}
		return []byte("[]"), nil
	})
	want := []string{"/tmp/operator", "operator", "hosts", "--config", "/tmp/operator.json", "--nats-forward", flags[0], "--nats-forward", flags[1]}
	if e != nil || len(statuses) != 0 || !slices.Equal(command, want) {
		t.Fatal(statuses, command, e)
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
	source, tree, digest := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 64)
	f.record = rcObject{"schema": "terrascale.bootstrap.local-build.v1", "repository": "TerraScale/ts-orchestrator", "source_revision": source, "source_tree": tree, "source_clean_before": true, "source_clean_after": true, "go_version": "go1.27.3", "go_mod_sha256": digest, "go_sum_sha256": digest, "goos": "linux", "goarch": "amd64", "cgo_enabled": false, "binary_name": "ts-bootstrap", "binary_sha256": rcSHA(header), "binary_bytes": 20, "vcs_revision": source, "vcs_modified": false, "elf_machine": "Advanced Micro Devices X86-64", "has_interp": false, "has_needed": false, "build_exit": 0, "test_exit": 0}
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
func (f *rcBootstrap) provenance(t *testing.T) (rcObject, error) {
	t.Helper()
	b := rcJSON(t, f.record)
	script.Write(t, f.receipt, b, 0600)
	return realcaller.BootstrapProvenance(t.Context(), f.receipt, rcSHA(b), f.binary, f.record["binary_sha256"].(string), f.qualified, f.retained, func(ctx context.Context, timeout time.Duration, args []string) ([]byte, error) {
		switch args[0] {
		case "go":
			return []byte("go1.27.3\nCGO_ENABLED=0\nvcs.revision=" + strings.Repeat("a", 40) + "\nvcs.modified=false\n"), nil
		case "readelf":
			return []byte("ELF has no dynamic loader"), nil
		}
		t.Fatal(args)
		return nil, nil
	})
}
func TestRealCallerBootstrapReceiptAndCommandIdentity(t *testing.T) {
	for _, identity := range []string{"ts-bootstrap", "ts-orch", "terrascale-orchestrator", "terrascale-orchestrator-linux-amd64", "renamed-tool", "ts-release", "terrascale-orchestrator-linux-arm64"} {
		t.Run(identity, func(t *testing.T) {
			f := rcBootstrapFixture(t)
			f.record["binary_name"] = identity
			p, e := f.provenance(t)
			if identity == "renamed-tool" || identity == "ts-release" || identity == "terrascale-orchestrator-linux-arm64" {
				if e == nil {
					t.Fatal("accepted invalid identity")
				}
				return
			}
			if e != nil || p["sha256"] != rcSHA(script.Read(t, f.receipt)) || p["binary_name"] != identity {
				t.Fatal(p, e)
			}
			if len(realcaller.BootstrapReceiptFields) != len(f.record) {
				t.Fatal(realcaller.BootstrapReceiptFields)
			}
			for _, v := range realcaller.BootstrapReceiptFields {
				if _, ok := f.record[v]; !ok {
					t.Fatalf("missing %s", v)
				}
			}
			opened := filepath.Join(f.dir, "opened.json")
			script.Write(t, opened, []byte(`{"version":1}`), 0600)
			var command []string
			material, e := realcaller.OpenCustomerMaterial(t.Context(), realcaller.Options{Bootstrap: f.binary, Reply: "/tmp/reply.json", Spec: "/tmp/spec.json", ControllerKey: "/tmp/controller.pub", Cell: "gru", RecipientKey: "/tmp/recipient.key"}, p, opened, func(ctx context.Context, timeout time.Duration, args []string) ([]byte, error) {
				command = args
				if timeout != 30*time.Second {
					t.Fatal(timeout)
				}
				return nil, nil
			})
			want := []string{f.binary}
			if identity != "ts-bootstrap" {
				want = append(want, "bootstrap")
			}
			want = append(want, "open-customer-material", "--reply", "/tmp/reply.json", "--spec", "/tmp/spec.json", "--controller-key", "/tmp/controller.pub", "--cell", "gru", "--recipient-key", "/tmp/recipient.key", "--out", opened)
			if e != nil || !slices.Equal(command, want) || !reflect.DeepEqual(material, rcObject{"version": uint64(1)}) {
				t.Fatal(material, command, e)
			}
			f.qualified["source_revision"] = strings.Repeat("d", 40)
			if _, e = f.provenance(t); e == nil {
				t.Fatal("accepted different qualification source")
			}
		})
	}
	for _, name := range []string{"tampered_build_log", "dirty_vcs", "unknown_field", "missing_evidence"} {
		t.Run(name, func(t *testing.T) {
			f := rcBootstrapFixture(t)
			switch name {
			case "tampered_build_log":
				script.Write(t, f.retained["build_log"], []byte("tampered\n"), 0600)
			case "dirty_vcs":
				f.record["vcs_modified"] = true
			case "unknown_field":
				f.record["unknown"] = true
			case "missing_evidence":
				delete(f.retained, "build_log")
			}
			if _, e := f.provenance(t); e == nil {
				t.Fatal("accepted tampered provenance")
			}
		})
	}
}
func TestRealCallerTerrabaseStaticARM64Qualification(t *testing.T) {
	for _, name := range []string{"valid", "dynamic", "old_schema", "gnu"} {
		t.Run(name, func(t *testing.T) {
			source, sha := strings.Repeat("a", 40), strings.Repeat("c", 64)
			artifact := rcObject{"name": "tb-server-linux-arm64", "target": "aarch64-unknown-linux-musl", "sha256": sha, "bytes": 42}
			record := rcObject{"schema": "terrascale.terrabase.qualification.v2", "repository": "TerraScale/TerraBase", "source_revision": source, "source_tree": strings.Repeat("b", 40), "build_profile": "release", "linkage": "static", "verification": rcObject{"workflow": "fast.yml", "job": "fast", "run_id": 7, "run_number": 3, "conclusion": "success"}, "artifacts": []any{rcObject{"name": "tb-server-linux-amd64", "target": "x86_64-unknown-linux-musl", "sha256": strings.Repeat("d", 64), "bytes": 11}, artifact}}
			switch name {
			case "dynamic":
				record["linkage"] = "dynamic"
			case "old_schema":
				record["schema"] = "terrascale.terrabase.qualification.v1"
			case "gnu":
				artifact["target"] = "aarch64-unknown-linux-gnu"
			}
			path := filepath.Join(t.TempDir(), "qualification.json")
			b := rcJSON(t, record)
			script.Write(t, path, b, 0600)
			out, e := realcaller.Qualification(path, rcSHA(b), "terrascale.terrabase.qualification.v2", "fast.yml", source, "tb-server-linux-arm64", sha, 42)
			if name == "valid" {
				if e != nil || out["artifact_sha256"] != sha {
					t.Fatal(out, e)
				}
			} else if e == nil {
				t.Fatal("accepted invalid qualification")
			}
		})
	}
}
func TestRealCallerLoopbackTCPPreservesSignedIPTLSAndHost(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "10.251.0.21"}, IPAddresses: []net.IP{net.ParseIP("10.251.0.21")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	requests := make(chan *http.Request, 1)
	server := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r
		io.WriteString(w, `{"version":1,"state":"absent"}`)
	})}
	t.Cleanup(func() { server.Close() })
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	connect := netip.MustParseAddrPort(listener.Addr().String())
	for _, ip := range []string{"10.251.0.21", "10.251.0.22"} {
		t.Run(ip, func(t *testing.T) {
			out, e := realcaller.Request(t.Context(), netip.AddrPortFrom(netip.MustParseAddr(ip), 9465), connect, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, "test-token", "GET", "/point", nil)
			if ip == "10.251.0.21" {
				if e != nil || out["state"] != "absent" {
					t.Fatal(out, e)
				}
			} else if e == nil {
				t.Fatal("accepted foreign certificate identity")
			}
		})
	}
	select {
	case req := <-requests:
		if req.Host != "10.251.0.21:9465" || req.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatal(req.Host, req.Header)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no authenticated request")
	}
	server.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("TLS server did not stop")
	}
}

func TestRealCallerAcknowledgmentFrontiersPreserveUint64(t *testing.T) {
	const sequence uint64 = 9007199254740993
	path := filepath.Join(t.TempDir(), "frontiers.json")
	script.Write(t, path, []byte(`{"a":{"local_source_sequence":9007199254740993,"peer_durable_sequence":9007199254740992,"peer_applied_sequence":9007199254740993},"b":{"local_inbox_durable_sequence":9007199254740993,"local_inbox_applied_sequence":9007199254740993}}`), 0600)
	record, e := realcaller.ReadJSON(path, 1024)
	if e != nil {
		t.Fatal(e)
	}
	a, b := rcMap(record["a"]), rcMap(record["b"])
	if a["local_source_sequence"] != sequence {
		t.Fatal("rounded source frontier", a)
	}
	advanced, e := realcaller.FrontierAdvanced(a, b, sequence-1, sequence-1)
	if e != nil || advanced {
		t.Fatal("accepted an ACK one sequence behind", advanced, e)
	}
	a["peer_durable_sequence"] = sequence
	advanced, e = realcaller.FrontierAdvanced(a, b, sequence-1, sequence-1)
	if e != nil || !advanced {
		t.Fatal("rejected exact current ACK frontiers", advanced, e)
	}
	delete(b, "local_inbox_durable_sequence")
	if _, e = realcaller.FrontierAdvanced(a, b, sequence-1, sequence-1); e == nil {
		t.Fatal("accepted missing frontier")
	}
}
