// Package realcaller qualifies an already deployed OCI pair using authenticated
// operator reports and private HTTPS callers. It never creates an instance.
package realcaller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
)

type Object = map[string]any
type Runner func(context.Context, time.Duration, []string) ([]byte, error)

func Execute(ctx context.Context, timeout time.Duration, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return exec.CommandContext(ctx, args[0], args[1:]...).Output()
}
func obj(v any) Object                { m, _ := v.(map[string]any); return m }
func array(v any) []any               { a, _ := v.([]any); return a }
func str(m Object, key string) string { v, _ := m[key].(string); return v }
func number(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case uint64:
		return float64(n)
	case float64:
		return n
	}
	return -1
}
func equal(a, b any) bool {
	x, e := json.Marshal(a, json.Deterministic(true))
	if e != nil {
		return false
	}
	y, e := json.Marshal(b, json.Deterministic(true))
	return e == nil && bytes.Equal(x, y)
}
func check(ok bool, message string) error {
	if !ok {
		return fmt.Errorf("%s", message)
	}
	return nil
}
func hashBytes(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Preserve integer frontiers exactly instead of rounding uint64 acknowledgments
// through an interface's default float64 representation.
var exactIntegers = json.WithUnmarshalers(json.UnmarshalFromFunc(func(dec *jsontext.Decoder, value *any) error {
	if dec.PeekKind() != '0' {
		return errors.ErrUnsupported
	}
	wire, err := dec.ReadValue()
	if err != nil {
		return err
	}
	if n, err := strconv.ParseUint(string(wire), 10, 64); err == nil {
		*value = n
		return nil
	}
	if n, err := strconv.ParseInt(string(wire), 10, 64); err == nil {
		*value = n
		return nil
	}
	n, err := strconv.ParseFloat(string(wire), 64)
	*value = n
	return err
}))

func sequence(value any) (uint64, error) {
	switch n := value.(type) {
	case uint64:
		return n, nil
	case int:
		if n >= 0 {
			return uint64(n), nil
		}
	case int64:
		if n >= 0 {
			return uint64(n), nil
		}
	}
	return 0, fmt.Errorf("replication frontier is not an unsigned integer")
}

func FrontierAdvanced(a, b Object, baseSource, baseInbox uint64) (bool, error) {
	keys := []string{"local_source_sequence", "peer_durable_sequence", "peer_applied_sequence", "local_inbox_durable_sequence", "local_inbox_applied_sequence"}
	values := make([]uint64, len(keys))
	for i, key := range keys {
		proof := a
		if i >= 3 {
			proof = b
		}
		n, err := sequence(proof[key])
		if err != nil {
			return false, err
		}
		values[i] = n
	}
	return values[0] > baseSource && values[1] >= values[0] && values[2] >= values[0] && values[3] >= values[0] && values[4] >= values[0] && values[4] > baseInbox, nil
}
func ReadJSON(path string, limit int64) (Object, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if len(b) == 0 || int64(len(b)) > limit {
		return nil, fmt.Errorf("input JSON is empty or oversized")
	}
	var value Object
	if e = json.Unmarshal(b, &value, exactIntegers); e != nil {
		return nil, e
	}
	if value == nil {
		return nil, fmt.Errorf("input JSON must be an object")
	}
	return value, nil
}
func DigestFile(path, expected string) (string, error) {
	if !lowerHex(expected, 64) {
		return "", fmt.Errorf("expected SHA-256 is malformed")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expected {
		return "", fmt.Errorf("artifact digest mismatch")
	}
	return actual, nil
}
func RequireELF(path string, machine uint16) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	var b [20]byte
	if _, e = io.ReadFull(f, b[:]); e != nil {
		return e
	}
	return check(bytes.Equal(b[:6], []byte{0x7f, 'E', 'L', 'F', 2, 1}) && binary.LittleEndian.Uint16(b[18:]) == machine, "retained binary has the wrong ELF target")
}
func RequireStatic(ctx context.Context, path string, run Runner) error {
	b, e := run(ctx, 10*time.Second, []string{"readelf", "-l", "-d", path})
	if e != nil {
		return fmt.Errorf("retained binary is dynamically linked")
	}
	return check(!bytes.Contains(b, []byte("INTERP")) && !bytes.Contains(b, []byte("(NEEDED)")), "retained binary is dynamically linked")
}
func Qualification(path, digest, schema, workflow, sourceSHA, artifact, artifactSHA string, artifactSize int64) (Object, error) {
	if _, e := DigestFile(path, digest); e != nil {
		return nil, e
	}
	r, e := ReadJSON(path, 1<<20)
	if e != nil {
		return nil, e
	}
	v := obj(r["verification"])
	repo, job := "TerraScale/TerraBase", "fast"
	if workflow == "ci.yml" {
		repo = "TerraScale/ts-orchestrator"
		job = "verify/go + artifact/linux-amd64-arm64"
	}
	if e = check(lowerHex(sourceSHA, 40) && r["schema"] == schema && r["repository"] == repo && r["source_revision"] == sourceSHA && lowerHex(str(r, "source_tree"), 40) && v["workflow"] == workflow && v["conclusion"] == "success" && v["job"] == job && number(v["run_id"]) > 0 && number(v["run_id"]) == float64(int64(number(v["run_id"]))) && number(v["run_number"]) > 0 && number(v["run_number"]) == float64(int64(number(v["run_number"]))), "qualification source or successful CI run is invalid"); e != nil {
		return nil, e
	}
	if workflow == "fast.yml" {
		e = check(r["build_profile"] == "release" && r["linkage"] == "static", "native qualification build is invalid")
	} else {
		e = check(r["go_version"] == "go1.27.1" && lowerHex(str(r, "go_mod_sha256"), 64) && lowerHex(str(r, "go_sum_sha256"), 64), "qualified Go module source hashes are invalid")
	}
	if e != nil {
		return nil, e
	}
	var selected Object
	count := 0
	for _, item := range array(r["artifacts"]) {
		a := obj(item)
		if a["name"] == artifact {
			selected = a
			count++
		}
	}
	if count != 1 || selected["sha256"] != artifactSHA || number(selected["bytes"]) != float64(artifactSize) {
		return nil, fmt.Errorf("qualification artifact differs from retained bytes")
	}
	if workflow == "fast.yml" && selected["target"] != "aarch64-unknown-linux-musl" {
		return nil, fmt.Errorf("native qualification target is invalid")
	}
	return Object{"sha256": digest, "source_revision": sourceSHA, "source_tree": r["source_tree"], "run_id": v["run_id"], "run_number": v["run_number"], "artifact_sha256": artifactSHA, "go_mod_sha256": r["go_mod_sha256"], "go_sum_sha256": r["go_sum_sha256"]}, nil
}

var BootstrapReceiptFields = []string{"schema", "repository", "source_revision", "source_tree", "source_clean_before", "source_clean_after", "go_version", "go_mod_sha256", "go_sum_sha256", "goos", "goarch", "cgo_enabled", "binary_name", "binary_sha256", "binary_bytes", "vcs_revision", "vcs_modified", "elf_machine", "has_interp", "has_needed", "build_exit", "build_command_sha256", "build_log_sha256", "test_exit", "test_command_sha256", "test_log_sha256"}
var BootstrapToolNames = []string{"ts-bootstrap", "ts-orch", "terrascale-orchestrator", "terrascale-orchestrator-linux-amd64"}

func BootstrapProvenance(ctx context.Context, path, expectedSHA, binaryPath, binarySHA string, qualified Object, retained map[string]string, run Runner) (Object, error) {
	if _, e := DigestFile(path, expectedSHA); e != nil {
		return nil, e
	}
	if e := RequireELF(binaryPath, 62); e != nil {
		return nil, e
	}
	r, e := ReadJSON(path, 16<<10)
	if e != nil {
		return nil, e
	}
	info, e := os.Stat(binaryPath)
	if e != nil {
		return nil, e
	}
	ok := len(r) == len(BootstrapReceiptFields)
	for _, k := range BootstrapReceiptFields {
		_, exists := r[k]
		ok = ok && exists
	}
	ok = ok && r["schema"] == "terrascale.bootstrap.local-build.v1" && r["repository"] == "TerraScale/ts-orchestrator" && r["source_revision"] == qualified["source_revision"] && r["source_tree"] == qualified["source_tree"] && r["source_clean_before"] == true && r["source_clean_after"] == true && r["go_version"] == "go1.27.1" && r["go_mod_sha256"] == qualified["go_mod_sha256"] && r["go_sum_sha256"] == qualified["go_sum_sha256"] && r["goos"] == "linux" && r["goarch"] == "amd64" && r["cgo_enabled"] == false && slices.Contains(BootstrapToolNames, str(r, "binary_name")) && r["binary_sha256"] == binarySHA && number(r["binary_bytes"]) == float64(info.Size()) && r["vcs_revision"] == r["source_revision"] && r["vcs_modified"] == false && r["elf_machine"] == "Advanced Micro Devices X86-64" && r["has_interp"] == false && r["has_needed"] == false && number(r["build_exit"]) == 0 && number(r["test_exit"]) == 0
	for _, k := range []string{"go_mod_sha256", "go_sum_sha256", "build_command_sha256", "build_log_sha256", "test_command_sha256", "test_log_sha256"} {
		ok = ok && lowerHex(str(r, k), 64)
	}
	if !ok {
		return nil, fmt.Errorf("bootstrap build receipt differs from the qualified Go source or retained binary")
	}
	if len(retained) != 4 {
		return nil, fmt.Errorf("bootstrap build receipt lacks retained command or log evidence")
	}
	evidence := Object{}
	for _, k := range []string{"build_command", "build_log", "test_command", "test_log"} {
		p, ok := retained[k]
		if !ok {
			return nil, fmt.Errorf("bootstrap build receipt lacks retained command or log evidence")
		}
		if _, e = DigestFile(p, str(r, k+"_sha256")); e != nil {
			return nil, e
		}
		evidence[k] = r[k+"_sha256"]
	}
	metadata, e := run(ctx, 10*time.Second, []string{"go", "version", "-m", binaryPath})
	if e != nil {
		return nil, fmt.Errorf("bootstrap binary Go build metadata differs from clean local receipt")
	}
	for _, s := range []string{"go1.27.1", "vcs.revision=" + str(r, "source_revision"), "vcs.modified=false", "CGO_ENABLED=0"} {
		if !bytes.Contains(metadata, []byte(s)) {
			return nil, fmt.Errorf("bootstrap binary Go build metadata differs from clean local receipt")
		}
	}
	if e = RequireStatic(ctx, binaryPath, run); e != nil {
		return nil, e
	}
	return Object{"sha256": expectedSHA, "source_revision": r["source_revision"], "source_tree": r["source_tree"], "binary_sha256": binarySHA, "binary_name": r["binary_name"], "retained_evidence_sha256": evidence}, nil
}
func OpenCustomerMaterial(ctx context.Context, args Options, receipt Object, openedPath string, run Runner) (Object, error) {
	name := str(receipt, "binary_name")
	if !slices.Contains(BootstrapToolNames, name) {
		return nil, fmt.Errorf("unknown verified bootstrap tool identity")
	}
	command := []string{args.Bootstrap}
	if name != "ts-bootstrap" {
		command = append(command, "bootstrap")
	}
	command = append(command, "open-customer-material", "--reply", args.Reply, "--spec", args.Spec, "--controller-key", args.ControllerKey, "--cell", args.Cell, "--recipient-key", args.RecipientKey, "--out", openedPath)
	if _, e := run(ctx, 30*time.Second, command); e != nil {
		return nil, fmt.Errorf("offline signed customer material opening failed")
	}
	info, e := os.Stat(openedPath)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("offline signed customer material opening failed")
	}
	return ReadJSON(openedPath, 16<<10)
}
func CatalogBinding(spec Object, collectionID string) (uint64, string, error) {
	var row Object
	count := 0
	for _, v := range array(spec["catalogs"]) {
		r := obj(v)
		if r["collection_id"] == collectionID {
			row = r
			count++
		}
	}
	if count != 1 {
		return 0, "", fmt.Errorf("selected collection is absent or duplicated in signed spec")
	}
	wire, e := base64.StdEncoding.Strict().DecodeString(str(row, "canonical_catalog"))
	if e != nil {
		return 0, "", e
	}
	id, e := entityid.Parse(collectionID)
	if e != nil {
		return 0, "", e
	}
	if len(wire) < 84 || string(wire[:8]) != "TBCAT001" || binary.LittleEndian.Uint32(wire[8:12]) != uint32(len(wire)) || !bytes.Equal(wire[12:28], id[:]) {
		return 0, "", fmt.Errorf("signed catalog framing is invalid")
	}
	generation := binary.LittleEndian.Uint64(wire[28:36])
	schemaDigest := hex.EncodeToString(wire[44:76])
	schemaLen := binary.LittleEndian.Uint32(wire[76:80])
	if generation == 0 || schemaLen == 0 || uint64(schemaLen)+84 != uint64(len(wire)) || hashBytes(wire[80:len(wire)-4]) != schemaDigest {
		return 0, "", fmt.Errorf("signed catalog schema binding is invalid")
	}
	return generation, schemaDigest, nil
}
func CustomerMaterial(reply, opened Object) (string, string, error) {
	customer := obj(reply["customer"])
	token, ca := str(opened, "token"), str(opened, "https_ca_pem")
	_, tokenOK := opened["token"].(string)
	_, caOK := opened["https_ca_pem"].(string)
	if number(opened["version"]) != 1 || !tokenOK || !caOK {
		return "", "", fmt.Errorf("opened customer material is invalid")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "tbk1" || parts[1] != customer["token_id"] {
		return "", "", fmt.Errorf("customer token ID differs from verified preparation reply")
	}
	id, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil {
		return "", "", fmt.Errorf("customer token encoding is invalid")
	}
	secret, e := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if e != nil || len(id) != 16 || len(secret) != 32 {
		return "", "", fmt.Errorf("customer token length is invalid")
	}
	material := append(append([]byte("TB-APIKEY-V1\x00"), id...), secret...)
	if hashBytes(material) != customer["verifier_sha256"] || hashBytes([]byte(ca)) != customer["https_ca_sha256"] {
		return "", "", fmt.Errorf("opened customer material differs from verified preparation reply")
	}
	return token, ca, nil
}
func Endpoint(member Object) (netip.AddrPort, error) {
	ip, e := netip.ParseAddr(str(member, "client_ip"))
	port := number(member["client_port"])
	if e != nil || !ip.IsPrivate() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || port < 1 || port > 65535 || port != float64(uint16(port)) {
		return netip.AddrPort{}, fmt.Errorf("signed member HTTPS endpoint is not a private unicast address")
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}
func ParseForward(raw string, remotePort uint16) (netip.AddrPort, netip.AddrPort, error) {
	source, dest, ok := strings.Cut(raw, "=")
	if !ok {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("forward mapping has invalid syntax")
	}
	a, e := netip.ParseAddrPort(source)
	if e != nil {
		return a, netip.AddrPort{}, e
	}
	b, e := netip.ParseAddrPort(dest)
	if e != nil {
		return a, b, e
	}
	if !a.Addr().Is4() || a.String() != source || !a.Addr().IsPrivate() || !a.Addr().IsGlobalUnicast() || a.Addr().IsLoopback() || a.Port() != remotePort || b.String() != dest || b.Addr() != netip.MustParseAddr("127.0.0.1") || b.Port() == 0 {
		return a, b, fmt.Errorf("forward mapping must use a canonical private source and IPv4 loopback port")
	}
	return a, b, nil
}
func Forwards(ctx context.Context, values []string, targets map[netip.AddrPort]bool, remotePort uint16, required bool) (map[netip.AddrPort]netip.AddrPort, error) {
	routes := map[netip.AddrPort]netip.AddrPort{}
	local := map[netip.AddrPort]bool{}
	if len(values) == 0 && required {
		return nil, fmt.Errorf("required Bastion forwarding mappings are absent")
	}
	for _, raw := range values {
		a, b, e := ParseForward(raw, remotePort)
		if e != nil {
			return nil, e
		}
		if !targets[a] || routes[a].IsValid() || local[b] {
			return nil, fmt.Errorf("forwarding entries are unknown, duplicate, or incomplete")
		}
		routes[a] = b
		local[b] = true
	}
	if required && len(routes) != len(targets) {
		return nil, fmt.Errorf("forwarding entries are unknown, duplicate, or incomplete")
	}
	for _, dest := range routes {
		conn, e := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", dest.String())
		if e != nil {
			return nil, e
		}
		conn.Close()
	}
	return routes, nil
}
func ConfiguredControllers(path string) (map[netip.AddrPort]bool, error) {
	r, e := ReadJSON(path, 1<<20)
	if e != nil {
		return nil, e
	}
	urls := strings.Split(str(obj(r["nats"]), "url"), ",")
	controllers := map[netip.AddrPort]bool{}
	for _, u := range urls {
		address, ok := strings.CutPrefix(u, "tls://")
		if !ok || strings.Count(u, ":") != 2 {
			return nil, fmt.Errorf("installed operator config has an unexpected controller URL")
		}
		a, e := netip.ParseAddrPort(address)
		if e != nil || a.String() != address || a.Port() != 4222 {
			return nil, fmt.Errorf("installed operator config has a noncanonical controller URL")
		}
		controllers[a] = true
	}
	if len(urls) != 3 || len(controllers) != 3 {
		return nil, fmt.Errorf("installed operator config lacks three distinct controller URLs")
	}
	return controllers, nil
}
func Hosts(ctx context.Context, operator, config string, natsForwards []string, run Runner) ([]any, error) {
	command := []string{operator, "operator", "hosts", "--config", config}
	for _, f := range natsForwards {
		command = append(command, "--nats-forward", f)
	}
	b, e := run(ctx, 30*time.Second, command)
	if e != nil || len(b) == 0 || len(b) > 1<<20 {
		return nil, fmt.Errorf("authenticated operator hosts request failed")
	}
	var statuses []any
	if e = json.Unmarshal(b, &statuses, exactIntegers); e != nil || statuses == nil {
		return nil, fmt.Errorf("operator hosts response is invalid")
	}
	return statuses, nil
}

// Request retains the signed endpoint for TLS identity and HTTP Host; the
// loopback endpoint only selects the TCP route through the reviewed forward.
func Request(ctx context.Context, target, connectTo netip.AddrPort, tlsConfig *tls.Config, token, method, path string, body Object) (Object, error) {
	var wire io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return nil, e
		}
		wire = bytes.NewReader(b)
	}
	config := tlsConfig.Clone()
	config.ServerName = target.Addr().String()
	config.MinVersion = tls.VersionTLS12
	transport := &http.Transport{TLSClientConfig: config, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", connectTo.String())
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, method, "https://"+target.String()+path, wire)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer response.Body.Close()
	b, e := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if e != nil {
		return nil, e
	}
	if response.StatusCode != 200 || len(b) > 64<<10 {
		return nil, fmt.Errorf("authenticated member HTTPS request failed or response was oversized")
	}
	var value Object
	if e = json.Unmarshal(b, &value, exactIntegers); e != nil {
		return nil, e
	}
	if value == nil {
		return nil, fmt.Errorf("member HTTPS response is not a JSON object")
	}
	return value, nil
}
func MemberReport(statuses []any, spec, member, peer Object, cell, instanceID, artifactSHA string, now time.Time) (Object, error) {
	scope := obj(spec["scope"])
	var status Object
	count := 0
	for _, v := range statuses {
		s := obj(v)
		binding := obj(obj(obj(s["registration"])["managed_member"])["scope"])
		if binding["member_id"] == member["member_id"] {
			status = s
			count++
		}
	}
	if count != 1 {
		return nil, fmt.Errorf("expected member has no unique registered host")
	}
	reg := obj(status["registration"])
	binding := obj(obj(reg["managed_member"])["scope"])
	oci := obj(reg["managed_oci"])
	placement := obj(reg["managed_placement"])
	ok := reg["cell"] == cell && reg["environment"] == "production" && oci["instance_id"] == instanceID && oci["region"] == "GRU" && placement["database_id"] == spec["placement_database_id"] && placement["partition_id"] == spec["partition_id"] && placement["seat_id"] == member["seat_id"] && binding["member_id"] == member["member_id"] && binding["incarnation"] == member["incarnation"]
	for _, k := range []string{"cluster_id", "tenant_id", "database_id", "shard_id"} {
		ok = ok && equal(binding[k], scope[k])
	}
	if !ok {
		return nil, fmt.Errorf("registered host differs from signed placement, instance or member")
	}
	var report Object
	count = 0
	for _, v := range array(status["reports"]) {
		r := obj(v)
		if r["role"] == "terrabase" {
			report = r
			count++
		}
	}
	if count != 1 {
		return nil, fmt.Errorf("expected member has no unique TerraBase report")
	}
	managed := obj(report["managed"])
	proof := obj(managed["serving_proof"])
	rep := obj(proof["replication"])
	observed, e := time.Parse(time.RFC3339Nano, str(report, "observed_at"))
	session, se := time.Parse(time.RFC3339Nano, str(status, "session_expires_at"))
	fresh := e == nil && se == nil && !observed.After(now) && now.Sub(observed) < 30*time.Second && session.After(now)
	ok = fresh && report["cell"] == cell && report["environment"] == reg["environment"] && report["node"] == reg["node"] && report["state"] == "running" && report["digest"] == artifactSHA && equal(managed["member"], reg["managed_member"]) && equal(managed["oci"], oci) && number(managed["process_pid"]) > 1 && managed["storage_recovered"] == true && managed["listener_ready"] == true && proof["serving"] == true && equal(proof["listeners"], Object{"client": true, "replication": true}) && equal(proof["scope"], binding) && equal(proof["authority"], managed["authority"]) && equal(proof["process"], Object{"pid": managed["process_pid"], "start_nonce": managed["process_boot_id"]}) && rep["peer_member_id"] == peer["member_id"] && rep["peer_incarnation"] == peer["incarnation"] && rep["current_authenticated"] == true
	if !ok {
		return nil, fmt.Errorf("current host report lacks the exact running managed process or serving proof")
	}
	return Object{"instance_id": instanceID, "node": report["node"], "observed_at": report["observed_at"], "artifact_sha256": report["digest"], "process_pid": managed["process_pid"], "process_boot_id": managed["process_boot_id"], "member_id": member["member_id"], "serving_proof": proof}, nil
}

type Options struct {
	Operator, Bootstrap, TBBinary, GoQualification, TBQualification                                                      string
	BootstrapBuildReceipt, BootstrapBuildCommand, BootstrapBuildLog, BootstrapTestCommand, BootstrapTestLog              string
	OperatorConfig, Spec, Reply, ControllerKey, RecipientKey, Output                                                     string
	OperatorSHA256, BootstrapSHA256, TBSHA256, GoQualificationSHA256, TBQualificationSHA256, BootstrapBuildReceiptSHA256 string
	GoSourceSHA, TBSourceSHA, InstanceA, InstanceB, CollectionID, Cell                                                   string
	NATSForward, HTTPSForward                                                                                            []string
}

func pause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func fileSize(path string) (int64, error) {
	i, e := os.Stat(path)
	if e != nil {
		return 0, e
	}
	return i.Size(), nil
}
func Scenario(ctx context.Context, o Options, run Runner) (Object, error) {
	if o.Cell != "gru" {
		return nil, fmt.Errorf("M0 OCI caller is scoped to the GRU regional cell")
	}
	goSHA, e := DigestFile(o.Operator, o.OperatorSHA256)
	if e != nil {
		return nil, e
	}
	if e = RequireELF(o.Operator, 62); e != nil {
		return nil, e
	}
	if _, e = DigestFile(o.Bootstrap, o.BootstrapSHA256); e != nil {
		return nil, e
	}
	tbSHA, e := DigestFile(o.TBBinary, o.TBSHA256)
	if e != nil {
		return nil, e
	}
	if e = RequireELF(o.TBBinary, 183); e != nil {
		return nil, e
	}
	if e = RequireStatic(ctx, o.TBBinary, run); e != nil {
		return nil, e
	}
	size, e := fileSize(o.Operator)
	if e != nil {
		return nil, e
	}
	goQ, e := Qualification(o.GoQualification, o.GoQualificationSHA256, "terrascale.release.qualification.v1", "ci.yml", o.GoSourceSHA, "terrascale-orchestrator-linux-amd64", goSHA, size)
	if e != nil {
		return nil, e
	}
	bootstrapReceipt, e := BootstrapProvenance(ctx, o.BootstrapBuildReceipt, o.BootstrapBuildReceiptSHA256, o.Bootstrap, o.BootstrapSHA256, goQ, map[string]string{"build_command": o.BootstrapBuildCommand, "build_log": o.BootstrapBuildLog, "test_command": o.BootstrapTestCommand, "test_log": o.BootstrapTestLog}, run)
	if e != nil {
		return nil, e
	}
	size, e = fileSize(o.TBBinary)
	if e != nil {
		return nil, e
	}
	tbQ, e := Qualification(o.TBQualification, o.TBQualificationSHA256, "terrascale.terrabase.qualification.v2", "fast.yml", o.TBSourceSHA, "tb-server-linux-arm64", tbSHA, size)
	if e != nil {
		return nil, e
	}
	if o.InstanceA == o.InstanceB {
		return nil, fmt.Errorf("two distinct OCI member instances are required")
	}
	spec, e := ReadJSON(o.Spec, 16<<10)
	if e != nil {
		return nil, e
	}
	reply, e := ReadJSON(o.Reply, 64<<10)
	if e != nil {
		return nil, e
	}
	if !equal(obj(reply["receipt"])["spec"], spec) {
		return nil, fmt.Errorf("preparation receipt differs from requested member spec")
	}
	directory, e := os.MkdirTemp("", "ts-m0-customer-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(directory)
	opened, e := OpenCustomerMaterial(ctx, o, bootstrapReceipt, directory+"/opened.json", run)
	if e != nil {
		return nil, e
	}
	token, ca, e := CustomerMaterial(reply, opened)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(ca)) {
		return nil, fmt.Errorf("customer CA is invalid")
	}
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	members := array(spec["members"])
	if len(members) != 2 {
		return nil, fmt.Errorf("signed spec does not contain two members")
	}
	a, b := obj(members[0]), obj(members[1])
	targetA, e := Endpoint(a)
	if e != nil {
		return nil, e
	}
	targetB, e := Endpoint(b)
	if e != nil {
		return nil, e
	}
	if targetA == targetB {
		return nil, fmt.Errorf("signed members share one client endpoint")
	}
	controllers, e := ConfiguredControllers(o.OperatorConfig)
	if e != nil {
		return nil, e
	}
	natsRoutes, e := Forwards(ctx, o.NATSForward, controllers, 4222, false)
	if e != nil {
		return nil, e
	}
	if len(natsRoutes) == 0 {
		return nil, fmt.Errorf("at least one reviewed controller NATS forward is required")
	}
	httpsRoutes, e := Forwards(ctx, o.HTTPSForward, map[netip.AddrPort]bool{targetA: true, targetB: true}, 9465, true)
	if e != nil {
		return nil, e
	}
	for _, n := range natsRoutes {
		for _, h := range httpsRoutes {
			if n == h {
				return nil, fmt.Errorf("controller and member forwards share a local port")
			}
		}
	}
	generation, schemaDigest, e := CatalogBinding(spec, o.CollectionID)
	if e != nil {
		return nil, e
	}
	scope := obj(spec["scope"])
	prefix := fmt.Sprintf("/v1/tenants/%v/databases/%v/shards/%v", scope["tenant_id"], scope["database_id"], scope["shard_id"])
	docID := entityid.New()
	point := prefix + "/collections/" + o.CollectionID + "/documents/" + docID
	before, e := Hosts(ctx, o.Operator, o.OperatorConfig, o.NATSForward, run)
	if e != nil {
		return nil, e
	}
	aBefore, e := MemberReport(before, spec, a, b, o.Cell, o.InstanceA, tbSHA, time.Now())
	if e != nil {
		return nil, e
	}
	bBefore, e := MemberReport(before, spec, b, a, o.Cell, o.InstanceB, tbSHA, time.Now())
	if e != nil {
		return nil, e
	}
	baseSource, e := sequence(obj(obj(aBefore["serving_proof"])["replication"])["local_source_sequence"])
	if e != nil {
		return nil, e
	}
	baseInbox, e := sequence(obj(obj(bBefore["serving_proof"])["replication"])["local_inbox_applied_sequence"])
	if e != nil {
		return nil, e
	}
	absent, e := Request(ctx, targetB, httpsRoutes[targetB], tlsConfig, token, "GET", point, nil)
	if e != nil {
		return nil, e
	}
	if number(absent["version"]) != 1 || absent["state"] != "absent" || !equal(absent["context"], []any{}) || !equal(absent["siblings"], []any{}) {
		return nil, fmt.Errorf("B did not show a fresh absent document before the write")
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	transaction := Object{"version": 1, "transaction_id": Object{"expires_at_unix_ms": strconv.FormatInt(time.Now().UnixMilli()+3600000, 10), "nonce": hex.EncodeToString(nonce[:])}, "writes": []any{Object{"collection": o.CollectionID, "document": docID, "observed": []any{}, "value": Object{"kind": "live", "document": Object{}}}}}
	receipt, e := Request(ctx, targetA, httpsRoutes[targetA], tlsConfig, token, "POST", prefix+"/transactions", transaction)
	if e != nil {
		return nil, e
	}
	if receipt["durability"] != "local_durable" {
		return nil, fmt.Errorf("A did not return a bounded local durable write receipt")
	}
	for _, k := range []string{"received", "applied", "remote_ack"} {
		if _, ok := receipt[k]; ok {
			return nil, fmt.Errorf("A did not return a bounded local durable write receipt")
		}
	}
	var value Object
	deadline := time.Now().Add(90 * time.Second)
	for {
		value, e = Request(ctx, targetB, httpsRoutes[targetB], tlsConfig, token, "GET", point, nil)
		if e != nil {
			return nil, e
		}
		siblings := array(value["siblings"])
		if number(value["version"]) == 1 && value["state"] == "value" && len(siblings) == 1 {
			v := obj(siblings[0])
			if v["kind"] == "live" && equal(v["document"], Object{}) && v["schema_generation"] == strconv.FormatUint(generation, 10) && v["schema_digest"] == schemaDigest {
				break
			}
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("B did not read A's authenticated write")
		}
		if e = pause(ctx, 250*time.Millisecond); e != nil {
			return nil, e
		}
	}
	var aAfter, bAfter Object
	deadline = time.Now().Add(30 * time.Second)
	for {
		after, e := Hosts(ctx, o.Operator, o.OperatorConfig, o.NATSForward, run)
		if e != nil {
			return nil, e
		}
		aAfter, e = MemberReport(after, spec, a, b, o.Cell, o.InstanceA, tbSHA, time.Now())
		if e != nil {
			return nil, e
		}
		bAfter, e = MemberReport(after, spec, b, a, o.Cell, o.InstanceB, tbSHA, time.Now())
		if e != nil {
			return nil, e
		}
		ap, bp := obj(obj(aAfter["serving_proof"])["replication"]), obj(obj(bAfter["serving_proof"])["replication"])
		advanced, err := FrontierAdvanced(ap, bp, baseSource, baseInbox)
		if err != nil {
			return nil, err
		}
		if advanced {
			break
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("current signed reports lack post-write peer ACK frontier")
		}
		if e = pause(ctx, 500*time.Millisecond); e != nil {
			return nil, e
		}
	}
	replyBytes, e := os.ReadFile(o.Reply)
	if e != nil {
		return nil, e
	}
	specBytes, e := os.ReadFile(o.Spec)
	if e != nil {
		return nil, e
	}
	return Object{"result": "scenario_passed", "profile": "m0-oci-real-caller-v1", "scope": "authenticated two-member document write/read and current peer ACK reports", "external_evidence_required": []string{"current signed ARM64 image receipt binding deployed Go binary and OCI image OCID", "retained bootstrap tool binary source and successful qualification manifest", "live OCI image and ownership readback for both member instance IDs", "deployed host Go binary admission and approved private caller route"}, "go_qualification": goQ, "tb_qualification": tbQ, "bootstrap_sha256": o.BootstrapSHA256, "bootstrap_build_receipt": bootstrapReceipt, "material_receipt_sha256": hashBytes(replyBytes), "spec_sha256": hashBytes(specBytes), "customer_ca_sha256": obj(reply["customer"])["https_ca_sha256"], "instances": Object{"a": o.InstanceA, "b": o.InstanceB}, "endpoints": Object{"a": "https://" + targetA.String(), "b": "https://" + targetB.String()}, "document_id": docID, "collection_id": o.CollectionID, "schema_generation": generation, "schema_digest": schemaDigest, "before": Object{"a": aBefore, "b": bBefore, "b_point": absent}, "write_receipt": receipt, "after": Object{"a": aAfter, "b": bAfter, "b_point": value}}, nil
}

type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }
func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	o := Options{}
	fs := flag.NewFlagSet("qualification real-caller", flag.ContinueOnError)
	fs.SetOutput(errOut)
	flags := map[string]*string{"operator": &o.Operator, "bootstrap": &o.Bootstrap, "tb-binary": &o.TBBinary, "go-qualification": &o.GoQualification, "tb-qualification": &o.TBQualification, "bootstrap-build-receipt": &o.BootstrapBuildReceipt, "bootstrap-build-command": &o.BootstrapBuildCommand, "bootstrap-build-log": &o.BootstrapBuildLog, "bootstrap-test-command": &o.BootstrapTestCommand, "bootstrap-test-log": &o.BootstrapTestLog, "operator-config": &o.OperatorConfig, "spec": &o.Spec, "reply": &o.Reply, "controller-key": &o.ControllerKey, "recipient-key": &o.RecipientKey, "output": &o.Output, "operator-sha256": &o.OperatorSHA256, "bootstrap-sha256": &o.BootstrapSHA256, "tb-sha256": &o.TBSHA256, "go-qualification-sha256": &o.GoQualificationSHA256, "tb-qualification-sha256": &o.TBQualificationSHA256, "bootstrap-build-receipt-sha256": &o.BootstrapBuildReceiptSHA256, "go-source-sha": &o.GoSourceSHA, "tb-source-sha": &o.TBSourceSHA, "instance-a": &o.InstanceA, "instance-b": &o.InstanceB, "collection-id": &o.CollectionID, "cell": &o.Cell}
	for k, p := range flags {
		fs.StringVar(p, k, "", "required retained evidence or scenario parameter")
	}
	fs.Var((*repeated)(&o.NATSForward), "nats-forward", "PRIVATE_IP:4222=127.0.0.1:LOCAL_PORT")
	fs.Var((*repeated)(&o.HTTPSForward), "https-forward", "SIGNED_MEMBER_IP:9465=127.0.0.1:LOCAL_PORT")
	if e := fs.Parse(args); e != nil {
		return 2
	}
	for k, p := range flags {
		if *p == "" {
			fmt.Fprintf(errOut, "--%s is required\n", k)
			return 2
		}
	}
	if fs.NArg() != 0 {
		return 2
	}
	if _, e := os.Lstat(o.Output); e == nil || !os.IsNotExist(e) {
		fmt.Fprintln(errOut, "output path must not already exist")
		return 2
	}
	evidence, e := Scenario(ctx, o, Execute)
	if e == nil {
		var b []byte
		b, e = json.Marshal(evidence, json.Deterministic(true), jsontext.Multiline(true), jsontext.WithIndent("  "))
		if e == nil {
			var f *os.File
			f, e = os.OpenFile(o.Output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e == nil {
				_, e = f.Write(append(b, '\n'))
				if ce := f.Close(); e == nil {
					e = ce
				}
			}
		}
	}
	if e != nil {
		fmt.Fprintln(errOut, "M0 OCI real caller failed")
		return 1
	}
	fmt.Fprintf(out, "M0 OCI document scenario passed; evidence=%s\n", o.Output)
	return 0
}
