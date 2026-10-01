package runtimepriority

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type boundedOutput struct {
	mu sync.Mutex
	bytes.Buffer
	maximum  int
	exceeded bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Len()+len(p) > b.maximum {
		b.exceeded = true
		return 0, fmt.Errorf("command output exceeded fixed evidence bound")
	}
	return b.Buffer.Write(p)
}
func RunBounded(ctx context.Context, argv []string, input []byte, timeout time.Duration, maximum int) ([]byte, error) {
	childCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	cmd := exec.CommandContext(childCtx, argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	}
	cmd.WaitDelay = time.Second
	out := &boundedOutput{maximum: maximum}
	stderr := &boundedOutput{maximum: maximum}
	cmd.Stdout, cmd.Stderr = out, stderr
	if e := cmd.Run(); e != nil {
		return nil, fmt.Errorf("bounded command failed: %w", e)
	}
	if out.exceeded || stderr.exceeded || out.Len()+stderr.Len() > maximum {
		return nil, fmt.Errorf("command output exceeds fixed evidence bound")
	}
	return bytes.Clone(out.Bytes()), nil
}
func VerifyTransport(request Object) (err error) {
	defer recoverError(&err)
	t := sub(request, "transport")
	for _, key := range []string{"operator", "ssh"} {
		o := sub(t, key)
		verifyPin(str(o, "executable_path"), str(o, "executable_sha256"), key+" executable", true)
	}
	o := sub(t, "operator")
	verifyPin(str(o, "config_path"), str(o, "config_sha256"), "operator hosts config", false)
	for label, v := range sub(sub(t, "ssh"), "targets") {
		target := obj(v, "SSH target")
		verifyPin(str(target, "known_hosts_path"), str(target, "known_hosts_sha256"), label+" SSH known_hosts", false)
		privateFile(str(target, "identity_file_path"), label+" SSH identity")
	}
	https := sub(t, "https")
	verifyPin(str(https, "ca_bundle_path"), str(https, "ca_bundle_sha256"), "TLS CA bundle", false)
	for _, label := range []string{"source", "peer"} {
		privateFile(str(https, label+"_credential_file"), label+" HTTPS credential")
	}
	verifyPin(str(request, "adapter_source_path"), str(request, "adapter_source_sha256"), "adapter binary", true)
	return
}

// Adapter transports immutable requests; all evidence is checked by Runner.
type Adapter struct {
	SSH           func(context.Context, Object, string, string, Object) (Object, error)
	HTTPS         func(context.Context, Object, string, string, string, []byte) ([]byte, error)
	OperatorHosts func(context.Context, Object) (string, error)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func (a *Adapter) ssh(ctx context.Context, request Object, label, action string, payload Object) (Object, error) {
	if a.SSH != nil {
		return a.SSH(ctx, request, label, action, payload)
	}
	transport := sub(request, "transport")
	target := sub(sub(sub(transport, "ssh"), "targets"), label)
	runtime := sub(transport, "runtime")
	remote := clone(request)
	if payload == nil {
		payload = Object{}
	}
	remote["remote_payload"] = payload
	wire := Canonical(remote)
	if len(wire) > 1<<20 {
		return nil, &DomainError{"HarnessError", "SSH helper input exceeds fixed bound"}
	}
	remoteArgs := []string{str(runtime, "sudo_path"), "-n", "--", str(runtime, "qualify_path"), "runtime-priority", "remote", action, "--probe-source-revision", str(request, "probe_source_revision"), "--probe-sha256", str(runtime, "qualify_sha256")}
	for i, s := range remoteArgs {
		remoteArgs[i] = shellQuote(s)
	}
	argv := []string{str(sub(transport, "ssh"), "executable_path"), "-F", "/dev/null", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oUpdateHostKeys=no", "-oUserKnownHostsFile=" + str(target, "known_hosts_path"), "-oGlobalKnownHostsFile=/dev/null", "-oCheckHostIP=no", "-oVerifyHostKeyDNS=no", "-oHostKeyAlias=" + str(target, "host_key_alias"), "-oIdentitiesOnly=yes", "-oIdentityAgent=none", "-oClearAllForwardings=yes", "-oPasswordAuthentication=no", "-oKbdInteractiveAuthentication=no", "-oProxyCommand=none", "-oConnectTimeout=10", "-i", str(target, "identity_file_path"), "-p", strconv.FormatInt(n(target, "port"), 10), str(target, "user") + "@" + str(target, "address"), strings.Join(remoteArgs, " ")}
	raw, e := RunBounded(ctx, argv, wire, time.Duration(n(request, "deadline_seconds"))*time.Second, 1<<20)
	if e != nil {
		return nil, e
	}
	var result Object
	if e := jsonUnmarshal(raw, &result); e != nil {
		return nil, &DomainError{"HarnessError", "remote pinned action returned invalid JSON"}
	}
	return result, nil
}
func (a *Adapter) operator(ctx context.Context, request Object) (string, error) {
	if a.OperatorHosts != nil {
		return a.OperatorHosts(ctx, request)
	}
	o := sub(sub(request, "transport"), "operator")
	raw, e := RunBounded(ctx, []string{str(o, "executable_path"), "operator", "hosts", "--config", str(o, "config_path")}, nil, time.Duration(n(request, "deadline_seconds"))*time.Second, 1<<20)
	if e != nil {
		return "", e
	}
	var rows []Object
	if e := jsonUnmarshal(raw, &rows); e != nil {
		return "", &DomainError{"HarnessError", "operator hosts did not return raw HostStatus JSON array"}
	}
	return string(raw), nil
}
func HTTPSRequest(ctx context.Context, request Object, label, method, path string, body []byte) (result []byte, err error) {
	defer recoverError(&err)
	h := sub(sub(request, "transport"), "https")
	endpoint := text(h[label+"_base_url"], "HTTPS origin")
	validateHTTPS(endpoint, "HTTPS origin")
	u, e := url.Parse(endpoint)
	if e != nil {
		return nil, e
	}
	ca, _, e := readNoFollow(str(h, "ca_bundle_path"), 16<<20)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		fail("TLS CA bundle has no certificates")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Duration(n(request, "deadline_seconds")) * time.Second}, Config: &tls.Config{RootCAs: roots, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}}
	connection, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if e != nil {
		return nil, &DomainError{"HarnessError", "HTTPS request failed with verified TLS"}
	}
	defer connection.Close()
	tlsConn, ok := connection.(*tls.Conn)
	if !ok {
		fail("HTTPS connection lost verified TLS socket")
	}
	state := tlsConn.ConnectionState()
	pin := str(sub(sub(sub(request, "managed_member"), label), "authority"), "tls_leaf_sha256")
	if len(state.PeerCertificates) == 0 || Hash(state.PeerCertificates[0].Raw) != pin {
		fail("%s HTTPS peer certificate differs from its member authority pin", label)
	}
	credential := str(h, label+"_credential_file")
	privateFile(credential, "HTTPS API credential")
	token := strings.TrimSpace(readText(credential, 65536))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		fail("HTTPS API credential file must contain one private bearer token")
	}
	target := u.Clone()
	target.Path = path
	req, e := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "close")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	deadline := time.Now().Add(time.Duration(n(request, "deadline_seconds")) * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = minTime(deadline, d)
	}
	connection.SetDeadline(deadline)
	if e := req.Write(connection); e != nil {
		return nil, e
	}
	reply, e := http.ReadResponse(bufio.NewReader(connection), req)
	if e != nil {
		return nil, e
	}
	defer reply.Body.Close()
	media, _, _ := strings.Cut(reply.Header.Get("Content-Type"), ";")
	if reply.StatusCode != 200 || media != "application/json" {
		fail("%s HTTPS data request did not return JSON HTTP 200", label)
	}
	if reply.ContentLength > 65536 {
		fail("HTTPS response exceeds evidence bound")
	}
	result, e = io.ReadAll(io.LimitReader(reply.Body, 65537))
	if e != nil {
		return nil, e
	}
	if len(result) > 65536 {
		fail("HTTPS response exceeds evidence bound")
	}
	return
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (a *Adapter) https(ctx context.Context, request Object, label, method, path string, body []byte) ([]byte, error) {
	if a.HTTPS != nil {
		return a.HTTPS(ctx, request, label, method, path, body)
	}
	return HTTPSRequest(ctx, request, label, method, path, body)
}
func (a *Adapter) Dispatch(ctx context.Context, request Object) (result Object, err error) {
	defer recoverError(&err)
	role := str(request, "role")
	if role == "service_state" || role == "qualify" {
		label := "source"
		if str(request, "guest_role") == "controller" {
			label = "controller"
		}
		reply, e := a.ssh(ctx, request, label, role, nil)
		if e != nil {
			return nil, e
		}
		if role == "service_state" {
			if !exact(reply, "guest_role", "units", "host_boot_id") {
				fail("remote service state unexpected evidence shape")
			}
			return reply, nil
		}
		summary := sub(reply, "summary")
		commands := text(reply["commands_log"], "qualifier commands log")
		return Object{"summary": summary, "probe_evidence": Object{"fresh_for_request_id": request["request_id"], "summary_sha256": Hash(pretty(summary)), "commands_log": commands, "commands_sha256": Hash([]byte(commands))}}, nil
	}
	if role == "target_identity" || role == "host_status" {
		raw, e := a.operator(ctx, request)
		if e != nil {
			return nil, e
		}
		hostsValue := rawJSON(raw, "operator hosts JSON", "", 1<<20)
		hosts, ok := hostsValue.([]any)
		if !ok {
			fail("operator hosts output must be actual HostStatus JSON array")
		}
		member := sub(request, "managed_member")
		rows := Object{}
		for _, label := range []string{"source", "peer"} {
			want := sub(member, label)
			matches := 0
			for _, v := range hosts {
				host := obj(v, "host status")
				reg, ok := host["registration"].(map[string]any)
				if !ok {
					continue
				}
				binding, ok := reg["managed_member"].(map[string]any)
				if ok && reg["cell"] == want["cell"] && reg["node"] == want["node"] && reg["environment"] == want["environment"] && same(binding["scope"], want["scope"]) {
					if sub(reg, "managed_oci")["instance_id"] != sub(sub(sub(sub(request, "transport"), "ssh"), "targets"), label)["oci_instance_id"] {
						fail("operator HostStatus does not bind pinned OCI instance")
					}
					rows[label] = host
					matches++
				}
			}
			if matches != 1 {
				fail("operator hosts returned %d exact %s registrations", matches, label)
			}
		}
		result = Object{"operator_hosts_json": raw, "operator_hosts_sha256": Hash([]byte(raw))}
		if role == "target_identity" {
			architectures := Object{}
			for _, label := range []string{"source", "peer", "controller"} {
				reply, e := a.ssh(ctx, request, label, "uname", nil)
				if e != nil {
					return nil, e
				}
				architectures[label] = reply["architecture"]
			}
			result["architecture_by_member"] = architectures
			for _, label := range []string{"source", "controller"} {
				reply, e := a.ssh(ctx, request, label, "oci_metadata", nil)
				if e != nil {
					return nil, e
				}
				result[label+"_oci_metadata"] = reply["oci_metadata"]
			}
			return
		}
		witnesses := Object{}
		for _, label := range []string{"source", "peer"} {
			want := sub(member, label)
			reports := array(sub(rows, label)["reports"], "operator HostStatus reports")
			var report Object
			count := 0
			for _, v := range reports {
				o := obj(v, "report")
				if o["cell"] == want["cell"] && o["node"] == want["node"] && o["environment"] == want["environment"] && o["role"] == want["role"] {
					report = o
					count++
				}
			}
			if count != 1 {
				fail("operator hosts omitted exact managed report")
			}
			pid := num(sub(report, "managed")["process_pid"], "process PID", 2)
			reply, e := a.ssh(ctx, request, label, "proc_witness", Object{"pid": pid})
			if e != nil {
				return nil, e
			}
			witnesses[label] = reply
		}
		result["process_witnesses"] = witnesses
		return
	}
	if role == "database_progress" {
		scope, document := sub(sub(sub(request, "managed_member"), "source"), "scope"), sub(sub(request, "managed_member"), "document")
		prefix := fmt.Sprintf("/v1/tenants/%s/databases/%s/shards/%d", str(scope, "tenant_id"), str(scope, "database_id"), n(scope, "shard_id"))
		writePath := prefix + "/transactions"
		readPath := fmt.Sprintf("%s/collections/%s/documents/%s", prefix, str(document, "collection_id"), str(request, "document_id"))
		write := Object{"version": 1, "transaction_id": request["transaction_id"], "writes": []Object{{"collection": document["collection_id"], "document": request["document_id"], "schema_generation": strconv.FormatInt(n(document, "schema_generation"), 10), "schema_digest": document["schema_digest"], "observed": []any{}, "value": Object{"kind": "live", "fields": []Object{{"id": document["field_id"], "value": Object{"type": "i64", "value": strconv.FormatInt(n(request, "value"), 10)}}}}}}}
		raw := Canonical(write)
		started := time.Now()
		receipt, e := a.https(ctx, request, "source", "POST", writePath, raw)
		if e != nil {
			return nil, e
		}
		point, e := a.https(ctx, request, "peer", "GET", readPath, nil)
		if e != nil {
			return nil, e
		}
		elapsed := time.Since(started).Milliseconds()
		if elapsed > n(request, "deadline_seconds")*1000 {
			fail("ObjectDurable write and peer read exceeded pinned deadline")
		}
		return Object{"write_path": writePath, "peer_read_path": readPath, "document_id": request["document_id"], "transaction_request_raw": string(raw), "transaction_request_sha256": Hash(raw), "write_receipt_raw": string(receipt), "write_receipt_sha256": Hash(receipt), "peer_read_raw": string(point), "peer_read_sha256": Hash(point), "operation_elapsed_ms": elapsed}, nil
	}
	action := role
	if role == "kernel_oom_evidence" {
		action = "oom_collect"
		if str(request, "phase") == "before" {
			action = "oom_watermark"
		} else if request["wait_for_event"] == true {
			action = "oom_fault"
		}
	}
	switch action {
	case "pressure_start", "pressure_status", "pressure_stop", "cleanup_verify", "failure_inject", "oom_collect", "oom_watermark", "oom_fault":
		return a.ssh(ctx, request, "source", action, nil)
	default:
		fail("alpha adapter received unsupported role")
	}
	return
}
func OpenPinnedProbe(base, source, hash, path string, owner uint32) (file *os.File, err error) {
	defer recoverError(&err)
	if !gitRE.MatchString(source) || !hashRE.MatchString(hash) {
		fail("D15 probe lacks full source and digest pin")
	}
	expected := filepath.Join(base, "probes", source, hash, "qualify")
	if path != expected {
		fail("D15 probe path differs from exact temporary staging pin")
	}
	for _, dir := range []string{base, filepath.Join(base, "probes"), filepath.Join(base, "probes", source), filepath.Dir(path)} {
		m, e := os.Lstat(dir)
		if e != nil {
			return nil, e
		}
		st := m.Sys().(*syscall.Stat_t)
		if !m.IsDir() || st.Uid != owner || st.Gid != owner || m.Mode().Perm() != 0700 {
			fail("D15 probe staging directory not root-owned mode 0700")
		}
	}
	b, m, e := readNoFollow(path, MaxProbeBytes)
	if e != nil {
		fail("D15 probe is not bounded root-owned regular mode-0555 file: %v", e)
	}
	st := m.Sys().(*syscall.Stat_t)
	if m.Mode().Perm() != 0555 || st.Uid != owner || st.Gid != owner || st.Nlink != 1 || len(b) == 0 {
		fail("D15 probe is not a bounded root-owned regular mode-0555 file")
	}
	if Hash(b) != hash {
		fail("D15 probe bytes differ from the exact CI digest pin")
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	file = os.NewFile(uintptr(fd), path)
	opened, e := file.Stat()
	if e != nil || !os.SameFile(m, opened) {
		file.Close()
		fail("D15 probe changed between path and descriptor inspection")
	}
	return
}
