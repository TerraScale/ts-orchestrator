package runtimepriority

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
)

func rawJSON(raw, label, hash string, max int) any {
	if len(raw) > max {
		fail("%s exceeds its %d-byte evidence bound", label, max)
	}
	if hash != "" && (!hashRE.MatchString(hash) || Hash([]byte(raw)) != hash) {
		fail("%s hash absent or does not match retained bytes", label)
	}
	var value any
	if e := jsonUnmarshal([]byte(raw), &value); e != nil {
		fail("%s invalid JSON: %v", label, e)
	}
	return value
}
func cgroupFilePath(path string) string {
	if !safePath(path) || path == "/" || inside(path, CgroupRoot) {
		fail("managed report process_cgroup is not a safe cgroup-root-relative path")
	}
	return filepath.Join(CgroupRoot, path)
}
func QualifiedRoleCgroups(nativeReport, databaseReport string) (native, database, role string, err error) {
	defer recoverError(&err)
	native, database, role = qualifiedRoleCgroups(nativeReport, databaseReport)
	return
}
func qualifiedRoleCgroups(nativeReport, databaseReport string) (string, string, string) {
	if !safePath(nativeReport) || !inside(nativeReport, CgroupRoot) {
		fail("qualifier native runner cgroup is not safely below the cgroup root")
	}
	database := cgroupFilePath(databaseReport)
	rel, e := filepath.Rel(nativeReport, database)
	if e != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		fail("TerraBase cgroup is not below measured native runner")
	}
	if rel == "." || strings.Contains(rel, "/") {
		fail("TerraBase cgroup must be a direct native role child")
	}
	return nativeReport, database, rel
}
func validateProof(report, member Object, label string) Object {
	managed := sub(report, "managed")
	proof := sub(managed, "serving_proof")
	if !exact(proof, "schema_version", "nonce", "process", "scope", "authority", "serving", "listeners", "object", "replication") || n(proof, "schema_version") != 1 {
		fail("%s ServingProof must be alpha wire version 1 shape", label)
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(str(proof, "nonce")) {
		fail("%s ServingProof nonce malformed", label)
	}
	process, scope, authority, listeners, ob, rep := sub(proof, "process"), sub(proof, "scope"), sub(proof, "authority"), sub(proof, "listeners"), sub(proof, "object"), sub(proof, "replication")
	if !exact(process, "pid", "start_nonce") || !exact(listeners, "client", "replication") || !same(scope, member["scope"]) || !same(authority, member["authority"]) {
		fail("%s ServingProof process/scope/authority fields differ from alpha wire", label)
	}
	// TerraBase releases before the received prefixes omit both of them.
	frontiers := []string{"local_source_sequence", "peer_durable_sequence", "peer_applied_sequence", "local_inbox_durable_sequence", "local_inbox_applied_sequence"}
	_, received := rep["peer_received_sequence"]
	if received {
		frontiers = append(frontiers, "peer_received_sequence", "local_inbox_received_sequence")
	}
	if !exact(ob, "root_sha256", "target_sha256", "native_commit_seq_at_recovery", "inbox_archive_sha256_at_recovery", "local_source_sequence", "remote_inbox_durable_sequence", "remote_applied_sequence") || !exact(rep, append([]string{"peer_member_id", "peer_incarnation", "current_authenticated"}, frontiers...)...) {
		fail("%s ServingProof frontier fields differ from alpha v1", label)
	}
	if !same(process["pid"], managed["process_pid"]) || process["start_nonce"] != managed["process_boot_id"] || !same(sub(managed, "member")["scope"], member["scope"]) || !same(managed["authority"], member["authority"]) {
		fail("%s ServingProof does not match accepted host managed report", label)
	}
	if proof["serving"] != true || listeners["client"] != true || listeners["replication"] != true {
		fail("%s ServingProof does not assert serving client and replication listeners", label)
	}
	for _, k := range []string{"root_sha256", "target_sha256", "inbox_archive_sha256_at_recovery"} {
		if !hashRE.MatchString(str(ob, k)) {
			fail("%s ServingProof object.%s not lowercase SHA-256", label, k)
		}
	}
	for _, k := range []string{"native_commit_seq_at_recovery", "local_source_sequence", "remote_inbox_durable_sequence", "remote_applied_sequence"} {
		num(ob[k], label+" ServingProof object."+k, 0)
	}
	for _, k := range frontiers {
		num(rep[k], label+" ServingProof replication."+k, 0)
	}
	if _, ok := rep["current_authenticated"].(bool); !ok {
		fail("ServingProof authentication flag must be boolean")
	}
	if !same(rep["local_source_sequence"], ob["local_source_sequence"]) || n(ob, "remote_applied_sequence") > n(ob, "remote_inbox_durable_sequence") || n(rep, "peer_applied_sequence") > n(rep, "peer_durable_sequence") || n(rep, "local_inbox_applied_sequence") > n(rep, "local_inbox_durable_sequence") ||
		received && (n(rep, "peer_received_sequence") < n(rep, "peer_durable_sequence") || n(rep, "local_inbox_received_sequence") < n(rep, "local_inbox_durable_sequence")) {
		fail("%s ServingProof contains inconsistent alpha v1 frontier", label)
	}
	return proof
}
func ValidateDatabaseWire(evidence, request, member Object) (result Object, err error) {
	defer recoverError(&err)
	scope, document := sub(sub(member, "source"), "scope"), sub(member, "document")
	prefix := fmt.Sprintf("/v1/tenants/%s/databases/%s/shards/%d", str(scope, "tenant_id"), str(scope, "database_id"), n(scope, "shard_id"))
	if str(evidence, "write_path") != prefix+"/transactions" || str(evidence, "peer_read_path") != fmt.Sprintf("%s/collections/%s/documents/%s", prefix, str(document, "collection_id"), str(request, "document_id")) {
		fail("database adapter did not use exact alpha transaction and cross-member point routes")
	}
	if evidence["document_id"] != request["document_id"] {
		fail("database adapter read different document than transaction operation")
	}
	transaction := obj(rawJSON(text(evidence["transaction_request_raw"], "transaction request"), "database transaction request", str(evidence, "transaction_request_sha256"), 65536), "transaction request")
	writes, ok := transaction["writes"].([]any)
	if !exact(transaction, "version", "transaction_id", "writes") || n(transaction, "version") != 1 || !same(transaction["transaction_id"], request["transaction_id"]) || !ok || len(writes) != 1 {
		fail("transaction request does not match alpha v1 document write request")
	}
	expectedDocument := Object{str(document, "utf8_field"): strconv.FormatInt(n(request, "value"), 10)}
	expected := Object{"collection": document["collection_id"], "document": request["document_id"], "observed": []any{}, "value": Object{"kind": "live", "document": expectedDocument}}
	if !same(writes[0], expected) {
		fail("transaction request bytes do not bind exact scoped document and value")
	}
	receipt := obj(rawJSON(text(evidence["write_receipt_raw"], "write receipt"), "database write receipt", str(evidence, "write_receipt_sha256"), 65536), "write receipt")
	if !exact(receipt, "version", "durability", "transaction_id", "event", "commit_sequence") {
		fail("write receipt does not match alpha transaction ACK shape")
	}
	if n(receipt, "version") != 1 || str(receipt, "durability") != "object_durable" {
		fail("write receipt did not acknowledge ObjectDurable")
	}
	if !same(receipt["transaction_id"], request["transaction_id"]) {
		fail("ObjectDurable receipt transaction ID differs from exact write request")
	}
	commit := str(receipt, "commit_sequence")
	if !decimalRE.MatchString(commit) {
		fail("ObjectDurable commit_sequence must remain opaque decimal string")
	}
	event := sub(receipt, "event")
	if !exact(event, "database", "shard", "replica", "incarnation", "sequence") {
		fail("receipt event does not match alpha scoped event identity")
	}
	for k, want := range (Object{"database": scope["database_id"], "shard": strconv.FormatInt(n(scope, "shard_id"), 10), "replica": scope["member_id"], "incarnation": scope["incarnation"]}) {
		if event[k] != want {
			fail("ObjectDurable receipt event scope/origin differs from signed source member")
		}
	}
	sequence := integerText(text(event["sequence"], "ObjectDurable event sequence"), "ObjectDurable event sequence")
	if sequence < 1 {
		fail("ObjectDurable event.sequence must be positive decimal string")
	}
	point := obj(rawJSON(text(evidence["peer_read_raw"], "peer read"), "peer point read", str(evidence, "peer_read_sha256"), 65536), "peer point read")
	siblings, ok := point["siblings"].([]any)
	if n(point, "version") != 1 || str(point, "state") != "value" || !ok {
		fail("cross-member point read did not return alpha value point")
	}
	matches := 0
	for _, v := range siblings {
		s, ok := v.(map[string]any)
		if !ok || !same(s["event"], event) {
			continue
		}
		if str(s, "kind") != "live" || str(s, "schema_generation") != strconv.FormatInt(n(document, "schema_generation"), 10) || s["schema_digest"] != document["schema_digest"] || !same(s["document"], expectedDocument) {
			fail("peer read event matches receipt but document schema/value does not")
		}
		matches++
	}
	if matches != 1 {
		fail("peer read does not contain exactly one sibling matching the ObjectDurable event")
	}
	return Object{"receipt": receipt, "event": event, "point": point, "event_sequence": sequence, "commit_sequence_opaque": commit}, nil
}
func reportTime(o Object, key string) time.Time {
	switch v := o[key].(type) {
	case time.Time:
		return v
	case string:
		return timestamp(v, key)
	case map[string]any:
		return timestamp(v["$datetime"], key)
	default:
		fail("missing %s timestamp", key)
	}
	return time.Time{}
}
func ValidateReportEvidence(evidence, request Object, observed string, member, previous Object) (result Object, err error) {
	defer recoverError(&err)
	hosts, ok := rawJSON(text(evidence["operator_hosts_json"], "operator hosts JSON"), "operator hosts JSON", str(evidence, "operator_hosts_sha256"), 1<<20).([]any)
	if !ok {
		fail("operator hosts output must be actual HostStatus JSON array")
	}
	sampled := timestamp(observed, "operator hosts observation time")
	witnesses := sub(evidence, "process_witnesses")
	if !exact(witnesses, "source", "peer") {
		fail("operator hosts adapter must witness both managed member processes")
	}
	selected := Object{}
	for _, label := range []string{"source", "peer"} {
		expected := sub(member, label)
		var host Object
		matches := 0
		for _, v := range hosts {
			row := obj(v, "HostStatus")
			registration, ok := row["registration"].(map[string]any)
			if !ok {
				continue
			}
			binding, ok := registration["managed_member"].(map[string]any)
			if ok && registration["cell"] == expected["cell"] && registration["node"] == expected["node"] && registration["environment"] == expected["environment"] && same(binding["scope"], expected["scope"]) {
				matches++
				host = row
			}
		}
		if matches != 1 {
			fail("operator hosts output has %d exact %s registrations", matches, label)
		}
		if host["verified"] != false {
			fail("read-only operator HostStatus.verified must remain false")
		}
		registration := sub(host, "registration")
		expires := timestamp(host["session_expires_at"], label+" session expiry")
		if !expires.After(sampled) {
			fail("%s host session expired at observation time", label)
		}
		reports, ok := host["reports"].([]any)
		if !ok {
			fail("%s HostStatus.reports not array", label)
		}
		var report Object
		matches = 0
		for _, v := range reports {
			r, ok := v.(map[string]any)
			if ok && r["cell"] == expected["cell"] && r["node"] == expected["node"] && r["environment"] == expected["environment"] && r["role"] == expected["role"] {
				report = r
				matches++
			}
		}
		if matches != 1 {
			fail("%s HostStatus does not contain one exact managed-role report", label)
		}
		when := timestamp(report["observed_at"], label+" report.observed_at")
		age := sampled.Sub(when)
		if age < -2*time.Second || age >= 30*time.Second {
			fail("%s accepted report is future-dated or at least 30 seconds old", label)
		}
		old, _ := previous[label].(map[string]any)
		if old != nil && !when.After(reportTime(old, "report_time")) {
			fail("%s report observed_at did not strictly advance", label)
		}
		if str(report, "state") != "running" {
			fail("%s actual report state=%q error=%v", label, str(report, "state"), report["error"])
		}
		num(report["generation"], label+" report generation", 1)
		num(registration["generation"], label+" registration generation", 1)
		num(report["epoch"], label+" report epoch", 1)
		if !hashRE.MatchString(str(report, "digest")) || str(report, "session_id") == "" {
			fail("%s report lacks accepted desired/session identity", label)
		}
		if old != nil {
			if !same(registration["generation"], old["registration_generation"]) || !same(report["generation"], old["generation"]) || report["digest"] != old["digest"] {
				fail("%s registration or desired report identity changed during D15", label)
			}
			restart := label == "source" && str(sub(request, "pressure"), "scenario") == "host_manager_sigkill" && str(request, "phase") == "post_recovery"
			if !restart && (report["session_id"] != old["session_id"] || !same(report["epoch"], old["epoch"])) {
				fail("%s host session identity changed without host-manager restart", label)
			}
		}
		managed := sub(report, "managed")
		binding, registered := sub(managed, "member"), sub(registration, "managed_member")
		if !exact(binding, "scope", "host_attempt") || !exact(registered, "scope", "host_attempt") || !same(binding["scope"], expected["scope"]) || !same(registered["scope"], expected["scope"]) || !same(binding["host_attempt"], registered["host_attempt"]) || !same(managed["authority"], expected["authority"]) || str(managed, "process_start") == "" || !entityid.Valid(str(managed, "process_boot_id")) || managed["storage_recovered"] != true || managed["listener_ready"] != true {
			fail("%s accepted managed report lacks exact process/mount readiness", label)
		}
		num(binding["host_attempt"], "host attempt", 1)
		num(managed["process_pid"], "managed process PID", 2)
		proof := validateProof(report, expected, label)
		w := sub(witnesses, label)
		if !exact(w, "pid", "stat_raw", "cgroup_raw", "host_boot_id") {
			fail("%s raw process witness has unexpected fields", label)
		}
		pid, start := procStatIdentity(text(w["stat_raw"], "process stat witness"))
		group := procCgroupPath(text(w["cgroup_raw"], "process cgroup witness"))
		if n(w, "pid") != n(managed, "process_pid") || pid != n(w, "pid") || start != str(managed, "process_start") || filepath.Join(CgroupRoot, group) != cgroupFilePath(str(managed, "process_cgroup")) {
			fail("%s raw process witness differs from accepted managed report", label)
		}
		boot := str(w, "host_boot_id")
		if !uuidRE.MatchString(boot) {
			fail("%s host boot ID not canonical UUID", label)
		}
		identity := Object{"pid": managed["process_pid"], "start": managed["process_start"], "nonce": managed["process_boot_id"], "cgroup": managed["process_cgroup"]}
		if old != nil {
			oldID := sub(old, "managed_identity")
			phase, scenario := str(request, "phase"), str(sub(request, "pressure"), "scenario")
			mayRestart := label == "source" && (phase == "post_recovery" || phase == "after" || phase == "after_write") && (scenario == "terrabase_process" || scenario == "terrabase_oom")
			if !mayRestart && (!same(oldID["pid"], identity["pid"]) || oldID["start"] != identity["start"] || oldID["nonce"] != identity["nonce"]) {
				fail("%s managed process identity changed outside recovery scenario", label)
			}
			if boot != str(old, "host_boot_id") {
				fail("%s host boot ID changed during pressure scenario", label)
			}
		}
		selected[label] = Object{"host": host, "report": report, "proof": proof, "report_time": when, "session_expires_at": expires, "verified": false, "registration_generation": registration["generation"], "generation": report["generation"], "digest": report["digest"], "session_id": report["session_id"], "epoch": report["epoch"], "managed_identity": identity, "host_boot_id": boot}
	}
	return Object{"raw": hosts, "members": selected, "process_witnesses": witnesses}, nil
}
func assertEventCovered(snapshot, member, event Object, sequence int64) {
	members := sub(snapshot, "members")
	source, peer := sub(sub(sub(members, "source"), "proof"), "replication"), sub(sub(sub(members, "peer"), "proof"), "replication")
	ss, ps := sub(sub(member, "source"), "scope"), sub(sub(member, "peer"), "scope")
	if source["peer_member_id"] != ps["member_id"] || source["peer_incarnation"] != ps["incarnation"] || source["current_authenticated"] != true || n(source, "local_source_sequence") < sequence || n(source, "peer_durable_sequence") < sequence || n(source, "peer_applied_sequence") < sequence {
		fail("source ServingProof v1 does not durably/applied-cover matching event origin")
	}
	if peer["peer_member_id"] != ss["member_id"] || peer["peer_incarnation"] != ss["incarnation"] || peer["current_authenticated"] != true || n(peer, "local_inbox_durable_sequence") < sequence || n(peer, "local_inbox_applied_sequence") < sequence {
		fail("peer ServingProof v1 lacks matching durable/applied inbox coverage")
	}
}
