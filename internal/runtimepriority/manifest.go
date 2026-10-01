package runtimepriority

import (
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var identityKeys = []string{"oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id", "architecture", "cell", "environment"}
var qualificationKeys = []string{"expected_memory_min_bytes", "expected_memory_low_bytes", "expected_controller_memory_min_bytes", "expected_controller_memory_low_bytes", "expected_system_slice_memory_min_bytes", "expected_system_slice_memory_low_bytes", "system_reserve_bytes", "allocatable_memory_bytes", "database_memory_max_bytes"}
var controllerKeys = []string{"expected_controller_memory_min_bytes", "expected_controller_memory_low_bytes", "expected_system_slice_memory_min_bytes", "expected_system_slice_memory_low_bytes", "system_reserve_bytes", "allocatable_memory_bytes"}
var baseRoles = []string{"target_identity", "qualify", "host_status", "database_progress", "service_state", "pressure_start", "pressure_status", "pressure_stop", "cleanup_verify"}
var instanceRE = regexp.MustCompile(`^ocid1\.instance\.oc1\.[A-Za-z0-9._-]{16,}$`)
var imageRE = regexp.MustCompile(`^ocid1\.image\.oc1\.[A-Za-z0-9._-]{16,}$`)

func validateScope(v any, label string) Object {
	o := obj(v, label)
	if !exact(o, "cluster_id", "tenant_id", "database_id", "shard_id", "member_id", "incarnation") {
		fail("%s must contain exactly the alpha member scope fields", label)
	}
	for _, k := range []string{"cluster_id", "incarnation"} {
		if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(str(o, k)) {
			fail("%s.%s must be 32 lowercase hexadecimal characters", label, k)
		}
	}
	for _, k := range []string{"tenant_id", "database_id", "member_id"} {
		if !uuidRE.MatchString(str(o, k)) {
			fail("%s.%s must be a canonical lowercase UUID", label, k)
		}
	}
	num(o["shard_id"], label+".shard_id", 1)
	return o
}
func validateAuthority(v any, label string) Object {
	o := obj(v, label)
	if !exact(o, "epoch", "configuration_id", "certificate_sha256", "tls_leaf_sha256") {
		fail("%s must contain exactly the alpha authority fields", label)
	}
	num(o["epoch"], label+".epoch", 1)
	for _, k := range []string{"configuration_id", "certificate_sha256", "tls_leaf_sha256"} {
		if !hashRE.MatchString(str(o, k)) {
			fail("%s.%s must be a lowercase SHA-256 digest", label, k)
		}
	}
	return o
}
func validateManaged(v any) Object {
	m := obj(v, "managed_member")
	if !exact(m, "source", "peer", "document", "acknowledgment_profile") || str(m, "acknowledgment_profile") != "object_durable" {
		fail("managed_member fields must pin source, peer, document, and ObjectDurable acknowledgment_profile")
	}
	for _, label := range []string{"source", "peer"} {
		row := sub(m, label)
		if !exact(row, "cell", "node", "environment", "role", "scope", "authority") {
			fail("managed_member.%s fields do not match alpha host report", label)
		}
		for _, k := range []string{"cell", "node", "environment", "role"} {
			text(row[k], "managed_member."+label+"."+k)
		}
		if str(row, "role") != "terrabase" {
			fail("managed_member.%s.role must be terrabase", label)
		}
		validateScope(row["scope"], label+".scope")
		validateAuthority(row["authority"], label+".authority")
	}
	a, b := sub(m, "source"), sub(m, "peer")
	if a["cell"] != b["cell"] || a["environment"] != b["environment"] || a["node"] == b["node"] {
		fail("source and peer must be distinct nodes in one cell and environment")
	}
	sa, sb := sub(a, "scope"), sub(b, "scope")
	for _, k := range []string{"cluster_id", "tenant_id", "database_id", "shard_id"} {
		if !same(sa[k], sb[k]) {
			fail("source and peer scopes disagree on %s", k)
		}
	}
	if sa["member_id"] == sb["member_id"] || sa["incarnation"] == sb["incarnation"] {
		fail("source and peer require distinct member IDs and incarnations")
	}
	d := sub(m, "document")
	if !exact(d, "collection_id", "schema_generation", "schema_digest", "field_id") || !uuidRE.MatchString(str(d, "collection_id")) || !hashRE.MatchString(str(d, "schema_digest")) {
		fail("managed_member.document does not match alpha document transaction input")
	}
	num(d["schema_generation"], "schema_generation", 1)
	num(d["field_id"], "field_id", 1)
	return m
}
func validateHTTPS(value any, label string) {
	s := text(value, label)
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		fail("%s must be an origin-only HTTPS URL without userinfo or query", label)
	}
}
func validateMetrics(value any, label string) {
	s := text(value, label)
	u, e := url.Parse(s)
	if e != nil {
		fail("%s must be a loopback HTTP /metrics URL", label)
	}
	address, e := netip.ParseAddr(u.Hostname())
	if e != nil || !address.IsLoopback() || u.Scheme != "http" || u.Path != "/metrics" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		fail("%s must be a loopback HTTP /metrics URL", label)
	}
}
func privateReason(path, label string, reasons *[]string) {
	e := func() (err error) {
		defer recoverError(&err)
		if !filepath.IsAbs(path) {
			fail("%s path must be absolute", label)
		}
		privateFile(path, label)
		return
	}()
	if e != nil {
		*reasons = append(*reasons, e.Error())
	}
}
func validateProbeAdmission(m Object, reasons *[]string) {
	pin := sub(m, "probe_admission")
	if !exact(pin, "receipt_path", "receipt_sha256") {
		fail("probe_admission must pin one exact CI readback receipt")
	}
	before := len(*reasons)
	pinReason(pin, "receipt_path", "receipt_sha256", "D15 probe admission", false, reasons)
	if len(*reasons) > before {
		return
	}
	r, _ := load(str(pin, "receipt_path"), 16384)
	if !exact(r, "schema", "repository", "source_revision", "source_tree", "release_tag", "run_id", "run_number", "workflow", "job", "job_id", "attempt", "probe_asset", "probe_bytes", "probe_sha256", "publication_sha256", "qualification_sha256", "run_detail_sha256", "job_log_sha256") || str(r, "schema") != "terrascale.d15.probe-admission/v1" || str(r, "repository") != "TerraScale/ts-orchestrator" || r["source_revision"] != m["repository_revision"] || str(r, "workflow") != "ci.yml" || str(r, "job") != ProducerJob || str(r, "probe_asset") != ProbeAsset || r["probe_sha256"] != sub(sub(m, "transport"), "runtime")["qualify_sha256"] {
		fail("D15 probe admission differs from exact source, CI job, or probe pin")
	}
	if !gitRE.MatchString(str(r, "source_tree")) {
		fail("D15 probe admission lacks exact source and readback hashes")
	}
	for _, k := range []string{"publication_sha256", "qualification_sha256", "run_detail_sha256", "job_log_sha256"} {
		if !hashRE.MatchString(str(r, k)) {
			fail("D15 probe admission lacks exact source and readback hashes")
		}
	}
	for _, k := range []string{"run_id", "run_number", "job_id", "attempt", "probe_bytes"} {
		num(r[k], "D15 probe admission "+k, 1)
	}
	if n(r, "probe_bytes") > MaxProbeBytes || str(r, "release_tag") != fmt.Sprintf("ci-%s-run-%d", str(r, "source_revision"), n(r, "run_id")) {
		fail("D15 probe admission has invalid release or bounded asset size")
	}
}
func validateTransport(m Object, reasons *[]string) {
	transport := sub(m, "transport")
	operator := sub(transport, "operator")
	pinReason(operator, "executable_path", "executable_sha256", "operator executable pin", true, reasons)
	pinReason(operator, "config_path", "config_sha256", "operator hosts config", false, reasons)
	ssh := sub(transport, "ssh")
	pinReason(ssh, "executable_path", "executable_sha256", "SSH executable pin", true, reasons)
	targets := sub(ssh, "targets")
	if !exact(targets, "source", "peer", "controller") {
		fail("transport.ssh.targets must contain source, peer, and controller targets")
	}
	ids := map[string]bool{}
	for _, label := range []string{"source", "peer", "controller"} {
		t := sub(targets, label)
		if !exact(t, "address", "user", "port", "host_key_alias", "known_hosts_path", "known_hosts_sha256", "identity_file_path", "oci_instance_id") {
			fail("transport.ssh.targets.%s fields differ from pinned SSH settings", label)
		}
		address := text(t["address"], label+" SSH address")
		if strings.HasPrefix(address, "-") || !regexp.MustCompile(`^[A-Za-z0-9.:%_-]{1,253}$`).MatchString(address) {
			fail("transport.ssh.targets.%s.address is not safe SSH host address", label)
		}
		if _, e := netip.ParseAddr(address); e != nil {
			for part := range strings.SplitSeq(address, ".") {
				if !regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`).MatchString(part) {
					fail("transport.ssh.targets.%s.address is not valid host or IP address", label)
				}
			}
		}
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,31}$`).MatchString(str(t, "user")) {
			fail("unsafe SSH account name")
		}
		if num(t["port"], label+" SSH port", 1) > 65535 {
			fail("SSH port must not exceed 65535")
		}
		text(t["host_key_alias"], label+" host key alias")
		id := text(t["oci_instance_id"], label+" OCI instance ID")
		if !instanceRE.MatchString(id) {
			*reasons = append(*reasons, label+" SSH instance ID must be real OCI instance OCID")
		}
		if ids[id] {
			fail("SSH targets must pin distinct OCI instance IDs")
		}
		ids[id] = true
		pinReason(t, "known_hosts_path", "known_hosts_sha256", label+" SSH known_hosts", false, reasons)
		privateReason(str(t, "identity_file_path"), label+" SSH identity file", reasons)
	}
	if sub(targets, "source")["oci_instance_id"] != sub(m, "identity")["oci_instance_id"] {
		fail("source SSH target OCI instance ID differs from target identity pin")
	}
	if sub(targets, "controller")["oci_instance_id"] != sub(m, "controller_identity")["oci_instance_id"] {
		fail("controller SSH target OCI instance ID differs from its target identity pin")
	}
	https := sub(transport, "https")
	for _, label := range []string{"source", "peer"} {
		validateHTTPS(https[label+"_base_url"], label+" HTTPS URL")
		validateMetrics(https[label+"_metrics_url"], label+" metrics URL")
		privateReason(str(https, label+"_credential_file"), label+" credential file", reasons)
	}
	pinReason(https, "ca_bundle_path", "ca_bundle_sha256", "TerraBase client CA bundle", false, reasons)
	runtime := sub(transport, "runtime")
	if !same(runtime["service_names"], Object{"host": HostUnit, "controller": ControllerUnit}) {
		fail("transport.runtime.service_names must pin exact alpha host/controller units")
	}
	for _, k := range []string{"sudo_path", "remote_executable_path", "qualify_path", "stress_launcher_path", "systemctl_path", "systemd_run_path", "journalctl_path"} {
		s := text(runtime[k], "transport.runtime."+k)
		if !regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`).MatchString(s) {
			fail("transport.runtime.%s must be absolute safe executable path", k)
		}
	}
	hash := text(runtime["qualify_sha256"], "transport.runtime.qualify_sha256")
	if !hashRE.MatchString(hash) {
		fail("transport.runtime.qualify_sha256 must pin exact CI probe bytes")
	}
	expected := fmt.Sprintf("/run/terrascale-d15/probes/%s/%s/qualify", m["repository_revision"], hash)
	if str(runtime, "qualify_path") != expected {
		fail("qualify_path must use exact root-owned temporary staging path")
	}
	if str(runtime, "remote_executable_path") != expected {
		fail("remote action executable must use exact admitted probe staging path")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.@:-]+\.slice$`).MatchString(str(runtime, "workload_slice")) {
		fail("transport.runtime.workload_slice must be exact systemd .slice unit")
	}
	if str(runtime, "stress_launcher_contract") != "terrascale.d15.cgroup-launch/v1" {
		*reasons = append(*reasons, "target native pressure launcher must implement terrascale.d15.cgroup-launch/v1")
	}
	if !hashRE.MatchString(str(runtime, "stress_launcher_sha256")) {
		*reasons = append(*reasons, "target native pressure launcher SHA-256 missing or malformed")
	}
	a := sub(m, "adapter")
	if !exact(a, "executable_path", "executable_sha256", "deadlines_seconds") {
		fail("adapter fields must be exactly pinned native executable and deadlines")
	}
	pinReason(a, "executable_path", "executable_sha256", "alpha adapter executable pin", true, reasons)
	contract := sub(m, "adapter_contract")
	if a["executable_path"] != contract["source_path"] || a["executable_sha256"] != contract["source_sha256"] {
		*reasons = append(*reasons, "adapter executable pin differs from frozen alpha contract source pin")
	}
	roles := slices.Clone(baseRoles)
	scenario := str(sub(m, "pressure"), "scenario")
	if scenario == "terrabase_process" || scenario == "host_manager_sigkill" {
		roles = append(roles, "failure_inject")
	}
	if scenario == "terrabase_oom" {
		roles = append(roles, "kernel_oom_evidence")
	}
	d := sub(a, "deadlines_seconds")
	if !exact(d, roles...) {
		*reasons = append(*reasons, "alpha adapter deadlines must cover exactly required scenario roles")
		for _, role := range roles {
			if _, ok := d[role]; !ok {
				*reasons = append(*reasons, fmt.Sprintf("required adapter '%s' is missing", role))
			}
		}
	}
	for role, v := range d {
		deadline := num(v, "adapter.deadlines_seconds."+role, 1)
		if deadline > 300 {
			*reasons = append(*reasons, "adapter deadline exceeds 300 seconds")
		}
		if role == "database_progress" && !same(v, contract["database_progress_deadline_seconds"]) {
			*reasons = append(*reasons, "database progress deadline differs from frozen alpha contract")
		}
	}
}
func ValidateManifest(m Object, dry, allocations bool) (reasons []string, err error) {
	defer recoverError(&err)
	reasons = []string{}
	if str(m, "schema") != Schema {
		fail("manifest schema must be %q", Schema)
	}
	id := sub(m, "identity")
	for _, k := range identityKeys {
		text(id[k], "identity."+k)
	}
	if !instanceRE.MatchString(str(id, "oci_instance_id")) {
		reasons = append(reasons, "identity.oci_instance_id must be a real OCI instance OCID")
	}
	if !imageRE.MatchString(str(id, "image_id")) {
		reasons = append(reasons, "identity.image_id must be actual imported OCI image OCID")
	}
	if str(id, "architecture") != "aarch64" {
		fail("D15 target architecture must be aarch64")
	}
	controller := sub(m, "controller_identity")
	if !exact(controller, identityKeys...) {
		fail("controller_identity must pin exact controller guest identity")
	}
	for _, k := range identityKeys {
		text(controller[k], "controller_identity."+k)
	}
	if str(controller, "architecture") != "aarch64" || controller["cell"] != id["cell"] || controller["environment"] != id["environment"] || controller["oci_instance_id"] == id["oci_instance_id"] {
		fail("controller identity must pin distinct ARM guest in same cell/environment")
	}
	if !instanceRE.MatchString(str(controller, "oci_instance_id")) {
		reasons = append(reasons, "controller_identity.oci_instance_id must be real OCI instance OCID")
	}
	if !imageRE.MatchString(str(controller, "image_id")) {
		reasons = append(reasons, "controller_identity.image_id must be actual imported OCI image OCID")
	}
	member := validateManaged(m["managed_member"])
	if sub(member, "source")["cell"] != id["cell"] || sub(member, "source")["environment"] != id["environment"] {
		fail("identity cell/environment differs from signed source member")
	}
	if !gitRE.MatchString(str(m, "repository_revision")) {
		fail("repository_revision must pin full 40-character Git source ID")
	}
	auth := sub(m, "authorization")
	contract := sub(m, "adapter_contract")
	if auth["live_stress_authorized"] != true {
		reasons = append(reasons, "OCI owner has not explicitly authorized live pressure")
	}
	pinReason(auth, "owner_handoff_path", "owner_handoff_sha256", "OCI owner handoff", false, &reasons)
	if contract["frozen"] != true {
		reasons = append(reasons, "alpha host, database, target, and recovery adapter contract is not frozen")
	}
	if str(contract, "schema") != "terrascale.d15.adapter-contract/v5" || num(contract["version"], "adapter contract version", 1) != 5 {
		reasons = append(reasons, "adapter contract must declare v5 schema and version 5")
	}
	text(contract["id"], "adapter_contract.id")
	for k, want := range map[string]string{"database_frontier_binding": "object_durable.event{database,shard,replica,incarnation,sequence};serving_proof.v1/same_scope/v1", "host_status_source": "operator-hosts-json/controller-admitted/read-only/v1", "managed_process_witness": "accepted-managed-report+proc-stat+cgroup+boot-id/v1", "pressure_survival_policy": "all-pressure-workers-through-duration/v1", "oom_journal_format": "systemd-journal-kernel-oom/v1"} {
		if str(contract, k) != want {
			reasons = append(reasons, "adapter contract must pin "+k)
		}
	}
	for _, k := range []string{"database_progress_deadline_seconds", "oom_event_window_seconds"} {
		v := num(contract[k], k, 1)
		if v > 300 {
			reasons = append(reasons, "adapter contract "+k+" exceeds 300 seconds")
		}
	}
	if num(contract["host_report_max_age_seconds"], "host report maximum age", 1) != 30 {
		reasons = append(reasons, "adapter contract must pin 30-second host report freshness")
	}
	if num(contract["target_witness_max_age_ms"], "target witness age", 1) > 1000 {
		reasons = append(reasons, "adapter contract target witness age exceeds 1000 milliseconds")
	}
	pinReason(contract, "source_path", "source_sha256", "adapter contract", true, &reasons)
	validateProbeAdmission(m, &reasons)
	q := sub(m, "qualification")
	for _, k := range qualificationKeys {
		num(q[k], "qualification."+k, 1)
	}
	page := num(m["page_size_bytes"], "page_size_bytes", 1)
	if page&(page-1) != 0 {
		fail("page_size_bytes must be positive power of two")
	}
	for _, k := range qualificationKeys[:8] {
		if n(q, k)%page != 0 {
			fail("profile memory values must be page aligned")
		}
	}
	if n(q, qualificationKeys[0]) > n(q, qualificationKeys[1]) || n(q, qualificationKeys[2]) > n(q, qualificationKeys[3]) || n(q, qualificationKeys[4]) > n(q, qualificationKeys[5]) || n(q, qualificationKeys[4]) < n(q, qualificationKeys[0])+n(q, qualificationKeys[2]) || n(q, qualificationKeys[5]) < n(q, qualificationKeys[1])+n(q, qualificationKeys[3]) || n(q, qualificationKeys[5]) > n(q, "system_reserve_bytes") {
		fail("service and system.slice floor values violate signed reserve relationship")
	}
	cq := sub(m, "controller_qualification")
	if !exact(cq, controllerKeys...) {
		fail("controller_qualification must pin exact controller memory allocations")
	}
	for _, k := range controllerKeys {
		if num(cq[k], "controller_qualification."+k, 1)%page != 0 {
			fail("controller_qualification.%s must be page aligned", k)
		}
	}
	if n(cq, controllerKeys[0]) > n(cq, controllerKeys[1]) || n(cq, controllerKeys[2]) < n(cq, controllerKeys[0]) || n(cq, controllerKeys[3]) < n(cq, controllerKeys[1]) || n(cq, controllerKeys[2]) > n(cq, controllerKeys[3]) || n(cq, controllerKeys[3]) > n(cq, "system_reserve_bytes") {
		fail("controller service and system.slice floors violate signed reserve")
	}
	for _, group := range []string{"memory_floor_evidence", "controller_memory_floor_evidence"} {
		floors := sub(m, group)
		keys := []string{"host_service", "controller_service", "system_slice"}
		if group == "controller_memory_floor_evidence" {
			keys = []string{"controller_service", "system_slice"}
			if !exact(floors, keys...) {
				fail("controller floor evidence must pin controller service and slice sources")
			}
		}
		for _, scope := range keys {
			e := sub(floors, scope)
			basis := str(e, "basis")
			if basis != "allocation" && basis != "measured" {
				fail("%s.%s.basis must be measured or allocation", group, scope)
			}
			text(e["source"], group+"."+scope+".source")
			timestamp(e["observed_at_utc"], group+"."+scope+".observed_at_utc")
			pinReason(e, "source_path", "source_sha256", scope+" floor evidence", false, &reasons)
			if basis != "measured" && !allocations {
				reasons = append(reasons, scope+" memory floors are allocations, not measured floors")
			}
		}
	}
	validatePressurePlan(sub(m, "pressure"), q, page, dry)
	validateTransport(m, &reasons)
	if !dry && len(reasons) > 0 {
		fail("live qualification is unqualified: %s", strings.Join(reasons, "; "))
	}
	return
}
func validatePressurePlan(p, q Object, page int64, dry bool) {
	scenario := text(p["scenario"], "pressure.scenario")
	if !slices.Contains([]string{"management_stability", "terrabase_process", "terrabase_oom", "host_manager_sigkill"}, scenario) {
		fail("unsupported pressure scenario")
	}
	duration := num(p["duration_seconds"], "pressure.duration_seconds", 1)
	interval := num(p["sample_interval_seconds"], "pressure.sample_interval_seconds", 1)
	if duration > 900 {
		fail("pressure.duration_seconds must not exceed 900")
	}
	if interval >= duration {
		fail("sample interval must be below pressure duration")
	}
	if (duration+interval-1)/interval > 180 {
		fail("pressure plan exceeds 180 sample harness limit")
	}
	if scenario != "management_stability" {
		event := num(p["scenario_event_after_seconds"], "pressure.scenario_event_after_seconds", 1)
		if event >= duration || event <= interval {
			fail("scenario event time must allow one sample and be below pressure duration")
		}
	}
	for _, k := range []string{"cpu_workers", "memory_bytes", "memory_headroom_bytes", "io_workers", "io_file_bytes", "io_total_bytes", "io_bytes_per_second", "io_block_bytes"} {
		num(p[k], "pressure."+k, 1)
	}
	limits := map[string]int64{"cpu_workers": 64, "io_workers": 32, "io_file_bytes": 2 << 30, "io_total_bytes": 64 << 30, "io_bytes_per_second": 128 << 20}
	for k, limit := range limits {
		if n(p, k) > limit {
			fail("pressure.%s must not exceed %d", k, limit)
		}
	}
	memory := n(p, "memory_bytes") + n(p, "memory_headroom_bytes")
	if memory > 16<<30 {
		fail("memory payload plus headroom exceeds maximum")
	}
	if memory > n(q, "allocatable_memory_bytes") {
		fail("memory payload plus headroom exceeds signed allocatable memory")
	}
	if n(p, "io_file_bytes") > 4<<30/n(p, "io_workers") {
		fail("pressure I/O scratch allocation exceeds maximum")
	}
	block := n(p, "io_block_bytes")
	if block&(block-1) != 0 {
		fail("pressure.io_block_bytes must be power of two")
	}
	if block > n(p, "io_file_bytes") || block > n(p, "io_total_bytes") || n(p, "io_file_bytes")%block != 0 {
		fail("pressure I/O bounds must be multiples of at least one block")
	}
	if n(p, "io_total_bytes") < n(p, "io_bytes_per_second")*duration {
		fail("finite I/O budget must cover configured rate for full duration")
	}
	if !filepath.IsAbs(text(p["io_directory"], "pressure.io_directory")) {
		fail("pressure.io_directory must be absolute")
	}
	cg := sub(p, "workload_cgroup")
	parent := text(cg["parent_path"], "pressure.workload_cgroup.parent_path")
	if !safePath(parent) || !inside(parent, CgroupRoot) {
		fail("pressure workload parent must identify existing native workload slice")
	}
	f := strings.Fields(text(cg["cpu_max"], "pressure.workload_cgroup.cpu_max"))
	if len(f) != 2 || !decimalRE.MatchString(f[0]) || integerText(f[0], "CPU quota") == 0 || f[1] != "100000" {
		fail("pressure workload cgroup cpu_max must be '<quota> 100000' for systemd CPUQuota")
	}
	num(cg["memory_max_bytes"], "pressure memory.max", 1)
	num(cg["io_weight"], "pressure io.weight", 1)
	device := text(cg["io_device"], "pressure IO device")
	if !regexp.MustCompile(`^[0-9]+:[0-9]+$`).MatchString(device) {
		fail("pressure I/O device must be block major:minor pair")
	}
	if !dry && strings.HasPrefix(device, "0:") {
		fail("live pressure I/O must target block-backed filesystem")
	}
	if memory > n(cg, "memory_max_bytes") {
		fail("memory payload plus explicit headroom exceeds the pressure cgroup memory.max")
	}
	if scenario == "terrabase_oom" {
		fault := sub(p, "oom_fault")
		if !exact(fault, "target_memory_max_bytes", "deadline_seconds") {
			fail("pressure.oom_fault must pin exact temporary native-role cap and deadline")
		}
		cap := num(fault["target_memory_max_bytes"], "pressure.oom_fault.target_memory_max_bytes", page)
		if cap%page != 0 {
			fail("OOM target memory.max must be page aligned")
		}
		if cap >= n(q, "database_memory_max_bytes") {
			fail("OOM target memory.max must be below the signed TerraBase role cap")
		}
		if num(fault["deadline_seconds"], "pressure.oom_fault.deadline_seconds", 1) > 30 {
			fail("bounded OOM fault deadline must not exceed 30 seconds")
		}
	} else if _, ok := p["oom_fault"]; ok {
		fail("oom_fault supported only by terrabase_oom scenario")
	}
}
func DryRun(m Object, hash string) (plan Object, err error) {
	reasons, e := ValidateManifest(m, true, false)
	if e != nil {
		return nil, e
	}
	slices.Sort(reasons)
	reasons = slices.Compact(reasons)
	roles := slices.Clone(baseRoles)
	scenario := str(sub(m, "pressure"), "scenario")
	if scenario == "terrabase_process" || scenario == "host_manager_sigkill" {
		roles = append(roles, "failure_inject")
	}
	if scenario == "terrabase_oom" {
		roles = append(roles, "kernel_oom_evidence")
	}
	slices.Sort(roles)
	a := sub(m, "adapter")
	plan = Object{"schema": Schema, "mode": "DRY_RUN_ONLY", "qualification_status": "UNQUALIFIED", "commands_executed": false, "pressure_started": false, "manifest_sha256": hash, "identity": m["identity"], "controller_identity": m["controller_identity"], "controller_memory_floor_evidence": m["controller_memory_floor_evidence"], "adapter_source": Object{"executable_path": a["executable_path"], "executable_sha256": a["executable_sha256"]}, "planned_adapter_roles": roles, "required_adapter_roles": roles, "missing_or_unqualified": reasons, "resource_plan": m["pressure"]}
	return
}
