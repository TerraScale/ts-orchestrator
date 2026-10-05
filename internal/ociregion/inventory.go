package ociregion

import (
	"slices"
	"strings"
	"time"
)

var activeStates = []string{"CREATING", "PROVISIONING", "STARTING", "RUNNING", "STOPPING", "STOPPED", "AVAILABLE", "ACTIVE", "FAULTY", "UPDATING", "TERMINATING", "DELETING"}

func rows(v any) []any {
	if m, ok := v.(Object); ok {
		v = m["items"]
	}
	a, ok := v.([]any)
	if !ok {
		fail("OCI list response has an unexpected shape")
	}
	for _, v := range a {
		if _, ok := v.(Object); !ok {
			fail("OCI list response has an unexpected shape")
		}
	}
	return a
}
func active(v any, kind string) []any {
	r := []any{}
	for _, x := range arr(v) {
		m := obj(x)
		if m["kind"] == kind && contains(activeStates, m["lifecycle-state"]) {
			r = append(r, x)
		}
	}
	return r
}
func positiveGiB(v any, label string) any {
	if !integer(v) || number(v) <= 0 {
		fail(label + " must be a positive integer billed GiB amount")
	}
	return v
}
func verifyImages(regions, compartments, images any) {
	a, ok := images.([]any)
	if !ok {
		fail("inventory lacks scoped custom images")
	}
	seen := map[string]bool{}
	for _, x := range a {
		m, ok := x.(Object)
		if !ok {
			fail("invalid scoped custom image entry")
		}
		if !exact(m, "region", "id", "compartment_id", "display_name", "lifecycle_state", "billable_size_in_gbs") || text(m["region"]) == "" || text(m["id"]) == "" || seen[text(m["id"])] || !contains(regions, m["region"]) || !contains(compartments, m["compartment_id"]) || text(m["display_name"]) == "" || text(m["lifecycle_state"]) == "" {
			fail("duplicate or incomplete scoped custom image identity")
		}
		seen[text(m["id"])] = true
		if m["billable_size_in_gbs"] == nil {
			fail("scoped custom image has no billed GiB size")
		}
		positiveGiB(m["billable_size_in_gbs"], "scoped image size")
	}
}
func (e *Engine) scopedImages(regions, compartments any) []any {
	images := []any{}
	seen := map[string]bool{}
	for _, region := range arr(regions) {
		for _, compartment := range arr(compartments) {
			for _, v := range rows(e.oci(text(region), "compute", "image", "list", "--compartment-id", str(compartment), "--all")) {
				m := obj(v)
				owner := m["compartment-id"]
				if owner == nil {
					continue
				}
				if owner != compartment {
					fail("image list returned an unexpected owning compartment")
				}
				id := text(m["id"])
				if id == "" || seen[id] {
					fail("duplicate or missing scoped image identity")
				}
				seen[id] = true
				images = append(images, Object{"region": region, "id": id, "compartment_id": compartment, "display_name": m["display-name"], "lifecycle_state": m["lifecycle-state"], "billable_size_in_gbs": m["billable-size-in-gbs"]})
			}
		}
	}
	verifyImages(regions, compartments, images)
	return images
}
func slim(m Object, kind, region string) Object {
	r := Object{"kind": kind, "region": region}
	for _, k := range []string{"id", "display-name", "name", "compartment-id", "lifecycle-state", "availability-domain", "fault-domain", "shape", "shape-config", "size-in-gbs", "vpus-per-gb", "freeform-tags", "cidr-block", "is-public", "prohibit-public-ip-on-vnic", "prohibit-internet-ingress", "ip-address", "unique-size-in-gbs", "scope", "time-created", "vcn-id", "subnet-id"} {
		if v, ok := m[k]; ok {
			r[k] = v
		}
	}
	return r
}
func (e *Engine) collectInventory(plan Object) Object {
	subscriptions := rows(e.oci("", "iam", "region-subscription", "list", "--tenancy-id", str(plan["tenancy_id"]), "--all"))
	regions := []string{}
	for _, v := range subscriptions {
		m := obj(v)
		if m["status"] == "READY" {
			regions = append(regions, text(m["region-name"]))
		}
	}
	slices.Sort(regions)
	if !slices.Contains(regions, text(plan["region"])) {
		fail(str(plan["region"]) + " is not a ready subscribed region")
	}
	children := rows(e.oci("", "iam", "compartment", "list", "--compartment-id", str(plan["parent_compartment_id"]), "--all"))
	ids := Object{}
	seen := map[string]bool{}
	for _, role := range []string{"control", "network", "workload"} {
		name := obj(plan["preview_compartment_names"])[role]
		matches := []any{}
		for _, v := range children {
			m := obj(v)
			if m["name"] == name && contains([]string{"ACTIVE", "CREATING"}, m["lifecycle-state"]) {
				matches = append(matches, v)
			}
		}
		if len(matches) > 1 || (len(matches) == 1 && obj(matches[0])["lifecycle-state"] == "CREATING") {
			fail("preview " + role + " compartment is duplicated or still creating")
		}
		ids[role] = nil
		if len(matches) > 0 {
			ids[role] = obj(matches[0])["id"]
		}
		planned := obj(plan["resource_ids"])[role+"_compartment"]
		if truth(planned) && planned != ids[role] {
			fail("recorded preview " + role + " compartment OCID differs from live inventory")
		}
		if truth(ids[role]) {
			if seen[text(ids[role])] {
				fail("preview compartments overlap")
			}
			seen[text(ids[role])] = true
		}
	}
	compartments := []any{plan["tenancy_id"], plan["parent_compartment_id"], plan["shared_compartment_id"]}
	for _, role := range []string{"control", "network", "workload"} {
		if truth(ids[role]) {
			compartments = append(compartments, ids[role])
		}
	}
	images := e.call("collect_scoped_images", []any{arr(regions), compartments}, Object{})
	namespace := e.oci(text(plan["region"]), "os", "ns", "get")
	resources, buckets := []any{}, []any{}
	type task struct {
		kind, region string
		args         []string
	}
	tasks := []task{}
	for _, region := range regions {
		domains := rows(e.oci(region, "iam", "availability-domain", "list", "--compartment-id", str(plan["tenancy_id"])))
		for _, compartment := range compartments {
			for _, row := range []struct{ kind, a, b string }{{"instance", "compute", "instance"}, {"volume", "bv", "volume"}, {"vcn", "network", "vcn"}, {"subnet", "network", "subnet"}, {"network-security-group", "network", "nsg"}, {"security-list", "network", "security-list"}, {"route-table", "network", "route-table"}, {"service-gateway", "network", "service-gateway"}, {"internet-gateway", "network", "internet-gateway"}, {"local-peering-gateway", "network", "local-peering-gateway"}, {"nat-gateway", "network", "nat-gateway"}, {"load-balancer", "lb", "load-balancer"}, {"network-load-balancer", "nlb", "network-load-balancer"}, {"volume-backup", "bv", "backup"}, {"boot-volume-backup", "bv", "boot-volume-backup"}} {
				tasks = append(tasks, task{row.kind, region, []string{row.a, row.b, "list", "--compartment-id", str(compartment), "--all"}})
			}
			for _, v := range domains {
				tasks = append(tasks, task{"boot-volume", region, []string{"bv", "boot-volume", "list", "--compartment-id", str(compartment), "--availability-domain", str(obj(v)["name"]), "--all"}})
			}
			tasks = append(tasks, task{"bucket", region, []string{"os", "bucket", "list", "--compartment-id", str(compartment), "--all"}}, task{"public-ip", region, []string{"network", "public-ip", "list", "--scope", "REGION", "--compartment-id", str(compartment), "--all"}})
		}
	}
	type bucketTask struct {
		region string
		bucket Object
	}
	bucketTasks := []bucketTask{}
	for _, task := range tasks {
		for _, v := range rows(e.oci(task.region, task.args...)) {
			m := obj(v)
			if task.kind == "bucket" {
				bucketTasks = append(bucketTasks, bucketTask{task.region, m})
			} else {
				resources = append(resources, slim(m, task.kind, task.region))
			}
		}
	}
	objects := make([][]any, len(bucketTasks))
	for i, t := range bucketTasks {
		objects[i] = rows(e.oci(t.region, "os", "object", "list", "--namespace-name", str(namespace), "--bucket-name", str(t.bucket["name"]), "--fields", "size", "--all"))
	}
	for i, t := range bucketTasks {
		m := t.bucket
		properties := obj(e.oci(t.region, "os", "bucket", "get", "--namespace-name", str(namespace), "--bucket-name", str(m["name"])))
		versioned := t.region == plan["region"] && m["compartment-id"] == ids["control"] && contains([]any{obj(plan["foundation_buckets"])["head"], obj(plan["foundation_buckets"])["material"]}, m["name"])
		expected := "Disabled"
		if versioned {
			expected = "Enabled"
		}
		if properties["versioning"] != expected || properties["storage-tier"] != "Standard" {
			fail("bucket versioning or tier is outside the cost model")
		}
		if properties["public-access-type"] != "NoPublicAccess" {
			fail("bucket public access is outside the private storage model")
		}
		r := objects[i]
		if versioned {
			r = rows(e.oci(t.region, "os", "object", "list-object-versions", "--namespace-name", str(namespace), "--bucket-name", str(m["name"]), "--fields", "size", "--all"))
		}
		size := 0.0
		for _, v := range r {
			if truth(obj(v)["size"]) {
				size += number(obj(v)["size"])
			}
		}
		buckets = append(buckets, Object{"region": t.region, "compartment_id": m["compartment-id"], "name": m["name"], "object_count": len(r), "bytes": size, "versioning": properties["versioning"], "storage_tier": properties["storage-tier"], "public_access_type": properties["public-access-type"], "kms_key_id": properties["kms-key-id"]})
	}
	return Object{"schema_version": 2, "captured_at": pythonTime(e.now()), "plan_sha256": fileSHA(sourcePath(e, plan)), "tenancy_id": plan["tenancy_id"], "regions": arr(regions), "preview_compartment_ids": ids, "resources": resources, "buckets": buckets, "images": images}
}
func (e *Engine) replacement(resources any, plan Object, now time.Time) bool {
	if len(arr(resources)) == 0 {
		return false
	}
	var newest time.Time
	for _, v := range arr(resources) {
		t, ok := parseTime(obj(v)["time-created"])
		if !ok {
			return false
		}
		if t.After(newest) {
			newest = t
		}
	}
	age := now.Sub(newest)
	return age >= 0 && age <= time.Duration(number(obj(plan["budget"])["replacement_overlap_hours_max"])*float64(time.Hour))
}
func (e *Engine) verifyInventory(plan, inventory Object, path string, now time.Time, maxAge float64) {
	if !eq(inventory["schema_version"], 2) || inventory["tenancy_id"] != plan["tenancy_id"] {
		fail("inventory belongs to another tenancy or schema")
	}
	if path == "" {
		path = sourcePath(e, plan)
	}
	if inventory["plan_sha256"] != fileSHA(path) {
		fail("inventory was captured against another plan revision")
	}
	ids, planned := obj(inventory["preview_compartment_ids"]), obj(plan["resource_ids"])
	if !exact(ids, "control", "network", "workload") {
		fail("inventory lacks the three planned preview compartment identities")
	}
	for role, id := range ids {
		if truth(planned[role+"_compartment"]) && planned[role+"_compartment"] != id {
			fail("preview " + role + " compartment differs from the recorded resource identity")
		}
	}
	regions, ok := inventory["regions"].([]any)
	if x, valid := inventory["regions"].([]string); valid {
		regions = arr(x)
		ok = true
	}
	if !ok {
		fail("inventory lacks subscribed region scope")
	}
	for _, v := range regions {
		if text(v) == "" {
			fail("inventory lacks subscribed region scope")
		}
	}
	compartments := []any{plan["tenancy_id"], plan["parent_compartment_id"], plan["shared_compartment_id"]}
	for _, role := range []string{"control", "network", "workload"} {
		if truth(ids[role]) {
			compartments = append(compartments, ids[role])
		}
	}
	verifyImages(regions, compartments, inventory["images"])
	foundation := obj(plan["foundation_buckets"])
	for _, v := range arr(inventory["buckets"]) {
		b := obj(v)
		known := false
		for _, name := range foundation {
			known = known || name == b["name"]
		}
		if truth(ids["control"]) && b["compartment_id"] == ids["control"] && !known {
			fail("control compartment has an unplanned object bucket")
		}
		versioned := b["region"] == plan["region"] && b["compartment_id"] == ids["control"] && (b["name"] == foundation["head"] || b["name"] == foundation["material"])
		expected := "Disabled"
		if versioned {
			expected = "Enabled"
		}
		if b["versioning"] != expected || b["storage_tier"] != "Standard" {
			fail("inventory contains an unpriced object storage tier or versioning mode")
		}
		if b["public_access_type"] != "NoPublicAccess" {
			fail("inventory contains a public object storage bucket")
		}
		if truth(ids["control"]) && b["compartment_id"] == ids["control"] && known && planned["key"] != nil && b["kms_key_id"] != planned["key"] {
			fail("inventory bucket encryption differs from the exact control KMS key")
		}
	}
	captured, valid := parseTime(inventory["captured_at"])
	age := now.Sub(captured)
	if !valid || age < -30*time.Second || age > time.Duration(maxAge*float64(time.Minute)) {
		fail("inventory is stale or has an invalid timestamp")
	}
	existing := obj(plan["existing_forgejo"])
	resources := inventory["resources"]
	for _, pair := range [][2]string{{"instance", "instance_id"}, {"boot-volume", "boot_volume_id"}, {"volume", "data_volume_id"}} {
		matches := []any{}
		for _, v := range active(resources, pair[0]) {
			if obj(v)["id"] == existing[pair[1]] {
				matches = append(matches, v)
			}
		}
		if len(matches) != 1 || obj(matches[0])["compartment-id"] != plan["shared_compartment_id"] {
			fail("existing Forgejo " + pair[0] + " identity changed")
		}
	}
	instances := active(resources, "instance")
	seedID := obj(planned["instances"])["controller-a"]
	create := plan["seed_a_create_identity"]
	seedCandidates := []any{}
	for _, v := range instances {
		m := obj(v)
		_, tagged := obj(m["freeform-tags"])["BootstrapCreateKey"]
		if eq(m["id"], seedID) || tagged {
			seedCandidates = append(seedCandidates, v)
		}
	}
	if seedID != nil {
		if !truth(create) || len(seedCandidates) != 1 || obj(seedCandidates[0])["id"] != seedID || obj(obj(seedCandidates[0])["freeform-tags"])["BootstrapCreateKey"] != create {
			fail("plan-bound controller-a OCID or BootstrapCreateKey differs from live inventory")
		}
	} else if len(seedCandidates) > 0 {
		fail("controller-a must be recorded by exact OCID and seed create identity before admission")
	}
	controllerCount, memberCount := 0, 0
	preview := []any{}
	hosts, seenHosts := []string{}, map[string]bool{}
	for _, v := range arr(plan["hosts"]) {
		if slot := text(obj(v)["slot"]); strings.HasPrefix(slot, "member-") {
			hosts = append(hosts, memberName(plan, slot))
		}
	}
	for _, v := range instances {
		m := obj(v)
		shape := obj(m["shape-config"])
		if m["id"] == existing["instance_id"] {
			if m["shape"] != "VM.Standard.A1.Flex" || number(shape["ocpus"]) != 2 || number(shape["memory-in-gbs"]) != 4 {
				fail("Forgejo A1 dimensions changed")
			}
			continue
		}
		compartment := m["compartment-id"]
		if compartment != ids["control"] && compartment != ids["workload"] {
			fail("unbudgeted instance found: " + str(m["id"]))
		}
		tags := obj(m["freeform-tags"])
		if compartment == ids["workload"] && tags["terrascale-managed-by"] == "ts-orchestrator" && tags["terrascale-owner"] == plan["orchestrator_owner"] && tags["terrascale-resource"] == "member-host" {
			memberCount++
		} else if name := text(m["display-name"]); compartment == ids["workload"] && slices.Contains(hosts, name) && eq(tags, memberTags(plan, name)) {
			if seenHosts[name] {
				fail("two active instances share the C# database host name " + name)
			}
			seenHosts[name] = true
			memberCount++
		} else if compartment == ids["control"] && (m["id"] == seedID || contains([]string{controllerName(plan, "controller-b"), controllerName(plan, "controller-c")}, m["display-name"])) {
			controllerCount++
		} else {
			fail("preview instance has no approved owner: " + str(m["id"]))
		}
		if m["shape"] != "VM.Standard.A1.Flex" || number(shape["ocpus"]) != 1 || number(shape["memory-in-gbs"]) != 6 {
			fail("preview instance dimensions exceed the plan")
		}
		preview = append(preview, v)
	}
	if controllerCount > 4 || memberCount > 3 || len(preview) > 6 || (len(preview) > 5 && !e.replacement(preview, plan, now)) {
		fail("preview controller or member count exceeds the plan")
	}
	for _, kind := range []string{"boot-volume", "volume"} {
		for _, v := range active(resources, kind) {
			m := obj(v)
			if m["id"] != existing["boot_volume_id"] && m["id"] != existing["data_volume_id"] && m["compartment-id"] != ids["control"] && m["compartment-id"] != ids["workload"] {
				fail("unbudgeted " + kind + " found: " + str(m["id"]))
			}
			size, vpus := any(50), any(10)
			if kind == "volume" && m["id"] == existing["data_volume_id"] {
				size = existing["expected_volume_gb"]
				vpus = existing["expected_volume_vpus_per_gb"]
			}
			if !eq(number(m["size-in-gbs"]), number(size)) || !eq(number(m["vpus-per-gb"]), number(vpus)) {
				fail("unexpected " + kind + " size or performance: " + str(m["id"]))
			}
		}
	}
	boot, data := active(resources, "boot-volume"), active(resources, "volume")
	if len(boot) > 7 || len(data) > 4 || (len(boot) > 6 && !e.replacement(boot, plan, now)) || (len(data) > 3 && !e.replacement(data, plan, now)) {
		fail("live volumes exceed the five-host plan")
	}
	public := map[string]bool{}
	backupSize := add(0)
	for _, v := range arr(resources) {
		m := obj(v)
		if m["kind"] == "public-ip" {
			public[text(m["id"])] = true
		}
		if contains([]string{"volume-backup", "boot-volume-backup"}, m["kind"]) && contains(activeStates, m["lifecycle-state"]) {
			if m["unique-size-in-gbs"] == nil && m["size-in-gbs"] == nil {
				fail("retained volume backup size is unavailable")
			}
			size := m["unique-size-in-gbs"]
			if !truth(size) {
				size = m["size-in-gbs"]
			}
			if size != nil {
				backupSize.Add(backupSize, rat(size))
			}
		}
	}
	if len(public) != 1 || !public[text(existing["public_ip_id"])] {
		fail("public IP inventory differs from the unrelated Forgejo baseline")
	}
	if greater(backupSize, obj(plan["budget"])["snapshot_gb_max"]) {
		fail("retained volume backups exceed the 350 GB reserve")
	}
	if len(active(resources, "nat-gateway")) > 0 || len(active(resources, "load-balancer")) > 0 {
		fail("unpriced gateway or load balancer is present")
	}
	verifyGateways(plan, resources, ids)
}
func verifyGateways(plan Object, resources any, preview Object) {
	existing, ids := obj(plan["existing_forgejo"]), obj(plan["resource_ids"])
	expected := map[string][]any{"internet-gateway": {[]any{existing["internet_gateway_id"], plan["shared_compartment_id"], existing["vcn_id"]}}, "network-load-balancer": {}, "local-peering-gateway": {}}
	if plan["public_api"] != nil {
		if ids["internet_gateway"] != nil {
			expected["internet-gateway"] = append(expected["internet-gateway"], []any{ids["internet_gateway"], preview["network"], ids["vcn"]})
		}
		if ids["network_load_balancer"] != nil {
			expected["network-load-balancer"] = append(expected["network-load-balancer"], []any{ids["network_load_balancer"], preview["network"], ids["public_subnet"]})
		}
	}
	gateway := obj(plan["operator_gateway"])
	if gateway["local_peering_gateway_id"] != nil {
		expected["local-peering-gateway"] = append(expected["local-peering-gateway"], []any{gateway["local_peering_gateway_id"], plan["shared_compartment_id"], existing["vcn_id"]})
	}
	if ids["local_peering_gateway"] != nil {
		expected["local-peering-gateway"] = append(expected["local-peering-gateway"], []any{ids["local_peering_gateway"], preview["network"], ids["vcn"]})
	}
	errors := map[string]string{"internet-gateway": "internet gateway inventory differs from the Forgejo and public API baseline", "network-load-balancer": "network load balancer inventory differs from the recorded public API balancer", "local-peering-gateway": "local peering gateway inventory differs from the recorded operator gateway pair"}
	for kind, want := range expected {
		seen := map[string]bool{}
		field := "vcn-id"
		if kind == "network-load-balancer" {
			field = "subnet-id"
		}
		for _, v := range active(resources, kind) {
			m := obj(v)
			seen[canonical([]any{m["id"], m["compartment-id"], m[field]})] = true
		}
		expectedSet := map[string]bool{}
		for _, v := range want {
			expectedSet[canonical(v)] = true
		}
		if !eq(seen, expectedSet) {
			fail(errors[kind])
		}
	}
}
func (e *Engine) estimate(plan, inventory Object, path string, now time.Time, maxAge float64) Object {
	e.verifyInventory(plan, inventory, path, now, maxAge)
	budget := obj(plan["budget"])
	rates := obj(budget["rates"])
	hours := budget["month_hours"]
	ocpus, memory, storage := add(2), add(4), add(50, obj(plan["existing_forgejo"])["expected_volume_gb"])
	for _, v := range arr(plan["hosts"]) {
		h := obj(v)
		ocpus.Add(ocpus, rat(h["ocpus"]))
		memory.Add(memory, rat(h["memory_gb"]))
		storage.Add(storage, add(h["boot_gb"], h["data_gb"]))
	}
	compute := add(mul(nonnegative(sub(mul(ocpus, hours), 1500)), rates["a1_ocpu_hour"]), mul(nonnegative(sub(mul(memory, hours), 9000)), rates["a1_memory_gb_hour"]))
	block := mul(nonnegative(sub(storage, 200)), add(rates["block_gb_month"], mul(plan["volume_vpus_per_gb"], rates["block_vpu_gb_month"])))
	imageGiB := add(0)
	for _, v := range arr(inventory["images"]) {
		imageGiB.Add(imageGiB, rat(positiveGiB(obj(v)["billable_size_in_gbs"], "scoped image size")))
	}
	liveBytes := add(0)
	for _, v := range arr(inventory["buckets"]) {
		liveBytes.Add(liveBytes, rat(obj(v)["bytes"]))
	}
	objectGB := add(maximum(div(liveBytes, 1024*1024*1024), budget["baseline_object_storage_gb"]), budget["object_storage_gb_max"], budget["staging_object_storage_gb_max"])
	overlap := budget["replacement_overlap_hours_max"]
	items := Object{"compute": compute, "block_storage": block, "replacement_compute": mul(overlap, add(rates["a1_ocpu_hour"], mul(6, rates["a1_memory_gb_hour"]))), "replacement_storage": mul(div(mul(100, overlap), hours), add(rates["block_gb_month"], mul(10, rates["block_vpu_gb_month"]))), "object_storage": mul(nonnegative(sub(objectGB, 10)), rates["object_gb_month"]), "custom_image_storage": mul(imageGiB, rates["object_gb_month"]), "object_requests": add(mul(div(budget["object_requests_max"], 10000), rates["object_10000_requests"]), budget["baseline_object_requests_usd"]), "egress": mul(budget["egress_gb_max"], rates["egress_gb"]), "snapshot_reserve": mul(budget["snapshot_gb_max"], rates["block_gb_month"]), "misc_reserve": rat(budget["misc_reserve_usd"])}
	total := add(0)
	formatted := Object{}
	for k, v := range items {
		total.Add(total, rat(v))
		formatted[k] = fixed(v, 4)
	}
	if greater(total, budget["monthly_limit"]) {
		fail("projected USD " + fixed(total, 2) + " exceeds the monthly ceiling")
	}
	return Object{"currency": "USD", "items": formatted, "total": fixed(total, 2), "limit": str(budget["monthly_limit"]), "headroom": fixed(sub(budget["monthly_limit"], total), 2), "assumptions": Object{"a1_free_ocpu_hours": 1500, "a1_free_memory_gb_hours": 9000, "free_block_gb": 200, "free_object_gb": 10, "object_growth_reserve_gb": str(budget["object_storage_gb_max"]), "object_staging_reserve_gb": str(budget["staging_object_storage_gb_max"]), "backup_reserve_pricing": "350 GB at block capacity rate; provisional", "custom_image_storage_rate": str(rates["object_gb_month"]), "custom_image_size_source": "OCI billableSizeInGBs for scoped custom images"}}
}
func Estimate(plan, inventory Object, planPath string) (Object, error) {
	e := &Engine{PlanPath: planPath}
	return capture(func() Object { return e.estimate(plan, inventory, planPath, e.now(), 15) })
}
