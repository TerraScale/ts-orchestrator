package ociregion

import (
	"errors"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (e *Engine) currentHead(namespace, bucket, name, region string) Object {
	var value any
	var parseErr error
	if v, ok := e.sdkHead(namespace, bucket, name, region); ok {
		value = v
	} else {
		p := e.process([]string{"oci", "os", "object", "head", "--namespace-name", namespace, "--bucket-name", bucket, "--name", name, "--region", region, "--output", "json"})
		if number(p["returncode"]) != 0 {
			fail("OCI current object HEAD failed or key is deleted")
		}
		value, parseErr = decodeJSON([]byte(text(p["stdout"])))
	}
	headers, valid := value.(Object)
	if parseErr != nil || !valid {
		fail("OCI current object HEAD response is invalid")
	}
	size, err := strconv.ParseInt(str(headers["content-length"]), 10, 64)
	_, terr := http.ParseTime(text(headers["last-modified"]))
	if err != nil || terr != nil {
		fail("OCI current object HEAD lacks size or timestamp")
	}
	if text(headers["version-id"]) == "" || (!integer(headers["content-length"]) && text(headers["content-length"]) == "") || size < 0 {
		fail("OCI current object HEAD lacks version identity, size, or timestamp")
	}
	return Object{"region": region, "bucket": bucket, "name": name, "version_id": headers["version-id"], "size": size, "last_modified": headers["last-modified"], "head_at": pythonTime(e.now())}
}

// sdkHead serves the object HEAD in-binary unless a test dependency or the
// CLI backend is in use.
func (e *Engine) sdkHead(namespace, bucket, name, region string) (any, bool) {
	if e.Dependency != nil {
		return nil, false
	}
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok && e.ctx().Err() != nil && errors.Is(err, e.ctx().Err()) {
				panic(err)
			}
			// Keep the diagnosis (missing object, unreadable OCI config,
			// invalid backend); anything that is not an operational
			// failure is a programming error and is not recast.
			if failure, ok := r.(Failure); ok {
				fail("OCI current object HEAD failed or key is deleted: " + failure.Message)
			}
			panic(r)
		}
	}()
	return e.sdkOCI([]any{"os", "object", "head", "--namespace-name", namespace, "--bucket-name", bucket, "--name", name}, Object{"region": region})
}

func objectVersion(row Object, versioned bool) Object {
	name, id, marker, size, tier := row["name"], row["version-id"], row["is-delete-marker"], row["size"], row["storage-tier"]
	if _, ok := row["is-delete-marker"]; !ok {
		marker = false
	}
	_, boolean := marker.(bool)
	_, explicit := row["is-delete-marker"]
	if text(name) == "" || !boolean || (versioned && (!explicit || text(id) == "")) || (!versioned && id != nil && id != "") || (!truth(marker) && (!integer(size) || number(size) < 0)) || tier != "Standard" {
		fail("object version has missing identity, size, or priced tier")
	}
	if !versioned {
		id = nil
	}
	return Object{"name": name, "version_id": id, "is_delete_marker": marker, "size": size, "storage_tier": tier, "archival_state": row["archival-state"]}
}
func (e *Engine) importInventory(plan Object, projection, staged, previous string) Object {
	snapshot := obj(e.call("collect_inventory", []any{plan}, Object{}))
	namespace := e.oci(text(plan["region"]), "os", "ns", "get")
	if text(namespace) == "" {
		fail("object namespace is missing")
	}
	buckets := arr(snapshot["buckets"])
	results := make([][]any, len(buckets))
	for i, v := range buckets {
		b := obj(v)
		cmd := "list"
		if b["versioning"] == "Enabled" {
			cmd = "list-object-versions"
		}
		results[i] = rows(e.oci(text(b["region"]), "os", "object", cmd, "--namespace-name", str(namespace), "--bucket-name", str(b["name"]), "--fields", "name,size,storageTier,archivalState", "--all"))
	}
	for i, v := range buckets {
		b := obj(v)
		versions := []any{}
		total := 0.0
		for _, x := range results[i] {
			r := objectVersion(obj(x), b["versioning"] == "Enabled")
			versions = append(versions, r)
			if !truth(r["is_delete_marker"]) {
				total += number(r["size"])
			}
		}
		b["versions"] = versions
		b["object_count"] = len(versions)
		b["bytes"] = total
	}
	snapshot["schema_version"] = 3
	snapshot["object_namespace"] = namespace
	snapshot["current_objects"] = []any{}
	if staged != "" {
		if projection == "" {
			fail("current object HEAD requires the reviewed import projection")
		}
		imports := reviewedImports(plan, snapshot, projection)
		receipt := readJSON(staged, 64*1024, "staged object version receipt")
		roles := keys(obj(receipt["versions"]))
		if !sameRoles(roles, "base") && !sameRoles(roles, "base", "final") {
			fail("current object HEAD requires base or both staged version IDs")
		}
		hash := fileSHA(projection)
		if previous != "" && sameRoles(roles, "base") {
			old := reviewedImports(plan, snapshot, previous)
			if !sameRoles(keys(old), "base") || !sameRoles(keys(imports), "base", "final") || !eq(old["base"], imports["base"]) {
				fail("full import projection base row differs from the staged base-only projection")
			}
			hash = fileSHA(previous)
		}
		versions := importReceipt(staged, "versions", hash, roles)
		current := []any{}
		for _, role := range keys(versions) {
			entry := obj(imports[role])
			ref := obj(entry["object"])
			current = append(current, e.call("current_object_head", []any{namespace, ref["bucket"], ref["key"], plan["region"]}, Object{}))
		}
		snapshot["current_objects"] = current
	}
	return snapshot
}
func (e *Engine) verifyImportInventory(plan, inventory Object, path string, now time.Time, maxAge float64) {
	if !eq(inventory["schema_version"], 3) {
		fail("import inventory requires schema v3")
	}
	base := maps.Clone(inventory)
	base["schema_version"] = 2
	e.verifyInventory(plan, base, path, now, maxAge)
	if text(inventory["object_namespace"]) == "" {
		fail("import inventory lacks object namespace")
	}
	if _, ok := inventory["regions"].([]any); !ok {
		fail("import inventory lacks region scope")
	}
	seenBuckets, seenVersions := map[string]bool{}, map[string]bool{}
	for _, v := range arr(inventory["buckets"]) {
		b := obj(v)
		identity := []any{b["region"], b["name"]}
		key := canonical(identity)
		if text(b["region"]) == "" || text(b["name"]) == "" || seenBuckets[key] {
			fail("duplicate or missing bucket identity")
		}
		seenBuckets[key] = true
		versions, ok := b["versions"].([]any)
		if !ok {
			fail("import inventory lacks object versions")
		}
		total := 0.0
		for _, x := range versions {
			r, ok := x.(Object)
			if !ok {
				fail("invalid object version")
			}
			normalized := objectVersion(Object{"name": r["name"], "version-id": r["version_id"], "is-delete-marker": r["is_delete_marker"], "size": r["size"], "storage-tier": r["storage_tier"], "archival-state": r["archival_state"]}, b["versioning"] == "Enabled")
			if !eq(r, normalized) {
				fail("object version detail was altered")
			}
			key := canonical(append(identity, r["name"], r["version_id"]))
			if seenVersions[key] {
				fail("duplicate object version identity")
			}
			seenVersions[key] = true
			if !truth(r["is_delete_marker"]) {
				total += number(r["size"])
			}
		}
		if !eq(b["object_count"], len(versions)) || !eq(b["bytes"], total) {
			fail("object version totals disagree with bucket")
		}
	}
	current, ok := inventory["current_objects"].([]any)
	if !ok {
		fail("import inventory lacks current object HEAD evidence")
	}
	seen := map[string]bool{}
	captured, _ := parseTime(inventory["captured_at"])
	for _, v := range current {
		c, ok := v.(Object)
		if !ok {
			fail("current object HEAD evidence is malformed")
		}
		key := canonical([]any{c["region"], c["bucket"], c["name"]})
		if text(c["region"]) == "" || text(c["bucket"]) == "" || text(c["name"]) == "" || seen[key] || !contains(inventory["regions"], c["region"]) || text(c["version_id"]) == "" || !integer(c["size"]) || number(c["size"]) < 0 {
			fail("current object HEAD identity or size is invalid")
		}
		seen[key] = true
		_, err := http.ParseTime(text(c["last_modified"]))
		head, ok := parseTime(c["head_at"])
		if err != nil || !ok {
			fail("current object HEAD timestamp is invalid")
		}
		if head.Before(captured.Add(-30*time.Second)) || head.After(now.Add(30*time.Second)) {
			fail("current object HEAD timestamp is stale or invalid")
		}
		matches := 0
		for _, v := range arr(inventory["buckets"]) {
			b := obj(v)
			if b["region"] == c["region"] && b["name"] == c["bucket"] && b["versioning"] == "Enabled" {
				for _, v := range arr(b["versions"]) {
					r := obj(v)
					if r["name"] == c["name"] && r["version_id"] == c["version_id"] && !truth(r["is_delete_marker"]) && eq(r["size"], c["size"]) {
						matches++
					}
				}
			}
		}
		if matches != 1 {
			fail("current object HEAD differs from retained version inventory")
		}
	}
}
func reviewedImports(plan, inventory Object, path string) Object {
	p := readJSON(path, 64*1024, "import projection")
	imports, ok := p["imports"].([]any)
	if !eq(p["schema_version"], 1) || !ok || (len(imports) != 1 && len(imports) != 2) {
		fail("import projection requires a base-only or base-and-final schema v1 import list")
	}
	roles := Object{}
	objects, names := map[string]bool{}, map[string]bool{}
	control := obj(inventory["preview_compartment_ids"])["control"]
	if !truth(control) {
		fail("import projection requires the live control compartment")
	}
	for _, v := range imports {
		if !exact(v, "role", "local_file", "sha256", "bytes", "object", "image") {
			fail("import projection entry has missing or unexpected fields")
		}
		entry := obj(v)
		role := text(entry["role"])
		if (role != "base" && role != "final") || roles[role] != nil {
			fail("import projection requires distinct base and final roles")
		}
		if !exact(entry["object"], "bucket", "key") || !exact(entry["image"], "display_name", "compartment_id", "max_billable_size_in_gbs", "evidence") {
			fail("import projection object or image identity is incomplete")
		}
		ref, image := obj(entry["object"]), obj(entry["image"])
		if text(ref["bucket"]) == "" || text(ref["key"]) == "" || text(image["display_name"]) == "" || image["compartment_id"] != control || strings.TrimSpace(text(image["evidence"])) == "" {
			fail("import projection lacks reviewed object or image identity and evidence")
		}
		objectKey, nameKey := canonical([]any{ref["bucket"], ref["key"]}), canonical([]any{control, image["display_name"]})
		if objects[objectKey] || names[nameKey] {
			fail("import projection has duplicate object keys or image names")
		}
		objects[objectKey], names[nameKey] = true, true
		matches := []any{}
		for _, v := range arr(inventory["buckets"]) {
			b := obj(v)
			if b["region"] == plan["region"] && b["compartment_id"] == control && b["name"] == ref["bucket"] {
				matches = append(matches, v)
			}
		}
		if len(matches) != 1 || obj(matches[0])["versioning"] != "Enabled" {
			fail("import object bucket must be a priced versioned control bucket")
		}
		positiveGiB(image["max_billable_size_in_gbs"], role+" reviewed maximum")
		if !safeMatch(`[0-9a-f]{64}`, entry["sha256"]) || !integer(entry["bytes"]) || number(entry["bytes"]) <= 0 || text(entry["local_file"]) == "" {
			fail("import projection lacks exact local file bytes and SHA-256")
		}
		local := text(entry["local_file"])
		st, err := os.Stat(local)
		if !filepath.IsAbs(local) || err != nil || !st.Mode().IsRegular() || !eq(st.Size(), entry["bytes"]) || fileSHA(local) != entry["sha256"] {
			fail(role + " local file bytes or SHA-256 changed")
		}
		roles[role] = entry
	}
	if !sameRoles(keys(roles), "base") && !sameRoles(keys(roles), "base", "final") {
		fail("import projection requires the base role and optional final role")
	}
	return roles
}
func sameRoles(got []string, want ...string) bool { return eq(got, want) }
func importReceipt(path, field, hash string, roles []string) Object {
	r := readJSON(path, 64*1024, "import "+field+" receipt")
	values := obj(r[field])
	valid := eq(r["schema_version"], 1) && r["projection_sha256"] == hash && sameRoles(keys(values), roles...)
	seen := map[string]bool{}
	for _, v := range values {
		if text(v) == "" || seen[text(v)] {
			valid = false
		}
		seen[text(v)] = true
	}
	if !valid {
		fail("import " + field + " receipt is incomplete or bound to another projection")
	}
	if field == "images" {
		for _, v := range values {
			if !strings.HasPrefix(text(v), "ocid1.image.") {
				fail("import image receipt lacks OCI image OCIDs")
			}
		}
	}
	return values
}
func (e *Engine) previousAdmission(path, phase, projection, planPath, staged, imported string) Object {
	p := readJSON(path, 64*1024, "previous import admission")
	_, estimate := p["estimate"].(Object)
	if !eq(p["schema_version"], 3) || p["phase"] != phase || p["plan_sha256"] != fileSHA(planPath) || p["projection_sha256"] != projection || (staged != "" && p["staged_versions_sha256"] != staged) || (imported != "" && p["imported_images_sha256"] != imported) || !estimate {
		fail("previous import admission does not bind this projection and stage")
	}
	admitted, aok := parseTime(p["admitted_at"])
	expires, eok := parseTime(p["expires_at"])
	if !aok || !eok || !expires.After(admitted) || expires.After(admitted.Add(15*time.Minute+30*time.Second)) || admitted.After(e.now().Add(30*time.Second)) {
		fail("previous import admission has invalid timestamps")
	}
	return p
}
func carriedLineage(v any, planHash string) Object {
	if !exact(v, "schema_version", "plan_sha256", "projection_sha256", "admission_sha256", "inventory_sha256", "staged_versions_sha256", "imported_images_sha256", "base_version_id", "base_image_id", "estimate") {
		fail("full import projection lacks valid base-only admission lineage")
	}
	r := obj(v)
	valid := eq(r["schema_version"], 1) && r["plan_sha256"] == planHash && text(r["base_version_id"]) != "" && strings.HasPrefix(text(r["base_image_id"]), "ocid1.image.")
	_, ok := r["estimate"].(Object)
	valid = valid && ok
	for _, key := range []string{"plan_sha256", "projection_sha256", "admission_sha256", "inventory_sha256", "staged_versions_sha256", "imported_images_sha256"} {
		valid = valid && safeMatch(`[0-9a-f]{64}`, r[key])
	}
	if !valid {
		fail("full import projection lacks valid base-only admission lineage")
	}
	return r
}
func (e *Engine) establishLineage(plan Object, full, base, inventoryPath, admission, staged, images, planPath string) Object {
	inventory := readJSON(inventoryPath, 4*1024*1024, "base-only import inventory")
	f, b := reviewedImports(plan, inventory, full), reviewedImports(plan, inventory, base)
	if !sameRoles(keys(b), "base") || !sameRoles(keys(f), "base", "final") || !eq(b["base"], f["base"]) {
		fail("full import projection base row differs from the admitted base-only input")
	}
	previous := e.previousAdmission(admission, "pre-import", fileSHA(base), planPath, fileSHA(staged), fileSHA(images))
	if previous["inventory_sha256"] != fileSHA(inventoryPath) {
		fail("base-only admission does not bind the supplied inventory")
	}
	at, _ := parseTime(previous["admitted_at"])
	_, offset := at.Zone()
	if offset != 0 {
		fail("base-only admission timestamp is not UTC")
	}
	expected := e.importEstimate(plan, inventory, base, "pre-import", staged, images, planPath, at, 10*365*24*60, nil)
	if !eq(previous["estimate"], expected) {
		fail("base-only admission cost differs from its exact inventory and receipts")
	}
	versions, imported := importReceipt(staged, "versions", fileSHA(base), []string{"base"}), importReceipt(images, "images", fileSHA(base), []string{"base"})
	return carriedLineage(Object{"schema_version": 1, "plan_sha256": fileSHA(planPath), "projection_sha256": fileSHA(base), "admission_sha256": fileSHA(admission), "inventory_sha256": fileSHA(inventoryPath), "staged_versions_sha256": fileSHA(staged), "imported_images_sha256": fileSHA(images), "base_version_id": versions["base"], "base_image_id": imported["base"], "estimate": expected}, fileSHA(planPath))
}
func (e *Engine) importEstimate(plan, inventory Object, projection, phase, stagedPath, importedPath, path string, now time.Time, maxAge float64, lineage Object) Object {
	if !contains([]string{"pre-stage", "pre-import", "post-import"}, phase) {
		fail("unknown import admission phase")
	}
	e.verifyImportInventory(plan, inventory, path, now, maxAge)
	imports := reviewedImports(plan, inventory, projection)
	hash := fileSHA(projection)
	var staged, imported Object
	if phase != "pre-stage" && stagedPath == "" {
		fail("staged object version receipt is required")
	}
	if stagedPath != "" {
		roles := keys(imports)
		if phase == "pre-stage" {
			roles = []string{"base"}
		}
		staged = importReceipt(stagedPath, "versions", hash, roles)
	}
	if phase == "post-import" && importedPath == "" {
		fail("imported image OCID receipt is required")
	}
	if importedPath != "" {
		if phase == "pre-stage" {
			fail("pre-stage cannot bind imported images")
		}
		roles := []string{"base"}
		if phase == "post-import" {
			roles = keys(imports)
		}
		imported = importReceipt(importedPath, "images", hash, roles)
	}
	if sameRoles(keys(imports), "base", "final") && lineage != nil {
		planPath := path
		if planPath == "" {
			planPath = sourcePath(e, plan)
		}
		lineage = carriedLineage(lineage, fileSHA(planPath))
		if (staged != nil && staged["base"] != nil && staged["base"] != lineage["base_version_id"]) || (imported != nil && imported["base"] != nil && imported["base"] != lineage["base_image_id"]) {
			fail("full import receipt changed the admitted base object version or image OCID")
		}
		if staged == nil {
			staged = Object{"base": lineage["base_version_id"]}
		}
		if imported == nil {
			imported = Object{"base": lineage["base_image_id"]}
		}
	}
	projected := 0.0
	for _, role := range keys(imports) {
		entry := obj(imports[role])
		ref, image := obj(entry["object"]), obj(entry["image"])
		var bucket Object
		for _, v := range arr(inventory["buckets"]) {
			b := obj(v)
			if b["region"] == plan["region"] && b["name"] == ref["bucket"] {
				bucket = b
				break
			}
		}
		if staged == nil || staged[role] == nil {
			projected += number(entry["bytes"])
		} else {
			matches := []any{}
			for _, v := range arr(bucket["versions"]) {
				r := obj(v)
				if r["name"] == ref["key"] && r["version_id"] == staged[role] && !truth(r["is_delete_marker"]) {
					matches = append(matches, v)
				}
			}
			if len(matches) != 1 || !eq(obj(matches[0])["size"], entry["bytes"]) {
				fail(role + " staged object version is absent or has different bytes")
			}
			current := []any{}
			for _, v := range arr(inventory["current_objects"]) {
				r := obj(v)
				if r["region"] == plan["region"] && r["bucket"] == ref["bucket"] && r["name"] == ref["key"] {
					current = append(current, v)
				}
			}
			if len(current) != 1 || obj(current[0])["version_id"] != staged[role] || !eq(obj(current[0])["size"], entry["bytes"]) {
				fail(role + " staged object is not the current import source version")
			}
		}
		matching := []any{}
		for _, v := range arr(inventory["images"]) {
			r := obj(v)
			if r["region"] == plan["region"] && r["compartment_id"] == image["compartment_id"] && r["display_name"] == image["display_name"] {
				matching = append(matching, v)
			}
		}
		if (imported == nil || imported[role] == nil) && len(matching) > 0 {
			fail(role + " image name already exists before import")
		}
		if imported != nil && imported[role] != nil {
			if len(matching) != 1 || obj(matching[0])["id"] != imported[role] || obj(matching[0])["lifecycle_state"] != "AVAILABLE" {
				fail(role + " imported image identity is absent, duplicated, or unavailable")
			}
			if greater(positiveGiB(obj(matching[0])["billable_size_in_gbs"], role+" billed size"), positiveGiB(image["max_billable_size_in_gbs"], role+" reviewed maximum")) {
				fail(role + " imported image exceeds reviewed billed GiB maximum")
			}
		}
	}
	base := maps.Clone(inventory)
	base["schema_version"] = 2
	baseline := e.estimate(plan, base, path, now, maxAge)
	budget := obj(plan["budget"])
	rate := obj(budget["rates"])["object_gb_month"]
	live := add(0)
	for _, v := range arr(inventory["buckets"]) {
		live.Add(live, rat(obj(v)["bytes"]))
	}
	objectGB := add(maximum(div(add(live, projected), 1000000000), budget["baseline_object_storage_gb"]), budget["object_storage_gb_max"], budget["staging_object_storage_gb_max"])
	existingGiB, expectedGiB := add(0), add(0)
	for _, v := range arr(inventory["images"]) {
		r := obj(v)
		found := false
		for _, id := range imported {
			found = found || r["id"] == id
		}
		if !found {
			existingGiB.Add(existingGiB, rat(positiveGiB(r["billable_size_in_gbs"], "scoped image size")))
		}
	}
	for _, role := range keys(imports) {
		size := obj(obj(imports[role])["image"])["max_billable_size_in_gbs"]
		if imported != nil && imported[role] != nil {
			for _, v := range arr(inventory["images"]) {
				r := obj(v)
				if r["id"] == imported[role] {
					size = r["billable_size_in_gbs"]
					break
				}
			}
		}
		expectedGiB.Add(expectedGiB, rat(size))
	}
	items := maps.Clone(obj(baseline["items"]))
	items["object_storage"] = mul(nonnegative(sub(objectGB, 10)), rate)
	items["custom_image_storage"] = mul(add(existingGiB, expectedGiB), rate)
	total := add(0)
	formatted := Object{}
	for key, v := range items {
		total.Add(total, rat(v))
		formatted[key] = fixed(v, 4)
	}
	if greater(total, budget["monthly_limit"]) {
		fail("projected USD " + fixed(total, 2) + " exceeds the monthly ceiling")
	}
	return Object{"currency": "USD", "items": formatted, "total": fixed(total, 2), "limit": str(budget["monthly_limit"]), "headroom": fixed(sub(budget["monthly_limit"], total), 2), "object_projected_bytes": projected, "existing_image_billed_gib": ratText(existingGiB), "import_image_billed_gib": ratText(expectedGiB), "assumptions": Object{"object_free_gb": 10, "custom_image_free_gib": 0, "object_growth_reserve_gb": str(budget["object_storage_gb_max"]), "object_staging_reserve_gb": str(budget["staging_object_storage_gb_max"]), "custom_image_rate": str(rate), "object_gb_bytes": 1000000000, "custom_image_size_source": "reviewed maxima plus OCI billableSizeInGBs for completed roles"}}
}
