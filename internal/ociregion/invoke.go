package ociregion

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
)

// Path is a file argument. It remains distinguishable from a textual argument for injected dependencies.
type Path string

// DecodeInvocation converts tagged contract values to the native API argument types.
func DecodeInvocation(v any) any {
	switch v := v.(type) {
	case []any:
		r := make([]any, len(v))
		for i, x := range v {
			r[i] = DecodeInvocation(x)
		}
		return r
	case Object:
		if p, ok := v["$path"]; ok {
			return Path(text(p))
		}
		if b, ok := v["$bytes"]; ok {
			return must(base64.StdEncoding.DecodeString(text(b)))
		}
		if d, ok := v["$decimal"]; ok {
			return rat(d)
		}
		if d, ok := v["$datetime"]; ok {
			t, _ := parseTime(d)
			return t
		}
		if n, ok := v["$namespace"]; ok {
			return DecodeInvocation(n)
		}
		if n, ok := v["$process"]; ok {
			return DecodeInvocation(n)
		}
		r := Object{}
		for k, x := range v {
			r[k] = DecodeInvocation(x)
		}
		return r
	}
	return v
}
func EncodeInvocation(v any) any {
	switch v := v.(type) {
	case Path:
		return Object{"$path": string(v)}
	case []byte:
		return Object{"$bytes": base64.StdEncoding.EncodeToString(v)}
	case time.Time:
		return Object{"$datetime": pythonTime(v)}
	case Object:
		r := Object{}
		for k, x := range v {
			r[k] = EncodeInvocation(x)
		}
		return r
	case []any:
		r := make([]any, len(v))
		for i, x := range v {
			r[i] = EncodeInvocation(x)
		}
		return r
	case []string:
		return arr(v)
	}
	return v
}

// Invoke is the same native API used by the command dispatcher, with optional injected dependencies.
func (e *Engine) Invoke(name string, args []any, kwargs Object) (any, error) {
	return capture(func() any { return e.invoke(name, args, kwargs) })
}
func (e *Engine) invoke(name string, args []any, kw Object) any {
	arg := func(i int) any {
		if i < len(args) {
			return args[i]
		}
		return nil
	}
	option := func(i int, key string, fallback any) any {
		if i < len(args) {
			return args[i]
		}
		if v, ok := kw[key]; ok {
			return v
		}
		return fallback
	}
	now := e.now()
	if t, ok := option(3, "now", nil).(time.Time); ok {
		now = t
	}
	switch name {
	case "main":
		e.run(e.Argv[1:])
		return nil
	case "load_plan":
		path := pathValue(option(0, "path", Path(e.PlanPath)))
		return e.loadPlan(path)
	case "require_ocid":
		return requireOCID(arg(0), str(arg(1)), text(option(2, "region", "")))
	case "oci":
		return e.realOCI(args, kw)
	case "checked_tool":
		return e.realChecked(args)
	case "collect_scoped_images":
		return e.scopedImages(arg(0), arg(1))
	case "collect_inventory":
		return e.collectInventory(obj(arg(0)))
	case "import_inventory":
		return e.importInventory(obj(arg(0)), pathValue(arg(1)), pathValue(arg(2)), pathValue(arg(3)))
	case "estimate":
		age := number(option(4, "max_age_minutes", 15))
		return e.estimate(obj(arg(0)), obj(arg(1)), pathValue(option(2, "plan_path", nil)), now, age)
	case "verify_inventory":
		age := number(option(2, "max_age_minutes", 15))
		if t, ok := option(4, "now", nil).(time.Time); ok {
			now = t
		}
		e.verifyInventory(obj(arg(0)), obj(arg(1)), pathValue(option(3, "plan_path", nil)), now, age)
		return nil
	case "current_object_head":
		return e.currentHead(str(arg(0)), str(arg(1)), str(arg(2)), str(arg(3)))
	case "import_estimate":
		if t, ok := option(7, "now", nil).(time.Time); ok {
			now = t
		}
		return e.importEstimate(obj(arg(0)), obj(arg(1)), pathValue(arg(2)), str(arg(3)), pathValue(option(4, "staged_path", nil)), pathValue(option(5, "imported_path", nil)), pathValue(option(6, "plan_path", nil)), now, number(option(8, "max_age_minutes", 15)), optionalObject(option(9, "base_lineage", nil)))
	case "verify_import_inventory":
		if t, ok := option(3, "now", nil).(time.Time); ok {
			now = t
		}
		e.verifyImportInventory(obj(arg(0)), obj(arg(1)), pathValue(option(2, "plan_path", nil)), now, number(option(4, "max_age_minutes", 15)))
		return nil
	case "reviewed_imports":
		return reviewedImports(obj(arg(0)), obj(arg(1)), pathValue(arg(2)))
	case "verify_previous_import_admission":
		return e.previousAdmission(pathValue(arg(0)), str(arg(1)), str(arg(2)), pathValue(arg(3)), text(option(4, "staged_hash", nil)), text(option(5, "imported_hash", nil)))
	case "establish_base_lineage":
		return e.establishLineage(obj(arg(0)), pathValue(arg(1)), pathValue(arg(2)), pathValue(arg(3)), pathValue(arg(4)), pathValue(arg(5)), pathValue(arg(6)), pathValue(arg(7)))
	case "required_resource_ids":
		return e.requiredIDs(obj(arg(0)))
	case "required_plan_bootstrap_prefix":
		return requiredPrefix(obj(arg(0)))
	case "controller_storage_statements":
		return storageStatements(obj(arg(0)), obj(arg(1)), str(arg(2)))
	case "required_controller_statements":
		return controllerStatements(obj(arg(0)), obj(arg(1)), str(arg(2)))
	case "required_netbird_statements":
		return netbirdStatements(obj(arg(0)))
	case "check_live_compartments":
		e.liveCompartments(obj(arg(0)), obj(arg(1)))
	case "check_live_network":
		e.liveNetwork(obj(arg(0)), obj(arg(1)))
	case "cloudflare_origin_ips":
		ranges, err := publicapi.PublishedOriginIPs(e.ctx())
		if err != nil {
			fail("Cloudflare's published IPv4 ranges: " + err.Error())
		}
		return arr(ranges)
	case "check_live_public_api":
		e.livePublic(obj(arg(0)), obj(arg(1)))
	case "check_live_operator_gateway":
		e.liveOperator(obj(arg(0)), obj(arg(1)))
	case "check_live_netbird_iam":
		e.liveNetbirdIAM(obj(arg(0)))
	case "check_live_iam":
		e.liveIAM(obj(arg(0)), obj(arg(1)), str(arg(2)))
	case "check_live_vault":
		e.liveVault(obj(arg(0)), obj(arg(1)))
	case "check_live_buckets":
		return e.liveBuckets(obj(arg(0)), obj(arg(1)))
	case "create_identity":
		return createIdentity(obj(arg(0)), pathValue(arg(1)), obj(arg(2)))
	case "canonical_manual_seed_plan":
		return canonicalSeed(obj(arg(0)))
	case "seed_launch":
		return e.seedLaunch(obj(arg(0)), pathValue(arg(1)), pathValue(arg(2)), pathValue(arg(3)), pathValue(arg(4)), pathValue(arg(5)), pathValue(arg(6)), pathValue(arg(7)), pathValue(arg(8)))
	case "verify_seed_preflight":
		return e.verifySeed(obj(arg(0)), pathValue(arg(1)), pathValue(arg(2)), obj(arg(3)), obj(arg(4)), pathValue(arg(5)), str(arg(6)), pathValue(option(7, "plan_path", nil)))
	case "seed_preflight":
		return e.seedPreflight(obj(arg(0)), obj(arg(1)), pathValue(arg(2)))
	case "inspect_foundation":
		return e.inspectFoundation(obj(arg(0)), pathValue(arg(1)), pathValue(arg(2)), pathValue(arg(3)))
	case "inspect_private_peer":
		paths := make([]string, len(args))
		for i, v := range args {
			paths[i] = pathValue(v)
		}
		return e.inspectPrivatePeer(paths)
	default:
		fail(fmt.Sprintf("unknown OCI region API %q", name))
	}
	return nil
}
func optionalObject(v any) Object {
	if v == nil {
		return nil
	}
	return obj(v)
}
