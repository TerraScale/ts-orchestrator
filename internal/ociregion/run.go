package ociregion

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

func (e *Engine) Run(args []string, out io.Writer) error {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			_, err := fmt.Fprintln(out, `Usage: ts-orch oci-region preview <command> [flags]

Read-only inventory and admission commands:
  inventory, admit, estimate, seed-preflight, seed-launch
  inspect-foundation, inspect-private-peer
  import-inventory, import-admit, import-reconcile

Use --plan PLAN.json --inventory INVENTORY.json --admission ADMISSION.json.
Write records with --out PATH; import admission also requires --projection PATH.
Private peer inspection requires --pair-intent and both regional --left-* and --right-* evidence paths.`)
			return err
		}
	}

	_, err := capture(func() bool { e.Stdout = out; e.run(args); return true })
	return err
}
func PreviewRun(ctx context.Context, args []string, out, errOut io.Writer) int {
	e := &Engine{Context: ctx, PlanPath: "deploy/oci-region/plan.json"}
	if err := e.Run(args, out); err != nil {
		fmt.Fprintln(errOut, "oci-preview:", err)
		return 1
	}
	return 0
}
func (e *Engine) print(v any) {
	if e.Stdout == nil {
		return
	}
	fmt.Fprintln(e.Stdout, string(must(json.Marshal(v, json.Deterministic(true), jsontext.Multiline(true)))))
}
func (e *Engine) run(argv []string) {
	if len(argv) == 0 {
		fail("OCI preview requires a command")
	}
	command := argv[0]
	f := flag.NewFlagSet("oci-preview", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	args := Object{}
	root := filepath.Dir(e.PlanPath)
	if e.PlanPath == "" {
		e.PlanPath = "deploy/oci-region/plan.json"
		root = "deploy/oci-region"
	}
	defaults := map[string]string{"plan": e.PlanPath, "inventory": filepath.Join(root, "inventory.json"), "admission": filepath.Join(root, "admission.json")}
	for _, name := range []string{"plan", "inventory", "out", "admission", "pair-intent", "left-plan", "left-inventory", "left-admission", "right-plan", "right-inventory", "right-admission", "bootstrap-tool", "anchor", "manifest", "identity", "image-ocid", "release-tool", "image-receipt", "release-delegation", "release-root", "image-file", "base-image-file", "kernel-file", "owner-ssh-public-key", "reviewed-plan", "host-enrollment", "projection", "phase", "staged-versions", "imported-images", "previous-admission", "previous-projection", "previous-inventory", "previous-imported-images", "previous-staged-versions"} {
		args[strings.ReplaceAll(name, "-", "_")] = defaults[name]
		f.Func(name, "", func(v string) error { args[strings.ReplaceAll(name, "-", "_")] = v; return nil })
	}
	args["bootstrap_root"] = []any{}
	f.Func("bootstrap-root", "", func(v string) error {
		args["bootstrap_root"] = append(arr(args["bootstrap_root"]), Path(v))
		return nil
	})
	for _, name := range []string{"legacy-bootstrap-tool", "legacy-release-tool"} {
		args[strings.ReplaceAll(name, "-", "_")] = false
		f.BoolFunc(name, "", func(v string) error { args[strings.ReplaceAll(name, "-", "_")] = v == "true"; return nil })
	}
	if err := f.Parse(argv[1:]); err != nil {
		panic(err)
	}
	if f.NArg() > 0 {
		fail("unexpected OCI preview arguments")
	}
	get := func(k string) string { return text(args[k]) }
	require := func(message string, names ...string) {
		for _, k := range names {
			if !truth(args[k]) {
				fail(message)
			}
		}
	}
	path := get("plan")
	if command == "inspect-private-peer" {
		require("private peer inspection requires pair intent, both regional plans, inventories, admissions, and --out", "pair_intent", "left_plan", "left_inventory", "left_admission", "right_plan", "right_inventory", "right_admission", "out")
		result := e.inspectPrivatePeer([]string{get("pair_intent"), get("left_plan"), get("left_inventory"), get("left_admission"), get("right_plan"), get("right_inventory"), get("right_admission")})
		writeJSON(get("out"), result)
		if e.Stdout != nil {
			fmt.Fprintf(e.Stdout, "private peer configuration readback PASS cells=%s budget_admission=%s\n", strings.Join(keys(obj(result["cells"])), ","), strings.ToUpper(text(obj(result["budget_admission"])["status"])))
		}
		return
	}
	plan := e.loadPlan(path)
	if command == "seed-launch" {
		require("seed launch requires --reviewed-plan, --manifest, --identity, --anchor, --host-enrollment and --out", "reviewed_plan", "manifest", "identity", "anchor", "host_enrollment", "out")
		launch := e.seedLaunch(plan, get("reviewed_plan"), get("manifest"), get("identity"), get("anchor"), get("host_enrollment"), get("owner_ssh_public_key"))
		wire := append(must(json.Marshal(launch, json.Deterministic(true), jsontext.Multiline(true))), '\n')
		writeBytes(get("out"), wire, 0600)
		if e.Stdout != nil {
			fmt.Fprintf(e.Stdout, "wrote controller-a launch input bytes=%d sha256=%s\n", len(wire), wireSHA(wire))
		}
		return
	}
	if command == "seed-preflight" {
		require("seed preflight requires signed bootstrap, release image, and exact image candidate inputs", "bootstrap_tool", "anchor", "manifest", "identity", "image_ocid", "release_tool", "image_receipt", "release_delegation", "release_root", "image_file", "base_image_file", "kernel_file", "out")
		for _, k := range []string{"bootstrap_tool", "anchor", "manifest", "identity", "release_tool", "image_receipt", "release_delegation", "release_root", "image_file", "base_image_file", "kernel_file", "inventory", "admission"} {
			args[k] = Path(get(k))
		}
		result := e.seedPreflight(args, plan, must(filepath.Abs(path)))
		wire := canonicalSeed(result)
		if len(wire) > 16*1024 {
			fail("manual seed plan exceeds the bounded Go consumer input")
		}
		writeBytes(get("out"), wire, 0600)
		if e.Stdout != nil {
			fmt.Fprintf(e.Stdout, "wrote reviewed manual seed plan slot=controller-a sha256=%s\n", wireSHA(wire))
		}
		return
	}
	if command == "inventory" {
		snapshot := e.collectInventory(plan)
		out := get("out")
		if out == "" {
			out = get("inventory")
		}
		writeJSON(out, snapshot)
		if e.Stdout != nil {
			fmt.Fprintf(e.Stdout, "captured %d OCI resources and %d buckets\n", len(arr(snapshot["resources"])), len(arr(snapshot["buckets"])))
		}
		return
	}
	if command == "import-inventory" {
		snapshot := e.importInventory(plan, get("projection"), get("staged_versions"), get("previous_projection"))
		e.verifyImportInventory(plan, snapshot, must(filepath.Abs(path)), e.now(), 15)
		out := get("out")
		if out == "" {
			out = get("inventory")
		}
		writeJSON(out, snapshot)
		if e.Stdout != nil {
			fmt.Fprintf(e.Stdout, "captured %d scoped images and %d detailed buckets\n", len(arr(snapshot["images"])), len(arr(snapshot["buckets"])))
		}
		return
	}
	if command == "inspect-foundation" {
		require("foundation inspection requires --out", "out")
		result := e.inspectFoundation(plan, must(filepath.Abs(path)), get("inventory"), get("admission"))
		writeJSON(get("out"), result)
		if e.Stdout != nil {
			fmt.Fprintf(e.Stdout, "foundation readback PASS region=%s inventory=%s\n", str(plan["region"]), str(result["inventory_sha256"]))
		}
		return
	}
	if command == "import-admit" || command == "import-reconcile" {
		require("import admission requires --projection and --out", "projection", "out")
		phase := get("phase")
		if command == "import-reconcile" {
			phase = "post-import"
		}
		if phase == "" {
			fail("import-admit requires --phase")
		}
		inventory := readJSON(get("inventory"), 4*1024*1024, "manual region import inventory")
		imports := reviewedImports(plan, inventory, get("projection"))
		var lineage Object
		full := sameRoles(keys(imports), "base", "final")
		if full {
			if get("previous_projection") != "" {
				if phase != "pre-stage" || get("staged_versions") != "" || get("previous_admission") == "" || get("previous_inventory") == "" || get("previous_staged_versions") == "" || get("previous_imported_images") == "" {
					fail("base-only lineage requires the first full pre-stage admission and all prior evidence")
				}
				lineage = e.establishLineage(plan, get("projection"), get("previous_projection"), get("previous_inventory"), get("previous_admission"), get("previous_staged_versions"), get("previous_imported_images"), must(filepath.Abs(path)))
			} else if get("previous_admission") != "" {
				if phase == "pre-stage" && get("staged_versions") == "" {
					fail("first full pre-stage admission requires the exact previous base-only projection")
				}
				previous := readJSON(get("previous_admission"), 64*1024, "previous import admission")
				lineage = carriedLineage(previous["base_lineage"], fileSHA(path))
			} else {
				fail("full import projection requires a verified base-only admission lineage")
			}
		} else if get("previous_projection") != "" || get("previous_inventory") != "" {
			fail("base-only projection cannot accept a prior base projection lineage")
		}
		preceding := ""
		if phase == "pre-stage" && get("staged_versions") != "" {
			preceding = "pre-stage"
		} else if phase == "pre-import" && get("imported_images") == "" {
			preceding = "pre-stage"
		} else if phase == "pre-import" || phase == "post-import" {
			preceding = "pre-import"
		}
		if preceding != "" {
			if get("staged_versions") == "" || get("previous_admission") == "" {
				fail("later import admission requires staged versions and previous admission")
			}
			stagedHash := ""
			if get("previous_staged_versions") != "" {
				stagedHash = fileSHA(get("previous_staged_versions"))
			} else if preceding == "pre-import" {
				stagedHash = fileSHA(get("staged_versions"))
			}
			previous := e.previousAdmission(get("previous_admission"), preceding, fileSHA(get("projection")), must(filepath.Abs(path)), stagedHash, "")
			if full {
				lineage = carriedLineage(previous["base_lineage"], fileSHA(path))
			}
			if phase == "pre-import" && get("imported_images") == "" && previous["staged_versions_sha256"] != nil {
				if get("previous_staged_versions") == "" {
					fail("pre-import requires the preceding base object version receipt")
				}
				if previous["staged_versions_sha256"] != fileSHA(get("previous_staged_versions")) {
					fail("preceding base object receipt changed")
				}
				base, current := importReceipt(get("previous_staged_versions"), "versions", fileSHA(get("projection")), []string{"base"}), importReceipt(get("staged_versions"), "versions", fileSHA(get("projection")), keys(imports))
				if base["base"] != current["base"] {
					fail("staged receipt changed the admitted base object version")
				}
			}
			if phase == "pre-import" && get("imported_images") != "" && previous["imported_images_sha256"] != nil {
				fail("base readback requires the preceding two-maximum pre-import admission")
			}
			if phase == "post-import" {
				if !full {
					if get("previous_imported_images") == "" || !truth(previous["imported_images_sha256"]) {
						fail("base reconciliation requires the preceding image readback admission and receipt")
					}
					if fileSHA(get("previous_imported_images")) != previous["imported_images_sha256"] {
						fail("preceding base image receipt changed")
					}
					base, final := importReceipt(get("previous_imported_images"), "images", fileSHA(get("projection")), []string{"base"}), importReceipt(get("imported_images"), "images", fileSHA(get("projection")), []string{"base"})
					if base["base"] != final["base"] {
						fail("final image receipt changed the admitted base image OCID")
					}
				} else if lineage == nil {
					fail("final reconciliation lacks the carried base image readback")
				}
			}
		}
		if full && lineage == nil {
			fail("full import admission lacks the carried base-only lineage")
		}
		result := e.importEstimate(plan, inventory, get("projection"), phase, get("staged_versions"), get("imported_images"), must(filepath.Abs(path)), e.now(), 15, lineage)
		now := e.now()
		optionalSHA := func(k string) any {
			if get(k) == "" {
				return nil
			}
			return fileSHA(get(k))
		}
		admission := Object{"schema_version": 3, "phase": phase, "admitted_at": pythonTime(now), "expires_at": pythonTime(now.Add(15 * time.Minute)), "plan_sha256": fileSHA(path), "inventory_sha256": fileSHA(get("inventory")), "projection_sha256": fileSHA(get("projection")), "staged_versions_sha256": optionalSHA("staged_versions"), "imported_images_sha256": optionalSHA("imported_images"), "previous_admission_sha256": optionalSHA("previous_admission"), "base_lineage": lineage, "estimate": result}
		writeJSON(get("out"), admission)
		e.print(admission)
		return
	}
	if command != "admit" && command != "estimate" {
		fail("unknown OCI preview command " + command)
	}
	inventory := readJSON(get("inventory"), 4*1024*1024, "manual region inventory")
	result := e.estimate(plan, inventory, must(filepath.Abs(path)), e.now(), 15)
	if command == "admit" {
		require("admit requires --out", "out")
		result = Object{"schema_version": 2, "admitted_at": pythonTime(e.now()), "expires_at": pythonTime(e.now().Add(15 * time.Minute)), "plan_sha256": fileSHA(path), "inventory_sha256": fileSHA(get("inventory")), "preview_compartment_ids": inventory["preview_compartment_ids"], "estimate": result}
		writeJSON(get("out"), result)
	}
	e.print(result)
}
