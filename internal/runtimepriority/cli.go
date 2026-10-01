package runtimepriority

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func parseOptions(args []string) (Object, error) {
	o := Object{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			return nil, fmt.Errorf("unexpected positional argument %s", arg)
		}
		key := strings.ReplaceAll(strings.TrimPrefix(arg, "--"), "-", "_")
		if _, exists := o[key]; exists {
			return nil, fmt.Errorf("repeated option %s", arg)
		}
		if key == "retain_evidence" {
			o[key] = true
			continue
		}
		i++
		if i >= len(args) {
			return nil, fmt.Errorf("%s requires a value", arg)
		}
		value := args[i]
		if strings.HasSuffix(key, "_bytes") || key == "database_pid" {
			n, e := strconv.ParseInt(value, 10, 64)
			if e != nil {
				return nil, fmt.Errorf("%s must be signed integer", arg)
			}
			o[key] = n
		} else {
			o[key] = value
		}
	}
	return o, nil
}
func readRequest(input io.Reader) (Object, error) {
	wire, e := io.ReadAll(io.LimitReader(input, (1<<20)+1))
	if e != nil {
		return nil, e
	}
	if len(wire) > 1<<20 {
		return nil, &DomainError{"HarnessError", "adapter request exceeds fixed input bound"}
	}
	var request Object
	if e := jsonUnmarshal(wire, &request); e != nil {
		return nil, e
	}
	if request == nil {
		return nil, fmt.Errorf("request must be a JSON object")
	}
	return request, nil
}

// Run dispatches the native tools within the single orchestrator executable.
func Run(ctx context.Context, args []string, out io.Writer) (err error) {
	defer recoverError(&err)
	if len(args) == 0 {
		return fmt.Errorf("runtime-priority requires qualify, pressure, probe-admission, adapter, or remote")
	}
	command := args[0]
	args = args[1:]
	switch command {
	case "adapter":
		request, e := readRequest(os.Stdin)
		if e != nil {
			return e
		}
		if str(request, "schema") != AdapterInputSchema {
			return fmt.Errorf("unsupported adapter input schema")
		}
		if e := VerifyTransport(request); e != nil {
			return e
		}
		adapter := Adapter{}
		evidence, e := adapter.Dispatch(ctx, request)
		if e != nil {
			return e
		}
		response := Object{"schema": AdapterResultSchema, "request_id": request["request_id"], "contract_id": request["contract_id"], "role": request["role"], "status": "PASS", "observed_at_utc": utcNow(), "evidence": evidence}
		wire := Canonical(response)
		if len(wire) > 1<<20 {
			return fmt.Errorf("native adapter output exceeds fixed evidence bound")
		}
		_, e = out.Write(append(wire, '\n'))
		return e
	case "remote":
		if len(args) < 1 {
			return fmt.Errorf("remote requires fixed action and admitted probe pins")
		}
		action := args[0]
		pins, e := parseOptions(args[1:])
		if e != nil {
			return e
		}
		source, hash := text(pins["probe_source_revision"], "probe source revision"), text(pins["probe_sha256"], "probe SHA-256")
		probe, e := OpenPinnedProbe("/run/terrascale-d15", source, hash, filepath.Join("/run/terrascale-d15/probes", source, hash, "qualify"), 0)
		if e != nil {
			return e
		}
		defer probe.Close()
		self, e := os.Executable()
		if e != nil {
			return e
		}
		wire, _, e := readNoFollow(self, MaxProbeBytes)
		if e != nil {
			return e
		}
		if Hash(wire) != hash {
			return fmt.Errorf("running remote helper differs from admitted native probe")
		}
		request, e := readRequest(os.Stdin)
		if e != nil {
			return e
		}
		if str(request, "probe_source_revision") != source || str(sub(sub(request, "transport"), "runtime"), "qualify_sha256") != hash {
			return fmt.Errorf("remote request differs from admitted native probe pins")
		}
		remote := Remote{}
		reply, e := remote.Dispatch(ctx, request, action)
		if e != nil {
			return e
		}
		wire = Canonical(reply)
		if len(wire) > 1<<20 {
			return fmt.Errorf("remote output exceeds fixed evidence bound")
		}
		_, e = out.Write(append(wire, '\n'))
		return e
	case "probe-admission":
		options, e := parseOptions(args)
		if e != nil {
			return e
		}
		for _, k := range []string{"probe", "publication", "qualification", "run_detail", "job_log", "release_tag", "out"} {
			text(options[k], "--"+strings.ReplaceAll(k, "_", "-"))
		}
		receipt, e := AdmitProbe(AdmissionPaths{Probe: str(options, "probe"), Publication: str(options, "publication"), Qualification: str(options, "qualification"), RunDetail: str(options, "run_detail"), JobLog: str(options, "job_log"), ReleaseTag: str(options, "release_tag")})
		if e != nil {
			return e
		}
		if e := writeJSON(str(options, "out"), receipt, true); e != nil {
			return e
		}
		fmt.Fprintf(out, "D15 probe admitted: %s\n", str(options, "out"))
		return nil
	case "qualify":
		mode := "qualify"
		if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
			mode, args = args[0], args[1:]
		}
		options, e := parseOptions(args)
		if e != nil {
			return e
		}
		if mode == "render-drop-ins" {
			return RenderDropIns(options, out)
		}
		if mode != "qualify" && mode != "capture" && mode != "probe" {
			return fmt.Errorf("unsupported qualifier mode %s", mode)
		}
		for _, k := range []string{"role", "artifact_id", "oci_instance_id", "image_id", "config_id", "profile_id", "evidence_dir"} {
			text(options[k], k)
		}
		role := str(options, "role")
		if role != "host" && role != "controller" {
			return fmt.Errorf("role must be host or controller")
		}
		for _, k := range []string{"expected_system_slice_memory_min_bytes", "expected_system_slice_memory_low_bytes", "system_reserve_bytes", "allocatable_memory_bytes"} {
			num(options[k], k, 1)
		}
		prefix := "expected_memory_"
		if role == "controller" {
			prefix = "expected_controller_memory_"
			if options["database_pid"] != nil || options["database_memory_max_bytes"] != nil {
				return fmt.Errorf("controller guest cannot qualify TerraBase")
			}
		}
		num(options[prefix+"min_bytes"], prefix+"min_bytes", 1)
		num(options[prefix+"low_bytes"], prefix+"low_bytes", 1)
		if options["database_pid"] != nil {
			num(options["database_pid"], "database_pid", 2)
		}
		if options["database_memory_max_bytes"] != nil {
			num(options["database_memory_max_bytes"], "database_memory_max_bytes", 1)
			if options["database_pid"] == nil {
				return fmt.Errorf("database_memory_max_bytes requires database_pid")
			}
		}
		evidence := str(options, "evidence_dir")
		if e := os.Mkdir(evidence, 0700); e != nil {
			return e
		}
		probe := Qualifier{Args: options}
		started := utcNow()
		summary, e := probe.Run(ctx)
		if e != nil {
			summary = Object{"status": "FAILED", "guest_role": role, "artifact_id": options["artifact_id"], "config_id": options["config_id"], "profile_id": options["profile_id"], "stage": "effective_priority_and_resource_validation", "error": e.Error()}
		}
		summary["started_at_utc"], summary["finished_at_utc"] = started, utcNow()
		if writeErr := os.WriteFile(filepath.Join(evidence, "commands.log"), []byte(strings.Join(probe.Log, "\n")+"\n"), 0600); writeErr != nil {
			return writeErr
		}
		if writeErr := os.WriteFile(filepath.Join(evidence, "summary.json"), pretty(summary), 0600); writeErr != nil {
			return writeErr
		}
		fmt.Fprintf(out, "%s: %s\n", summary["status"], filepath.Join(evidence, "summary.json"))
		return e
	case "pressure":
		if len(args) == 0 {
			return fmt.Errorf("pressure requires dry-run, run, or stress-worker")
		}
		mode := args[0]
		args = args[1:]
		if mode == "resource-worker" {
			return RunResourceWorker(ctx, args, out)
		}
		options, e := parseOptions(args)
		if e != nil {
			return e
		}
		manifest, wire, e := LoadJSON(text(options["manifest"], "--manifest"), 1<<20)
		if e != nil {
			return e
		}
		switch mode {
		case "dry-run":
			plan, e := DryRun(manifest, Hash(wire))
			if e != nil {
				return e
			}
			_, e = out.Write(pretty(plan))
			return e
		case "run":
			status, e := RunQualification(ctx, manifest, wire, Hash(wire), text(options["evidence_dir"], "--evidence-dir"), nil, out)
			if e != nil {
				return e
			}
			if status != 0 {
				return fmt.Errorf("runtime priority qualification did not pass")
			}
			return nil
		case "stress-worker":
			assigned := text(options["assigned_pressure_cgroup"], "--assigned-pressure-cgroup")
			if str(sub(sub(manifest, "pressure"), "workload_cgroup"), "path") != assigned {
				return fmt.Errorf("stress worker assigned scope differs from manifest")
			}
			return RunStressWorker(ctx, manifest, text(options["expected_native_runner_cgroup"], "--expected-native-runner-cgroup"), text(options["protected_database_cgroup"], "--protected-database-cgroup"), text(options["run_id"], "--run-id"), options["retain_evidence"] == true, out)
		default:
			return fmt.Errorf("unsupported pressure mode %s", mode)
		}
	default:
		return fmt.Errorf("unsupported runtime-priority command %s", command)
	}
}
