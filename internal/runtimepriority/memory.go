package runtimepriority

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

type MemoryValidation struct {
	Identity                                                     Object
	GuestRole, ServiceCgroup, BootID, SystemdVersion, CgroupRoot string
	NotBefore, NotAfter                                          time.Time
}

func ValidateMemorySample(sample Object, v MemoryValidation) (result Object, err error) {
	defer recoverError(&err)
	if v.CgroupRoot == "" {
		v.CgroupRoot = CgroupRoot
	}
	if !exact(sample, "schema", "guest_role", "oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id", "host_boot_id", "kernel_release", "systemd_version", "started_at_utc", "finished_at_utc", "scopes", "system_slice_direct_child_cgroups", "sample_sha256") {
		fail("memory usage sample fields differ from pinned schema")
	}
	if str(sample, "schema") != MemorySampleSchema {
		fail("memory usage sample schema unsupported")
	}
	if (v.GuestRole != "host" && v.GuestRole != "controller") || str(sample, "guest_role") != v.GuestRole {
		fail("memory usage sample guest role differs from pinned target")
	}
	for _, k := range []string{"oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id"} {
		if sample[k] != v.Identity[k] {
			fail("memory usage sample %s differs from the pinned target", k)
		}
	}
	if !uuidRE.MatchString(str(sample, "host_boot_id")) || str(sample, "host_boot_id") != v.BootID {
		fail("memory usage sample boot ID differs from accepted guest")
	}
	text(sample["kernel_release"], "memory usage sample kernel_release")
	if str(sample, "systemd_version") != v.SystemdVersion {
		fail("memory usage sample systemd version differs from packaged qualifier")
	}
	started, finished := timestamp(sample["started_at_utc"], "memory sample start"), timestamp(sample["finished_at_utc"], "memory sample finish")
	if v.NotBefore.After(started) || started.After(finished) || finished.After(v.NotAfter) {
		fail("memory usage sample is stale or outside its exact qualification request")
	}
	scopes := sub(sample, "scopes")
	serviceScope := v.GuestRole + "_service"
	if !exact(scopes, serviceScope, "system_slice") {
		fail("memory usage sample must contain selected service and system.slice scopes")
	}
	if !filepath.IsAbs(v.ServiceCgroup) || filepath.Base(filepath.Dir(v.ServiceCgroup)) != "system.slice" {
		fail("qualified service cgroup outside expected system.slice")
	}
	for scope, path := range map[string]string{serviceScope: v.ServiceCgroup, "system_slice": filepath.Dir(v.ServiceCgroup)} {
		row := sub(scopes, scope)
		if !exact(row, "cgroup_path", "cgroup_inode", "memory_current_raw", "memory_current_bytes", "memory_peak_raw", "memory_peak_bytes", "memory_stat_raw", "memory_stat_sha256") {
			fail("memory usage sample %s fields differ from pinned schema", scope)
		}
		if str(row, "cgroup_path") != path || !safePath(path) || !inside(path, v.CgroupRoot) {
			fail("memory usage sample %s cgroup differs from the exact unit scope", scope)
		}
		num(row["cgroup_inode"], "memory sample cgroup inode", 1)
		for _, kind := range []string{"current", "peak"} {
			raw := text(row["memory_"+kind+"_raw"], "memory sample counter")
			if len(raw) > 128 {
				fail("memory usage sample %s counter exceeds its fixed evidence bound", scope)
			}
			value := strings.TrimSuffix(raw, "\n")
			if !decimalRE.MatchString(value) {
				fail("memory usage sample counter must be decimal bytes")
			}
			if integerText(value, "memory sample counter") != num(row["memory_"+kind+"_bytes"], "memory sample counter bytes", 0) {
				fail("memory usage sample counter differs from raw cgroup value")
			}
		}
		if n(row, "memory_peak_bytes") < n(row, "memory_current_bytes") {
			fail("memory usage sample peak below current usage")
		}
		raw := text(row["memory_stat_raw"], "memory sample stat")
		if len(raw) > 16384 {
			fail("memory usage sample %s memory.stat exceeds its fixed evidence bound", scope)
		}
		statValues(raw)
		if !hashRE.MatchString(str(row, "memory_stat_sha256")) || Hash([]byte(raw)) != str(row, "memory_stat_sha256") {
			fail("memory usage sample memory.stat hash differs from raw value")
		}
	}
	children := stringsList(sample["system_slice_direct_child_cgroups"], "memory sample child scopes")
	if len(children) > 256 {
		fail("memory usage sample system.slice child list exceeds its fixed evidence bound")
	}
	size := 0
	for _, name := range children {
		if name == "" {
			fail("memory usage sample child list malformed")
		}
		size += len(name)
	}
	if size > 16384 {
		fail("memory usage sample child list exceeds its fixed evidence bound")
	}
	if !slices.IsSorted(children) || len(slices.Compact(slices.Clone(children))) != len(children) {
		fail("memory usage sample child list malformed or unordered")
	}
	if !slices.Contains(children, filepath.Base(v.ServiceCgroup)) {
		fail("memory usage sample system.slice does not list protected service cgroup")
	}
	unhashed := clone(sample)
	delete(unhashed, "sample_sha256")
	if !hashRE.MatchString(str(sample, "sample_sha256")) || Hash(Canonical(unhashed)) != str(sample, "sample_sha256") {
		fail("memory usage sample hash differs from its canonical contents")
	}
	return sample, nil
}
func stringsList(value any, label string) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = text(s, label)
		}
		return out
	default:
		fail("%s must be an array", label)
	}
	return nil
}
func statValues(raw string) Object {
	o := Object{}
	for line := range strings.SplitSeq(strings.TrimSuffix(raw, "\n"), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || !regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(f[0]) || !decimalRE.MatchString(f[1]) {
			fail("memory.stat must contain unique key and nonnegative decimal value rows")
		}
		if _, ok := o[f[0]]; ok {
			fail("memory.stat repeats key %q", f[0])
		}
		o[f[0]] = integerText(f[1], "memory.stat")
	}
	if len(o) == 0 {
		fail("memory.stat empty")
	}
	return o
}
