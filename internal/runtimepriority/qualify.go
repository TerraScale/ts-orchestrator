package runtimepriority

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Qualifier dependencies default to the live guest. Tests supply isolated roots
// and a command executor, without replacing any qualification decision.
type Qualifier struct {
	Args                                                    Object
	BakedProfile                                            func() (Object, error)
	CgroupRoot, ProcRoot, ProfilePath, UnitRoot, Executable string
	Command                                                 func(context.Context, []string) (string, error)
	AfterDirectoryOpen                                      func(string)
	ChildVisited                                            func(string)
	Log                                                     []string
}

func RenderDropIns(args Object, out io.Writer) (err error) {
	defer recoverError(&err)
	keys := []string{"service_memory_min_bytes", "service_memory_low_bytes", "controller_memory_min_bytes", "controller_memory_low_bytes", "system_slice_memory_min_bytes", "system_slice_memory_low_bytes", "system_reserve_bytes"}
	for _, k := range keys {
		v := num(args[k], k, 1)
		if v%int64(os.Getpagesize()) != 0 {
			qfail("drop-in memory values must be positive, page-aligned bytes")
		}
	}
	mi, lo, cmi, clo, smi, slo, res := n(args, keys[0]), n(args, keys[1]), n(args, keys[2]), n(args, keys[3]), n(args, keys[4]), n(args, keys[5]), n(args, keys[6])
	if mi > lo || cmi > clo || smi > slo || slo > res {
		qfail("service/controller/system.slice floors must satisfy MemoryMin <= MemoryLow <= signed SystemReserveBytes")
	}
	if smi < mi+cmi || slo < lo+clo {
		qfail("system.slice floors must cover aggregate host and controller child floors")
	}
	id := str(args, "profile_id")
	if !tokenRE.MatchString(id) {
		qfail("profile ID must be a 1-128 character safe token")
	}
	root := str(args, "output_root")
	if !filepath.IsAbs(root) {
		qfail("--output-root must be an absolute image staging path")
	}
	resolved, e := filepath.EvalSymlinks(root)
	if e == nil {
		root = resolved
	}
	root = filepath.Clean(root)
	for _, path := range []string{"/", "/etc", "/usr", "/lib"} {
		if root == path || (path != "/" && inside(root, path)) {
			qfail("refusing to write systemd drop-ins into a live system directory")
		}
	}
	header := fmt.Sprintf("# Profile: %s\n# Signed SystemReserveBytes: %d\n# Explicit image-profile allocations; adequacy requires target pressure qualification.\n", id, res)
	for _, row := range []struct {
		unit, section string
		mi, lo        int64
	}{{"system.slice", "Slice", smi, slo}, {HostUnit, "Service", mi, lo}, {ControllerUnit, "Service", cmi, clo}} {
		path := filepath.Join(root, "etc/systemd/system", row.unit+".d/50-terrascale-memory-protection.conf")
		wire := []byte(fmt.Sprintf("%s[%s]\nMemoryMin=%d\nMemoryLow=%d\n", header, row.section, row.mi, row.lo))
		if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			return e
		}
		if old, e := os.ReadFile(path); e == nil {
			if string(old) != string(wire) {
				qfail("refusing to replace conflicting image profile drop-in: %s", path)
			}
		} else if os.IsNotExist(e) {
			f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
			if e != nil {
				return e
			}
			_, e = f.Write(wire)
			f.Close()
			if e != nil {
				return e
			}
		} else {
			return e
		}
		fmt.Fprintf(out, "%s sha256=%s\n", path, Hash(wire))
	}
	return
}
