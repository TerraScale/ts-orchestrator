package hostload

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestReportFilesystemValidation(t *testing.T) {
	valid := observability.FilesystemView{Role: "terrabase_data", Path: "/srv/terrabase/data",
		SizeBytes: 1024, AvailBytes: 256, FreeBytes: 384, Files: 100, FilesFree: 50, Device: 42}
	for name, change := range map[string]func(*observability.FilesystemView){
		"missing role":           func(f *observability.FilesystemView) { f.Role = "" },
		"invalid role":           func(f *observability.FilesystemView) { f.Role = "data.*" },
		"long role":              func(f *observability.FilesystemView) { f.Role = strings.Repeat("a", 64) },
		"uppercase role":         func(f *observability.FilesystemView) { f.Role = "DATA" },
		"relative path":          func(f *observability.FilesystemView) { f.Path = "data" },
		"unclean path":           func(f *observability.FilesystemView) { f.Path = "/srv/../data" },
		"control path":           func(f *observability.FilesystemView) { f.Path = "/data\x00" },
		"unicode control path":   func(f *observability.FilesystemView) { f.Path = "/data\u0085" },
		"invalid UTF8":           func(f *observability.FilesystemView) { f.Path = "/data\xff" },
		"long path":              func(f *observability.FilesystemView) { f.Path = "/" + strings.Repeat("a", 4096) },
		"zero size":              func(f *observability.FilesystemView) { f.SizeBytes = 0 },
		"size bound":             func(f *observability.FilesystemView) { f.SizeBytes = MaxFilesystemBytes + 1 },
		"available exceeds free": func(f *observability.FilesystemView) { f.AvailBytes = f.FreeBytes + 1 },
		"free exceeds size":      func(f *observability.FilesystemView) { f.FreeBytes = f.SizeBytes + 1 },
		"free inode count":       func(f *observability.FilesystemView) { f.FilesFree = f.Files + 1 },
		"inode bound":            func(f *observability.FilesystemView) { f.Files = MaxFilesystemBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			filesystem := valid
			change(&filesystem)
			report := Report{SchemaVersion: SchemaVersion, Host: HostUsage{Filesystems: []observability.FilesystemView{filesystem}}}
			if err := report.Validate(); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("malformed filesystem accepted: %v", err)
			}
		})
	}
	for _, count := range []int{MaxFilesystems, MaxFilesystems + 1} {
		report := Report{SchemaVersion: SchemaVersion}
		for i := range count {
			filesystem := valid
			filesystem.Role = fmt.Sprintf("volume-%d", i)
			report.Host.Filesystems = append(report.Host.Filesystems, filesystem)
		}
		if err := report.Validate(); (err == nil) != (count == MaxFilesystems) {
			t.Fatalf("filesystem count %d: %v", count, err)
		}
	}
	report := Report{SchemaVersion: SchemaVersion, Host: HostUsage{Filesystems: []observability.FilesystemView{valid, valid}}}
	if err := report.Validate(); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("duplicate filesystem role accepted: %v", err)
	}
}

func TestSamplerPreservesBoundedFilesystemIdentity(t *testing.T) {
	view := observability.SystemView{CPUCount: 8, MemTotalBytes: 16 << 30,
		Filesystems: []observability.FilesystemView{
			{Role: "state", Path: "/state", SizeBytes: 100, AvailBytes: 80, FreeBytes: 90, Device: 1},
			{Role: "terrabase_data", Path: "/data", SizeBytes: 1000, AvailBytes: 250, FreeBytes: 300, Device: 2},
			{Role: "terrabase_data", Path: "/duplicate", SizeBytes: 1000, Device: 3},
			{Role: "unreadable", Path: "/unreadable"},
			{Role: "malformed", Path: "/malformed", SizeBytes: 1, AvailBytes: 2},
		}}
	want := slices.Clone(view.Filesystems[:2])
	sampler := NewSampler(SamplerConfig{ReadSystem: func([]observability.FilesystemRole) (observability.SystemView, error) {
		return view, nil
	}})
	report := sampler.Sample(nil)
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var restored Report
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.Host.Filesystems, want) || restored.Host.Disk == nil || *restored.Host.Disk != .75 ||
		restored.Host.CPUCores != 8 || restored.Host.MemoryBytes != 16<<30 || !restored.Host.FilesystemsIncomplete {
		t.Fatalf("filesystem identity/capacity lost: %+v", restored.Host)
	}
	for i := range MaxFilesystems + 1 {
		view.Filesystems = append(view.Filesystems, observability.FilesystemView{
			Role: fmt.Sprintf("volume-%d", i), Path: fmt.Sprintf("/volume-%d", i), SizeBytes: MaxFilesystemBytes})
	}
	view.CPUCount, view.MemTotalBytes = MaxCPUCores+1, MaxMemoryBytes+1
	bounded := sampler.Sample(nil)
	if len(bounded.Host.Filesystems) != MaxFilesystems || bounded.Host.CPUCores != 0 || bounded.Host.MemoryBytes != 0 || !bounded.Host.FilesystemsIncomplete {
		t.Fatalf("unbounded host observation: %+v", bounded.Host)
	}
	if err := bounded.Validate(); err != nil {
		t.Fatal(err)
	}
}
