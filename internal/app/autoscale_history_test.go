package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

func TestHostResourceHistorySkipsMissingAndStaleMeasurements(t *testing.T) {
	now := time.Now()
	load := hostload.NewAggregator(hostload.AggregatorConfig{Now: func() time.Time { return now }})
	cpu, memory, disk, cores := 0.4, 0.7, 0.2, 1.5
	bytes := uint64(128 << 20)
	if err := load.Record(hostload.Origin{Cell: "gru", Environment: "prod", Node: "Host-A"},
		hostload.Report{SchemaVersion: hostload.SchemaVersion,
			Host:  hostload.HostUsage{CPU: &cpu, Memory: &memory, Disk: &disk},
			Roles: []hostload.RoleUsage{{Role: "api", CPUCores: &cores, MemoryBytes: &bytes}, {Role: "unmeasured"}}}); err != nil {
		t.Fatal(err)
	}
	if err := load.Record(hostload.Origin{Cell: "gru", Environment: "prod", Node: "host-b"},
		hostload.Report{SchemaVersion: hostload.SchemaVersion}); err != nil {
		t.Fatal(err)
	}
	samples := hostLoadSamples(load)
	if len(samples) != 9 {
		t.Fatalf("resource samples = %+v, want measured values and both controller receive times", samples)
	}
	history := observability.NewHistory(observability.HistoryConfig{})
	history.Append(now, samples)
	for _, want := range []struct {
		metric  string
		value   float64
		service string
	}{{observability.HistHostCPUUtilization, cpu, ""},
		{observability.HistHostMemoryRatio, memory, ""},
		{observability.HistHostDiskRatio, disk, ""},
		{observability.HistHostReceivedAt, float64(now.UnixMilli()), ""},
		{observability.HistHostFSIncomplete, 0, ""},
		{observability.HistServiceCPUCores, cores, "api"},
		{observability.HistServiceMemoryUsed, float64(bytes), "api"}} {
		labels := map[string]string{"member": "host-a"}
		if want.service != "" {
			labels["service"] = want.service
		}
		result := history.Range(observability.HistoryQuery{Metric: want.metric, Labels: labels,
			Start: now.Add(-time.Minute), End: now})
		if len(result.Series) != 1 || len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != want.value {
			t.Fatalf("%s history = %+v, want %v for host-a/%s", want.metric, result, want.value, want.service)
		}
	}
	result := history.Range(observability.HistoryQuery{Metric: observability.HistHostReceivedAt,
		Labels: map[string]string{"member": "host-b"}, Start: now.Add(-time.Minute), End: now})
	if len(result.Series) != 1 || len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != float64(now.UnixMilli()) {
		t.Fatalf("empty host report lost controller receive time: %+v", result)
	}
	now = now.Add(hostload.DefaultStaleAfter + time.Second)
	if samples := hostLoadSamples(load); len(samples) != 0 {
		t.Fatalf("stale reports still charted = %+v", samples)
	}
	if samples := hostLoadSamples(nil); len(samples) != 0 {
		t.Fatalf("disabled telemetry = %+v", samples)
	}
}

func TestHostCapacityAndFilesystemCollectorArchiveReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(observability.HostMetricInterval)
	filesystem := observability.FilesystemView{Role: "terrabase_data", Path: "/srv/terrabase/data",
		SizeBytes: 1000, AvailBytes: 250, FreeBytes: 300, Files: 100, FilesFree: 50, Device: 42}
	filesystems := []observability.FilesystemView{
		{Role: "boot", Path: "/", SizeBytes: 100, AvailBytes: 90, FreeBytes: 95, Files: 20, FilesFree: 15},
		{Role: "state", Path: "/state", SizeBytes: 200, AvailBytes: 100, FreeBytes: 120,
			Files: 200, FilesFree: 175, Device: ^uint64(0)},
		filesystem,
	}
	sampler := hostload.NewSampler(hostload.SamplerConfig{
		ReadSystem: func([]observability.FilesystemRole) (observability.SystemView, error) {
			return observability.SystemView{CPUCount: 8, MemTotalBytes: 16 << 30, MemAvailBytes: 4 << 30,
				Filesystems: append(slices.Clone(filesystems), observability.FilesystemView{Role: "unreadable", Path: "/missing"})}, nil
		}})
	data, err := json.Marshal(sampler.Sample(nil))
	if err != nil {
		t.Fatal(err)
	}
	var report hostload.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.Host.Filesystems, filesystems) || !report.Host.FilesystemsIncomplete {
		t.Fatalf("serialized filesystem identity lost: %+v", report.Host)
	}
	fence := &metricTestFence{}
	fence.set(authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)})
	receivedAt := now.Add(39 * time.Second)
	controllerNow := receivedAt
	load := &hostTelemetry{fencer: fence, load: hostload.NewAggregator(hostload.AggregatorConfig{
		Now: func() time.Time { return controllerNow },
	})}
	if err := load.record(hostload.Origin{Cell: "gru", Environment: "prod", Node: "Host-A"}, report); err != nil {
		t.Fatal(err)
	}
	// Keep malformed values typed until production admission rejects them.
	manyRoles := hostload.Report{SchemaVersion: hostload.SchemaVersion}
	for range hostload.MaxRoles + 1 {
		manyRoles.Roles = append(manyRoles.Roles, hostload.RoleUsage{Role: "r"})
	}
	invalid := map[string]hostload.Report{
		"version":        {SchemaVersion: 2},
		"host above one": {SchemaVersion: 1, Host: hostload.HostUsage{CPU: new(1.5)}},
		"host NaN":       {SchemaVersion: 1, Host: hostload.HostUsage{Disk: new(math.NaN())}},
		"role token":     {SchemaVersion: 1, Roles: []hostload.RoleUsage{{Role: "API"}}},
		"repeated role":  {SchemaVersion: 1, Roles: []hostload.RoleUsage{{Role: "api"}, {Role: "api"}}},
		"negative cores": {SchemaVersion: 1, Roles: []hostload.RoleUsage{{Role: "api", CPUCores: new(-1.0)}}},
		"infinite cores": {SchemaVersion: 1, Roles: []hostload.RoleUsage{{Role: "api", CPUCores: new(math.Inf(1))}}},
		"memory":         {SchemaVersion: 1, Roles: []hostload.RoleUsage{{Role: "api", MemoryBytes: new(uint64(hostload.MaxMemoryBytes + 1))}}},
		"terrabase":      {SchemaVersion: 1, Roles: []hostload.RoleUsage{{Role: "tb", TerraBase: &memberstatus.Load{WriteQPS: -1}}}},
		"too many roles": manyRoles,
	}
	for name, host := range map[string]hostload.HostUsage{
		"negative rx":      {NetworkRxBps: new(-1.0)},
		"NaN tx":           {NetworkTxBps: new(math.NaN())},
		"rate above bound": {NetworkRxBps: new(hostload.MaxNetworkBps + 1.0)},
		"negative load":    {Load1: new(-0.1)},
		"infinite load":    {Load1: new(math.Inf(1))},
		"load above bound": {Load1: new(hostload.MaxLoad1 + 1)},
	} {
		invalid[name] = hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: host}
	}
	validFilesystem := observability.FilesystemView{Role: "terrabase_data", Path: "/srv/terrabase/data",
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
		"size bound":             func(f *observability.FilesystemView) { f.SizeBytes = hostload.MaxFilesystemBytes + 1 },
		"available exceeds free": func(f *observability.FilesystemView) { f.AvailBytes = f.FreeBytes + 1 },
		"free exceeds size":      func(f *observability.FilesystemView) { f.FreeBytes = f.SizeBytes + 1 },
		"free inode count":       func(f *observability.FilesystemView) { f.FilesFree = f.Files + 1 },
		"inode bound":            func(f *observability.FilesystemView) { f.Files = hostload.MaxFilesystemBytes + 1 },
	} {
		filesystem := validFilesystem
		change(&filesystem)
		invalid["filesystem "+name] = hostload.Report{SchemaVersion: hostload.SchemaVersion,
			Host: hostload.HostUsage{Filesystems: []observability.FilesystemView{filesystem}}}
	}
	controls := map[string]hostload.Report{
		"hostload-bounds": {SchemaVersion: hostload.SchemaVersion,
			Host: hostload.HostUsage{CPU: new(0.5), Memory: new(1.0), Disk: new(0.0)},
			Roles: []hostload.RoleUsage{{Role: "api", CPUCores: new(2.0), MemoryBytes: new(uint64(1 << 30)),
				TerraBase: &memberstatus.Load{Connections: 1, WriteQPS: 3}}}},
		"hostload-network": {SchemaVersion: hostload.SchemaVersion,
			Host: hostload.HostUsage{NetworkRxBps: new(1.5e6), NetworkTxBps: new(0.0), Load1: new(0.75)}},
	}
	for _, count := range []int{hostload.MaxFilesystems, hostload.MaxFilesystems + 1} {
		report := hostload.Report{SchemaVersion: hostload.SchemaVersion}
		for i := range count {
			filesystem := validFilesystem
			filesystem.Role = fmt.Sprintf("volume-%d", i)
			report.Host.Filesystems = append(report.Host.Filesystems, filesystem)
		}
		if count == hostload.MaxFilesystems {
			controls["hostload-filesystems"] = report
		} else {
			invalid["too many filesystems"] = report
		}
	}
	invalid["duplicate filesystem"] = hostload.Report{SchemaVersion: hostload.SchemaVersion,
		Host: hostload.HostUsage{Filesystems: []observability.FilesystemView{validFilesystem, validFilesystem}}}
	rejectedNodes := make([]string, 0, len(invalid))
	for name, report := range invalid {
		node := fmt.Sprintf("hostload-invalid-%d", len(rejectedNodes))
		beforeNodes, beforeBatch := load.nodes(), load.archiveBatch(now)
		if err := load.record(hostload.Origin{Cell: "gru", Environment: "prod", Node: node}, report); !errors.Is(err, hostload.ErrInvalidReport) {
			t.Fatalf("%s admission = %v, want invalid report", name, err)
		}
		if !reflect.DeepEqual(load.nodes(), beforeNodes) || !reflect.DeepEqual(load.archiveBatch(now), beforeBatch) {
			t.Fatalf("%s rejection changed accepted reports or archive", name)
		}
		if !fence.Current().CanMutate() || t.Context().Err() != nil {
			t.Fatalf("%s rejection lost live fixture authority/context", name)
		}
		rejectedNodes = append(rejectedNodes, node)
	}
	if len(rejectedNodes) != 34 {
		t.Fatalf("rejected case count = %d, want 34", len(rejectedNodes))
	}

	// Reuse the controlled ReadSystem seam; these are not kernel measurements.
	view := observability.SystemView{CPUCount: 8, MemTotalBytes: 16 << 30,
		Filesystems: []observability.FilesystemView{
			{Role: "state", Path: "/state", SizeBytes: 100, AvailBytes: 80, FreeBytes: 90, Device: 1},
			{Role: "terrabase_data", Path: "/data", SizeBytes: 1000, AvailBytes: 250, FreeBytes: 300, Device: 2},
			{Role: "terrabase_data", Path: "/duplicate", SizeBytes: 1000, Device: 3},
			{Role: "unreadable", Path: "/unreadable"},
			{Role: "malformed", Path: "/malformed", SizeBytes: 1, AvailBytes: 2},
		}}
	want := slices.Clone(view.Filesystems[:2])
	identitySampler := hostload.NewSampler(hostload.SamplerConfig{ReadSystem: func([]observability.FilesystemRole) (observability.SystemView, error) {
		return view, nil
	}})
	sampled := identitySampler.Sample(nil)
	identityData, err := json.Marshal(sampled)
	if err != nil {
		t.Fatal(err)
	}
	var restored hostload.Report
	if err := json.Unmarshal(identityData, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.Host.Filesystems, want) || restored.Host.Disk == nil || *restored.Host.Disk != .75 ||
		restored.Host.CPUCores != 8 || restored.Host.MemoryBytes != 16<<30 || !restored.Host.FilesystemsIncomplete {
		t.Fatalf("filesystem identity/capacity lost: %+v", restored.Host)
	}
	for i := range hostload.MaxFilesystems + 1 {
		view.Filesystems = append(view.Filesystems, observability.FilesystemView{
			Role: fmt.Sprintf("volume-%d", i), Path: fmt.Sprintf("/volume-%d", i), SizeBytes: hostload.MaxFilesystemBytes})
	}
	view.CPUCount, view.MemTotalBytes = hostload.MaxCPUCores+1, hostload.MaxMemoryBytes+1
	bounded := identitySampler.Sample(nil)
	if len(bounded.Host.Filesystems) != hostload.MaxFilesystems || bounded.Host.CPUCores != 0 || bounded.Host.MemoryBytes != 0 || !bounded.Host.FilesystemsIncomplete {
		t.Fatalf("unbounded host observation: %+v", bounded.Host)
	}
	if err := bounded.Validate(); err != nil {
		t.Fatal(err)
	}
	wantBounded := slices.Clone(want)
	for i := range hostload.MaxFilesystems - len(want) {
		wantBounded = append(wantBounded, observability.FilesystemView{
			Role: fmt.Sprintf("volume-%d", i), Path: fmt.Sprintf("/volume-%d", i), SizeBytes: hostload.MaxFilesystemBytes})
	}
	if !reflect.DeepEqual(bounded.Host.Filesystems, wantBounded) {
		t.Fatalf("bounded filesystem identities = %+v, want %+v", bounded.Host.Filesystems, wantBounded)
	}
	controls["hostload-restored"], controls["hostload-bounded"] = restored, bounded
	for node, report := range controls {
		origin := hostload.Origin{Cell: "gru", Environment: "prod", Node: node}
		if err := load.record(origin, report); err != nil {
			t.Fatalf("%s positive admission: %v", node, err)
		}
		nodes := load.nodes()
		index := slices.IndexFunc(nodes, func(candidate hostload.NodeLoad) bool { return candidate.Origin == origin })
		if index < 0 || !nodes[index].At.Equal(receivedAt) || !reflect.DeepEqual(nodes[index].Report, report) {
			t.Fatalf("%s accepted report lost exact input: %+v", node, nodes)
		}
	}
	js := testRolloutJetStream(t)
	writer, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	if stored, err := writer.Publish(t.Context(), load.archiveBatch(now)); err != nil || !stored {
		t.Fatalf("archive publication stored=%t: %v", stored, err)
	}
	republishedAt := now.Add(3 * observability.HostMetricInterval)
	controllerNow = republishedAt
	if stored, err := writer.Publish(t.Context(), load.archiveBatch(republishedAt)); err != nil || !stored {
		t.Fatalf("unchanged report publication stored=%t: %v", stored, err)
	}
	reader, err := observability.OpenHostMetricStream(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	history := observability.NewHistory(observability.HistoryConfig{Interval: observability.HostMetricInterval})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- reader.Tail(ctx, history) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("archive replay stopped: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("archive replay did not stop")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for !reader.CaughtUp() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !reader.CaughtUp() || reader.ReplayFailures() != 0 {
		t.Fatal("archive replay did not accept collected host metrics")
	}
	for _, node := range rejectedNodes {
		result := history.Range(observability.HistoryQuery{Metric: observability.HistHostReceivedAt,
			Labels: map[string]string{"member": node}, Start: now.Add(-time.Minute), End: republishedAt})
		if len(result.Series) != 0 {
			t.Fatalf("rejected %s acquired replay receipt: %+v", node, result)
		}
	}
	for node, control := range controls {
		// Network/load and TerraBase fields are checked in accepted Nodes above;
		// this archive carries their causal receipt, not those unprojected fields.
		incomplete := 0.0
		if control.Host.FilesystemsIncomplete {
			incomplete = 1
		}
		metrics := []struct {
			metric  string
			value   *float64
			service string
		}{
			{observability.HistHostReceivedAt, new(float64(receivedAt.UnixMilli())), ""},
			{observability.HistHostFSIncomplete, new(incomplete), ""},
			{observability.HistHostCPUUtilization, control.Host.CPU, ""},
			{observability.HistHostMemoryRatio, control.Host.Memory, ""},
			{observability.HistHostDiskRatio, control.Host.Disk, ""},
			{observability.HistHostCPUCores, nil, ""},
			{observability.HistHostMemoryTotal, nil, ""},
		}
		if control.Host.CPUCores > 0 {
			metrics[5].value = new(float64(control.Host.CPUCores))
		}
		if control.Host.MemoryBytes > 0 {
			metrics[6].value = new(float64(control.Host.MemoryBytes))
		}
		if node == "hostload-bounds" {
			metrics = append(metrics, struct {
				metric  string
				value   *float64
				service string
			}{
				observability.HistServiceCPUCores, new(2.0), "api"},
				struct {
					metric  string
					value   *float64
					service string
				}{
					observability.HistServiceMemoryUsed, new(float64(1 << 30)), "api"})
		}
		for _, want := range metrics {
			labels := map[string]string{"member": node}
			if want.service != "" {
				labels["service"] = want.service
			}
			result := history.Range(observability.HistoryQuery{Metric: want.metric, Labels: labels,
				Start: now.Add(-time.Minute), End: republishedAt})
			if want.value == nil {
				if len(result.Series) != 0 {
					t.Fatalf("%s invented %s measurement: %+v", node, want.metric, result)
				}
				continue
			}
			if len(result.Series) != 1 || !reflect.DeepEqual(result.Series[0].Labels, labels) || len(result.Series[0].Points) != 2 {
				t.Fatalf("%s replayed %s identities/publications: %+v", node, want.metric, result)
			}
			for i, point := range result.Series[0].Points {
				if point.Value != *want.value || !point.Time.Equal([]time.Time{now, republishedAt}[i]) {
					t.Fatalf("%s replayed %s = %+v, want %v at both original minutes", node, want.metric, result, *want.value)
				}
			}
		}
		for _, metric := range []string{observability.HistHostFSSize, observability.HistHostFSUsed, observability.HistHostFSRatio,
			observability.HistHostFSFiles, observability.HistHostFSFilesFree} {
			result := history.Range(observability.HistoryQuery{Metric: metric, Labels: map[string]string{"member": node},
				Start: now.Add(-time.Minute), End: republishedAt})
			if len(result.Series) != len(control.Host.Filesystems) {
				t.Fatalf("%s replayed %s filesystem count = %d, want %d", node, metric, len(result.Series), len(control.Host.Filesystems))
			}
		}
		for _, filesystem := range control.Host.Filesystems {
			labels := map[string]string{"member": node, "role": filesystem.Role,
				"path": filesystem.Path, "device": strconv.FormatUint(filesystem.Device, 10)}
			for _, want := range []struct {
				metric string
				value  float64
			}{
				{observability.HistHostFSSize, float64(filesystem.SizeBytes)},
				{observability.HistHostFSUsed, float64(filesystem.SizeBytes - filesystem.AvailBytes)},
				{observability.HistHostFSRatio, float64(filesystem.SizeBytes-filesystem.AvailBytes) / float64(filesystem.SizeBytes)},
				{observability.HistHostFSFiles, float64(filesystem.Files)},
				{observability.HistHostFSFilesFree, float64(filesystem.FilesFree)},
			} {
				result := history.Range(observability.HistoryQuery{Metric: want.metric,
					Labels: map[string]string{"member": node, "role": filesystem.Role}, Start: now.Add(-time.Minute), End: republishedAt})
				if len(result.Series) != 1 || !reflect.DeepEqual(result.Series[0].Labels, labels) || len(result.Series[0].Points) != 2 {
					t.Fatalf("%s replayed %s filesystem identity/publications: %+v", node, want.metric, result)
				}
				for i, point := range result.Series[0].Points {
					if point.Value != want.value || !point.Time.Equal([]time.Time{now, republishedAt}[i]) {
						t.Fatalf("%s replayed %s filesystem value: %+v, want %v", node, want.metric, result, want.value)
					}
				}
			}
		}
		resources := regionview.CollectResources(regionview.Node{Name: node}, history, republishedAt)
		wantCount := len(control.Host.Filesystems)
		if node == "hostload-filesystems" {
			wantCount = 1 // All 37 logical roles share physical device 42.
		}
		if !resources.ObservedAt.Equal(receivedAt) || resources.Pending || resources.Incomplete != control.Host.FilesystemsIncomplete || len(resources.Filesystems) != wantCount {
			t.Fatalf("%s resource identity/collection status lost: %+v", node, resources)
		}
		for _, want := range []struct {
			name    string
			reading *regionview.Reading
			value   float64
		}{
			{"cpu cores", resources.CPUCores, float64(control.Host.CPUCores)},
			{"memory bytes", resources.MemoryBytes, float64(control.Host.MemoryBytes)},
		} {
			if want.value == 0 {
				if want.reading != nil {
					t.Fatalf("%s invented %s capacity: %+v", node, want.name, want.reading)
				}
			} else if want.reading == nil || want.reading.Value != want.value || !want.reading.ObservedAt.Equal(receivedAt) {
				t.Fatalf("%s resource %s = %+v, want %v", node, want.name, want.reading, want.value)
			}
		}
		for _, filesystem := range resources.Filesystems {
			index := slices.IndexFunc(control.Host.Filesystems, func(want observability.FilesystemView) bool {
				return want.Path == filesystem.Path && strconv.FormatUint(want.Device, 10) == filesystem.Device &&
					(want.Role == filesystem.Role || node == "hostload-filesystems")
			})
			if index < 0 {
				t.Fatalf("%s invented resource filesystem: %+v", node, filesystem)
			}
			want := control.Host.Filesystems[index]
			if node == "hostload-filesystems" {
				roles := make([]string, 0, len(control.Host.Filesystems))
				for _, entry := range control.Host.Filesystems {
					roles = append(roles, entry.Role)
				}
				slices.Sort(roles)
				if filesystem.Role != strings.Join(roles, ", ") {
					t.Fatalf("shared-device resource lost roles: %+v", filesystem)
				}
			}
			for _, gauge := range []struct {
				reading *regionview.Reading
				value   float64
			}{
				{filesystem.SizeBytes, float64(want.SizeBytes)},
				{filesystem.UsedBytes, float64(want.SizeBytes - want.AvailBytes)},
				{filesystem.UsedRatio, float64(want.SizeBytes-want.AvailBytes) / float64(want.SizeBytes)},
				{filesystem.Files, float64(want.Files)},
				{filesystem.FilesFree, float64(want.FilesFree)},
			} {
				if gauge.reading == nil || gauge.reading.Value != gauge.value || !gauge.reading.ObservedAt.Equal(receivedAt) {
					t.Fatalf("%s resource filesystem gauge = %+v, want %v", node, gauge.reading, gauge.value)
				}
			}
		}
	}
	for _, want := range []struct {
		metric string
		value  float64
	}{
		{observability.HistHostCPUCores, 8},
		{observability.HistHostMemoryTotal, 16 << 30},
		{observability.HistHostMemoryRatio, .75},
		{observability.HistHostDiskRatio, .75},
		{observability.HistHostReceivedAt, float64(receivedAt.UnixMilli())},
		{observability.HistHostFSIncomplete, 1},
	} {
		labels := map[string]string{"member": "host-a"}
		result := history.Range(observability.HistoryQuery{Metric: want.metric, Labels: labels, Start: now.Add(-time.Minute), End: now})
		if len(result.Series) != 1 || len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != want.value {
			t.Fatalf("replayed %s = %+v, want %v", want.metric, result, want.value)
		}
	}
	for _, filesystem := range filesystems {
		labels := map[string]string{"member": "host-a", "role": filesystem.Role,
			"path": filesystem.Path, "device": strconv.FormatUint(filesystem.Device, 10)}
		for _, want := range []struct {
			metric string
			value  float64
		}{
			{observability.HistHostFSSize, float64(filesystem.SizeBytes)},
			{observability.HistHostFSUsed, float64(filesystem.SizeBytes - filesystem.AvailBytes)},
			{observability.HistHostFSRatio, float64(filesystem.SizeBytes-filesystem.AvailBytes) / float64(filesystem.SizeBytes)},
			{observability.HistHostFSFiles, float64(filesystem.Files)},
			{observability.HistHostFSFilesFree, float64(filesystem.FilesFree)},
		} {
			result := history.Range(observability.HistoryQuery{Metric: want.metric,
				Labels: map[string]string{"member": "host-a", "role": filesystem.Role}, Start: now.Add(-time.Minute), End: now})
			if len(result.Series) != 1 || !reflect.DeepEqual(result.Series[0].Labels, labels) ||
				len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != want.value {
				t.Fatalf("replayed %s identity or value lost: %+v, want %+v = %v", want.metric, result, labels, want.value)
			}
		}
	}
	receipts := history.Range(observability.HistoryQuery{Metric: observability.HistHostReceivedAt,
		Labels: map[string]string{"member": "host-a"}, Start: now.Add(-time.Minute), End: republishedAt})
	if len(receipts.Series) != 1 || len(receipts.Series[0].Points) != 2 {
		t.Fatalf("receive time did not replay for both publication minutes: %+v", receipts)
	}
	for i, point := range receipts.Series[0].Points {
		if point.Value != float64(receivedAt.UnixMilli()) || !point.Time.Equal([]time.Time{now, republishedAt}[i]) {
			t.Fatalf("publication refreshed unchanged report receive time: %+v", receipts)
		}
	}
	resources := regionview.CollectResources(regionview.Node{Name: "host-a"}, history, republishedAt)
	if !resources.Incomplete || len(resources.Filesystems) != len(filesystems) {
		t.Fatalf("replayed collection failure was hidden or invented a measurement: %+v", resources)
	}
}
