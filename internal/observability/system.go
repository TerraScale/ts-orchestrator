package observability

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FilesystemRole names one directory whose filesystem capacity is reported,
// for example {Role: "nats", Path: "/var/lib/terrascale-orchestrator-controller/nats"}.
type FilesystemRole struct {
	Role string
	Path string
}

// userHZ is the kernel's USER_HZ, fixed at 100 on every Linux ABI this
// binary ships for, which /proc/stat counts in.
const userHZ = 100

// parseProcStat reads the aggregate "cpu" line and counts per-CPU lines.
func parseProcStat(data []byte) (CPUSeconds, int, error) {
	var total CPUSeconds
	found := false
	cpus := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// The intr line holds one counter per IRQ and can exceed the default
	// 64 KiB token limit on large hosts; the whole file is already in memory.
	scanner.Buffer(make([]byte, 0, 64*1024), len(data)+1)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}
		if fields[0] != "cpu" {
			cpus++
			continue
		}
		if len(fields) < 5 {
			return CPUSeconds{}, 0, errors.New("/proc/stat cpu line is short")
		}
		values := make([]float64, 8)
		for index := range values {
			if index+1 >= len(fields) {
				break
			}
			ticks, err := strconv.ParseUint(fields[index+1], 10, 64)
			if err != nil {
				return CPUSeconds{}, 0, errors.New("/proc/stat cpu line is malformed")
			}
			values[index] = float64(ticks) / userHZ
		}
		total = CPUSeconds{User: values[0], Nice: values[1], System: values[2], Idle: values[3],
			IOWait: values[4], IRQ: values[5], SoftIRQ: values[6], Steal: values[7]}
		found = true
	}
	if !found {
		return CPUSeconds{}, 0, errors.New("/proc/stat has no aggregate cpu line")
	}
	return total, cpus, scanner.Err()
}

// parseMeminfo returns the kB-valued fields of /proc/meminfo in bytes.
func parseMeminfo(data []byte) (map[string]uint64, error) {
	values, err := parseKilobyteFields(data)
	if err != nil {
		return nil, err
	}
	if _, ok := values["MemTotal"]; !ok {
		return nil, errors.New("/proc/meminfo has no MemTotal")
	}
	return values, nil
}

func parseLoadavg(data []byte) (float64, float64, float64, error) {
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, errors.New("/proc/loadavg is malformed")
	}
	var loads [3]float64
	for index := range loads {
		value, err := strconv.ParseFloat(fields[index], 64)
		if err != nil {
			return 0, 0, 0, errors.New("/proc/loadavg is malformed")
		}
		loads[index] = value
	}
	return loads[0], loads[1], loads[2], nil
}

// parsePressure reads one /proc/pressure/<resource> file.
func parsePressure(data []byte) (PSI, error) {
	var psi PSI
	seen := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] != "some" && fields[0] != "full" {
			continue
		}
		var avg10, avg60 float64
		var total uint64
		for _, field := range fields[1:] {
			key, raw, found := strings.Cut(field, "=")
			if !found {
				continue
			}
			var err error
			switch key {
			case "avg10":
				avg10, err = strconv.ParseFloat(raw, 64)
			case "avg60":
				avg60, err = strconv.ParseFloat(raw, 64)
			case "total":
				total, err = strconv.ParseUint(raw, 10, 64)
			}
			if err != nil {
				return PSI{}, errors.New("pressure line is malformed")
			}
		}
		if fields[0] == "some" {
			psi.SomeAvg10, psi.SomeAvg60, psi.SomeTotal = avg10, avg60, total
		} else {
			psi.FullAvg10, psi.FullAvg60, psi.FullTotal, psi.HasFullRow = avg10, avg60, total, true
		}
		seen = true
	}
	if !seen {
		return PSI{}, errors.New("pressure file has no some line")
	}
	return psi, scanner.Err()
}

func parseUptime(data []byte) (float64, error) {
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, errors.New("/proc/uptime is malformed")
	}
	return strconv.ParseFloat(fields[0], 64)
}

// readNetDev sums receive and transmit bytes over every interface except
// loopback. Malformed lines are skipped; ok is false when no line parsed.
func readNetDev(path string) (rx, tx uint64, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, rest, found := strings.Cut(line, ":")
		fields := strings.Fields(rest)
		if !found || len(fields) < 9 || strings.TrimSpace(name) == "lo" {
			continue
		}
		received, errRx := strconv.ParseUint(fields[0], 10, 64)
		sent, errTx := strconv.ParseUint(fields[8], 10, 64)
		if errRx != nil || errTx != nil {
			continue
		}
		rx += received
		tx += sent
		ok = true
	}
	return rx, tx, ok
}

// parseStatusRSS reads VmRSS from /proc/self/status.
func parseStatusRSS(data []byte) uint64 {
	values, _ := parseKilobyteFields(data)
	return values["VmRSS"]
}

// parseKilobyteFields reads "Name: <n> kB" lines as bytes, the shared shape
// of /proc/meminfo and /proc/self/status.
func parseKilobyteFields(data []byte) (map[string]uint64, error) {
	values := map[string]uint64{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		name, rest, found := strings.Cut(scanner.Text(), ":")
		fields := strings.Fields(rest)
		if !found || len(fields) != 2 || fields[1] != "kB" {
			continue
		}
		if value, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			values[name] = value * 1024
		}
	}
	return values, scanner.Err()
}

// WriteSystemMetrics renders a SystemView as ts_orch_host_* series.
func WriteSystemMetrics(w io.Writer, view SystemView) {
	cpu := view.CPUSeconds
	for _, mode := range []struct {
		name  string
		value float64
	}{{"user", cpu.User}, {"nice", cpu.Nice}, {"system", cpu.System}, {"idle", cpu.Idle},
		{"iowait", cpu.IOWait}, {"irq", cpu.IRQ}, {"softirq", cpu.SoftIRQ}, {"steal", cpu.Steal}} {
		WriteCounter(w, Series(MetricPrefix+"host_cpu_seconds_total", "mode", mode.name), mode.value)
	}
	WriteGauge(w, MetricPrefix+"host_cpus", float64(view.CPUCount))
	WriteGauge(w, MetricPrefix+"host_load1", view.Load1)
	WriteGauge(w, MetricPrefix+"host_load5", view.Load5)
	WriteGauge(w, MetricPrefix+"host_load15", view.Load15)
	WriteGauge(w, MetricPrefix+"host_memory_total_bytes", float64(view.MemTotalBytes))
	WriteGauge(w, MetricPrefix+"host_memory_available_bytes", float64(view.MemAvailBytes))
	WriteGauge(w, MetricPrefix+"host_swap_total_bytes", float64(view.SwapTotalBytes))
	WriteGauge(w, MetricPrefix+"host_swap_free_bytes", float64(view.SwapFreeBytes))
	WriteGauge(w, MetricPrefix+"host_uptime_seconds", view.UptimeSeconds)
	for _, resource := range []string{"cpu", "memory", "io"} {
		psi, ok := view.Pressure[resource]
		if !ok {
			continue
		}
		WriteGauge(w, Series(MetricPrefix+"host_pressure_avg10", "resource", resource, "kind", "some"), psi.SomeAvg10)
		WriteCounter(w, Series(MetricPrefix+"host_pressure_stalled_seconds_total", "resource", resource, "kind", "some"),
			float64(psi.SomeTotal)/1e6)
		if psi.HasFullRow {
			WriteGauge(w, Series(MetricPrefix+"host_pressure_avg10", "resource", resource, "kind", "full"), psi.FullAvg10)
			WriteCounter(w, Series(MetricPrefix+"host_pressure_stalled_seconds_total", "resource", resource, "kind", "full"),
				float64(psi.FullTotal)/1e6)
		}
	}
	if clock := view.Clock; clock != nil {
		synchronized := 0.0
		if clock.Synchronized {
			synchronized = 1
		}
		WriteGauge(w, MetricPrefix+"host_clock_synchronized", synchronized)
		WriteGauge(w, MetricPrefix+"host_clock_offset_seconds", clock.OffsetSeconds)
		WriteGauge(w, MetricPrefix+"host_clock_max_error_seconds", clock.MaxErrorSeconds)
	}
	for _, filesystem := range view.Filesystems {
		if filesystem.SizeBytes == 0 {
			continue
		}
		WriteGauge(w, Series(MetricPrefix+"host_filesystem_size_bytes", "role", filesystem.Role), float64(filesystem.SizeBytes))
		WriteGauge(w, Series(MetricPrefix+"host_filesystem_avail_bytes", "role", filesystem.Role), float64(filesystem.AvailBytes))
		WriteGauge(w, Series(MetricPrefix+"host_filesystem_files", "role", filesystem.Role), float64(filesystem.Files))
		WriteGauge(w, Series(MetricPrefix+"host_filesystem_files_free", "role", filesystem.Role), float64(filesystem.FilesFree))
	}
}

// ReadSystem reads this machine's CPU, memory, pressure and filesystem state
// from /proc and statfs. Missing pressure files (kernels without PSI) are
// skipped; a filesystem that cannot be read keeps its role and path with
// zero sizes as unavailable evidence, without discarding successful readings.
func ReadSystem(filesystems []FilesystemRole) (SystemView, error) {
	view, err := readSystem("/proc", filesystems, statFilesystem)
	view.Clock = readClock()
	return view, err
}

func readSystem(procRoot string, filesystems []FilesystemRole,
	stat func(string) (FilesystemView, error),
) (SystemView, error) {
	var view SystemView
	data, err := os.ReadFile(filepath.Join(procRoot, "stat"))
	if err != nil {
		return SystemView{}, err
	}
	if view.CPUSeconds, view.CPUCount, err = parseProcStat(data); err != nil {
		return SystemView{}, err
	}
	data, err = os.ReadFile(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return SystemView{}, err
	}
	memory, err := parseMeminfo(data)
	if err != nil {
		return SystemView{}, err
	}
	view.MemTotalBytes, view.MemAvailBytes = memory["MemTotal"], memory["MemAvailable"]
	view.SwapTotalBytes, view.SwapFreeBytes = memory["SwapTotal"], memory["SwapFree"]
	if data, err = os.ReadFile(filepath.Join(procRoot, "loadavg")); err == nil {
		view.Load1, view.Load5, view.Load15, _ = parseLoadavg(data)
	}
	if data, err = os.ReadFile(filepath.Join(procRoot, "uptime")); err == nil {
		view.UptimeSeconds, _ = parseUptime(data)
	}
	if data, err = os.ReadFile(filepath.Join(procRoot, "self", "status")); err == nil {
		view.ProcessRSSBytes = parseStatusRSS(data)
	}
	if rx, tx, ok := readNetDev(filepath.Join(procRoot, "net", "dev")); ok {
		view.NetRxBytes, view.NetTxBytes = rx, tx
	}
	for _, resource := range []string{"cpu", "memory", "io"} {
		data, err := os.ReadFile(filepath.Join(procRoot, "pressure", resource))
		if err != nil {
			continue
		}
		if psi, err := parsePressure(data); err == nil {
			if view.Pressure == nil {
				view.Pressure = map[string]PSI{}
			}
			view.Pressure[resource] = psi
		}
	}
	for _, filesystem := range filesystems {
		if filesystem.Role == "" || filesystem.Path == "" {
			continue
		}
		observed, err := stat(filesystem.Path)
		if err != nil {
			observed = FilesystemView{}
		}
		observed.Role, observed.Path = filesystem.Role, filesystem.Path
		view.Filesystems = append(view.Filesystems, observed)
	}
	return view, nil
}
