// This file implements the D-69 clock rule for ts-node: read the measured
// system-time offset from chrony tracking on every host, publish it as a
// heartbeat fact, and mark the host unhealthy for writes once its magnitude
// exceeds 500 ms. Refusing new writes is the member engine's job; ts-node
// exports the fact both directions — the offset metric and the unhealthy
// flag — over the control plane.
package hostagent

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"time"
)

// ClockWriteRefusalThreshold is the D-69 bound: beyond this measured offset
// a member never mints HLC timestamps from its local clock, so ts-node marks
// the host unhealthy for writes.
const ClockWriteRefusalThreshold = 500 * time.Millisecond

const (
	chronyMaximumOutputBytes = 64 << 10
	chronyMaximumOffset      = 24 * time.Hour
)

// ClockOffsetSample is one measured clock fact.
type ClockOffsetSample struct {
	// OffsetMillis is the signed system-time offset from NTP time; positive
	// means the local clock is fast.
	OffsetMillis int64
	// Unhealthy reports whether the offset exceeds the write-refusal
	// threshold.
	Unhealthy bool
	// Measured is false when chrony could not be read; an unreadable clock
	// is treated as unhealthy for writes, never as healthy.
	Measured bool
}

// ClockSource reads the chrony tracking offset; ChronyTrackingSource is the
// live spelling and tests inject parsed output.
type ClockSource interface {
	// Offset returns the current measured system-time offset.
	Offset(ctx context.Context) (time.Duration, error)
}

// ChronyTrackingSource shells out to `chronyc tracking` and parses its
// synchronization state and System time line.
type ChronyTrackingSource struct {
	// ChronycBinary is the absolute path of chronyc.
	ChronycBinary string
	// Timeout bounds the invocation.
	Timeout time.Duration
}

// Offset runs chronyc tracking and parses the system-time offset.
func (s ChronyTrackingSource) Offset(ctx context.Context) (time.Duration, error) {
	if ctx == nil {
		return 0, &InvalidOperationError{Message: "The chrony context is required."}
	}
	if !hostmanifest.SafeAbsolutePath(s.ChronycBinary) {
		return 0, &InvalidOperationError{Message: "The chronyc binary must be an absolute safe path."}
	}
	if s.Timeout <= 0 {
		return 0, &InvalidOperationError{Message: "The chronyc timeout must be positive."}
	}
	commandContext, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	command := exec.CommandContext(commandContext, s.ChronycBinary, "tracking")
	command.Env = append(os.Environ(), "LC_ALL=C", "TZ=UTC")
	command.WaitDelay = s.Timeout
	output := &boundedCommandOutput{maximum: chronyMaximumOutputBytes}
	command.Stdout = output
	command.Stderr = &boundedCommandOutput{maximum: 4096}
	err := command.Run()
	if err != nil {
		if contextErr := commandContext.Err(); contextErr != nil {
			return 0, fmt.Errorf("chronyc tracking failed: %w", contextErr)
		}
		return 0, fmt.Errorf("chronyc tracking failed: %w", err)
	}
	if output.exceeded {
		return 0, &InvalidDataError{Message: "The chrony tracking report exceeds its size bound."}
	}
	return ParseChronySystemTime(output.buffer.String())
}

type boundedCommandOutput struct {
	buffer   bytes.Buffer
	maximum  int
	exceeded bool
}

func (w *boundedCommandOutput) Write(data []byte) (int, error) {
	remaining := w.maximum - w.buffer.Len()
	if remaining > 0 {
		written := len(data)
		if written > remaining {
			written = remaining
		}
		_, _ = w.buffer.Write(data[:written])
	}
	if len(data) > remaining {
		w.exceeded = true
	}
	return len(data), nil
}

// chronySystemTimePattern matches the stable tracking line
// "System time     : 0.000012345 seconds fast of NTP time".
var chronySystemTimePattern = regexp.MustCompile(
	`^System time\s*:\s*([0-9]+(?:\.[0-9]+)?) seconds (fast|slow) of NTP time$`)

// ParseChronySystemTime accepts a complete synchronized chronyc tracking report.
// Leap insertion/deletion announcements remain synchronized states. See the
// chrony 4.6 chronyc tracking manual for these spellings and local-mode refid.
func ParseChronySystemTime(tracking string) (time.Duration, error) {
	invalid := func() (time.Duration, error) {
		return 0, &InvalidDataError{Message: "The chrony tracking report is incomplete, invalid, or not externally synchronized."}
	}
	if len(tracking) == 0 || len(tracking) > chronyMaximumOutputBytes || strings.ContainsRune(tracking, '\x00') {
		return invalid()
	}
	fields := map[string]string{
		"Reference ID": "", "Stratum": "", "Ref time (UTC)": "", "System time": "",
		"Last offset": "", "RMS offset": "", "Frequency": "", "Residual freq": "",
		"Skew": "", "Root delay": "", "Root dispersion": "", "Update interval": "", "Leap status": "",
	}
	lines := strings.Split(strings.TrimSpace(tracking), "\n")
	if len(lines) != len(fields) {
		return invalid()
	}
	for _, line := range lines {
		if len(line) > 1024 {
			return invalid()
		}
		name, value, found := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		previous, known := fields[name]
		if !found || !known || previous != "" || value == "" {
			return invalid()
		}
		fields[name] = value
	}
	switch fields["Leap status"] {
	case "Normal", "Insert second", "Delete second":
	default:
		return invalid()
	}
	stratum, err := strconv.Atoi(fields["Stratum"])
	if err != nil || stratum < 1 || stratum > 15 || strconv.Itoa(stratum) != fields["Stratum"] {
		return invalid()
	}
	reference := strings.Fields(fields["Reference ID"])
	if len(reference) == 0 || len(reference[0]) != 8 {
		return invalid()
	}
	refID, err := strconv.ParseUint(reference[0], 16, 32)
	if err != nil || refID == 0 {
		return invalid()
	}
	// chrony's local reference deliberately claims synchronization without
	// an external clock; it cannot establish the host write-health gate.
	if refID == 0x7f7f0101 && (len(reference) == 1 || len(reference) == 2 && reference[1] == "()") {
		return invalid()
	}
	refTime, err := time.Parse("Mon Jan _2 15:04:05 2006", fields["Ref time (UTC)"])
	if err != nil || refTime.Unix() <= 0 {
		return invalid()
	}
	for _, name := range []string{"Last offset", "RMS offset", "Root delay", "Root dispersion", "Update interval"} {
		if !finiteChronyValue(fields[name], " seconds") {
			return invalid()
		}
	}
	for _, name := range []string{"Residual freq", "Skew"} {
		if !finiteChronyValue(fields[name], " ppm") {
			return invalid()
		}
	}
	if !finiteChronyValue(fields["Frequency"], " ppm fast") && !finiteChronyValue(fields["Frequency"], " ppm slow") {
		return invalid()
	}
	match := chronySystemTimePattern.FindStringSubmatch("System time : " + fields["System time"])
	if match == nil {
		return invalid()
	}
	seconds, err := strconv.ParseFloat(match[1], 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > chronyMaximumOffset.Seconds() {
		return invalid()
	}
	offset := time.Duration(seconds * float64(time.Second))
	if match[2] == "slow" {
		offset = -offset
	}
	return offset, nil
}

func finiteChronyValue(value, unit string) bool {
	number, found := strings.CutSuffix(value, unit)
	if !found || number == "" || strings.TrimSpace(number) != number {
		return false
	}
	parsed, err := strconv.ParseFloat(number, 64)
	return err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0)
}

// SampleClock turns one offset reading into the D-69 clock fact: the signed
// offset, the unhealthy flag, and the measured marker. An unreadable clock
// reports unhealthy with a zero offset and Measured=false, so the engine
// fails closed on silence instead of trusting a stale figure.
func SampleClock(offset time.Duration, readErr error) ClockOffsetSample {
	if readErr != nil {
		return ClockOffsetSample{OffsetMillis: 0, Unhealthy: true, Measured: false}
	}
	return ClockOffsetSample{
		OffsetMillis: offset.Milliseconds(),
		Unhealthy:    offset < -ClockWriteRefusalThreshold || offset > ClockWriteRefusalThreshold,
		Measured:     true,
	}
}
