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
	"os/exec"
	"regexp"
	"strconv"
	"strings"
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
// System time line.
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
	if !safeAbsolutePath(s.ChronycBinary) {
		return 0, &InvalidOperationError{Message: "The chronyc binary must be an absolute safe path."}
	}
	if s.Timeout <= 0 {
		return 0, &InvalidOperationError{Message: "The chronyc timeout must be positive."}
	}
	commandContext, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	command := exec.CommandContext(commandContext, s.ChronycBinary, "tracking")
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

// ParseChronySystemTime extracts the signed system-time offset from one
// chronyc tracking report: fast of NTP time is a positive offset, slow is
// negative.
func ParseChronySystemTime(tracking string) (time.Duration, error) {
	for _, line := range strings.Split(tracking, "\n") {
		match := chronySystemTimePattern.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		seconds, err := strconv.ParseFloat(match[1], 64)
		if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) ||
			seconds < 0 || seconds > chronyMaximumOffset.Seconds() {
			break
		}
		offset := time.Duration(seconds * float64(time.Second))
		if match[2] == "slow" {
			offset = -offset
		}
		return offset, nil
	}
	return 0, &InvalidDataError{Message: "The chrony tracking report carries no system-time line."}
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
