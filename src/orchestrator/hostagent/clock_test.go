package hostagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const chronyTrackingReport = `Reference ID    : C0A80101 (192.168.1.1)
Stratum         : 3
Ref time (UTC)  : Thu Sep  3 10:00:00 2026
System time     : 0.000012345 seconds fast of NTP time
Last offset     : +0.000012000 seconds
RMS offset      : 0.000015000 seconds
Frequency       : 1.234 ppm slow
Residual freq   : +0.001 ppm
Skew            : 0.026 ppm
Root delay      : 0.000123456 seconds
Root dispersion : 0.000234567 seconds
Update interval : 64.5 seconds
Leap status     : Normal
`

// TestParseChronySystemTime covers the fast and slow spellings and the
// missing-line failure.
func TestParseChronySystemTime(t *testing.T) {
	offset, err := ParseChronySystemTime(chronyTrackingReport)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if want := 12345 * time.Nanosecond; offset != want {
		t.Fatalf("offset is %v, want %v", offset, want)
	}
	slow := strings.Replace(chronyTrackingReport,
		"0.000012345 seconds fast", "1.500000000 seconds slow", 1)
	offset, err = ParseChronySystemTime(slow)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if want := -1500 * time.Millisecond; offset != want {
		t.Fatalf("offset is %v, want %v", offset, want)
	}
	if _, err := ParseChronySystemTime("Reference ID    : C0A80101 (192.168.1.1)\n"); err == nil {
		t.Fatal("report without a system-time line accepted")
	}
	for _, invalid := range []string{
		"System time : -1.0 seconds fast of NTP time",
		"System time : -1.0 seconds slow of NTP time",
		"System time : 86401 seconds fast of NTP time",
	} {
		if _, err := ParseChronySystemTime(invalid); err == nil {
			t.Fatalf("invalid magnitude accepted: %q", invalid)
		}
	}
}

func TestChronyTrackingSourceBoundsInvocationAndOutput(t *testing.T) {
	hanging := filepath.Join(t.TempDir(), "chronyc-hang")
	if err := os.WriteFile(hanging, []byte("#!/bin/sh\nsleep 10\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	source := ChronyTrackingSource{ChronycBinary: hanging, Timeout: 30 * time.Millisecond}
	started := time.Now()
	if _, err := source.Offset(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hung chronyc error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("hung chronyc exceeded bounded shutdown: %v", elapsed)
	}

	oversized := filepath.Join(t.TempDir(), "chronyc-large")
	if err := os.WriteFile(oversized, []byte("#!/bin/sh\nhead -c 70000 /dev/zero\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	source = ChronyTrackingSource{ChronycBinary: oversized, Timeout: time.Second}
	if _, err := source.Offset(context.Background()); err == nil || !strings.Contains(err.Error(), "size bound") {
		t.Fatalf("oversized chronyc output error = %v", err)
	}

	if _, err := (ChronyTrackingSource{ChronycBinary: "chronyc", Timeout: time.Second}).Offset(context.Background()); err == nil {
		t.Fatal("relative chronyc binary accepted")
	}
}

// TestSampleClockEnforcesWriteRefusalThreshold asserts the D-69 rule at and
// beyond 500 ms in both directions, and that an unreadable clock is
// unhealthy rather than healthy.
func TestSampleClockEnforcesWriteRefusalThreshold(t *testing.T) {
	cases := []struct {
		name      string
		offset    time.Duration
		readErr   error
		unhealthy bool
		measured  bool
	}{
		{"healthy fast", 499 * time.Millisecond, nil, false, true},
		{"healthy slow", -499 * time.Millisecond, nil, false, true},
		{"threshold fast", 500 * time.Millisecond, nil, false, true},
		{"threshold slow", -500 * time.Millisecond, nil, false, true},
		{"beyond fast", 501 * time.Millisecond, nil, true, true},
		{"beyond slow", -501 * time.Millisecond, nil, true, true},
		{"unreadable", 0, &InvalidDataError{Message: "chrony down"}, true, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			sample := SampleClock(testCase.offset, testCase.readErr)
			if sample.Unhealthy != testCase.unhealthy {
				t.Fatalf("unhealthy is %v", sample.Unhealthy)
			}
			if sample.Measured != testCase.measured {
				t.Fatalf("measured is %v", sample.Measured)
			}
			if testCase.readErr == nil && sample.OffsetMillis != testCase.offset.Milliseconds() {
				t.Fatalf("offset millis is %d", sample.OffsetMillis)
			}
		})
	}
}
